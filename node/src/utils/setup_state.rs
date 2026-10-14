//! The BABE setup state and soldering payloads kept on disk during graph setup.

use crate::action::SolderingProofReady;
use crate::env::*;
use crate::soldering_payload_store::{
    delete_soldering_proof_store_payload, is_soldering_proof_s3_path,
    soldering_proof_payload_store_path, write_soldering_proof_store_payload,
};
use anyhow::{Context, Result, bail};
use bitcoin::PublicKey;
use bitvm_lib::types::BitvmGcCircuitData;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use store::localdb::LocalDB;

use bitvm_lib::babe_adapter::{
    BabeVerifierPrivateState, CACSetupPackage, FinalizedInstanceData, Seed, SolderingData,
    compact_soldering_proof_payload,
};
use store::GraphStatus;
use tracing::warn;
use uuid::Uuid;

const BABE_SETUP_STATE_ORPHAN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

pub(crate) fn babe_setup_state_root(local_db: &LocalDB) -> PathBuf {
    std::env::var_os(ENV_BABE_SETUP_STATE_DIR)
        .filter(|path| !path.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let db_path = local_db
                .path
                .strip_prefix("sqlite://")
                .or_else(|| local_db.path.strip_prefix("sqlite:"))
                .unwrap_or(&local_db.path);
            PathBuf::from(db_path)
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".bitvm-babe-state")
        })
}

fn babe_setup_state_path(local_db: &LocalDB, instance_id: Uuid, graph_id: Uuid) -> PathBuf {
    babe_setup_state_root(local_db).join(instance_id.to_string()).join(format!("{graph_id}.bin"))
}

pub(crate) fn soldering_payload_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub(crate) fn soldering_payload_hash_hex(payload_hash: &[u8; 32]) -> String {
    payload_hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn save_soldering_proof_payload(
    instance_id: Uuid,
    graph_id: Uuid,
    candidate_index: usize,
    opened: &[(usize, Seed)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<SolderingProofReady> {
    let compact_payload = compact_soldering_proof_payload(opened, finalized, soldering)?;
    let payload = bincode::serialize(&compact_payload)
        .context("serialize compact soldering proof payload")?;
    let payload_hash = soldering_payload_hash(&payload);
    let total_len = payload.len();
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        candidate_index,
        &payload_hash,
    )?;
    let store_mode = if is_soldering_proof_s3_path(&store_base_path) { "s3" } else { "local" };
    if let Err(err) =
        write_soldering_proof_store_payload(&payload_path, &payload).await.with_context(|| {
            format!("write soldering proof payload to configured store path {payload_path}")
        })
    {
        tracing::error!(
            store_mode,
            total_len,
            payload_hash = %soldering_payload_hash_hex(&payload_hash),
            payload_path = %payload_path,
            error = %err,
            "failed to write soldering proof payload to store"
        );
        return Err(err);
    }
    tracing::info!(
        store_mode,
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "saved compact soldering proof to payload store"
    );
    Ok(SolderingProofReady { instance_id, graph_id, candidate_index, payload_hash, total_len })
}

fn load_babe_setup_state_from_path(path: &Path) -> Result<Option<BabeSetupState>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            bincode::deserialize(&bytes)
                .with_context(|| format!("decode BABE setup state {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read BABE setup state {}", path.display())),
    }
}

fn save_babe_setup_state_to_path(path: &Path, state: &BabeSetupState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create BABE setup state dir {}", parent.display()))?;
    }
    let bytes = bincode::serialize(state)?;
    let mut temp_path = path.as_os_str().to_os_string();
    temp_path.push(".tmp");
    let temp_path = PathBuf::from(temp_path);
    std::fs::write(&temp_path, bytes)
        .with_context(|| format!("write BABE setup state {}", temp_path.display()))?;
    std::fs::rename(&temp_path, path).with_context(|| {
        format!("move BABE setup state {} to {}", temp_path.display(), path.display())
    })
}

pub(crate) fn load_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<BabeSetupState>> {
    load_babe_setup_state_from_path(&babe_setup_state_path(local_db, instance_id, graph_id))
}

pub(crate) fn save_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    state: &BabeSetupState,
) -> Result<()> {
    save_babe_setup_state_to_path(&babe_setup_state_path(local_db, instance_id, graph_id), state)
}

pub(crate) fn update_babe_setup_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    update: impl FnOnce(&mut BabeSetupState),
) -> Result<BabeSetupState> {
    let mut state = load_babe_setup_state(local_db, instance_id, graph_id)?.unwrap_or_default();
    update(&mut state);
    save_babe_setup_state(local_db, instance_id, graph_id, &state)?;
    Ok(state)
}

fn babe_setup_state_is_stale(path: &Path, now: SystemTime) -> Result<bool> {
    let modified = std::fs::metadata(path)
        .with_context(|| format!("read BABE setup state metadata {}", path.display()))?
        .modified()
        .with_context(|| format!("read BABE setup state modified time {}", path.display()))?;
    Ok(now.duration_since(modified).unwrap_or_default() >= BABE_SETUP_STATE_ORPHAN_RETENTION)
}

fn should_cleanup_babe_setup_state(status: Option<GraphStatus>, is_stale: bool) -> bool {
    match status {
        Some(status) if status.is_closed() => true,
        Some(status) if status.is_obsoleted() => is_stale,
        None => is_stale,
        Some(_) => false,
    }
}

pub(crate) async fn cleanup_babe_setup_states(
    local_db: &LocalDB,
    payload_store: &str,
) -> Result<usize> {
    let root = babe_setup_state_root(local_db);
    let instance_dirs = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read BABE setup state root {}", root.display()));
        }
    };
    let mut storage = local_db.acquire().await?;
    let now = SystemTime::now();
    let mut deleted = 0;
    for instance_dir in instance_dirs {
        let instance_dir = instance_dir?;
        if !instance_dir.file_type()?.is_dir() {
            continue;
        }
        let Ok(instance_id) = Uuid::parse_str(&instance_dir.file_name().to_string_lossy()) else {
            continue;
        };
        for state_file in std::fs::read_dir(instance_dir.path())? {
            let state_file = state_file?;
            let path = state_file.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
                continue;
            }
            let Some(graph_id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| Uuid::parse_str(stem).ok())
            else {
                continue;
            };
            let is_stale = babe_setup_state_is_stale(&path, now)?;
            let status = match storage.find_graph(&graph_id).await? {
                Some(graph) if graph.instance_id == instance_id => {
                    let Ok(status) = GraphStatus::from_str(&graph.status) else {
                        warn!(
                            "Skip BABE setup cleanup for {graph_id}: invalid graph status {}",
                            graph.status
                        );
                        continue;
                    };
                    Some(status)
                }
                Some(graph) => {
                    warn!(
                        "BABE setup state {graph_id} belongs to {instance_id}, but the stored graph belongs to {}",
                        graph.instance_id
                    );
                    None
                }
                None => None,
            };
            if !should_cleanup_babe_setup_state(status, is_stale) {
                continue;
            }
            if status.is_none() {
                warn!("Cleaning stale orphan BABE setup state for {instance_id}:{graph_id}");
            }
            let Some(state) = load_babe_setup_state_from_path(&path)? else {
                continue;
            };
            let mut payloads = Vec::new();
            if let Some(ready) = state.verifier.and_then(|verifier| verifier.soldering_proof_ready)
            {
                payloads.push(ready);
            }
            if let Some(operator) = state.operator {
                payloads.extend(
                    operator
                        .candidates
                        .into_iter()
                        .filter_map(|candidate| candidate.soldering_proof_ready),
                );
            }
            for ready in payloads {
                if ready.instance_id != instance_id || ready.graph_id != graph_id {
                    bail!("BABE setup payload reference does not match state path");
                }
                let payload_path = soldering_proof_payload_store_path(
                    payload_store,
                    instance_id,
                    graph_id,
                    ready.candidate_index,
                    &ready.payload_hash,
                )?;
                delete_soldering_proof_store_payload(&payload_path).await?;
            }
            std::fs::remove_file(&path)
                .with_context(|| format!("delete BABE setup state {}", path.display()))?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BabeSetupState {
    pub verifier: Option<VerifierBabeSetupState>,
    pub operator: Option<OperatorBabeSetupState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierBabeSetupState {
    pub verifier_pubkey: PublicKey,
    /// Authenticated operator identity that initiated this setup.
    pub operator_pubkey: PublicKey,
    /// Signed operator P2P identity used for directed setup replies and ACKs.
    pub operator_peer_id: Vec<u8>,
    pub setup_package: CACSetupPackage,
    pub private_state: BabeVerifierPrivateState,
    pub finalized_indices: Vec<usize>,
    pub soldering_proof_ready: Option<SolderingProofReady>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorVerifierCandidate {
    pub verifier_peer_id: Vec<u8>,
    pub verifier_pubkey: PublicKey,
    pub setup_package: CACSetupPackage,
    /// Immutable slot within the candidate pool and proof payload store.
    pub candidate_index: Option<usize>,
    pub selected_circuit_indexes: Vec<usize>,
    pub gc_data: Option<BitvmGcCircuitData>,
    pub soldering_proof_ready: Option<SolderingProofReady>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorBabeSetupState {
    /// Candidate pool closed before CutCircuits. This is not the final graph
    /// verifier set; `selected_verifier_pubkeys` is set after proof validation.
    pub candidate_verifier_pubkeys: Option<Vec<PublicKey>>,
    pub candidates: Vec<OperatorVerifierCandidate>,
    #[serde(default)]
    pub candidate_collection_started_at: Option<i64>,
    #[serde(default)]
    pub proof_collection_started_at: Option<i64>,
    #[serde(default)]
    pub selected_verifier_pubkeys: Option<Vec<PublicKey>>,
    #[serde(default)]
    pub asserted_operator_proof: Option<Vec<u8>>,
}
