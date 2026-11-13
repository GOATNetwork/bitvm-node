//! Fetch and serve graph definitions over `GetGraph`.
//!
//! Fetched definitions must match the requested identity and chain parameters.
//! Operator pre-signatures are verified, as are committee pre-signatures when
//! present. A graph posted on Goat requires committee pre-signatures.

use crate::middleware::get_graph::{GetGraphRequest, GetGraphResponse};
use crate::middleware::publisher::NetworkPublisher;
use crate::utils::{
    load_validated_graph_definition, parse_graph_raw_data, store_finalized_graph_if_needed,
    store_operator_presigned_graph, validate_graph_instance_parameters,
};
use anyhow::{Context, bail};
use bitvm_lib::operator::verify_graph_operator_pre_signatures;
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use store::GraphStatus;
use store::localdb::LocalDB;
use tracing::{info, warn};
use uuid::Uuid;

/// Which definition a fetch job wants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphLookup {
    /// By id; `finalized` asks for a copy with committee pre-signatures, so a
    /// stored operator-presigned copy does not satisfy it.
    Id {
        instance_id: Uuid,
        graph_id: Uuid,
        finalized: bool,
    },
    Slot {
        operator_pubkey: String,
        graph_nonce: u64,
    },
    /// By slot, accepting only a copy with committee pre-signatures. An
    /// operator-only copy would claim the slot for a graph the committee never
    /// signed, and the finalized one could no longer be stored. A separate
    /// variant keeps the encoding of persisted `Slot` lookups.
    FinalizedSlot {
        operator_pubkey: String,
        graph_nonce: u64,
    },
}

impl GraphLookup {
    pub fn request(&self) -> GetGraphRequest {
        match self {
            GraphLookup::Id { instance_id, graph_id, finalized } => {
                GetGraphRequest::by_id(*instance_id, *graph_id, *finalized)
            }
            GraphLookup::Slot { operator_pubkey, graph_nonce } => {
                GetGraphRequest::by_slot(operator_pubkey.clone(), *graph_nonce, false)
            }
            GraphLookup::FinalizedSlot { operator_pubkey, graph_nonce } => {
                GetGraphRequest::by_slot(operator_pubkey.clone(), *graph_nonce, true)
            }
        }
    }

    fn wants_finalized(&self) -> bool {
        matches!(self, GraphLookup::Id { finalized: true, .. } | GraphLookup::FinalizedSlot { .. })
    }
}

/// Answer a request from the local store.
pub async fn serve_graph_request(
    local_db: &LocalDB,
    request: &GetGraphRequest,
) -> anyhow::Result<GetGraphResponse> {
    let mut storage = local_db.acquire().await?;
    let row = match (request.graph_id, &request.operator_pubkey, request.graph_nonce) {
        (Some(graph_id), _, _) => storage.find_graph(&graph_id).await?,
        (None, Some(operator_pubkey), Some(graph_nonce)) => {
            storage.find_graph_by_operator_slot(operator_pubkey, graph_nonce as i64).await?
        }
        _ => return Ok(GetGraphResponse::not_found()),
    };
    let Some(row) = row else {
        return Ok(GetGraphResponse::not_found());
    };
    if let Some(instance_id) = request.instance_id
        && row.instance_id != instance_id
    {
        return Ok(GetGraphResponse::not_found());
    }
    // Only the operator's copy is stored while the graph is OperatorPresigned.
    if request.finalized && row.status == GraphStatus::OperatorPresigned.to_string() {
        return Ok(GetGraphResponse::not_found());
    }
    let Some(raw) = storage.find_graph_raw_data(&row.graph_id).await? else {
        return Ok(GetGraphResponse::not_found());
    };
    Ok(GetGraphResponse::found(row.instance_id, row.graph_id, raw.raw_data))
}

/// What a fetch stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_pubkey: String,
    pub graph_nonce: u64,
    pub finalized: bool,
}

/// Candidate peers: the registered committee members first, then the
/// graph's operator when its key is known (slot lookups), never this node.
pub fn fetch_candidates(operator_pubkey: Option<&str>) -> Vec<PeerId> {
    let now = std::time::Instant::now();
    let registry = crate::p2p_admission::peer_registry();
    let mut peers = registry.committee_peer_ids(now);
    if let Some(operator_pubkey) = operator_pubkey
        && let Ok(pubkey) = bitcoin::PublicKey::from_str(operator_pubkey)
    {
        let key = crate::p2p_admission::operator_key(&bitcoin::XOnlyPublicKey::from(pubkey));
        if let Some(peer) = registry.operator_peer_for(&key)
            && !peers.contains(&peer)
        {
            peers.push(peer);
        }
    }
    let local = crate::env::get_peer_id();
    peers.retain(|peer| peer.to_string() != local);
    peers
}

/// Ask the candidates one by one until a copy validates and is stored.
pub async fn fetch_and_store_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    publisher: &NetworkPublisher,
    lookup: &GraphLookup,
) -> anyhow::Result<Option<FetchedGraph>> {
    // Already present (another path stored it meanwhile).
    if let Some(found) = local_copy(local_db, lookup).await? {
        return Ok(Some(found));
    }
    let operator_pubkey = match lookup {
        GraphLookup::Slot { operator_pubkey, .. }
        | GraphLookup::FinalizedSlot { operator_pubkey, .. } => Some(operator_pubkey.as_str()),
        GraphLookup::Id { .. } => None,
    };
    let candidates = fetch_candidates(operator_pubkey);
    if candidates.is_empty() {
        bail!("no committee or operator peer known to ask for {lookup:?}");
    }
    let mut last_error = None;
    for peer in candidates {
        let response = match publisher.request_graph(peer, lookup.request()).await {
            Ok(response) => response,
            Err(error) => {
                warn!(event = "get_graph", outcome = "request_failed", %peer, error = %error, "GetGraph request failed");
                last_error = Some(error);
                continue;
            }
        };
        let (Some(instance_id), Some(graph_id), Some(raw)) =
            (response.instance_id, response.graph_id, response.graph)
        else {
            info!(event = "get_graph", outcome = "not_found", %peer, ?lookup, "peer has no copy");
            continue;
        };
        match validate_and_store(
            local_db,
            btc_client,
            goat_client,
            lookup,
            instance_id,
            graph_id,
            raw,
        )
        .await
        {
            Ok(found) => {
                info!(event = "get_graph", outcome = "stored", %peer, graph_id = %found.graph_id, finalized = found.finalized, "stored a pulled graph definition");
                return Ok(Some(found));
            }
            Err(error) => {
                warn!(event = "get_graph", outcome = "rejected", %peer, graph_id = %graph_id, error = %error, "rejected a pulled graph definition");
                last_error = Some(error);
            }
        }
    }
    match last_error {
        Some(error) => Err(error.context("no candidate served an acceptable definition")),
        None => Ok(None),
    }
}

async fn local_copy(
    local_db: &LocalDB,
    lookup: &GraphLookup,
) -> anyhow::Result<Option<FetchedGraph>> {
    let mut storage = local_db.acquire().await?;
    let row = match lookup {
        GraphLookup::Id { graph_id, .. } => storage.find_graph(graph_id).await?,
        GraphLookup::Slot { operator_pubkey, graph_nonce }
        | GraphLookup::FinalizedSlot { operator_pubkey, graph_nonce } => {
            storage.find_graph_by_operator_slot(operator_pubkey, *graph_nonce as i64).await?
        }
    };
    let Some(row) = row else { return Ok(None) };
    let Some(graph) =
        load_validated_graph_definition(&mut storage, row.instance_id, row.graph_id).await?
    else {
        return Ok(None);
    };
    let finalized = graph.committee_pre_signed();
    if lookup.wants_finalized() && !finalized {
        // The stored copy is the operator's version; the finalized one is fetched.
        return Ok(None);
    }
    Ok(Some(FetchedGraph {
        instance_id: row.instance_id,
        graph_id: row.graph_id,
        operator_pubkey: row.operator_pubkey,
        graph_nonce: graph.parameters.graph_nonce,
        finalized,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn validate_and_store(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    lookup: &GraphLookup,
    instance_id: Uuid,
    graph_id: Uuid,
    raw: String,
) -> anyhow::Result<FetchedGraph> {
    let graph: SimplifiedBitvmGcGraph = parse_graph_raw_data(raw, graph_id).await?;
    if graph.parameters.graph_id != graph_id
        || graph.parameters.instance_parameters.instance_id != instance_id
    {
        bail!("response identifiers do not match the definition");
    }
    match lookup {
        GraphLookup::Id { instance_id: wanted_instance, graph_id: wanted_graph, .. } => {
            if *wanted_instance != instance_id || *wanted_graph != graph_id {
                bail!("response names another graph than requested");
            }
        }
        GraphLookup::Slot { operator_pubkey, graph_nonce }
        | GraphLookup::FinalizedSlot { operator_pubkey, graph_nonce } => {
            if graph.parameters.operator_pubkey.to_string() != *operator_pubkey
                || graph.parameters.graph_nonce != *graph_nonce
            {
                bail!("response names another slot than requested");
            }
        }
    }
    if lookup.wants_finalized() && !graph.committee_pre_signed() {
        bail!("response lacks the committee pre-signatures the lookup asks for");
    }
    if !graph.operator_pre_signed() {
        bail!("definition lacks operator pre-signatures");
    }
    crate::utils::validate_graph_preflight(&graph.parameters)?;
    // Bind the instance parameters to both chains before trusting anything else.
    validate_graph_instance_parameters(
        btc_client,
        goat_client,
        &graph.parameters.instance_parameters,
    )
    .await
    .context("instance parameters")?;
    let full_graph = BitvmGcGraph::from_simplified(&graph).map_err(|error| {
        crate::error::SpecialError::InvalidGraph(format!("rebuild pulled graph: {error}"))
    })?;
    verify_graph_operator_pre_signatures(&full_graph).map_err(|error| {
        crate::error::SpecialError::InvalidGraph(format!("operator pre-signatures: {error}"))
    })?;
    let posted = goat_client.gateway_get_graph_data(&graph_id).await?.operator_pubkey != [0u8; 32];
    let finalized = if graph.committee_pre_signed() {
        bitvm_lib::committee::verify_graph_committee_pre_signatures(&full_graph).map_err(
            |error| {
                crate::error::SpecialError::InvalidGraph(format!(
                    "committee pre-signatures: {error}"
                ))
            },
        )?;
        true
    } else {
        if posted {
            bail!(
                "graph {graph_id} is posted on Goat; a copy without committee pre-signatures is not acceptable"
            );
        }
        false
    };
    if finalized {
        store_finalized_graph_if_needed(local_db, &graph).await?;
    } else {
        store_operator_presigned_graph(local_db, &graph).await?;
    }
    Ok(FetchedGraph {
        instance_id,
        graph_id,
        operator_pubkey: graph.parameters.operator_pubkey.to_string(),
        graph_nonce: graph.parameters.graph_nonce,
        finalized,
    })
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::error::{FailureClass, classify_failure};
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crates/bitvm-gc/tests/fixtures/admission.rs"
    ));

    #[tokio::test]
    async fn pulled_malformed_graphs_reject_before_rebuild_and_same_id_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("pull.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        let (btc, _) = BTCClient::new_mock_client();
        let (goat, _) = GOATClient::new_mock_client();
        let parameters =
            admission_parameters(crate::env::get_network(), crate::utils::min_required_verifier());
        let graph_id = parameters.graph_id;
        let instance_id = parameters.instance_parameters.instance_id;
        let lookup = GraphLookup::Id { instance_id, graph_id, finalized: true };
        for case in 0..3 {
            let mut candidate = parameters.clone();
            if case == 0 {
                candidate.instance_parameters.committee_pubkeys.clear();
            }
            if case == 1 {
                candidate.instance_parameters.pegin_amount = bitcoin::Amount::from_sat(u64::MAX);
            }
            let raw=serde_json::json!({"parameters":candidate,"operator_pre_signed":true,"committee_pre_signed":true,"operator_pre_sigs":null,"committee_pre_sigs":null}).to_string();
            let error = validate_and_store(&db, &btc, &goat, &lookup, instance_id, graph_id, raw)
                .await
                .err()
                .unwrap();
            if case < 2 {
                assert!(
                    matches!(classify_failure(&error), FailureClass::Permanent(_)),
                    "{error:#}"
                );
            } else {
                assert!(
                    format!("{error:#}")
                        .contains("failed to load instance parameters from GoatChain"),
                    "{error:#}"
                );
            }
        }
        assert!(db.acquire().await.unwrap().find_graph(&graph_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn finalized_slot_pull_rejects_an_operator_only_copy_before_storing() {
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("pull.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        let (btc, _) = BTCClient::new_mock_client();
        let (goat, _) = GOATClient::new_mock_client();
        let parameters =
            admission_parameters(crate::env::get_network(), crate::utils::min_required_verifier());
        let graph_id = parameters.graph_id;
        let instance_id = parameters.instance_parameters.instance_id;
        let operator_pubkey = parameters.operator_pubkey.to_string();
        let graph_nonce = parameters.graph_nonce;
        let raw=serde_json::json!({"parameters":parameters,"operator_pre_signed":true,"committee_pre_signed":false,"operator_pre_sigs":null,"committee_pre_sigs":null}).to_string();
        let finalized =
            GraphLookup::FinalizedSlot { operator_pubkey: operator_pubkey.clone(), graph_nonce };
        assert!(finalized.request().finalized);
        let error =
            validate_and_store(&db, &btc, &goat, &finalized, instance_id, graph_id, raw.clone())
                .await
                .err()
                .unwrap();
        assert!(format!("{error:#}").contains("committee pre-signatures"), "{error:#}");
        assert!(db.acquire().await.unwrap().find_graph(&graph_id).await.unwrap().is_none());
        // A plain slot pull goes on to the other checks with the same copy.
        let slot = GraphLookup::Slot { operator_pubkey, graph_nonce };
        assert!(!slot.request().finalized);
        let error = validate_and_store(&db, &btc, &goat, &slot, instance_id, graph_id, raw)
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("committee pre-signatures"), "{error:#}");
    }
}
