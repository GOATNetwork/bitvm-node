//! Mock proof builder for the localnet (`mock-gc` only).
//!
//! Serves the exact HTTP routes and JSON the bitvm-noded Operator and Watchtower call, returning
//! proof data the node accepts. It performs *no* real proving: the operator proof is the repo's
//! real Groth16 fixture with its 96 public-value bytes re-patched to match the request (so the
//! node's `convert_ark_imm_wrap_vk` decoding, vk-hash, version and constant checks all pass), and
//! the watchtower proof is dummy bytes of the exact lengths the node validates.
//!
//! Realistic waiting: for each `(kind, graph, ...)` the first request is recorded, and the builder
//! answers `{"proof_data": null, "error": "..."}` until the configured delay has elapsed, then
//! serves the proof. The delay is a "ready_at" timestamp, never a slow HTTP response (the node has
//! no request timeout and dispatches messages one at a time).
//!
//! Auth headers are accepted without verification (logged at debug).
//!
//! ## Environment
//! - `MOCK_PROOF_DELAY_SECS`            default "not ready" window for every proof (default 0)
//! - `MOCK_PROOF_OPERATOR_DELAY_SECS`   override for operator proofs
//! - `MOCK_PROOF_WATCHTOWER_DELAY_SECS` override for watchtower proofs
//! - `MOCK_PROOF_RESPONSE_LATENCY_MS`   optional artificial per-response latency (default 0; keep small)
//! - `GENESIS_SEQUENCER_COMMIT_TXID`    REQUIRED for operator proofs (same value as the nodes)
//! - `MOCK_PROOF_OPERATOR_VK`           operator proof vk-hash string (default = fixture vk)
//! - `MOCK_PROOF_OPERATOR_ZKM_VERSION`  operator proof Ziren version (default = fixture version)
//! - `MOCK_PROOF_WATCHTOWER_VK`         watchtower proof vk-hash string (default documented value)
//! - `MOCK_PROOF_WATCHTOWER_ZKM_VERSION`watchtower proof Ziren version (default "v1.2.7")

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use clap::Parser;
use proof_builder::{
    OperatorProofRequest, OperatorProofResponse, ProofData, ProofDescResponse,
    WatchtowerProofRequest, WatchtowerProofResponse, WatchtowerProofTimeoutUpdateRequest,
    WatchtowerProofTimeoutUpdateResponse,
};
use zkm_sdk::{ZKMProofWithPublicValues, ZKMPublicValues};

/// Real Groth16 operator-proof fixture (bincode `ZKMProofWithPublicValues`, 1498 bytes). Only its
/// 96 public-value bytes are re-patched per request; all curve points stay valid.
const OPERATOR_PROOF_FIXTURE: &[u8] = include_bytes!("../../testdata/test-operator-proof.bin");
/// vk-hash string matching the fixture (see the `assert_ready_extracts_blake3_xd_from_operator_proof` test).
const DEFAULT_OPERATOR_VK: &str =
    "0x00ba1ff974eb6e5890f238f8a11c1aeff2d5f4a68a860274bcb602c3c5c681b7";
/// A valid 66-char vk-hash string for the watchtower proof (only the length/format is checked).
const DEFAULT_WATCHTOWER_VK: &str =
    "0x0074ea3cc3dc181f156a1808459846d54700a7c4b2f6fd58a18499f2d7910e58";
const WATCHTOWER_PROOF_SIZE: usize = 260;
const WATCHTOWER_PUBLIC_INPUTS_SIZE: usize = 36;

#[derive(Parser, Debug)]
#[command(name = "mock-proof-builder", about = "Localnet mock proof builder for bitvm-noded")]
struct Args {
    /// Address to listen on. Keep it path-less so the node's URL joins agree.
    #[arg(long, default_value = "127.0.0.1:22950")]
    listen: SocketAddr,
}

struct AppState {
    /// First-seen instant per proof task key -> used to gate readiness.
    seen: Mutex<HashMap<String, Instant>>,
    /// Watchtower task keys marked failed by the timeout endpoint (stay "not ready" forever).
    failed_watchtower: Mutex<HashSet<String>>,
    /// Pre-parsed operator proof template.
    operator_template: ZKMProofWithPublicValues,
    operator_vk: String,
    operator_zkm_version: String,
    watchtower_vk: String,
    watchtower_zkm_version: String,
    /// Internal-byte-order genesis txid, required to compute the operator constant.
    genesis_txid_internal: Option<[u8; 32]>,
}

fn env_secs(name: &str) -> Option<Duration> {
    let secs = std::env::var(name).ok()?.trim().parse::<f64>().ok()?;
    (secs.is_finite() && secs > 0.0).then(|| Duration::from_secs_f64(secs))
}

fn operator_delay() -> Duration {
    env_secs("MOCK_PROOF_OPERATOR_DELAY_SECS")
        .or_else(|| env_secs("MOCK_PROOF_DELAY_SECS"))
        .unwrap_or(Duration::ZERO)
}

fn watchtower_delay() -> Duration {
    env_secs("MOCK_PROOF_WATCHTOWER_DELAY_SECS")
        .or_else(|| env_secs("MOCK_PROOF_DELAY_SECS"))
        .unwrap_or(Duration::ZERO)
}

async fn response_latency() {
    let ms = std::env::var("MOCK_PROOF_RESPONSE_LATENCY_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

/// Records the first-seen time for `key` and reports whether `delay` has elapsed since then.
fn task_ready(state: &AppState, key: &str, delay: Duration) -> bool {
    let mut seen = state.seen.lock().expect("seen mutex poisoned");
    let first = seen.entry(key.to_string()).or_insert_with(Instant::now);
    first.elapsed() >= delay
}

fn log_auth_headers(kind: &str, headers: &HeaderMap) {
    let pubkey =
        headers.get("x-proof-auth-public-key").and_then(|v| v.to_str().ok()).unwrap_or("<none>");
    tracing::debug!(
        kind,
        auth_public_key = pubkey,
        "accepting proof request without auth verification"
    );
}

/// Parse a 64-hex display txid/blockhash into internal (reversed) byte order.
fn display_hex_to_internal(display: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(display.trim_start_matches("0x")).ok()?;
    let mut bytes: [u8; 32] = raw.try_into().ok()?;
    bytes.reverse();
    Some(bytes)
}

/// Compute the 96-byte operator guest public values for a request:
/// `btc_best_block_hash(internal) || operator_constant || included_watchtowers_bitmap`.
fn build_operator_public_values(
    state: &AppState,
    req: &OperatorProofRequest,
) -> Result<[u8; 96], String> {
    let genesis = state
        .genesis_txid_internal
        .ok_or_else(|| "GENESIS_SEQUENCER_COMMIT_TXID is not set".to_string())?;

    let graph_uuid =
        uuid::Uuid::parse_str(&req.graph_id).map_err(|e| format!("invalid graph_id: {e}"))?;
    let graph_id_bytes = *graph_uuid.as_bytes();

    let wci_internal = display_hex_to_internal(&req.watchtower_challenge_init_txid)
        .ok_or_else(|| "invalid watchtower_challenge_init_txid".to_string())?;

    let mut xonly_keys = Vec::with_capacity(req.watchtower_challenge_pubkeys.len());
    for key in &req.watchtower_challenge_pubkeys {
        let raw = hex::decode(key.trim_start_matches("0x"))
            .map_err(|e| format!("invalid watchtower pubkey hex: {e}"))?;
        // 33-byte compressed key -> drop the parity prefix to get the 32-byte x-only key.
        let xonly: [u8; 32] = raw
            .get(raw.len().saturating_sub(32)..)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "watchtower pubkey is too short".to_string())?;
        xonly_keys.push(xonly);
    }

    let constant = bitcoin_light_client_circuit::hash_operator_constant(
        graph_id_bytes,
        genesis,
        wci_internal,
        &xonly_keys,
    );

    let blockhash = display_hex_to_internal(&req.operator_committed_blockhash)
        .ok_or_else(|| "invalid operator_committed_blockhash".to_string())?;

    let mut bitmap = [0u8; 32];
    for (i, included) in req.included_watchtowers.iter().enumerate() {
        if *included && i < 256 {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }

    let mut pubin = [0u8; 96];
    pubin[..32].copy_from_slice(&blockhash);
    pubin[32..64].copy_from_slice(&constant);
    pubin[64..].copy_from_slice(&bitmap);
    Ok(pubin)
}

fn operator_proof_data(state: &AppState, req: &OperatorProofRequest) -> Result<ProofData, String> {
    let public_values = build_operator_public_values(state, req)?;
    let mut proof = state.operator_template.clone();
    proof.public_values = ZKMPublicValues::from(&public_values);
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| format!("failed to serialize patched operator proof: {e}"))?;
    Ok(ProofData {
        proof: proof_bytes,
        vk: state.operator_vk.clone(),
        public_inputs: public_values.to_vec(),
        zkm_version: state.operator_zkm_version.clone(),
    })
}

fn watchtower_proof_data(state: &AppState, key: &str) -> ProofData {
    // Deterministic dummy bytes of exactly the lengths the node validates; content is not checked.
    let seed = {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        d
    };
    let mut proof = Vec::with_capacity(WATCHTOWER_PROOF_SIZE);
    while proof.len() < WATCHTOWER_PROOF_SIZE {
        proof.extend_from_slice(&seed);
    }
    proof.truncate(WATCHTOWER_PROOF_SIZE);
    let mut public_inputs = Vec::with_capacity(WATCHTOWER_PUBLIC_INPUTS_SIZE);
    while public_inputs.len() < WATCHTOWER_PUBLIC_INPUTS_SIZE {
        public_inputs.extend_from_slice(&seed);
    }
    public_inputs.truncate(WATCHTOWER_PUBLIC_INPUTS_SIZE);
    ProofData {
        proof,
        vk: state.watchtower_vk.clone(),
        public_inputs,
        zkm_version: state.watchtower_zkm_version.clone(),
    }
}

async fn handle_operator_proof(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<OperatorProofRequest>,
) -> Json<OperatorProofResponse> {
    log_auth_headers("operator", &headers);
    response_latency().await;
    let key = format!("operator:{}:{}", req.instance_id, req.graph_id);
    if !task_ready(&state, &key, operator_delay()) {
        return Json(OperatorProofResponse {
            proof_data: None,
            error: Some("operator proof is not ready".to_string()),
        });
    }
    match operator_proof_data(&state, &req) {
        Ok(proof_data) => {
            tracing::info!(graph_id = %req.graph_id, "serving mock operator proof");
            Json(OperatorProofResponse { proof_data: Some(proof_data), error: None })
        }
        Err(error) => {
            tracing::warn!(graph_id = %req.graph_id, %error, "cannot build mock operator proof");
            Json(OperatorProofResponse { proof_data: None, error: Some(error) })
        }
    }
}

async fn handle_watchtower_proof(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WatchtowerProofRequest>,
) -> Json<WatchtowerProofResponse> {
    log_auth_headers("watchtower", &headers);
    response_latency().await;
    let key = format!("watchtower:{}:{}:{}", req.instance_id, req.graph_id, req.public_key);
    if state.failed_watchtower.lock().expect("failed set poisoned").contains(&key) {
        return Json(WatchtowerProofResponse {
            proof_data: None,
            error: Some("watchtower proof task was marked failed".to_string()),
        });
    }
    if !task_ready(&state, &key, watchtower_delay()) {
        return Json(WatchtowerProofResponse {
            proof_data: None,
            error: Some("watchtower proof is not ready".to_string()),
        });
    }
    tracing::info!(graph_id = %req.graph_id, "serving mock watchtower proof");
    Json(WatchtowerProofResponse {
        proof_data: Some(watchtower_proof_data(&state, &key)),
        error: None,
    })
}

async fn handle_watchtower_timeout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WatchtowerProofTimeoutUpdateRequest>,
) -> Json<WatchtowerProofTimeoutUpdateResponse> {
    log_auth_headers("watchtower-timeout", &headers);
    let key = format!("watchtower:{}:{}:{}", req.instance_id, req.graph_id, req.public_key);
    state.failed_watchtower.lock().expect("failed set poisoned").insert(key);
    Json(WatchtowerProofTimeoutUpdateResponse {
        instance_id: req.instance_id,
        graph_id: req.graph_id,
        public_key: req.public_key,
        data: Some("1 rows affected".to_string()),
        error: None,
    })
}

async fn handle_proof_desc() -> Json<ProofDescResponse> {
    Json(ProofDescResponse { proof_desc: None, error: Some("No proof found".to_string()) })
}

async fn handle_root() -> &'static str {
    "Hello, World!"
}

fn build_state() -> AppState {
    let operator_template: ZKMProofWithPublicValues = bincode::deserialize(OPERATOR_PROOF_FIXTURE)
        .expect("embedded operator proof fixture must deserialize");
    let operator_zkm_version = std::env::var("MOCK_PROOF_OPERATOR_ZKM_VERSION")
        .unwrap_or_else(|_| operator_template.zkm_version.clone());
    let operator_vk =
        std::env::var("MOCK_PROOF_OPERATOR_VK").unwrap_or_else(|_| DEFAULT_OPERATOR_VK.to_string());
    let watchtower_vk = std::env::var("MOCK_PROOF_WATCHTOWER_VK")
        .unwrap_or_else(|_| DEFAULT_WATCHTOWER_VK.to_string());
    let watchtower_zkm_version =
        std::env::var("MOCK_PROOF_WATCHTOWER_ZKM_VERSION").unwrap_or_else(|_| "v1.2.7".to_string());

    let genesis_txid_internal = match std::env::var("GENESIS_SEQUENCER_COMMIT_TXID") {
        Ok(value) => match display_hex_to_internal(&value) {
            Some(bytes) => Some(bytes),
            None => {
                tracing::warn!(
                    "GENESIS_SEQUENCER_COMMIT_TXID is set but not a 32-byte hex txid; operator proofs will fail"
                );
                None
            }
        },
        Err(_) => {
            tracing::warn!(
                "GENESIS_SEQUENCER_COMMIT_TXID is not set; operator proofs cannot be served until it is"
            );
            None
        }
    };

    AppState {
        seen: Mutex::new(HashMap::new()),
        failed_watchtower: Mutex::new(HashSet::new()),
        operator_template,
        operator_vk,
        operator_zkm_version,
        watchtower_vk,
        watchtower_zkm_version,
        genesis_txid_internal,
    }
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(handle_root))
        .route("/v1/proofs/operator_proofs", post(handle_operator_proof))
        .route("/v1/proofs/watchtower_proofs", post(handle_watchtower_proof))
        .route("/v1/proofs/watchtower_proofs_timeout", post(handle_watchtower_timeout))
        .route("/v1/proofs/chain_proofs_desc", get(handle_proof_desc))
        .route("/v1/proofs/operator_proofs_desc", get(handle_proof_desc))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let state = Arc::new(build_state());
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, "mock proof builder listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        let operator_template: ZKMProofWithPublicValues =
            bincode::deserialize(OPERATOR_PROOF_FIXTURE).unwrap();
        AppState {
            seen: Mutex::new(HashMap::new()),
            failed_watchtower: Mutex::new(HashSet::new()),
            operator_template,
            operator_vk: DEFAULT_OPERATOR_VK.to_string(),
            operator_zkm_version: "v1.2.5".to_string(),
            watchtower_vk: DEFAULT_WATCHTOWER_VK.to_string(),
            watchtower_zkm_version: "v1.2.7".to_string(),
            genesis_txid_internal: Some([7u8; 32]),
        }
    }

    fn sample_operator_request() -> OperatorProofRequest {
        OperatorProofRequest {
            instance_id: "11111111-1111-1111-1111-111111111111".to_string(),
            graph_id: "22222222-2222-2222-2222-222222222222".to_string(),
            gateway_address: None,
            operator_committed_blockhash: "aa".repeat(32),
            execution_layer_block_number: 5,
            watchtower_challenge_txids: vec![Some("bb".repeat(32))],
            included_watchtowers: vec![true],
            watchtower_challenge_init_txid: "cc".repeat(32),
            watchtower_challenge_pubkeys: vec![format!("02{}", "dd".repeat(32))],
        }
    }

    #[test]
    fn readiness_gate_defers_then_serves() {
        let state = test_state();
        let key = "operator:i:g";
        // With a positive delay the first look is not ready; with zero delay it is ready.
        assert!(!task_ready(&state, key, Duration::from_secs(3600)));
        assert!(task_ready(&state, "operator:i:g2", Duration::ZERO));
    }

    #[test]
    fn operator_proof_reencodes_and_is_node_decodable() {
        let state = test_state();
        let req = sample_operator_request();
        let data = operator_proof_data(&state, &req).expect("operator proof data");
        assert_eq!(data.vk, DEFAULT_OPERATOR_VK);
        assert_eq!(data.public_inputs.len(), 96);
        // The node deserializes the proof bytes back into a ZKMProofWithPublicValues.
        let proof: ZKMProofWithPublicValues = bincode::deserialize(&data.proof).unwrap();
        assert_eq!(proof.public_values.as_slice(), data.public_inputs.as_slice());
        // public_values[32..64] is the operator constant computed from the request fields.
        let expected = build_operator_public_values(&state, &req).unwrap();
        assert_eq!(proof.public_values.as_slice(), &expected);
    }

    #[test]
    fn operator_proof_requires_genesis_txid() {
        let mut state = test_state();
        state.genesis_txid_internal = None;
        let err = operator_proof_data(&state, &sample_operator_request()).unwrap_err();
        assert!(err.contains("GENESIS_SEQUENCER_COMMIT_TXID"));
    }

    #[test]
    fn watchtower_proof_has_expected_lengths() {
        let state = test_state();
        let data = watchtower_proof_data(&state, "watchtower:i:g:pk");
        assert_eq!(data.proof.len(), WATCHTOWER_PROOF_SIZE);
        assert_eq!(data.public_inputs.len(), WATCHTOWER_PUBLIC_INPUTS_SIZE);
        assert_eq!(data.vk.len(), 66);
        assert!(!data.zkm_version.is_empty());
    }
}
