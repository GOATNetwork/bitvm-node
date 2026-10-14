use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use commit_chain::CircuitCommit;
use header_chain::CircuitBlockHeader;
use serde::{Deserialize, Serialize};
use state_chain::CircuitStateBlock;
use std::fs;
use strum::{Display, EnumString};
use thiserror::Error;
use zkm_sdk::{HashableKey, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofWithPublicValues};
use zkm_sdk::{Prover, ZKMProofKind, ZKMProvingKey, ZKMStdin, ZKMVerifyingKey};

pub mod api_auth;
pub mod artifacts;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofRequest {
    HeaderChainProofRequest {
        init_input: bool,
        input_proof: String,
        output_proof: String,
        start: usize,
        batch_size: usize,
        total_block_headers: Vec<CircuitBlockHeader>,
    },
    CommitChainProofRequest {
        commit_info: String,
        commits: Vec<CircuitCommit>,
        init_input: bool,
        input_proof: String,
        output_proof: String,
    },
    StateChainProofRequest {
        init_input: bool,
        input_proof: String,
        output_proof: String,
        batch_size: u64,
        start: u64,
        l2_contract_addresses: String,
        blocks: Vec<CircuitStateBlock>,
    },
    WatchtowerProofRequest {
        genesis_sequencer_commit_txid: String,
        latest_sequencer_commit_txid: String,
        header_chain_input_proof: String,
        commit_chain_input_proof: String,
        state_chain_input_proof: String,
        output: String,
        target_block: Block,
        block_pos: u32,
        latest_sequencer_commit_tx: Transaction,
    },
    OperatorProofRequest {
        included_watchtowers: String,
        graph_id: [u8; 16],
        genesis_sequencer_commit_txid: String,
        header_chain_input_proof: String,
        commit_chain_input_proof: String,
        state_chain_input_proof: String,
        execution_layer_block_number: u64,
        output: String,

        target_block_ss_commit: Block,
        block_pos_ss_commit: u32,
        operator_latest_sequencer_commit_txn: Transaction,

        operator_committed_blockhash: BlockHash,

        graph_watchtower_xonly_public_keys: Vec<[u8; 32]>,
        watchtower_challenge_init_txid: Txid,
        watchtower_challenge_init_txn: Option<Transaction>,
        watchtower_challenge_witnesses: Vec<(u16, u32, Block, Transaction)>,
    },
}

#[derive(Error, Debug, Clone)]
pub enum ProofError {
    #[error("Retry after {0} seconds")]
    InputNotReady(u64),
    #[error("File {0} not found")]
    FileNotExit(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub trait ProofBuilder {
    fn client(&self) -> &ProverClient;
    fn pk(&self) -> &ZKMProvingKey;
    fn vk(&self) -> &ZKMVerifyingKey;

    /// Returns the Program ID derived from the builder's verifying key.
    fn program_id(&self) -> Result<verifier::ProgramId> {
        verifier::program_id(self.vk().bytes32().as_bytes(), ZKM_CIRCUIT_VERSION)
            .map_err(anyhow::Error::msg)
    }

    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)>;

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        input: &[u8],
        cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)>;

    fn name() -> String;
}

pub trait LongRunning {
    fn rotate(&self) -> Self;
}

/// Proves `stdin` and returns the proof, its cycles, and its execution time in
/// milliseconds: the prover's own measurement when it reports one (the GPU server's
/// `prove_ms`), otherwise the wall time of the prove call. Transfers and the CPU
/// Groth16 wrap are excluded from the GPU measurement.
pub fn prove_timed(
    client: &ProverClient,
    pk: &ZKMProvingKey,
    stdin: &ZKMStdin,
    kind: ZKMProofKind,
    elf_id: Option<String>,
) -> Result<(ZKMProofWithPublicValues, u64, f32)> {
    // Discard a measurement left by an earlier call on this client.
    let _ = client.take_prove_ms();
    let started = std::time::Instant::now();
    let (proof, cycles) = client.prove_with_cycles(pk, stdin, kind, elf_id)?;
    let wall_ms = started.elapsed().as_secs_f32() * 1000.0;
    let prove_ms = client.take_prove_ms().map_or(wall_ms, |ms| ms as f32);
    Ok((proof, cycles, prove_ms))
}

#[derive(Debug, Default)]
pub struct OnDemandTask {
    pub task_index: i64,
    pub latest_sequencer_commit_txid: String,
    pub header_chain_input_proof: String,
    pub commit_chain_input_proof: String,
    pub state_chain_input_proof: String,

    pub watchtower_challenge_init_txid: Option<String>,
    pub watchtower_challenge_txids: Vec<Option<String>>,
    pub included_watchtowers: Vec<bool>,
    pub watchtower_public_keys: Vec<String>,
    pub graph_id: Option<String>,
    pub operator_committed_blockhash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum ProofType {
    #[strum(serialize = "header_chain")]
    HeaderChain,
    #[strum(serialize = "commit_chain")]
    CommitChain,
    #[strum(serialize = "state_chain")]
    StateChain,
    Operator,
    Watchtower,
}

const HEADER_CHAIN_NAME: &str = "header-chain";
const COMMIT_CHAIN_NAME: &str = "commit-chain";
const STATE_CHAIN_NAME: &str = "state-chain";
const OPERATOR_NAME: &str = "operator";
const WATCHTOWER_NAME: &str = "watchtower";
impl ProofType {
    pub fn get_chain_name(&self) -> &'static str {
        match self {
            ProofType::HeaderChain => HEADER_CHAIN_NAME,
            ProofType::CommitChain => COMMIT_CHAIN_NAME,
            ProofType::StateChain => STATE_CHAIN_NAME,
            ProofType::Operator => OPERATOR_NAME,
            ProofType::Watchtower => WATCHTOWER_NAME,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainProofDescRequest {
    pub height: Option<i64>,
    pub proof_type: ProofType,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProofDesc {
    pub block_start: i64,
    pub block_end: i64,
    pub proof_type: String,
    pub state: String,
    pub proving_cycles: i64,
    pub proving_time: i64,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub pub_values: String,
    pub prev_proof_number: Option<i64>,
    pub next_proof_number: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct OperatorProofDescRequest {
    pub instance_id: String,
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProofDescResponse {
    pub proof_desc: Option<ProofDesc>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<String>,
    pub operator_committed_blockhash: String,
    pub execution_layer_block_number: i64,
    pub watchtower_challenge_txids: Vec<Option<String>>,
    pub included_watchtowers: Vec<bool>,
    pub watchtower_challenge_init_txid: String,
    pub watchtower_challenge_pubkeys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProofData {
    pub proof: Vec<u8>,
    pub vk: String,
    pub public_inputs: Vec<u8>,
    pub zkm_version: String,
}

impl ProofData {
    pub fn load_proof_data(path: &str, proof_type: ProofType) -> Self {
        let mut proof_data = ProofData::default();
        match proof_type {
            ProofType::HeaderChain
            | ProofType::CommitChain
            | ProofType::StateChain
            | ProofType::Watchtower
            | ProofType::Operator => {
                proof_data.proof = fs::read(path).unwrap_or_default();
                proof_data.public_inputs =
                    fs::read(format!("{path}.public_inputs.bin")).unwrap_or_default();
                proof_data.vk =
                    String::from_utf8(fs::read(format!("{path}.vk_hash.bin")).unwrap_or_default())
                        .unwrap_or_default();
                proof_data.zkm_version = String::from_utf8(
                    fs::read(format!("{path}.zkm_version.bin")).unwrap_or_default(),
                )
                .unwrap_or_default();
            }
        }
        proof_data
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofRequest {
    pub instance_id: String,
    pub graph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<String>,
    pub public_key: String,
    pub challenge_init_txid: String,
    pub execution_layer_block_number: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofResponse {
    pub proof_data: Option<ProofData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofTimeoutUpdateRequest {
    pub instance_id: String,
    pub graph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OperatorProofTimeoutUpdateResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub data: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofTimeoutUpdateRequest {
    pub instance_id: String,
    pub graph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchtowerProofTimeoutUpdateResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub public_key: String,
    pub data: Option<String>,
    pub error: Option<String>,
}
