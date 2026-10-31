#![allow(clippy::collapsible_match)]
#![allow(clippy::single_match)]
#![allow(clippy::collapsible_else_if)]

use crate::env::{
    get_local_node_info, get_p2p_graph_setup_retry_interval_secs,
    get_p2p_graph_setup_retry_window_secs, get_p2p_inbox_batch_size, get_p2p_outbox_batch_size,
};
use crate::handle::{
    HandlerContext, HeavyTaskContext, dispatch as handle_dispatch, heavy_task_from_content,
    is_heavy_task_message_type, run_heavy_task,
};
use crate::metrics_service::MetricsState;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::utils::*;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::{PublicKey, Txid, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::{BabeBundleBuilder, CACSetupPackage};
use bitvm_lib::committee::*;
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use client::goat_chain::DisproveTxType;
use client::http_client::async_client::HttpAsyncClient;
use client::{
    btc_chain::{BTCClient, BtcRpcTimeoutError},
    goat_chain::GOATClient,
};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use secp256k1::{
    Keypair, Message as SecpMessage, SECP256K1, schnorr::Signature as SchnorrSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use store::localdb::LocalDB;
use store::{MessageState, P2pInboxMessage};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: GOATMessageContent,
}

const GOAT_MESSAGE_BIN_PREFIX: &[u8] = b"GOATBIN1";
const TRANSIENT_PEGIN_RETRY_DELAY_SECS: usize = 30;
const P2P_INBOX_LEASE_SECS: i64 = 5 * 60;
const P2P_INBOX_LEASE_RENEW_INTERVAL_SECS: u64 = 60;
const P2P_INBOX_ENQUEUE_ATTEMPTS: usize = 3;

/// Delivery semantics for externally received P2P messages.
///
/// Protocol-state messages remain durable. Ephemeral messages carry
/// recoverable peer state or graph synchronization data and can be resent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2PMessageDelivery {
    Inbox,
    Immediate,
}

struct ActiveHeavyTask {
    message_id: String,
    lease_token: String,
}

static ACTIVE_HEAVY_TASK: LazyLock<Mutex<Option<ActiveHeavyTask>>> =
    LazyLock::new(|| Mutex::new(None));

struct HeavyTaskPermit {
    message_id: String,
    lease_token: String,
}

impl Drop for HeavyTaskPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_HEAVY_TASK.lock()
            && active.as_ref().is_some_and(|active| {
                active.message_id == self.message_id && active.lease_token == self.lease_token
            })
        {
            *active = None;
        }
    }
}

fn active_heavy_task_message_ids() -> Vec<String> {
    ACTIVE_HEAVY_TASK
        .lock()
        .ok()
        .and_then(|active| active.as_ref().map(|active| vec![active.message_id.clone()]))
        .unwrap_or_default()
}

fn try_acquire_heavy_task_permit(message_id: &str, lease_token: &str) -> Option<HeavyTaskPermit> {
    let mut active = ACTIVE_HEAVY_TASK.lock().ok()?;
    if active.is_some() {
        return None;
    }
    *active = Some(ActiveHeavyTask {
        message_id: message_id.to_owned(),
        lease_token: lease_token.to_owned(),
    });
    Some(HeavyTaskPermit { message_id: message_id.to_owned(), lease_token: lease_token.to_owned() })
}

/// Stable retry categories shared by P2P inbox consumers and protocol
/// handlers. A handler must opt into retrying; all other failures are treated
/// as terminal and retained as `Failed` inbox records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryableDispatchReason {
    StorageBusy,
    ExternalRpcUnavailable,
    PayloadNotReady,
    DependencyPending,
    PublishFailed,
    ResourceLocked,
}

impl RetryableDispatchReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::StorageBusy => "storage_busy",
            Self::ExternalRpcUnavailable => "external_rpc_unavailable",
            Self::PayloadNotReady => "payload_not_ready",
            Self::DependencyPending => "dependency_pending",
            Self::PublishFailed => "publish_failed",
            Self::ResourceLocked => "resource_locked",
        }
    }
}

#[derive(Debug)]
pub struct RetryableDispatchError {
    pub reason: RetryableDispatchReason,
    pub retry_after_secs: Option<i64>,
    detail: String,
}

impl fmt::Display for RetryableDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "retryable {}: {}", self.reason.code(), self.detail)
    }
}

impl std::error::Error for RetryableDispatchError {}

pub fn retryable_dispatch_error(
    reason: RetryableDispatchReason,
    retry_after_secs: Option<i64>,
    detail: impl fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(RetryableDispatchError {
        reason,
        retry_after_secs,
        detail: detail.to_string(),
    })
}

fn is_retryable_http_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

fn is_retryable_reqwest_error(error: &reqwest::Error) -> bool {
    error.is_timeout()
        || error.is_connect()
        || error.status().is_some_and(|status| is_retryable_http_status(status.as_u16()))
}

/// Only classify transport-level RPC failures. Contract reverts, malformed
/// responses and application errors are intentionally left terminal.
fn is_retryable_external_rpc_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            return is_retryable_reqwest_error(error);
        }
        if cause.downcast_ref::<BtcRpcTimeoutError>().is_some() {
            return true;
        }
        if let Some(error) = cause.downcast_ref::<esplora_client::Error>() {
            return match error {
                // esplora-client uses reqwest 0.11 while this crate uses
                // reqwest 0.12, so this check must remain inline instead of
                // sharing the 0.12 helper above.
                esplora_client::Error::Reqwest(error) => {
                    error.is_timeout()
                        || error.is_connect()
                        || error
                            .status()
                            .is_some_and(|status| is_retryable_http_status(status.as_u16()))
                }
                esplora_client::Error::HttpResponse { status, .. } => {
                    is_retryable_http_status(*status)
                }
                _ => false,
            };
        }
        if let Some(error) = cause.downcast_ref::<alloy::transports::TransportError>() {
            // GOAT uses an HTTP Alloy provider. A transport error means the
            // request did not receive a valid RPC result; RPC ErrorResp is
            // deliberately excluded by this predicate.
            return error.is_transport_error();
        }
        false
    })
}

fn classify_retryable_dispatch_error(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| cause.downcast_ref::<RetryableDispatchError>().is_some())
        || !is_retryable_external_rpc_error(&error)
    {
        return error;
    }
    retryable_dispatch_error(RetryableDispatchReason::ExternalRpcUnavailable, None, error)
}

#[derive(Clone, Copy, Debug)]
pub enum MessageDeferReason {
    TransientStorageRetry,
    RecoveryRepublish,
    PreviousGraphPending,
    CommitteeNoncesPending,
    CommitteeNonceConsensusPending,
    CommitteeEndorsementsPending,
    BitcoinTransactionPending,
    BitcoinConfirmationPending,
    GoatSpvPending,
    ProofPending,
    ProtocolInputsPending,
    TimelockPending,
    WithdrawKickoffPending,
    ChainStatePending,
    ValidationRetry,
    GraphSyncPending,
    HandlerError,
}

impl MessageDeferReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TransientStorageRetry => "transient_storage_retry",
            Self::RecoveryRepublish => "recovery_republish",
            Self::PreviousGraphPending => "previous_graph_pending",
            Self::CommitteeNoncesPending => "committee_nonces_pending",
            Self::CommitteeNonceConsensusPending => "committee_nonce_consensus_pending",
            Self::CommitteeEndorsementsPending => "committee_endorsements_pending",
            Self::BitcoinTransactionPending => "bitcoin_transaction_pending",
            Self::BitcoinConfirmationPending => "bitcoin_confirmation_pending",
            Self::GoatSpvPending => "goat_spv_pending",
            Self::ProofPending => "proof_pending",
            Self::ProtocolInputsPending => "protocol_inputs_pending",
            Self::TimelockPending => "timelock_pending",
            Self::WithdrawKickoffPending => "withdraw_kickoff_pending",
            Self::ChainStatePending => "chain_state_pending",
            Self::ValidationRetry => "validation_retry",
            Self::GraphSyncPending => "graph_sync_pending",
            Self::HandlerError => "handler_error",
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum GOATMessageContent {
    PeginRequest(PeginRequest),
    CreateGraph(CreateGraph),
    ConfirmInstance(ConfirmInstance),
    InitGraph(InitGraph),
    GenCircuits(GenCircuits),
    CutCircuits(CutCircuits),
    SolderingProofReady(SolderingProofReady),
    GraphSetupAck(GraphSetupAck),
    VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement),
    NonceGeneration(NonceGeneration),
    AggNonceConsensus(AggNonceConsensus),
    CommitteePresign(CommitteePresign),
    EndorseGraph(EndorseGraph),
    GraphFinalize(GraphFinalize),
    PeginConfirmNonce(PeginConfirmNonce),
    PeginConfirmNonceConsensus(PeginConfirmNonceConsensus),
    PeginConfirmPartialSig(PeginConfirmPartialSig),
    PostReady(PostReady),
    KickoffReady(KickoffReady),
    KickoffSent(KickoffSent),
    PreKickoffSent(PreKickoffSent),
    ChallengeSent(ChallengeSent),
    WatchtowerChallengeInitSent(WatchtowerChallengeInitSent),
    WatchtowerChallengeSent(WatchtowerChallengeSent),
    WatchtowerChallengeTimeout(WatchtowerChallengeTimeout),
    NackReady(NackReady),
    OperatorCommitPubinReady(OperatorCommitPubinReady),
    OperatorCommitPubinTimeout(OperatorCommitPubinTimeout),
    AssertReady(AssertReady),
    AssertSent(AssertSent),
    ChallengeAssertSent(ChallengeAssertSent),
    WronglyChallengeTimeout(WronglyChallengeTimeout),
    DisproveSent(DisproveSent),
    Take1Ready(Take1Ready),
    Take1Sent(Take1Sent),
    Take2Ready(Take2Ready),
    Take2Sent(Take2Sent),
    RequestNodeInfo(NodeInfo),
    ResponseNodeInfo(NodeInfo),
    SyncGraphRequest(SyncGraphRequest),
    SyncGraph(SyncGraph),
    InstanceDiscarded(InstanceDiscarded),
    Tick,
}

impl GOATMessageContent {
    /// New messages default to the durable inbox and must explicitly opt into
    /// immediate processing when they are safe to drop.
    pub const fn p2p_delivery(&self) -> P2PMessageDelivery {
        match self {
            Self::RequestNodeInfo(_)
            | Self::ResponseNodeInfo(_)
            | Self::SyncGraphRequest(_)
            | Self::SyncGraph(_)
            | Self::GraphSetupAck(_) => P2PMessageDelivery::Immediate,
            _ => P2PMessageDelivery::Inbox,
        }
    }

    /// Stable message name for logs/metrics.  Keep this independent of `Debug`, whose
    /// output can include protocol payloads (and, for proofs, be very large).
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::PeginRequest(_) => "PeginRequest",
            Self::CreateGraph(_) => "CreateGraph",
            Self::ConfirmInstance(_) => "ConfirmInstance",
            Self::InitGraph(_) => "InitGraph",
            Self::GenCircuits(_) => "GenCircuits",
            Self::CutCircuits(_) => "CutCircuits",
            Self::SolderingProofReady(_) => "SolderingProofReady",
            Self::GraphSetupAck(_) => "GraphSetupAck",
            Self::VerifierGraphParamsEndorsement(_) => "VerifierGraphParamsEndorsement",
            Self::NonceGeneration(_) => "NonceGeneration",
            Self::AggNonceConsensus(_) => "AggNonceConsensus",
            Self::CommitteePresign(_) => "CommitteePresign",
            Self::EndorseGraph(_) => "EndorseGraph",
            Self::GraphFinalize(_) => "GraphFinalize",
            Self::PeginConfirmNonce(_) => "PeginConfirmNonce",
            Self::PeginConfirmNonceConsensus(_) => "PeginConfirmNonceConsensus",
            Self::PeginConfirmPartialSig(_) => "PeginConfirmPartialSig",
            Self::PostReady(_) => "PostReady",
            Self::KickoffReady(_) => "KickoffReady",
            Self::KickoffSent(_) => "KickoffSent",
            Self::PreKickoffSent(_) => "PreKickoffSent",
            Self::ChallengeSent(_) => "ChallengeSent",
            Self::WatchtowerChallengeInitSent(_) => "WatchtowerChallengeInitSent",
            Self::WatchtowerChallengeSent(_) => "WatchtowerChallengeSent",
            Self::WatchtowerChallengeTimeout(_) => "WatchtowerChallengeTimeout",
            Self::NackReady(_) => "NackReady",
            Self::OperatorCommitPubinReady(_) => "OperatorCommitPubinReady",
            Self::OperatorCommitPubinTimeout(_) => "OperatorCommitPubinTimeout",
            Self::AssertReady(_) => "AssertReady",
            Self::AssertSent(_) => "AssertSent",
            Self::ChallengeAssertSent(_) => "ChallengeAssertSent",
            Self::WronglyChallengeTimeout(_) => "WronglyChallengeTimeout",
            Self::DisproveSent(_) => "DisproveSent",
            Self::Take1Ready(_) => "Take1Ready",
            Self::Take1Sent(_) => "Take1Sent",
            Self::Take2Ready(_) => "Take2Ready",
            Self::Take2Sent(_) => "Take2Sent",
            Self::RequestNodeInfo(_) => "RequestNodeInfo",
            Self::ResponseNodeInfo(_) => "ResponseNodeInfo",
            Self::SyncGraphRequest(_) => "SyncGraphRequest",
            Self::SyncGraph(_) => "SyncGraph",
            Self::InstanceDiscarded(_) => "InstanceDiscarded",
            Self::Tick => "Tick",
        }
    }

    fn pegin_retry_business_id(&self) -> Option<Uuid> {
        match self {
            Self::PeginRequest(message) => Some(message.instance_id),
            Self::ConfirmInstance(message) => Some(message.instance_id),
            Self::CreateGraph(message) => Some(message.graph_id),
            Self::InitGraph(message) => Some(message.graph_id),
            Self::GenCircuits(message) => Some(message.graph_id),
            Self::CutCircuits(message) => Some(message.graph_id),
            Self::SolderingProofReady(message) => Some(message.graph_id),
            Self::VerifierGraphParamsEndorsement(message) => Some(message.graph_id),
            Self::NonceGeneration(message) => Some(message.graph_id),
            Self::AggNonceConsensus(message) => Some(message.graph_id),
            Self::CommitteePresign(message) => Some(message.graph_id),
            Self::EndorseGraph(message) => Some(message.graph_id),
            Self::GraphFinalize(message) => Some(message.graph_id),
            Self::PeginConfirmNonce(message) => Some(message.instance_id),
            Self::PeginConfirmNonceConsensus(message) => Some(message.instance_id),
            Self::PeginConfirmPartialSig(message) => Some(message.instance_id),
            Self::PostReady(message) => Some(message.instance_id),
            _ => None,
        }
    }
}

fn is_retryable_sqlite_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("database is locked")
            || message.contains("database is busy")
            || message.contains("sqlite_busy")
    })
}

fn is_pegin_message_type(message_type: &str) -> bool {
    matches!(
        message_type,
        "PeginRequest"
            | "ConfirmInstance"
            | "CreateGraph"
            | "InitGraph"
            | "GenCircuits"
            | "CutCircuits"
            | "SolderingProof"
            | "SolderingProofReady"
            | "VerifierGraphParamsEndorsement"
            | "NonceGeneration"
            | "AggNonceConsensus"
            | "CommitteePresign"
            | "EndorseGraph"
            | "GraphFinalize"
            | "PeginConfirmNonce"
            | "PeginConfirmNonceConsensus"
            | "PeginConfirmPartialSig"
            | "PostReady"
    )
}

/// Pegin

#[derive(Serialize, Deserialize, Clone)]
pub struct PeginRequest {
    pub instance_id: Uuid,
    pub pegin_request_tx_hash: String, // goat tx hash
    pub pegin_request_height: i64,
    pub pegin_timestamp: i64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ConfirmInstance {
    pub instance_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct InitGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_pubkey: PublicKey,
    pub operator_peer_id: Vec<u8>,
    pub signature: SchnorrSignature,
}

const INIT_GRAPH_SIGNATURE_DOMAIN: &[u8] = b"bitvm2-node/init-graph/v1";

fn init_graph_signature_message(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_pubkey: &PublicKey,
    operator_peer_id: &[u8],
) -> SecpMessage {
    let mut hasher = Sha256::new();
    hasher.update(INIT_GRAPH_SIGNATURE_DOMAIN);
    hasher.update(instance_id.as_bytes());
    hasher.update(graph_id.as_bytes());
    hasher.update(operator_pubkey.to_bytes());
    hasher.update((operator_peer_id.len() as u32).to_be_bytes());
    hasher.update(operator_peer_id);
    SecpMessage::from_digest(hasher.finalize().into())
}

pub fn sign_init_graph(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_keypair: &Keypair,
    operator_peer_id: Vec<u8>,
) -> InitGraph {
    let operator_pubkey = operator_keypair.public_key().into();
    let signature = SECP256K1.sign_schnorr(
        &init_graph_signature_message(instance_id, graph_id, &operator_pubkey, &operator_peer_id),
        operator_keypair,
    );
    InitGraph { instance_id, graph_id, operator_pubkey, operator_peer_id, signature }
}

pub fn verify_init_graph_signature(message: &InitGraph) -> bool {
    SECP256K1
        .verify_schnorr(
            &message.signature,
            &init_graph_signature_message(
                message.instance_id,
                message.graph_id,
                &message.operator_pubkey,
                &message.operator_peer_id,
            ),
            &XOnlyPublicKey::from(message.operator_pubkey),
        )
        .is_ok()
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GenCircuits {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub setup_package: CACSetupPackage,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CutCircuits {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub candidate_index: usize,
    pub selected_circuit_indexes: Vec<usize>,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SolderingProofReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub candidate_index: usize,
    pub payload_hash: [u8; 32],
    pub total_len: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum GraphSetupStage {
    GenCircuits,
    CutCircuits,
    SolderingProofReady,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphSetupAck {
    pub outbox_id: String,
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub stage: GraphSetupStage,
    pub acknowledger_peer_id: String,
}

pub fn graph_setup_outbox_id(content: &GOATMessageContent) -> Option<String> {
    match content {
        GOATMessageContent::InitGraph(message) => Some(format!("init-graph:{}", message.graph_id)),
        GOATMessageContent::GenCircuits(message) => Some(format!(
            "gen-circuits:{}:{}:{}",
            message.instance_id, message.graph_id, message.verifier_pubkey
        )),
        GOATMessageContent::CutCircuits(message) => Some(format!(
            "cut-circuits:{}:{}:{}",
            message.instance_id, message.graph_id, message.verifier_pubkey
        )),
        GOATMessageContent::SolderingProofReady(message) => Some(format!(
            "soldering-proof-ready:{}:{}:{}",
            message.graph_id,
            message.candidate_index,
            hex::encode(message.payload_hash),
        )),
        _ => None,
    }
}

fn graph_setup_ack(content: &GOATMessageContent) -> Option<GraphSetupAck> {
    let (instance_id, graph_id, stage) = match content {
        GOATMessageContent::GenCircuits(message) => {
            (message.instance_id, message.graph_id, GraphSetupStage::GenCircuits)
        }
        GOATMessageContent::CutCircuits(message) => {
            (message.instance_id, message.graph_id, GraphSetupStage::CutCircuits)
        }
        GOATMessageContent::SolderingProofReady(message) => {
            (message.instance_id, message.graph_id, GraphSetupStage::SolderingProofReady)
        }
        _ => return None,
    };
    Some(GraphSetupAck {
        outbox_id: graph_setup_outbox_id(content)?,
        instance_id,
        graph_id,
        stage,
        acknowledger_peer_id: get_local_node_info().peer_id,
    })
}

pub async fn enqueue_graph_setup_outbox_message(
    local_db: &LocalDB,
    message: GOATMessage,
    ack_peer_id: Option<&str>,
) -> Result<String> {
    let outbox_id = graph_setup_outbox_id(&message.content)
        .ok_or_else(|| anyhow!("not a graph setup message"))?;
    let serialized = message.serialize_message().await?;
    let now = current_time_secs();
    local_db
        .acquire()
        .await?
        .enqueue_p2p_outbox_retry_message(
            &outbox_id,
            message.content.event_type(),
            &serialized,
            now + get_p2p_graph_setup_retry_window_secs(),
            get_p2p_graph_setup_retry_interval_secs(),
            ack_peer_id,
        )
        .await?;
    Ok(outbox_id)
}
#[derive(Serialize, Deserialize, Clone)]
pub struct VerifierGraphParamsEndorsement {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub verifier_index: usize,
    pub canonical_graph_params_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvmGcGraph,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: CommitteePubNonces,
    pub nonce_sigs: CommitteeNonceSignatures,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AggNonceConsensus {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub consensus_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: CommitteePartialSignatures,
    pub agg_nonces: CommitteeAggNonces,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct EndorseGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_evm_address: EvmAddress,
    pub committee_sig_for_graph: Vec<u8>, // ECDSA signature signed with committee evm keypair
    pub committee_sig_for_params: Vec<u8>, // ECDSA signature over canonical_graph_params_hash
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvmGcGraph,
    pub endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
    pub params_endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonce {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonce: PubNonce,
    pub nonce_sig: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonceConsensus {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub consensus_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmPartialSig {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub partial_sig: PartialSignature,
    pub endorse_sig: Vec<u8>, // ECDSA signature signed with committee evm keypair
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PostReady {
    pub instance_id: Uuid,
}

/// Pegout

#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct KickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PreKickoffSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Txid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeInitSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub watchtower_index: usize,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WatchtowerChallengeTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NackReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitPubinReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct OperatorCommitPubinTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AssertReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub assert_txid: Txid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ChallengeAssertSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_assert_txid: Txid,
    pub verifier_index: usize,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct WronglyChallengeTimeout {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_assert_txid: Txid,
    pub verifier_index: usize,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct DisproveSent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub disprove_type: DisproveTxType,
    pub index: usize, // nack txns index or assert timeout txns index, ignored for other disprove types
    pub challenge_start_txid: Option<Txid>,
    pub challenge_finish_txid: Txid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take1Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take1Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take2Ready {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Take2Sent {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

/// Others

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct NodeInfo {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub node_name: String,
    pub service_fee_rate: f64,
    pub available_peg_btc: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncGraphRequest {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph: SimplifiedBitvmGcGraph,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceDiscarded {
    // (graph_id, instance_id, OperatorPubkey)
    pub graph_infos: Vec<(Uuid, Uuid, String)>,
}

impl GOATMessage {
    pub fn new(actor: Actor, content: GOATMessageContent) -> Self {
        Self { actor, content }
    }

    pub fn content(&self) -> &GOATMessageContent {
        &self.content
    }

    pub fn default_message_id() -> MessageId {
        MessageId(b"__inner_message_id__".to_vec())
    }

    pub async fn serialize_message(&self) -> Result<Vec<u8>> {
        let cloned = self.clone();
        tokio::task::spawn_blocking(move || {
            if matches!(&cloned.content, GOATMessageContent::GenCircuits(_)) {
                let mut encoded = bincode::serialize(&cloned)
                    .context("failed to serialize bincode GOATMessage")?;
                let mut message = Vec::with_capacity(GOAT_MESSAGE_BIN_PREFIX.len() + encoded.len());
                message.extend_from_slice(GOAT_MESSAGE_BIN_PREFIX);
                message.append(&mut encoded);
                Ok(message)
            } else {
                serde_json::to_vec(&cloned).context("failed to serialize legacy JSON GOATMessage")
            }
        })
        .await?
    }

    pub async fn deserialize_message(message: &[u8]) -> Result<GOATMessage> {
        let cloned = message.to_vec();
        tokio::task::spawn_blocking(move || {
            if let Some(encoded) = cloned.strip_prefix(GOAT_MESSAGE_BIN_PREFIX) {
                bincode::deserialize(encoded).context("failed to deserialize bincode GOATMessage")
            } else {
                serde_json::from_slice(&cloned)
                    .context("failed to deserialize legacy JSON GOATMessage")
            }
        })
        .await?
    }
}

/// Decode an externally received P2P message and route it by delivery semantics.
#[allow(clippy::too_many_arguments)]
pub async fn handle_inbound_p2p_message(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
    metrics_state: &MetricsState,
) -> Result<()> {
    let decoded = match GOATMessage::deserialize_message(message).await {
        Ok(message) => {
            metrics_state.record_p2p_receive(true);
            message
        }
        Err(error) => {
            metrics_state.record_p2p_receive(false);
            return Err(error).context("decode inbound P2P message");
        }
    };

    if let Err(error) = update_node_timestamp(local_db, &from_peer_id.to_string()).await {
        tracing::warn!(
            event = "p2p_message",
            outcome = "peer_timestamp_update_failed",
            message_id = %hex::encode(&id.0),
            from_peer_id = %from_peer_id,
            error = %error,
            "received inbound P2P message but failed to update peer timestamp"
        );
    }

    match decoded.content.p2p_delivery() {
        P2PMessageDelivery::Inbox => {
            enqueue_p2p_message(local_db, actor, from_peer_id, id, message, &decoded).await?;
            if let Some(ack) = graph_setup_ack(&decoded.content) {
                // ACKs are deliberately ephemeral. A duplicate delivery is
                // acknowledged again, which lets the sender recover when its
                // previous ACK was dropped.
                if let Err(error) = send_to_peer(
                    swarm,
                    GOATMessage::new(Actor::All, GOATMessageContent::GraphSetupAck(ack)),
                )
                .await
                {
                    tracing::debug!(
                        event = "p2p_graph_setup_ack",
                        outcome = "publish_failed",
                        error = %error,
                        "inbound graph-setup message remains durable; sender will retry"
                    );
                }
            }
            Ok(())
        }
        P2PMessageDelivery::Immediate => {
            tracing::debug!(
                event = "p2p_message",
                delivery = "immediate",
                message_id = %hex::encode(&id.0),
                message_type = decoded.content.event_type(),
                from_peer_id = %from_peer_id,
                content_size = message.len(),
                "dispatching ephemeral P2P message"
            );
            dispatch_decoded_p2p_message(
                swarm,
                local_db,
                btc_client,
                goat_client,
                http_client,
                soldering_builder,
                actor,
                from_peer_id,
                id,
                decoded,
                metrics_state,
            )
            .await
        }
    }
}

/// Persist a decoded durable P2P message. Protocol work runs from the inbox on
/// a regular tick.
async fn enqueue_p2p_message(
    local_db: &LocalDB,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
    decoded: &GOATMessage,
) -> Result<()> {
    let message_id = hex::encode(&id.0);
    let inbox_message = P2pInboxMessage {
        message_id: message_id.clone(),
        business_id: decoded.content.pegin_retry_business_id(),
        actor: actor.to_string(),
        from_peer: from_peer_id.to_string(),
        msg_type: decoded.content.event_type().to_owned(),
        content: message.to_vec(),
        content_size: message.len() as i64,
        ..Default::default()
    };
    let mut inserted = None;
    for attempt in 1..=P2P_INBOX_ENQUEUE_ATTEMPTS {
        let result = async {
            let mut storage = local_db.acquire().await?;
            storage.insert_p2p_inbox_message(&inbox_message).await
        }
        .await;
        match result {
            Ok(value) => {
                inserted = Some(value);
                break;
            }
            Err(error)
                if is_retryable_sqlite_error(&error) && attempt < P2P_INBOX_ENQUEUE_ATTEMPTS =>
            {
                tracing::warn!(
                    event = "p2p_inbox",
                    outcome = "enqueue_retry",
                    message_id = %message_id,
                    attempt,
                    error = %error,
                    "retrying transient P2P inbox insert"
                );
                tokio::time::sleep(Duration::from_millis(50 * attempt as u64)).await;
            }
            Err(error) => return Err(error).context("persist inbound P2P message"),
        }
    }
    let inserted = inserted.expect("P2P inbox insert loop exits only after success or error");
    tracing::info!(
        event = "p2p_inbox",
        outcome = if inserted { "enqueued" } else { "duplicate" },
        message_id = %message_id,
        message_type = %inbox_message.msg_type,
        from_peer_id = %from_peer_id,
        content_size = message.len(),
        "received P2P message"
    );
    Ok(())
}

fn p2p_retry_delay_secs(attempt_count: i64) -> i64 {
    match attempt_count {
        ..=1 => 10,
        2 => 30,
        3 => 60,
        4 => 120,
        _ => 300,
    }
}

fn p2p_retryable_dispatch_error(
    error: &anyhow::Error,
) -> Option<(RetryableDispatchReason, Option<i64>)> {
    if let Some(retryable) =
        error.chain().find_map(|cause| cause.downcast_ref::<RetryableDispatchError>())
    {
        return Some((retryable.reason, retryable.retry_after_secs));
    }
    if is_retryable_sqlite_error(error) {
        return Some((RetryableDispatchReason::StorageBusy, None));
    }
    None
}

fn log_stale_p2p_inbox_lease(message_id: &str, lease_token: &str, operation: &str) {
    tracing::warn!(
        event = "p2p_inbox",
        outcome = "stale_lease",
        message_id,
        lease_token,
        operation,
        "ignored P2P inbox state update from a stale lease"
    );
}

async fn renew_p2p_inbox_lease_until_cancelled(
    local_db: LocalDB,
    message_id: String,
    lease_token: String,
    cancellation: CancellationToken,
) -> bool {
    let mut interval =
        tokio::time::interval(Duration::from_secs(P2P_INBOX_LEASE_RENEW_INTERVAL_SECS));
    interval.tick().await;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return true,
            _ = interval.tick() => {
                let renewal = match local_db.acquire().await {
                    Ok(mut storage) => storage
                        .renew_p2p_inbox_lease(
                            &message_id,
                            &lease_token,
                            current_time_secs() + P2P_INBOX_LEASE_SECS,
                        )
                        .await,
                    Err(error) => Err(error),
                };
                match renewal {
                    Ok(true) => {}
                    Ok(false) => {
                        log_stale_p2p_inbox_lease(&message_id, &lease_token, "renew");
                        return false;
                    }
                    Err(error) => {
                        tracing::warn!(
                            event = "p2p_inbox",
                            outcome = "lease_renew_failed",
                            message_id,
                            error = %error,
                            "failed to renew P2P inbox lease; will retry before expiry"
                        );
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_p2p_inbox_messages(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    metrics_state: &MetricsState,
) -> Result<()> {
    let now = current_time_secs();
    let active_heavy_task_ids = active_heavy_task_message_ids();
    let mut storage = local_db.start_immediate_transaction().await?;
    let messages = storage
        .claim_p2p_inbox_messages(
            now,
            now + P2P_INBOX_LEASE_SECS,
            get_p2p_inbox_batch_size(),
            &active_heavy_task_ids,
        )
        .await?;
    storage.commit().await?;

    for message in messages {
        let from_peer_id = match PeerId::from_str(&message.from_peer) {
            Ok(peer_id) => peer_id,
            Err(error) => {
                let updated = local_db
                    .acquire()
                    .await?
                    .fail_p2p_inbox_message(
                        &message.message_id,
                        &message.lease_token,
                        &format!("invalid stored source peer: {error}"),
                    )
                    .await?;
                if !updated {
                    log_stale_p2p_inbox_lease(&message.message_id, &message.lease_token, "fail");
                }
                continue;
            }
        };
        let is_heavy_task_message = is_heavy_task_message_type(&message.msg_type, &actor);
        let heavy_task = if is_heavy_task_message {
            let decoded = match GOATMessage::deserialize_message(&message.content).await {
                Ok(message) => message,
                Err(error) => {
                    let updated = local_db
                        .acquire()
                        .await?
                        .fail_p2p_inbox_message(
                            &message.message_id,
                            &message.lease_token,
                            &error.to_string(),
                        )
                        .await?;
                    if !updated {
                        log_stale_p2p_inbox_lease(
                            &message.message_id,
                            &message.lease_token,
                            "fail",
                        );
                    }
                    continue;
                }
            };
            let Some(task) = heavy_task_from_content(decoded.content(), &actor) else {
                let updated = local_db
                    .acquire()
                    .await?
                    .fail_p2p_inbox_message(
                        &message.message_id,
                        &message.lease_token,
                        &format!("inbox message type does not match {} content", message.msg_type),
                    )
                    .await?;
                if !updated {
                    log_stale_p2p_inbox_lease(&message.message_id, &message.lease_token, "fail");
                }
                continue;
            };
            Some(task)
        } else {
            None
        };

        if let Some(heavy_task) = heavy_task {
            let local_db = local_db.clone();
            let btc_client = Arc::clone(btc_client);
            let goat_client = Arc::clone(goat_client);
            let soldering_builder = soldering_builder.clone();
            let metrics_state = metrics_state.clone();
            let message_id = message.message_id.clone();
            let lease_token = message.lease_token.clone();
            let attempt_count = message.attempt_count;
            let task_type = heavy_task.message_type();
            let task_kind = heavy_task.kind();
            let graph_id = heavy_task.graph_id();
            let Some(permit) = try_acquire_heavy_task_permit(&message_id, &lease_token) else {
                let retry_after_secs = 5;
                let updated = local_db
                    .acquire()
                    .await?
                    .defer_p2p_inbox_message(
                        &message_id,
                        &lease_token,
                        current_time_secs() + retry_after_secs,
                        RetryableDispatchReason::ResourceLocked.code(),
                    )
                    .await?;
                if !updated {
                    log_stale_p2p_inbox_lease(&message.message_id, &message.lease_token, "defer");
                }
                tracing::debug!(
                    event = "p2p_inbox",
                    outcome = "deferred",
                    reason = RetryableDispatchReason::ResourceLocked.code(),
                    message_id,
                    retry_after_secs,
                    task_kind,
                    "deferred heavy task while the worker is busy"
                );
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                let lease_cancellation = CancellationToken::new();
                let lease_renewal = tokio::spawn(renew_p2p_inbox_lease_until_cancelled(
                    local_db.clone(),
                    message_id.clone(),
                    lease_token.clone(),
                    lease_cancellation.clone(),
                ));
                let context = HeavyTaskContext {
                    local_db: local_db.clone(),
                    btc_client,
                    goat_client,
                    soldering_builder,
                    metrics_state: metrics_state.clone(),
                    from_peer_id,
                };
                let result = run_heavy_task(&context, heavy_task).await;
                lease_cancellation.cancel();
                let lease_is_current = match lease_renewal.await {
                    Ok(lease_is_current) => lease_is_current,
                    Err(error) => {
                        tracing::error!(error = %error, message_id, "P2P inbox lease renewal task failed");
                        false
                    }
                };
                if !lease_is_current {
                    return;
                }
                metrics_state.record_message_dispatch(
                    task_type,
                    if result.is_ok() { "success" } else { "failed" },
                );
                if let Err(error) = finish_p2p_inbox_attempt(
                    &local_db,
                    &metrics_state,
                    &message_id,
                    &lease_token,
                    task_type,
                    attempt_count,
                    result,
                )
                .await
                {
                    tracing::error!(error = %error, message_id, "failed to persist heavy task result");
                }
            });
            tracing::info!(
                event = "p2p_inbox",
                outcome = "heavy_task_started",
                message_id = %message.message_id,
                graph_id = %graph_id,
                message_type = task_type,
                task_kind,
                "started background heavy task"
            );
            continue;
        }
        let raw_message_id = match hex::decode(&message.message_id) {
            Ok(message_id) => MessageId(message_id),
            Err(error) => {
                let updated = local_db
                    .acquire()
                    .await?
                    .fail_p2p_inbox_message(
                        &message.message_id,
                        &message.lease_token,
                        &format!("invalid stored message id: {error}"),
                    )
                    .await?;
                if !updated {
                    log_stale_p2p_inbox_lease(&message.message_id, &message.lease_token, "fail");
                }
                continue;
            }
        };

        let result = recv_and_dispatch(
            swarm,
            local_db,
            btc_client,
            goat_client,
            http_client,
            soldering_builder,
            actor.clone(),
            from_peer_id,
            raw_message_id,
            &message.content,
            metrics_state,
        )
        .await;

        let mut storage = local_db.acquire().await?;
        match result {
            Ok(()) => {
                if !storage
                    .complete_p2p_inbox_message(&message.message_id, &message.lease_token)
                    .await?
                {
                    log_stale_p2p_inbox_lease(
                        &message.message_id,
                        &message.lease_token,
                        "complete",
                    );
                }
            }
            Err(error) => {
                let Some((reason, requested_retry_after_secs)) =
                    p2p_retryable_dispatch_error(&error)
                else {
                    if !storage
                        .fail_p2p_inbox_message(
                            &message.message_id,
                            &message.lease_token,
                            &error.to_string(),
                        )
                        .await?
                    {
                        log_stale_p2p_inbox_lease(
                            &message.message_id,
                            &message.lease_token,
                            "fail",
                        );
                    }
                    tracing::warn!(
                        event = "p2p_inbox",
                        outcome = "failed",
                        message_id = %message.message_id,
                        message_type = %message.msg_type,
                        attempt_count = message.attempt_count,
                        error = %error,
                        "cached P2P message failed permanently"
                    );
                    continue;
                };
                let retry_after_secs = requested_retry_after_secs
                    .unwrap_or_else(|| p2p_retry_delay_secs(message.attempt_count));
                if !storage
                    .retry_p2p_inbox_message(
                        &message.message_id,
                        &message.lease_token,
                        current_time_secs() + retry_after_secs,
                        &error.to_string(),
                    )
                    .await?
                {
                    log_stale_p2p_inbox_lease(&message.message_id, &message.lease_token, "retry");
                }
                metrics_state.record_message_retry();
                tracing::warn!(
                    event = "p2p_inbox",
                    outcome = "deferred",
                    reason = reason.code(),
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    attempt_count = message.attempt_count,
                    retry_after_secs,
                    error = %error,
                    "deferred cached P2P message for retry"
                );
            }
        }
    }
    Ok(())
}

async fn finish_p2p_inbox_attempt(
    local_db: &LocalDB,
    metrics_state: &MetricsState,
    message_id: &str,
    lease_token: &str,
    message_type: &str,
    attempt_count: i64,
    result: Result<()>,
) -> Result<()> {
    let mut storage = local_db.acquire().await?;
    match result {
        Ok(()) => {
            if !storage.complete_p2p_inbox_message(message_id, lease_token).await? {
                log_stale_p2p_inbox_lease(message_id, lease_token, "complete");
            }
        }
        Err(error) => {
            let Some((reason, requested_retry_after_secs)) = p2p_retryable_dispatch_error(&error)
            else {
                if !storage
                    .fail_p2p_inbox_message(message_id, lease_token, &error.to_string())
                    .await?
                {
                    log_stale_p2p_inbox_lease(message_id, lease_token, "fail");
                }
                return Ok(());
            };
            let retry_after_secs =
                requested_retry_after_secs.unwrap_or_else(|| p2p_retry_delay_secs(attempt_count));
            if !storage
                .retry_p2p_inbox_message(
                    message_id,
                    lease_token,
                    current_time_secs() + retry_after_secs,
                    &error.to_string(),
                )
                .await?
            {
                log_stale_p2p_inbox_lease(message_id, lease_token, "retry");
            }
            metrics_state.record_message_retry();
            tracing::warn!(
                event = "p2p_inbox",
                outcome = "deferred",
                reason = reason.code(),
                message_id,
                message_type,
                attempt_count,
                retry_after_secs,
                error = %error,
                "deferred cached P2P message for retry"
            );
        }
    }
    Ok(())
}

async fn handle_p2p_outbox_messages(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
) -> Result<()> {
    let now = current_time_secs();
    let mut storage = local_db.start_immediate_transaction().await?;
    let expired = storage.expire_p2p_outbox_retry_messages(now).await?;
    let messages = storage
        .claim_p2p_outbox_messages(now, now + P2P_INBOX_LEASE_SECS, get_p2p_outbox_batch_size())
        .await?;
    storage.commit().await?;

    if expired > 0 {
        tracing::warn!(
            event = "p2p_outbox",
            outcome = "retry_window_expired",
            expired,
            "graph-setup outbound messages reached their retry window without the expected ACK"
        );
    }

    for message in messages {
        let outbound = match GOATMessage::deserialize_message(&message.content).await {
            Ok(message) => message,
            Err(error) => {
                local_db
                    .acquire()
                    .await?
                    .fail_p2p_outbox_message(&message.message_id, &error.to_string())
                    .await?;
                tracing::error!(
                    event = "p2p_outbox",
                    outcome = "failed",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    error = %error,
                    "discarded corrupt durable outbound P2P message"
                );
                continue;
            }
        };
        let result = send_to_peer(swarm, outbound).await;
        let mut storage = local_db.acquire().await?;
        match result {
            Ok(_) => {
                if message.retry_until > 0 {
                    let next_retry_at = current_time_secs() + message.retry_interval_secs;
                    storage.schedule_p2p_outbox_retry(&message.message_id, next_retry_at).await?;
                    tracing::info!(
                        event = "p2p_outbox",
                        outcome = "published_retry_window",
                        message_id = %message.message_id,
                        message_type = %message.msg_type,
                        next_retry_at,
                        retry_until = message.retry_until,
                        "published graph-setup P2P message; awaiting ACK or retry window expiry"
                    );
                } else {
                    storage.complete_p2p_outbox_message(&message.message_id).await?;
                }
            }
            Err(error) => {
                let retry_after_secs = p2p_retry_delay_secs(message.attempt_count);
                storage
                    .retry_p2p_outbox_message(
                        &message.message_id,
                        current_time_secs() + retry_after_secs,
                        &error.to_string(),
                    )
                    .await?;
                tracing::warn!(
                    event = "p2p_outbox",
                    outcome = "deferred",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    attempt_count = message.attempt_count,
                    retry_after_secs,
                    error = %error,
                    "deferred outbound P2P message"
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_self_p2p_msg(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
    metrics_state: &MetricsState,
) -> Result<()> {
    if id != GOATMessage::default_message_id() {
        tracing::warn!(
            event = "local_message_queue",
            outcome = "unexpected_message_id",
            message_id = ?id,
            "ignoring local queue trigger with an unexpected message id"
        );
        return Ok(());
    }
    let message = GOATMessage::deserialize_message(message).await?;
    tracing::info!(
        event = "local_message_queue",
        outcome = "trigger_received",
        role = %message.actor,
        message_type = message.content.event_type(),
        message_id = ?id,
        from_peer_id = %from_peer_id,
        "received local queue trigger"
    );

    let messages =
        pop_batch_local_unhandle_msg(local_db, actor.clone(), current_time_secs(), 0, 50).await?;
    tracing::info!(
        event = "local_message_queue",
        outcome = "batch_loaded",
        role = %actor,
        batch_size = messages.len(),
        "loaded pending local messages"
    );
    for message in messages {
        let queue_wait_secs = current_time_secs().saturating_sub(message.created_at);
        let started_at = Instant::now();
        match recv_and_dispatch(
            swarm,
            local_db,
            btc_client,
            goat_client,
            http_client,
            soldering_builder,
            actor.clone(),
            from_peer_id,
            id.clone(),
            &message.content,
            metrics_state,
        )
        .await
        {
            Ok(_) => {
                let mut storage_processor = local_db.acquire().await?;
                let state_updated = storage_processor
                    .update_messages_state(
                        &message.message_id,
                        message.message_version,
                        MessageState::Processed.to_string(),
                    )
                    .await?;
                if state_updated {
                    tracing::info!(
                        event = "local_message_queue",
                        outcome = "processed",
                        role = %actor,
                        business_id = %message.business_id,
                        queued_message_id = %message.message_id,
                        message_type = %message.msg_type,
                        queue_wait_secs,
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        "processed local message"
                    );
                } else {
                    tracing::warn!(
                        event = "local_message_queue",
                        outcome = "state_update_conflict",
                        role = %actor,
                        business_id = %message.business_id,
                        queued_message_id = %message.message_id,
                        message_type = %message.msg_type,
                        queue_wait_secs,
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        "local message handler completed but its processed state was not persisted"
                    );
                }
            }
            Err(err) => {
                let lock_time: i64 = if is_retryable_sqlite_error(&err)
                    && is_pegin_message_type(&message.msg_type)
                {
                    TRANSIENT_PEGIN_RETRY_DELAY_SECS as i64
                } else {
                    600
                };
                metrics_state.record_message_retry();
                tracing::warn!(
                    event = "local_message_queue",
                    outcome = "deferred",
                    role = %actor,
                    business_id = %message.business_id,
                    queued_message_id = %message.message_id,
                    message_type = %message.msg_type,
                    retry_after_secs = lock_time,
                    queue_wait_secs,
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    error = %err,
                    "failed to process local message; deferred for retry"
                );
                let mut storage_processor = local_db.acquire().await?;
                if let Err(reason_error) = storage_processor
                    .upsert_message_debug_reason(
                        &message.message_id,
                        MessageDeferReason::HandlerError.code(),
                        &err.to_string(),
                    )
                    .await
                {
                    tracing::warn!(
                        event = "local_message_queue",
                        outcome = "debug_reason_store_failed",
                        queued_message_id = %message.message_id,
                        error = %reason_error,
                        "failed to persist local message debug reason"
                    );
                }
                storage_processor
                    .update_messages_lock_time_until(
                        &message.message_id,
                        message.message_version,
                        current_time_secs() + lock_time,
                    )
                    .await?;
            }
        }
    }
    handle_p2p_outbox_messages(swarm, local_db).await?;
    handle_p2p_inbox_messages(
        swarm,
        local_db,
        btc_client,
        goat_client,
        http_client,
        soldering_builder,
        actor,
        metrics_state,
    )
    .await?;
    Ok(())
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
/// TODO: we should create a trait for all the actions of different roles to simplify this function.
#[allow(clippy::too_many_arguments)]
pub async fn recv_and_dispatch(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
    metrics_state: &MetricsState,
) -> Result<()> {
    let message = GOATMessage::deserialize_message(message).await?;
    dispatch_decoded_p2p_message(
        swarm,
        local_db,
        btc_client,
        goat_client,
        http_client,
        soldering_builder,
        actor,
        from_peer_id,
        id,
        message,
        metrics_state,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_decoded_p2p_message(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: GOATMessage,
    metrics_state: &MetricsState,
) -> Result<()> {
    // Determine whether the message comes from this node itself to optionally skip validations.
    let is_self_peer = get_local_node_info().peer_id == from_peer_id.to_string();
    let message_type = message.content.event_type();
    let role = actor.to_string();
    let from_peer_id_string = from_peer_id.to_string();
    let started_at = Instant::now();
    let mut handler_ctx = HandlerContext {
        swarm,
        local_db,
        btc_client,
        goat_client,
        http_client,
        soldering_builder,
        metrics_state,
        actor,
        from_peer_id,
        id,
        is_self_peer,
    };
    let result = handle_dispatch(&mut handler_ctx, message.content())
        .await
        .map_err(classify_retryable_dispatch_error);
    metrics_state
        .record_message_dispatch(message_type, if result.is_ok() { "success" } else { "failed" });
    match &result {
        Ok(()) => tracing::info!(
            event = "message_dispatch_result",
            outcome = "handled",
            role,
            message_type,
            from_peer_id = %from_peer_id_string,
            is_self_peer,
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            "message dispatch completed"
        ),
        Err(err) => tracing::warn!(
            event = "message_dispatch_result",
            outcome = "failed",
            role,
            message_type,
            from_peer_id = %from_peer_id_string,
            is_self_peer,
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            error = %err,
            "message dispatch failed"
        ),
    }
    result
}

pub(crate) async fn try_finalize_graph(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: Option<&SimplifiedBitvmGcGraph>,
    broadcast_graph_finalize: bool,
) -> Result<Option<(BitvmGcGraph, FinalizedGraphStoreOutcome)>> {
    let endorsements =
        get_committee_endorsements_for_graph(local_db, instance_id, graph_id).await?;
    let params_endorsements =
        get_committee_params_endorsements_for_graph(local_db, instance_id, graph_id).await?;
    let pub_nonoces = get_committee_pub_nonces_for_graph(local_db, instance_id, graph_id).await?;
    let partial_sigs =
        get_committee_partial_sigs_for_graph(local_db, instance_id, graph_id).await?;
    let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    if endorsements.len() == committee_pubkeys.len()
        && params_endorsements.len() == committee_pubkeys.len()
        && pub_nonoces.len() == committee_pubkeys.len()
        && partial_sigs.len() == committee_pubkeys.len()
    {
        let mut graph = match graph {
            Some(g) => BitvmGcGraph::from_simplified(g)?,
            None => {
                let g = get_graph(local_db, instance_id, graph_id)
                    .await?
                    .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
                BitvmGcGraph::from_simplified(&g)?
            }
        };
        if graph.parameters.instance_parameters.instance_id != instance_id
            || graph.parameters.graph_id != graph_id
        {
            bail!(
                "refuse to finalize graph {instance_id}:{graph_id} with mismatched graph parameters {}:{}",
                graph.parameters.instance_parameters.instance_id,
                graph.parameters.graph_id
            );
        }
        let pub_nonces =
            order_committee_values(&committee_pubkeys, pub_nonoces, "graph committee pub nonces")?;
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let partial_sigs = order_committee_values(
            &committee_pubkeys,
            partial_sigs,
            "graph committee partial sigs",
        )?;
        let committee_sig_for_graph = signature_aggregation(&partial_sigs, &agg_nonces, &graph)?;
        push_committee_pre_signatures(&mut graph, &committee_sig_for_graph)?;
        let simplified_graph = graph.to_simplified()?;
        let store_outcome = store_finalized_graph_if_needed(local_db, &simplified_graph).await?;
        mark_graph_as_endorsed(local_db, instance_id, graph_id).await?;
        try_transition_instance_to_presigned(local_db, instance_id).await?;
        if broadcast_graph_finalize {
            let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce: graph.parameters.graph_nonce,
                endorse_sigs: endorsements,
                params_endorse_sigs: params_endorsements,
                graph: simplified_graph,
            });
            send_to_peer(swarm, GOATMessage::new(Actor::All, message_content)).await?;
        }
        return Ok(Some((graph, store_outcome)));
    }
    Ok(None)
}

pub async fn send_to_peer(
    swarm: &mut Swarm<AllBehaviours>,
    message: GOATMessage,
) -> Result<MessageId> {
    let target_actor = message.actor.to_string();
    let message_type = message.content.event_type();
    let topic = crate::middleware::get_topic_name(&target_actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    let serialized = match message.serialize_message().await {
        Ok(serialized) => serialized,
        Err(error) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(false);
            }
            return Err(error);
        }
    };
    if serialized.len() > crate::middleware::behaviour::MAX_GOSSIPSUB_TRANSMIT_SIZE
        && let Some(metrics_state) = crate::metrics_service::node_metrics_state()
    {
        metrics_state.record_p2p_oversized_message();
    }
    match swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, serialized) {
        Ok(message_id) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(true);
            }
            tracing::info!(
                event = "p2p_message_publish",
                outcome = "published",
                target_actor,
                message_type,
                message_id = ?message_id,
                "published protocol message"
            );
            Ok(message_id)
        }
        Err(err) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(false);
            }
            tracing::warn!(
                event = "p2p_message_publish",
                outcome = "failed",
                target_actor,
                message_type,
                error = %err,
                "failed to publish protocol message"
            );
            Err(retryable_dispatch_error(
                RetryableDispatchReason::PublishFailed,
                Some(10),
                format!("publish {message_type} to {target_actor}: {err}"),
            ))
        }
    }
}

pub async fn push_local_unhandled_messages_with_reason(
    local_db: &LocalDB,
    business_id: Uuid,
    message: &GOATMessage,
    delay_secs: usize,
    reason: MessageDeferReason,
    reason_detail: &str,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let actor = message.actor.clone();
    let content: GOATMessageContent = message.content().clone();
    upsert_message(
        &mut storage_processor,
        true,
        business_id,
        None,
        SELF_SENDER.to_string(),
        actor,
        content,
        0,
        delay_secs as i64,
    )
    .await?;
    let persist_result = match storage_processor
        .find_message_by_business_id(&business_id, message.content.event_type())
        .await
    {
        Ok(Some(queued_message)) => {
            storage_processor
                .upsert_message_debug_reason(
                    &queued_message.message_id,
                    reason.code(),
                    reason_detail,
                )
                .await
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = persist_result {
        tracing::warn!(
            event = "local_message_queue",
            outcome = "debug_reason_store_failed",
            error = %error,
            "failed to persist local message defer reason"
        );
    }
    if delay_secs > 0
        && let Some(metrics_state) = crate::metrics_service::node_metrics_state()
    {
        metrics_state.record_message_retry();
    }
    Ok(())
}

/// Helper: try to get graph. If missing, send SyncGraphRequest and defer current handling.
pub(crate) async fn get_graph_or_defer(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    message: &GOATMessage,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    match get_graph(local_db, instance_id, graph_id).await? {
        Some(g) => Ok(Some(g)),
        None => {
            // Ask for sync and push to local queue with a short retry delay
            let sync_request_outcome = if let Err(error) =
                try_send_sync_graph_request(swarm, goat_client, instance_id, graph_id).await
            {
                tracing::warn!(
                    event = "graph_resolution",
                    outcome = "sync_request_failed",
                    instance_id = %instance_id,
                    graph_id = %graph_id,
                    message_type = message.content.event_type(),
                    error_class = "p2p",
                    error = %error,
                    "failed to request graph synchronization"
                );
                "failed"
            } else {
                "submitted"
            };
            let delay_secs: usize = 60; // 1 min default retry
            if let Err(error) = push_local_unhandled_messages_with_reason(
                local_db,
                graph_id,
                message,
                delay_secs,
                MessageDeferReason::GraphSyncPending,
                "graph is missing locally; requested SyncGraph from a relayer",
            )
            .await
            {
                tracing::error!(
                    event = "graph_resolution",
                    outcome = "defer_failed",
                    instance_id = %instance_id,
                    graph_id = %graph_id,
                    message_type = message.content.event_type(),
                    retry_after_secs = delay_secs,
                    error_class = "database",
                    error = %error,
                    "failed to enqueue message while graph is missing"
                );
                return Err(error).context("failed to defer message while graph is missing");
            }
            tracing::info!(
                event = "graph_resolution",
                outcome = "deferred_missing_graph",
                instance_id = %instance_id,
                graph_id = %graph_id,
                message_type = message.content.event_type(),
                sync_request_outcome,
                retry_after_secs = delay_secs,
                "graph missing locally; requested sync and deferred message"
            );
            Ok(None)
        }
    }
}

pub async fn try_send_sync_graph_request(
    swarm: &mut Swarm<AllBehaviours>,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    validate_graph_id_on_goat(goat_client, instance_id, graph_id).await?;
    let message_content =
        GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id });
    let message = GOATMessage::new(Actor::All, message_content);
    send_to_peer(swarm, message).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soldering_proof_ready_is_descriptor_only() {
        let ready = SolderingProofReady {
            instance_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            graph_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            candidate_index: 3,
            payload_hash: [0xabu8; 32],
            total_len: 1024,
        };

        let value = serde_json::to_value(ready).unwrap();
        let object = value.as_object().unwrap();

        assert!(object.contains_key("instance_id"));
        assert!(object.contains_key("graph_id"));
        assert!(object.contains_key("candidate_index"));
        assert!(object.contains_key("payload_hash"));
        assert!(object.contains_key("total_len"));
        assert!(!object.contains_key("payload_path"));
        assert!(!object.contains_key("payload"));
        assert!(!object.contains_key("setup_package"));
        assert!(!object.contains_key("verifier_pubkey"));
    }
}
