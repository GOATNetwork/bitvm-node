#![allow(clippy::collapsible_match)]
#![allow(clippy::single_match)]
#![allow(clippy::collapsible_else_if)]

use crate::env::{
    MESSAGE_EXPIRE_TIME, get_p2p_graph_setup_retry_interval_secs,
    get_p2p_graph_setup_retry_window_secs, get_p2p_inbox_batch_size,
};
use crate::handle::{
    HandlerContext, HeavyTaskContext, dispatch as handle_dispatch, heavy_task_from_content,
    run_heavy_task,
};
use crate::metrics_service::MetricsState;
use crate::middleware::AllBehaviours;
use crate::middleware::publisher::MessagePublisher;
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
use futures::FutureExt;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use node_macros::MessageBusinessRef;
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
use store::{GraphStatus, InstanceBridgeInStatus, MessageState, P2pInboxMessage};
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};
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

/// Budget for claims that never reported an outcome. Small on purpose: reaching
/// this means the node went down mid-dispatch more than once on the same
/// payload, which is the signature of a message that reproducibly kills it.
const QUEUE_MAX_ABANDONS: i64 = 3;
/// How long a claimed local message stays claimed before another tick may take
/// it over. Heavy work is routed through the durable P2P inbox instead, so local
/// handlers are expected to be short.
const LOCAL_MESSAGE_LEASE_SECS: i64 = 10 * 60;
/// Backoff applied to a local message whose handler returned a non-transient error.
const LOCAL_MESSAGE_RETRY_DELAY_SECS: i64 = 600;
const LOCAL_MESSAGE_BATCH_SIZE: i64 = 50;
/// Delay applied per recorded abandon before a payload may run again, so a
/// supervisor restart after a panic or an unclean exit does not replay it at
/// full speed.
const QUEUE_ABANDON_BACKOFF_SECS: i64 = 60;
/// Maximum retained Quarantined payload bytes.
const P2P_INBOX_QUARANTINE_MAX_BYTES: i64 = 256 * 1024 * 1024;
/// Ceiling on terminal (`Processed`/`Failed`/`Quarantined`) inbox rows kept for
/// diagnostics; the oldest beyond it are deleted.
const P2P_INBOX_TERMINAL_MAX_ROWS: i64 = 100_000;
/// Maximum terminal rows removed per cleanup pass.
const P2P_INBOX_TERMINAL_PURGE_BATCH: i64 = 4_096;
/// Minimum listed-batch shares for Registered and Unregistered senders.
const P2P_INBOX_UNREGISTERED_BATCH_DIVISOR: i64 = 4;
const P2P_INBOX_REGISTERED_BATCH_DIVISOR: i64 = 4;
/// A `node` row of an unregistered peer may be evicted to make room for a new
/// one once it has gone this long without a refresh: three missed heartbeats.
pub const NODE_TABLE_EVICTABLE_AFTER_SECS: i64 = 3 * crate::env::HEARTBEAT_INTERVAL_SECOND as i64;
/// Maximum unregistered node rows.
pub const NODE_TABLE_MAX_UNREGISTERED_ROWS: i64 = 4_096;
/// A `node` row of a peer that is not registered is deleted once it has not been
/// refreshed for this long; live nodes refresh theirs on every heartbeat.
const NODE_TABLE_STALE_SECS: i64 = 7 * 24 * 60 * 60;
const NODE_TABLE_PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// How long each durable queue may start work in a business-worker tick.
/// Individual handlers have a separate timeout; swarm runs on another thread.
const P2P_INBOX_DRAIN_BUDGET: Duration = Duration::from_secs(4);
/// Initial signing-round retry delay; doubles after successful publishes up to the configured ceiling.
const PROTOCOL_RETRY_BASE_SECS: i64 = 30;
/// Maximum accepted binding timestamp lead.
pub const NODE_INFO_BINDING_MAX_FUTURE_SECS: i64 = 10 * 60;
/// A dispatch future erased behind a box to keep the enclosing task's state
/// machine reasonably small.
type BoxedDispatch<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>>;

enum DispatchExecution<T> {
    Completed(T),
    Shutdown,
    Panicked(String),
}

struct LocalMessageClaim {
    message_id: String,
    message_version: i64,
}

/// Identify the current inbox message by kind, business reference and qualifier.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DispatchFingerprint {
    kind: MessageKind,
    business_ref: BusinessRef,
    qualifier: MessageQualifier,
}

impl DispatchFingerprint {
    fn of(content: &GOATMessageContent) -> Self {
        Self {
            kind: content.kind(),
            business_ref: content.business_ref(),
            qualifier: content.qualifier(),
        }
    }
}

struct InboxDispatchContext {
    fingerprint: DispatchFingerprint,
    retry: std::cell::RefCell<Option<anyhow::Error>>,
}

tokio::task_local! {
    static ACTIVE_LOCAL_MESSAGE_CLAIM: LocalMessageClaim;
    static ACTIVE_INBOX_DISPATCH: InboxDispatchContext;
}

async fn track_inbox_retry(
    fingerprint: DispatchFingerprint,
    dispatch: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    ACTIVE_INBOX_DISPATCH
        .scope(InboxDispatchContext { fingerprint, retry: Default::default() }, async {
            let result = dispatch.await;
            // Apply self-deferral after handler compensation, including when compensation returns an error.
            match ACTIVE_INBOX_DISPATCH.with(|active| active.retry.borrow_mut().take()) {
                Some(retry) => {
                    if let Err(error) = &result {
                        tracing::warn!(
                            event = "p2p_inbox",
                            outcome = "deferred_despite_error",
                            error = %error,
                            "handler failed after asking to be retried; keeping the retry"
                        );
                    }
                    Err(retry)
                }
                None => result,
            }
        })
        .await
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Catch only at the worker-supervisor boundary. A panic is returned separately
/// so the caller can record an abandon and stop the node; it is never converted
/// into an ordinary handler error or followed by more business work.
async fn supervise_dispatch<F, T>(future: F, shutdown: &CancellationToken) -> DispatchExecution<T>
where
    F: std::future::Future<Output = T>,
{
    match std::panic::AssertUnwindSafe(async {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => None,
            result = future => Some(result),
        }
    })
    .catch_unwind()
    .await
    {
        Ok(Some(result)) => DispatchExecution::Completed(result),
        Ok(None) => DispatchExecution::Shutdown,
        Err(payload) => DispatchExecution::Panicked(panic_payload_message(payload.as_ref())),
    }
}

/// Log a per-message bookkeeping failure without aborting the rest of the batch.
///
/// Propagating here used to abandon every message still claimed in the batch.
/// Those rows stay `Processing` until their lease lapses and are then charged an
/// abandon they never earned — so one transient storage blip could push a whole
/// batch of healthy messages toward quarantine.
fn log_queue_bookkeeping_failure(
    queue: &'static str,
    message_id: &str,
    operation: &str,
    error: &anyhow::Error,
) {
    tracing::error!(
        event = queue,
        outcome = "bookkeeping_failed",
        message_id,
        operation,
        error = %error,
        "failed to persist a message outcome; leaving it claimed for its lease to lapse"
    );
}

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

/// Ensure a panicking background task cannot leave its detached lease renewer
/// running forever. Once renewal stops, the durable row becomes claimable and
/// the unfinished execution is counted as an abandon.
struct LeaseRenewalGuard(CancellationToken);

impl Drop for LeaseRenewalGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
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
pub(crate) fn is_retryable_external_rpc_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        // Inspect contract transport errors before traversing their transparent sources.
        if let Some(alloy::contract::Error::TransportError(error)) =
            cause.downcast_ref::<alloy::contract::Error>()
        {
            return error.is_transport_error();
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BusinessRef {
    Instance { instance_id: Uuid },
    Graph { instance_id: Uuid, graph_id: Uuid },
    Unscoped,
}

impl BusinessRef {
    pub const fn primary_id(self) -> Option<Uuid> {
        match self {
            Self::Instance { instance_id } => Some(instance_id),
            Self::Graph { graph_id, .. } => Some(graph_id),
            Self::Unscoped => None,
        }
    }

    fn key_part(self) -> String {
        match self {
            Self::Instance { instance_id } => format!("instance:{instance_id}"),
            Self::Graph { graph_id, .. } => format!("graph:{graph_id}"),
            Self::Unscoped => "unscoped".to_owned(),
        }
    }
}

pub trait HasBusinessRef {
    fn business_ref(&self) -> BusinessRef;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageQualifier {
    Singleton,
    Watchtower(usize),
    Verifier(usize),
    Disprove { kind: DisproveTxType, index: usize },
}

impl MessageQualifier {
    fn key_part(&self) -> String {
        match self {
            Self::Singleton => "singleton".to_owned(),
            Self::Watchtower(index) => format!("watchtower:{index}"),
            Self::Verifier(index) => format!("verifier:{index}"),
            Self::Disprove { kind, index } => format!("disprove:{kind}:{index}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMessageKey {
    actor: Actor,
    kind: MessageKind,
    business_ref: BusinessRef,
    qualifier: MessageQualifier,
}

impl LocalMessageKey {
    pub fn from_content(actor: Actor, content: &GOATMessageContent) -> Result<Self> {
        let business_ref = content.business_ref();
        if business_ref.primary_id().is_none() {
            bail!("cannot persist unscoped {} as a local message", content.event_type());
        }
        Ok(Self { actor, kind: content.kind(), business_ref, qualifier: content.qualifier() })
    }

    pub fn business_id(&self) -> Uuid {
        match self.business_ref {
            BusinessRef::Instance { instance_id } => instance_id,
            BusinessRef::Graph { graph_id, .. } => graph_id,
            BusinessRef::Unscoped => unreachable!("unscoped messages cannot have a local key"),
        }
    }

    pub fn message_id(&self) -> String {
        format!(
            "local:v1:{}:{}:{}:{}",
            self.actor,
            self.business_ref.key_part(),
            self.kind,
            self.qualifier.key_part(),
        )
    }
}

#[derive(Serialize, Deserialize, Clone, EnumDiscriminants, MessageBusinessRef)]
#[strum_discriminants(name(MessageKind))]
#[strum_discriminants(derive(Hash, Display, EnumString, EnumIter, IntoStaticStr))]
pub enum GOATMessageContent {
    #[business_ref(instance)]
    PeginRequest(PeginRequest),
    #[business_ref(graph)]
    CreateGraph(CreateGraph),
    #[business_ref(instance)]
    ConfirmInstance(ConfirmInstance),
    #[business_ref(graph)]
    InitGraph(InitGraph),
    #[business_ref(graph)]
    GenCircuits(GenCircuits),
    #[business_ref(graph)]
    CutCircuits(CutCircuits),
    #[business_ref(graph)]
    SolderingProofReady(SolderingProofReady),
    #[business_ref(graph)]
    GraphSetupAck(GraphSetupAck),
    #[business_ref(graph)]
    VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement),
    #[business_ref(graph)]
    NonceGeneration(NonceGeneration),
    #[business_ref(graph)]
    AggNonceConsensus(AggNonceConsensus),
    #[business_ref(graph)]
    CommitteePresign(CommitteePresign),
    #[business_ref(graph)]
    EndorseGraph(EndorseGraph),
    #[business_ref(graph)]
    GraphFinalize(GraphFinalize),
    #[business_ref(instance)]
    PeginConfirmNonce(PeginConfirmNonce),
    #[business_ref(instance)]
    PeginConfirmNonceConsensus(PeginConfirmNonceConsensus),
    #[business_ref(instance)]
    PeginConfirmPartialSig(PeginConfirmPartialSig),
    #[business_ref(instance)]
    PostReady(PostReady),
    #[business_ref(graph)]
    KickoffReady(KickoffReady),
    #[business_ref(graph)]
    KickoffSent(KickoffSent),
    #[business_ref(graph)]
    PreKickoffSent(PreKickoffSent),
    #[business_ref(graph)]
    ChallengeSent(ChallengeSent),
    #[business_ref(graph)]
    WatchtowerChallengeInitSent(WatchtowerChallengeInitSent),
    #[business_ref(graph)]
    WatchtowerChallengeSent(WatchtowerChallengeSent),
    #[business_ref(graph)]
    WatchtowerChallengeTimeout(WatchtowerChallengeTimeout),
    #[business_ref(graph)]
    NackReady(NackReady),
    #[business_ref(graph)]
    OperatorCommitPubinReady(OperatorCommitPubinReady),
    #[business_ref(graph)]
    OperatorCommitPubinTimeout(OperatorCommitPubinTimeout),
    #[business_ref(graph)]
    AssertReady(AssertReady),
    #[business_ref(graph)]
    AssertSent(AssertSent),
    #[business_ref(graph)]
    ChallengeAssertSent(ChallengeAssertSent),
    #[business_ref(graph)]
    WronglyChallengeTimeout(WronglyChallengeTimeout),
    #[business_ref(graph)]
    DisproveSent(DisproveSent),
    #[business_ref(graph)]
    Take1Ready(Take1Ready),
    #[business_ref(graph)]
    Take1Sent(Take1Sent),
    #[business_ref(graph)]
    Take2Ready(Take2Ready),
    #[business_ref(graph)]
    Take2Sent(Take2Sent),
    #[business_ref(unscoped)]
    RequestNodeInfo(NodeInfo),
    #[business_ref(unscoped)]
    ResponseNodeInfo(NodeInfo),
    #[business_ref(graph)]
    SyncGraphRequest(SyncGraphRequest),
    #[business_ref(graph)]
    SyncGraph(SyncGraph),
    #[business_ref(unscoped)]
    InstanceDiscarded(InstanceDiscarded),
    #[business_ref(unscoped)]
    Tick,
}

impl MessageKind {
    const fn is_pegin(self) -> bool {
        matches!(
            self,
            Self::PeginRequest
                | Self::ConfirmInstance
                | Self::CreateGraph
                | Self::InitGraph
                | Self::GenCircuits
                | Self::CutCircuits
                | Self::SolderingProofReady
                | Self::VerifierGraphParamsEndorsement
                | Self::NonceGeneration
                | Self::AggNonceConsensus
                | Self::CommitteePresign
                | Self::EndorseGraph
                | Self::GraphFinalize
                | Self::PeginConfirmNonce
                | Self::PeginConfirmNonceConsensus
                | Self::PeginConfirmPartialSig
                | Self::PostReady
        )
    }
}

impl MessageKind {
    /// Receiver roles handled by `dispatch` and `heavy_task_from_content`.
    pub fn handled_by(self, actor: &Actor) -> bool {
        use Actor::{Committee, Operator, Verifier, Watchtower};
        match self {
            // Every role has an arm (a role-specific one or the default).
            Self::PeginRequest
            | Self::ConfirmInstance
            | Self::GraphSetupAck
            | Self::GraphFinalize
            | Self::KickoffSent
            | Self::PreKickoffSent
            | Self::ChallengeSent
            | Self::DisproveSent
            | Self::Take1Sent
            | Self::Take2Sent
            | Self::RequestNodeInfo
            | Self::ResponseNodeInfo
            | Self::SyncGraph
            // Not dispatched through the role table; keep them as they are.
            | Self::InstanceDiscarded
            | Self::Tick => true,
            Self::InitGraph | Self::CutCircuits => matches!(actor, Verifier),
            Self::CreateGraph => matches!(actor, Verifier | Committee),
            Self::GenCircuits | Self::SolderingProofReady | Self::EndorseGraph => {
                matches!(actor, Operator)
            }
            Self::NonceGeneration | Self::CommitteePresign => matches!(actor, Committee | Operator),
            Self::VerifierGraphParamsEndorsement
            | Self::AggNonceConsensus
            | Self::PeginConfirmNonce
            | Self::PeginConfirmNonceConsensus
            | Self::PeginConfirmPartialSig
            | Self::PostReady
            | Self::SyncGraphRequest => matches!(actor, Committee),
            Self::KickoffReady
            | Self::WatchtowerChallengeSent
            | Self::WatchtowerChallengeTimeout
            | Self::OperatorCommitPubinReady
            | Self::AssertReady
            | Self::ChallengeAssertSent
            | Self::Take1Ready
            | Self::Take2Ready => matches!(actor, Operator),
            Self::WatchtowerChallengeInitSent => matches!(actor, Watchtower),
            Self::NackReady
            | Self::OperatorCommitPubinTimeout
            | Self::AssertSent
            | Self::WronglyChallengeTimeout => matches!(actor, Verifier),
        }
    }
}

impl MessageKind {
    /// Sender roles verified against chain registration; other message kinds use `Any`.
    pub fn sender_role(self) -> crate::p2p_admission::SenderRole {
        use crate::p2p_admission::SenderRole;
        match self {
            Self::NonceGeneration
            | Self::AggNonceConsensus
            | Self::CommitteePresign
            | Self::EndorseGraph
            | Self::PeginConfirmNonce
            | Self::PeginConfirmNonceConsensus
            | Self::PeginConfirmPartialSig
            | Self::SyncGraph => SenderRole::Committee,
            Self::GenCircuits | Self::VerifierGraphParamsEndorsement => SenderRole::Verifier,
            Self::InitGraph => SenderRole::Operator,
            _ => SenderRole::Any,
        }
    }
}

impl GOATMessageContent {
    pub fn kind(&self) -> MessageKind {
        self.into()
    }

    /// New messages default to the durable inbox and must explicitly opt into
    /// immediate processing when they are safe to drop.
    pub const fn p2p_delivery(&self) -> P2PMessageDelivery {
        match self {
            Self::RequestNodeInfo(_) | Self::ResponseNodeInfo(_) | Self::GraphSetupAck(_) => {
                P2PMessageDelivery::Immediate
            }
            _ => P2PMessageDelivery::Inbox,
        }
    }

    /// Stable message name for logs/metrics. Keep this independent of `Debug`, whose
    /// output can include protocol payloads (and, for proofs, be very large).
    pub fn event_type(&self) -> &'static str {
        self.kind().into()
    }

    pub fn qualifier(&self) -> MessageQualifier {
        match self {
            Self::WatchtowerChallengeSent(message) => {
                MessageQualifier::Watchtower(message.watchtower_index)
            }
            Self::ChallengeAssertSent(message) => {
                MessageQualifier::Verifier(message.verifier_index)
            }
            Self::WronglyChallengeTimeout(message) => {
                MessageQualifier::Verifier(message.verifier_index)
            }
            Self::DisproveSent(message) => {
                MessageQualifier::Disprove { kind: message.disprove_type, index: message.index }
            }
            _ => MessageQualifier::Singleton,
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
        acknowledger_peer_id: crate::env::get_peer_id(),
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
            // Only the outbox ever sends these, so the row is due at once.
            0,
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
    /// Hex master-key Schnorr signature over peer ID, public key and issuance time.
    #[serde(default)]
    pub binding_sig: String,
    /// Unix seconds when the binding was signed. Orders re-bindings so one key
    /// maps to a single peer id at a time.
    #[serde(default)]
    pub binding_issued_at: i64,
}

const NODE_INFO_BINDING_DOMAIN: &[u8] = b"bitvm2-node/node-info-binding/v1";

fn node_info_binding_message(peer_id: &str, btc_pub_key: &str, issued_at: i64) -> SecpMessage {
    let mut hasher = Sha256::new();
    hasher.update(NODE_INFO_BINDING_DOMAIN);
    hasher.update((peer_id.len() as u32).to_be_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.update((btc_pub_key.len() as u32).to_be_bytes());
    hasher.update(btc_pub_key.as_bytes());
    hasher.update(issued_at.to_be_bytes());
    SecpMessage::from_digest(hasher.finalize().into())
}

/// Sign the binding that proves `master_keypair`'s key authorised `peer_id`.
pub fn sign_node_info_binding(
    peer_id: &str,
    btc_pub_key: &str,
    issued_at: i64,
    master_keypair: &Keypair,
) -> String {
    let signature = SECP256K1
        .sign_schnorr(&node_info_binding_message(peer_id, btc_pub_key, issued_at), master_keypair);
    hex::encode(signature.serialize())
}

/// Verify the NodeInfo binding and return its parsed public key.
pub fn verify_node_info_binding(node_info: &NodeInfo) -> Option<XOnlyPublicKey> {
    if node_info.binding_sig.is_empty() {
        return None;
    }
    let pubkey = PublicKey::from_str(&node_info.btc_pub_key).ok()?;
    let xonly = XOnlyPublicKey::from(pubkey);
    let signature_bytes = hex::decode(&node_info.binding_sig).ok()?;
    let signature = SchnorrSignature::from_slice(&signature_bytes).ok()?;
    SECP256K1
        .verify_schnorr(
            &signature,
            &node_info_binding_message(
                &node_info.peer_id,
                &node_info.btc_pub_key,
                node_info.binding_issued_at,
            ),
            &xonly,
        )
        .ok()
        .map(|()| xonly)
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

    /// Whether `message` uses the bincode envelope, which only `GenCircuits` does.
    pub fn is_binary_envelope(message: &[u8]) -> bool {
        message.starts_with(GOAT_MESSAGE_BIN_PREFIX)
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

/// Report exactly one forwarding verdict for each received gossipsub message.
fn report_gossip_validation(
    swarm: &mut Swarm<AllBehaviours>,
    id: &MessageId,
    propagation_source: &PeerId,
    acceptance: gossipsub::MessageAcceptance,
) {
    let cached = swarm.behaviour_mut().gossipsub.report_message_validation_result(
        id,
        propagation_source,
        acceptance,
    );
    if !cached {
        tracing::debug!(
            event = "p2p_message",
            outcome = "validation_report_missed",
            message_id = %hex::encode(&id.0),
            "gossipsub had already evicted the message awaiting validation"
        );
    }
}

/// Apply admission before routing; a dropped message is not an error.
#[allow(clippy::too_many_arguments)]
pub async fn handle_inbound_p2p_message(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    _btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    _http_client: &HttpAsyncClient,
    _soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    from_peer_id: PeerId,
    propagation_source: PeerId,
    sequence_number: Option<u64>,
    id: MessageId,
    message: &[u8],
    metrics_state: &MetricsState,
    worker: &crate::p2p_msg_handler::WorkerControl,
) -> Result<()> {
    use crate::p2p_admission::{self, InboundVerdict};
    use gossipsub::MessageAcceptance;

    let now = Instant::now();
    p2p_admission::refresh_registry_in_background(local_db, goat_client, Some(from_peer_id));
    let verdict = p2p_admission::evaluate_inbound_message(
        local_db,
        &p2p_admission::AdmissionGates::global(&actor),
        &p2p_admission::InboundGossip {
            direct_peer: &propagation_source,
            source: &from_peer_id,
            sequence_number,
            data: message,
        },
        now,
    )
    .await;
    let verdict = match verdict {
        Ok(verdict) => verdict,
        Err(error) => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Ignore);
            return Err(error).context("evaluate inbound P2P message admission");
        }
    };

    match verdict {
        InboundVerdict::Drop(reason) => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Ignore);
            if reason.blames_direct_peer() {
                strike_direct_peer(swarm, local_db, goat_client, propagation_source, now);
            }
            if reason == p2p_admission::DropReason::Undecodable {
                metrics_state.record_p2p_receive(false);
            } else if reason.after_decode() {
                metrics_state.record_p2p_receive(true);
            }
            p2p_admission::record_drop(reason);
            Ok(())
        }
        // Forward messages for other roles without persistence or ACK.
        InboundVerdict::Forward => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            Ok(())
        }
        // Persist durable messages before allowing forwarding.
        InboundVerdict::Enqueue { message: decoded, class, content_hash } => {
            if let Err(error) = enqueue_p2p_message(
                local_db,
                actor,
                from_peer_id,
                id.clone(),
                message,
                &decoded,
                class,
                content_hash,
            )
            .await
            {
                report_gossip_validation(
                    swarm,
                    &id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                return Err(error);
            }
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            maybe_send_graph_setup_ack(swarm, &decoded, from_peer_id, now).await;
            Ok(())
        }
        // Forward duplicates with rate-limited ACKs and logs.
        InboundVerdict::Duplicate(decoded) => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            p2p_admission::record_drop(p2p_admission::DropReason::DuplicatePayload);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            maybe_send_graph_setup_ack(swarm, &decoded, from_peer_id, now).await;
            Ok(())
        }
        InboundVerdict::Immediate(decoded) => {
            if !worker.enqueue(from_peer_id, id.clone(), decoded, message.len()) {
                report_gossip_validation(
                    swarm,
                    &id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                p2p_admission::record_drop(p2p_admission::DropReason::ControlQueueFull);
                return Ok(());
            }
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_immediate_message(
    publisher: &mut dyn MessagePublisher,
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
    let kind = message.content.event_type();
    match tokio::time::timeout(
        crate::env::get_p2p_handler_timeout(),
        dispatch_decoded_p2p_message(
            publisher,
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
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                event = "p2p_message",
                outcome = "handler_timeout",
                message_type = kind,
                "ephemeral message exceeded business worker budget"
            );
            Ok(())
        }
    }
}

/// Count relay strikes and temporarily ban repeat offenders.
/// Registered peers and peers with unresolved registration are exempt.
fn strike_direct_peer(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    direct_peer: PeerId,
    now: Instant,
) {
    let registry = crate::p2p_admission::peer_registry();
    if !registry.is_known_unregistered(&direct_peer, now) {
        crate::p2p_admission::refresh_neighbour_in_background(local_db, goat_client, direct_peer);
        return;
    }
    if !crate::p2p_admission::direct_peer_strikes().strike(&direct_peer, now) {
        return;
    }
    // The strike table now lists the peer as banned, and the connection gate
    // consults it for every connection: closing this one is all that is left.
    let _ = swarm.disconnect_peer_id(direct_peer);
    tracing::warn!(
        event = "p2p_admission",
        outcome = "direct_peer_banned",
        peer_id = %direct_peer,
        "temporarily ignoring a neighbour that keeps relaying invalid messages"
    );
}

/// Refresh peer liveness at most once per cooldown.
async fn refresh_peer_timestamp_throttled(local_db: &LocalDB, from_peer_id: PeerId, now: Instant) {
    let peer = from_peer_id.to_string();
    if !crate::p2p_admission::peer_timestamp_gate().allow(&peer, now) {
        return;
    }
    if let Err(error) = update_node_timestamp(local_db, &peer).await {
        tracing::debug!(
            event = "p2p_message",
            outcome = "peer_timestamp_update_failed",
            from_peer_id = %peer,
            error = %error,
            "failed to refresh peer liveness timestamp"
        );
    }
}

/// Rate-limit graph-setup ACKs by sender and outbox slot.
async fn maybe_send_graph_setup_ack(
    swarm: &mut dyn MessagePublisher,
    decoded: &GOATMessage,
    from_peer_id: PeerId,
    now: Instant,
) {
    let Some(ack) = graph_setup_ack(&decoded.content) else {
        return;
    };
    let key = format!("{from_peer_id}:{}", ack.outbox_id);
    if !crate::p2p_admission::dedup_ack_gate().allow(&key, now) {
        return;
    }
    if let Err(error) =
        send_to_peer(swarm, GOATMessage::new(Actor::All, GOATMessageContent::GraphSetupAck(ack)))
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

/// Persist a decoded durable P2P message. Protocol work runs from the inbox on
/// a regular tick.
#[allow(clippy::too_many_arguments)]
async fn enqueue_p2p_message(
    local_db: &LocalDB,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
    decoded: &GOATMessage,
    admission_class: store::P2pInboxAdmissionClass,
    content_hash: [u8; 32],
) -> Result<()> {
    let message_id = hex::encode(&id.0);
    let inbox_message = P2pInboxMessage {
        message_id: message_id.clone(),
        business_id: decoded.content.business_ref().primary_id(),
        actor: actor.to_string(),
        from_peer: from_peer_id.to_string(),
        msg_type: decoded.content.event_type().to_owned(),
        content: message.to_vec(),
        content_size: message.len() as i64,
        admission_class: admission_class.to_string(),
        content_hash: Some(content_hash.to_vec()),
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
    // Aggregate unregistered admission logs; log registered messages individually.
    if admission_class.is_registered() {
        tracing::info!(
            event = "p2p_inbox",
            outcome = if inserted { "enqueued" } else { "duplicate" },
            message_id = %message_id,
            message_type = %inbox_message.msg_type,
            from_peer_id = %from_peer_id,
            content_size = message.len(),
            "received P2P message"
        );
    } else {
        crate::p2p_admission::record_admitted_unregistered();
        tracing::debug!(
            event = "p2p_inbox",
            outcome = if inserted { "enqueued" } else { "duplicate" },
            message_id = %message_id,
            message_type = %inbox_message.msg_type,
            from_peer_id = %from_peer_id,
            content_size = message.len(),
            "received P2P message"
        );
    }
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

async fn fail_p2p_inbox_without_aborting_batch(
    local_db: &LocalDB,
    message_id: &str,
    lease_token: &str,
    error: &str,
) {
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage.fail_p2p_inbox_message(message_id, lease_token, error).await
    }
    .await;
    match result {
        Ok(true) => {}
        Ok(false) => log_stale_p2p_inbox_lease(message_id, lease_token, "fail"),
        Err(error) => log_queue_bookkeeping_failure("p2p_inbox", message_id, "fail", &error),
    }
}

async fn defer_p2p_inbox_without_aborting_batch(
    local_db: &LocalDB,
    message_id: &str,
    lease_token: &str,
    next_retry_at: i64,
    reason: &str,
) {
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage.defer_p2p_inbox_message(message_id, lease_token, next_retry_at, reason).await
    }
    .await;
    match result {
        Ok(true) => {}
        Ok(false) => log_stale_p2p_inbox_lease(message_id, lease_token, "defer"),
        Err(error) => log_queue_bookkeeping_failure("p2p_inbox", message_id, "defer", &error),
    }
}

async fn abandon_p2p_inbox_after_panic(
    local_db: &LocalDB,
    message_id: &str,
    lease_token: &str,
    detail: &str,
) {
    let error = format!("handler panicked: {detail}");
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage
            .abandon_p2p_inbox_message(
                message_id,
                lease_token,
                current_time_secs(),
                QUEUE_ABANDON_BACKOFF_SECS,
                &error,
            )
            .await
    }
    .await;
    match result {
        Ok(true) => {}
        Ok(false) => log_stale_p2p_inbox_lease(message_id, lease_token, "abandon"),
        Err(error) => log_queue_bookkeeping_failure("p2p_inbox", message_id, "abandon", &error),
    }
}

async fn abandon_local_message_after_panic(
    local_db: &LocalDB,
    message_id: &str,
    message_version: i64,
    detail: &str,
) {
    let error = format!("handler panicked: {detail}");
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage
            .abandon_local_message(
                message_id,
                message_version,
                current_time_secs(),
                QUEUE_ABANDON_BACKOFF_SECS,
                &error,
            )
            .await
    }
    .await;
    match result {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            event = "local_message_queue",
            outcome = "stale_claim",
            message_id,
            message_version,
            operation = "abandon",
            "ignored local message update from a stale claim"
        ),
        Err(error) => {
            log_queue_bookkeeping_failure("local_message_queue", message_id, "abandon", &error)
        }
    }
}

/// Claim one listed inbox row immediately before dispatching it.
///
/// `None` means the row is no longer claimable or the claim could not be
/// persisted; either way it is skipped this tick and listed again on the next.
async fn claim_p2p_inbox_candidate(
    local_db: &LocalDB,
    message_id: &str,
) -> Option<P2pInboxMessage> {
    let now = current_time_secs();
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage.claim_p2p_inbox_message(message_id, now, now + P2P_INBOX_LEASE_SECS).await
    }
    .await;
    match result {
        Ok(Some(message)) => Some(message),
        Ok(None) => {
            tracing::debug!(
                event = "p2p_inbox",
                outcome = "claim_skipped",
                message_id,
                "listed inbox message is no longer claimable"
            );
            None
        }
        Err(error) => {
            tracing::error!(
                event = "p2p_inbox",
                outcome = "claim_failed",
                message_id,
                error = %error,
                "failed to claim a listed inbox message; it stays queued for the next tick"
            );
            None
        }
    }
}

/// Claim one listed local message immediately before dispatching it. See
/// [`claim_p2p_inbox_candidate`].
async fn claim_local_candidate(
    local_db: &LocalDB,
    candidate: &store::Message,
) -> Option<store::Message> {
    let now = current_time_secs();
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage
            .claim_local_message(
                &candidate.message_id,
                candidate.message_version,
                now,
                now + LOCAL_MESSAGE_LEASE_SECS,
            )
            .await
    }
    .await;
    match result {
        Ok(Some(message)) => Some(message),
        Ok(None) => {
            tracing::debug!(
                event = "local_message_queue",
                outcome = "claim_skipped",
                queued_message_id = %candidate.message_id,
                message_version = candidate.message_version,
                "listed local message is no longer claimable"
            );
            None
        }
        Err(error) => {
            tracing::error!(
                event = "local_message_queue",
                outcome = "claim_failed",
                queued_message_id = %candidate.message_id,
                error = %error,
                "failed to claim a listed local message; it stays queued for the next tick"
            );
            None
        }
    }
}

/// Charge and release every queue claim left behind by a previous process.
///
/// Run once at startup, before any dispatcher starts. The database is
/// process-local, so a `Processing` row at this point is an attempt that never
/// reported an outcome. Waiting for its lease to lapse instead kept the row
/// locked for minutes while every producer touching it backed off with
/// ResourceLocked; a graceful shutdown never leaves such rows behind.
pub async fn reclaim_stale_queue_claims(local_db: &LocalDB) -> Result<(u64, u64)> {
    let now = current_time_secs();
    let mut storage = local_db.start_immediate_transaction().await?;
    let local = storage.reclaim_processing_local_messages(now, QUEUE_ABANDON_BACKOFF_SECS).await?;
    let inbox =
        storage.reclaim_processing_p2p_inbox_messages(now, QUEUE_ABANDON_BACKOFF_SECS).await?;
    storage.commit().await?;
    Ok((local, inbox))
}

/// Restore persisted operator bindings, re-verify signatures and refresh stake asynchronously.
pub async fn load_persisted_peer_bindings(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
) -> Result<u64> {
    let bindings = local_db
        .acquire()
        .await?
        .load_p2p_peer_bindings(crate::p2p_admission::OPERATOR_BINDING_LOAD_LIMIT)
        .await?;
    let registry = crate::p2p_admission::peer_registry();
    let mut loaded = 0;
    let mut verified_bindings = std::collections::HashMap::new();
    for node in bindings {
        let node_info = NodeInfo {
            peer_id: node.peer_id.clone(),
            btc_pub_key: node.btc_pub_key.clone(),
            binding_sig: node.binding_sig.clone(),
            binding_issued_at: node.binding_issued_at,
            ..Default::default()
        };
        let Some(operator_key) = verify_node_info_binding(&node_info) else {
            continue;
        };
        if node.binding_issued_at > current_time_secs() + NODE_INFO_BINDING_MAX_FUTURE_SECS {
            continue;
        }
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            let operator_key = crate::p2p_admission::operator_key(&operator_key);
            registry.observe_operator_binding(&peer_id, &operator_key, node.binding_issued_at);
            verified_bindings.insert(peer_id, (operator_key, node.binding_issued_at));
            loaded += 1;
        }
    }
    // Apply configured bindings only where no signed binding exists; stake still requires confirmation.
    for (peer_id, operator_key) in crate::env::get_p2p_trusted_operator_bindings() {
        match registry.trust_operator_binding(&peer_id, &operator_key) {
            Ok(()) => loaded += 1,
            Err(conflict) => tracing::warn!(
                event = "p2p_admission",
                outcome = "trusted_binding_ignored",
                peer_id = %peer_id,
                configured_key = %hex::encode(operator_key),
                conflict = ?conflict,
                env = crate::env::ENV_P2P_TRUSTED_OPERATOR_BINDINGS,
                "configured operator binding disagrees with one the operator signed; keeping \
                 the signed binding — update or remove the configured entry"
            ),
        }
    }
    // Apply configured replay resets, then restore persisted marks before admission.
    let reset_peers = crate::env::get_p2p_replay_mark_reset_peers();
    if !reset_peers.is_empty() {
        let dropped = local_db.acquire().await?.delete_p2p_replay_marks(&reset_peers).await?;
        tracing::warn!(
            event = "p2p_admission",
            outcome = "replay_marks_reset",
            requested = reset_peers.len(),
            dropped,
            "dropped persisted replay marks on operator request"
        );
    }
    for (peer_id, highest) in local_db.acquire().await?.load_p2p_replay_marks().await? {
        if let Ok(peer_id) = PeerId::from_str(&peer_id) {
            crate::p2p_admission::replay_guard().restore_mark(&peer_id, highest as u64);
        }
    }
    // Peers confirmed on chain in an earlier session keep their class and are
    // re-validated as known members, outside the discovery budget.
    loaded += crate::p2p_admission::seed_registry_from_store(
        local_db,
        registry,
        &verified_bindings,
        Instant::now(),
    )
    .await?;
    // Everything loaded is due; the unconfirmed remainder is picked up by the
    // regular tick as lookup slots free up.
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    Ok(loaded)
}

/// A clock disagreement below this is not worth reporting.
const CLOCK_LEAD_REPORT_THRESHOLD: Duration = Duration::from_secs(60);

/// Warn about registered authors whose message numbering is ahead of the local clock.
fn report_clock_leads(leads: Vec<(PeerId, Duration)>) {
    let ahead: Vec<&(PeerId, Duration)> =
        leads.iter().filter(|(_, lead)| *lead >= CLOCK_LEAD_REPORT_THRESHOLD).collect();
    let max_lead = ahead.iter().map(|(_, lead)| *lead).max().unwrap_or_default();
    match ahead.as_slice() {
        [] => {}
        [(peer, lead)] => tracing::warn!(
            event = "p2p_admission",
            outcome = "author_clock_ahead",
            peer_id = %peer,
            lead_secs = lead.as_secs(),
            "a registered author's clock is ahead of this node's; past the tolerance its \
             messages are refused as coming from the future"
        ),
        several => tracing::error!(
            event = "p2p_admission",
            outcome = "local_clock_behind_suspected",
            authors = several.len(),
            max_lead_secs = max_lead.as_secs(),
            "several registered authors' clocks are ahead of this node's: check this node's \
             clock (NTP). Past the tolerance their messages are refused as coming from the future"
        ),
    }
}

/// Refresh registrations, summarize drops and purge stale node rows.
pub async fn run_p2p_admission_maintenance(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let now = Instant::now();
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    crate::p2p_admission::log_drop_summary();
    // Expired bans only need forgetting: the gate compares against the clock.
    crate::p2p_admission::direct_peer_strikes().take_expired_bans(now);
    report_clock_leads(crate::p2p_admission::replay_guard().take_clock_leads());
    for (peer, rejected) in crate::p2p_admission::replay_guard().take_lockout_suspects() {
        tracing::warn!(
            event = "p2p_admission",
            outcome = "replay_lockout_suspected",
            peer_id = %peer,
            rejected,
            reset_env = crate::env::ENV_P2P_REPLAY_MARK_RESET_PEERS,
            "a registered author keeps being refused as a replay; if it is not under \
             attack, its clock stepped back or another instance shares its key"
        );
    }

    // Persist replay marks and confirm them only after a successful write.
    let owed = crate::p2p_admission::replay_guard().pending_marks();
    let marks: Vec<(String, i64)> = owed
        .iter()
        .map(|(peer, highest)| (peer.to_string(), (*highest).min(i64::MAX as u64) as i64))
        .collect();
    let purge_due = crate::p2p_admission::node_table_purge_due(NODE_TABLE_PURGE_INTERVAL, now);
    if marks.is_empty() && !purge_due {
        return;
    }
    let result = async {
        let mut storage = local_db.acquire().await?;
        storage.raise_p2p_replay_marks(&marks).await?;
        crate::p2p_admission::replay_guard().confirm_persisted(&owed);
        if !purge_due {
            return Ok(0);
        }
        if let Some(verifiers) = crate::p2p_admission::peer_registry().verifier_peer_ids() {
            storage.prune_p2p_replay_marks(&verifiers).await?;
        }
        storage
            .purge_stale_unregistered_nodes(
                current_time_secs() - NODE_TABLE_STALE_SECS,
                &crate::env::get_peer_id(),
            )
            .await
    }
    .await;
    match result {
        Ok(0) => {}
        Ok(purged) => tracing::info!(
            event = "p2p_admission",
            outcome = "stale_nodes_purged",
            purged,
            "removed node rows of unregistered peers that stopped announcing themselves"
        ),
        Err(error) => tracing::warn!(
            event = "p2p_admission",
            outcome = "maintenance_write_failed",
            error = %error,
            "failed to persist replay marks or purge stale node rows; retried next tick"
        ),
    }
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

/// Drain inbox batches until caught up or the message-start budget is exhausted.
#[allow(clippy::too_many_arguments)]
async fn handle_p2p_inbox_messages(
    swarm: &mut dyn MessagePublisher,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    metrics_state: &MetricsState,
    shutdown: &CancellationToken,
) -> Result<bool> {
    let started_at = Instant::now();
    let deadline = started_at + P2P_INBOX_DRAIN_BUDGET;
    let mut first_batch = true;
    // A backlogged worker comes straight back here; the retention sweeps keep
    // the cadence of the tick they were written for.
    let housekeeping = inbox_housekeeping_due(started_at);
    let mut total_claimed = 0;
    loop {
        let batch = drain_p2p_inbox_batch(
            swarm,
            local_db,
            btc_client,
            goat_client,
            http_client,
            soldering_builder,
            actor.clone(),
            metrics_state,
            shutdown,
            first_batch,
            first_batch && housekeeping,
            deadline,
        )
        .await?;
        first_batch = false;
        total_claimed += batch.claimed;
        // Stop when fewer messages were claimed than requested.
        let full_batch = (batch.claimed as i64) >= get_p2p_inbox_batch_size();
        if !full_batch || Instant::now() >= deadline || shutdown.is_cancelled() {
            // Continue immediately only when a productive pass stopped on its budget.
            return Ok(!shutdown.is_cancelled()
                && total_claimed > 0
                && (batch.cut_short || full_batch));
        }
    }
}

/// Whether the inbox retention sweeps should run in this pass: once per regular
/// tick interval, however often a backlog brings the worker back.
fn inbox_housekeeping_due(now: Instant) -> bool {
    static LAST_RUN: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last_run = LAST_RUN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let interval = Duration::from_secs(crate::env::REGULAR_TASK_INTERVAL_SECOND);
    if last_run.is_some_and(|last_run| now.saturating_duration_since(last_run) < interval) {
        return false;
    }
    *last_run = Some(now);
    true
}

struct InboxBatch {
    claimed: usize,
    /// The budget ran out with listed rows still unserved.
    cut_short: bool,
}

/// List and dispatch one inbox batch.
#[allow(clippy::too_many_arguments)]
async fn drain_p2p_inbox_batch(
    swarm: &mut dyn MessagePublisher,
    local_db: &LocalDB,
    btc_client: &Arc<BTCClient>,
    goat_client: &Arc<GOATClient>,
    http_client: &HttpAsyncClient,
    soldering_builder: &Option<Arc<BabeBundleBuilder>>,
    actor: Actor,
    metrics_state: &MetricsState,
    shutdown: &CancellationToken,
    first_batch: bool,
    housekeeping: bool,
    deadline: Instant,
) -> Result<InboxBatch> {
    let now = current_time_secs();
    let active_heavy_task_ids = active_heavy_task_message_ids();
    let mut storage = local_db.start_immediate_transaction().await?;
    let (mut quarantined, mut purged, mut expired, mut trimmed, mut capped) = (0, 0, 0, 0, 0);
    if housekeeping {
        // Quarantine rows whose dispatch repeatedly failed to report any outcome.
        // Returned retryable errors do not consume this budget.
        quarantined = storage.quarantine_p2p_inbox_messages(now, QUEUE_MAX_ABANDONS).await?;
        // Bound terminal metadata and the temporary payload retained for manual
        // inspection of quarantined rows.
        purged = storage.purge_terminal_p2p_inbox_messages(now - MESSAGE_EXPIRE_TIME).await?;
        // Expire Pending rows by age, using the shorter unregistered retention.
        expired = storage
            .expire_pending_p2p_inbox_messages(
                Some(store::P2pInboxAdmissionClass::Unregistered),
                now - crate::p2p_admission::UNREGISTERED_PENDING_TTL_SECS,
            )
            .await?
            + storage.expire_pending_p2p_inbox_messages(None, now - MESSAGE_EXPIRE_TIME).await?;
        // Cap quarantined payload bytes and terminal row count.
        trimmed =
            storage.trim_quarantined_p2p_inbox_payloads(P2P_INBOX_QUARANTINE_MAX_BYTES).await?;
        capped = storage
            .purge_p2p_inbox_over_terminal_cap(
                P2P_INBOX_TERMINAL_MAX_ROWS,
                P2P_INBOX_TERMINAL_PURGE_BATCH,
            )
            .await?;
    }
    // Only list here. Each row is claimed right before its own dispatch so a
    // crash mid-dispatch is charged to that row alone.
    let batch_size = get_p2p_inbox_batch_size();
    let candidates = storage
        .list_claimable_p2p_inbox_messages_by_class(
            now,
            batch_size,
            (batch_size / P2P_INBOX_REGISTERED_BATCH_DIVISOR).max(1),
            (batch_size / P2P_INBOX_UNREGISTERED_BATCH_DIVISOR).max(1),
            QUEUE_MAX_ABANDONS,
            &active_heavy_task_ids,
        )
        .await?;
    storage.commit().await?;
    let mut claimed = 0;
    let mut cut_short = false;

    if quarantined > 0 {
        tracing::warn!(
            event = "p2p_inbox",
            outcome = "quarantined",
            quarantined,
            max_abandons = QUEUE_MAX_ABANDONS,
            "quarantined inbox messages that repeatedly abandoned their lease"
        );
    }
    if purged > 0 {
        tracing::info!(
            event = "p2p_inbox",
            outcome = "purged",
            purged,
            "removed terminal inbox rows past their retention window"
        );
    }
    if expired > 0 {
        tracing::warn!(
            event = "p2p_inbox",
            outcome = "expired",
            expired,
            "retired inbox messages that stayed pending past their retention window"
        );
    }
    if trimmed > 0 || capped > 0 {
        tracing::info!(
            event = "p2p_inbox",
            outcome = "capacity_trimmed",
            trimmed_quarantine_payloads = trimmed,
            deleted_terminal_rows = capped,
            "trimmed retained inbox data over its capacity limits"
        );
    }

    // Serve listed classes using the persistent weighted rotation.
    let mut queues: [std::collections::VecDeque<store::P2pInboxMessage>; 3] = Default::default();
    for candidate in candidates {
        queues[crate::p2p_admission::InboxSchedule::queue_of(&candidate.admission_class)]
            .push_back(candidate);
    }
    loop {
        // Check the budget before each claim; always allow the first message to make progress.
        if (claimed > 0 || !first_batch) && Instant::now() >= deadline {
            cut_short = queues.iter().any(|queue| !queue.is_empty());
            break;
        }
        let Some(candidate) = crate::p2p_admission::inbox_schedule().next(&mut queues) else {
            break;
        };
        let Some(message) = claim_p2p_inbox_candidate(local_db, &candidate.message_id).await else {
            continue;
        };
        claimed += 1;
        let from_peer_id = match PeerId::from_str(&message.from_peer) {
            Ok(peer_id) => peer_id,
            Err(error) => {
                fail_p2p_inbox_without_aborting_batch(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    &format!("invalid stored source peer: {error}"),
                )
                .await;
                continue;
            }
        };
        let decoded = match GOATMessage::deserialize_message(&message.content).await {
            Ok(message) => message,
            Err(error) => {
                fail_p2p_inbox_without_aborting_batch(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    &error.to_string(),
                )
                .await;
                continue;
            }
        };
        // After persistence, sender authorization belongs to the handler, not the admission cache.
        let fingerprint = DispatchFingerprint::of(decoded.content());
        let heavy_task = heavy_task_from_content(decoded.content(), &actor);

        if let Some(heavy_task) = heavy_task {
            let local_db = local_db.clone();
            let btc_client = Arc::clone(btc_client);
            let goat_client = Arc::clone(goat_client);
            let soldering_builder = soldering_builder.clone();
            let metrics_state = metrics_state.clone();
            let message_id = message.message_id.clone();
            let lease_token = message.lease_token.clone();
            let attempt_count = message.attempt_count;
            let task_type = message.msg_type.clone();
            let task_type_for_task = task_type.clone();
            let task_kind = heavy_task.kind();
            let graph_id = heavy_task.graph_id();
            let Some(permit) = try_acquire_heavy_task_permit(&message_id, &lease_token) else {
                let retry_after_secs = 5;
                defer_p2p_inbox_without_aborting_batch(
                    &local_db,
                    &message_id,
                    &lease_token,
                    current_time_secs() + retry_after_secs,
                    RetryableDispatchReason::ResourceLocked.code(),
                )
                .await;
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
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let lease_cancellation = CancellationToken::new();
                let _lease_guard = LeaseRenewalGuard(lease_cancellation.clone());
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
                // Set the inbox task-local context explicitly for the spawned heavy task.
                let execution = supervise_dispatch(
                    track_inbox_retry(fingerprint, run_heavy_task(&context, heavy_task)),
                    &shutdown,
                )
                .await;
                lease_cancellation.cancel();
                let lease_is_current = match lease_renewal.await {
                    Ok(lease_is_current) => lease_is_current,
                    Err(error) => {
                        tracing::error!(error = %error, message_id, "P2P inbox lease renewal task failed");
                        false
                    }
                };
                match execution {
                    DispatchExecution::Completed(result) => {
                        if !lease_is_current {
                            return;
                        }
                        // Apply the same RPC retry classification as inline dispatch.
                        let result = result.map_err(classify_retryable_dispatch_error);
                        metrics_state.record_message_dispatch(
                            &task_type_for_task,
                            if result.is_ok() { "success" } else { "failed" },
                        );
                        if let Err(error) = finish_p2p_inbox_attempt(
                            &local_db,
                            &metrics_state,
                            &message_id,
                            &lease_token,
                            &task_type_for_task,
                            attempt_count,
                            result,
                        )
                        .await
                        {
                            tracing::error!(error = %error, message_id, "failed to persist heavy task result");
                        }
                    }
                    DispatchExecution::Shutdown => {
                        if lease_is_current {
                            defer_p2p_inbox_without_aborting_batch(
                                &local_db,
                                &message_id,
                                &lease_token,
                                current_time_secs(),
                                "graceful_shutdown",
                            )
                            .await;
                        }
                    }
                    DispatchExecution::Panicked(detail) => {
                        metrics_state.record_message_dispatch(&task_type_for_task, "failed");
                        tracing::error!(
                            event = "heavy_task_panic",
                            outcome = "node_shutdown",
                            message_id,
                            graph_id = %graph_id,
                            message_type = %task_type_for_task,
                            task_kind,
                            detail,
                            "heavy task panicked; recorded an abandon and stopping the node"
                        );
                        abandon_p2p_inbox_after_panic(
                            &local_db,
                            &message_id,
                            &lease_token,
                            &detail,
                        )
                        .await;
                        shutdown.cancel();
                    }
                }
            });
            tracing::info!(
                event = "p2p_inbox",
                outcome = "heavy_task_started",
                message_id = %message.message_id,
                graph_id = %graph_id,
                message_type = %task_type,
                task_kind,
                "started background heavy task"
            );
            continue;
        }
        let raw_message_id = match hex::decode(&message.message_id) {
            Ok(message_id) => MessageId(message_id),
            Err(error) => {
                fail_p2p_inbox_without_aborting_batch(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    &format!("invalid stored message id: {error}"),
                )
                .await;
                continue;
            }
        };

        // Keep the deeply nested dispatch future out of the enclosing task's
        // inline state machine.
        let dispatch: BoxedDispatch<'_> = Box::pin(dispatch_decoded_p2p_message(
            swarm,
            local_db,
            btc_client,
            goat_client,
            http_client,
            soldering_builder,
            actor.clone(),
            from_peer_id,
            raw_message_id,
            decoded,
            metrics_state,
        ));
        let handler_budget = crate::env::get_p2p_handler_timeout();
        let dispatch = track_inbox_retry(fingerprint, dispatch);
        let dispatch = tokio::time::timeout(handler_budget, dispatch);
        let result = match supervise_dispatch(dispatch, shutdown).await {
            DispatchExecution::Completed(Ok(result)) => result,
            // Cancel an expired handler at its current await and retry its persisted work.
            DispatchExecution::Completed(Err(_elapsed)) => {
                tracing::warn!(
                    event = "p2p_inbox",
                    outcome = "handler_timeout",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    from_peer_id = %from_peer_id,
                    budget_secs = handler_budget.as_secs(),
                    attempt_count = message.attempt_count + 1,
                    "P2P message handler exceeded its execution budget; deferred for retry"
                );
                defer_p2p_inbox_without_aborting_batch(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    current_time_secs() + p2p_retry_delay_secs(message.attempt_count + 1),
                    "handler_timeout",
                )
                .await;
                continue;
            }
            DispatchExecution::Shutdown => {
                defer_p2p_inbox_without_aborting_batch(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    current_time_secs(),
                    "graceful_shutdown",
                )
                .await;
                return Ok(InboxBatch { claimed, cut_short: false });
            }
            DispatchExecution::Panicked(detail) => {
                tracing::error!(
                    event = "p2p_dispatch_panic",
                    outcome = "node_shutdown",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    detail,
                    "P2P message handler panicked; recorded an abandon and stopping the node"
                );
                abandon_p2p_inbox_after_panic(
                    local_db,
                    &message.message_id,
                    &message.lease_token,
                    &detail,
                )
                .await;
                shutdown.cancel();
                bail!("P2P message handler panicked: {detail}");
            }
        };
        metrics_state.record_message_dispatch(
            &message.msg_type,
            if result.is_ok() { "success" } else { "failed" },
        );
        if let Err(error) = finish_p2p_inbox_attempt(
            local_db,
            metrics_state,
            &message.message_id,
            &message.lease_token,
            &message.msg_type,
            message.attempt_count,
            result,
        )
        .await
        {
            log_queue_bookkeeping_failure("p2p_inbox", &message.message_id, "finish", &error);
        }
    }
    Ok(InboxBatch { claimed, cut_short })
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
                tracing::warn!(
                    event = "p2p_inbox",
                    outcome = "failed",
                    message_id,
                    message_type,
                    attempt_count,
                    error = %error,
                    "cached P2P message failed permanently"
                );
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

/// Publish due outbox rows until caught up, blocked or past the start budget.
async fn handle_p2p_outbox_messages(
    swarm: &mut dyn MessagePublisher,
    local_db: &LocalDB,
) -> Result<()> {
    let deadline = Instant::now() + P2P_INBOX_DRAIN_BUDGET;
    let now = current_time_secs();
    let mut storage = local_db.start_immediate_transaction().await?;
    let expired = storage.expire_p2p_outbox_retry_messages(now).await?;
    storage.commit().await?;

    if expired > 0 {
        tracing::warn!(
            event = "p2p_outbox",
            outcome = "retry_window_expired",
            expired,
            "outbound messages reached the end of their retry window: graph-setup messages without the expected ACK, signing-round messages without their round closing"
        );
    }
    recover_exhausted_setup(local_db).await?;
    drain_p2p_outbox(swarm, local_db, deadline).await
}

/// Recovery is driven by durable delivery state even when no new gossip arrives.
async fn recover_exhausted_setup(local_db: &LocalDB) -> Result<()> {
    let now = current_time_secs();
    let Some((id, bytes, created_at)) = local_db.acquire().await?.next_exhausted_setup(now).await?
    else {
        return Ok(());
    };
    let decoded = GOATMessage::deserialize_message(&bytes).await;
    let mut storage = local_db.start_immediate_transaction().await?;
    let mut resume = false;
    let mut canonical = id.clone();
    if let Ok(message) = decoded
        && let Some(key) = graph_setup_outbox_id(&message.content)
        && let BusinessRef::Graph { instance_id, graph_id } = message.content.business_ref()
    {
        canonical = key;
        let instance = storage.find_instance(&instance_id).await?;
        let graph = storage.find_graph(&graph_id).await?;
        resume = now - created_at < MESSAGE_EXPIRE_TIME
            && graph.is_none()
            && instance.is_some_and(|row| {
                matches!(
                    InstanceBridgeInStatus::from_str(&row.status),
                    Ok(InstanceBridgeInStatus::UserBroadcastPeginPrepare
                        | InstanceBridgeInStatus::Presigned
                        | InstanceBridgeInStatus::RelayerL1Broadcasted
                        | InstanceBridgeInStatus::RelayerL2Minted)
                )
            });
    }
    storage
        .recover_setup_delivery(
            &id,
            &canonical,
            now,
            get_p2p_graph_setup_retry_window_secs(),
            resume,
        )
        .await?;
    storage.commit().await?;
    tracing::info!(event = "setup_delivery_recovery", message_id = %id, resume,
        "settled exhausted setup delivery");
    Ok(())
}

fn setup_retry_interval_secs(publish_count: i64, base: i64, id: &str) -> i64 {
    let base = base.max(1);
    let delay = base
        .saturating_mul(1_i64 << publish_count.saturating_sub(1).clamp(0, 20))
        .min(base.max(60));
    // Stable jitter keeps retries reproducible across restarts without synchronizing peers.
    let jitter =
        id.bytes().fold(publish_count as u64, |n, b| n.wrapping_mul(31).wrapping_add(b as u64)) % 7;
    delay + jitter as i64
}

async fn drain_p2p_outbox(
    swarm: &mut dyn MessagePublisher,
    local_db: &LocalDB,
    deadline: Instant,
) -> Result<()> {
    loop {
        // Check the start budget before claiming the next row; let in-flight publishes finish.
        if Instant::now() >= deadline {
            break;
        }
        let now = current_time_secs();
        let mut storage = local_db.start_immediate_transaction().await?;
        let message =
            storage.claim_p2p_outbox_messages(now, now + P2P_INBOX_LEASE_SECS, 1).await?.pop();
        storage.commit().await?;
        let Some(message) = message else { break };
        match publish_p2p_outbox_row(swarm, local_db, &message).await {
            Ok(OutboxRowOutcome::PublishFailed) => break,
            Ok(OutboxRowOutcome::Published | OutboxRowOutcome::Closed) => {}
            Err(error) => {
                tracing::warn!(
                    event = "p2p_outbox",
                    outcome = "bookkeeping_failed",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    error = %error,
                    "could not settle an outbound P2P message; releasing it for the next pass"
                );
                if let Ok(mut storage) = local_db.acquire().await {
                    let _ = storage
                        .retry_p2p_outbox_message(
                            &message.message_id,
                            current_time_secs() + PROTOCOL_RETRY_BASE_SECS,
                            &error.to_string(),
                        )
                        .await;
                }
            }
        }
    }
    Ok(())
}

enum OutboxRowOutcome {
    Published,
    PublishFailed,
    /// Settled without publishing: corrupt, or nobody needs it any more.
    Closed,
}

async fn publish_p2p_outbox_row(
    swarm: &mut dyn MessagePublisher,
    local_db: &LocalDB,
    message: &store::P2pOutboxMessage,
) -> Result<OutboxRowOutcome> {
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
            return Ok(OutboxRowOutcome::Closed);
        }
    };
    if let Some(canonical_id) = graph_setup_outbox_id(&outbound.content)
        && let BusinessRef::Graph { instance_id, graph_id } = outbound.content.business_ref()
    {
        let mut storage = local_db.acquire().await?;
        let instance = storage.find_instance(&instance_id).await?;
        let failed = instance.as_ref().is_some_and(|row| {
            InstanceBridgeInStatus::from_str(&row.status).is_ok_and(|status| {
                SigningRound::GraphSigning.delivery_finished(None, Some(&status))
            })
        });
        if failed
            || storage.find_graph(&graph_id).await?.is_some()
            || current_time_secs() - message.created_at >= MESSAGE_EXPIRE_TIME
        {
            storage.cancel_p2p_outbox_message(&canonical_id).await?;
            return Ok(OutboxRowOutcome::Closed);
        }
    }
    let signing_round = if message.message_id.starts_with(PROTOCOL_OUTBOX_PREFIX) {
        let round = SigningRound::of(&outbound.content)
            .filter(|_| outbound.content.business_ref() != BusinessRef::Unscoped);
        if round.is_none() {
            local_db
                .acquire()
                .await?
                .fail_p2p_outbox_message(
                    &message.message_id,
                    "signing outbox message has no round or business reference",
                )
                .await?;
            return Ok(OutboxRowOutcome::Closed);
        }
        round
    } else {
        None
    };
    if signing_round.is_some() && protocol_delivery_finished(local_db, &outbound.content).await? {
        local_db.acquire().await?.complete_p2p_outbox_message(&message.message_id).await?;
        tracing::info!(
            event = "p2p_outbox",
            outcome = "round_closed",
            message_id = %message.message_id,
            message_type = %message.msg_type,
            publish_count = message.publish_count,
            "stopped re-publishing a signing-round message: its round is over"
        );
        return Ok(OutboxRowOutcome::Closed);
    }
    let result = send_to_peer(swarm, outbound).await;
    let mut storage = local_db.acquire().await?;
    match result {
        Ok(_) => {
            if message.retry_until > 0 {
                let interval = match signing_round {
                    Some(round) => protocol_retry_interval_secs(
                        message.publish_count + 1,
                        round.retry_ceiling_secs(crate::env::get_p2p_protocol_retry_max_secs()),
                    ),
                    None => setup_retry_interval_secs(
                        message.publish_count + 1,
                        message.retry_interval_secs,
                        &message.message_id,
                    ),
                };
                let next_retry_at = current_time_secs() + interval;
                storage.schedule_p2p_outbox_retry(&message.message_id, next_retry_at).await?;
                tracing::info!(
                    event = "p2p_outbox",
                    outcome = "published_retry_window",
                    message_id = %message.message_id,
                    message_type = %message.msg_type,
                    next_retry_at,
                    retry_until = message.retry_until,
                    "published durable P2P message; it stays due until acknowledged, closed or expired"
                );
            } else {
                storage.complete_p2p_outbox_message(&message.message_id).await?;
            }
            Ok(OutboxRowOutcome::Published)
        }
        Err(error) => {
            // `attempt_count` counts claims, and a signing-round row is claimed
            // for days: by it, one failed publish would cost the longest delay.
            let retry_after_secs = if signing_round.is_some() {
                PROTOCOL_RETRY_BASE_SECS
            } else {
                p2p_retry_delay_secs(message.attempt_count)
            };
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
            Ok(OutboxRowOutcome::PublishFailed)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_self_p2p_msg(
    swarm: &mut dyn MessagePublisher,
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
    shutdown: &CancellationToken,
) -> Result<bool> {
    if id != GOATMessage::default_message_id() {
        tracing::warn!(
            event = "local_message_queue",
            outcome = "unexpected_message_id",
            message_id = ?id,
            "ignoring local queue trigger with an unexpected message id"
        );
        return Ok(false);
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

    let (candidates, quarantined) =
        list_batch_local_msg(local_db, QUEUE_MAX_ABANDONS, LOCAL_MESSAGE_BATCH_SIZE).await?;
    if quarantined > 0 {
        tracing::warn!(
            event = "local_message_queue",
            outcome = "quarantined",
            quarantined,
            max_abandons = QUEUE_MAX_ABANDONS,
            "retired local messages that kept failing to report an outcome"
        );
    }
    tracing::info!(
        event = "local_message_queue",
        outcome = "batch_listed",
        role = %actor,
        batch_size = candidates.len(),
        "listed claimable local messages"
    );
    let local_deadline = Instant::now() + P2P_INBOX_DRAIN_BUDGET;
    let listed_full_batch = candidates.len() as i64 >= LOCAL_MESSAGE_BATCH_SIZE;
    let mut local_dispatched = 0_usize;
    let mut local_cut_short = false;
    for (index, candidate) in candidates.into_iter().enumerate() {
        if index > 0 && Instant::now() >= local_deadline {
            local_cut_short = true;
            break;
        }
        // Claim right before dispatch so a crash mid-dispatch is charged to
        // this row alone, and so a producer that re-armed the row since it was
        // listed wins: the stale version is skipped until the next tick.
        let Some(message) = claim_local_candidate(local_db, &candidate).await else {
            continue;
        };
        local_dispatched += 1;
        let queue_wait_secs = current_time_secs().saturating_sub(message.created_at);
        let started_at = Instant::now();
        let claim = LocalMessageClaim {
            message_id: message.message_id.clone(),
            message_version: message.message_version,
        };
        let dispatch: BoxedDispatch<'_> = Box::pin(ACTIVE_LOCAL_MESSAGE_CLAIM.scope(
            claim,
            recv_and_dispatch(
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
            ),
        ));
        let dispatch = tokio::time::timeout(crate::env::get_p2p_handler_timeout(), dispatch);
        let result = match supervise_dispatch(dispatch, shutdown).await {
            DispatchExecution::Completed(Ok(result)) => result,
            DispatchExecution::Completed(Err(_)) => Err(retryable_dispatch_error(
                RetryableDispatchReason::ExternalRpcUnavailable,
                None,
                "local handler execution budget exceeded",
            )),
            DispatchExecution::Shutdown => return Ok(false),
            DispatchExecution::Panicked(detail) => {
                tracing::error!(
                    event = "local_message_dispatch_panic",
                    outcome = "node_shutdown",
                    queued_message_id = %message.message_id,
                    business_id = %message.business_id,
                    message_type = %message.msg_type,
                    detail,
                    "local message handler panicked; recorded an abandon and stopping the node"
                );
                abandon_local_message_after_panic(
                    local_db,
                    &message.message_id,
                    message.message_version,
                    &detail,
                )
                .await;
                shutdown.cancel();
                bail!("local message handler panicked: {detail}");
            }
        };
        match result {
            Ok(_) => {
                let mut storage_processor = match local_db.acquire().await {
                    Ok(storage_processor) => storage_processor,
                    Err(error) => {
                        log_queue_bookkeeping_failure(
                            "local_message_queue",
                            &message.message_id,
                            "acquire",
                            &error,
                        );
                        continue;
                    }
                };
                let state_updated = match storage_processor
                    .complete_local_message(&message.message_id, message.message_version)
                    .await
                {
                    Ok(state_updated) => state_updated,
                    Err(error) => {
                        log_queue_bookkeeping_failure(
                            "local_message_queue",
                            &message.message_id,
                            "complete",
                            &error,
                        );
                        continue;
                    }
                };
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
                    // A row that is Pending under our claim version was
                    // rescheduled by the handler itself. Only now, after the
                    // handler returned, is that a reported outcome, so only now
                    // does its consecutive-abandon counter reset.
                    match storage_processor
                        .confirm_local_message_self_defer(
                            &message.message_id,
                            message.message_version,
                        )
                        .await
                    {
                        Ok(true) => {
                            tracing::debug!(
                                event = "local_message_queue",
                                outcome = "self_deferred",
                                role = %actor,
                                business_id = %message.business_id,
                                queued_message_id = %message.message_id,
                                message_type = %message.msg_type,
                                queue_wait_secs,
                                elapsed_ms = started_at.elapsed().as_millis() as u64,
                                "local message handler rescheduled its own queue entry"
                            );
                        }
                        Ok(false) => {
                            let current_state = storage_processor
                                .find_messages_by_id(&message.message_id)
                                .await
                                .ok()
                                .flatten()
                                .map(|message| message.state);
                            tracing::warn!(
                                event = "local_message_queue",
                                outcome = "state_update_conflict",
                                role = %actor,
                                business_id = %message.business_id,
                                queued_message_id = %message.message_id,
                                message_type = %message.msg_type,
                                current_state = ?current_state,
                                queue_wait_secs,
                                elapsed_ms = started_at.elapsed().as_millis() as u64,
                                "local message handler completed but its processed state was not persisted"
                            );
                        }
                        Err(error) => log_queue_bookkeeping_failure(
                            "local_message_queue",
                            &message.message_id,
                            "confirm_self_defer",
                            &error,
                        ),
                    }
                }
            }
            Err(err) => {
                let is_transient = is_retryable_sqlite_error(&err);
                let requested_retry_delay =
                    p2p_retryable_dispatch_error(&err).and_then(|(_, delay)| delay);
                let lock_time: i64 = requested_retry_delay.unwrap_or_else(|| {
                    if is_transient
                        && MessageKind::from_str(&message.msg_type).is_ok_and(MessageKind::is_pegin)
                    {
                        TRANSIENT_PEGIN_RETRY_DELAY_SECS as i64
                    } else {
                        LOCAL_MESSAGE_RETRY_DELAY_SECS
                    }
                });
                let mut storage_processor = match local_db.acquire().await {
                    Ok(storage_processor) => storage_processor,
                    Err(error) => {
                        log_queue_bookkeeping_failure(
                            "local_message_queue",
                            &message.message_id,
                            "acquire",
                            &error,
                        );
                        continue;
                    }
                };
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
                let deferred = storage_processor
                    .defer_local_message(
                        &message.message_id,
                        message.message_version,
                        current_time_secs() + lock_time,
                        &err.to_string(),
                    )
                    .await;
                match deferred {
                    Ok(true) => {}
                    Ok(false) => {
                        // The handler may have rescheduled its own row before
                        // returning the error; that is still a reported outcome.
                        match storage_processor
                            .confirm_local_message_self_defer(
                                &message.message_id,
                                message.message_version,
                            )
                            .await
                        {
                            Ok(true) => tracing::debug!(
                                event = "local_message_queue",
                                outcome = "self_deferred",
                                queued_message_id = %message.message_id,
                                error = %err,
                                "local message handler rescheduled its own queue entry before failing"
                            ),
                            Ok(false) => tracing::warn!(
                                event = "local_message_queue",
                                outcome = "stale_claim",
                                queued_message_id = %message.message_id,
                                message_version = message.message_version,
                                operation = "defer",
                                "ignored local message update from a stale claim"
                            ),
                            Err(error) => log_queue_bookkeeping_failure(
                                "local_message_queue",
                                &message.message_id,
                                "confirm_self_defer",
                                &error,
                            ),
                        }
                        continue;
                    }
                    Err(error) => {
                        log_queue_bookkeeping_failure(
                            "local_message_queue",
                            &message.message_id,
                            "defer",
                            &error,
                        );
                        continue;
                    }
                }
                metrics_state.record_message_retry();
                tracing::warn!(
                    event = "local_message_queue",
                    outcome = "deferred",
                    role = %actor,
                    business_id = %message.business_id,
                    queued_message_id = %message.message_id,
                    message_type = %message.msg_type,
                    retry_after_secs = lock_time,
                    attempt_count = message.attempt_count + 1,
                    queue_wait_secs,
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    error = %err,
                    "failed to process local message; deferred for retry"
                );
            }
        }
    }
    // Handle each queue's failure independently.
    if let Err(error) = handle_p2p_outbox_messages(swarm, local_db).await {
        tracing::error!(error = %error, "failed to drain the durable P2P outbox");
    }
    // A queue that failed reports no backlog: asking for another pass at once
    // would spin on whatever made it fail.
    let local_backlog = local_dispatched > 0 && (local_cut_short || listed_full_batch);
    let inbox_backlog = match handle_p2p_inbox_messages(
        swarm,
        local_db,
        btc_client,
        goat_client,
        http_client,
        soldering_builder,
        actor,
        metrics_state,
        shutdown,
    )
    .await
    {
        Ok(backlog) => backlog,
        Err(error) => {
            tracing::error!(error = %error, "failed to drain the durable P2P inbox");
            if shutdown.is_cancelled() {
                return Err(error);
            }
            false
        }
    };
    Ok(local_backlog || inbox_backlog)
}

/// Filter the message and dispatch message to different handlers, like rpc handler, or other peers
///     * database: inner_rpc: Write or Read.
///     * peers: send
/// TODO: we should create a trait for all the actions of different roles to simplify this function.
#[allow(clippy::too_many_arguments)]
pub async fn recv_and_dispatch(
    swarm: &mut dyn MessagePublisher,
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
    swarm: &mut dyn MessagePublisher,
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
    // Not `get_local_node_info()`: that signs a fresh binding on every call, and
    // this runs for every dispatched message.
    let is_self_peer = crate::env::get_peer_id() == from_peer_id.to_string();
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
    swarm: &mut dyn MessagePublisher,
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
        // Reuse stored committee signatures when retrying graph finalization.
        if !graph.committee_pre_signed() {
            let pub_nonces = order_committee_values(
                &committee_pubkeys,
                pub_nonoces,
                "graph committee pub nonces",
            )?;
            let agg_nonces = nonces_aggregation(&pub_nonces)?;
            let partial_sigs = order_committee_values(
                &committee_pubkeys,
                partial_sigs,
                "graph committee partial sigs",
            )?;
            let committee_sig_for_graph =
                signature_aggregation(&partial_sigs, &agg_nonces, &graph)?;
            push_committee_pre_signatures(&mut graph, &committee_sig_for_graph)?;
        }
        let simplified_graph = graph.to_simplified()?;
        let store_outcome = store_finalized_graph_if_needed(local_db, &simplified_graph).await?;
        mark_graph_as_endorsed(local_db, instance_id, graph_id).await?;
        try_transition_instance_to_presigned(local_db, instance_id).await?;
        // Throttle GraphFinalize recovery and stamp the gate only on success.
        let gate = crate::p2p_admission::protocol_republish_gate();
        let gate_key = format!("graph-finalize:{graph_id}");
        let now = Instant::now();
        if broadcast_graph_finalize && !gate.is_cooling(&gate_key, now) {
            let message_content = GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce: graph.parameters.graph_nonce,
                endorse_sigs: endorsements,
                params_endorse_sigs: params_endorsements,
                graph: simplified_graph,
            });
            send_protocol_message(
                swarm,
                local_db,
                GOATMessage::new(Actor::All, message_content),
                StoredValue::Fresh,
            )
            .await?;
            gate.allow(&gate_key, now);
        }
        return Ok(Some((graph, store_outcome)));
    }
    Ok(None)
}

const PROTOCOL_OUTBOX_PREFIX: &str = "protocol:";

/// The rounds whose messages are kept in the outbox and re-published until the
/// round is over, whatever traffic arrives or does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningRound {
    /// NonceGeneration, AggNonceConsensus, CommitteePresign and EndorseGraph:
    /// what the operator needs to assemble GraphFinalize.
    GraphSigning,
    /// The operator's GraphFinalize, the only source of the finalized graph
    /// until a relayer has posted it.
    GraphFinalize,
    /// The committee's PeginConfirm nonce, consensus and partial-signature rounds.
    PeginConfirm,
}

impl SigningRound {
    pub(crate) fn of(content: &GOATMessageContent) -> Option<Self> {
        match content {
            GOATMessageContent::NonceGeneration(_)
            | GOATMessageContent::AggNonceConsensus(_)
            | GOATMessageContent::CommitteePresign(_)
            | GOATMessageContent::EndorseGraph(_) => Some(Self::GraphSigning),
            GOATMessageContent::GraphFinalize(_) => Some(Self::GraphFinalize),
            GOATMessageContent::PeginConfirmNonce(_)
            | GOATMessageContent::PeginConfirmNonceConsensus(_)
            | GOATMessageContent::PeginConfirmPartialSig(_) => Some(Self::PeginConfirm),
            _ => None,
        }
    }

    /// Retry ceiling; GraphFinalize uses six times the ordinary signing-round ceiling.
    fn retry_ceiling_secs(self, configured_max_secs: i64) -> i64 {
        match self {
            Self::GraphFinalize => configured_max_secs.saturating_mul(6),
            Self::GraphSigning | Self::PeginConfirm => configured_max_secs,
        }
    }

    /// Check delivery completion from local state; unknown statuses remain open.
    /// Graph rounds close by graph status, not another operator's instance progress.
    fn delivery_finished(
        self,
        graph: Option<GraphStatus>,
        instance: Option<&InstanceBridgeInStatus>,
    ) -> bool {
        use InstanceBridgeInStatus as Instance;
        let instance_failed = matches!(
            instance,
            Some(
                Instance::PresignedFailed
                    | Instance::RelayerL2MintedFailed
                    | Instance::Timeout
                    | Instance::UserCanceled
                    | Instance::NoEnoughCommitteesAnswered
                    | Instance::UserDiscarded
            )
        );
        if instance_failed {
            return true;
        }
        match self {
            Self::PeginConfirm => {
                matches!(instance, Some(Instance::RelayerL1Broadcasted | Instance::RelayerL2Minted))
            }
            // A finalized or posted graph proves every member's values reached
            // the operator. An obsoleted one will never be posted or used.
            Self::GraphSigning => graph.is_some_and(|status| match status {
                GraphStatus::OperatorPresigned => false,
                GraphStatus::CommitteePresigned
                | GraphStatus::OperatorDataPushed
                | GraphStatus::PreKickoff
                | GraphStatus::OperatorKickOff
                | GraphStatus::Challenge
                | GraphStatus::Disprove
                | GraphStatus::Obsoleted
                | GraphStatus::Skipped
                | GraphStatus::OperatorTake1
                | GraphStatus::OperatorTake2 => true,
            }),
            // Keep GraphFinalize delivery open until the graph is posted or retired.
            Self::GraphFinalize => graph.is_some_and(|status| match status {
                GraphStatus::OperatorPresigned | GraphStatus::CommitteePresigned => false,
                GraphStatus::OperatorDataPushed
                | GraphStatus::PreKickoff
                | GraphStatus::OperatorKickOff
                | GraphStatus::Challenge
                | GraphStatus::Disprove
                | GraphStatus::Obsoleted
                | GraphStatus::Skipped
                | GraphStatus::OperatorTake1
                | GraphStatus::OperatorTake2 => true,
            }),
        }
    }
}

/// [`SigningRound::delivery_finished`] over the local graph and instance rows.
/// Reads the rows only: loading the graph itself re-verifies its signatures.
pub(crate) async fn protocol_delivery_finished(
    local_db: &LocalDB,
    content: &GOATMessageContent,
) -> Result<bool> {
    let Some(round) = SigningRound::of(content) else {
        return Ok(false);
    };
    let (instance_id, graph_id) = match content.business_ref() {
        BusinessRef::Graph { instance_id, graph_id } => (instance_id, Some(graph_id)),
        BusinessRef::Instance { instance_id } => (instance_id, None),
        BusinessRef::Unscoped => return Ok(false),
    };
    let mut storage = local_db.acquire().await?;
    let instance = storage
        .find_instance(&instance_id)
        .await?
        .and_then(|instance| InstanceBridgeInStatus::from_str(&instance.status).ok());
    let graph = match graph_id {
        Some(graph_id) => storage
            .find_graph(&graph_id)
            .await?
            .filter(|graph| graph.instance_id == instance_id)
            .and_then(|graph| GraphStatus::from_str(&graph.status).ok()),
        None => None,
    };
    Ok(round.delivery_finished(graph, instance.as_ref()))
}

/// Wait before the next re-publish of a signing-round row that has gone out of
/// the outbox `publish_count` times.
fn protocol_retry_interval_secs(publish_count: i64, max_secs: i64) -> i64 {
    let doublings = publish_count.clamp(0, 20) as u32;
    PROTOCOL_RETRY_BASE_SECS
        .saturating_mul(1_i64 << doublings)
        .min(max_secs.max(PROTOCOL_RETRY_BASE_SECS))
}

fn protocol_outbox_id(content: &GOATMessageContent) -> String {
    format!(
        "{PROTOCOL_OUTBOX_PREFIX}{}:{}",
        content.event_type(),
        content.business_ref().key_part()
    )
}

/// Store a signing-round message for re-publication. Returns whether this call
/// created the row: an existing one, live or closed, is left as it is.
async fn store_protocol_message(local_db: &LocalDB, message: &GOATMessage) -> Result<bool> {
    let bytes = message.serialize_message().await?;
    let now = current_time_secs();
    local_db
        .acquire()
        .await?
        .enqueue_p2p_outbox_retry_message(
            &protocol_outbox_id(&message.content),
            message.content.event_type(),
            &bytes,
            now + MESSAGE_EXPIRE_TIME,
            PROTOCOL_RETRY_BASE_SECS,
            None,
            // The caller publishes right after this; a row due at once would
            // have the outbox send a second copy seconds later.
            now + PROTOCOL_RETRY_BASE_SECS,
        )
        .await
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StoredValue {
    Fresh,
    Found,
}

/// Persist signing-round bytes; recovery leaves live outbox rows to the worker.
pub async fn send_protocol_message(
    publisher: &mut dyn MessagePublisher,
    local_db: &LocalDB,
    message: GOATMessage,
    origin: StoredValue,
) -> Result<()> {
    let outbox_id =
        SigningRound::of(&message.content).map(|_| protocol_outbox_id(&message.content));
    if let Some(id) = &outbox_id {
        let inserted = store_protocol_message(local_db, &message).await?;
        if origin == StoredValue::Found && !inserted {
            let state = local_db.acquire().await?.p2p_outbox_entry_state(id).await?;
            let live = state.is_some_and(|(state, _)| state == "Pending" || state == "Processing");
            if live || protocol_delivery_finished(local_db, &message.content).await? {
                return Ok(());
            }
        }
    }
    let result = send_to_peer(publisher, message).await;
    if let (Err(_), Some(outbox_id)) = (&result, outbox_id) {
        // Nothing went out, so there is no copy for the outbox to duplicate:
        // let it publish on its next pass instead of a full interval from now.
        if let Ok(mut storage) = local_db.acquire().await {
            let _ = storage.expedite_p2p_outbox_message(&outbox_id).await;
        }
    }
    result.map(|_| ())
}

pub async fn send_to_peer(
    swarm: &mut dyn MessagePublisher,
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
    // Receivers drop what exceeds their envelope limit without telling anyone,
    // so an outgrown message has to be loud on the sending side.
    let limits = crate::p2p_admission::inbound_limits();
    let receiver_limit = if GOATMessage::is_binary_envelope(&serialized) {
        limits.max_binary_bytes
    } else {
        limits.max_json_bytes
    };
    if serialized.len() > receiver_limit {
        if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
            metrics_state.record_p2p_oversized_message();
        }
        tracing::error!(
            event = "p2p_message_publish",
            outcome = "oversized",
            target_actor,
            message_type,
            content_size = serialized.len(),
            receiver_limit,
            "outbound protocol message exceeds the inbound size limit peers enforce"
        );
    }
    match swarm.publish_message(gossipsub_topic, serialized).await {
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

/// Defer the message currently being dispatched, or enqueue a new local task.
pub async fn defer_or_enqueue_message(
    local_db: &LocalDB,
    message: &GOATMessage,
    delay_secs: usize,
    reason: MessageDeferReason,
    reason_detail: &str,
) -> Result<()> {
    if defer_current_inbox(message, delay_secs, reason_detail) {
        return Ok(());
    }

    let actor = message.actor.clone();
    let content: GOATMessageContent = message.content().clone();
    let key = LocalMessageKey::from_content(actor.clone(), &content)?;
    let business_id = key.business_id();
    let message_type = message.content.event_type();
    let target_message_id = key.message_id();
    let active_claim = ACTIVE_LOCAL_MESSAGE_CLAIM
        .try_with(|claim| (claim.message_id.clone(), claim.message_version))
        .ok();
    let mut storage_processor = local_db.start_immediate_transaction().await?;

    let queued_message_id = if let Some((message_id, message_version)) =
        active_claim.filter(|(message_id, _)| message_id == &target_message_id)
    {
        let deferred = storage_processor
            .self_defer_local_message(
                &message_id,
                message_version,
                current_time_secs() + delay_secs as i64,
                reason_detail,
            )
            .await?;
        if !deferred {
            return Err(retryable_dispatch_error(
                RetryableDispatchReason::ResourceLocked,
                Some(delay_secs.max(1) as i64),
                format!(
                    "local message {business_id}:{message_type} is no longer owned by this claim"
                ),
            ));
        }
        message_id
    } else {
        let upserted = upsert_message(
            &mut storage_processor,
            true,
            SELF_SENDER.to_string(),
            actor,
            content,
            0,
            delay_secs as i64,
        )
        .await?;
        if !upserted {
            let current = storage_processor.find_messages_by_id(&target_message_id).await?;
            if current
                .as_ref()
                .is_some_and(|message| message.state == MessageState::Processing.to_string())
            {
                return Err(retryable_dispatch_error(
                    RetryableDispatchReason::ResourceLocked,
                    Some(delay_secs.max(1) as i64),
                    format!(
                        "local message {business_id}:{message_type} is owned by another active claim"
                    ),
                ));
            }
        }
        target_message_id
    };
    let persist_result = storage_processor
        .upsert_message_debug_reason(&queued_message_id, reason.code(), reason_detail)
        .await;
    if let Err(error) = persist_result {
        tracing::warn!(
            event = "local_message_queue",
            outcome = "debug_reason_store_failed",
            error = %error,
            "failed to persist local message defer reason"
        );
    }
    storage_processor.commit().await?;
    if delay_secs > 0
        && let Some(metrics_state) = crate::metrics_service::node_metrics_state()
    {
        metrics_state.record_message_retry();
    }
    Ok(())
}

fn defer_current_inbox(message: &GOATMessage, delay_secs: usize, reason_detail: &str) -> bool {
    ACTIVE_INBOX_DISPATCH
        .try_with(|active| {
            if DispatchFingerprint::of(message.content()) != active.fingerprint {
                return false;
            }
            *active.retry.borrow_mut() = Some(retryable_dispatch_error(
                RetryableDispatchReason::DependencyPending,
                Some(delay_secs.max(1) as i64),
                reason_detail.to_owned(),
            ));
            true
        })
        .unwrap_or(false)
}

/// Helper: try to get graph. If missing, send SyncGraphRequest and defer current handling.
pub(crate) async fn get_graph_or_defer(
    swarm: &mut dyn MessagePublisher,
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
            if let Err(error) = defer_or_enqueue_message(
                local_db,
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
    swarm: &mut dyn MessagePublisher,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    validate_graph_id_on_goat(goat_client, instance_id, graph_id).await?;
    // Record the graph request before publishing it.
    if !crate::p2p_admission::requested_graphs().insert(&graph_id.to_string(), Instant::now()) {
        bail!(
            "too many graph sync requests outstanding; {instance_id}:{graph_id} is retried later"
        );
    }
    let message_content =
        GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id });
    let message = GOATMessage::new(Actor::All, message_content);
    send_to_peer(swarm, message).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnavailablePublisher;
    impl MessagePublisher for UnavailablePublisher {
        fn publish_message(
            &mut self,
            _: gossipsub::IdentTopic,
            _: Vec<u8>,
        ) -> futures::future::BoxFuture<'_, Result<MessageId>> {
            Box::pin(async { bail!("network unavailable") })
        }
    }

    #[tokio::test]
    async fn signing_round_survives_publish_failure_without_reopening_completed_delivery() {
        let db = store::create_local_db("sqlite::memory:").await;
        let key = Keypair::from_secret_key(
            SECP256K1,
            &secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
        );
        let message = GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
                instance_id: Uuid::new_v4(),
                graph_id: Uuid::new_v4(),
                committee_pubkey: key.public_key().into(),
                consensus_hash: [3; 32],
                signature: SECP256K1.sign_schnorr(&SecpMessage::from_digest([3; 32]), &key),
            }),
        );
        assert!(
            send_protocol_message(
                &mut UnavailablePublisher,
                &db,
                message.clone(),
                StoredValue::Fresh
            )
            .await
            .is_err()
        );
        let now = current_time_secs();
        let mut storage = db.acquire().await.unwrap();
        let rows = storage.claim_p2p_outbox_messages(now, now + 300, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content, message.serialize_message().await.unwrap());
        assert_eq!(rows[0].retry_interval_secs, 30);
        storage.complete_p2p_outbox_message(&rows[0].message_id).await.unwrap();
        drop(storage);
        let _ = send_protocol_message(&mut UnavailablePublisher, &db, message, StoredValue::Fresh)
            .await;
        assert!(
            db.acquire()
                .await
                .unwrap()
                .claim_p2p_outbox_messages(now + 301, now + 601, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[derive(Default)]
    struct RecordingPublisher(Vec<Vec<u8>>);
    impl MessagePublisher for RecordingPublisher {
        fn publish_message(
            &mut self,
            _: gossipsub::IdentTopic,
            data: Vec<u8>,
        ) -> futures::future::BoxFuture<'_, Result<MessageId>> {
            self.0.push(data);
            Box::pin(async { Ok(MessageId::from("published")) })
        }
    }

    async fn queued_outbox_fixture() -> LocalDB {
        let db = store::create_local_db("sqlite::memory:").await;
        let content =
            committee_vote(Uuid::new_v4(), Uuid::new_v4()).serialize_message().await.unwrap();
        for index in 0..3 {
            db.acquire()
                .await
                .unwrap()
                .enqueue_p2p_outbox_message(
                    &format!("budget-{index}"),
                    "AggNonceConsensus",
                    &content,
                )
                .await
                .unwrap();
        }
        db
    }

    async fn assert_unclaimed_outbox_rows(db: &LocalDB, expected: usize) {
        let now = current_time_secs();
        let rows = db
            .acquire()
            .await
            .unwrap()
            .claim_p2p_outbox_messages(now, now + 300, 16)
            .await
            .unwrap();
        assert_eq!(rows.len(), expected, "untouched rows must remain immediately claimable");
        assert!(rows.iter().all(|row| row.attempt_count == 1));
    }

    #[tokio::test]
    async fn outbox_expired_budget_claims_nothing() {
        let db = queued_outbox_fixture().await;
        let mut publisher = RecordingPublisher::default();
        drain_p2p_outbox(&mut publisher, &db, Instant::now()).await.unwrap();
        assert!(publisher.0.is_empty());
        assert_unclaimed_outbox_rows(&db, 3).await;
    }

    #[tokio::test]
    async fn outbox_publish_failure_does_not_claim_the_rest() {
        let db = queued_outbox_fixture().await;
        drain_p2p_outbox(&mut UnavailablePublisher, &db, Instant::now() + Duration::from_secs(60))
            .await
            .unwrap();
        assert_unclaimed_outbox_rows(&db, 2).await;
    }

    #[tokio::test]
    async fn outbox_checks_budget_between_publishes() {
        struct DeadlinePublisher(Instant);
        impl MessagePublisher for DeadlinePublisher {
            fn publish_message(
                &mut self,
                _: gossipsub::IdentTopic,
                _: Vec<u8>,
            ) -> futures::future::BoxFuture<'_, Result<MessageId>> {
                Box::pin(async move {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(self.0)).await;
                    Ok(MessageId::from("published"))
                })
            }
        }
        let db = queued_outbox_fixture().await;
        let deadline = Instant::now() + Duration::from_secs(2);
        drain_p2p_outbox(&mut DeadlinePublisher(deadline), &db, deadline).await.unwrap();
        assert_unclaimed_outbox_rows(&db, 2).await;
    }

    fn committee_vote(instance_id: Uuid, graph_id: Uuid) -> GOATMessage {
        let key = Keypair::from_secret_key(
            SECP256K1,
            &secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
        );
        GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
                instance_id,
                graph_id,
                committee_pubkey: key.public_key().into(),
                consensus_hash: [3; 32],
                signature: SECP256K1.sign_schnorr(&SecpMessage::from_digest([3; 32]), &key),
            }),
        )
    }

    async fn store_graph_row(db: &LocalDB, instance_id: Uuid, graph_id: Uuid, status: GraphStatus) {
        let mut storage = db.acquire().await.unwrap();
        storage
            .upsert_graph_definition(&store::Graph {
                graph_id,
                instance_id,
                status: GraphStatus::OperatorPresigned.to_string(),
                definition_hash: "definition".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        if status != GraphStatus::OperatorPresigned {
            storage
                .transition_graph_status(
                    instance_id,
                    graph_id,
                    status,
                    store::GraphStatusSource::Definition,
                    None,
                )
                .await
                .unwrap();
        }
    }

    #[test]
    fn signing_round_backoff_doubles_up_to_its_ceiling() {
        let waits: Vec<i64> = (0..8).map(|n| protocol_retry_interval_secs(n, 600)).collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 600, 600, 600]);
        // A short-timelock network asks for a ceiling below the base step.
        assert_eq!(protocol_retry_interval_secs(5, 10), 30);
        assert_eq!(protocol_retry_interval_secs(i64::MAX, 600), 600);
        assert_eq!(protocol_retry_interval_secs(-1, 600), 30);
        // The whole graph backs off further than the small round messages.
        assert_eq!(SigningRound::GraphSigning.retry_ceiling_secs(600), 600);
        assert_eq!(SigningRound::GraphFinalize.retry_ceiling_secs(600), 3_600);
        assert_eq!(protocol_retry_interval_secs(9, 3_600), 3_600);
    }

    #[test]
    fn a_graph_round_is_closed_by_its_graph_and_not_by_the_instance() {
        use GraphStatus as G;
        use InstanceBridgeInStatus as I;
        // The instance moves on with the first graph; a second operator's graph
        // is still mid-round then, and must keep its retries.
        for instance in [I::Presigned, I::RelayerL1Broadcasted, I::RelayerL2Minted] {
            for round in [SigningRound::GraphSigning, SigningRound::GraphFinalize] {
                assert!(!round.delivery_finished(Some(G::OperatorPresigned), Some(&instance)));
                assert!(!round.delivery_finished(None, Some(&instance)));
            }
        }
        // This node holding the finalized graph closes its own round values, but
        // says nothing about whether a relayer has the GraphFinalize.
        assert!(SigningRound::GraphSigning.delivery_finished(Some(G::CommitteePresigned), None));
        assert!(!SigningRound::GraphFinalize.delivery_finished(Some(G::CommitteePresigned), None));
        for posted in [G::OperatorDataPushed, G::PreKickoff, G::OperatorTake1, G::Obsoleted] {
            assert!(SigningRound::GraphSigning.delivery_finished(Some(posted), None));
            assert!(SigningRound::GraphFinalize.delivery_finished(Some(posted), None));
        }
        // PeginConfirm is the instance's round.
        assert!(!SigningRound::PeginConfirm.delivery_finished(None, Some(&I::Presigned)));
        assert!(!SigningRound::PeginConfirm.delivery_finished(None, None));
        assert!(SigningRound::PeginConfirm.delivery_finished(None, Some(&I::RelayerL1Broadcasted)));
        // A failed instance closes everything.
        for failed in [I::PresignedFailed, I::Timeout, I::UserCanceled, I::UserDiscarded] {
            assert!(
                SigningRound::GraphSigning
                    .delivery_finished(Some(G::OperatorPresigned), Some(&failed))
            );
            assert!(SigningRound::GraphFinalize.delivery_finished(None, Some(&failed)));
            assert!(SigningRound::PeginConfirm.delivery_finished(None, Some(&failed)));
        }
    }

    #[tokio::test]
    async fn a_published_signing_message_is_not_sent_again_until_its_first_interval() {
        let db = store::create_local_db("sqlite::memory:").await;
        let message = committee_vote(Uuid::new_v4(), Uuid::new_v4());
        let mut publisher = RecordingPublisher::default();
        send_protocol_message(&mut publisher, &db, message.clone(), StoredValue::Fresh)
            .await
            .unwrap();
        assert_eq!(publisher.0.len(), 1);

        // The handler has just published: the outbox must not follow with a copy.
        handle_p2p_outbox_messages(&mut publisher, &db).await.unwrap();
        assert_eq!(publisher.0.len(), 1);

        // A later visit that finds the value stored leaves the live row alone...
        send_protocol_message(&mut publisher, &db, message.clone(), StoredValue::Found)
            .await
            .unwrap();
        assert_eq!(publisher.0.len(), 1);

        // ...and the outbox re-publishes it on schedule, backing off.
        let now = current_time_secs();
        let mut storage = db.acquire().await.unwrap();
        let due = storage
            .claim_p2p_outbox_messages(now + PROTOCOL_RETRY_BASE_SECS, now + 600, 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].publish_count, 0);
        storage.schedule_p2p_outbox_retry(&due[0].message_id, now + 1_000).await.unwrap();
        let due = storage.claim_p2p_outbox_messages(now + 1_000, now + 2_000, 10).await.unwrap();
        assert_eq!(due[0].publish_count, 1, "only publishes that went through are counted");
    }

    #[tokio::test]
    async fn a_value_stored_without_an_outbox_row_is_published_by_the_retry() {
        // The first run stored its value and was cut off before the outbox row:
        // nothing was ever published, and the retry is the only one who can.
        let db = store::create_local_db("sqlite::memory:").await;
        let message = committee_vote(Uuid::new_v4(), Uuid::new_v4());
        let mut publisher = RecordingPublisher::default();
        send_protocol_message(&mut publisher, &db, message.clone(), StoredValue::Found)
            .await
            .unwrap();
        assert_eq!(publisher.0.len(), 1);
        let id = protocol_outbox_id(&message.content);
        let state = db.acquire().await.unwrap().p2p_outbox_entry_state(&id).await.unwrap();
        assert_eq!(state.unwrap().0, "Pending");

        // A failed publish leaves the row due at once rather than an interval away.
        let other = committee_vote(Uuid::new_v4(), Uuid::new_v4());
        assert!(
            send_protocol_message(&mut UnavailablePublisher, &db, other, StoredValue::Found)
                .await
                .is_err()
        );
        let now = current_time_secs();
        let due = db
            .acquire()
            .await
            .unwrap()
            .claim_p2p_outbox_messages(now, now + 300, 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
    }

    #[tokio::test]
    async fn a_closed_outbox_row_is_published_past_only_while_the_round_is_open() {
        let db = store::create_local_db("sqlite::memory:").await;
        let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
        store_graph_row(&db, instance_id, graph_id, GraphStatus::OperatorPresigned).await;
        let message = committee_vote(instance_id, graph_id);
        assert!(
            send_protocol_message(
                &mut UnavailablePublisher,
                &db,
                message.clone(),
                StoredValue::Fresh
            )
            .await
            .is_err()
        );
        let now = current_time_secs();
        let mut storage = db.acquire().await.unwrap();
        let rows = storage.claim_p2p_outbox_messages(now, now + 300, 10).await.unwrap();
        storage.fail_p2p_outbox_message(&rows[0].message_id, "corrupt").await.unwrap();
        drop(storage);

        // The row is gone for good, the round is not over: silence would strand it.
        let mut publisher = RecordingPublisher::default();
        send_protocol_message(&mut publisher, &db, message.clone(), StoredValue::Found)
            .await
            .unwrap();
        assert_eq!(publisher.0.len(), 1);

        // Once the graph is finalized here, nobody needs the vote any more.
        store_graph_row(&db, instance_id, graph_id, GraphStatus::CommitteePresigned).await;
        send_protocol_message(&mut publisher, &db, message, StoredValue::Found).await.unwrap();
        assert_eq!(publisher.0.len(), 1);
    }

    #[tokio::test]
    async fn the_outbox_stops_a_round_by_its_graph_and_survives_a_bad_row() {
        let db = store::create_local_db("sqlite::memory:").await;
        let (instance_id, open_graph, finalized_graph) =
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        store_graph_row(&db, instance_id, open_graph, GraphStatus::OperatorPresigned).await;
        store_graph_row(&db, instance_id, finalized_graph, GraphStatus::CommitteePresigned).await;
        // A graph row of another instance must not close this one's round.
        let foreign_graph = Uuid::new_v4();
        store_graph_row(&db, Uuid::new_v4(), foreign_graph, GraphStatus::CommitteePresigned).await;
        for graph_id in [open_graph, finalized_graph, foreign_graph] {
            let _ = send_protocol_message(
                &mut UnavailablePublisher,
                &db,
                committee_vote(instance_id, graph_id),
                StoredValue::Fresh,
            )
            .await;
        }
        // A corrupt row sits first in the batch; the rows behind it are still served.
        let now = current_time_secs();
        db.acquire()
            .await
            .unwrap()
            .enqueue_p2p_outbox_retry_message(
                "protocol:AggNonceConsensus:graph:corrupt",
                "AggNonceConsensus",
                b"not a message",
                now + 600,
                30,
                None,
                0,
            )
            .await
            .unwrap();

        let mut publisher = RecordingPublisher::default();
        handle_p2p_outbox_messages(&mut publisher, &db).await.unwrap();
        assert_eq!(publisher.0.len(), 2, "the open round and the foreign-row round publish");

        let mut storage = db.acquire().await.unwrap();
        let state =
            |graph_id: Uuid| protocol_outbox_id(&committee_vote(instance_id, graph_id).content);
        let open = storage.p2p_outbox_entry_state(&state(open_graph)).await.unwrap().unwrap();
        assert_eq!(open.0, "Pending");
        let closed =
            storage.p2p_outbox_entry_state(&state(finalized_graph)).await.unwrap().unwrap();
        assert_eq!(closed, ("Processed".to_owned(), 0));
        let foreign = storage.p2p_outbox_entry_state(&state(foreign_graph)).await.unwrap().unwrap();
        assert_eq!(foreign.0, "Pending");
    }

    #[test]
    fn inbox_retention_sweeps_keep_the_tick_cadence_under_backlog() {
        let start = Instant::now();
        // Whatever an earlier test left behind, two calls inside one interval
        // cannot both be due.
        let first = inbox_housekeeping_due(start);
        let second = inbox_housekeeping_due(start + Duration::from_secs(1));
        assert!(!(first && second));
        assert!(!second);
        let interval = Duration::from_secs(crate::env::REGULAR_TASK_INTERVAL_SECOND);
        assert!(inbox_housekeeping_due(start + interval + Duration::from_secs(2)));
    }

    #[tokio::test]
    async fn inbox_dependency_retry_never_collapses_into_local_queue() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let message = GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest {
                instance_id: Uuid::new_v4(),
                graph_id: Uuid::new_v4(),
            }),
        );
        let mut compensated = false;
        let result = track_inbox_retry(DispatchFingerprint::of(message.content()), async {
            defer_or_enqueue_message(
                &local_db,
                &message,
                30,
                MessageDeferReason::PreviousGraphPending,
                "wait for graph",
            )
            .await?;
            // Some handlers rebroadcast a prerequisite only after asking
            // for deferral. An early Err would skip that recovery action.
            compensated = true;
            Ok(())
        })
        .await;
        assert!(compensated);
        assert!(result.unwrap_err().downcast_ref::<RetryableDispatchError>().is_some());
        let key = LocalMessageKey::from_content(Actor::Committee, message.content()).unwrap();
        assert!(
            local_db
                .acquire()
                .await
                .unwrap()
                .find_messages_by_id(&key.message_id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Verify self-deferral survives later handler errors; other events still use the local queue.
    #[tokio::test]
    async fn deferral_survives_a_later_error_and_other_events_stay_local() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
        let dispatched = GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id }),
        );
        // The handler builds its own copy, under its own role: same message.
        let own_copy = GOATMessage::new(Actor::Operator, dispatched.content().clone());
        let other_event = GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
        );

        let result = track_inbox_retry(DispatchFingerprint::of(dispatched.content()), async {
            defer_or_enqueue_message(
                &local_db,
                &other_event,
                30,
                MessageDeferReason::ChainStatePending,
                "a different event",
            )
            .await?;
            defer_or_enqueue_message(
                &local_db,
                &own_copy,
                45,
                MessageDeferReason::PreviousGraphPending,
                "wait for graph",
            )
            .await?;
            bail!("compensation failed after the deferral was recorded")
        })
        .await;
        let retry = result.unwrap_err();
        let retry = retry
            .downcast_ref::<RetryableDispatchError>()
            .expect("the recorded deferral wins over the later, non-retryable error");
        assert_eq!(retry.retry_after_secs, Some(45));

        let mut storage = local_db.acquire().await.unwrap();
        let own_key = LocalMessageKey::from_content(Actor::Operator, own_copy.content()).unwrap();
        assert!(storage.find_messages_by_id(&own_key.message_id()).await.unwrap().is_none());
        let other_key =
            LocalMessageKey::from_content(Actor::Committee, other_event.content()).unwrap();
        assert!(
            storage.find_messages_by_id(&other_key.message_id()).await.unwrap().is_some(),
            "an event of another kind is not the dispatched message"
        );
    }

    /// Verify handler timeout, completion and shutdown outcomes.
    #[tokio::test]
    async fn handler_budget_cuts_off_an_overrunning_dispatch() {
        let shutdown = CancellationToken::new();
        let budget = Duration::from_millis(100);

        let overrunning = async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<(), anyhow::Error>(())
        };
        let outcome =
            supervise_dispatch(tokio::time::timeout(budget, overrunning), &shutdown).await;
        assert!(matches!(outcome, DispatchExecution::Completed(Err(_))), "cut off at the budget");

        let prompt = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok::<(), anyhow::Error>(())
        };
        let outcome = supervise_dispatch(tokio::time::timeout(budget, prompt), &shutdown).await;
        assert!(matches!(outcome, DispatchExecution::Completed(Ok(Ok(())))));

        shutdown.cancel();
        let outcome = supervise_dispatch(
            tokio::time::timeout(budget, std::future::pending::<Result<()>>()),
            &shutdown,
        )
        .await;
        assert!(matches!(outcome, DispatchExecution::Shutdown));
    }

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

    #[tokio::test]
    async fn genuine_transient_errors_are_still_retryable() {
        let error = anyhow!("database is locked");
        assert!(
            p2p_retryable_dispatch_error(&error).is_some(),
            "a real SQLite-busy error must remain retryable"
        );
    }

    #[test]
    fn contract_revert_is_not_a_retryable_transport_failure() {
        let response =
            serde_json::from_str(r#"{"code":3,"message":"execution reverted"}"#).unwrap();
        let error = anyhow::Error::new(alloy::contract::Error::TransportError(
            alloy::transports::TransportError::ErrorResp(response),
        ))
        .context("validate SyncGraph instance parameters");
        assert!(!is_retryable_external_rpc_error(&error));
        assert!(
            classify_retryable_dispatch_error(error)
                .downcast_ref::<RetryableDispatchError>()
                .is_none()
        );
    }

    #[tokio::test]
    async fn dispatch_supervisor_distinguishes_shutdown_and_panic() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        assert!(matches!(
            supervise_dispatch(std::future::pending::<()>(), &shutdown).await,
            DispatchExecution::Shutdown
        ));

        let running = CancellationToken::new();
        let result = supervise_dispatch(
            async {
                panic!("poison message");
            },
            &running,
        )
        .await;
        assert!(matches!(
            result,
            DispatchExecution::Panicked(detail) if detail == "poison message"
        ));
    }

    #[tokio::test]
    async fn non_owner_requeue_reports_processing_conflict() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::new_v4();
        let message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::PostReady(PostReady { instance_id }),
        );
        defer_or_enqueue_message(
            &local_db,
            &message,
            0,
            MessageDeferReason::HandlerError,
            "initial",
        )
        .await
        .unwrap();

        let claimed = {
            let mut storage = local_db.acquire().await.unwrap();
            storage
                .claim_local_messages(
                    current_time_secs() + 1,
                    current_time_secs() + 300,
                    0,
                    1,
                    QUEUE_MAX_ABANDONS,
                )
                .await
                .unwrap()
        };
        assert_eq!(claimed.len(), 1);

        let error = defer_or_enqueue_message(
            &local_db,
            &message,
            30,
            MessageDeferReason::HandlerError,
            "retry",
        )
        .await
        .unwrap_err();
        let retryable = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<RetryableDispatchError>())
            .expect("Processing conflict must be retryable");
        assert_eq!(retryable.reason, RetryableDispatchReason::ResourceLocked);
        assert_eq!(retryable.retry_after_secs, Some(30));

        let mut storage = local_db.acquire().await.unwrap();
        let stored = storage.find_messages_by_id(&claimed[0].message_id).await.unwrap().unwrap();
        assert_eq!(stored.state, MessageState::Processing.to_string());
        assert_eq!(stored.message_version, claimed[0].message_version);
    }

    #[tokio::test]
    async fn owner_requeue_uses_content_derived_message_id() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::new_v4();
        let message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::PostReady(PostReady { instance_id }),
        );
        let message_id = LocalMessageKey::from_content(message.actor.clone(), &message.content)
            .unwrap()
            .message_id();
        {
            let mut storage = local_db.acquire().await.unwrap();
            assert!(
                upsert_message(
                    &mut storage,
                    false,
                    SELF_SENDER.to_owned(),
                    message.actor.clone(),
                    message.content.clone(),
                    0,
                    0,
                )
                .await
                .unwrap()
            );
        }
        let claimed = {
            let mut storage = local_db.acquire().await.unwrap();
            storage
                .claim_local_messages(
                    current_time_secs() + 1,
                    current_time_secs() + 300,
                    0,
                    1,
                    QUEUE_MAX_ABANDONS,
                )
                .await
                .unwrap()
                .pop()
                .unwrap()
        };
        assert_eq!(claimed.message_id, message_id);

        // Two earlier attempts died mid-dispatch; the row carries their abandons
        // into this claim, and the handler's own reschedule must not erase them.
        {
            let mut storage = local_db.acquire().await.unwrap();
            for _ in 0..2 {
                assert!(
                    storage
                        .abandon_local_message(
                            &message_id,
                            claimed.message_version,
                            current_time_secs(),
                            0,
                            "died mid-dispatch",
                        )
                        .await
                        .unwrap()
                );
            }
        }
        let claimed = {
            let mut storage = local_db.acquire().await.unwrap();
            storage
                .claim_local_messages(
                    current_time_secs() + 301,
                    current_time_secs() + 600,
                    0,
                    1,
                    QUEUE_MAX_ABANDONS,
                )
                .await
                .unwrap()
                .pop()
                .unwrap()
        };
        assert_eq!(claimed.abandon_count, 2);

        ACTIVE_LOCAL_MESSAGE_CLAIM
            .scope(
                LocalMessageClaim {
                    message_id: claimed.message_id.clone(),
                    message_version: claimed.message_version,
                },
                defer_or_enqueue_message(
                    &local_db,
                    &message,
                    30,
                    MessageDeferReason::HandlerError,
                    "retry subtyped message",
                ),
            )
            .await
            .unwrap();

        let mut storage = local_db.acquire().await.unwrap();
        let stored = storage.find_messages_by_id(&message_id).await.unwrap().unwrap();
        assert_eq!(stored.state, MessageState::Pending.to_string());
        assert_eq!(stored.abandon_count, 2, "a self-defer must keep the abandon count");

        // The dispatcher confirms the self-defer once the handler has returned.
        assert!(
            storage
                .confirm_local_message_self_defer(&message_id, claimed.message_version)
                .await
                .unwrap()
        );
        assert_eq!(
            storage.find_messages_by_id(&message_id).await.unwrap().unwrap().abandon_count,
            0
        );
    }

    #[tokio::test]
    async fn local_claim_is_not_deferred_by_another_actor_message() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::new_v4();
        let claimed_message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::PostReady(PostReady { instance_id }),
        );
        let other_actor_message =
            GOATMessage::new(Actor::Committee, claimed_message.content.clone());
        let claimed_id =
            LocalMessageKey::from_content(claimed_message.actor.clone(), claimed_message.content())
                .unwrap()
                .message_id();
        let other_id = LocalMessageKey::from_content(
            other_actor_message.actor.clone(),
            other_actor_message.content(),
        )
        .unwrap()
        .message_id();
        {
            let mut storage = local_db.acquire().await.unwrap();
            upsert_message(
                &mut storage,
                false,
                SELF_SENDER.to_owned(),
                claimed_message.actor.clone(),
                claimed_message.content.clone(),
                0,
                0,
            )
            .await
            .unwrap();
        }
        let claimed = local_db
            .acquire()
            .await
            .unwrap()
            .claim_local_messages(
                current_time_secs() + 1,
                current_time_secs() + 300,
                0,
                1,
                QUEUE_MAX_ABANDONS,
            )
            .await
            .unwrap()
            .pop()
            .unwrap();

        ACTIVE_LOCAL_MESSAGE_CLAIM
            .scope(
                LocalMessageClaim {
                    message_id: claimed.message_id.clone(),
                    message_version: claimed.message_version,
                },
                defer_or_enqueue_message(
                    &local_db,
                    &other_actor_message,
                    30,
                    MessageDeferReason::HandlerError,
                    "other actor",
                ),
            )
            .await
            .unwrap();

        let mut storage = local_db.acquire().await.unwrap();
        assert_eq!(
            storage.find_messages_by_id(&claimed_id).await.unwrap().unwrap().state,
            MessageState::Processing.to_string()
        );
        assert_eq!(
            storage.find_messages_by_id(&other_id).await.unwrap().unwrap().state,
            MessageState::Pending.to_string()
        );
    }
}
