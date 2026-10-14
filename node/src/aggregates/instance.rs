//! Instance lifecycle decisions from messages, chain snapshots and job results.
//!
//! Apply updates the instance row and records its jobs, outgoing messages and
//! cleanup actions in one transaction. The engine row tracks status and phase.
//! Signing closes at the cancel height. After the abandon buffer, an unconfirmed
//! Peg-In-Confirm absent from the mempool can cause Timeout.

use crate::action::{BusinessRef, GOATMessage, HasBusinessRef};
use crate::aggregates::graph::{
    EnvelopeProbe, InboundMessage, MembershipProbe, NextStep, PARKED_MESSAGE_TTL_SECS,
    PlannedMessage, content_event_id, operator_start_event,
};
use crate::engine_bridge::record_event_in;
use crate::env::{
    get_committee_instance_key_delete_timelock_blocks, get_network, get_peer_id,
    get_pegin_abandon_buffer_blocks, is_enable_committee_instance_key_delete, is_relayer,
};
use crate::metrics_service::node_metrics_state;
use crate::middleware::get_topic_name;
use crate::utils::{
    find_pegin_instance_process_data, gen_instance_parameters_local, min_required_operator,
    obsolete_instance_graphs_except,
};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use bitvm_lib::timelocks::default_connector_z_timelock_blocks;
use bitvm_lib::transactions::base::BaseTransaction;
use client::btc_chain::BTCClient;
use engine::{
    AggregateHandler, AggregateRef, ApplyContext, ApplyError, ApplyOutcome, EngineInboxEvent,
    EngineOutboxCloseTarget, EventSource, JOB_RESULT_KIND, JobPool, JobResultEvent,
    JobResultOutcome, JobSpec, NewEvent, OutboxMessage, WaitingFor,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::{InstanceUpdate, LocalDB};
use store::{Instance, InstanceBridgeInStatus, SerializableTxid};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const INSTANCE_KIND: &str = "instance";

pub const EVENT_BTC_SNAPSHOT: &str = "btc_snapshot";
pub const EVENT_ANSWER_WINDOW: &str = "answer_window";
pub const EVENT_GRAPH_ENDORSED: &str = "graph_endorsed";
pub const EVENT_L2_MINTED: &str = "l2_minted";
/// A Goat `BridgeInRequest` this node indexed while its response window is open.
pub const EVENT_PEGIN_REQUEST: &str = "pegin_request";

pub const JOB_POST_PEGIN_DATA: &str = "post_pegin_data";
pub const JOB_DELETE_INSTANCE_KEY: &str = "delete_instance_key";
/// The committee's `answerPeginRequest` (Answer phase).
pub const JOB_ANSWER_PEGIN_REQUEST: &str = "answer_pegin_request";
/// Peg-In-Prepare confirmed: store the parameters, operators open a setup.
pub const JOB_CONFIRM_INSTANCE: &str = "confirm_instance";
/// The committee's PeginConfirm round start on entering Presigned.
pub const JOB_START_PEGIN_CONFIRM: &str = "start_pegin_confirm";
pub const JOB_INGEST_PEGIN_CONFIRM_NONCE: &str = "ingest_pegin_confirm_nonce";
pub const JOB_PEGIN_CONFIRM_VOTE: &str = "pegin_confirm_vote";
pub const JOB_INGEST_PEGIN_CONFIRM_VOTE: &str = "ingest_pegin_confirm_vote";
pub const JOB_PEGIN_CONFIRM_SIGN: &str = "pegin_confirm_sign";
pub const JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG: &str = "ingest_pegin_confirm_partial_sig";
/// The relayer's aggregation and broadcast of the Peg-In-Confirm.
pub const JOB_BROADCAST_PEGIN_CONFIRM: &str = "broadcast_pegin_confirm";

/// The jobs that return an [`InstancePlan`].
pub const INSTANCE_JOBS: &[&str] = &[
    JOB_ANSWER_PEGIN_REQUEST,
    JOB_CONFIRM_INSTANCE,
    JOB_START_PEGIN_CONFIRM,
    JOB_INGEST_PEGIN_CONFIRM_NONCE,
    JOB_PEGIN_CONFIRM_VOTE,
    JOB_INGEST_PEGIN_CONFIRM_VOTE,
    JOB_PEGIN_CONFIRM_SIGN,
    JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG,
    JOB_BROADCAST_PEGIN_CONFIRM,
];

pub const PHASE_ANSWER: &str = "Answer";
pub const PHASE_AWAIT_PREPARE: &str = "AwaitPrepare";
pub const PHASE_PRESIGN: &str = "Presign";
pub const PHASE_CONFIRM: &str = "Confirm";
pub const PHASE_POST: &str = "Post";
pub const PHASE_DONE: &str = "Done";
pub const PHASE_FAILED: &str = "Failed";
/// Phase of the key deletion jobs; they belong to no protocol phase.
pub const PHASE_KEY: &str = "Key";

pub fn instance_ref(instance_id: Uuid) -> AggregateRef {
    AggregateRef::new(INSTANCE_KIND, instance_id.to_string())
}

/// Phase of the instance state machine for a status.
pub fn phase_of(status: InstanceBridgeInStatus) -> &'static str {
    use InstanceBridgeInStatus::*;
    match status {
        UserInited => PHASE_ANSWER,
        CommitteesAnswered => PHASE_AWAIT_PREPARE,
        UserBroadcastPeginPrepare => PHASE_PRESIGN,
        Presigned => PHASE_CONFIRM,
        RelayerL1Broadcasted => PHASE_POST,
        RelayerL2Minted => PHASE_DONE,
        Timeout | UserCanceled | NoEnoughCommitteesAnswered | UserDiscarded => PHASE_FAILED,
    }
}

/// The job phase an action runs in; jobs are cancelled by phase.
pub fn job_phase(action: &str) -> &'static str {
    match action {
        JOB_ANSWER_PEGIN_REQUEST => PHASE_ANSWER,
        JOB_CONFIRM_INSTANCE => PHASE_PRESIGN,
        JOB_POST_PEGIN_DATA => PHASE_POST,
        JOB_DELETE_INSTANCE_KEY => PHASE_KEY,
        _ => PHASE_CONFIRM,
    }
}

/// The PeginConfirm round is over: nothing of the Confirm phase is sent or started any more.
pub fn confirm_round_over(status: InstanceBridgeInStatus) -> bool {
    status.is_failed()
        || matches!(
            status,
            InstanceBridgeInStatus::RelayerL1Broadcasted | InstanceBridgeInStatus::RelayerL2Minted
        )
}

// ------------------------------------------------------------------- routing

/// Message kinds the aggregate takes from the network, and which job ingests
/// them. Only committee nodes take part in the PeginConfirm round.
pub fn route_action(kind: &str, actor: &Actor) -> Option<&'static str> {
    if *actor != Actor::Committee {
        return None;
    }
    Some(match kind {
        "PeginConfirmNonce" => JOB_INGEST_PEGIN_CONFIRM_NONCE,
        "PeginConfirmNonceConsensus" => JOB_INGEST_PEGIN_CONFIRM_VOTE,
        "PeginConfirmPartialSig" => JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG,
        _ => return None,
    })
}

/// Whether this role takes `kind` through the engine at all.
pub fn engine_handles(kind: &str, actor: &Actor) -> bool {
    route_action(kind, actor).is_some()
}

/// The inbox event for an admitted PeginConfirm round message, or `None`
/// when this role does not take the kind through the engine.
pub fn inbound_event(
    actor: &Actor,
    author: &str,
    decoded: &GOATMessage,
    raw: &[u8],
) -> anyhow::Result<Option<NewEvent>> {
    let kind = decoded.content.event_type();
    if !engine_handles(kind, actor) {
        return Ok(None);
    }
    let BusinessRef::Instance { instance_id } = decoded.content.business_ref() else {
        return Ok(None);
    };
    let inbound = InboundMessage {
        author: author.to_string(),
        instance_id,
        graph_nonce: None,
        operator_pubkey: None,
        message: raw.to_vec(),
    };
    Ok(Some(
        NewEvent::new(
            content_event_id(author, kind, &instance_id.to_string(), raw),
            instance_ref(instance_id),
            kind,
            EventSource::Network,
            inbound.encode()?,
        )
        .with_author(author),
    ))
}

// ------------------------------------------------------------------ deadlines

/// Block-height deadlines of a peg-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeginDeadlines {
    /// `T0`: `connector_z` of the network.
    pub t0_blocks: i64,
    /// `B`: the abandon buffer after `T0`.
    pub buffer_blocks: i64,
    /// Success-side key deletion depth after Peg-In-Confirm confirmation.
    pub key_delete_blocks: i64,
}

impl PeginDeadlines {
    pub fn from_env() -> Self {
        Self {
            t0_blocks: i64::from(default_connector_z_timelock_blocks(get_network())),
            buffer_blocks: get_pegin_abandon_buffer_blocks(),
            key_delete_blocks: get_committee_instance_key_delete_timelock_blocks(),
        }
    }

    /// `H_p + T0`: from this height the user may broadcast Peg-In-Cancel and
    /// no node produces a new protocol signature for the instance. `None`
    /// while the Prepare height is unknown.
    pub fn cancel_from_height(&self, prepare_height: i64) -> Option<i64> {
        (prepare_height > 0).then(|| prepare_height + self.t0_blocks)
    }

    /// `H_p + T0 + B`: from this height the peg-in is abandoned unless the
    /// Peg-In-Confirm is confirmed or visible in the mempool.
    pub fn abandon_height(&self, prepare_height: i64) -> Option<i64> {
        self.cancel_from_height(prepare_height).map(|height| height + self.buffer_blocks)
    }

    /// The T0 gate: signing stays open while the Prepare height is unknown or
    /// `h < H_p + T0`.
    pub fn signing_open(&self, prepare_height: i64, height: i64) -> bool {
        self.cancel_from_height(prepare_height).is_none_or(|t0| height < t0)
    }
}

// ---------------------------------------------------------------------- facts

/// What this node's Bitcoin data source says about one transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxFact {
    pub confirmed: bool,
    pub block_height: Option<i64>,
    /// Returned by the data source but unconfirmed. Per-node: another node
    /// may not see it.
    pub in_mempool: bool,
}

impl TxFact {
    pub const UNKNOWN: TxFact = TxFact { confirmed: false, block_height: None, in_mempool: false };

    pub fn confirmed_at(height: i64) -> Self {
        Self { confirmed: true, block_height: Some(height), in_mempool: false }
    }

    pub fn mempool() -> Self {
        Self { confirmed: false, block_height: None, in_mempool: true }
    }

    /// Neither confirmed nor in this node's mempool.
    pub fn invisible(&self) -> bool {
        !self.confirmed && !self.in_mempool
    }
}

/// Bitcoin facts about an instance at tip height `height`. A `None` fact was
/// not queried for the status the scan saw; the apply never decides on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcSnapshot {
    pub height: i64,
    pub status_at_scan: String,
    pub prepare: Option<TxFact>,
    pub confirm: Option<TxFact>,
    pub cancel: Option<TxFact>,
    /// Whether every input of Peg-In-Prepare is unspent or spent by Prepare itself.
    pub inputs_available: Option<bool>,
}

impl BtcSnapshot {
    /// The event id carries the height and the status the scan saw, so a scan
    /// after a status change at the same height is a new event.
    pub fn event(&self, instance_id: Uuid) -> anyhow::Result<NewEvent> {
        Ok(NewEvent::new(
            format!("instance:{instance_id}:btc:{}:{}", self.height, self.status_at_scan),
            instance_ref(instance_id),
            EVENT_BTC_SNAPSHOT,
            EventSource::Height,
            serde_json::to_vec(self)?,
        ))
    }
}

/// Committee answers on Goat once the response window closed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerWindow {
    pub goat_height: i64,
    pub window_blocks: i64,
    pub quorum: u64,
    /// committee address -> instance pubkey, as stored on Goat.
    pub answers: IndexMap<String, Vec<u8>>,
}

impl AnswerWindow {
    pub fn event(&self, instance_id: Uuid) -> anyhow::Result<NewEvent> {
        Ok(NewEvent::new(
            format!("instance:{instance_id}:answers:{}", self.goat_height),
            instance_ref(instance_id),
            EVENT_ANSWER_WINDOW,
            EventSource::Chain,
            serde_json::to_vec(self)?,
        ))
    }
}

/// The Goat `BridgeInRequest` the event watcher indexed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeginRequested {
    pub tx_hash: String,
}

/// One event per request transaction: a re-indexed request is a new event.
pub fn pegin_request_event(
    instance_id: Uuid,
    request: &PeginRequested,
) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("instance:{instance_id}:pegin-request:{}", request.tx_hash),
        instance_ref(instance_id),
        EVENT_PEGIN_REQUEST,
        EventSource::Chain,
        serde_json::to_vec(request)?,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEndorsed {
    pub graph_id: Uuid,
}

/// A graph of the instance is finalized and endorsed locally.
pub fn graph_endorsed_event(instance_id: Uuid, graph_id: Uuid) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("instance:{instance_id}:graph-endorsed:{graph_id}"),
        instance_ref(instance_id),
        EVENT_GRAPH_ENDORSED,
        EventSource::Local,
        serde_json::to_vec(&GraphEndorsed { graph_id })?,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2Minted {
    pub tx_hash: String,
}

/// The Goat `BridgeIn` event.
pub fn l2_minted_event(instance_id: Uuid, tx_hash: &str) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("instance:{instance_id}:l2-minted:{tx_hash}"),
        instance_ref(instance_id),
        EVENT_L2_MINTED,
        EventSource::Chain,
        serde_json::to_vec(&L2Minted { tx_hash: tx_hash.to_string() })?,
    ))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDeleteParams {
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDeleteResult {
    pub deleted: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------- plans

/// The operator opens a setup session for its graph of the instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartGraph {
    /// The id of the session, or of the existing session when one is open.
    pub graph_id: Uuid,
    pub operator_pubkey: String,
}

/// What an instance job decided; the apply commits it with the row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstancePlan {
    pub messages: Vec<PlannedMessage>,
    pub next: Vec<NextStep>,
    pub start_graph: Option<StartGraph>,
    pub wake_refs: Vec<String>,
    pub note: Option<String>,
}

impl InstancePlan {
    pub fn noted(note: impl Into<String>) -> Self {
        Self { note: Some(note.into()), ..Default::default() }
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn send(&mut self, message: PlannedMessage) -> &mut Self {
        self.messages.push(message);
        self
    }

    pub fn then(&mut self, action: &str, params: Vec<u8>, delay_secs: Option<i64>) -> &mut Self {
        self.next.push(NextStep::Job { action: action.to_string(), params, delay_secs });
        self
    }
}

// ------------------------------------------------------------------ decisions

/// Conditions that need a human: the state machine does not move on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceAlert {
    /// Peg-In-Confirm confirmed after the instance was abandoned.
    PeginConfirmAfterTimeout,
    /// Goat minted for an instance this node holds in a failure state.
    L2MintedAfterFailure,
    /// The gateway rejected `postPeginData` permanently.
    PostPeginDataRejected,
    /// The committee key envelope could not be deleted.
    KeyDeleteFailed,
    /// A step of the committee's PeginConfirm round failed for good.
    PeginConfirmRoundFailed,
    /// The committee could not answer the peg-in request.
    AnswerPeginRequestFailed,
    /// Goat refused the data of a confirmed peg-in for good: no instance
    /// parameters stored, no graph started by this operator.
    ConfirmInstanceRejected,
}

impl InstanceAlert {
    pub const fn reason(self) -> &'static str {
        match self {
            InstanceAlert::PeginConfirmAfterTimeout => "pegin_confirm_after_timeout",
            InstanceAlert::L2MintedAfterFailure => "l2_minted_after_failure",
            InstanceAlert::PostPeginDataRejected => "post_pegin_data_rejected",
            InstanceAlert::KeyDeleteFailed => "key_delete_failed",
            InstanceAlert::PeginConfirmRoundFailed => "pegin_confirm_round_failed",
            InstanceAlert::AnswerPeginRequestFailed => "answer_pegin_request_failed",
            InstanceAlert::ConfirmInstanceRejected => "confirm_instance_rejected",
        }
    }
}

/// What one event changes. Pure: computed from the current row and the facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transition {
    pub next: Option<InstanceBridgeInStatus>,
    /// Peg-In-Prepare confirmation height, when the snapshot established it.
    pub prepare_height: Option<i64>,
    pub committees_answers: Option<IndexMap<String, Vec<u8>>>,
    pub post_pegin_txhash: Option<String>,
    /// Success-side key deletion is due (Peg-In-Confirm confirmed + depth).
    pub delete_key: bool,
    pub alerts: Vec<InstanceAlert>,
}

impl Transition {
    fn to(status: InstanceBridgeInStatus) -> Self {
        Self { next: Some(status), ..Default::default() }
    }

    fn alert(alert: InstanceAlert) -> Self {
        Self { alerts: vec![alert], ..Default::default() }
    }
}

/// Decide from a Bitcoin snapshot. A scan may cross several states: Prepare confirmation, then
/// Confirm or Cancel confirmation, are evaluated in order on the same facts.
pub fn decide_btc_snapshot(
    status: InstanceBridgeInStatus,
    prepare_height: i64,
    key_deleted: bool,
    snapshot: &BtcSnapshot,
    deadlines: &PeginDeadlines,
) -> Transition {
    use InstanceBridgeInStatus::*;
    let confirm = snapshot.confirm;
    let cancel = snapshot.cancel;
    let prepare = snapshot.prepare;
    let confirm_confirmed = confirm.is_some_and(|f| f.confirmed);
    let cancel_confirmed = cancel.is_some_and(|f| f.confirmed);

    if status.is_failed() {
        // Failure states are terminal except Timeout -> UserCanceled. A late Peg-In-Confirm
        // is reported, never acted on.
        if status == Timeout {
            if cancel_confirmed {
                return Transition::to(UserCanceled);
            }
            if confirm_confirmed {
                return Transition::alert(InstanceAlert::PeginConfirmAfterTimeout);
            }
        }
        return Transition::default();
    }

    let mut transition = Transition::default();
    let mut current = status;
    let mut prepare_height = prepare_height;

    // 1. Answer / AwaitPrepare: Prepare confirmation or a conflicting spend.
    // A conflicting spend is only judged once the Prepare txid is known
    // (CommitteesAnswered): before that the user's own Prepare, seen by a
    // node whose answer-window scan lags, would pass for a double spend.
    if matches!(current, UserInited | CommitteesAnswered) {
        if let Some(prepare) = prepare.filter(|f| f.confirmed) {
            current = UserBroadcastPeginPrepare;
            prepare_height = prepare.block_height.unwrap_or(prepare_height);
            transition.prepare_height = Some(prepare_height);
        } else if current == CommitteesAnswered && snapshot.inputs_available == Some(false) {
            transition.next = Some(UserDiscarded);
            return transition;
        }
    }

    // 2. Presign / Confirm: chain facts first, the deadline last.
    if matches!(current, UserBroadcastPeginPrepare | Presigned) {
        if confirm_confirmed {
            current = RelayerL1Broadcasted;
        } else if cancel_confirmed {
            current = UserCanceled;
        } else if current == UserBroadcastPeginPrepare
            && prepare.is_some_and(|f| !f.confirmed)
            && snapshot.inputs_available == Some(false)
        {
            // Prepare was reorged out and an input is spent elsewhere.
            current = UserDiscarded;
        } else if let Some(confirm) = confirm
            && deadlines.abandon_height(prepare_height).is_some_and(|h| snapshot.height >= h)
            && !confirm.in_mempool
        {
            current = Timeout;
        }
    }

    // 3. Post / Done: success-side key deletion depth.
    if matches!(current, RelayerL1Broadcasted | RelayerL2Minted)
        && !key_deleted
        && let Some(confirm) = confirm.filter(|f| f.confirmed)
        && let Some(confirmed_at) = confirm.block_height
        && confirmed_at + deadlines.key_delete_blocks <= snapshot.height
    {
        transition.delete_key = true;
    }

    if current != status {
        transition.next = Some(current);
    }
    transition
}

/// Decide the Answer phase once the response window closed.
pub fn decide_answer_window(
    status: InstanceBridgeInStatus,
    request_height: i64,
    known_answers: &IndexMap<String, Vec<u8>>,
    window: &AnswerWindow,
) -> Transition {
    if status != InstanceBridgeInStatus::UserInited
        || window.goat_height <= request_height + window.window_blocks
    {
        return Transition::default();
    }
    let mut answers = known_answers.clone();
    for (address, pubkey) in &window.answers {
        answers.insert(address.clone(), pubkey.clone());
    }
    let next = if answers.len() as u64 >= window.quorum {
        InstanceBridgeInStatus::CommitteesAnswered
    } else {
        InstanceBridgeInStatus::NoEnoughCommitteesAnswered
    };
    Transition { next: Some(next), committees_answers: Some(answers), ..Default::default() }
}

/// The Presigned threshold: finalized and endorsed graphs >= `min_required_operator()`.
pub fn decide_graph_endorsed(status: InstanceBridgeInStatus, endorsed_graphs: usize) -> Transition {
    if status == InstanceBridgeInStatus::UserBroadcastPeginPrepare
        && endorsed_graphs >= min_required_operator()
    {
        Transition::to(InstanceBridgeInStatus::Presigned)
    } else {
        Transition::default()
    }
}

/// The Goat `BridgeIn` event: success from any live state; an alert for failed instances.
pub fn decide_l2_minted(status: InstanceBridgeInStatus, tx_hash: &str) -> Transition {
    if status.is_failed() {
        return Transition::alert(InstanceAlert::L2MintedAfterFailure);
    }
    Transition {
        next: (status != InstanceBridgeInStatus::RelayerL2Minted)
            .then_some(InstanceBridgeInStatus::RelayerL2Minted),
        post_pegin_txhash: Some(tx_hash.to_string()),
        ..Default::default()
    }
}

/// The relayer re-broadcasts a Peg-In-Confirm that is neither confirmed nor in its mempool
/// while the instance stays Presigned.
pub fn rebroadcast_due(
    status: InstanceBridgeInStatus,
    transition: &Transition,
    snapshot: &BtcSnapshot,
) -> bool {
    status == InstanceBridgeInStatus::Presigned
        && transition.next.is_none()
        && snapshot.confirm.is_some_and(|confirm| confirm.invisible())
}

// --------------------------------------------------------------- signing gate

/// Signing and broadcast eligibility for an instance.
/// Closed for failed instances or when the tip reaches the Prepare height plus
/// its cancellation delay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningGate {
    Open,
    Closed(String),
}

impl SigningGate {
    pub fn is_open(&self) -> bool {
        matches!(self, SigningGate::Open)
    }
}

pub fn signing_gate_for(
    status: InstanceBridgeInStatus,
    prepare_height: i64,
    height: i64,
    deadlines: &PeginDeadlines,
) -> SigningGate {
    if status.is_failed() {
        return SigningGate::Closed(format!("instance is {status}"));
    }
    match deadlines.cancel_from_height(prepare_height) {
        Some(t0) if height >= t0 => {
            SigningGate::Closed(format!("height {height} reached T0 at {t0}"))
        }
        _ => SigningGate::Open,
    }
}

/// Evaluate the gate against the instance row and the current tip height.
pub async fn signing_gate(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    instance_id: Uuid,
) -> anyhow::Result<SigningGate> {
    let instance = local_db.acquire().await?.find_instance(&instance_id).await?;
    let Some(instance) = instance else {
        return Ok(SigningGate::Closed("instance not found".to_string()));
    };
    let Ok(status) = InstanceBridgeInStatus::from_str(&instance.status) else {
        return Ok(SigningGate::Closed(format!("unknown instance status {}", instance.status)));
    };
    if status.is_failed() {
        return Ok(SigningGate::Closed(format!("instance is {status}")));
    }
    if instance.btc_height <= 0 {
        return Ok(SigningGate::Open);
    }
    let height = i64::from(btc_client.get_height().await?);
    Ok(signing_gate_for(status, instance.btc_height, height, &PeginDeadlines::from_env()))
}

// -------------------------------------------------------------------- handler

pub struct InstanceAggregate {
    actor: Actor,
    deadlines: PeginDeadlines,
    relayer: bool,
    key_delete_enabled: bool,
    local_peer: String,
    membership: Arc<dyn MembershipProbe>,
}

impl InstanceAggregate {
    pub fn from_env(actor: Actor) -> Self {
        Self::new(
            actor,
            PeginDeadlines::from_env(),
            is_relayer(),
            is_enable_committee_instance_key_delete(),
            get_peer_id(),
        )
    }

    pub fn new(
        actor: Actor,
        deadlines: PeginDeadlines,
        relayer: bool,
        key_delete_enabled: bool,
        local_peer: String,
    ) -> Self {
        Self {
            actor,
            deadlines,
            relayer,
            key_delete_enabled,
            local_peer,
            membership: Arc::new(EnvelopeProbe),
        }
    }

    pub fn with_membership(mut self, membership: Arc<dyn MembershipProbe>) -> Self {
        self.membership = membership;
        self
    }

    fn job(&self, ctx: &mut ApplyContext<'_>, action: &str, params: Vec<u8>) {
        ctx.effects.enqueue_job(JobSpec::new(
            &ctx.aggregate,
            job_phase(action),
            action,
            JobPool::Network,
            params,
        ));
    }

    async fn commit(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
        status: InstanceBridgeInStatus,
        transition: Transition,
    ) -> anyhow::Result<()> {
        let instance_id = instance.instance_id;
        let mut final_status = status;
        if let Some(next) = transition.next.filter(|next| *next != status) {
            let mut update = InstanceUpdate::new_with_instance_id(instance_id)
                .with_status(next.to_string())
                .with_only_if_status_in(vec![status.to_string()]);
            if let Some(height) = transition.prepare_height {
                update = update.with_btc_height(height);
            }
            if let Some(answers) = transition.committees_answers.clone() {
                update = update.with_committees_answers(answers.clone());
                if next == InstanceBridgeInStatus::CommitteesAnswered {
                    let mut seeded = instance.clone();
                    seeded.committees_answers = answers;
                    match pegin_txids(&seeded) {
                        Ok((deposit, confirm, cancel)) => {
                            update = update
                                .with_btc_txid(deposit)
                                .with_pegin_confirm_txid(confirm)
                                .with_pegin_cancel_txid(cancel);
                        }
                        Err(error) => warn!(
                            event = "instance_transition",
                            instance_id = %instance_id,
                            error = %error,
                            "could not derive the peg-in txids from the committee answers"
                        ),
                    }
                }
            }
            if let Some(tx_hash) = transition.post_pegin_txhash.clone() {
                update = update.with_post_pegin(tx_hash);
            }
            if !ctx.storage.update_instance(&update).await? {
                anyhow::bail!("instance {instance_id} left status {status} during the apply");
            }
            info!(
                event = "instance_transition",
                instance_id = %instance_id,
                from = %status,
                to = %next,
                height = ?transition.prepare_height,
                "instance status updated"
            );
            final_status = next;
            self.on_entered(ctx, instance, status, next).await?;
        } else if let Some(tx_hash) = transition.post_pegin_txhash.clone() {
            ctx.storage
                .update_instance(
                    &InstanceUpdate::new_with_instance_id(instance_id).with_post_pegin(tx_hash),
                )
                .await?;
        }
        if transition.prepare_height.is_some() {
            // Peg-In-Prepare confirmed: every role stores the instance parameters, operators
            // start graphs.
            self.job(ctx, JOB_CONFIRM_INSTANCE, Vec::new());
        }
        if transition.delete_key {
            self.request_key_delete(ctx, instance, "success");
        }
        for alert in transition.alerts {
            raise_alert(instance_id, alert, "");
        }
        ctx.effects
            .set_status(final_status.to_string())
            .set_phase(phase_of(final_status).to_string());
        Ok(())
    }

    async fn on_entered(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
        previous: InstanceBridgeInStatus,
        next: InstanceBridgeInStatus,
    ) -> anyhow::Result<()> {
        use InstanceBridgeInStatus::*;
        match next {
            CommitteesAnswered => {
                ctx.effects.cancel_phase_jobs(PHASE_ANSWER);
            }
            Presigned => {
                // The committee's PeginConfirm round starts from the stored values; the outbox
                // re-publishes them until the round closes.
                if self.actor == Actor::Committee {
                    self.job(ctx, JOB_START_PEGIN_CONFIRM, Vec::new());
                }
            }
            RelayerL1Broadcasted => {
                self.close_confirm_round(ctx, instance.instance_id, "Peg-In-Confirm confirmed");
                if self.relayer {
                    self.job(ctx, JOB_POST_PEGIN_DATA, Vec::new());
                }
            }
            RelayerL2Minted => {
                self.close_confirm_round(ctx, instance.instance_id, "minted on Goat");
                ctx.effects.cancel_phase_jobs(PHASE_CONFIRM);
                ctx.effects.cancel_phase_jobs(PHASE_POST);
            }
            failed if failed.is_failed() => {
                self.enter_failure(ctx, instance, previous, failed).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Close the instance's Confirm-phase outbox deliveries.
    fn close_confirm_round(&self, ctx: &mut ApplyContext<'_>, instance_id: Uuid, reason: &str) {
        ctx.effects.close_outbox(
            EngineOutboxCloseTarget::Phase {
                aggregate_kind: INSTANCE_KIND.to_string(),
                aggregate_id: instance_id.to_string(),
                phase_ref: PHASE_CONFIRM.to_string(),
            },
            reason,
        );
    }

    /// Close instance deliveries and retire its graphs on failure.
    /// Delete the committee key unless the status is Timeout. A later UserCanceled
    /// transition repeats cleanup and requests key deletion.
    async fn enter_failure(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
        previous: InstanceBridgeInStatus,
        failed: InstanceBridgeInStatus,
    ) -> anyhow::Result<()> {
        let instance_id = instance.instance_id;
        let obsoleted = obsolete_instance_graphs_except(ctx.storage, instance_id, None).await?;
        ctx.effects.close_outbox(
            EngineOutboxCloseTarget::Aggregate {
                aggregate_kind: INSTANCE_KIND.to_string(),
                aggregate_id: instance_id.to_string(),
            },
            format!("instance {failed}"),
        );
        for phase in [PHASE_ANSWER, PHASE_PRESIGN, PHASE_CONFIRM, PHASE_POST] {
            ctx.effects.cancel_phase_jobs(phase);
        }
        // Close graph deliveries and cancel setup/post jobs. Keep kickoff and settlement
        // jobs so chain monitoring and challenges can continue.
        for graph in ctx.storage.get_graphs_by_instance_id(&instance_id).await? {
            let graph_ref = crate::aggregates::graph::graph_ref(graph.graph_id);
            ctx.effects.close_outbox(
                EngineOutboxCloseTarget::Aggregate {
                    aggregate_kind: graph_ref.kind.clone(),
                    aggregate_id: graph_ref.id.clone(),
                },
                format!("instance {failed}"),
            );
            for phase in [crate::aggregates::graph::JOB_PHASE, crate::aggregates::graph::PHASE_POST]
            {
                ctx.effects.cancel_phase_jobs_for_aggregate(&graph_ref, phase);
            }
            ctx.effects.wake(crate::aggregates::graph::slot_ref(
                &graph.operator_pubkey,
                graph.kickoff_index as u64,
            ));
        }
        // A setup session that never stored a definition (the operator's own
        // graph in Setup) is released with the slot it was taking.
        for session in ctx.storage.list_pending_graph_inits_by_instance(&instance_id).await? {
            let next_slot = crate::aggregates::graph::release_setup_session(
                ctx,
                &session,
                &format!("instance {failed}"),
            )
            .await?;
            info!(
                event = "instance_failed",
                instance_id = %instance_id,
                graph_id = %session.graph_id,
                next_slot,
                "dropped the setup session of a failed instance"
            );
        }
        warn!(
            event = "instance_failed",
            instance_id = %instance_id,
            from = %previous,
            to = %failed,
            obsoleted_graphs = ?obsoleted,
            "instance entered a failure state"
        );
        if failed.deletes_key_on_entry() {
            self.request_key_delete(ctx, instance, "failure");
        } else {
            info!(
                event = "instance_key_delete",
                instance_id = %instance_id,
                outcome = "kept",
                reason = %failed,
                "committee instance key kept for manual handling"
            );
        }
        Ok(())
    }

    /// Queue the deletion of the committee instance key. Only committee nodes
    /// hold an envelope; with deletion disabled the intent is only recorded.
    fn request_key_delete(&self, ctx: &mut ApplyContext<'_>, instance: &Instance, reason: &str) {
        if self.actor != Actor::Committee || instance.key_deleted {
            return;
        }
        if !self.key_delete_enabled {
            info!(
                event = "instance_key_delete",
                instance_id = %instance.instance_id,
                outcome = "disabled",
                reason,
                "committee instance key is due for deletion; deletion is disabled"
            );
            return;
        }
        let params = serde_json::to_vec(&KeyDeleteParams { reason: reason.to_string() })
            .expect("KeyDeleteParams serializes");
        ctx.effects.enqueue_job(JobSpec::new(
            &ctx.aggregate,
            PHASE_KEY,
            JOB_DELETE_INSTANCE_KEY,
            JobPool::Network,
            params,
        ));
    }

    /// A `pegin_request` event: the row was stored by the scan; a committee
    /// node answers on Goat while the request is still in its Answer phase.
    fn apply_pegin_request(
        &self,
        ctx: &mut ApplyContext<'_>,
        status: InstanceBridgeInStatus,
        payload: &[u8],
    ) -> ApplyOutcome {
        if status != InstanceBridgeInStatus::UserInited {
            return ApplyOutcome::Applied;
        }
        if self.actor == Actor::Committee {
            self.job(ctx, JOB_ANSWER_PEGIN_REQUEST, payload.to_vec());
        }
        ApplyOutcome::Applied
    }

    /// A committee member's PeginConfirm round message: ignored from this
    /// node itself, for instances this node holds no key of, and once the
    /// round is over; otherwise handed to its ingest job. A partial
    /// signature is still taken after the Peg-In-Confirm confirmed: it
    /// carries the endorsement the relayer's post needs.
    fn apply_round_message(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance_id: Uuid,
        status: InstanceBridgeInStatus,
        kind: &str,
        payload: &[u8],
    ) -> ApplyOutcome {
        let inbound = match InboundMessage::decode(payload) {
            Ok(inbound) => inbound,
            Err(error) => {
                return ApplyOutcome::Rejected(format!("malformed {kind} event: {error}"));
            }
        };
        if inbound.author == self.local_peer {
            return ApplyOutcome::Applied;
        }
        let Some(action) = route_action(kind, &self.actor) else {
            return ApplyOutcome::Rejected(format!("{kind} is not handled by {}", self.actor));
        };
        // A relayer collects every round whether or not it signs in it: it
        // aggregates and broadcasts for committees it is not a member of.
        if !self.relayer && !self.membership.holds_instance_key(instance_id) {
            debug!(event = "instance_apply", instance_id = %instance_id, kind, "not in this instance's committee; message ignored");
            return ApplyOutcome::Applied;
        }
        // The round's parameters derive from the committee answers; a message
        // that arrives before the window closed here (a node catching up)
        // waits for them instead of running a job that cannot aggregate.
        if status == InstanceBridgeInStatus::UserInited {
            return ApplyOutcome::Waiting(WaitingFor::on(
                &ctx.aggregate,
                "committee answers not recorded yet",
            ));
        }
        let round_over = status.is_failed()
            || status == InstanceBridgeInStatus::RelayerL2Minted
            || (status == InstanceBridgeInStatus::RelayerL1Broadcasted
                && kind != "PeginConfirmPartialSig");
        if round_over {
            debug!(event = "instance_apply", instance_id = %instance_id, kind, status = %status, "PeginConfirm round is over; message ignored");
            return ApplyOutcome::Applied;
        }
        ctx.effects.enqueue_job(
            JobSpec::new(&ctx.aggregate, PHASE_CONFIRM, action, JobPool::Network, payload.to_vec())
                .with_deadline(ctx.now + PARKED_MESSAGE_TTL_SECS),
        );
        ApplyOutcome::Applied
    }

    async fn apply_plan(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
        status: InstanceBridgeInStatus,
        plan: InstancePlan,
    ) -> anyhow::Result<()> {
        let instance_id = instance.instance_id;
        let round_over = confirm_round_over(status);
        for message in plan.messages {
            if round_over && message.phase_ref == PHASE_CONFIRM {
                continue;
            }
            ctx.effects.send(OutboxMessage {
                outbox_id: message.outbox_id,
                phase_ref: message.phase_ref,
                kind: message.kind,
                topic: get_topic_name(&message.actor),
                payload: message.payload,
                ack_set: message.ack_set,
            });
        }
        for step in plan.next {
            let NextStep::Job { action, params, delay_secs } = step;
            let phase = job_phase(&action);
            if round_over && phase == PHASE_CONFIRM {
                continue;
            }
            let mut job = JobSpec::new(&ctx.aggregate, phase, &action, JobPool::Network, params);
            if let Some(delay) = delay_secs {
                job = job.with_run_after(ctx.now + delay.max(0));
            }
            ctx.effects.enqueue_job(job);
        }
        if let Some(start) = plan.start_graph
            && !status.is_failed()
        {
            // One session per (instance, operator): a repeat of the job
            // resumes the open session instead of opening a second one.
            let graph_id = match ctx
                .storage
                .find_pending_graph_init_by_instance_and_operator_pubkey(
                    &instance_id,
                    &start.operator_pubkey,
                )
                .await?
            {
                Some(session) => session.graph_id,
                None => {
                    ctx.storage
                        .upsert_pending_graph_init(
                            &instance_id,
                            &start.operator_pubkey,
                            &start.graph_id,
                        )
                        .await?;
                    start.graph_id
                }
            };
            record_event_in(
                ctx.storage,
                operator_start_event(instance_id, graph_id, &start.operator_pubkey)?,
            )
            .await?;
            info!(event = "graph_start", instance_id = %instance_id, graph_id = %graph_id, "operator setup session opened");
        }
        for wake_ref in plan.wake_refs {
            ctx.effects.wake(wake_ref);
        }
        Ok(())
    }

    async fn apply_job_result(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
        status: InstanceBridgeInStatus,
        result: JobResultEvent,
    ) -> Result<ApplyOutcome, ApplyError> {
        let instance_id = instance.instance_id;
        match result.action.as_str() {
            JOB_DELETE_INSTANCE_KEY => match &result.outcome {
                JobResultOutcome::Done(bytes) => {
                    let outcome: KeyDeleteResult =
                        serde_json::from_slice(bytes).unwrap_or_default();
                    if outcome.deleted {
                        ctx.storage
                            .update_instance(
                                &InstanceUpdate::new_with_instance_id(instance_id)
                                    .with_key_deleted(true),
                            )
                            .await?;
                        info!(
                            event = "instance_key_delete",
                            instance_id = %instance_id,
                            outcome = "deleted",
                            stale = result.stale,
                            detail = %outcome.detail,
                            "committee instance key envelope deleted"
                        );
                    } else {
                        info!(
                            event = "instance_key_delete",
                            instance_id = %instance_id,
                            outcome = "recorded",
                            detail = %outcome.detail,
                            "committee instance key deletion recorded without deleting"
                        );
                    }
                }
                JobResultOutcome::Failed(error) => {
                    raise_alert(instance_id, InstanceAlert::KeyDeleteFailed, error);
                }
                JobResultOutcome::Cancelled => {
                    debug!(event = "instance_key_delete", instance_id = %instance_id, outcome = "cancelled", "key deletion job cancelled");
                }
                JobResultOutcome::Poisoned(error) => {
                    warn!(event = "instance_key_delete", instance_id = %instance_id, outcome = "poisoned", error = %error, "key deletion job panicked");
                }
            },
            JOB_POST_PEGIN_DATA => match &result.outcome {
                JobResultOutcome::Done(_) => {
                    info!(event = "instance_post", instance_id = %instance_id, outcome = "posted", stale = result.stale, "pegin data posted; waiting for the BridgeIn event");
                }
                JobResultOutcome::Failed(error) => {
                    raise_alert(instance_id, InstanceAlert::PostPeginDataRejected, error);
                }
                JobResultOutcome::Cancelled => {
                    debug!(event = "instance_post", instance_id = %instance_id, outcome = "cancelled", "post job cancelled");
                }
                JobResultOutcome::Poisoned(error) => {
                    warn!(event = "instance_post", instance_id = %instance_id, outcome = "poisoned", error = %error, "post job panicked");
                }
            },
            action if INSTANCE_JOBS.contains(&action) => match &result.outcome {
                JobResultOutcome::Done(bytes) => {
                    let plan = match InstancePlan::decode(bytes) {
                        Ok(plan) => plan,
                        Err(error) => {
                            return Ok(ApplyOutcome::Rejected(format!(
                                "malformed plan from {action}: {error}"
                            )));
                        }
                    };
                    if let Some(note) = &plan.note {
                        info!(event = "instance_job", instance_id = %instance_id, action, stale = result.stale, note = %note, "job note");
                    }
                    self.apply_plan(ctx, instance, status, plan).await?;
                }
                JobResultOutcome::Failed(error) => {
                    let alert = match action {
                        JOB_ANSWER_PEGIN_REQUEST => Some(InstanceAlert::AnswerPeginRequestFailed),
                        JOB_CONFIRM_INSTANCE => Some(InstanceAlert::ConfirmInstanceRejected),
                        JOB_START_PEGIN_CONFIRM
                        | JOB_PEGIN_CONFIRM_VOTE
                        | JOB_PEGIN_CONFIRM_SIGN
                        | JOB_BROADCAST_PEGIN_CONFIRM => {
                            Some(InstanceAlert::PeginConfirmRoundFailed)
                        }
                        _ => None,
                    };
                    match alert {
                        Some(alert) => raise_alert(instance_id, alert, error),
                        None => {
                            warn!(event = "instance_job", instance_id = %instance_id, action, error = %error, "job failed")
                        }
                    }
                }
                JobResultOutcome::Cancelled => {
                    debug!(event = "instance_job", instance_id = %instance_id, action, "job cancelled");
                }
                JobResultOutcome::Poisoned(error) => {
                    warn!(event = "instance_job", instance_id = %instance_id, action, error = %error, "job panicked");
                }
            },
            other => {
                return Ok(ApplyOutcome::Rejected(format!("unknown instance job action {other}")));
            }
        }
        ctx.storage.clear_engine_job_result(&result.job_id, ctx.now).await?;
        ctx.effects.set_status(status.to_string()).set_phase(phase_of(status).to_string());
        Ok(ApplyOutcome::Applied)
    }

    /// Every partial signature of the committee is stored locally: the
    /// relayer can aggregate.
    async fn partial_sigs_complete(
        &self,
        ctx: &mut ApplyContext<'_>,
        instance: &Instance,
    ) -> anyhow::Result<bool> {
        let committee = instance.committees_answers.len();
        if committee == 0 {
            return Ok(false);
        }
        let process_data =
            find_pegin_instance_process_data(ctx.storage, instance.instance_id).await?;
        Ok(process_data.values().filter(|item| item.partial_sign.is_some()).count() >= committee)
    }
}

fn decode<T: for<'de> Deserialize<'de>>(kind: &str, payload: &[u8]) -> Result<T, ApplyOutcome> {
    serde_json::from_slice(payload)
        .map_err(|error| ApplyOutcome::Rejected(format!("malformed {kind} payload: {error}")))
}

#[async_trait]
impl AggregateHandler for InstanceAggregate {
    async fn apply(
        &self,
        ctx: &mut ApplyContext<'_>,
        event: &EngineInboxEvent,
    ) -> Result<ApplyOutcome, ApplyError> {
        let instance_id = Uuid::from_str(&ctx.aggregate.id).map_err(|error| {
            ApplyError::invariant(anyhow!("instance aggregate id {}: {error}", ctx.aggregate.id))
        })?;
        let Some(instance) = ctx.storage.find_instance(&instance_id).await? else {
            return Ok(ApplyOutcome::Waiting(WaitingFor::on(
                &ctx.aggregate,
                "instance row not found",
            )));
        };
        let status = InstanceBridgeInStatus::from_str(&instance.status).map_err(|_| {
            ApplyError::invariant(anyhow!(
                "instance {instance_id} has unknown status {}",
                instance.status
            ))
        })?;
        let payload = event.payload.as_deref().unwrap_or_default();
        let transition = match event.kind.as_str() {
            EVENT_BTC_SNAPSHOT => {
                let snapshot: BtcSnapshot = match decode(EVENT_BTC_SNAPSHOT, payload) {
                    Ok(snapshot) => snapshot,
                    Err(rejected) => return Ok(rejected),
                };
                let transition = decide_btc_snapshot(
                    status,
                    instance.btc_height,
                    instance.key_deleted,
                    &snapshot,
                    &self.deadlines,
                );
                // The relayer re-sends a Peg-In-Confirm that fell out of its
                // mempool, once per block, until it is seen or the instance
                // is abandoned.
                if self.relayer
                    && rebroadcast_due(status, &transition, &snapshot)
                    && self.partial_sigs_complete(ctx, &instance).await?
                {
                    self.job(
                        ctx,
                        JOB_BROADCAST_PEGIN_CONFIRM,
                        snapshot.height.to_le_bytes().to_vec(),
                    );
                }
                transition
            }
            EVENT_ANSWER_WINDOW => {
                let window: AnswerWindow = match decode(EVENT_ANSWER_WINDOW, payload) {
                    Ok(window) => window,
                    Err(rejected) => return Ok(rejected),
                };
                decide_answer_window(
                    status,
                    instance.goat_tx_height,
                    &instance.committees_answers,
                    &window,
                )
            }
            EVENT_GRAPH_ENDORSED => {
                if matches!(
                    status,
                    InstanceBridgeInStatus::UserInited | InstanceBridgeInStatus::CommitteesAnswered
                ) {
                    // Keep the endorsement event pending until Prepare is confirmed, so an early
                    // finalized graph still counts toward the Presigned threshold.
                    return Ok(ApplyOutcome::Waiting(WaitingFor::on(
                        &ctx.aggregate,
                        "instance has not reached the Presign phase",
                    )));
                }
                let endorsed = ctx
                    .storage
                    .get_pegin_graph_endorsed_len_by_instance_id(&instance_id, true)
                    .await
                    .context("count endorsed graphs")?;
                decide_graph_endorsed(status, usize::try_from(endorsed).unwrap_or(0))
            }
            EVENT_L2_MINTED => {
                let minted: L2Minted = match decode(EVENT_L2_MINTED, payload) {
                    Ok(minted) => minted,
                    Err(rejected) => return Ok(rejected),
                };
                decide_l2_minted(status, &minted.tx_hash)
            }
            EVENT_PEGIN_REQUEST => {
                if let Err(rejected) = decode::<PeginRequested>(EVENT_PEGIN_REQUEST, payload) {
                    return Ok(rejected);
                }
                let outcome = self.apply_pegin_request(ctx, status, payload);
                ctx.effects.set_status(status.to_string()).set_phase(phase_of(status).to_string());
                return Ok(outcome);
            }
            JOB_RESULT_KIND => {
                let result = JobResultEvent::decode(payload).map_err(ApplyError::invariant)?;
                return self.apply_job_result(ctx, &instance, status, result).await;
            }
            kind if engine_handles(kind, &Actor::Committee) => {
                let outcome = self.apply_round_message(ctx, instance_id, status, kind, payload);
                ctx.effects.set_status(status.to_string()).set_phase(phase_of(status).to_string());
                return Ok(outcome);
            }
            other => {
                return Ok(ApplyOutcome::Rejected(format!("unknown instance event kind {other}")));
            }
        };
        self.commit(ctx, &instance, status, transition).await?;
        Ok(ApplyOutcome::Applied)
    }
}

fn raise_alert(instance_id: Uuid, alert: InstanceAlert, detail: &str) {
    warn!(
        event = "instance_alert",
        instance_id = %instance_id,
        reason = alert.reason(),
        detail,
        "instance needs manual handling"
    );
    if let Some(metrics) = node_metrics_state() {
        metrics.record_instance_alert(alert.reason());
    }
}

/// The three peg-in txids once the committee answers are known.
pub fn pegin_txids(
    instance: &Instance,
) -> anyhow::Result<(SerializableTxid, SerializableTxid, SerializableTxid)> {
    let (deposit, confirm, cancel) = gen_instance_parameters_local(instance)?.build_pegin_tx()?;
    Ok((
        deposit.tx().compute_txid().into(),
        confirm.finalize().compute_txid().into(),
        cancel.finalize().compute_txid().into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use InstanceBridgeInStatus::*;

    const DEADLINES: PeginDeadlines =
        PeginDeadlines { t0_blocks: 60, buffer_blocks: 6, key_delete_blocks: 32 };
    const PREPARE: i64 = 1_000;

    fn snapshot(height: i64) -> BtcSnapshot {
        BtcSnapshot { height, status_at_scan: String::new(), ..Default::default() }
    }

    fn decide(status: InstanceBridgeInStatus, snapshot: &BtcSnapshot) -> Transition {
        decide_btc_snapshot(status, PREPARE, false, snapshot, &DEADLINES)
    }

    #[test]
    fn deadlines_follow_the_prepare_height() {
        assert_eq!(DEADLINES.cancel_from_height(0), None);
        assert_eq!(DEADLINES.abandon_height(0), None);
        assert_eq!(DEADLINES.cancel_from_height(PREPARE), Some(1_060));
        assert_eq!(DEADLINES.abandon_height(PREPARE), Some(1_066));
        assert!(DEADLINES.signing_open(0, 5_000));
        assert!(DEADLINES.signing_open(PREPARE, 1_059));
        assert!(!DEADLINES.signing_open(PREPARE, 1_060));
    }

    #[test]
    fn inputs_spent_discards_before_prepare() {
        let mut snap = snapshot(10);
        snap.inputs_available = Some(false);
        // Before the Prepare txid is known the spender may be the user's own
        // Prepare: no decision at UserInited.
        assert_eq!(decide(UserInited, &snap).next, None);
        assert_eq!(decide(CommitteesAnswered, &snap).next, Some(UserDiscarded));
        snap.inputs_available = Some(true);
        assert_eq!(decide(UserInited, &snap).next, None);
        // Not queried: no decision.
        snap.inputs_available = None;
        assert_eq!(decide(CommitteesAnswered, &snap).next, None);
    }

    #[test]
    fn prepare_confirmation_records_the_height_and_may_cross_states() {
        let mut snap = snapshot(500);
        snap.prepare = Some(TxFact::confirmed_at(480));
        let t = decide(CommitteesAnswered, &snap);
        assert_eq!(t.next, Some(UserBroadcastPeginPrepare));
        assert_eq!(t.prepare_height, Some(480));
        // Prepare and Confirm seen in one scan.
        snap.confirm = Some(TxFact::confirmed_at(490));
        let t = decide(CommitteesAnswered, &snap);
        assert_eq!(t.next, Some(RelayerL1Broadcasted));
        assert_eq!(t.prepare_height, Some(480));
        // Prepare and Cancel seen in one scan.
        snap.confirm = Some(TxFact::UNKNOWN);
        snap.cancel = Some(TxFact::confirmed_at(545));
        assert_eq!(decide(CommitteesAnswered, &snap).next, Some(UserCanceled));
    }

    #[test]
    fn reorged_prepare_with_spent_inputs_discards() {
        let mut snap = snapshot(1_010);
        snap.prepare = Some(TxFact::UNKNOWN);
        snap.inputs_available = Some(false);
        snap.confirm = Some(TxFact::UNKNOWN);
        snap.cancel = Some(TxFact::UNKNOWN);
        assert_eq!(decide(UserBroadcastPeginPrepare, &snap).next, Some(UserDiscarded));
        // A Presigned instance has no Prepare fact; nothing happens.
        assert_eq!(decide(Presigned, &snap).next, None);
    }

    #[test]
    fn confirm_confirmed_in_the_buffer_still_broadcasts() {
        for height in [1_050, 1_060, 1_065, 1_066, 2_000] {
            let mut snap = snapshot(height);
            snap.confirm = Some(TxFact::confirmed_at(height - 1));
            snap.cancel = Some(TxFact::UNKNOWN);
            assert_eq!(decide(Presigned, &snap).next, Some(RelayerL1Broadcasted), "{height}");
            assert_eq!(
                decide(UserBroadcastPeginPrepare, &snap).next,
                Some(RelayerL1Broadcasted),
                "{height}"
            );
        }
    }

    #[test]
    fn cancel_confirmed_fails_from_presign_confirm_and_timeout() {
        let mut snap = snapshot(1_100);
        snap.confirm = Some(TxFact::UNKNOWN);
        snap.cancel = Some(TxFact::confirmed_at(1_099));
        assert_eq!(decide(UserBroadcastPeginPrepare, &snap).next, Some(UserCanceled));
        assert_eq!(decide(Presigned, &snap).next, Some(UserCanceled));
        assert_eq!(decide(Timeout, &snap).next, Some(UserCanceled));
    }

    #[test]
    fn timeout_only_past_the_abandon_height_without_mempool_visibility() {
        let mut snap = snapshot(1_065);
        snap.confirm = Some(TxFact::UNKNOWN);
        snap.cancel = Some(TxFact::UNKNOWN);
        // T0 reached, buffer not over: keep following the chain.
        assert_eq!(decide(Presigned, &snap).next, None);
        snap.height = 1_066;
        assert_eq!(decide(Presigned, &snap).next, Some(Timeout));
        assert_eq!(decide(UserBroadcastPeginPrepare, &snap).next, Some(Timeout));
        // Visible in the mempool: keep waiting, no upper bound.
        snap.confirm = Some(TxFact::mempool());
        snap.height = 9_999;
        assert_eq!(decide(Presigned, &snap).next, None);
        // Confirm fact missing: never decide Timeout on it.
        snap.confirm = None;
        assert_eq!(decide(Presigned, &snap).next, None);
        // Unknown Prepare height: no deadline at all.
        snap.confirm = Some(TxFact::UNKNOWN);
        assert_eq!(decide_btc_snapshot(Presigned, 0, false, &snap, &DEADLINES).next, None);
    }

    #[test]
    fn failure_states_are_absorbing_and_late_confirm_only_alerts() {
        let mut snap = snapshot(1_200);
        snap.confirm = Some(TxFact::confirmed_at(1_150));
        snap.cancel = Some(TxFact::UNKNOWN);
        let t = decide(Timeout, &snap);
        assert_eq!(t.next, None);
        assert_eq!(t.alerts, vec![InstanceAlert::PeginConfirmAfterTimeout]);
        for failed in [UserCanceled, UserDiscarded, NoEnoughCommitteesAnswered] {
            let t = decide(failed, &snap);
            assert_eq!(t.next, None, "{failed}");
            assert!(t.alerts.is_empty(), "{failed}");
        }
        snap.cancel = Some(TxFact::confirmed_at(1_190));
        assert_eq!(decide(UserCanceled, &snap).next, None);
    }

    #[test]
    fn success_side_key_deletion_waits_for_the_depth() {
        let mut snap = snapshot(1_131);
        snap.confirm = Some(TxFact::confirmed_at(1_100));
        assert!(!decide(RelayerL1Broadcasted, &snap).delete_key);
        snap.height = 1_132;
        assert!(decide(RelayerL1Broadcasted, &snap).delete_key);
        assert!(decide(RelayerL2Minted, &snap).delete_key);
        assert!(!decide_btc_snapshot(RelayerL2Minted, PREPARE, true, &snap, &DEADLINES).delete_key);
        assert_eq!(decide(RelayerL2Minted, &snap).next, None);
    }

    #[test]
    fn answer_window_decides_quorum_once_closed() {
        let mut answers = IndexMap::new();
        answers.insert("0xa".to_string(), vec![1u8]);
        let window = AnswerWindow { goat_height: 200, window_blocks: 50, quorum: 2, answers };
        // Window not over.
        assert_eq!(decide_answer_window(UserInited, 150, &IndexMap::new(), &window).next, None);
        assert_eq!(
            decide_answer_window(UserInited, 149, &IndexMap::new(), &window).next,
            Some(NoEnoughCommitteesAnswered)
        );
        let mut known = IndexMap::new();
        known.insert("0xb".to_string(), vec![2u8]);
        let t = decide_answer_window(UserInited, 100, &known, &window);
        assert_eq!(t.next, Some(CommitteesAnswered));
        assert_eq!(t.committees_answers.as_ref().map(IndexMap::len), Some(2));
        // Only the Answer phase decides on it.
        assert_eq!(decide_answer_window(CommitteesAnswered, 100, &known, &window).next, None);
        assert_eq!(decide_answer_window(UserDiscarded, 100, &known, &window).next, None);
    }

    #[test]
    fn presigned_threshold_only_from_presign_phase() {
        assert_eq!(decide_graph_endorsed(UserBroadcastPeginPrepare, 0).next, None);
        assert_eq!(decide_graph_endorsed(UserBroadcastPeginPrepare, 1).next, Some(Presigned));
        assert_eq!(decide_graph_endorsed(Presigned, 3).next, None);
        assert_eq!(decide_graph_endorsed(Timeout, 3).next, None);
        assert_eq!(decide_graph_endorsed(CommitteesAnswered, 3).next, None);
    }

    #[test]
    fn l2_mint_succeeds_from_live_states_and_alerts_on_failure() {
        for live in [
            UserInited,
            CommitteesAnswered,
            UserBroadcastPeginPrepare,
            Presigned,
            RelayerL1Broadcasted,
        ] {
            let t = decide_l2_minted(live, "0xmint");
            assert_eq!(t.next, Some(RelayerL2Minted), "{live}");
            assert_eq!(t.post_pegin_txhash.as_deref(), Some("0xmint"));
        }
        assert_eq!(decide_l2_minted(RelayerL2Minted, "0xmint").next, None);
        for failed in InstanceBridgeInStatus::FAILED {
            let t = decide_l2_minted(failed, "0xmint");
            assert_eq!(t.next, None, "{failed}");
            assert_eq!(t.alerts, vec![InstanceAlert::L2MintedAfterFailure]);
        }
    }

    #[test]
    fn signing_gate_closes_at_t0_and_on_failure() {
        assert!(signing_gate_for(Presigned, PREPARE, 1_059, &DEADLINES).is_open());
        assert!(!signing_gate_for(Presigned, PREPARE, 1_060, &DEADLINES).is_open());
        assert!(signing_gate_for(UserBroadcastPeginPrepare, 0, 9_999, &DEADLINES).is_open());
        for failed in InstanceBridgeInStatus::FAILED {
            assert!(!signing_gate_for(failed, PREPARE, 10, &DEADLINES).is_open());
        }
    }

    #[test]
    fn phases_follow_the_phase_table() {
        assert_eq!(phase_of(UserInited), PHASE_ANSWER);
        assert_eq!(phase_of(CommitteesAnswered), PHASE_AWAIT_PREPARE);
        assert_eq!(phase_of(UserBroadcastPeginPrepare), PHASE_PRESIGN);
        assert_eq!(phase_of(Presigned), PHASE_CONFIRM);
        assert_eq!(phase_of(RelayerL1Broadcasted), PHASE_POST);
        assert_eq!(phase_of(RelayerL2Minted), PHASE_DONE);
        for failed in InstanceBridgeInStatus::FAILED {
            assert_eq!(phase_of(failed), PHASE_FAILED);
        }
    }

    #[test]
    fn snapshot_event_ids_change_with_height_and_status() {
        let id = Uuid::new_v4();
        let mut snap = snapshot(10);
        snap.status_at_scan = "Presigned".into();
        let a = snap.event(id).unwrap().event_id;
        snap.status_at_scan = "RelayerL1Broadcasted".into();
        let b = snap.event(id).unwrap().event_id;
        snap.height = 11;
        let c = snap.event(id).unwrap().event_id;
        assert!(a != b && b != c && a != c);
        assert_eq!(graph_endorsed_event(id, id).unwrap().aggregate, instance_ref(id));
        let request = PeginRequested { tx_hash: "0xreq".into() };
        let event = pegin_request_event(id, &request).unwrap();
        assert_eq!(event.kind, EVENT_PEGIN_REQUEST);
        assert_eq!(event.event_id, format!("instance:{id}:pegin-request:0xreq"));
    }

    #[test]
    fn round_messages_are_routed_to_committee_ingest_jobs_only() {
        assert_eq!(
            route_action("PeginConfirmNonce", &Actor::Committee),
            Some(JOB_INGEST_PEGIN_CONFIRM_NONCE)
        );
        assert_eq!(
            route_action("PeginConfirmNonceConsensus", &Actor::Committee),
            Some(JOB_INGEST_PEGIN_CONFIRM_VOTE)
        );
        assert_eq!(
            route_action("PeginConfirmPartialSig", &Actor::Committee),
            Some(JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG)
        );
        for actor in [Actor::Operator, Actor::Verifier, Actor::Watchtower, Actor::All] {
            assert!(!engine_handles("PeginConfirmNonce", &actor), "{actor}");
        }
        assert!(!engine_handles("NonceGeneration", &Actor::Committee));
        for action in INSTANCE_JOBS {
            let phase = job_phase(action);
            let expected = match *action {
                JOB_ANSWER_PEGIN_REQUEST => PHASE_ANSWER,
                JOB_CONFIRM_INSTANCE => PHASE_PRESIGN,
                _ => PHASE_CONFIRM,
            };
            assert_eq!(phase, expected, "{action}");
        }
        assert_eq!(job_phase(JOB_POST_PEGIN_DATA), PHASE_POST);
        assert_eq!(job_phase(JOB_DELETE_INSTANCE_KEY), PHASE_KEY);
    }

    #[test]
    fn plans_round_trip_and_the_round_ends_with_the_confirm() {
        let mut plan = InstancePlan::noted("x");
        plan.send(crate::aggregates::graph::PlannedMessage {
            outbox_id: "instance:i:PeginConfirmNonce".into(),
            phase_ref: PHASE_CONFIRM.into(),
            kind: "PeginConfirmNonce".into(),
            actor: Actor::Committee.to_string(),
            payload: vec![1, 2, 3],
            ack_set: None,
        })
        .then(JOB_PEGIN_CONFIRM_VOTE, Vec::new(), None);
        plan.start_graph = Some(StartGraph { graph_id: Uuid::nil(), operator_pubkey: "op".into() });
        plan.wake_refs.push("graph:x".into());
        assert_eq!(InstancePlan::decode(&plan.encode().unwrap()).unwrap(), plan);
        for status in [RelayerL1Broadcasted, RelayerL2Minted] {
            assert!(confirm_round_over(status), "{status}");
        }
        for status in InstanceBridgeInStatus::FAILED {
            assert!(confirm_round_over(status), "{status}");
        }
        for status in [UserInited, CommitteesAnswered, UserBroadcastPeginPrepare, Presigned] {
            assert!(!confirm_round_over(status), "{status}");
        }
    }

    #[test]
    fn rebroadcast_is_due_only_for_an_invisible_confirm_while_presigned() {
        let mut snap = snapshot(1_050);
        snap.confirm = Some(TxFact::UNKNOWN);
        snap.cancel = Some(TxFact::UNKNOWN);
        let stays = decide(Presigned, &snap);
        assert!(rebroadcast_due(Presigned, &stays, &snap));
        assert!(!rebroadcast_due(UserBroadcastPeginPrepare, &stays, &snap));
        snap.confirm = Some(TxFact::mempool());
        assert!(!rebroadcast_due(Presigned, &decide(Presigned, &snap), &snap));
        snap.confirm = Some(TxFact::confirmed_at(1_049));
        let moves = decide(Presigned, &snap);
        assert_eq!(moves.next, Some(RelayerL1Broadcasted));
        assert!(!rebroadcast_due(Presigned, &moves, &snap));
        snap.confirm = None;
        assert!(!rebroadcast_due(Presigned, &decide(Presigned, &snap), &snap));
    }
}
