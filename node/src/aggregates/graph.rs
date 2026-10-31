//! Graph event handling and coordination.
//!
//! Apply routes messages to validation jobs, waits for missing definitions and
//! commits job plans as outgoing messages, follow-up jobs and state updates.
//! Graph status also receives updates from stored definitions and chain events.

use crate::aggregates::common::{
    EnvelopeProbe, InboundMessage, MembershipProbe, NextJob, PARKED_MESSAGE_TTL_SECS,
    PlannedMessage, instance_failed,
};
use crate::aggregates::graph_fetch::GraphLookup;
use crate::aggregates::graph_pegout::{
    EVENT_CHAIN_SCAN, EVENT_GOAT_STATUS, EVENT_WITHDRAW_CANCEL, EVENT_WITHDRAW_INIT, PEGOUT_JOBS,
    PHASE_KICKOFF, PHASE_SETTLEMENT, pegout_job_pool,
};
use crate::aggregates::instance::graph_endorsed_event;
use crate::aggregates::jobs::Plan;
use crate::engine_bridge::record_event_in;
use crate::metrics_service::node_metrics_state;
use crate::middleware::get_topic_name;
use anyhow::anyhow;
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use engine::{
    AggregateHandler, AggregateRef, ApplyContext, ApplyError, ApplyOutcome, EngineInboxEvent,
    EngineOutboxCloseTarget, EventSource, JOB_RESULT_KIND, JobPool, JobResultEvent,
    JobResultOutcome, JobSpec, NewEvent, OutboxMessage, WaitingFor,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::GraphQuery;
use store::{EngineJobState, GraphStatus, GraphStatusSource};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const GRAPH_KIND: &str = "graph";

pub const EVENT_OPERATOR_START: &str = "operator_start";
pub const EVENT_GRAPH_POSTED: &str = "graph_posted";
pub const EVENT_GRAPH_PULL: &str = "graph_pull";
/// A definition this node pulled was stored (sent to the pulled graph).
pub const EVENT_GRAPH_PULLED: &str = "graph_pulled";
/// The operator's setup was still unfinished at the instance's abandon height.
pub const EVENT_SETUP_ABANDONED: &str = "setup_abandoned";
/// The operator's setup collected its proofs: build the definition once no
/// other build of the operator is in flight.
pub const EVENT_BUILD_READY: &str = "build_ready";

pub const PHASE_SETUP: &str = "Setup";
pub const PHASE_COLLECT: &str = "Collect";
pub const PHASE_SIGNING: &str = "Signing";
pub const PHASE_SIGNED: &str = "Signed";
pub const PHASE_DELIVER: &str = "Deliver";
pub const PHASE_POST: &str = "Post";
pub const PHASE_AWAIT_WITHDRAW: &str = "AwaitWithdraw";
pub const PHASE_CLOSED: &str = "Closed";
pub const PHASE_OBSOLETED: &str = "Obsoleted";
/// Outbox phase of the verifier's endorsement (closes on CommitteePresigned).
pub const PHASE_ENDORSE: &str = "Endorse";
/// Job phase of the setup and signing jobs (everything before the relayer's
/// post); peg-out jobs run in the Kickoff and Settlement phases.
pub const JOB_PHASE: &str = "graph";

pub const JOB_OPERATOR_INIT: &str = "operator_init_graph";
pub const JOB_VERIFIER_SETUP: &str = "verifier_setup";
pub const JOB_INGEST_GEN_CIRCUITS: &str = "ingest_gen_circuits";
pub const JOB_FREEZE_CANDIDATES: &str = "freeze_candidates";
pub const JOB_VERIFIER_SOLDER: &str = "verifier_solder";
pub const JOB_INGEST_SOLDERING_PROOF: &str = "ingest_soldering_proof";
pub const JOB_SEAL_PROOFS: &str = "seal_proofs";
pub const JOB_BUILD_GRAPH: &str = "build_graph";
pub const JOB_VERIFIER_VALIDATE_GRAPH: &str = "verifier_validate_graph";
pub const JOB_COMMITTEE_INGEST_GRAPH: &str = "committee_ingest_graph";
pub const JOB_INGEST_VERIFIER_ENDORSEMENT: &str = "ingest_verifier_endorsement";
pub const JOB_COMMITTEE_NONCES: &str = "committee_nonces";
pub const JOB_INGEST_NONCES: &str = "ingest_nonces";
pub const JOB_COMMITTEE_VOTE: &str = "committee_vote";
pub const JOB_INGEST_VOTE: &str = "ingest_vote";
pub const JOB_COMMITTEE_PRESIGN: &str = "committee_presign";
pub const JOB_INGEST_PRESIGN: &str = "ingest_presign";
pub const JOB_COMMITTEE_ENDORSE: &str = "committee_endorse";
pub const JOB_INGEST_ENDORSEMENT: &str = "ingest_endorsement";
pub const JOB_FINALIZE_GRAPH: &str = "finalize_graph";
pub const JOB_INGEST_FINALIZED: &str = "ingest_finalized";
pub const JOB_POST_GRAPH_DATA: &str = "post_graph_data";
pub const JOB_FETCH_GRAPH: &str = "fetch_graph";

pub const ALL_JOBS: &[&str] = &[
    JOB_OPERATOR_INIT,
    JOB_VERIFIER_SETUP,
    JOB_INGEST_GEN_CIRCUITS,
    JOB_FREEZE_CANDIDATES,
    JOB_VERIFIER_SOLDER,
    JOB_INGEST_SOLDERING_PROOF,
    JOB_SEAL_PROOFS,
    JOB_BUILD_GRAPH,
    JOB_VERIFIER_VALIDATE_GRAPH,
    JOB_COMMITTEE_INGEST_GRAPH,
    JOB_INGEST_VERIFIER_ENDORSEMENT,
    JOB_COMMITTEE_NONCES,
    JOB_INGEST_NONCES,
    JOB_COMMITTEE_VOTE,
    JOB_INGEST_VOTE,
    JOB_COMMITTEE_PRESIGN,
    JOB_INGEST_PRESIGN,
    JOB_COMMITTEE_ENDORSE,
    JOB_INGEST_ENDORSEMENT,
    JOB_FINALIZE_GRAPH,
    JOB_INGEST_FINALIZED,
    JOB_POST_GRAPH_DATA,
    JOB_FETCH_GRAPH,
];

/// CPU-bound jobs share the engine's `J` slots; the rest talk to the chain.
pub fn job_pool(action: &str) -> JobPool {
    if PEGOUT_JOBS.contains(&action) {
        return pegout_job_pool(action);
    }
    match action {
        JOB_VERIFIER_SETUP
        | JOB_VERIFIER_SOLDER
        | JOB_INGEST_SOLDERING_PROOF
        | JOB_BUILD_GRAPH
        | JOB_VERIFIER_VALIDATE_GRAPH
        | JOB_COMMITTEE_INGEST_GRAPH
        | JOB_COMMITTEE_PRESIGN
        | JOB_INGEST_PRESIGN
        | JOB_FINALIZE_GRAPH
        | JOB_INGEST_FINALIZED => JobPool::Cpu,
        _ => JobPool::Network,
    }
}

pub fn graph_ref(graph_id: Uuid) -> AggregateRef {
    AggregateRef::new(GRAPH_KIND, graph_id.to_string())
}

/// Wake reference of an operator slot; waiters are released when a
/// definition for the slot is stored by any path.
pub fn slot_ref(operator_pubkey: &str, graph_nonce: u64) -> String {
    format!("slot:{operator_pubkey}:{graph_nonce}")
}

/// Outbox row id of a message kind of this graph (per recipient for the
/// operator's `CutCircuits`).
pub fn outbox_id(graph_id: Uuid, kind: &str, qualifier: Option<&str>) -> String {
    match qualifier {
        Some(qualifier) => format!("graph:{graph_id}:{kind}:{qualifier}"),
        None => format!("graph:{graph_id}:{kind}"),
    }
}

// ----------------------------------------------------------------- payloads

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorStart {
    pub instance_id: Uuid,
    /// The local operator key: the slot chain the new graph extends.
    pub operator_pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPull {
    pub lookup: GraphLookup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPulled {
    pub instance_id: Uuid,
    pub finalized: bool,
}

/// The Bitcoin height a scan saw at or past the instance's abandon height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupAbandoned {
    pub instance_id: Uuid,
    pub abandon_height: i64,
    pub height: i64,
}

/// Bookkeeping a job learned about the graph.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphStateUpdate {
    pub instance_id: Option<Uuid>,
    pub operator_pubkey: Option<String>,
    pub graph_nonce: Option<u64>,
    pub finalized: Option<bool>,
}

/// What a job decided; the apply commits it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPlan {
    pub messages: Vec<PlannedMessage>,
    pub close_rows: Vec<String>,
    pub next: Vec<NextJob>,
    pub state: GraphStateUpdate,
    pub delete_pending_session: bool,
    pub notify_instance_endorsed: bool,
    pub wake_refs: Vec<String>,
    pub note: Option<String>,
}

impl Plan for GraphPlan {
    fn noted(note: impl Into<String>) -> Self {
        Self { note: Some(note.into()), ..Default::default() }
    }
}

impl GraphPlan {
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
        self.next.push(NextJob { action: action.to_string(), params, delay_secs });
        self
    }
}

/// Opaque aggregate state (JSON in the engine row).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphState {
    pub instance_id: Option<Uuid>,
    pub operator_pubkey: Option<String>,
    pub graph_nonce: Option<u64>,
    #[serde(default)]
    pub finalized: bool,
    /// The operator's live `InitWithdraw` (its Goat tx hash): Kickoff phase.
    #[serde(default)]
    pub withdraw: Option<String>,
    /// Withdraws cancelled on Goat; a late re-apply of their init is ignored.
    #[serde(default)]
    pub retired_withdraws: Vec<String>,
    /// The graph's Pre-Kickoff can never confirm (reported once).
    #[serde(default)]
    pub dead: bool,
    /// The operator gave up its unfinished setup at the abandon height.
    #[serde(default)]
    pub abandoned: bool,
}

impl GraphState {
    fn load(raw: Option<&str>) -> Self {
        raw.and_then(|raw| serde_json::from_str(raw).ok()).unwrap_or_default()
    }

    fn merge(&mut self, update: GraphStateUpdate) {
        if update.instance_id.is_some() {
            self.instance_id = update.instance_id;
        }
        if update.operator_pubkey.is_some() {
            self.operator_pubkey = update.operator_pubkey;
        }
        if update.graph_nonce.is_some() {
            self.graph_nonce = update.graph_nonce;
        }
        if let Some(finalized) = update.finalized {
            self.finalized = finalized;
        }
    }
}

// ------------------------------------------------------------------- routing

/// Message kinds the aggregate takes from the network, and which job ingests
/// them for which role.
pub fn route_action(kind: &str, actor: &Actor) -> Option<&'static str> {
    use Actor::{Committee, Operator, Verifier};
    Some(match (kind, actor) {
        ("InitGraph", Verifier) => JOB_VERIFIER_SETUP,
        ("GenCircuits", Operator) => JOB_INGEST_GEN_CIRCUITS,
        ("CutCircuits", Verifier) => JOB_VERIFIER_SOLDER,
        ("SolderingProofReady", Operator) => JOB_INGEST_SOLDERING_PROOF,
        ("CreateGraph", Verifier) => JOB_VERIFIER_VALIDATE_GRAPH,
        ("CreateGraph", Committee) => JOB_COMMITTEE_INGEST_GRAPH,
        ("VerifierGraphParamsEndorsement", Committee) => JOB_INGEST_VERIFIER_ENDORSEMENT,
        ("NonceGeneration", Committee | Operator) => JOB_INGEST_NONCES,
        ("AggNonceConsensus", Committee) => JOB_INGEST_VOTE,
        ("CommitteePresign", Committee | Operator) => JOB_INGEST_PRESIGN,
        ("EndorseGraph", Operator) => JOB_INGEST_ENDORSEMENT,
        ("GraphFinalize", _) => JOB_INGEST_FINALIZED,
        _ => return None,
    })
}

/// Whether this role takes `kind` through the engine at all.
pub fn engine_handles(kind: &str, actor: &Actor) -> bool {
    route_action(kind, actor).is_some()
}

/// Heavy messages are ACKed once durably recorded.
pub fn ack_required(kind: &str) -> bool {
    matches!(
        kind,
        "GenCircuits" | "CutCircuits" | "SolderingProofReady" | "CreateGraph" | "GraphFinalize"
    )
}

pub fn operator_start_event(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_pubkey: &str,
) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("graph:{graph_id}:operator-start"),
        graph_ref(graph_id),
        EVENT_OPERATOR_START,
        EventSource::Local,
        bincode::serialize(&OperatorStart {
            instance_id,
            operator_pubkey: operator_pubkey.to_string(),
        })?,
    ))
}

/// Create the event that requests serialized graph building.
pub fn build_ready_event(graph_id: Uuid) -> NewEvent {
    NewEvent::new(
        format!("graph:{graph_id}:build-ready"),
        graph_ref(graph_id),
        EVENT_BUILD_READY,
        EventSource::Local,
        Vec::new(),
    )
}

/// Keyed by height, not only by graph: a graph whose build lands after its
/// session was released is still given up on a later block.
pub fn setup_abandoned_event(
    graph_id: Uuid,
    abandoned: &SetupAbandoned,
) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("graph:{graph_id}:abandon:{}", abandoned.height),
        graph_ref(graph_id),
        EVENT_SETUP_ABANDONED,
        EventSource::Height,
        bincode::serialize(abandoned)?,
    ))
}

/// A pull stored this graph's definition; the graph's own apply decides what
/// follows (the relayer's post for a finalized one).
pub fn graph_pulled_event(
    graph_id: Uuid,
    instance_id: Uuid,
    finalized: bool,
) -> anyhow::Result<NewEvent> {
    let flavour = if finalized { "finalized" } else { "presigned" };
    Ok(NewEvent::new(
        format!("graph:{graph_id}:pulled:{flavour}"),
        graph_ref(graph_id),
        EVENT_GRAPH_PULLED,
        EventSource::Local,
        bincode::serialize(&GraphPulled { instance_id, finalized })?,
    ))
}

pub fn graph_posted_event(graph_id: Uuid) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("graph:{graph_id}:posted"),
        graph_ref(graph_id),
        EVENT_GRAPH_POSTED,
        EventSource::Chain,
        Vec::new(),
    ))
}

/// Ask the aggregate to pull a definition this node lacks.
pub fn graph_pull_event(graph_id: Uuid, lookup: GraphLookup) -> anyhow::Result<NewEvent> {
    let key = match &lookup {
        GraphLookup::Id { finalized: false, .. } => "id".to_string(),
        GraphLookup::Id { finalized: true, .. } => "finalized".to_string(),
        GraphLookup::Slot { operator_pubkey, graph_nonce } => {
            format!("slot:{operator_pubkey}:{graph_nonce}")
        }
    };
    Ok(NewEvent::new(
        format!("graph:{graph_id}:pull:{key}"),
        graph_ref(graph_id),
        EVENT_GRAPH_PULL,
        EventSource::Local,
        bincode::serialize(&GraphPull { lookup })?,
    ))
}

// -------------------------------------------------------------------- phases

/// Choose the local phase from graph status, node role and live withdrawal state.
pub fn phase_of(
    status: Option<GraphStatus>,
    actor: &Actor,
    relayer: bool,
    withdrawing: bool,
) -> &'static str {
    use GraphStatus::*;
    match status {
        None => PHASE_SETUP,
        Some(OperatorPresigned) => match actor {
            Actor::Operator => PHASE_COLLECT,
            Actor::Committee => PHASE_SIGNING,
            _ => PHASE_SETUP,
        },
        Some(CommitteePresigned) => match actor {
            Actor::Operator => PHASE_DELIVER,
            _ if relayer => PHASE_POST,
            _ => PHASE_SIGNED,
        },
        Some(OperatorDataPushed) if withdrawing => PHASE_KICKOFF,
        Some(OperatorDataPushed) => PHASE_AWAIT_WITHDRAW,
        Some(PreKickoff) => PHASE_KICKOFF,
        Some(OperatorKickOff | Challenge) => PHASE_SETTLEMENT,
        Some(Obsoleted) => PHASE_OBSOLETED,
        Some(Skipped | Disprove | OperatorTake1 | OperatorTake2) => PHASE_CLOSED,
    }
}

/// Whether committee round messages and deliveries are no longer needed.
pub fn signing_round_over(status: Option<GraphStatus>) -> bool {
    status.is_some_and(|status| !matches!(status, GraphStatus::OperatorPresigned))
}

/// Past the signing phases (posted, obsoleted or skipped): every delivery
/// of the graph is closed.
pub fn past_signing(status: Option<GraphStatus>) -> bool {
    status.is_some_and(|status| {
        !matches!(status, GraphStatus::OperatorPresigned | GraphStatus::CommitteePresigned)
    })
}

/// Whether setup and deliveries should stop. Peg-out work may still be needed
/// for chain monitoring or Goat settlement.
pub fn retired(status: Option<GraphStatus>) -> bool {
    status.is_some_and(|status| status.is_obsoleted() || status.is_closed())
}

// ------------------------------------------------------------------- handler

pub struct GraphAggregate {
    actor: Actor,
    relayer: bool,
    local_peer: String,
    membership: Arc<dyn MembershipProbe>,
    /// The local operator key as stored in `graph.operator_pubkey`.
    local_operator: Option<String>,
}

impl GraphAggregate {
    pub fn new(actor: Actor, relayer: bool, local_peer: String) -> Self {
        Self {
            actor,
            relayer,
            local_peer,
            membership: Arc::new(EnvelopeProbe),
            local_operator: None,
        }
    }

    pub fn with_membership(mut self, membership: Arc<dyn MembershipProbe>) -> Self {
        self.membership = membership;
        self
    }

    /// The operator key whose graphs this node withdraws and defends.
    pub fn with_local_operator(mut self, operator_pubkey: Option<String>) -> Self {
        self.local_operator = operator_pubkey;
        self
    }

    pub(super) fn actor(&self) -> Actor {
        self.actor.clone()
    }

    pub(super) fn relayer(&self) -> bool {
        self.relayer
    }

    /// The graph belongs to this node's operator.
    pub(super) fn owns(&self, row: &store::Graph) -> bool {
        self.actor == Actor::Operator
            && self.local_operator.as_deref() == Some(row.operator_pubkey.as_str())
    }

    /// Wait for a missing definition, scheduling a fetch only for registered authors.
    /// Reject the message if its instance failed or its waiting deadline elapsed.
    async fn park_for_definition(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        inbound: &InboundMessage,
        created_at: i64,
        lookup: GraphLookup,
        waiting: WaitingFor,
    ) -> anyhow::Result<ApplyOutcome> {
        if instance_failed(ctx, inbound.instance_id).await? {
            debug!(event = "graph_apply", graph_id = %graph_id, detail = %waiting.detail, "instance failed; message ignored");
            return Ok(ApplyOutcome::Applied);
        }
        let waited = ctx.now - created_at;
        if waited > PARKED_MESSAGE_TTL_SECS {
            return Ok(ApplyOutcome::Rejected(format!(
                "waited {waited}s for the {}; giving up",
                waiting.detail
            )));
        }
        if self.membership.is_registered_peer(&inbound.author) {
            let params = bincode::serialize(&lookup)
                .map_err(|error| anyhow!("encode graph lookup: {error}"))?;
            self.enqueue_setup_job(ctx, JOB_FETCH_GRAPH, &params);
        } else {
            debug!(event = "graph_apply", graph_id = %graph_id, author = %inbound.author, detail = %waiting.detail, "author is not a registered peer; waiting without a pull");
        }
        Ok(ApplyOutcome::Waiting(waiting))
    }

    fn enqueue_setup_job(&self, ctx: &mut ApplyContext<'_>, action: &str, payload: &[u8]) {
        ctx.effects.enqueue_job(JobSpec::new(
            &ctx.aggregate,
            JOB_PHASE,
            action,
            job_pool(action),
            payload.to_vec(),
        ));
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_message(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &mut GraphState,
        status: Option<GraphStatus>,
        kind: &str,
        payload: &[u8],
        created_at: i64,
    ) -> anyhow::Result<ApplyOutcome> {
        let inbound = match InboundMessage::decode(payload) {
            Ok(inbound) => inbound,
            Err(error) => {
                return Ok(ApplyOutcome::Rejected(format!("malformed {kind} event: {error}")));
            }
        };
        if inbound.author == self.local_peer {
            return Ok(ApplyOutcome::Applied);
        }
        let Some(action) = route_action(kind, &self.actor) else {
            return Ok(ApplyOutcome::Rejected(format!("{kind} is not handled by {}", self.actor)));
        };
        // A committee node outside the instance's committee neither signs
        // nor waits for the graph; the finalized definition is still taken.
        if self.actor == Actor::Committee
            && kind != "GraphFinalize"
            && !self.membership.holds_instance_key(inbound.instance_id)
        {
            debug!(event = "graph_apply", graph_id = %graph_id, kind, instance_id = %inbound.instance_id, "not in this instance's committee; message ignored");
            return Ok(ApplyOutcome::Applied);
        }
        if retired(status) {
            debug!(event = "graph_apply", graph_id = %graph_id, kind, "graph retired; message ignored");
            return Ok(ApplyOutcome::Applied);
        }
        if state.instance_id.is_none() {
            state.instance_id = Some(inbound.instance_id);
        }
        if state.operator_pubkey.is_none() {
            state.operator_pubkey = inbound.operator_pubkey.clone();
        }
        if state.graph_nonce.is_none() {
            state.graph_nonce = inbound.graph_nonce;
        }
        match kind {
            "InitGraph" => {
                if status.is_some() {
                    return Ok(ApplyOutcome::Applied);
                }
            }
            "GenCircuits" | "SolderingProofReady" => {
                let pending = ctx.storage.find_pending_graph_init_by_graph_id(&graph_id).await?;
                if pending.is_none_or(|pending| pending.instance_id != inbound.instance_id) {
                    debug!(event = "graph_apply", graph_id = %graph_id, kind, "no pending setup session; message ignored");
                    return Ok(ApplyOutcome::Applied);
                }
            }
            "CutCircuits" => {}
            "CreateGraph" => {
                if self.actor == Actor::Committee
                    && let (Some(operator_pubkey), Some(graph_nonce)) =
                        (inbound.operator_pubkey.as_deref(), inbound.graph_nonce)
                {
                    // One definition per slot.
                    if let Some(existing) = ctx
                        .storage
                        .find_graph_by_operator_slot(operator_pubkey, graph_nonce as i64)
                        .await?
                        && existing.graph_id != graph_id
                    {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "slot {operator_pubkey}:{graph_nonce} already holds graph {}",
                            existing.graph_id
                        )));
                    }
                    // Continuity needs the previous slot's definition; pull it
                    // and wait instead of refusing or retrying blindly.
                    if graph_nonce > 0
                        && ctx
                            .storage
                            .find_graph_by_operator_slot(operator_pubkey, graph_nonce as i64 - 1)
                            .await?
                            .is_none()
                    {
                        let lookup = GraphLookup::Slot {
                            operator_pubkey: operator_pubkey.to_string(),
                            graph_nonce: graph_nonce - 1,
                        };
                        let waiting = WaitingFor::on_ref(
                            slot_ref(operator_pubkey, graph_nonce - 1),
                            format!("previous graph definition for slot {graph_nonce}"),
                        );
                        return self
                            .park_for_definition(
                                ctx, graph_id, &inbound, created_at, lookup, waiting,
                            )
                            .await;
                    }
                }
            }
            "VerifierGraphParamsEndorsement"
            | "NonceGeneration"
            | "AggNonceConsensus"
            | "CommitteePresign"
            | "EndorseGraph" => {
                if status.is_none() {
                    if self.actor == Actor::Operator {
                        debug!(event = "graph_apply", graph_id = %graph_id, kind, "not a local graph; message ignored");
                        return Ok(ApplyOutcome::Applied);
                    }
                    // The definition may never reach this node by gossip
                    // (it was offline, or missing from the operator's ack
                    // set): pull it while waiting.
                    let lookup = GraphLookup::Id {
                        instance_id: inbound.instance_id,
                        graph_id,
                        finalized: false,
                    };
                    let waiting = WaitingFor::on(&ctx.aggregate, "graph definition not stored yet");
                    return self
                        .park_for_definition(ctx, graph_id, &inbound, created_at, lookup, waiting)
                        .await;
                }
                if signing_round_over(status) {
                    debug!(event = "graph_apply", graph_id = %graph_id, kind, "signing round is over; message ignored");
                    return Ok(ApplyOutcome::Applied);
                }
            }
            "GraphFinalize" => {
                if state.finalized {
                    return Ok(ApplyOutcome::Applied);
                }
            }
            _ => {}
        }
        self.enqueue_setup_job(ctx, action, payload);
        Ok(ApplyOutcome::Applied)
    }

    async fn apply_job_result(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &mut GraphState,
        status: Option<GraphStatus>,
        result: JobResultEvent,
    ) -> anyhow::Result<ApplyOutcome> {
        match &result.outcome {
            JobResultOutcome::Done(bytes) => {
                let mut plan = match GraphPlan::decode(bytes) {
                    Ok(plan) => plan,
                    Err(error) => {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "malformed plan from {}: {error}",
                            result.action
                        )));
                    }
                };
                if let Some(note) = &plan.note {
                    info!(event = "graph_job", graph_id = %graph_id, action = %result.action, stale = result.stale, note = %note, "job note");
                }
                // Drop late setup/post actions for retired graphs, but preserve dependency wakes.
                // Peg-out results may still be needed for settlement.
                if retired(status) && !PEGOUT_JOBS.contains(&result.action.as_str()) {
                    info!(event = "graph_job", graph_id = %graph_id, action = %result.action, status = ?status, "graph retired; plan dropped");
                    plan = GraphPlan { wake_refs: plan.wake_refs, ..Default::default() };
                }
                self.apply_plan(ctx, graph_id, state, plan).await?;
            }
            JobResultOutcome::Failed(error) => {
                warn!(event = "graph_job", graph_id = %graph_id, action = %result.action, error = %error, "job failed");
                if result.action == JOB_POST_GRAPH_DATA
                    && let Some(metrics) = node_metrics_state()
                {
                    metrics.record_instance_alert("post_graph_data_rejected");
                }
                // The builds waiting behind a failed build go on.
                if result.action == JOB_BUILD_GRAPH
                    && let Some(operator_pubkey) = state.operator_pubkey.as_deref()
                {
                    let slot = next_slot(ctx, operator_pubkey).await?;
                    ctx.effects.wake(slot_ref(operator_pubkey, slot));
                }
            }
            JobResultOutcome::Cancelled => {
                debug!(event = "graph_job", graph_id = %graph_id, action = %result.action, "job cancelled");
            }
            JobResultOutcome::Poisoned(error) => {
                warn!(event = "graph_job", graph_id = %graph_id, action = %result.action, error = %error, "job panicked");
            }
        }
        ctx.storage.clear_engine_job_result(&result.job_id, ctx.now).await?;
        Ok(ApplyOutcome::Applied)
    }

    async fn apply_plan(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &mut GraphState,
        plan: GraphPlan,
    ) -> anyhow::Result<()> {
        state.merge(plan.state);
        for message in plan.messages {
            ctx.effects.send(OutboxMessage {
                outbox_id: message.outbox_id,
                phase_ref: message.phase_ref,
                kind: message.kind,
                topic: get_topic_name(&message.actor),
                payload: message.payload,
                ack_set: message.ack_set,
            });
        }
        for row in plan.close_rows {
            ctx.effects.close_outbox(EngineOutboxCloseTarget::Row(row), "superseded");
        }
        for NextJob { action, params, delay_secs } in plan.next {
            if action == JOB_BUILD_GRAPH {
                // Builds of one operator run one at a time.
                record_event_in(ctx.storage, build_ready_event(graph_id)).await?;
                continue;
            }
            let phase = if action == JOB_POST_GRAPH_DATA {
                PHASE_POST
            } else if PEGOUT_JOBS.contains(&action.as_str()) {
                PHASE_SETTLEMENT
            } else {
                JOB_PHASE
            };
            let mut job = JobSpec::new(&ctx.aggregate, phase, &action, job_pool(&action), params);
            if let Some(delay) = delay_secs {
                job = job.with_run_after(ctx.now + delay.max(0));
            }
            ctx.effects.enqueue_job(job);
        }
        if plan.delete_pending_session
            && let (Some(instance_id), Some(operator_pubkey)) =
                (state.instance_id, state.operator_pubkey.as_deref())
        {
            ctx.storage.delete_pending_graph_init(&instance_id, operator_pubkey).await?;
        }
        if plan.notify_instance_endorsed
            && let Some(instance_id) = state.instance_id
        {
            record_event_in(ctx.storage, graph_endorsed_event(instance_id, graph_id)?).await?;
        }
        for wake_ref in plan.wake_refs {
            ctx.effects.wake(wake_ref);
        }
        Ok(())
    }

    /// Start building after proof collection unless this operator has another build
    /// in flight. Wait for that build's slot or session release to avoid slot reuse.
    async fn apply_build_ready(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        row: Option<&store::Graph>,
    ) -> anyhow::Result<ApplyOutcome> {
        if row.is_some() {
            return Ok(ApplyOutcome::Applied);
        }
        let Some(session) = ctx.storage.find_pending_graph_init_by_graph_id(&graph_id).await?
        else {
            debug!(event = "graph_apply", graph_id = %graph_id, "no pending setup session; build dropped");
            return Ok(ApplyOutcome::Applied);
        };
        if instance_failed(ctx, session.instance_id).await? {
            return Ok(ApplyOutcome::Applied);
        }
        if let Some((builder, slot)) =
            building_sibling(ctx, &session.operator_pubkey, graph_id).await?
        {
            return Ok(ApplyOutcome::Waiting(WaitingFor::on_ref(
                slot_ref(&session.operator_pubkey, slot),
                format!("graph {builder} is building slot {slot}"),
            )));
        }
        self.enqueue_setup_job(ctx, JOB_BUILD_GRAPH, &[]);
        Ok(ApplyOutcome::Applied)
    }

    /// Retire unfinished setup at the abandon height and release its pending session,
    /// allowing later setups to proceed. Built graphs without committee signatures
    /// remain available for Skip handling.
    async fn abandon_setup(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &mut GraphState,
        row: Option<&store::Graph>,
        abandoned: &SetupAbandoned,
    ) -> anyhow::Result<ApplyOutcome> {
        if self.actor != Actor::Operator || instance_failed(ctx, abandoned.instance_id).await? {
            return Ok(ApplyOutcome::Applied);
        }
        match row {
            Some(row) => {
                if !self.owns(row) || row.status != GraphStatus::OperatorPresigned.to_string() {
                    return Ok(ApplyOutcome::Applied);
                }
                ctx.storage
                    .transition_graph_status(
                        row.instance_id,
                        graph_id,
                        GraphStatus::Obsoleted,
                        GraphStatusSource::ChainReconcile,
                        None,
                    )
                    .await?;
                // A build whose result has not applied yet still holds the
                // session; the retired graph drops that result, so the session
                // is released here.
                if let Some(session) =
                    ctx.storage.find_pending_graph_init_by_graph_id(&graph_id).await?
                {
                    release_setup_session(ctx, &session, "setup abandoned").await?;
                }
            }
            None => {
                let Some(session) =
                    ctx.storage.find_pending_graph_init_by_graph_id(&graph_id).await?
                else {
                    return Ok(ApplyOutcome::Applied);
                };
                release_setup_session(ctx, &session, "setup abandoned").await?;
            }
        }
        state.abandoned = true;
        warn!(
            event = "graph_abandoned",
            graph_id = %graph_id,
            instance_id = %abandoned.instance_id,
            built = row.is_some(),
            height = abandoned.height,
            abandon_height = abandoned.abandon_height,
            "setup unfinished at the abandon height; given up"
        );
        Ok(ApplyOutcome::Applied)
    }

    /// Mirror graph status and close deliveries for completed or retired phases.
    async fn finish(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &GraphState,
    ) -> anyhow::Result<()> {
        // The apply may have moved the row (a chain scan): mirror what is stored.
        let row = ctx.storage.find_graph(&graph_id).await?;
        let status = row.as_ref().and_then(|row| GraphStatus::from_str(&row.status).ok());
        let previous = ctx.status().to_string();
        let current = status.map(|status| status.to_string()).unwrap_or_default();
        if current != previous {
            // Waiters on the slot re-check: the operator's next build and kickoff.
            if let Some(row) = &row {
                ctx.effects.wake(slot_ref(&row.operator_pubkey, row.kickoff_index as u64));
            }
            if signing_round_over(status) {
                for phase in [PHASE_COLLECT, PHASE_SIGNING, PHASE_ENDORSE, PHASE_SETUP] {
                    ctx.effects.close_outbox(
                        EngineOutboxCloseTarget::Phase {
                            aggregate_kind: GRAPH_KIND.to_string(),
                            aggregate_id: graph_id.to_string(),
                            phase_ref: phase.to_string(),
                        },
                        format!("graph {current}"),
                    );
                }
            }
            if past_signing(status) {
                ctx.effects.close_outbox(
                    EngineOutboxCloseTarget::Aggregate {
                        aggregate_kind: GRAPH_KIND.to_string(),
                        aggregate_id: graph_id.to_string(),
                    },
                    format!("graph {current}"),
                );
                ctx.effects.cancel_phase_jobs(PHASE_POST);
            }
            if retired(status) {
                ctx.effects.cancel_phase_jobs(JOB_PHASE);
            }
            // Taken, disproved or skipped: the slot can no longer be kicked off. Obsoleted
            // alone forbids nothing.
            if status.is_some_and(|status| status.is_closed()) {
                ctx.effects.cancel_phase_jobs(PHASE_KICKOFF);
            }
            info!(event = "graph_transition", graph_id = %graph_id, from = %previous, to = %current, "graph status mirrored");
        }
        let withdrawing = state.withdraw.is_some();
        ctx.effects
            .set_status(current)
            .set_phase(phase_of(status, &self.actor, self.relayer, withdrawing).to_string())
            .set_state(Some(serde_json::to_string(state)?));
        Ok(())
    }
}

#[async_trait]
impl AggregateHandler for GraphAggregate {
    async fn apply(
        &self,
        ctx: &mut ApplyContext<'_>,
        event: &EngineInboxEvent,
    ) -> Result<ApplyOutcome, ApplyError> {
        let graph_id = Uuid::from_str(&ctx.aggregate.id).map_err(|error| {
            ApplyError::invariant(anyhow!("graph aggregate id {}: {error}", ctx.aggregate.id))
        })?;
        let mut state = GraphState::load(ctx.state());
        let row = ctx.storage.find_graph(&graph_id).await?;
        let status = row.as_ref().and_then(|row| GraphStatus::from_str(&row.status).ok());
        if let Some(row) = &row
            && state.instance_id.is_none()
        {
            state.instance_id = Some(row.instance_id);
            state.operator_pubkey = Some(row.operator_pubkey.clone());
            state.graph_nonce = Some(row.kickoff_index as u64);
        }
        let payload = event.payload.as_deref().unwrap_or_default();
        let outcome = match event.kind.as_str() {
            JOB_RESULT_KIND => {
                let result = JobResultEvent::decode(payload).map_err(ApplyError::invariant)?;
                self.apply_job_result(ctx, graph_id, &mut state, status, result).await?
            }
            EVENT_OPERATOR_START => {
                let start: OperatorStart = match bincode::deserialize(payload) {
                    Ok(start) => start,
                    Err(error) => {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "malformed operator_start: {error}"
                        )));
                    }
                };
                if self.actor != Actor::Operator {
                    return Ok(ApplyOutcome::Rejected("only operators start graphs".into()));
                }
                if row.is_some() {
                    // Built already; its deliveries live in the outbox.
                    ApplyOutcome::Applied
                } else if state.abandoned {
                    info!(event = "graph_apply", graph_id = %graph_id, instance_id = %start.instance_id, "instance passed its abandon height before the graph started; start dropped");
                    ApplyOutcome::Applied
                } else if instance_failed(ctx, start.instance_id).await? {
                    ctx.storage
                        .delete_pending_graph_init(&start.instance_id, &start.operator_pubkey)
                        .await?;
                    info!(event = "graph_apply", graph_id = %graph_id, instance_id = %start.instance_id, "instance failed before its graph started; session dropped");
                    ApplyOutcome::Applied
                } else {
                    // Setups of one operator overlap; only their builds are serialized
                    // (`build_ready`), so the previous slot need not be finalized, or even
                    // built, to start.
                    state.instance_id = Some(start.instance_id);
                    state.operator_pubkey = Some(start.operator_pubkey.clone());
                    self.enqueue_setup_job(ctx, JOB_OPERATOR_INIT, payload);
                    ApplyOutcome::Applied
                }
            }
            EVENT_GRAPH_PULLED => {
                let pulled: GraphPulled = match bincode::deserialize(payload) {
                    Ok(pulled) => pulled,
                    Err(error) => {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "malformed graph_pulled: {error}"
                        )));
                    }
                };
                if state.instance_id.is_none() {
                    state.instance_id = Some(pulled.instance_id);
                }
                // Pulled definitions lack EVM endorsements. Keep accepting GraphFinalize for
                // those endorsements, and queue publishing for a finalized, unposted copy.
                if self.relayer && pulled.finalized && !past_signing(status) {
                    ctx.effects.enqueue_job(JobSpec::new(
                        &ctx.aggregate,
                        PHASE_POST,
                        JOB_POST_GRAPH_DATA,
                        job_pool(JOB_POST_GRAPH_DATA),
                        Vec::new(),
                    ));
                }
                ApplyOutcome::Applied
            }
            EVENT_GRAPH_POSTED | EVENT_GOAT_STATUS => {
                // The watcher already wrote the status (OperatorDataPushed or a
                // settlement); mirroring below closes deliveries and wakes the
                // next slot.
                ApplyOutcome::Applied
            }
            EVENT_BUILD_READY => self.apply_build_ready(ctx, graph_id, row.as_ref()).await?,
            EVENT_SETUP_ABANDONED => {
                let abandoned: SetupAbandoned = match bincode::deserialize(payload) {
                    Ok(abandoned) => abandoned,
                    Err(error) => {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "malformed setup_abandoned: {error}"
                        )));
                    }
                };
                self.abandon_setup(ctx, graph_id, &mut state, row.as_ref(), &abandoned).await?
            }
            EVENT_WITHDRAW_INIT => {
                self.apply_withdraw_init(ctx, &mut state, row.as_ref(), payload).await?
            }
            EVENT_WITHDRAW_CANCEL => self.apply_withdraw_cancel(ctx, &mut state),
            EVENT_CHAIN_SCAN => {
                self.apply_chain_scan(ctx, graph_id, &mut state, row.as_ref(), payload).await?
            }
            EVENT_GRAPH_PULL => {
                let pull: GraphPull = match bincode::deserialize(payload) {
                    Ok(pull) => pull,
                    Err(error) => {
                        return Ok(ApplyOutcome::Rejected(format!(
                            "malformed graph_pull: {error}"
                        )));
                    }
                };
                if row.is_none() {
                    let params = bincode::serialize(&pull.lookup)
                        .map_err(|error| anyhow::anyhow!("encode graph lookup: {error}"))?;
                    self.enqueue_setup_job(ctx, JOB_FETCH_GRAPH, &params);
                }
                ApplyOutcome::Applied
            }
            kind => {
                self.apply_message(
                    ctx,
                    graph_id,
                    &mut state,
                    status,
                    kind,
                    payload,
                    event.created_at,
                )
                .await?
            }
        };
        if matches!(outcome, ApplyOutcome::Applied | ApplyOutcome::Waiting(_)) {
            self.finish(ctx, graph_id, &state).await?;
        }
        Ok(outcome)
    }
}

/// The operator's graph holding the highest slot, if any.
async fn latest_slot(
    ctx: &mut ApplyContext<'_>,
    operator_pubkey: &str,
) -> anyhow::Result<Option<store::Graph>> {
    Ok(ctx
        .storage
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?
        .pop())
}

/// The slot the operator's next graph takes: one past the highest stored.
pub(crate) async fn next_slot(
    ctx: &mut ApplyContext<'_>,
    operator_pubkey: &str,
) -> anyhow::Result<u64> {
    Ok(latest_slot(ctx, operator_pubkey)
        .await?
        .map(|graph| graph.kickoff_index as u64 + 1)
        .unwrap_or(0))
}

/// Close a setup session that never stored its definition: its deliveries
/// and jobs go, the session goes, and the slot it was taking is released to
/// the starts waiting on it. Returns that slot.
pub(crate) async fn release_setup_session(
    ctx: &mut ApplyContext<'_>,
    session: &store::PendingGraphInit,
    reason: &str,
) -> anyhow::Result<u64> {
    let graph_ref = graph_ref(session.graph_id);
    ctx.effects.close_outbox(
        EngineOutboxCloseTarget::Aggregate {
            aggregate_kind: graph_ref.kind.clone(),
            aggregate_id: graph_ref.id.clone(),
        },
        reason,
    );
    ctx.effects.cancel_jobs_for_aggregate(&graph_ref);
    ctx.storage.delete_pending_graph_init(&session.instance_id, &session.operator_pubkey).await?;
    let next_slot = next_slot(ctx, &session.operator_pubkey).await?;
    ctx.effects.wake(slot_ref(&session.operator_pubkey, next_slot));
    Ok(next_slot)
}

/// Another session of the operator whose `build_graph` is pending or running
/// and whose definition is not stored yet, with the slot it will take. A
/// session whose instance failed holds nothing: the instance's failure
/// removes it and cancels its build.
async fn building_sibling(
    ctx: &mut ApplyContext<'_>,
    operator_pubkey: &str,
    graph_id: Uuid,
) -> anyhow::Result<Option<(Uuid, u64)>> {
    let sessions = ctx.storage.list_pending_graph_inits_by_operator(operator_pubkey).await?;
    for session in sessions {
        if session.graph_id == graph_id
            || ctx.storage.find_graph(&session.graph_id).await?.is_some()
            || instance_failed(ctx, session.instance_id).await?
        {
            continue;
        }
        let building = ctx
            .storage
            .list_engine_jobs_for_aggregate(GRAPH_KIND, &session.graph_id.to_string())
            .await?
            .into_iter()
            .any(|job| {
                job.action == JOB_BUILD_GRAPH
                    && (job.state == EngineJobState::Pending.to_string()
                        || job.state == EngineJobState::Running.to_string())
            });
        if building {
            return Ok(Some((session.graph_id, next_slot(ctx, operator_pubkey).await?)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use GraphStatus::*;
    use std::collections::BTreeMap;

    #[test]
    fn routes_follow_the_role_table() {
        assert_eq!(route_action("InitGraph", &Actor::Verifier), Some(JOB_VERIFIER_SETUP));
        assert_eq!(route_action("InitGraph", &Actor::Committee), None);
        assert_eq!(route_action("GenCircuits", &Actor::Operator), Some(JOB_INGEST_GEN_CIRCUITS));
        assert_eq!(
            route_action("CreateGraph", &Actor::Verifier),
            Some(JOB_VERIFIER_VALIDATE_GRAPH)
        );
        assert_eq!(
            route_action("CreateGraph", &Actor::Committee),
            Some(JOB_COMMITTEE_INGEST_GRAPH)
        );
        assert_eq!(route_action("CreateGraph", &Actor::Operator), None);
        assert_eq!(route_action("NonceGeneration", &Actor::Operator), Some(JOB_INGEST_NONCES));
        assert_eq!(route_action("AggNonceConsensus", &Actor::Operator), None);
        assert_eq!(route_action("EndorseGraph", &Actor::Committee), None);
        assert_eq!(route_action("GraphFinalize", &Actor::Watchtower), Some(JOB_INGEST_FINALIZED));
        assert_eq!(route_action("PeginConfirmNonce", &Actor::Committee), None);
        for kind in
            ["GenCircuits", "CutCircuits", "SolderingProofReady", "CreateGraph", "GraphFinalize"]
        {
            assert!(ack_required(kind), "{kind}");
        }
        assert!(!ack_required("NonceGeneration") && !ack_required("InitGraph"));
    }

    #[test]
    fn phases_follow_the_phase_table() {
        let phase = |status, actor: &Actor, relayer| phase_of(status, actor, relayer, false);
        assert_eq!(phase(None, &Actor::Operator, false), PHASE_SETUP);
        assert_eq!(phase(Some(OperatorPresigned), &Actor::Operator, false), PHASE_COLLECT);
        assert_eq!(phase(Some(OperatorPresigned), &Actor::Committee, false), PHASE_SIGNING);
        assert_eq!(phase(Some(OperatorPresigned), &Actor::Verifier, false), PHASE_SETUP);
        assert_eq!(phase(Some(CommitteePresigned), &Actor::Operator, false), PHASE_DELIVER);
        assert_eq!(phase(Some(CommitteePresigned), &Actor::Committee, true), PHASE_POST);
        assert_eq!(phase(Some(CommitteePresigned), &Actor::Committee, false), PHASE_SIGNED);
        assert_eq!(phase(Some(OperatorDataPushed), &Actor::Operator, false), PHASE_AWAIT_WITHDRAW);
        assert_eq!(
            phase_of(Some(OperatorDataPushed), &Actor::Operator, false, true),
            PHASE_KICKOFF
        );
        assert_eq!(phase(Some(PreKickoff), &Actor::Verifier, false), PHASE_KICKOFF);
        assert_eq!(phase(Some(OperatorKickOff), &Actor::Operator, false), PHASE_SETTLEMENT);
        assert_eq!(phase(Some(Challenge), &Actor::Committee, true), PHASE_SETTLEMENT);
        assert_eq!(phase(Some(Obsoleted), &Actor::Operator, false), PHASE_OBSOLETED);
        assert_eq!(phase(Some(Skipped), &Actor::Operator, false), PHASE_CLOSED);
        assert!(!signing_round_over(Some(OperatorPresigned)) && !signing_round_over(None));
        assert!(
            signing_round_over(Some(CommitteePresigned)) && signing_round_over(Some(Obsoleted))
        );
        assert!(!past_signing(Some(CommitteePresigned)) && past_signing(Some(OperatorDataPushed)));
        assert!(
            retired(Some(Obsoleted)) && retired(Some(OperatorTake1)) && !retired(Some(PreKickoff))
        );
    }

    #[test]
    fn plans_and_state_round_trip() {
        let mut plan = GraphPlan::noted("x");
        plan.send(PlannedMessage {
            outbox_id: "o".into(),
            phase_ref: PHASE_SETUP.into(),
            kind: "InitGraph".into(),
            actor: "Verifier".into(),
            payload: vec![1, 2, 3],
            ack_set: Some(BTreeMap::from([("p".to_string(), "d".to_string())])),
        })
        .then(JOB_FREEZE_CANDIDATES, vec![7], Some(15));
        plan.state.graph_nonce = Some(2);
        let decoded = GraphPlan::decode(&plan.encode().unwrap()).unwrap();
        assert_eq!(decoded, plan);
        let mut state = GraphState::default();
        state.merge(decoded.state);
        assert_eq!(state.graph_nonce, Some(2));
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(GraphState::load(Some(&json)), state);
        assert_eq!(GraphState::load(Some("garbage")), GraphState::default());
        assert_eq!(
            outbox_id(Uuid::nil(), "CutCircuits", Some("k")),
            format!("graph:{}:CutCircuits:k", Uuid::nil())
        );
        assert_eq!(slot_ref("op", 3), "slot:op:3");
    }
}
