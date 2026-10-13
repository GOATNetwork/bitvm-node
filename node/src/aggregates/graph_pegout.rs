//! Graph withdraw and settlement decisions.
//!
//! Withdraw events, chain scans and Goat settlement events update graph state
//! and schedule jobs for this node's role. Kickoff waits for the previous slot
//! to settle; earlier slots are skipped only when the collected facts allow it.

use super::graph::{GraphAggregate, GraphState, slot_ref};
use super::graph_fetch::GraphLookup;
use super::instance::TxFact;
use crate::metrics_service::node_metrics_state;
use anyhow::anyhow;
use bitcoin::{OutPoint, Txid};
use bitvm_lib::actors::Actor;
use client::goat_chain::DisproveTxType;
use engine::{ApplyContext, ApplyOutcome, EventSource, JobPool, JobSpec, NewEvent, WaitingFor};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use store::{Graph, GraphStatus, GraphStatusSource, GraphStatusTransitionOutcome};
use store::{InstanceBridgeInStatus, localdb::GraphRuntimeUpdate};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const EVENT_WITHDRAW_INIT: &str = "withdraw_init";
pub const EVENT_WITHDRAW_CANCEL: &str = "withdraw_cancel";
pub const EVENT_CHAIN_SCAN: &str = "chain_scan";
/// A Goat settlement event changed the status; the aggregate mirrors it.
pub const EVENT_GOAT_STATUS: &str = "goat_status";

/// Job phase of the operator's withdraw: cancelled by `CancelWithdraw`.
pub const PHASE_KICKOFF: &str = "Kickoff";
/// Job phase of everything the chain scan triggers.
pub const PHASE_SETTLEMENT: &str = "Settlement";

// Kickoff (operator).
pub const JOB_KICKOFF: &str = "kickoff";
pub const JOB_SETTLE_PREDECESSORS: &str = "settle_predecessors";
// Settlement, by the signal that triggers them.
pub const JOB_CHECK_PREVIOUS_GRAPH: &str = "check_previous_graph";
pub const JOB_PROCEED_WITHDRAW: &str = "proceed_withdraw";
pub const JOB_CHALLENGE_KICKOFF: &str = "challenge_kickoff";
pub const JOB_WATCHTOWER_CHALLENGE_INIT: &str = "watchtower_challenge_init";
pub const JOB_WATCHTOWER_CHALLENGE: &str = "watchtower_challenge";
pub const JOB_WATCHTOWER_PROOF_TIMEOUT: &str = "watchtower_proof_timeout";
pub const JOB_CHALLENGE_ACK: &str = "challenge_ack";
pub const JOB_WATCHTOWER_TIMEOUT: &str = "watchtower_timeout";
pub const JOB_CHALLENGE_NACK: &str = "challenge_nack";
pub const JOB_COMMIT_PUBIN: &str = "commit_pubin";
pub const JOB_COMMIT_TIMEOUT: &str = "commit_timeout";
pub const JOB_PROVER_ASSERT: &str = "prover_assert";
pub const JOB_VERIFIER_ASSERT: &str = "verifier_assert";
pub const JOB_WRONGLY_CHALLENGED: &str = "wrongly_challenged";
pub const JOB_DISPROVE: &str = "disprove";
pub const JOB_FINISH_DISPROVED: &str = "finish_disproved";
pub const JOB_TAKE1: &str = "take1";
pub const JOB_FINISH_HAPPY: &str = "finish_happy";
pub const JOB_TAKE2: &str = "take2";
pub const JOB_FINISH_UNHAPPY: &str = "finish_unhappy";

pub const PEGOUT_JOBS: &[&str] = &[
    JOB_KICKOFF,
    JOB_SETTLE_PREDECESSORS,
    JOB_CHECK_PREVIOUS_GRAPH,
    JOB_PROCEED_WITHDRAW,
    JOB_CHALLENGE_KICKOFF,
    JOB_WATCHTOWER_CHALLENGE_INIT,
    JOB_WATCHTOWER_CHALLENGE,
    JOB_WATCHTOWER_PROOF_TIMEOUT,
    JOB_CHALLENGE_ACK,
    JOB_WATCHTOWER_TIMEOUT,
    JOB_CHALLENGE_NACK,
    JOB_COMMIT_PUBIN,
    JOB_COMMIT_TIMEOUT,
    JOB_PROVER_ASSERT,
    JOB_VERIFIER_ASSERT,
    JOB_WRONGLY_CHALLENGED,
    JOB_DISPROVE,
    JOB_FINISH_DISPROVED,
    JOB_TAKE1,
    JOB_FINISH_HAPPY,
    JOB_TAKE2,
    JOB_FINISH_UNHAPPY,
];

/// WOTS and garbled-circuit work runs on the peg-out slots, apart from the
/// setup's CPU slots: a graph build takes hours, a challenge answers a
/// timelock. The rest broadcasts or calls Goat.
pub fn pegout_job_pool(action: &str) -> JobPool {
    match action {
        JOB_WATCHTOWER_CHALLENGE
        | JOB_COMMIT_PUBIN
        | JOB_PROVER_ASSERT
        | JOB_VERIFIER_ASSERT
        | JOB_WRONGLY_CHALLENGED => JobPool::Pegout,
        _ => JobPool::Network,
    }
}

// ----------------------------------------------------------------- payloads

/// `InitWithdraw` / `CancelWithdraw` on Goat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawEvent {
    pub instance_id: Uuid,
    pub tx_hash: String,
}

/// Params of the operator's kickoff jobs: the withdraw they serve, so a new
/// `InitWithdraw` after a cancel gets fresh jobs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KickoffParams {
    pub tx_hash: String,
}

/// Chain signals mapped to role-specific jobs with stable IDs for deduplication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PegoutSignal {
    /// Pre-Kickoff of the graph is on chain.
    PreKickoffSent,
    /// Kickoff of the graph is on chain.
    KickoffSent,
    Take1Ready,
    Take1Sent,
    ChallengeSent {
        challenge_txid: Txid,
    },
    WatchtowerChallengeInitSent,
    WatchtowerChallengeSent {
        watchtower_index: usize,
    },
    WatchtowerChallengeTimeout,
    NackReady,
    OperatorCommitPubinReady,
    OperatorCommitPubinTimeout,
    AssertReady,
    AssertSent {
        assert_txid: Txid,
    },
    ChallengeAssertSent {
        challenge_assert_txid: Txid,
        verifier_index: usize,
    },
    WronglyChallengeTimeout {
        challenge_assert_txid: Txid,
        verifier_index: usize,
    },
    DisproveSent {
        disprove_type: DisproveTxType,
        index: usize,
        challenge_start_txid: Option<Txid>,
        challenge_finish_txid: Txid,
    },
    Take2Ready,
    Take2Sent,
}

impl PegoutSignal {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// A chain fact that makes the graph unusable before its Pre-Kickoff confirms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unusable {
    /// Connector-0 was spent by another graph's Take-1 / Take-2.
    ConnectorZeroTaken { spent_by: Txid },
    /// An input of this graph's Pre-Kickoff was spent by another transaction
    /// (Challenge-Incomplete-Kickoff or another Pre-Kickoff): it can never
    /// confirm, and neither can any later slot of the operator.
    PrekickoffInputSpent { outpoint: OutPoint, spent_by: Txid },
    /// That happened to an earlier slot of the operator, which this graph's
    /// Pre-Kickoff extends.
    EarlierSlotDead { slot: u64 },
}

/// One scan of a graph at a Bitcoin height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainScan {
    pub height: i64,
    /// The persisted status the scan saw; part of the event id.
    pub status_at_scan: String,
    /// The stage both chains show; never `Obsoleted`.
    pub stage: GraphStatus,
    /// Challenge progress (`ChallengeSubStatus` JSON).
    pub sub_status: Option<String>,
    pub challenge_txid: Option<Txid>,
    pub unusable: Option<Unusable>,
    pub signals: Vec<PegoutSignal>,
}

impl ChainScan {
    /// One event per graph, height and status seen: a rescan at the same tip
    /// is deduplicated, a scan after a status change is not.
    pub fn event(&self, graph_id: Uuid) -> anyhow::Result<NewEvent> {
        Ok(NewEvent::new(
            format!("graph:{graph_id}:scan:{}:{}", self.height, self.status_at_scan),
            super::graph::graph_ref(graph_id),
            EVENT_CHAIN_SCAN,
            EventSource::Height,
            serde_json::to_vec(self)?,
        ))
    }
}

pub fn withdraw_init_event(
    instance_id: Uuid,
    graph_id: Uuid,
    tx_hash: &str,
) -> anyhow::Result<NewEvent> {
    withdraw_event(EVENT_WITHDRAW_INIT, "withdraw-init", instance_id, graph_id, tx_hash)
}

pub fn withdraw_cancel_event(
    instance_id: Uuid,
    graph_id: Uuid,
    tx_hash: &str,
) -> anyhow::Result<NewEvent> {
    withdraw_event(EVENT_WITHDRAW_CANCEL, "withdraw-cancel", instance_id, graph_id, tx_hash)
}

fn withdraw_event(
    kind: &str,
    key: &str,
    instance_id: Uuid,
    graph_id: Uuid,
    tx_hash: &str,
) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("graph:{graph_id}:{key}:{tx_hash}"),
        super::graph::graph_ref(graph_id),
        kind,
        EventSource::Chain,
        serde_json::to_vec(&WithdrawEvent { instance_id, tx_hash: tx_hash.to_string() })?,
    ))
}

/// A Goat settlement event moved the graph's status.
pub fn goat_status_event(
    graph_id: Uuid,
    status: GraphStatus,
    tx_hash: &str,
) -> anyhow::Result<NewEvent> {
    Ok(NewEvent::new(
        format!("graph:{graph_id}:goat:{status}:{tx_hash}"),
        super::graph::graph_ref(graph_id),
        EVENT_GOAT_STATUS,
        EventSource::Chain,
        Vec::new(),
    ))
}

// ------------------------------------------------------------------ routing

/// The job this role runs for a signal; `own` is whether the graph belongs
/// to the local operator.
pub fn route_signal(
    signal: &PegoutSignal,
    actor: &Actor,
    relayer: bool,
    own: bool,
) -> Option<&'static str> {
    use Actor::{Committee, Operator, Verifier, Watchtower};
    use PegoutSignal::*;
    Some(match (signal, actor) {
        (PreKickoffSent, Verifier) => JOB_CHECK_PREVIOUS_GRAPH,
        (KickoffSent, Committee) if relayer => JOB_PROCEED_WITHDRAW,
        (KickoffSent, Verifier) => JOB_CHALLENGE_KICKOFF,
        (ChallengeSent { .. }, Operator) if own => JOB_WATCHTOWER_CHALLENGE_INIT,
        (WatchtowerChallengeInitSent, Watchtower) => JOB_WATCHTOWER_CHALLENGE,
        (AssertSent { .. }, Watchtower) => JOB_WATCHTOWER_PROOF_TIMEOUT,
        (WatchtowerChallengeSent { .. }, Operator) if own => JOB_CHALLENGE_ACK,
        (WatchtowerChallengeTimeout, Operator) if own => JOB_WATCHTOWER_TIMEOUT,
        (NackReady, Verifier) => JOB_CHALLENGE_NACK,
        (OperatorCommitPubinReady, Operator) if own => JOB_COMMIT_PUBIN,
        (OperatorCommitPubinTimeout, Verifier) => JOB_COMMIT_TIMEOUT,
        (AssertReady, Operator) if own => JOB_PROVER_ASSERT,
        (AssertSent { .. }, Verifier) => JOB_VERIFIER_ASSERT,
        (ChallengeAssertSent { .. }, Operator) if own => JOB_WRONGLY_CHALLENGED,
        (WronglyChallengeTimeout { .. }, Verifier) => JOB_DISPROVE,
        (DisproveSent { .. }, Committee) if relayer => JOB_FINISH_DISPROVED,
        (Take1Ready, Operator) if own => JOB_TAKE1,
        (Take1Sent, Committee) if relayer => JOB_FINISH_HAPPY,
        (Take2Ready, Operator) if own => JOB_TAKE2,
        (Take2Sent, Committee) if relayer => JOB_FINISH_UNHAPPY,
        _ => return None,
    })
}

// ---------------------------------------------------------------- decisions

/// Derive status from chain progress. Confirmed Pre-Kickoff or later progress takes
/// precedence over local Obsoleted state. Before that, unusable graphs or unposted
/// graphs belonging to failed instances become Obsoleted.
pub fn decide_status(scan: &ChainScan, instance_failed: bool) -> Option<GraphStatus> {
    use GraphStatus::*;
    match scan.stage {
        PreKickoff | OperatorKickOff | Challenge | Disprove | OperatorTake1 | OperatorTake2
        | Skipped => Some(scan.stage),
        _ if scan.unusable.is_some() => Some(Obsoleted),
        OperatorDataPushed => Some(OperatorDataPushed),
        OperatorPresigned | CommitteePresigned if instance_failed => Some(Obsoleted),
        OperatorPresigned | CommitteePresigned | Obsoleted => None,
    }
}

/// How a Kickoff Connector was spent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KickoffConnector {
    /// Unspent, or its Pre-Kickoff is not on chain.
    #[default]
    Unspent,
    ByKickoff,
    /// Skip-Kickoff or Force-Skip-Kickoff.
    ByOther,
}

/// The local copy of a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSlot {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub status: GraphStatus,
    /// Carries committee pre-signatures.
    pub finalized: bool,
    pub instance_status: Option<InstanceBridgeInStatus>,
}

/// Facts about one slot of an operator's chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotFacts {
    pub slot: u64,
    pub local: Option<LocalSlot>,
    pub kickoff_connector: KickoffConnector,
    /// An input of the slot's Pre-Kickoff was spent by another transaction.
    pub prekickoff_dead: bool,
    /// L2 `GraphData` of the graph is posted.
    pub posted: bool,
    /// Connector-0 was spent by another graph's Take.
    pub connector_zero_taken: bool,
    /// Peg-In-Cancel of the instance is confirmed (Connector-Z spent by Cancel).
    pub cancel_confirmed: bool,
    /// Peg-In-Confirm of the instance.
    pub confirm: TxFact,
    /// The instance passed its abandon height `H_p + T0 + B`: no committee
    /// member signs after `T0`, so an unfinished graph stays unfinished.
    pub past_abandon_height: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotVerdict {
    /// Taken, disproved or skipped.
    Settled,
    /// Fetch the definition first: a missing or unfinalized local copy is
    /// never taken for an abandoned graph.
    Pull(GraphLookup),
    /// Pre-Kickoff + Skip-Kickoff, for the named premise.
    Skip(&'static str),
    /// Live, in peg-out, or undecided: look again later.
    Wait(String),
    /// Never skipped automatically; needs a human.
    Stuck(String),
}

/// Determine whether a slot is settled, skippable or still blocks its successor.
/// Use chain evidence rather than Obsoleted status alone.
pub fn decide_slot(facts: &SlotFacts, operator_pubkey: &str) -> SlotVerdict {
    let slot = facts.slot;
    let Some(local) = &facts.local else {
        return SlotVerdict::Pull(GraphLookup::Slot {
            operator_pubkey: operator_pubkey.to_string(),
            graph_nonce: slot,
        });
    };
    if facts.kickoff_connector == KickoffConnector::ByOther || local.status.is_closed() {
        return SlotVerdict::Settled;
    }
    if facts.kickoff_connector == KickoffConnector::ByKickoff || local.status.is_pegout_started() {
        return SlotVerdict::Wait(format!("slot {slot} is in peg-out"));
    }
    if facts.prekickoff_dead {
        return SlotVerdict::Stuck(format!(
            "Pre-Kickoff of slot {slot} can never confirm: an input is spent elsewhere"
        ));
    }
    if facts.posted {
        if !local.finalized {
            return SlotVerdict::Pull(GraphLookup::Id {
                instance_id: local.instance_id,
                graph_id: local.graph_id,
                finalized: true,
            });
        }
        if facts.connector_zero_taken {
            return SlotVerdict::Skip("connector-0 taken by another graph");
        }
        return SlotVerdict::Wait(format!("slot {slot} is posted and available for withdrawal"));
    }
    if facts.connector_zero_taken {
        return SlotVerdict::Skip("connector-0 taken by another graph");
    }
    if facts.cancel_confirmed {
        return SlotVerdict::Skip("peg-in canceled");
    }
    match local.instance_status {
        Some(status) if status.is_failed() => {
            // Checked again right before the skip: a Peg-In-Confirm that
            // landed after the abandon height keeps the graph.
            if facts.confirm.confirmed {
                SlotVerdict::Stuck(format!(
                    "Peg-In-Confirm of slot {slot} is confirmed although its instance is {status}"
                ))
            } else if facts.confirm.in_mempool {
                SlotVerdict::Wait(format!("Peg-In-Confirm of slot {slot} is in the mempool"))
            } else if status == InstanceBridgeInStatus::Timeout {
                SlotVerdict::Skip("instance timed out")
            } else {
                SlotVerdict::Skip("instance failed")
            }
        }
        // After abandonment, an unfinished graph is skippable. A late finalized
        // definition may have been stored after the row became Obsoleted.
        Some(_)
            if facts.past_abandon_height
                && (!local.finalized || local.status == GraphStatus::Obsoleted) =>
        {
            SlotVerdict::Skip("unfinished at the abandon height")
        }
        Some(status) => SlotVerdict::Wait(format!(
            "slot {slot} ({}) belongs to a live instance ({status})",
            if local.finalized { "finalized" } else { "unfinished" }
        )),
        None => SlotVerdict::Wait(format!("instance of slot {slot} is unknown")),
    }
}

/// Whether the local copy of slot `nonce − 1` is settled.
async fn predecessor_settled(
    ctx: &mut ApplyContext<'_>,
    operator_pubkey: &str,
    graph_nonce: u64,
) -> anyhow::Result<Option<String>> {
    if graph_nonce == 0 {
        return Ok(None);
    }
    let previous =
        ctx.storage.find_graph_by_operator_slot(operator_pubkey, graph_nonce as i64 - 1).await?;
    Ok(match previous {
        Some(previous)
            if GraphStatus::from_str(&previous.status).is_ok_and(|status| status.is_closed()) =>
        {
            None
        }
        Some(previous) => Some(format!(
            "previous slot {} (graph {}) is {}",
            previous.kickoff_index, previous.graph_id, previous.status
        )),
        None => Some(format!("previous slot {} is not stored", graph_nonce - 1)),
    })
}

fn kickoff_job(ctx: &ApplyContext<'_>, action: &str, tx_hash: &str) -> anyhow::Result<JobSpec> {
    Ok(JobSpec::new(
        &ctx.aggregate,
        PHASE_KICKOFF,
        action,
        pegout_job_pool(action),
        serde_json::to_vec(&KickoffParams { tx_hash: tx_hash.to_string() })?,
    ))
}

// ------------------------------------------------------------------- applies

impl GraphAggregate {
    /// `InitWithdraw`: the owning operator kicks off once the previous slot
    /// settled; meanwhile a job settles the earlier slots and the event waits
    /// on the previous slot.
    pub(super) async fn apply_withdraw_init(
        &self,
        ctx: &mut ApplyContext<'_>,
        state: &mut GraphState,
        row: Option<&Graph>,
        payload: &[u8],
    ) -> anyhow::Result<ApplyOutcome> {
        let withdraw: WithdrawEvent = match serde_json::from_slice(payload) {
            Ok(withdraw) => withdraw,
            Err(error) => {
                return Ok(ApplyOutcome::Rejected(format!("malformed withdraw_init: {error}")));
            }
        };
        let Some(row) = row else {
            return Ok(ApplyOutcome::Applied);
        };
        if self.actor() != Actor::Operator || !self.owns(row) {
            return Ok(ApplyOutcome::Applied);
        }
        if state.retired_withdraws.contains(&withdraw.tx_hash) {
            debug!(event = "graph_kickoff", graph_id = %row.graph_id, tx_hash = %withdraw.tx_hash, "withdraw was cancelled; ignored");
            return Ok(ApplyOutcome::Applied);
        }
        let status = GraphStatus::from_str(&row.status).map_err(|error| anyhow!("{error}"))?;
        if status.is_closed() || status.is_pegout_started() {
            state.withdraw = None;
            return Ok(ApplyOutcome::Applied);
        }
        // A new init replaces the active one: Goat accepts it only after the
        // previous withdraw was cancelled, so that cancel was missed. The jobs
        // check the graph's Goat withdraw status, whichever hash they carry.
        if let Some(active) = state.withdraw.take_if(|active| *active != withdraw.tx_hash) {
            for action in [JOB_KICKOFF, JOB_SETTLE_PREDECESSORS] {
                ctx.effects.cancel_job(kickoff_job(ctx, action, &active)?.job_id);
            }
            info!(event = "graph_kickoff", graph_id = %row.graph_id, replaced = %active, tx_hash = %withdraw.tx_hash, "withdraw replaced");
            state.retired_withdraws.push(active);
        }
        state.withdraw = Some(withdraw.tx_hash.clone());
        let graph_nonce = row.kickoff_index as u64;
        let settle = kickoff_job(ctx, JOB_SETTLE_PREDECESSORS, &withdraw.tx_hash)?;
        match predecessor_settled(ctx, &row.operator_pubkey, graph_nonce).await? {
            None => {
                let kickoff = kickoff_job(ctx, JOB_KICKOFF, &withdraw.tx_hash)?;
                ctx.effects.cancel_job(settle.job_id);
                ctx.effects.enqueue_job(kickoff);
                info!(event = "graph_kickoff", graph_id = %row.graph_id, graph_nonce, "previous slot settled; kickoff queued");
                Ok(ApplyOutcome::Applied)
            }
            Some(detail) => {
                ctx.effects.enqueue_job(settle);
                Ok(ApplyOutcome::Waiting(WaitingFor::on_ref(
                    slot_ref(&row.operator_pubkey, graph_nonce - 1),
                    detail,
                )))
            }
        }
    }

    /// `CancelWithdraw`: back to AwaitWithdraw; the kickoff jobs go.
    pub(super) fn apply_withdraw_cancel(
        &self,
        ctx: &mut ApplyContext<'_>,
        state: &mut GraphState,
    ) -> ApplyOutcome {
        if let Some(active) = state.withdraw.take() {
            info!(event = "graph_kickoff", aggregate = %ctx.aggregate, tx_hash = %active, "withdraw cancelled");
            state.retired_withdraws.push(active);
            ctx.effects.cancel_phase_jobs(PHASE_KICKOFF);
        }
        ApplyOutcome::Applied
    }

    /// A chain scan: reconcile the status, mark dead slots, and hand every
    /// signal to this role's job.
    pub(super) async fn apply_chain_scan(
        &self,
        ctx: &mut ApplyContext<'_>,
        graph_id: Uuid,
        state: &mut GraphState,
        row: Option<&Graph>,
        payload: &[u8],
    ) -> anyhow::Result<ApplyOutcome> {
        let scan: ChainScan = match serde_json::from_slice(payload) {
            Ok(scan) => scan,
            Err(error) => {
                return Ok(ApplyOutcome::Rejected(format!("malformed chain_scan: {error}")));
            }
        };
        let Some(row) = row else {
            return Ok(ApplyOutcome::Applied);
        };
        let failed = super::graph::instance_failed(ctx, row.instance_id).await?;
        if let Some(target) = decide_status(&scan, failed) {
            let outcome = ctx
                .storage
                .transition_graph_status(
                    row.instance_id,
                    graph_id,
                    target,
                    GraphStatusSource::ChainReconcile,
                    scan.sub_status.clone(),
                )
                .await?;
            if let GraphStatusTransitionOutcome::Rejected { current } = outcome {
                debug!(event = "graph_scan", graph_id = %graph_id, target = %target, current = %current, "stale chain stage ignored");
            }
        }
        if let Some(challenge_txid) = scan.challenge_txid
            && row.challenge_txid.as_ref().map(|txid| txid.0) != Some(challenge_txid)
        {
            ctx.storage
                .update_graph_runtime(
                    &GraphRuntimeUpdate::new(row.instance_id, graph_id)
                        .with_challenge_txid(challenge_txid.into()),
                )
                .await?;
        }
        if let Some(Unusable::PrekickoffInputSpent { outpoint, spent_by }) = &scan.unusable {
            report_dead(state, row, outpoint, spent_by);
        }
        let own = self.owns(row);
        for signal in &scan.signals {
            if let Some(action) = route_signal(signal, &self.actor(), self.relayer(), own) {
                ctx.effects.enqueue_job(JobSpec::new(
                    &ctx.aggregate,
                    PHASE_SETTLEMENT,
                    action,
                    pegout_job_pool(action),
                    signal.encode()?,
                ));
            }
            // The operator asserted: the watchtower window is over.
            if self.actor() == Actor::Watchtower
                && matches!(signal, PegoutSignal::AssertSent { .. })
            {
                ctx.effects.cancel_job(
                    JobSpec::new(
                        &ctx.aggregate,
                        PHASE_SETTLEMENT,
                        JOB_WATCHTOWER_CHALLENGE,
                        pegout_job_pool(JOB_WATCHTOWER_CHALLENGE),
                        PegoutSignal::WatchtowerChallengeInitSent.encode()?,
                    )
                    .job_id,
                );
            }
        }
        Ok(ApplyOutcome::Applied)
    }
}

/// Report a dead Pre-Kickoff once. Each later slot of the operator is
/// obsoleted by its own scan, which reports `EarlierSlotDead`.
fn report_dead(state: &mut GraphState, row: &Graph, outpoint: &OutPoint, spent_by: &Txid) {
    if state.dead {
        return;
    }
    state.dead = true;
    warn!(
        event = "graph_dead",
        graph_id = %row.graph_id,
        operator_pubkey = %row.operator_pubkey,
        slot = row.kickoff_index,
        outpoint = %outpoint,
        spent_by = %spent_by,
        "Pre-Kickoff can never confirm; this slot and every later slot of the operator are unusable"
    );
    if let Some(metrics) = node_metrics_state() {
        metrics.record_instance_alert("operator_chain_dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use GraphStatus::*;

    fn scan(stage: GraphStatus, unusable: Option<Unusable>) -> ChainScan {
        ChainScan {
            height: 1,
            status_at_scan: String::new(),
            stage,
            sub_status: None,
            challenge_txid: None,
            unusable,
            signals: Vec::new(),
        }
    }

    fn taken() -> Option<Unusable> {
        Some(Unusable::ConnectorZeroTaken { spent_by: Txid::from_str(&"11".repeat(32)).unwrap() })
    }

    #[test]
    fn chain_progress_beats_the_projection() {
        let live = |stage, unusable| decide_status(&scan(stage, unusable), false);
        assert_eq!(live(PreKickoff, taken()), Some(PreKickoff));
        assert_eq!(live(Challenge, taken()), Some(Challenge));
        assert_eq!(live(Skipped, None), Some(Skipped));
        assert_eq!(live(OperatorDataPushed, taken()), Some(Obsoleted));
        assert_eq!(live(CommitteePresigned, taken()), Some(Obsoleted));
        // A later slot of a dead chain stays Obsoleted on its own scans.
        let behind = Some(Unusable::EarlierSlotDead { slot: 2 });
        assert_eq!(live(OperatorDataPushed, behind), Some(Obsoleted));
        // Posted overrides a local failure; nothing else is inferred.
        assert_eq!(live(OperatorDataPushed, None), Some(OperatorDataPushed));
        assert_eq!(decide_status(&scan(OperatorDataPushed, None), true), Some(OperatorDataPushed));
        assert_eq!(live(CommitteePresigned, None), None);
        assert_eq!(live(OperatorPresigned, None), None);
        // A copy stored after its instance failed follows the failure.
        assert_eq!(decide_status(&scan(OperatorPresigned, None), true), Some(Obsoleted));
        assert_eq!(decide_status(&scan(PreKickoff, None), true), Some(PreKickoff));
    }

    #[test]
    fn signals_route_to_the_acting_role() {
        use Actor::*;
        use PegoutSignal::*;
        assert_eq!(route_signal(&Take1Ready, &Operator, false, true), Some(JOB_TAKE1));
        assert_eq!(route_signal(&Take1Ready, &Operator, false, false), None);
        assert_eq!(route_signal(&Take1Sent, &Committee, true, false), Some(JOB_FINISH_HAPPY));
        assert_eq!(route_signal(&Take1Sent, &Committee, false, false), None);
        assert_eq!(
            route_signal(&PreKickoffSent, &Verifier, false, false),
            Some(JOB_CHECK_PREVIOUS_GRAPH)
        );
        assert_eq!(
            route_signal(&KickoffSent, &Verifier, false, false),
            Some(JOB_CHALLENGE_KICKOFF)
        );
        assert_eq!(route_signal(&KickoffSent, &Committee, true, false), Some(JOB_PROCEED_WITHDRAW));
        assert_eq!(route_signal(&KickoffSent, &Watchtower, false, false), None);
        let assert = AssertSent { assert_txid: Txid::from_str(&"22".repeat(32)).unwrap() };
        assert_eq!(route_signal(&assert, &Verifier, false, false), Some(JOB_VERIFIER_ASSERT));
        assert_eq!(
            route_signal(&assert, &Watchtower, false, false),
            Some(JOB_WATCHTOWER_PROOF_TIMEOUT)
        );
        assert_eq!(
            route_signal(&WatchtowerChallengeInitSent, &Watchtower, false, false),
            Some(JOB_WATCHTOWER_CHALLENGE)
        );
        let signal = DisproveSent {
            disprove_type: DisproveTxType::QuickChallenge,
            index: 0,
            challenge_start_txid: None,
            challenge_finish_txid: Txid::from_str(&"33".repeat(32)).unwrap(),
        };
        assert_eq!(PegoutSignal::decode(&signal.encode().unwrap()).unwrap(), signal);
        for action in PEGOUT_JOBS {
            assert!(!super::super::graph::ALL_JOBS.contains(action), "{action} is a setup job");
        }
    }

    #[test]
    fn computing_pegout_jobs_have_their_own_pool() {
        use super::super::graph::{JOB_BUILD_GRAPH, job_pool};
        for action in
            [JOB_WATCHTOWER_CHALLENGE, JOB_COMMIT_PUBIN, JOB_PROVER_ASSERT, JOB_VERIFIER_ASSERT]
        {
            assert_eq!(job_pool(action), JobPool::Pegout, "{action}");
        }
        assert_eq!(job_pool(JOB_WRONGLY_CHALLENGED), JobPool::Pegout);
        assert_eq!(job_pool(JOB_TAKE1), JobPool::Network);
        assert_eq!(job_pool(JOB_BUILD_GRAPH), JobPool::Cpu);
    }

    fn local(status: GraphStatus, finalized: bool, instance: InstanceBridgeInStatus) -> SlotFacts {
        SlotFacts {
            slot: 3,
            local: Some(LocalSlot {
                graph_id: Uuid::from_u128(1),
                instance_id: Uuid::from_u128(2),
                status,
                finalized,
                instance_status: Some(instance),
            }),
            ..Default::default()
        }
    }

    fn skip(verdict: SlotVerdict) -> bool {
        matches!(verdict, SlotVerdict::Skip(_))
    }

    #[test]
    fn a_graph_confirmed_in_the_buffer_is_never_skipped() {
        use InstanceBridgeInStatus::*;
        // Peg-In-Confirm confirmed in the buffer: the instance moved on, the
        // graph is live whether or not it is posted yet.
        let mut facts = local(CommitteePresigned, true, RelayerL1Broadcasted);
        facts.confirm = TxFact::confirmed_at(100);
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        facts.posted = true;
        facts.local.as_mut().unwrap().status = OperatorDataPushed;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // Locally abandoned, but the confirm landed after all: alert, no skip.
        let mut facts = local(Obsoleted, true, Timeout);
        facts.confirm = TxFact::confirmed_at(100);
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Stuck(_)));
        facts.confirm = TxFact::mempool();
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // Neither confirmed nor visible: the timed-out slot is skipped.
        facts.confirm = TxFact::UNKNOWN;
        assert_eq!(decide_slot(&facts, "op"), SlotVerdict::Skip("instance timed out"));
    }

    #[test]
    fn missing_or_unfinalized_copies_are_pulled_before_deciding() {
        use InstanceBridgeInStatus::*;
        let missing = SlotFacts { slot: 4, ..Default::default() };
        assert_eq!(
            decide_slot(&missing, "op"),
            SlotVerdict::Pull(GraphLookup::Slot {
                operator_pubkey: "op".to_string(),
                graph_nonce: 4
            })
        );
        // Posted on Goat but only operator pre-signed here: pull the
        // finalized copy, never treat it as abandoned.
        let mut facts = local(Obsoleted, false, UserCanceled);
        facts.posted = true;
        facts.cancel_confirmed = true;
        assert_eq!(
            decide_slot(&facts, "op"),
            SlotVerdict::Pull(GraphLookup::Id {
                instance_id: Uuid::from_u128(2),
                graph_id: Uuid::from_u128(1),
                finalized: true,
            })
        );
        // Without evidence, an unfinished graph of a failed instance is
        // abandoned.
        let facts = local(Obsoleted, false, NoEnoughCommitteesAnswered);
        assert_eq!(decide_slot(&facts, "op"), SlotVerdict::Skip("instance failed"));
        // Of a live instance it is not, until the instance passed its
        // abandon height: other graphs carried it, this one is never signed.
        let mut facts = local(OperatorPresigned, false, RelayerL2Minted);
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        facts.past_abandon_height = true;
        assert_eq!(
            decide_slot(&facts, "op"),
            SlotVerdict::Skip("unfinished at the abandon height")
        );
        // Posted after all: pull the finalized copy first.
        facts.posted = true;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Pull(_)));
        // A finalized graph past that height is still live ...
        let mut facts = local(CommitteePresigned, true, RelayerL1Broadcasted);
        facts.past_abandon_height = true;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // ... unless the operator gave it up at that height and the finalize
        // only landed afterwards: Obsoleted under a finalized definition.
        let mut facts = local(Obsoleted, true, RelayerL1Broadcasted);
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        facts.past_abandon_height = true;
        assert_eq!(
            decide_slot(&facts, "op"),
            SlotVerdict::Skip("unfinished at the abandon height")
        );
    }

    #[test]
    fn skip_premises_are_chain_facts() {
        use InstanceBridgeInStatus::*;
        // Skipped or force-skipped on chain, or closed locally: settled.
        let mut facts = local(Obsoleted, true, Timeout);
        facts.kickoff_connector = KickoffConnector::ByOther;
        assert_eq!(decide_slot(&facts, "op"), SlotVerdict::Settled);
        assert_eq!(
            decide_slot(&local(OperatorTake1, true, RelayerL2Minted), "op"),
            SlotVerdict::Settled
        );
        // Kicked off: wait for its settlement, never skip.
        let mut facts = local(Obsoleted, true, RelayerL2Minted);
        facts.kickoff_connector = KickoffConnector::ByKickoff;
        facts.connector_zero_taken = true;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // Posted and available: the successor waits (withdraw it first).
        let mut facts = local(OperatorDataPushed, true, RelayerL2Minted);
        facts.posted = true;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // ... unless another graph took Connector-0.
        facts.connector_zero_taken = true;
        assert!(skip(decide_slot(&facts, "op")));
        // Canceled peg-in: Connector-Z is gone.
        let mut facts = local(Obsoleted, true, UserCanceled);
        facts.cancel_confirmed = true;
        assert_eq!(decide_slot(&facts, "op"), SlotVerdict::Skip("peg-in canceled"));
        // The Obsoleted projection alone proves nothing.
        let facts = local(Obsoleted, true, Presigned);
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Wait(_)));
        // A dead Pre-Kickoff cannot be skipped either.
        let mut facts = local(Obsoleted, true, Timeout);
        facts.prekickoff_dead = true;
        assert!(matches!(decide_slot(&facts, "op"), SlotVerdict::Stuck(_)));
    }
}
