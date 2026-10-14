//! Jobs for kickoff, challenges and withdraw settlement.
//!
//! Jobs query chain state before taking action. A mempool spend does not settle
//! a slot; pending transactions are checked again until confirmed, and local
//! broadcasts can be repeated if the transaction disappears.

use super::graph::{GraphPlan, graph_pulled_event, slot_ref};
use super::graph_fetch::fetch_and_store_graph;
use super::graph_jobs::{GraphJobDeps, Step};
use super::graph_pegout::{
    JOB_CHALLENGE_ACK, JOB_CHALLENGE_KICKOFF, JOB_CHALLENGE_NACK, JOB_COMMIT_PUBIN,
    JOB_COMMIT_TIMEOUT, JOB_DISPROVE, JOB_ENFORCE_PREVIOUS_SLOT, JOB_FINISH_DISPROVED,
    JOB_FINISH_HAPPY, JOB_FINISH_UNHAPPY, JOB_KICKOFF, JOB_PROCEED_WITHDRAW, JOB_PROVER_ASSERT,
    JOB_SETTLE_PREDECESSORS, JOB_TAKE1, JOB_TAKE2, JOB_VERIFIER_ASSERT, JOB_WATCHTOWER_CHALLENGE,
    JOB_WATCHTOWER_CHALLENGE_INIT, JOB_WATCHTOWER_PROOF_TIMEOUT, JOB_WATCHTOWER_TIMEOUT,
    JOB_WRONGLY_CHALLENGED, KickoffConnectorSpend, KickoffParams, LocalSlot, PegoutSignal,
    SlotFacts, SlotVerdict, decide_slot,
};
use super::graph_scan::{connector_zero_taken, prekickoff_input_spent};
use super::graph_setup::{
    build_babe_prover_state, decode_soldering_proof_payload, find_verifier_index_by_pubkey,
    selected_candidate_for_graph_index, validate_verifier_slot,
};
use super::instance::{PeginDeadlines, TxFact};
use crate::engine_bridge::submit_event;
use crate::env::{get_bitvm_key, get_soldering_proof_payload_store_path};
use crate::metrics_service::node_metrics_state;
use crate::soldering_payload_store::{
    read_soldering_proof_store_payload, soldering_proof_payload_store_path,
};
use crate::utils::*;
use anyhow::{Context, Result, anyhow, bail};
use ark_serialize::CanonicalSerialize;
use bitcoin::{Amount, PublicKey, Txid};
use bitvm_lib::babe_adapter::{
    BabeChallengeAssertWitness, ChallengeAssertWitnessRaw, TxAssertWitness, WOTS_SIG_COUNT,
    assert_wots_message, build_assert_witness, build_real_challenge_assert_witness,
    expand_compact_soldering_proof_payload, recover_operator_proof_from_assert_witness,
    recover_real_wrongly_challenged_witness,
};
use bitvm_lib::keys::{OperatorMasterKey, VerifierMasterKey, WatchtowerMasterKey};
use bitvm_lib::operator::*;
use bitvm_lib::types::BitvmGcGraph;
use bitvm_lib::verifier::*;
use client::goat_chain::{DisproveTxType, WithdrawStatus};
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::wots::{Wots, Wots96};
use std::str::FromStr;
use store::localdb::{GraphQuery, LocalDB};
use store::{Graph, GraphStatus, InstanceBridgeInStatus, SerializableTxid};
use tracing::{info, warn};
use uuid::Uuid;

pub(super) async fn run_pegout_step(
    deps: &GraphJobDeps,
    action: &str,
    graph_id: Uuid,
    params: &[u8],
    attempts: i64,
) -> Result<Step> {
    match action {
        JOB_KICKOFF => kickoff(deps, graph_id, params).await,
        JOB_SETTLE_PREDECESSORS => settle_predecessors(deps, graph_id, params).await,
        _ => {
            let signal = PegoutSignal::decode(params).context("decode peg-out signal")?;
            let Some((row, graph)) = load_graph(&deps.local_db, graph_id).await? else {
                return Step::ignore("graph not stored locally");
            };
            settlement_step(deps, action, &row, graph, signal, attempts).await
        }
    }
}

async fn settlement_step(
    deps: &GraphJobDeps,
    action: &str,
    row: &Graph,
    graph: BitvmGcGraph,
    signal: PegoutSignal,
    attempts: i64,
) -> Result<Step> {
    use PegoutSignal::*;
    // A closed graph's branches are over; it may still owe the relayer's Goat
    // call, and its Pre-Kickoff still asks about the previous slot.
    let after_close = matches!(
        action,
        JOB_PROCEED_WITHDRAW
            | JOB_FINISH_HAPPY
            | JOB_FINISH_UNHAPPY
            | JOB_FINISH_DISPROVED
            | JOB_ENFORCE_PREVIOUS_SLOT
    );
    if closed(row) && !after_close {
        return Step::ignore(format!("graph is {}", row.status));
    }
    match (action, signal) {
        (JOB_ENFORCE_PREVIOUS_SLOT, _) => enforce_previous_slot(deps, &graph).await,
        (JOB_PROCEED_WITHDRAW, _) => proceed_withdraw(deps, row, &graph, attempts).await,
        (JOB_CHALLENGE_KICKOFF, _) => challenge_kickoff(deps, &graph).await,
        (JOB_WATCHTOWER_CHALLENGE_INIT, ChallengeSent { challenge_txid }) => {
            watchtower_challenge_init(deps, row, graph, challenge_txid).await
        }
        (JOB_WATCHTOWER_CHALLENGE, _) => watchtower_challenge(deps, row, &graph).await,
        (JOB_WATCHTOWER_PROOF_TIMEOUT, _) => watchtower_proof_timeout(row, &graph).await,
        (JOB_CHALLENGE_ACK, WatchtowerChallengeSent { watchtower_index }) => {
            challenge_ack(deps, row, &graph, watchtower_index).await
        }
        (JOB_WATCHTOWER_TIMEOUT, _) => watchtower_timeout(deps, row, graph).await,
        (JOB_CHALLENGE_NACK, NackReady { watchtower_index }) => {
            challenge_nack(deps, row, &graph, watchtower_index).await
        }
        (JOB_COMMIT_PUBIN, _) => commit_pubin(deps, &graph).await,
        (JOB_COMMIT_TIMEOUT, _) => commit_timeout(deps, row, &graph).await,
        (JOB_PROVER_ASSERT, _) => prover_assert(deps, graph).await,
        (JOB_VERIFIER_ASSERT, AssertSent { assert_txid }) => {
            verifier_assert(deps, &graph, assert_txid).await
        }
        (JOB_WRONGLY_CHALLENGED, ChallengeAssertSent { challenge_assert_txid, verifier_index }) => {
            wrongly_challenged(deps, &graph, challenge_assert_txid, verifier_index).await
        }
        (JOB_DISPROVE, WronglyChallengeTimeout { challenge_assert_txid, verifier_index }) => {
            disprove(deps, &graph, challenge_assert_txid, verifier_index).await
        }
        (
            JOB_FINISH_DISPROVED,
            DisproveSent { disprove_type, index, challenge_finish_txid, .. },
        ) => {
            finish_disproved(deps, &graph, disprove_type, index, challenge_finish_txid, attempts)
                .await
        }
        (JOB_TAKE1, _) => take1(deps, row, graph).await,
        (JOB_FINISH_HAPPY, _) => finish_happy(deps, &graph, attempts).await,
        (JOB_TAKE2, _) => take2(deps, row, graph).await,
        (JOB_FINISH_UNHAPPY, _) => finish_unhappy(deps, &graph, attempts).await,
        (action, signal) => bail!("{action} does not act on {signal:?}"),
    }
}

// ------------------------------------------------------------------ helpers

/// The graph row with its validated definition.
async fn load_graph(local_db: &LocalDB, graph_id: Uuid) -> Result<Option<(Graph, BitvmGcGraph)>> {
    let mut storage = local_db.acquire().await?;
    let Some(row) = storage.find_graph(&graph_id).await? else {
        return Ok(None);
    };
    let Some(definition) =
        load_validated_graph_definition(&mut storage, row.instance_id, graph_id).await?
    else {
        return Ok(None);
    };
    Ok(Some((row, BitvmGcGraph::from_simplified(&definition)?)))
}

fn status_of(row: &Graph) -> Option<GraphStatus> {
    GraphStatus::from_str(&row.status).ok()
}

/// Closed graphs only owe the relayer's Goat call; their branches are over.
fn closed(row: &Graph) -> bool {
    status_of(row).is_some_and(|status| status.is_closed())
}

fn block_secs(deps: &GraphJobDeps) -> i64 {
    avg_block_time_secs(deps.btc_client.network()) as i64
}

/// Retry after `blocks` blocks (at least one).
fn after_blocks(deps: &GraphJobDeps, reason: impl Into<String>, blocks: u64) -> Result<Step> {
    Step::retry(reason, block_secs(deps) * blocks.max(1) as i64)
}

/// What the chain says about an outpoint: a spend that is only in the mempool can still be
/// replaced, so a job waits on it instead of deciding on it.
enum Spend {
    Unspent,
    Pending(Txid),
    Confirmed(Txid),
}

async fn spend_of(btc: &client::btc_chain::BTCClient, txid: &Txid, vout: u64) -> Result<Spend> {
    Ok(match outpoint_spent_txid(btc, txid, vout).await? {
        None => Spend::Unspent,
        Some(spender) if btc.get_tx_status(&spender).await?.confirmed => Spend::Confirmed(spender),
        Some(spender) => Spend::Pending(spender),
    })
}

/// The step a connector's spend settles, `None` while it is unspent: a
/// confirmed spend ends the job, a pending one is looked at again.
fn settled_by(deps: &GraphJobDeps, spend: &Spend, what: &str) -> Option<Result<Step>> {
    match spend {
        Spend::Unspent => None,
        Spend::Confirmed(by) => Some(Step::ignore(format!("{what} already spent by {by}"))),
        Spend::Pending(by) => {
            Some(after_blocks(deps, format!("{what} spent by unconfirmed {by}"), 1))
        }
    }
}

/// Whether one of the graph's transactions is confirmed, in the mempool or
/// nowhere.
enum Presence {
    Absent,
    Mempool,
    Confirmed,
}

async fn presence_of(btc: &client::btc_chain::BTCClient, txid: &Txid) -> Result<Presence> {
    Ok(match btc.get_tx_info(txid).await? {
        None => Presence::Absent,
        Some(tx) if tx.status.confirmed => Presence::Confirmed,
        Some(_) => Presence::Mempool,
    })
}

/// The step an own transaction's presence settles, `None` while it is absent.
fn present(deps: &GraphJobDeps, presence: &Presence, what: &str) -> Option<Result<Step>> {
    match presence {
        Presence::Absent => None,
        Presence::Confirmed => Some(Step::ignore(format!("{what} is confirmed"))),
        Presence::Mempool => Some(after_blocks(deps, format!("{what} is in the mempool"), 1)),
    }
}

/// After a broadcast: look again next block, so a transaction that fell out
/// of the mempool is sent again and a confirmed one ends the job.
fn broadcast_pending(deps: &GraphJobDeps, what: &str) -> Result<Step> {
    after_blocks(deps, format!("{what} broadcast; waiting for its confirmation"), 1)
}

fn alert(reason: &str) {
    if let Some(metrics) = node_metrics_state() {
        metrics.record_instance_alert(reason);
    }
}

fn local_operator() -> Result<(OperatorMasterKey, PublicKey)> {
    let master = OperatorMasterKey::new(get_bitvm_key()?);
    let pubkey = master.master_keypair().public_key().into();
    Ok((master, pubkey))
}

/// The step that ends an operator's kickoff job unless its withdraw is live
/// on Goat. `None` is a lagging Goat node (the `InitWithdraw` came from a
/// finalized block), so it is looked at again; any other status is over.
async fn step_unless_withdraw_live(
    deps: &GraphJobDeps,
    graph_id: Uuid,
    tx_hash: &str,
) -> Result<Option<Step>> {
    Ok(match deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status {
        WithdrawStatus::Initialized => None,
        WithdrawStatus::None => {
            Some(after_blocks(deps, format!("withdraw {tx_hash} is not visible on Goat yet"), 1)?)
        }
        other => Some(Step::ignore(format!("withdraw {tx_hash} is {other:?}"))?),
    })
}

// ------------------------------------------------------------------- kickoff

/// Pre-Kickoff + Kickoff of the operator's graph; the apply queued it once
/// the previous slot settled.
async fn kickoff(deps: &GraphJobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let params: KickoffParams = serde_json::from_slice(params).context("decode kickoff params")?;
    let Some((_, mut graph)) = load_graph(&deps.local_db, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let (_, operator_pubkey) = local_operator()?;
    if graph.parameters.operator_pubkey != operator_pubkey {
        return Step::ignore("not this operator's graph");
    }
    if let Some(step) = step_unless_withdraw_live(deps, graph_id, &params.tx_hash).await? {
        return Ok(step);
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    let kickoff_connector = output_topology::prekickoff::kickoff_connector() as u64;
    match outpoint_spent_txid(&deps.btc_client, &prekickoff_txid, kickoff_connector).await? {
        Some(spent_by) if spent_by != kickoff_txid => {
            if !deps.btc_client.get_tx_status(&spent_by).await?.confirmed {
                return after_blocks(
                    deps,
                    format!("kickoff connector spent by unconfirmed {spent_by}"),
                    1,
                );
            }
            return Step::ignore(format!("kickoff connector already spent by {spent_by}"));
        }
        // Broadcast but not confirmed: the retry below re-sends the CPFP
        // children an earlier attempt may not have reached.
        Some(_) if deps.btc_client.get_tx_status(&kickoff_txid).await?.confirmed => {
            return Step::ignore("already kicked off");
        }
        _ => {}
    }
    if let Some((outpoint, spent_by)) = prekickoff_input_spent(&deps.btc_client, &graph).await? {
        alert("operator_chain_dead");
        return Step::ignore(format!(
            "Pre-Kickoff can never confirm: {outpoint} was spent by {spent_by}"
        ));
    }
    operator_kickoff(&deps.btc_client, &mut graph).await?;
    info!(event = "graph_kickoff", graph_id = %graph_id, tx_hash = %params.tx_hash, "Pre-Kickoff and Kickoff broadcast");
    broadcast_pending(deps, &format!("Pre-Kickoff and Kickoff for withdraw {}", params.tx_hash))
}

/// Settle earlier operator slots in order: skip eligible slots, fetch missing
/// definitions and wait for unresolved slots. Completion unblocks kickoff.
async fn settle_predecessors(deps: &GraphJobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let params: KickoffParams = serde_json::from_slice(params).context("decode kickoff params")?;
    let Some(row) = deps.local_db.acquire().await?.find_graph(&graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let (_, operator_pubkey) = local_operator()?;
    if row.operator_pubkey != operator_pubkey.to_string() {
        return Step::ignore("not this operator's graph");
    }
    if let Some(step) = step_unless_withdraw_live(deps, graph_id, &params.tx_hash).await? {
        return Ok(step);
    }
    let graph_nonce = row.kickoff_index as u64;
    let chain = ChainClock {
        height: i64::from(deps.btc_client.get_height().await?),
        deadlines: PeginDeadlines::from_env(),
    };
    for slot in first_open_slot(&deps.local_db, &row).await?..graph_nonce {
        let mut facts = slot_facts(deps, &row.operator_pubkey, slot, &chain).await?;
        let mut verdict = decide_slot(&facts, &row.operator_pubkey);
        if let SlotVerdict::Pull(lookup) = &verdict {
            match fetch_and_store_graph(
                &deps.local_db,
                &deps.btc_client,
                &deps.goat_client,
                &deps.publisher,
                lookup,
            )
            .await
            {
                Ok(Some(found)) => {
                    submit_event(
                        &deps.local_db,
                        graph_pulled_event(found.graph_id, found.instance_id, found.finalized)?,
                    )
                    .await?;
                    facts = slot_facts(deps, &row.operator_pubkey, slot, &chain).await?;
                    verdict = decide_slot(&facts, &row.operator_pubkey);
                }
                Ok(None) => {
                    return Step::retry(format!("slot {slot}: no peer served {lookup:?}"), 60);
                }
                Err(error) => {
                    return Step::retry(format!("slot {slot}: pull failed: {error:#}"), 60);
                }
            }
        }
        match verdict {
            SlotVerdict::Settled => continue,
            SlotVerdict::Pull(lookup) => {
                return Step::retry(format!("slot {slot}: still missing {lookup:?}"), 60);
            }
            SlotVerdict::Skip(premise) => {
                let Some(local) = facts.local else {
                    bail!("slot {slot} has no local copy to skip");
                };
                let Some((_, mut skipped)) = load_graph(&deps.local_db, local.graph_id).await?
                else {
                    bail!("slot {slot} definition disappeared");
                };
                operator_skip_graph(&deps.btc_client, &mut skipped).await?;
                info!(
                    event = "graph_skip",
                    graph_id = %graph_id,
                    skipped_graph_id = %local.graph_id,
                    slot,
                    premise,
                    "Pre-Kickoff and Skip-Kickoff of an earlier slot broadcast"
                );
                return after_blocks(deps, format!("skipped slot {slot} ({premise})"), 1);
            }
            SlotVerdict::Wait(reason) => return after_blocks(deps, reason, 1),
            SlotVerdict::Stuck(reason) => {
                warn!(event = "graph_skip", graph_id = %graph_id, slot, reason = %reason, "earlier slot needs manual handling");
                alert("pegout_predecessor_stuck");
                return after_blocks(deps, reason, 10);
            }
        }
    }
    let mut plan = GraphPlan::noted("every earlier slot is settled on chain");
    if graph_nonce > 0 {
        plan.wake_refs.push(slot_ref(&row.operator_pubkey, graph_nonce - 1));
    }
    Step::done(plan)
}

/// One past the operator's highest closed slot below this graph: the slots
/// under it were settled when it advanced.
async fn first_open_slot(local_db: &LocalDB, row: &Graph) -> Result<u64> {
    let closed: Vec<String> =
        GraphStatus::get_closed_status().iter().map(ToString::to_string).collect();
    let highest = local_db
        .acquire()
        .await?
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(row.operator_pubkey.clone())
                .with_statuses(closed)
                .with_raw_condition(format!("kickoff_index < {}", row.kickoff_index))
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?
        .pop();
    Ok(highest.map(|graph| graph.kickoff_index as u64 + 1).unwrap_or(0))
}

/// Facts about one slot: the local copy, then the chain.
/// The Bitcoin height and peg-in deadlines a settle run judges every slot by.
struct ChainClock {
    height: i64,
    deadlines: PeginDeadlines,
}

async fn slot_facts(
    deps: &GraphJobDeps,
    operator_pubkey: &str,
    slot: u64,
    chain: &ChainClock,
) -> Result<SlotFacts> {
    let mut facts = SlotFacts { slot, ..Default::default() };
    let (row, instance, definition) = {
        let mut storage = deps.local_db.acquire().await?;
        let Some(row) = storage.find_graph_by_operator_slot(operator_pubkey, slot as i64).await?
        else {
            return Ok(facts);
        };
        let instance = storage.find_instance(&row.instance_id).await?;
        let definition =
            load_validated_graph_definition(&mut storage, row.instance_id, row.graph_id).await?;
        (row, instance, definition)
    };
    let Some(definition) = definition else {
        return Ok(facts);
    };
    let graph = BitvmGcGraph::from_simplified(&definition)?;
    let btc = &deps.btc_client;
    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    let kickoff_connector = output_topology::prekickoff::kickoff_connector() as u64;
    facts.kickoff_connector =
        match outpoint_spent_txid(btc, &prekickoff_txid, kickoff_connector).await? {
            Some(spent_by) if spent_by == graph.kickoff.tx().compute_txid() => {
                KickoffConnectorSpend::ByKickoff
            }
            // Settled only once the Skip / Force-Skip confirmed.
            Some(spent_by) if btc.get_tx_status(&spent_by).await?.confirmed => {
                KickoffConnectorSpend::ByOther
            }
            _ => KickoffConnectorSpend::Unspent,
        };
    if facts.kickoff_connector == KickoffConnectorSpend::Unspent
        && !tx_visible(btc, &prekickoff_txid).await?
    {
        facts.prekickoff_dead = prekickoff_input_spent(btc, &graph).await?.is_some();
    }
    facts.posted =
        deps.goat_client.gateway_get_graph_data(&row.graph_id).await?.operator_pubkey != [0u8; 32];
    facts.connector_zero_taken = connector_zero_taken(btc, &graph).await?.is_some();
    if let Some(instance) = &instance {
        if let Some(cancel) = &instance.pegin_cancel_txid {
            facts.cancel_confirmed = btc.get_tx_status(&cancel.0).await?.confirmed;
        }
        if let Some(confirm) = &instance.pegin_confirm_txid {
            facts.confirm = match btc.get_tx_info(&confirm.0).await? {
                None => TxFact::UNKNOWN,
                Some(tx) if tx.status.confirmed => TxFact {
                    confirmed: true,
                    block_height: tx.status.block_height.map(i64::from),
                    in_mempool: false,
                },
                Some(_) => TxFact::mempool(),
            };
        }
    }
    let finalized = graph.committee_pre_signed();
    if let Some(instance) = &instance {
        facts.past_abandon_height = chain
            .deadlines
            .abandon_height(instance.btc_height)
            .is_some_and(|abandon_height| chain.height >= abandon_height);
    }
    facts.local = Some(LocalSlot {
        graph_id: row.graph_id,
        instance_id: row.instance_id,
        status: GraphStatus::from_str(&row.status).map_err(|error| anyhow!("{error}"))?,
        finalized,
        instance_status: instance
            .as_ref()
            .and_then(|instance| InstanceBridgeInStatus::from_str(&instance.status).ok()),
    });
    Ok(facts)
}

// ---------------------------------------------------------------- verifier

/// Pre-Kickoff-N is on chain: the previous slot must have been kicked off and
/// settled, or skipped. Force-Skip it if Kickoff-(N−1) never appeared,
/// Quick-Challenge it if it is still unsettled. The previous definition comes
/// from the store or, if missing, from the relayer / committee.
async fn enforce_previous_slot(deps: &GraphJobDeps, graph: &BitvmGcGraph) -> Result<Step> {
    let graph_nonce = graph.parameters.graph_nonce;
    if graph_nonce == 0 {
        return Step::ignore("first slot of the operator");
    }
    let btc = &deps.btc_client;
    // The scan saw the Pre-Kickoff confirmed; a read that disagrees (a lagging
    // backend, a reorg) is looked at again rather than ending the job.
    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    if !tx_confirmed(btc, &prekickoff_txid).await? {
        return after_blocks(deps, "pre-kickoff is not confirmed yet", 1);
    }
    let operator_pubkey = graph.parameters.operator_pubkey.to_string();
    let previous_slot = graph_nonce - 1;
    let previous_id = deps
        .local_db
        .acquire()
        .await?
        .find_graph_by_operator_slot(&operator_pubkey, previous_slot as i64)
        .await?
        .map(|row| row.graph_id);
    let previous = match previous_id {
        Some(previous_id) => load_graph(&deps.local_db, previous_id).await?,
        None => None,
    };
    let (previous_row, previous) = match previous {
        Some(previous) => previous,
        None => {
            let lookup = super::graph_fetch::GraphLookup::Slot {
                operator_pubkey: operator_pubkey.clone(),
                graph_nonce: previous_slot,
            };
            match fetch_and_store_graph(
                &deps.local_db,
                btc,
                &deps.goat_client,
                &deps.publisher,
                &lookup,
            )
            .await
            {
                Ok(Some(found)) => {
                    submit_event(
                        &deps.local_db,
                        graph_pulled_event(found.graph_id, found.instance_id, found.finalized)?,
                    )
                    .await?;
                    match load_graph(&deps.local_db, found.graph_id).await? {
                        Some(previous) => previous,
                        None => return Step::retry("pulled previous graph is not readable", 60),
                    }
                }
                Ok(None) => return Step::retry("no peer served the previous graph", 60),
                Err(error) => {
                    return Step::retry(
                        format!("pulling the previous graph failed: {error:#}"),
                        60,
                    );
                }
            }
        }
    };
    let stage = scan_graph_chain_state(btc, &deps.goat_client, &previous).await?.status;
    let previous_kickoff = previous.kickoff.tx().compute_txid();
    if !tx_visible(btc, &previous_kickoff).await? {
        let previous_prekickoff = previous.cur_prekickoff.tx().compute_txid();
        let kickoff_connector = output_topology::prekickoff::kickoff_connector() as u64;
        let spend = spend_of(btc, &previous_prekickoff, kickoff_connector).await?;
        if let Some(step) = settled_by(deps, &spend, "previous slot's kickoff connector") {
            return step;
        }
        let txid = verifier_force_skip_kickoff(btc, &previous).await?;
        info!(event = "graph_punish", graph_id = %previous_row.graph_id, txid = %txid, "Force-Skip-Kickoff broadcast");
        return broadcast_pending(deps, &format!("Force-Skip-Kickoff {txid}"));
    }
    if stage.is_closed() {
        return Step::ignore(format!("previous slot is {stage}"));
    }
    let guardian = output_topology::kickoff::guardian_connector() as u64;
    let spend = spend_of(btc, &previous_kickoff, guardian).await?;
    if let Some(step) = settled_by(deps, &spend, "previous slot's guardian connector") {
        return step;
    }
    let txid = verifier_quick_challenge(btc, &previous).await?;
    info!(event = "graph_punish", graph_id = %previous_row.graph_id, txid = %txid, "Quick-Challenge broadcast");
    broadcast_pending(deps, &format!("Quick-Challenge {txid}"))
}

/// Kickoff confirmed: challenge it when Goat shows no live withdraw.
async fn challenge_kickoff(deps: &GraphJobDeps, graph: &BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    let graph_id = graph.parameters.graph_id;
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let Some(kickoff_height) = btc.get_tx_status(&kickoff_txid).await?.block_height else {
        return after_blocks(deps, "kickoff is not confirmed yet", 1);
    };
    let take1_txid = graph.take1.tx().compute_txid();
    let (challenge_tx, _) = export_challenge_tx(graph)?;
    let outpoint = challenge_tx.input[0].previous_output;
    if let Some(spent_txid) =
        outpoint_spent_txid(btc, &outpoint.txid, u64::from(outpoint.vout)).await?
    {
        // Only a confirmed spend settles it: a Challenge in the mempool may be
        // ours (resent below if it is evicted) or a decoy an operator replaces.
        if !btc.get_tx_status(&spent_txid).await?.confirmed {
            return after_blocks(
                deps,
                format!("challenge connector spent by unconfirmed {spent_txid}"),
                1,
            );
        }
        let spender = if spent_txid == take1_txid { "Take-1" } else { "Challenge" };
        return Step::ignore(format!(
            "challenge connector already spent by {spender} {spent_txid}"
        ));
    }
    match deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status {
        WithdrawStatus::None | WithdrawStatus::Canceled => {}
        // Passing: the relayer's proceedWithdraw makes it Processing, a
        // cancel makes it Canceled. Decided on the next look, not dropped.
        WithdrawStatus::Initialized => {
            return after_blocks(
                deps,
                "withdraw is initialized; waiting for proceedWithdraw or a cancel",
                1,
            );
        }
        other => return Step::ignore(format!("withdraw is {other:?}")),
    }
    let spv_height = deps.goat_client.btc_spv_latest_height().await? as u32;
    if kickoff_height >= spv_height {
        return after_blocks(
            deps,
            "kickoff block is not available through GOAT SPV",
            u64::from(kickoff_height - spv_height),
        );
    }
    // The connector is unspent, so no Challenge of ours is pending.
    let txid = send_challenge_tx(btc, graph).await?;
    info!(event = "graph_challenge", graph_id = %graph_id, txid = %txid, "Challenge broadcast");
    broadcast_pending(deps, &format!("Challenge {txid}"))
}

fn local_verifier_pubkey() -> Result<PublicKey> {
    Ok(VerifierMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

/// An ACK-Connector unspent past `T5` after a watchtower challenge: NACK.
async fn challenge_nack(
    deps: &GraphJobDeps,
    row: &Graph,
    graph: &BitvmGcGraph,
    watchtower_index: usize,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let watchtower_num = validate_watchtower_branches(graph)?;
    if watchtower_index >= watchtower_num {
        bail!("watchtower index {watchtower_index} out of range for {watchtower_num} slots");
    }
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if let Some(step) =
        settled_by(deps, &spend_of(btc, &wci_txid, connector_f).await?, "connector-F")
    {
        return step;
    }
    // The scan saw this watchtower's challenge confirmed; a read that disagrees
    // is looked at again.
    let watchtower_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index) as u64;
    let Some(watchtower_spent) = outpoint_spent_txid(btc, &wci_txid, watchtower_vout).await? else {
        return after_blocks(
            deps,
            format!("watchtower connector {watchtower_index} is not spent"),
            1,
        );
    };
    if watchtower_spent == graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid()
    {
        return Step::ignore(format!("watchtower {watchtower_index} timed out"));
    }
    // ACK or NACK (ours included) spend the ACK-Connector: confirmed, the
    // branch is settled; pending, it is looked at again.
    let ack_vout =
        output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
    if let Some(step) = settled_by(
        deps,
        &spend_of(btc, &wci_txid, ack_vout).await?,
        &format!("ack connector {watchtower_index}"),
    ) {
        return step;
    }
    let nack = graph
        .operator_challenge_nacks
        .get(watchtower_index)
        .ok_or_else(|| anyhow!("invalid watchtower index {watchtower_index}"))?;
    let nack_tx = nack.tx().clone();
    let nack_txid = nack_tx.compute_txid();
    let input_amount = nack.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc, nack_tx, input_amount).await?;
    info!(event = "graph_challenge", graph_id = %row.graph_id, watchtower_index, txid = %nack_txid, "Operator-Challenge-NACK broadcast");
    broadcast_pending(deps, &format!("Operator-Challenge-NACK {nack_txid}"))
}

/// Commit-pubin missing past `T6`: Operator-Commit-Timeout.
async fn commit_timeout(deps: &GraphJobDeps, row: &Graph, graph: &BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let connector_e =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    for (vout, what) in [(connector_e, "connector-E"), (connector_f, "connector-F")] {
        if let Some(step) = settled_by(deps, &spend_of(btc, &wci_txid, vout).await?, what) {
            return step;
        }
    }
    let timeout_tx = graph.operator_commit_timeout.tx().clone();
    let timeout_txid = timeout_tx.compute_txid();
    let input_amount =
        graph.operator_commit_timeout.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc, timeout_tx, input_amount).await?;
    info!(event = "graph_challenge", graph_id = %row.graph_id, txid = %timeout_txid, "Operator-Commit-Timeout broadcast");
    broadcast_pending(deps, &format!("Operator-Commit-Timeout {timeout_txid}"))
}

/// Prover-Assert confirmed: Pubin-Disprove if the committed pubin and the
/// asserted one disagree, otherwise Verifier-Assert unless the proof is valid.
async fn verifier_assert(
    deps: &GraphJobDeps,
    graph: &BitvmGcGraph,
    assert_txid: Txid,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    let Some(assert_tx) = btc.get_tx(&assert_txid).await? else {
        return after_blocks(deps, format!("assert tx {assert_txid} is not available"), 1);
    };
    let verifier_pubkey = local_verifier_pubkey()?;
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        return Step::ignore("local verifier has no graph slot");
    };
    validate_verifier_slot(graph, verifier_index)?;
    // Connector-D of the assert goes to Take-2 or a Pubin-Disprove, this
    // verifier's connector to its ChallengeAssert: either on chain (ours
    // included) ends the job, either in the mempool is looked at again, before
    // the proof work below is repeated.
    let verifier_num = graph.parameters.gc_data.len();
    for (vout, what) in [
        (output_topology::operator_assert::connector_d(verifier_num) as u64, "assert connector-D"),
        (
            output_topology::operator_assert::verifier_connector(verifier_index) as u64,
            "verifier connector",
        ),
    ] {
        if let Some(step) = settled_by(deps, &spend_of(btc, &assert_txid, vout).await?, what) {
            return step;
        }
    }

    // ChallengeAssert may only be skipped after this graph's commit-pubin is
    // on-chain and proves consistent with the assert witness. OperatorAssert
    // can otherwise be broadcast before connector-E is spent.
    let connector_e = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|error| anyhow!("failed to resolve connector-E input: {error}"))?
        .outpoint;
    let Some(connector_e_spent) =
        outpoint_spent_txid(btc, &connector_e.txid, u64::from(connector_e.vout)).await?
    else {
        return after_blocks(deps, "operator commit-pubin is not on chain yet", 1);
    };

    let mut pubin_consistent = false;
    if connector_e_spent != graph.operator_commit_timeout.tx().compute_txid() {
        if !btc.get_tx_status(&connector_e_spent).await?.confirmed {
            return after_blocks(deps, "operator commit-pubin is not confirmed yet", 1);
        }
        let Some(commit_pubin_tx) = btc.get_tx(&connector_e_spent).await? else {
            return after_blocks(deps, "operator commit-pubin is not available yet", 1);
        };
        let assert_txin = assert_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
        let commit_pubin_txin = commit_pubin_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator commit-pubin transaction has no input"))?;
        let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let timeout_txids = graph
            .watchtower_challenge_timeouts
            .iter()
            .map(|tx| tx.tx().compute_txid())
            .collect::<Vec<_>>();
        let ack_txins = match collect_ack_txins(btc, &wci_txid, &timeout_txids).await {
            Ok(txins) => txins,
            Err(error) => {
                return after_blocks(
                    deps,
                    format!("operator ACK inputs are not ready: {error}"),
                    1,
                );
            }
        };
        match validate_pubin_disprove(graph, commit_pubin_txin, assert_txin, &ack_txins) {
            Ok(Some((witness_data, _))) => {
                // PubinDisprove is not pre-signed, so fund it directly rather
                // than relying on CPFP.
                let input_amount = graph
                    .operator_assert
                    .connector_d_input()
                    .map_err(|e| anyhow!("failed to get connector-d input: {e}"))?
                    .amount;
                let txin = build_pubin_disprove_txin(graph, witness_data)?;
                let outputs = vec![
                    goat::scripts::p2a_output(),
                    // Keep the transaction above Bitcoin Core's minimum
                    // non-witness relay size.
                    bitcoin::TxOut {
                        value: Amount::ZERO,
                        script_pubkey: goat::scripts::generate_opreturn_script(
                            PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                        ),
                    },
                ];
                let verifier_keypair = VerifierMasterKey::new(get_bitvm_key()?).master_keypair();
                let txid = build_sign_and_broadcast_tx(
                    btc,
                    verifier_keypair,
                    vec![txin],
                    input_amount,
                    outputs,
                )
                .await?;
                info!(event = "graph_challenge", graph_id = %graph_id, txid = %txid, "Pubin-Disprove broadcast");
                return broadcast_pending(deps, &format!("Pubin-Disprove {txid}"));
            }
            Ok(None) => pubin_consistent = true,
            Err(error) => warn!(
                "PubinDisprove validation failed for {instance_id}:{graph_id}: {error}; proceeding to ChallengeAssert"
            ),
        }
    }

    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;
    if pubin_consistent && assert_witness.verify_groth16_proof(&vk, &[static_input]) {
        return Step::ignore("operator assert proof is valid");
    }
    let broadcast = broadcast_verifier_challenge_assert_tx(
        &deps.local_db,
        btc,
        graph,
        instance_id,
        graph_id,
        &assert_tx,
        false,
    )
    .await?;
    if broadcast.is_none() {
        // Without the BABE verifier state the assert cannot be challenged by
        // this node; repeating the proof work every block would not change that.
        warn!(event = "graph_challenge", graph_id = %graph_id, "ChallengeAssert cannot be built: BABE verifier state or soldering proof reference missing");
        alert("verifier_assert_unavailable");
        return Step::ignore("ChallengeAssert not built: missing BABE verifier state");
    }
    broadcast_pending(deps, "ChallengeAssert")
}

const PUBIN_DISPROVE_OP_RETURN_DATA: &[u8] = b"pubin-disprove";

pub async fn broadcast_verifier_challenge_assert_tx(
    local_db: &LocalDB,
    btc_client: &client::btc_chain::BTCClient,
    graph: &BitvmGcGraph,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_tx: &bitcoin::Transaction,
    strict: bool,
) -> Result<Option<(Txid, usize)>> {
    let verifier_pubkey = local_verifier_pubkey()?;
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        if strict {
            bail!("local verifier has no graph slot for {instance_id}:{graph_id}");
        }
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(None);
    };
    validate_verifier_slot(graph, verifier_index)?;

    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;

    let Some(saved_verifier_state) =
        load_babe_setup_state(local_db, instance_id, graph_id)?.and_then(|state| state.verifier)
    else {
        if strict {
            bail!("missing BABE verifier setup state for {instance_id}:{graph_id}");
        }
        warn!("Ignore AssertSent for {instance_id}:{graph_id}: missing BABE verifier setup state");
        return Ok(None);
    };
    if saved_verifier_state.soldering_proof_ready.is_none() {
        if strict {
            bail!("missing soldering proof reference for {instance_id}:{graph_id}");
        }
        warn!("Ignore AssertSent for {instance_id}:{graph_id}: missing soldering proof reference");
        return Ok(None);
    }
    let challenge_witness = build_real_challenge_assert_witness(
        &saved_verifier_state.private_state,
        &saved_verifier_state.setup_package,
        &saved_verifier_state.finalized_indices,
        &vk,
        static_input,
        &assert_witness,
        verifier_index,
    )?;
    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txin = assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let challenge_assert_tx =
        build_verifier_assert_tx(graph, operator_assert_txin, verifier_index, labels)?;
    let challenge_assert_txid = challenge_assert_tx.compute_txid();
    if btc_client.get_tx(&challenge_assert_txid).await?.is_some() {
        info!(
            "Verifier ChallengeAssert already exists for {instance_id}:{graph_id}: verifier_index={verifier_index}, txid={challenge_assert_txid}"
        );
        return Ok(Some((challenge_assert_txid, verifier_index)));
    }
    let input_amount =
        graph.verifier_asserts[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc_client, challenge_assert_tx, input_amount).await?;
    Ok(Some((challenge_assert_txid, verifier_index)))
}

/// A Verifier-Assert unanswered past `T2`: Disprove-X by its own verifier.
async fn disprove(
    deps: &GraphJobDeps,
    graph: &BitvmGcGraph,
    challenge_assert_txid: Txid,
    verifier_index: usize,
) -> Result<Step> {
    let btc = &deps.btc_client;
    validate_expected_challenge_assert_txid(graph, verifier_index, challenge_assert_txid)?;
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != local_verifier_pubkey()? {
        return Step::ignore(format!("local verifier does not own slot {verifier_index}"));
    }
    if btc.get_tx(&challenge_assert_txid).await?.is_none() {
        return after_blocks(deps, "ChallengeAssert is not available from the Bitcoin backend", 1);
    }
    let Some(assert_height) = btc.get_tx_status(&challenge_assert_txid).await?.block_height else {
        return after_blocks(deps, "ChallengeAssert is not confirmed", 1);
    };
    let disprove_height = u64::from(assert_height)
        + disprove_timelock_with_config(
            graph.parameters.instance_parameters.network,
            &graph.parameters.timelock_config,
        ) as u64;
    let height = u64::from(btc.get_height().await?);
    if height < disprove_height {
        return after_blocks(deps, "disprove timelock has not expired", disprove_height - height);
    }
    if let Some(step) = settled_by(
        deps,
        &spend_of(btc, &challenge_assert_txid, 0).await?,
        "verifier assertion output",
    ) {
        return step;
    }
    let disprove_tx = build_disprove_tx(graph, verifier_index, None)?;
    let input_amount =
        graph.disproves[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc, disprove_tx, input_amount).await?;
    broadcast_pending(deps, &format!("Disprove of slot {verifier_index}"))
}

// ---------------------------------------------------------------- operator

/// Challenge on Connector-A: Watchtower-Challenge-Init.
async fn watchtower_challenge_init(
    deps: &GraphJobDeps,
    row: &Graph,
    mut graph: BitvmGcGraph,
    challenge_txid: Txid,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if let Some(step) =
        present(deps, &presence_of(btc, &wci_txid).await?, "Watchtower-Challenge-Init")
    {
        return step;
    }
    let Some(challenge_tx) = btc.get_tx(&challenge_txid).await? else {
        return after_blocks(deps, "challenge tx is not available", 1);
    };
    let connector_a = graph
        .kickoff
        .connector_a_input()
        .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?
        .outpoint;
    if challenge_tx.input.first().map(|input| input.previous_output) != Some(connector_a) {
        return Step::ignore("challenge does not spend connector-A");
    }
    let (master, _) = local_operator()?;
    let wci_tx = operator_sign_watchtower_challenge_init(master.master_keypair(), &mut graph)?;
    let anchor_vout = wci_tx.output.len() as u64 - 1;
    let input_amount = graph.watchtower_challenge_init.prev_outs().iter().map(|o| o.value).sum();
    match build_cpfp_txns(btc, &wci_tx, anchor_vout, input_amount).await? {
        Some(child) => broadcast_package(btc, &[wci_tx, child], true).await?,
        None => broadcast_tx(btc, &wci_tx).await?,
    };
    info!(event = "graph_challenge", graph_id = %row.graph_id, txid = %wci_txid, "Watchtower-Challenge-Init broadcast");
    broadcast_pending(deps, &format!("Watchtower-Challenge-Init {wci_txid}"))
}

/// A watchtower challenged: reveal the ACK preimage.
async fn challenge_ack(
    deps: &GraphJobDeps,
    row: &Graph,
    graph: &BitvmGcGraph,
    watchtower_index: usize,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let watchtower_num = validate_watchtower_branches(graph)?;
    if watchtower_index >= watchtower_num {
        bail!("watchtower index {watchtower_index} out of range for {watchtower_num} slots");
    }
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index) as u64;
    // The scan saw this watchtower's challenge confirmed; a read that disagrees
    // is looked at again rather than ending the only ACK job of the branch.
    let Some((spent_txid, vin, _)) = outpoint_spent_txin(btc, &wci_txid, watchtower_vout).await?
    else {
        return after_blocks(
            deps,
            format!("watchtower connector {watchtower_index} is not spent"),
            1,
        );
    };
    if vin != 0 {
        return Step::ignore(format!(
            "watchtower connector {watchtower_index} spent by {spent_txid} at input {vin}"
        ));
    }
    let timeout_txid = graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
    if spent_txid == timeout_txid {
        return Step::ignore(format!("watchtower {watchtower_index} timed out"));
    }
    let ack_vout =
        output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
    if let Some(step) = settled_by(
        deps,
        &spend_of(btc, &wci_txid, ack_vout).await?,
        &format!("ack connector {watchtower_index}"),
    ) {
        return step;
    }
    let (master, _) = local_operator()?;
    let preimage = master.preimage_for_graph(row.graph_id, watchtower_index);
    let ack_connector = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|e| anyhow!("failed to get ack connector input: {e}"))?;
    let ack_input = operator_sign_challenge_ack(graph, watchtower_index, &preimage)?;
    let ack_txid = build_sign_and_broadcast_tx(
        btc,
        master.master_keypair(),
        vec![ack_input],
        ack_connector.amount,
        vec![goat::scripts::p2a_output()],
    )
    .await?;
    info!(event = "graph_challenge", graph_id = %row.graph_id, watchtower_index, txid = %ack_txid, "Operator-Challenge-ACK broadcast");
    broadcast_pending(deps, &format!("Operator-Challenge-ACK {ack_txid}"))
}

/// Watchtowers silent past `T4`: their timeouts.
async fn watchtower_timeout(
    deps: &GraphJobDeps,
    row: &Graph,
    mut graph: BitvmGcGraph,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let watchtower_num = validate_watchtower_branches(&graph)?;
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let (master, _) = local_operator()?;
    let mut sent = 0;
    let mut pending = 0;
    for index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(index) as u64;
        let ack_vout = output_topology::watchtower_challenge_init::ack_connector(index) as u64;
        // A challenge, or a timeout of ours, spends the watchtower connector:
        // confirmed, the branch is settled; pending, it is looked at again.
        let mut settled = false;
        for vout in [watchtower_vout, ack_vout] {
            match spend_of(btc, &wci_txid, vout).await? {
                Spend::Confirmed(_) => settled = true,
                Spend::Pending(_) => {
                    settled = true;
                    pending += 1;
                }
                Spend::Unspent => {}
            }
        }
        if settled {
            continue;
        }
        let timeout_tx =
            operator_sign_watchtower_challenge_timeout(master.master_keypair(), &mut graph, index)?;
        let timeout_txid = timeout_tx.compute_txid();
        let input_amount = graph.watchtower_challenge_timeouts[index]
            .prev_outs()
            .iter()
            .map(|o| o.value)
            .sum::<Amount>();
        broadcast_tx_with_cpfp(btc, timeout_tx, input_amount).await?;
        info!(event = "graph_challenge", graph_id = %row.graph_id, watchtower_index = index, txid = %timeout_txid, "Watchtower-Challenge-Timeout broadcast");
        sent += 1;
    }
    if sent + pending > 0 {
        return after_blocks(
            deps,
            format!("{sent} watchtower timeouts broadcast, {pending} branches pending"),
            1,
        );
    }
    Step::ignore("every watchtower branch is settled")
}

/// Every watchtower branch resolved: Operator-Commit-Pubin.
async fn commit_pubin(deps: &GraphJobDeps, graph: &BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    let graph_id = graph.parameters.graph_id;
    let wci = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    // Commit-Pubin and Commit-Timeout both spend Connector-E.
    let connector_e =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    if let Some(step) = settled_by(deps, &spend_of(btc, &wci, connector_e).await?, "connector-E") {
        return step;
    }
    let wci_txid = SerializableTxid::from(wci);
    let timeout_txids: Vec<Txid> =
        graph.watchtower_challenge_timeouts.iter().map(|tx| tx.tx().compute_txid()).collect();
    let WatchtowerChallengeInfo {
        included_watchtowers: included_bits, resolved_branch_txids, ..
    } = match get_watchtower_challenge_info(btc, &wci_txid, &timeout_txids, watchtower_num).await {
        Ok(info) => info,
        Err(error) => {
            return after_blocks(deps, format!("challenge info is not ready: {error}"), 1);
        }
    };
    let (best_block_hash, included_bitmap) = match compute_operator_pubin_blockhash_and_bitmap(
        btc,
        &resolved_branch_txids,
        &included_bits,
    )
    .await
    {
        Ok(inputs) => inputs,
        Err(error) => {
            return after_blocks(deps, format!("operator pubin inputs are not ready: {error}"), 1);
        }
    };
    let guest_pubin = build_operator_guest_pubin(
        &best_block_hash,
        &graph.parameters.pubin_disprove_constant,
        &included_bitmap,
    );
    let (master, _) = local_operator()?;
    let wots_secret = master.commit_pubin_wots_keypair_for_graph(graph_id).0;
    let signed_input = operator_sign_commit_pubin(graph, &wots_secret, &guest_pubin)?;
    let connector_e_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow!("failed to get connector-e input: {e}"))?
        .amount;
    let txid = build_sign_and_broadcast_tx(
        btc,
        master.master_keypair(),
        vec![signed_input],
        connector_e_amount,
        vec![],
    )
    .await?;
    info!(event = "graph_challenge", graph_id = %graph_id, txid = %txid, "Operator-Commit-Pubin broadcast");
    broadcast_pending(deps, &format!("Operator-Commit-Pubin {txid}"))
}

/// Watchtower flow over and pubin committed: prove and assert.
async fn prover_assert(deps: &GraphJobDeps, mut graph: BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    // The assert's input on chain (an assert of ours included) ends the job.
    let assert_input = graph
        .operator_assert
        .tx()
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert has no input"))?
        .previous_output;
    if let Some(step) = settled_by(
        deps,
        &spend_of(btc, &assert_input.txid, u64::from(assert_input.vout)).await?,
        "assert input",
    ) {
        return step;
    }
    let (proof, wait_secs) =
        get_operator_proof(&deps.local_db, &deps.http_client, &graph, btc, instance_id, graph_id)
            .await?;
    let Some(proof) = proof else {
        // Not ready yet, never "never": the assert must follow once the proof exists.
        return Step::retry("operator proof is not ready", (wait_secs as i64).max(1));
    };
    let (master, _) = local_operator()?;
    let assert_secret = master.assert_wots_keypair_for_graph(graph_id).0;
    let dynamic_input = operator_assert_dynamic_input(&proof.public_inputs)?;
    let witness = build_assert_witness(&proof.proof, &assert_secret, dynamic_input)?;
    let message = assert_wots_message(&witness)?;
    let mut asserted_proof = Vec::new();
    proof.proof.serialize_compressed(&mut asserted_proof)?;
    let mut setup_state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    if let Some(existing) = &operator_state.asserted_operator_proof
        && existing != &asserted_proof
    {
        bail!("operator assertion proof conflicts with persisted proof");
    }
    operator_state.asserted_operator_proof = Some(asserted_proof);
    save_babe_setup_state(&deps.local_db, instance_id, graph_id, &setup_state)?;
    let assert_tx =
        operator_sign_assert(&mut graph, &assert_secret, &message, &witness.pi2, &witness.pi3)?;
    let input_amount = graph.operator_assert.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    let assert_txid = assert_tx.compute_txid();
    broadcast_tx_with_cpfp(btc, assert_tx, input_amount).await?;
    info!(event = "graph_challenge", graph_id = %graph_id, txid = %assert_txid, "Prover-Assert broadcast");
    broadcast_pending(deps, &format!("Prover-Assert {assert_txid}"))
}

/// Recovers a `BabeChallengeAssertWitness` from the on-chain challenge assert tx.
fn recover_challenge_assert_witness(
    challenge_assert_tx: &bitcoin::Transaction,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    let txin = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("challenge assert tx has no input"))?;
    let items: Vec<Vec<u8>> = txin.witness.to_vec();
    let expected_len = 2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM + 2;
    if items.len() != expected_len {
        bail!(
            "unexpected challenge assert witness length: {} (expected {expected_len})",
            items.len()
        );
    }
    let mut bitcoin_witness = bitcoin::Witness::new();
    for item in &items[..2 * WOTS_SIG_COUNT] {
        bitcoin_witness.push(item);
    }
    let wots_sig = Wots96::raw_witness_to_signature(&bitcoin_witness).to_vec();
    let input_labels: Vec<[u8; 16]> = items
        [2 * WOTS_SIG_COUNT..2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM]
        .iter()
        .map(|item| item.as_slice().try_into())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("challenge assert label item is not 16 bytes"))?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: ChallengeAssertWitnessRaw { input_labels, wots_sig },
    })
}

/// A verifier asserted against the operator's proof: Wrongly-Challenged.
async fn wrongly_challenged(
    deps: &GraphJobDeps,
    graph: &BitvmGcGraph,
    challenge_assert_txid: Txid,
    verifier_index: usize,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    validate_expected_challenge_assert_txid(graph, verifier_index, challenge_assert_txid)?;
    // Wrongly-Challenged and Disprove both spend the ChallengeAssert output:
    // one on chain (ours included) ends the job.
    if let Some(step) = settled_by(
        deps,
        &spend_of(btc, &challenge_assert_txid, 0).await?,
        "verifier assertion output",
    ) {
        return step;
    }
    let Some(challenge_assert_tx) = btc.get_tx(&challenge_assert_txid).await? else {
        return after_blocks(deps, "ChallengeAssert is not available from the Bitcoin backend", 1);
    };
    let challenge_witness = recover_challenge_assert_witness(&challenge_assert_tx, verifier_index)?;
    if challenge_witness.verifier_index != verifier_index {
        bail!(
            "challenge witness verifier index {} does not match {verifier_index}",
            challenge_witness.verifier_index
        );
    }
    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txid = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("published verifier assert transaction has no input"))?
        .previous_output
        .txid;
    let operator_assert_tx = btc.get_tx(&operator_assert_txid).await?.ok_or_else(|| {
        anyhow!("published operator assert transaction {operator_assert_txid} is unavailable")
    })?;
    let operator_assert_txin = operator_assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("published operator assert transaction has no input"))?;
    let operator_assert_witness = extract_operator_assert_witness(graph, &operator_assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let expected =
        build_verifier_assert_tx(graph, operator_assert_txin.clone(), verifier_index, labels)?;
    if expected.input.first().map(|input| &input.witness)
        != challenge_assert_tx.input.first().map(|input| &input.witness)
    {
        bail!("published verifier assert witness does not match BABE challenge labels");
    }
    let setup_state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let candidate = selected_candidate_for_graph_index(&operator_state, verifier_index)?;
    let soldering_proof_ready = candidate.soldering_proof_ready.as_ref().ok_or_else(|| {
        anyhow!("missing soldering proof reference for verifier slot {verifier_index}")
    })?;
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        soldering_proof_ready.candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = read_soldering_proof_store_payload(&payload_path)
        .await
        .with_context(|| format!("read soldering proof payload from {payload_path}"))?;
    let payload = decode_soldering_proof_payload(soldering_proof_ready, &payload)?;
    let (_, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand compact soldering proof payload for challenge")?;
    let prover_state = build_babe_prover_state(&candidate.setup_package, finalized, soldering)?;
    let assert_witness = TxAssertWitness {
        wots_sig: challenge_witness.witness.wots_sig.clone(),
        pi2: operator_assert_witness.pi2,
        pi3: operator_assert_witness.pi3,
    };
    let proof = recover_operator_proof_from_assert_witness(&assert_witness)
        .context("recover asserted operator proof from on-chain assert witness")?;
    let vk = crate::vk::get_vk()
        .await
        .context("load Groth16 verifying key for BABE wrongly challenged")?;
    let (_, dyn_pubin) = assert_witness.try_recover_pi1_xd().ok_or_else(|| {
        anyhow!("cannot recover dynamic input from challenge witness WOTS signature")
    })?;
    let wrongly_challenged_witness = recover_real_wrongly_challenged_witness(
        &prover_state,
        &challenge_witness,
        &proof,
        vk,
        dyn_pubin,
    )?;
    let (input, input_amount) = operator_sign_wrongly_challenged(
        graph,
        verifier_index,
        &wrongly_challenged_witness.final_msg,
    )?;
    let (master, _) = local_operator()?;
    let txid = build_sign_and_broadcast_tx(
        btc,
        master.master_keypair(),
        vec![input],
        input_amount,
        vec![
            goat::scripts::p2a_output(),
            // This makes the non-witness transaction size safely exceed the
            // relay minimum even before the locally funded fee input is added.
            bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: goat::scripts::generate_opreturn_script(
                    WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                ),
            },
        ],
    )
    .await?;
    info!(event = "graph_challenge", graph_id = %graph_id, verifier_index, txid = %txid, "Wrongly-Challenged broadcast");
    broadcast_pending(deps, &format!("Wrongly-Challenged {txid}"))
}

const WRONGLY_CHALLENGED_OP_RETURN_DATA: &[u8] = b"wrongly-challenged";

/// No challenge for `T1` after the kickoff: Take-1.
async fn take1(deps: &GraphJobDeps, row: &Graph, mut graph: BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let connector_a = output_topology::kickoff::connector_a() as u64;
    let guardian = output_topology::kickoff::guardian_connector() as u64;
    for (vout, what) in [(connector_a, "connector-A"), (guardian, "guardian connector")] {
        if let Some(step) = settled_by(deps, &spend_of(btc, &kickoff_txid, vout).await?, what) {
            return step;
        }
    }
    let Some(kickoff_height) = btc.get_tx_status(&kickoff_txid).await?.block_height else {
        return after_blocks(deps, "kickoff is not confirmed yet", 1);
    };
    if !is_take1_timelock_expired(btc, kickoff_height, &graph.parameters.timelock_config).await? {
        return after_blocks(deps, "take-1 timelock has not expired", 1);
    }
    let (master, _) = local_operator()?;
    let take1_tx = operator_sign_take1(master.master_keypair(), &mut graph)?;
    let take1_txid = take1_tx.compute_txid();
    let anchor_vout = take1_tx.output.len() as u64 - 1;
    let input_amount = graph.take1.prev_outs().iter().map(|o| o.value).sum();
    match build_cpfp_txns(btc, &take1_tx, anchor_vout, input_amount).await? {
        Some(child) => broadcast_package(btc, &[take1_tx, child], true).await?,
        None => broadcast_tx(btc, &take1_tx).await?,
    };
    info!(event = "graph_take", graph_id = %row.graph_id, txid = %take1_txid, "Take-1 broadcast");
    broadcast_pending(deps, &format!("Take-1 {take1_txid}"))
}

/// Challenge answered and `T3` / `T7` elapsed: Take-2.
async fn take2(deps: &GraphJobDeps, row: &Graph, mut graph: BitvmGcGraph) -> Result<Step> {
    let btc = &deps.btc_client;
    // Take-2 spends Connector-0, Connector-D, Connector-F and the Guardian
    // Connector: recheck every input before signing.
    for input in graph.take2.tx().input.iter().map(|txin| txin.previous_output) {
        if let Some(step) = settled_by(
            deps,
            &spend_of(btc, &input.txid, u64::from(input.vout)).await?,
            &format!("take-2 input {input}"),
        ) {
            return step;
        }
    }
    let assert_txid = graph.operator_assert.tx().compute_txid();
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let Some(assert_height) = btc.get_tx_status(&assert_txid).await?.block_height else {
        return after_blocks(deps, "prover assert is not confirmed yet", 1);
    };
    let Some(wci_height) = btc.get_tx_status(&wci_txid).await?.block_height else {
        return after_blocks(deps, "watchtower challenge init is not confirmed yet", 1);
    };
    if !is_take2_timelock_expired(btc, assert_height, wci_height, &graph.parameters.timelock_config)
        .await?
    {
        return after_blocks(deps, "take-2 timelock has not expired", 1);
    }
    let (master, _) = local_operator()?;
    let take2_tx = operator_sign_take2(master.master_keypair(), &mut graph)?;
    let take2_txid = take2_tx.compute_txid();
    let anchor_vout = take2_tx.output.len() as u64 - 1;
    let input_amount = graph.take2.prev_outs().iter().map(|o| o.value).sum();
    match build_cpfp_txns(btc, &take2_tx, anchor_vout, input_amount).await? {
        Some(child) => broadcast_package(btc, &[take2_tx, child], true).await?,
        None => broadcast_tx(btc, &take2_tx).await?,
    };
    info!(event = "graph_take", graph_id = %row.graph_id, txid = %take2_txid, "Take-2 broadcast");
    broadcast_pending(deps, &format!("Take-2 {take2_txid}"))
}

// --------------------------------------------------------------- watchtower

fn watchtower_index(graph: &BitvmGcGraph) -> Result<Option<usize>> {
    let keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let local = keypair.public_key().x_only_public_key().0;
    Ok(graph.parameters.watchtower_pubkeys.iter().position(|pubkey| *pubkey == local))
}

/// Watchtower-Challenge-Init confirmed: challenge with the watchtower proof.
async fn watchtower_challenge(
    deps: &GraphJobDeps,
    row: &Graph,
    graph: &BitvmGcGraph,
) -> Result<Step> {
    let btc = &deps.btc_client;
    let Some(index) = watchtower_index(graph)? else {
        return Step::ignore("not a watchtower of this graph");
    };
    let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if !tx_visible(btc, &wci_txid).await? {
        return after_blocks(deps, "watchtower challenge init is not on chain", 1);
    }
    let vout = output_topology::watchtower_challenge_init::watchtower_connector(index) as u64;
    if let Some(step) =
        settled_by(deps, &spend_of(btc, &wci_txid, vout).await?, "watchtower challenge connector")
    {
        return step;
    }
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let proof = match get_watchtower_commitment(
        &deps.local_db,
        btc,
        &deps.http_client,
        instance_id,
        row.graph_id,
    )
    .await?
    {
        (Some(proof), _) => proof,
        (None, wait_secs) => {
            return Step::retry(
                "watchtower proof commitment is not ready",
                (wait_secs as i64).max(1),
            );
        }
    };
    match send_watchtower_challenge_tx(btc, graph, index, proof).await {
        Ok(txid) => {
            info!(event = "graph_challenge", graph_id = %row.graph_id, watchtower_index = index, txid = %txid, "Watchtower-Challenge broadcast");
            broadcast_pending(deps, &format!("Watchtower-Challenge {txid}"))
        }
        Err(error) => Step::retry(format!("watchtower challenge broadcast failed: {error:#}"), 30),
    }
}

/// The operator asserted: stop the watchtower proof this node still waits on.
async fn watchtower_proof_timeout(row: &Graph, graph: &BitvmGcGraph) -> Result<Step> {
    if watchtower_index(graph)?.is_none() {
        return Step::ignore("not a watchtower of this graph");
    }
    let cancelled = notify_watchtower_proof_timeout(row.instance_id, row.graph_id).await?;
    Step::done(GraphPlan::noted(format!("watchtower proof timeout sent: {cancelled}")))
}

// ------------------------------------------------------------------ relayer

/// Kickoff confirmed and covered by the SPV client: `proceedWithdraw`.
/// Blocks a relayer job waits for a lagging Goat node to show the withdraw
/// before it gives up on it.
const WITHDRAW_LAG_RETRIES: i64 = 30;
/// Runs (six blocks apart) a finish job waits for `proceedWithdraw` to land.
const WITHDRAW_PROCEED_RETRIES: i64 = 60;

/// Goat does not show the withdraw: a lagging node (the `InitWithdraw` came
/// from a finalized block) is waited out; a kickoff without a withdraw is
/// given up on with an alert. These jobs run once per graph, so an early
/// `ignore` would leave the Goat side behind for good.
fn withdraw_missing(
    deps: &GraphJobDeps,
    graph_id: Uuid,
    call: &str,
    attempts: i64,
) -> Result<Step> {
    if attempts < WITHDRAW_LAG_RETRIES {
        return after_blocks(deps, format!("withdraw is not visible on Goat yet; {call} waits"), 1);
    }
    warn!(event = "graph_withdraw", graph_id = %graph_id, call, attempts, "withdraw never appeared on Goat; giving up");
    alert("pegout_withdraw_missing");
    Step::ignore(format!("withdraw not on Goat after {attempts} attempts; {call} skipped"))
}

/// `proceedWithdraw` has not landed: wait for it, but not forever.
fn withdraw_not_proceeded(
    deps: &GraphJobDeps,
    graph_id: Uuid,
    call: &str,
    attempts: i64,
) -> Result<Step> {
    if attempts < WITHDRAW_PROCEED_RETRIES {
        return after_blocks(deps, "withdraw is initialized but the kickoff is not posted", 6);
    }
    warn!(event = "graph_withdraw", graph_id = %graph_id, call, attempts, "proceedWithdraw never landed; giving up");
    alert("pegout_withdraw_stuck");
    Step::ignore(format!("withdraw still Initialized after {attempts} attempts; {call} skipped"))
}

/// Goat shows a status the chain contradicts: report it, nothing to send.
fn withdraw_inconsistent(
    graph_id: Uuid,
    call: &str,
    status: WithdrawStatus,
    settled_by: &str,
) -> Result<Step> {
    warn!(event = "graph_withdraw", graph_id = %graph_id, call, status = ?status, "withdraw status on Goat contradicts the {settled_by} on Bitcoin");
    alert("pegout_withdraw_inconsistent");
    Step::ignore(format!("withdraw is {status:?} although {settled_by} confirmed; {call} skipped"))
}

async fn proceed_withdraw(
    deps: &GraphJobDeps,
    row: &Graph,
    graph: &BitvmGcGraph,
    attempts: i64,
) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    let btc = &deps.btc_client;
    let graph_id = graph.parameters.graph_id;
    let withdraw_status = deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    match withdraw_status {
        WithdrawStatus::Initialized => {}
        WithdrawStatus::None if closed(row) => {
            return Step::ignore("graph closed without a withdraw on Goat");
        }
        WithdrawStatus::None => {
            return withdraw_missing(deps, graph_id, "proceedWithdraw", attempts);
        }
        WithdrawStatus::Canceled => {
            // Cancelling needs the committee; a cancelled withdraw is handled by hand.
            info!(event = "graph_withdraw", graph_id = %graph_id, "withdraw cancelled on Goat; nothing to proceed");
            return Step::ignore("withdraw is Canceled");
        }
        other => return Step::ignore(format!("withdraw is already {other:?}")),
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let Some(kickoff_tx) = btc.get_tx(&kickoff_txid).await? else {
        return after_blocks(deps, "kickoff tx is not available", 1);
    };
    let Some(kickoff_height) = btc.get_tx_status(&kickoff_txid).await?.block_height else {
        return after_blocks(deps, "kickoff is not confirmed yet", 1);
    };
    let kickoff_height = u64::from(kickoff_height);
    let spv_height = deps.goat_client.btc_spv_latest_height().await?;
    if spv_height < kickoff_height {
        return after_blocks(
            deps,
            "kickoff block is not available through GOAT SPV",
            kickoff_height - spv_height,
        );
    }
    deps.goat_client.gateway_process_withdraw(btc, &graph_id, &kickoff_tx).await?;
    info!(event = "graph_withdraw", graph_id = %graph_id, "proceedWithdraw sent");
    Step::done(GraphPlan::noted("proceedWithdraw sent"))
}

/// The SPV height covering `txid`, or a retry while it does not.
async fn spv_covered(deps: &GraphJobDeps, txid: &Txid, what: &str) -> Result<Option<Step>> {
    let Some(height) = deps.btc_client.get_tx_status(txid).await?.block_height else {
        return after_blocks(deps, format!("{what} is not confirmed yet"), 1).map(Some);
    };
    let height = u64::from(height);
    let spv_height = deps.goat_client.btc_spv_latest_height().await?;
    if spv_height < height {
        return after_blocks(
            deps,
            format!("{what} block is not available through GOAT SPV"),
            height - spv_height,
        )
        .map(Some);
    }
    Ok(None)
}

/// Take-1 confirmed: `finishWithdrawHappyPath`.
async fn finish_happy(deps: &GraphJobDeps, graph: &BitvmGcGraph, attempts: i64) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    let graph_id = graph.parameters.graph_id;
    let take1_txid = graph.take1.tx().compute_txid();
    let Some(take1_tx) = deps.btc_client.get_tx(&take1_txid).await? else {
        return after_blocks(deps, "take-1 tx is not available", 1);
    };
    let withdraw_status = deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    match withdraw_status {
        WithdrawStatus::Processing => {}
        WithdrawStatus::Initialized => {
            return withdraw_not_proceeded(deps, graph_id, "finishWithdrawHappyPath", attempts);
        }
        WithdrawStatus::None => {
            return withdraw_missing(deps, graph_id, "finishWithdrawHappyPath", attempts);
        }
        WithdrawStatus::Complete => return Step::ignore("withdraw already complete on Goat"),
        other => {
            return withdraw_inconsistent(graph_id, "finishWithdrawHappyPath", other, "Take-1");
        }
    }
    if let Some(retry) = spv_covered(deps, &take1_txid, "take-1").await? {
        return Ok(retry);
    }
    deps.goat_client
        .gateway_finish_withdraw_happy_path(&deps.btc_client, &graph_id, &take1_tx)
        .await?;
    info!(event = "graph_withdraw", graph_id = %graph_id, "finishWithdrawHappyPath sent");
    Step::done(GraphPlan::noted("finishWithdrawHappyPath sent"))
}

/// Take-2 confirmed: `finishWithdrawUnhappyPath`.
async fn finish_unhappy(deps: &GraphJobDeps, graph: &BitvmGcGraph, attempts: i64) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    let graph_id = graph.parameters.graph_id;
    let take2_txid = graph.take2.tx().compute_txid();
    let Some(take2_tx) = deps.btc_client.get_tx(&take2_txid).await? else {
        return after_blocks(deps, "take-2 tx is not available", 1);
    };
    let withdraw_status = deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    match withdraw_status {
        WithdrawStatus::Processing => {}
        WithdrawStatus::Initialized => {
            return withdraw_not_proceeded(deps, graph_id, "finishWithdrawUnhappyPath", attempts);
        }
        WithdrawStatus::None => {
            return withdraw_missing(deps, graph_id, "finishWithdrawUnhappyPath", attempts);
        }
        WithdrawStatus::Complete => return Step::ignore("withdraw already complete on Goat"),
        other => {
            return withdraw_inconsistent(graph_id, "finishWithdrawUnhappyPath", other, "Take-2");
        }
    }
    if let Some(retry) = spv_covered(deps, &take2_txid, "take-2").await? {
        return Ok(retry);
    }
    deps.goat_client
        .gateway_finish_withdraw_unhappy_path(&deps.btc_client, &graph_id, &take2_tx)
        .await?;
    info!(event = "graph_withdraw", graph_id = %graph_id, "finishWithdrawUnhappyPath sent");
    Step::done(GraphPlan::noted("finishWithdrawUnhappyPath sent"))
}

/// A challenge succeeded on Bitcoin: `finishWithdrawDisproved`.
async fn finish_disproved(
    deps: &GraphJobDeps,
    graph: &BitvmGcGraph,
    disprove_type: DisproveTxType,
    index: usize,
    challenge_finish_txid: Txid,
    attempts: i64,
) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    let btc = &deps.btc_client;
    let graph_id = graph.parameters.graph_id;
    let withdraw_status = deps.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    match withdraw_status {
        WithdrawStatus::Disproved => return Step::ignore("already disproved on Goat"),
        WithdrawStatus::None => {
            return withdraw_missing(deps, graph_id, "finishWithdrawDisproved", attempts);
        }
        _ => {}
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let take1_txid = graph.take1.tx().compute_txid();
    let connector_a = output_topology::kickoff::connector_a() as u64;
    let challenge_start_tx = match outpoint_spent_txid(btc, &kickoff_txid, connector_a).await? {
        Some(spent_txid) if spent_txid == take1_txid => {
            return Step::ignore(format!("graph already settled by Take-1 {spent_txid}"));
        }
        Some(spent_txid) => btc.get_tx(&spent_txid).await?,
        None => None,
    };
    let Some(challenge_finish_tx) = btc.get_tx(&challenge_finish_txid).await? else {
        return after_blocks(
            deps,
            format!("challenge finish tx {challenge_finish_txid} is not available"),
            1,
        );
    };
    if let Some(retry) = spv_covered(deps, &challenge_finish_txid, "challenge finish").await? {
        return Ok(retry);
    }
    let result = deps
        .goat_client
        .gateway_finish_withdraw_disproved(
            btc,
            &graph_id,
            disprove_type,
            index as u64,
            challenge_start_tx.as_ref(),
            &challenge_finish_tx,
        )
        .await;
    deps.metrics_state.record_withdraw_finalize(result.is_ok());
    result?;
    info!(event = "graph_withdraw", graph_id = %graph_id, disprove_type = %disprove_type, index, "finishWithdrawDisproved sent");
    Step::done(GraphPlan::noted("finishWithdrawDisproved sent"))
}

// -------------------------------------------------------------- validation

fn validate_watchtower_branches(graph: &BitvmGcGraph) -> Result<usize> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if watchtower_num == 0 {
        bail!("graph has no watchtower slots");
    }
    if graph.parameters.watchtower_ack_hashlocks.len() != watchtower_num
        || graph.watchtower_challenge_timeouts.len() != watchtower_num
        || graph.operator_challenge_nacks.len() != watchtower_num
    {
        bail!(
            "graph watchtower branch lengths differ: watchtowers={}, ack_hashlocks={}, timeouts={}, nacks={}",
            watchtower_num,
            graph.parameters.watchtower_ack_hashlocks.len(),
            graph.watchtower_challenge_timeouts.len(),
            graph.operator_challenge_nacks.len()
        );
    }
    Ok(watchtower_num)
}

fn validate_expected_challenge_assert_txid(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    challenge_assert_txid: Txid,
) -> Result<()> {
    validate_verifier_slot(graph, verifier_index)?;
    let expected_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
    if challenge_assert_txid != expected_txid {
        bail!(
            "challenge assert txid {challenge_assert_txid} does not match graph verifier assert txid {expected_txid}"
        );
    }
    Ok(())
}

/// The on-chain ACK inputs of every watchtower that ACKed.
async fn collect_ack_txins(
    btc_client: &client::btc_chain::BTCClient,
    wci_txid: &Txid,
    watchtower_timeout_txids: &[Txid],
) -> Result<Vec<bitcoin::TxIn>> {
    let mut ack_txins = Vec::new();
    for (i, timeout_txid) in watchtower_timeout_txids.iter().enumerate() {
        let ack_vout = output_topology::watchtower_challenge_init::ack_connector(i) as u64;
        let Some(ack_spent_txid) = outpoint_spent_txid(btc_client, wci_txid, ack_vout).await?
        else {
            continue;
        };
        if &ack_spent_txid == timeout_txid {
            continue;
        }
        let Some((_, _, txin)) = outpoint_spent_txin(btc_client, wci_txid, ack_vout).await? else {
            bail!("ACK spending tx {ack_spent_txid} for watchtower {i} is unavailable");
        };
        ack_txins.push(txin);
    }
    Ok(ack_txins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    // ── collect_ack_txins ─────────────────────────────────────────────────────

    fn make_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn make_confirmed_ack_tx(ack_txid: Txid, wci_txid: Txid, ack_vout: u32) -> esplora_client::Tx {
        use esplora_client::{TxStatus, Vin};
        let preimage = b"test-ack-preimage".to_vec();
        esplora_client::Tx {
            txid: ack_txid,
            version: 2,
            locktime: 0,
            vin: vec![Vin {
                txid: wci_txid,
                vout: ack_vout,
                prevout: None,
                scriptsig: bitcoin::ScriptBuf::default(),
                witness: vec![preimage],
                sequence: 1,
                is_coinbase: false,
            }],
            vout: vec![],
            size: 1,
            weight: 1,
            status: TxStatus {
                confirmed: true,
                block_height: Some(800_000),
                block_hash: None,
                block_time: Some(1_000_000),
            },
            fee: 0,
        }
    }

    #[tokio::test]
    async fn collect_ack_txins_returns_only_spent_connectors() {
        let (btc_client, mock) = client::btc_chain::BTCClient::new_mock_client();
        let wci_txid = make_txid(0x00);
        let ack_txid_0 = make_txid(0x01);
        let timeout_txid_1 = make_txid(0x03);
        let timeout_txids = vec![make_txid(0x10), timeout_txid_1, make_txid(0x12)];

        // Watchtower 0 ACKed
        let vout_0 = output_topology::watchtower_challenge_init::ack_connector(0) as u32;
        mock.set_tx(ack_txid_0, make_confirmed_ack_tx(ack_txid_0, wci_txid, vout_0));

        // Watchtower 1 timed out; the timeout spend must not count as an ACK.
        let vout_1 = output_topology::watchtower_challenge_init::ack_connector(1) as u32;
        mock.set_tx(timeout_txid_1, make_confirmed_ack_tx(timeout_txid_1, wci_txid, vout_1));

        // Watchtower 2 ACKed
        let ack_txid_2 = make_txid(0x02);
        let vout_2 = output_topology::watchtower_challenge_init::ack_connector(2) as u32;
        mock.set_tx(ack_txid_2, make_confirmed_ack_tx(ack_txid_2, wci_txid, vout_2));

        let txins = collect_ack_txins(&btc_client, &wci_txid, &timeout_txids).await.unwrap();

        assert_eq!(txins.len(), 2);
        assert_eq!(txins[0].previous_output.vout, vout_0);
        assert_eq!(txins[1].previous_output.vout, vout_2);
    }

    // ── recover_challenge_assert_witness ──────────────────────────────────────

    fn build_challenge_assert_tx(
        sig: &<Wots96 as Wots>::Signature,
        labels: &[[u8; 16]],
    ) -> bitcoin::Transaction {
        let mut witness = bitcoin::Witness::new();
        let raw_wots = Wots96::signature_to_raw_witness(sig);
        for item in raw_wots.iter() {
            witness.push(item);
        }
        for label in labels {
            witness.push(label.as_slice());
        }
        witness.push([0xde, 0xad]); // placeholder script
        witness.push([0xbe, 0xef]); // placeholder control block
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn { witness, ..Default::default() }],
            output: vec![],
        }
    }

    #[test]
    fn recover_challenge_assert_witness_extracts_wots_sig_and_labels() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-challenge-witness");
        let msg = [0x42u8; 96];
        let sig = Wots96::sign(&sk, &msg);

        let labels: Vec<[u8; 16]> =
            (0..goat::assert_scripts::INPUT_WIRE_NUM).map(|i| [(i % 256) as u8; 16]).collect();

        let tx = build_challenge_assert_tx(&sig, &labels);
        let verifier_index = 3;
        let recovered = recover_challenge_assert_witness(&tx, verifier_index).unwrap();

        assert_eq!(recovered.verifier_index, verifier_index);
        assert_eq!(recovered.witness.wots_sig.len(), WOTS_SIG_COUNT);
        assert_eq!(recovered.witness.input_labels.len(), goat::assert_scripts::INPUT_WIRE_NUM);

        let mut bw = bitcoin::Witness::new();
        for item in Wots96::signature_to_raw_witness(&sig).iter() {
            bw.push(item);
        }
        assert_eq!(recovered.witness.wots_sig, Wots96::raw_witness_to_signature(&bw).to_vec());

        // labels are correctly extracted
        for (i, label) in recovered.witness.input_labels.iter().enumerate() {
            assert_eq!(label[0], (i % 256) as u8, "label {i} mismatch");
        }
    }

    #[test]
    fn recover_challenge_assert_witness_rejects_wrong_length() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-wrong-len");
        let sig = Wots96::sign(&sk, &[0u8; 96]);
        let labels: Vec<[u8; 16]> = vec![[0u8; 16]; goat::assert_scripts::INPUT_WIRE_NUM];

        // one label short
        let mut short_labels = labels.clone();
        short_labels.pop();
        let bad_tx = build_challenge_assert_tx(&sig, &short_labels);
        assert!(recover_challenge_assert_witness(&bad_tx, 0).is_err());

        // no inputs at all
        let empty_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(recover_challenge_assert_witness(&empty_tx, 0).is_err());
    }

    #[test]
    fn wrongly_challenge_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "wrongly-challenge transaction is {} non-witness bytes",
            tx.base_size()
        );
    }

    #[test]
    fn pubin_disprove_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "pubin-disprove transaction is {} non-witness bytes",
            tx.base_size()
        );
    }
}
