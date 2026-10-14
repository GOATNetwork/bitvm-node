//! Collect graph chain facts outside the apply transaction.
//!
//! Maintenance scans active graphs once per Bitcoin height and stored status;
//! Obsoleted graphs only get a cheap probe until their Pre-Kickoff confirms.
//! Each result becomes a `chain_scan` event. Operator nodes also report setups
//! unfinished at their instance's abandon height.

use super::graph::{SetupAbandoned, setup_abandoned_event};
use super::graph_pegout::{ChainScan, PegoutSignal, Unusable};
use super::instance::PeginDeadlines;
use crate::env::{get_network, get_node_pubkey};
use crate::rpc_service::current_time_secs;
use crate::utils::{
    GraphChainScan, load_validated_graph_definition, outpoint_spent_confirmed, outpoint_spent_txid,
    scan_graph_chain_state,
};
use bitcoin::{OutPoint, Txid};
use bitvm_lib::timelocks::{
    connector_f_timelock_blocks, disprove_timelock_blocks, operator_ack_timelock_blocks,
    operator_commit_timelock_blocks, take1_timelock_blocks, take2_timelock_blocks,
    validate_timelock_config, watchtower_challenge_timelock_blocks,
};
use bitvm_lib::types::BitvmGcGraph;
use client::btc_chain::BTCClient;
use client::goat_chain::{DisproveTxType, GOATClient};
use engine::EngineHandle;
use goat::constants::TimelockConfig;
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use store::localdb::{GraphQuery, LocalDB};
use store::{Graph, GraphBtcTxVoutMonitor, GraphStatus, InstanceBridgeInStatus, SerializableTxid};
use strum::{Display, EnumString};
use tracing::{debug, trace, warn};
use uuid::Uuid;

/// Graphs scanned per tick; the rest follow on the next ticks, which resume
/// after the slot the previous tick stopped at and wrap around, so no graph
/// starves at a height when there are more graphs than one tick covers.
const SCAN_BATCH: usize = 64;
/// Obsoleted graphs probed per tick, in their own rotation so they never hold
/// the active graphs back.
const OBSOLETED_SCAN_BATCH: usize = 16;
/// Every this many heights an Obsoleted graph gets a full scan anyway, so a
/// dead Pre-Kickoff input is still noticed and recorded for the later slots.
const OBSOLETED_FULL_SCAN_EVERY: i64 = 16;
const SCAN_MARKS_LIMIT: usize = 50_000;

const MONITOR_KICKOFF: &str = "kickoff";
const MONITOR_WATCHTOWER_INIT: &str = "watchtower_init";
const MONITOR_PROVER_ASSERT: &str = "prover_assert";
const MONITOR_VERIFIER_ASSERT: &str = "verifier_assert";

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum VerifierChallengeStatus {
    #[default]
    None,
    VerifierAsserted,
    ProverAnswered,
    Disproved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: Vec<bool>, // true for challenge connector spend
    pub verifier_challenge_status: Vec<VerifierChallengeStatus>,
    pub disprove_type: Option<DisproveTxType>,
    pub disprove_index: i32,
}

// ------------------------------------------------------------------- marks

/// `(height, status)` of the last scan recorded per graph: a scan at the same
/// tip for the same status would repeat the same facts.
static SCAN_MARKS: LazyLock<Mutex<HashMap<Uuid, (i64, GraphStatus)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The slot `(operator_pubkey, kickoff_index)` the last tick stopped at, for
/// the active graphs and for the Obsoleted ones.
static SCAN_CURSOR: LazyLock<Mutex<Option<(String, i64)>>> = LazyLock::new(|| Mutex::new(None));
static OBSOLETED_SCAN_CURSOR: LazyLock<Mutex<Option<(String, i64)>>> =
    LazyLock::new(|| Mutex::new(None));

/// Where a scan over `slots` (sorted by operator and nonce) resumes: the
/// first slot after `cursor`, or the start when the cursor is unset or past
/// the last slot.
fn resume_index(slots: &[(String, i64)], cursor: Option<&(String, i64)>) -> usize {
    let Some(cursor) = cursor else { return 0 };
    slots.iter().position(|slot| slot > cursor).unwrap_or(0)
}

fn already_scanned(graph_id: Uuid, height: i64, status: GraphStatus) -> bool {
    let marks = SCAN_MARKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    marks.get(&graph_id).is_some_and(|mark| *mark == (height, status))
}

fn mark_scanned(graph_id: Uuid, height: i64, status: GraphStatus) {
    let mut marks = SCAN_MARKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if marks.len() >= SCAN_MARKS_LIMIT {
        marks.clear();
    }
    marks.insert(graph_id, (height, status));
}

/// Lowest slot per operator whose Pre-Kickoff can never confirm. The later
/// slots extend it, so their own scans report it too and keep them Obsoleted
/// instead of following their own unspent outpoints. Graphs are scanned
/// lowest slot first, which rebuilds the map after a restart.
static DEAD_SLOTS: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn dead_slot_below(operator_pubkey: &str, slot: u64) -> Option<u64> {
    let dead = DEAD_SLOTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    dead.get(operator_pubkey).copied().filter(|dead| *dead < slot)
}

fn record_dead_slot(operator_pubkey: &str, slot: u64) {
    let mut dead = DEAD_SLOTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let lowest = dead.entry(operator_pubkey.to_string()).or_insert(slot);
    *lowest = (*lowest).min(slot);
}

/// Statuses with something left to happen on chain: everything but closed.
fn monitored_statuses() -> Vec<String> {
    use GraphStatus::*;
    [
        OperatorPresigned,
        CommitteePresigned,
        OperatorDataPushed,
        PreKickoff,
        OperatorKickOff,
        Challenge,
        Obsoleted,
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}

/// Record a chain scan for every monitored graph not yet scanned at this
/// height, the operator's lower slots first.
pub async fn scan_graphs_on_chain(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    engine: &EngineHandle,
) -> anyhow::Result<()> {
    let graphs = local_db
        .acquire()
        .await?
        .get_operator_graphs(
            GraphQuery::default()
                .with_statuses(monitored_statuses())
                .with_order("operator_pubkey, kickoff_index".to_string()),
        )
        .await?;
    if graphs.is_empty() {
        return Ok(());
    }
    let height = i64::from(btc_client.get_height().await?);
    let (obsoleted, active): (Vec<Graph>, Vec<Graph>) =
        graphs.into_iter().partition(|row| row.status == GraphStatus::Obsoleted.to_string());
    let scan = ScanPass { local_db, btc_client, goat_client, engine, height };
    scan.rows(&active, SCAN_BATCH, &SCAN_CURSOR, false).await?;
    scan.rows(&obsoleted, OBSOLETED_SCAN_BATCH, &OBSOLETED_SCAN_CURSOR, true).await
}

struct ScanPass<'a> {
    local_db: &'a LocalDB,
    btc_client: &'a BTCClient,
    goat_client: &'a GOATClient,
    engine: &'a EngineHandle,
    height: i64,
}

impl ScanPass<'_> {
    /// Scan up to `batch` of `graphs`, resuming after the slot `cursor` points
    /// at. The cursor moves per graph, so a tick cut short by the maintenance
    /// timeout resumes where it stopped instead of restarting at the same slot.
    async fn rows(
        &self,
        graphs: &[Graph],
        batch: usize,
        cursor: &Mutex<Option<(String, i64)>>,
        obsoleted: bool,
    ) -> anyhow::Result<()> {
        if graphs.is_empty() {
            return Ok(());
        }
        let slots: Vec<(String, i64)> =
            graphs.iter().map(|row| (row.operator_pubkey.clone(), row.kickoff_index)).collect();
        let start = {
            let cursor = cursor.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            resume_index(&slots, cursor.as_ref())
        };
        let mut scanned = 0;
        for offset in 0..graphs.len() {
            if scanned >= batch {
                break;
            }
            let index = (start + offset) % graphs.len();
            let row = &graphs[index];
            *cursor.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(slots[index].clone());
            let Ok(status) = GraphStatus::from_str(&row.status) else {
                continue;
            };
            if already_scanned(row.graph_id, self.height, status) {
                continue;
            }
            scanned += 1;
            if obsoleted && self.height % OBSOLETED_FULL_SCAN_EVERY != 0 {
                match prekickoff_confirmed(self.btc_client, row).await {
                    Ok(true) => {}
                    Ok(false) => {
                        mark_scanned(row.graph_id, self.height, status);
                        continue;
                    }
                    Err(error) => {
                        warn!(event = "graph_scan", graph_id = %row.graph_id, status = %status, height = self.height, error = %error, "pre-kickoff probe failed; retried on the next tick");
                        continue;
                    }
                }
            }
            match gather_chain_scan(
                self.local_db,
                self.btc_client,
                self.goat_client,
                row,
                status,
                self.height,
            )
            .await
            {
                Ok(Some(scan)) => {
                    self.engine.submit(scan.event(row.graph_id)?).await?;
                    mark_scanned(row.graph_id, self.height, status);
                }
                Ok(None) => mark_scanned(row.graph_id, self.height, status),
                Err(error) => warn!(
                    event = "graph_scan",
                    graph_id = %row.graph_id,
                    status = %status,
                    height = self.height,
                    error = %error,
                    "chain scan failed; retried on the next tick"
                ),
            }
        }
        Ok(())
    }
}

/// Nothing happens on chain for an Obsoleted graph until its Pre-Kickoff
/// confirms (a Skip-Kickoff needs it, and a confirmed Pre-Kickoff makes the
/// graph live again), so that is all the regular probe asks.
async fn prekickoff_confirmed(btc_client: &BTCClient, row: &Graph) -> anyhow::Result<bool> {
    let Some(txid) = row.cur_prekickoff_txid.clone() else {
        return Ok(false);
    };
    Ok(btc_client.get_tx_status(&Txid::from(txid)).await?.confirmed)
}

/// Report operator setups unfinished at the abandon height, including pending
/// sessions and built graphs without committee pre-signatures. Failed instances
/// are handled by their own cleanup.
pub async fn abandon_unfinished_setups(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    engine: &EngineHandle,
) -> anyhow::Result<()> {
    let operator_pubkey = get_node_pubkey()?.to_string();
    let setups: BTreeMap<Uuid, Uuid> = {
        let mut storage = local_db.acquire().await?;
        let sessions = storage.list_pending_graph_inits_by_operator(&operator_pubkey).await?;
        let graphs = storage
            .get_operator_graphs(
                GraphQuery::default()
                    .with_operator_pubkey(operator_pubkey)
                    .with_statuses(vec![GraphStatus::OperatorPresigned.to_string()]),
            )
            .await?;
        sessions
            .into_iter()
            .map(|session| (session.graph_id, session.instance_id))
            .chain(graphs.into_iter().map(|graph| (graph.graph_id, graph.instance_id)))
            .collect()
    };
    if setups.is_empty() {
        return Ok(());
    }
    let height = i64::from(btc_client.get_height().await?);
    let deadlines = PeginDeadlines::from_env();
    for (graph_id, instance_id) in setups {
        let Some(instance) = local_db.acquire().await?.find_instance(&instance_id).await? else {
            continue;
        };
        if InstanceBridgeInStatus::from_str(&instance.status).is_ok_and(|status| status.is_failed())
        {
            continue;
        }
        if let Some(abandon_height) = deadlines.abandon_height(instance.btc_height)
            && height >= abandon_height
        {
            let abandoned = SetupAbandoned { instance_id, abandon_height, height };
            engine.submit(setup_abandoned_event(graph_id, &abandoned)?).await?;
        }
    }
    Ok(())
}

/// The facts of one graph at `height`; `None` when its definition is not
/// stored (nothing on chain can be decided without it).
pub async fn gather_chain_scan(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    row: &Graph,
    status: GraphStatus,
    height: i64,
) -> anyhow::Result<Option<ChainScan>> {
    let definition = {
        let mut storage = local_db.acquire().await?;
        load_validated_graph_definition(&mut storage, row.instance_id, row.graph_id).await?
    };
    let Some(definition) = definition else {
        return Ok(None);
    };
    let graph = BitvmGcGraph::from_simplified(&definition)?;
    let chain = scan_graph_chain_state(btc_client, goat_client, &graph).await?;
    let unusable = if before_prekickoff(chain.status) {
        unusable_fact(btc_client, &graph, row).await?
    } else {
        None
    };
    let mut signals = stage_signals(&chain);
    match chain.status {
        GraphStatus::OperatorKickOff => {
            let timelocks = graph_timelocks(&graph)?;
            if let Some(signal) = take1_ready(btc_client, local_db, row, &timelocks, height).await?
            {
                signals.push(signal);
            }
        }
        GraphStatus::Challenge => {
            let timelocks = graph_timelocks(&graph)?;
            signals.extend(challenge_signals(btc_client, local_db, row, &timelocks, height).await?);
        }
        _ => {}
    }
    signals.dedup();
    let scan = ChainScan {
        height,
        status_at_scan: status.to_string(),
        stage: chain.status,
        sub_status: Some(serde_json::to_string(&chain.sub_status)?),
        challenge_txid: chain.challenge_txid,
        unusable,
        signals,
    };
    debug!(
        event = "graph_scan",
        graph_id = %row.graph_id,
        status = %status,
        stage = %scan.stage,
        height,
        unusable = ?scan.unusable,
        signals = ?scan.signals,
        "chain scan"
    );
    Ok(Some(scan))
}

/// Pre-Kickoff of the graph is not on chain yet.
fn before_prekickoff(stage: GraphStatus) -> bool {
    matches!(
        stage,
        GraphStatus::OperatorPresigned
            | GraphStatus::CommitteePresigned
            | GraphStatus::OperatorDataPushed
    )
}

/// A chain fact that rules the graph out before its Pre-Kickoff confirms.
async fn unusable_fact(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    row: &Graph,
) -> anyhow::Result<Option<Unusable>> {
    let slot = row.kickoff_index as u64;
    if let Some(dead) = dead_slot_below(&row.operator_pubkey, slot) {
        return Ok(Some(Unusable::EarlierSlotDead { slot: dead }));
    }
    if let Some((outpoint, spent_by)) = prekickoff_input_spent(btc_client, graph).await? {
        record_dead_slot(&row.operator_pubkey, slot);
        return Ok(Some(Unusable::PrekickoffInputSpent { outpoint, spent_by }));
    }
    Ok(connector_zero_taken(btc_client, graph)
        .await?
        .map(|spent_by| Unusable::ConnectorZeroTaken { spent_by }))
}

/// An input of the graph's Pre-Kickoff spent by another confirmed
/// transaction: the Pre-Kickoff can never confirm. A conflicting spend still
/// in the mempool may never confirm, and what follows is irreversible.
pub async fn prekickoff_input_spent(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> anyhow::Result<Option<(OutPoint, Txid)>> {
    let prekickoff = graph.cur_prekickoff.tx();
    let prekickoff_txid = prekickoff.compute_txid();
    for input in &prekickoff.input {
        let outpoint = input.previous_output;
        if let Some(spent_by) =
            outpoint_spent_txid(btc_client, &outpoint.txid, u64::from(outpoint.vout)).await?
            && spent_by != prekickoff_txid
            && btc_client.get_tx_status(&spent_by).await?.confirmed
        {
            return Ok(Some((outpoint, spent_by)));
        }
    }
    Ok(None)
}

/// Connector-0 spent by a confirmed transaction other than this graph's
/// Take-1 / Take-2: another graph of the instance took the peg-in.
pub async fn connector_zero_taken(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> anyhow::Result<Option<Txid>> {
    let Some(input) = graph.take1.tx().input.first() else {
        return Ok(None);
    };
    let outpoint = input.previous_output;
    let take1 = graph.take1.tx().compute_txid();
    let take2 = graph.take2.tx().compute_txid();
    let Some(spent_by) = outpoint_spent_txid(btc_client, &outpoint.txid, u64::from(outpoint.vout))
        .await?
        .filter(|spent_by| *spent_by != take1 && *spent_by != take2)
    else {
        return Ok(None);
    };
    Ok(btc_client.get_tx_status(&spent_by).await?.confirmed.then_some(spent_by))
}

/// Signals implied by chain progress, including stages crossed between scans.
fn stage_signals(chain: &GraphChainScan) -> Vec<PegoutSignal> {
    use GraphStatus::*;
    let stage = chain.status;
    let mut signals = Vec::new();
    if !before_prekickoff(stage) {
        signals.push(PegoutSignal::PreKickoffSent);
    }
    if matches!(stage, OperatorKickOff | Challenge | Disprove | OperatorTake1 | OperatorTake2) {
        signals.push(PegoutSignal::KickoffSent);
    }
    if let Some(challenge_txid) = chain.challenge_txid {
        signals.push(PegoutSignal::ChallengeSent { challenge_txid });
    }
    match stage {
        OperatorTake1 => signals.push(PegoutSignal::Take1Sent),
        OperatorTake2 => signals.push(PegoutSignal::Take2Sent),
        Disprove => {
            if let Some(disprove) = &chain.disprove {
                signals.push(PegoutSignal::DisproveSent {
                    disprove_type: disprove.disprove_type,
                    index: disprove.index,
                    challenge_finish_txid: disprove.challenge_finish_txid,
                });
            }
        }
        _ => {}
    }
    signals
}

fn graph_timelocks(graph: &BitvmGcGraph) -> anyhow::Result<TimelockConfig> {
    validate_timelock_config(
        graph.parameters.instance_parameters.network,
        &graph.parameters.timelock_config,
    )?;
    Ok(graph.parameters.timelock_config)
}

fn is_timelock_ready(confirmed_height: i64, lock_blocks: i64, current_height: i64) -> bool {
    confirmed_height > 0 && confirmed_height + lock_blocks <= current_height
}

/// Confirmation height of a transaction, cached in the graph's monitor table.
async fn confirmed_monitor(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_id: Uuid,
    txid: Txid,
    tx_name: String,
) -> anyhow::Result<Option<GraphBtcTxVoutMonitor>> {
    let txid_serial = SerializableTxid::from(txid);
    let existing = {
        let mut storage = local_db.acquire().await?;
        storage.find_graph_btc_tx_vout_monitor(&graph_id, &txid_serial).await?
    };
    if let Some(existing) = existing
        && existing.height > 0
        && existing.vout_len > 0
    {
        return Ok(Some(existing));
    }
    let Some(tx_info) = btc_client.get_tx_info(&txid).await? else {
        return Ok(None);
    };
    let height = tx_info.status.block_height.unwrap_or_default() as i64;
    if height <= 0 {
        return Ok(None);
    }
    let now = current_time_secs();
    let monitor = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name,
        txid: txid_serial,
        height,
        vout_len: tx_info.vout.len() as i64,
        monitor_data: String::new(),
        created_at: now,
        updated_at: now,
    };
    local_db.acquire().await?.upsert_graph_btc_tx_vout_monitor(&monitor).await?;
    Ok(Some(monitor))
}

/// Kicked off, Connector-A and the Guardian Connector unspent, `T1` elapsed.
async fn take1_ready(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
    timelocks: &TimelockConfig,
    height: i64,
) -> anyhow::Result<Option<PegoutSignal>> {
    let Some(kickoff_txid) = row.kickoff_txid.clone().map(Txid::from) else {
        warn!(graph_id = %row.graph_id, "kickoff txid is missing");
        return Ok(None);
    };
    let connector_a = output_topology::kickoff::connector_a() as u64;
    let guardian = output_topology::kickoff::guardian_connector() as u64;
    if outpoint_spent_txid(btc_client, &kickoff_txid, connector_a).await?.is_some()
        || outpoint_spent_txid(btc_client, &kickoff_txid, guardian).await?.is_some()
    {
        return Ok(None);
    }
    let Some(kickoff) = confirmed_monitor(
        btc_client,
        local_db,
        row.graph_id,
        kickoff_txid,
        MONITOR_KICKOFF.to_string(),
    )
    .await?
    else {
        return Ok(None);
    };
    let lock_blocks = take1_timelock_blocks(get_network(), timelocks) as i64;
    Ok(is_timelock_ready(kickoff.height, lock_blocks, height).then_some(PegoutSignal::Take1Ready))
}

/// The challenge sub-flows of a graph in Challenge: watchtower branches,
/// commit-pubin, asserts, and Take-2.
async fn challenge_signals(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
    timelocks: &TimelockConfig,
    height: i64,
) -> anyhow::Result<Vec<PegoutSignal>> {
    let mut signals = watchtower_flow(btc_client, local_db, row, timelocks, height).await?;
    signals.extend(assert_flow(btc_client, local_db, row).await?);
    signals.extend(wrongly_challenge_timeout(btc_client, local_db, row, timelocks, height).await?);
    if take2_ready(btc_client, local_db, row, timelocks, height).await? {
        signals.push(PegoutSignal::Take2Ready);
    }
    Ok(signals)
}

/// Watchtower-Challenge-Init and its branches: each watchtower challenged,
/// timed out, ACKed or NACKed; then commit-pubin and the operator's assert.
async fn watchtower_flow(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
    timelocks: &TimelockConfig,
    height: i64,
) -> anyhow::Result<Vec<PegoutSignal>> {
    let Some(wci_txid) = row.watchtower_challenge_init_txid.clone().map(Txid::from) else {
        return Ok(Vec::new());
    };
    let Some(monitor) = confirmed_monitor(
        btc_client,
        local_db,
        row.graph_id,
        wci_txid,
        MONITOR_WATCHTOWER_INIT.to_string(),
    )
    .await?
    else {
        trace!(graph_id = %row.graph_id, "watchtower challenge init not confirmed");
        return Ok(Vec::new());
    };
    let mut signals = vec![PegoutSignal::WatchtowerChallengeInitSent];
    let watchtower_num = output_topology::watchtower_challenge_init::watchtower_num(
        monitor.vout_len.max(0) as usize,
    );
    if watchtower_num == 0 {
        return Ok(signals);
    }
    let network = get_network();
    let connector_e =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    let connector_e_spent = outpoint_spent_txid(btc_client, &wci_txid, connector_e).await?;
    let connector_f_spent = outpoint_spent_txid(btc_client, &wci_txid, connector_f).await?;
    let commit_timeout_txid: Option<Txid> =
        row.operator_commit_timeout_txid.clone().map(Into::into);
    let commit_timed_out = matches!(
        (connector_e_spent.as_ref(), commit_timeout_txid.as_ref()),
        (Some(spent), Some(timeout)) if spent == timeout
    );
    let pubin_committed = connector_e_spent.is_some() && !commit_timed_out;

    let mut all_resolved = true;
    let mut timeout_ready = false;
    let mut nack_ready = Vec::new();
    for index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(index) as u64;
        let ack_vout = output_topology::watchtower_challenge_init::ack_connector(index) as u64;
        let watchtower_spent = outpoint_spent_txid(btc_client, &wci_txid, watchtower_vout).await?;
        let ack_spent = outpoint_spent_txid(btc_client, &wci_txid, ack_vout).await?;
        let timeout_txid: Option<Txid> =
            row.watchtower_challenge_timeout_txids.get(index).cloned().map(Into::into);
        let watchtower_confirmed = match watchtower_spent.as_ref() {
            Some(txid) => btc_client.get_tx_status(txid).await?.confirmed,
            None => false,
        };
        let ack_confirmed = match ack_spent.as_ref() {
            Some(txid) => btc_client.get_tx_status(txid).await?.confirmed,
            None => false,
        };
        let timed_out = matches!(
            (watchtower_spent.as_ref(), timeout_txid.as_ref()),
            (Some(spent), Some(timeout)) if spent == timeout && watchtower_confirmed
        );
        match watchtower_spent {
            Some(_) if !watchtower_confirmed => all_resolved = false,
            Some(_) if !timed_out => {
                signals.push(PegoutSignal::WatchtowerChallengeSent { watchtower_index: index });
                if !ack_confirmed {
                    all_resolved = false;
                    if connector_f_spent.is_none()
                        && ack_spent.is_none()
                        && is_timelock_ready(
                            monitor.height,
                            operator_ack_timelock_blocks(network, timelocks) as i64,
                            height,
                        )
                    {
                        nack_ready.push(index);
                    }
                }
            }
            Some(_) => {}
            None => {
                all_resolved = false;
                if ack_spent.is_none()
                    && is_timelock_ready(
                        monitor.height,
                        watchtower_challenge_timelock_blocks(network, timelocks) as i64,
                        height,
                    )
                {
                    timeout_ready = true;
                }
            }
        }
    }
    if timeout_ready {
        signals.push(PegoutSignal::WatchtowerChallengeTimeout);
    }
    for watchtower_index in nack_ready {
        signals.push(PegoutSignal::NackReady { watchtower_index });
    }
    if all_resolved && connector_e_spent.is_none() && connector_f_spent.is_none() {
        signals.push(PegoutSignal::OperatorCommitPubinReady);
        if is_timelock_ready(
            monitor.height,
            operator_commit_timelock_blocks(network, timelocks) as i64,
            height,
        ) {
            signals.push(PegoutSignal::OperatorCommitPubinTimeout);
        }
    }
    if all_resolved
        && pubin_committed
        && let Some(assert_txid) = row.operator_assert_txid.clone()
        && !btc_client.get_tx_status(&assert_txid.0).await?.confirmed
    {
        signals.push(PegoutSignal::AssertReady);
    }
    Ok(signals)
}

/// Prover-Assert confirmed, and each Verifier-Assert confirmed after it.
async fn assert_flow(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
) -> anyhow::Result<Vec<PegoutSignal>> {
    let Some(assert_txid) = row.operator_assert_txid.clone().map(Txid::from) else {
        return Ok(Vec::new());
    };
    if confirmed_monitor(
        btc_client,
        local_db,
        row.graph_id,
        assert_txid,
        MONITOR_PROVER_ASSERT.to_string(),
    )
    .await?
    .is_none()
    {
        return Ok(Vec::new());
    }
    let mut signals = vec![PegoutSignal::AssertSent { assert_txid }];
    for (verifier_index, txid) in row.verifier_assert_txids.iter().enumerate() {
        let challenge_assert_txid: Txid = txid.clone().into();
        if confirmed_monitor(
            btc_client,
            local_db,
            row.graph_id,
            challenge_assert_txid,
            format!("{MONITOR_VERIFIER_ASSERT}_{verifier_index}"),
        )
        .await?
        .is_some()
        {
            signals
                .push(PegoutSignal::ChallengeAssertSent { challenge_assert_txid, verifier_index });
        }
    }
    Ok(signals)
}

/// Every Verifier-Assert unanswered past `T2`: each of those verifiers may
/// disprove, and each only acts on its own slot.
async fn wrongly_challenge_timeout(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
    timelocks: &TimelockConfig,
    height: i64,
) -> anyhow::Result<Vec<PegoutSignal>> {
    let mut signals = Vec::new();
    let Some(assert_txid) = row.operator_assert_txid.clone().map(Txid::from) else {
        return Ok(signals);
    };
    if row.verifier_assert_txids.is_empty() {
        return Ok(signals);
    }
    let connector_d =
        output_topology::operator_assert::connector_d(row.verifier_assert_txids.len()) as u64;
    // Confirmed spends only: an answer that is still in the mempool can be
    // replaced, and the disprove job waits it out itself.
    if outpoint_spent_confirmed(btc_client, &assert_txid, connector_d).await?.is_some() {
        return Ok(signals);
    }
    let disprove_blocks = disprove_timelock_blocks(get_network(), timelocks) as i64;
    for (index, txid) in row.verifier_assert_txids.iter().enumerate() {
        let challenge_assert_txid: Txid = txid.clone().into();
        if outpoint_spent_confirmed(btc_client, &challenge_assert_txid, 0).await?.is_some() {
            continue;
        }
        let Some(monitor) = confirmed_monitor(
            btc_client,
            local_db,
            row.graph_id,
            challenge_assert_txid,
            format!("{MONITOR_VERIFIER_ASSERT}_{index}"),
        )
        .await?
        else {
            continue;
        };
        if monitor.height + disprove_blocks <= height {
            signals.push(PegoutSignal::WronglyChallengeTimeout {
                challenge_assert_txid,
                verifier_index: index,
            });
        }
    }
    Ok(signals)
}

/// Connector-D and the Guardian Connector unspent, `T3` after the assert and
/// `T7` after Watchtower-Challenge-Init.
async fn take2_ready(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    row: &Graph,
    timelocks: &TimelockConfig,
    height: i64,
) -> anyhow::Result<bool> {
    let (Some(kickoff_txid), Some(wci_txid), Some(assert_txid)) = (
        row.kickoff_txid.clone().map(Txid::from),
        row.watchtower_challenge_init_txid.clone().map(Txid::from),
        row.operator_assert_txid.clone().map(Txid::from),
    ) else {
        return Ok(false);
    };
    let connector_d =
        output_topology::operator_assert::connector_d(row.verifier_assert_txids.len()) as u64;
    let guardian = output_topology::kickoff::guardian_connector() as u64;
    if outpoint_spent_txid(btc_client, &assert_txid, connector_d).await?.is_some()
        || outpoint_spent_txid(btc_client, &kickoff_txid, guardian).await?.is_some()
    {
        return Ok(false);
    }
    let network = get_network();
    let Some(assert) = confirmed_monitor(
        btc_client,
        local_db,
        row.graph_id,
        assert_txid,
        MONITOR_PROVER_ASSERT.to_string(),
    )
    .await?
    else {
        return Ok(false);
    };
    let Some(wci) = confirmed_monitor(
        btc_client,
        local_db,
        row.graph_id,
        wci_txid,
        MONITOR_WATCHTOWER_INIT.to_string(),
    )
    .await?
    else {
        return Ok(false);
    };
    Ok(is_timelock_ready(assert.height, take2_timelock_blocks(network, timelocks) as i64, height)
        && is_timelock_ready(
            wci.height,
            connector_f_timelock_blocks(network, timelocks) as i64,
            height,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::DetectedDisprove;
    use GraphStatus::*;

    fn chain(stage: GraphStatus) -> GraphChainScan {
        GraphChainScan::for_test(stage)
    }

    #[test]
    fn a_scan_resumes_after_the_slot_the_last_tick_stopped_at() {
        let slot = |op: &str, nonce: i64| (op.to_string(), nonce);
        let slots = [slot("a", 0), slot("a", 1), slot("b", 0)];
        assert_eq!(resume_index(&slots, None), 0);
        assert_eq!(resume_index(&slots, Some(&slot("a", 0))), 1);
        assert_eq!(resume_index(&slots, Some(&slot("a", 1))), 2);
        // Past the end, or at a slot that disappeared: wrap, or the next one.
        assert_eq!(resume_index(&slots, Some(&slot("b", 0))), 0);
        assert_eq!(resume_index(&slots, Some(&slot("a", 5))), 2);
        assert_eq!(resume_index(&[], Some(&slot("a", 0))), 0);
    }

    #[test]
    fn edges_follow_the_chain_stage() {
        assert!(stage_signals(&chain(OperatorDataPushed)).is_empty());
        assert_eq!(stage_signals(&chain(PreKickoff)), vec![PegoutSignal::PreKickoffSent]);
        assert_eq!(stage_signals(&chain(Skipped)), vec![PegoutSignal::PreKickoffSent]);
        assert_eq!(
            stage_signals(&chain(OperatorTake1)),
            vec![PegoutSignal::PreKickoffSent, PegoutSignal::KickoffSent, PegoutSignal::Take1Sent]
        );
        let challenge_txid = Txid::from_str(&"44".repeat(32)).unwrap();
        let mut disproved = chain(Disprove);
        disproved.challenge_txid = Some(challenge_txid);
        disproved.disprove = Some(DetectedDisprove {
            disprove_type: DisproveTxType::Disprove,
            index: 1,
            challenge_finish_txid: challenge_txid,
        });
        let signals = stage_signals(&disproved);
        assert!(signals.contains(&PegoutSignal::ChallengeSent { challenge_txid }));
        assert!(signals.iter().any(|signal| matches!(
            signal,
            PegoutSignal::DisproveSent { index: 1, disprove_type: DisproveTxType::Disprove, .. }
        )));
        assert!(is_timelock_ready(10, 5, 15) && !is_timelock_ready(10, 5, 14));
        assert!(!is_timelock_ready(0, 0, 15));
    }

    #[test]
    fn later_slots_report_the_lowest_dead_slot() {
        let operator = "03dead-slot-test";
        assert_eq!(dead_slot_below(operator, 9), None);
        record_dead_slot(operator, 5);
        record_dead_slot(operator, 7);
        assert_eq!(dead_slot_below(operator, 9), Some(5));
        assert_eq!(dead_slot_below(operator, 5), None, "the dead slot reports its own fact");
        record_dead_slot(operator, 3);
        assert_eq!(dead_slot_below(operator, 5), Some(3));
        assert_eq!(dead_slot_below("03another-operator", 9), None);
    }
}
