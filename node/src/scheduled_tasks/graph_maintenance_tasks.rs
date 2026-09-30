use crate::action::{
    AssertReady, AssertSent, ChallengeAssertSent, ChallengeSent, DisproveSent, GOATMessageContent,
    KickoffReady, KickoffSent, NackReady, OperatorCommitPubinReady, OperatorCommitPubinTimeout,
    PreKickoffSent, Take1Ready, Take1Sent, Take2Ready, Take2Sent, WatchtowerChallengeInitSent,
    WatchtowerChallengeSent, WatchtowerChallengeTimeout, WronglyChallengeTimeout,
};
use crate::env::get_network;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::{
    fetch_all_graphs_by_status, fetch_first_graph_per_operator_by_status,
};
use crate::utils::{
    SELF_SENDER, load_validated_graph_definition, outpoint_spent_txid, upsert_message,
};
use bitcoin::Txid;
use bitvm_lib::actors::Actor;
use bitvm_lib::timelocks::{
    connector_f_timelock_blocks, disprove_timelock_blocks, operator_ack_timelock_blocks,
    operator_commit_timelock_blocks, take1_timelock_blocks, take2_timelock_blocks,
    validate_timelock_config, watchtower_challenge_timelock_blocks,
};
use client::btc_chain::BTCClient;
use client::goat_chain::DisproveTxType;
use goat::{constants::TimelockConfig, transactions::base::output_topology};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use store::localdb::{LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxType, Graph, GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, trace, warn};
use uuid::Uuid;

const MONITE_BTC_TX_NAME_KICKOFF: &str = "kickoff";
const MONITE_BTC_TX_NAME_WATCHTOWER_INIT: &str = "watchtower_init";
const MONITE_BTC_TX_NAME_PROVER_ASSERT: &str = "prover_assert";
const MONITE_BTC_TX_NAME_VERIFIER_ASSERT: &str = "verifier_assert";
const MAX_PREKICKOFF_SUCCESSORS_PER_SCAN: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString)]
enum OperatorWithdrawType {
    Take1,
    Take2,
}

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

struct DetectedGraphMessage {
    actor: Actor,
    content: GOATMessageContent,
}

impl DetectedGraphMessage {
    fn new(actor: Actor, content: GOATMessageContent) -> Self {
        Self { actor, content }
    }
}

async fn graph_timelock_config(
    local_db: &LocalDB,
    graph_id: Uuid,
) -> anyhow::Result<TimelockConfig> {
    let mut storage_processor = local_db.acquire().await?;
    let graph_row = storage_processor.find_graph(&graph_id).await?.ok_or_else(|| {
        anyhow::anyhow!("graph {graph_id} is missing while loading its timelock config")
    })?;
    let graph =
        load_validated_graph_definition(&mut storage_processor, graph_row.instance_id, graph_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("graph {graph_id} has no validated raw definition"))?;
    validate_timelock_config(
        graph.parameters.instance_parameters.network,
        &graph.parameters.timelock_config,
    )?;
    Ok(graph.parameters.timelock_config)
}

impl ChallengeSubStatus {
    pub fn is_watchtower_challenge_success(&self, required_watchtower_num: usize) -> bool {
        self.watchtower_challenge_status
            .iter()
            .filter(|&&status| status)
            .take(required_watchtower_num)
            .count()
            == required_watchtower_num
    }

    pub fn is_disproved(&self) -> bool {
        self.disprove_type.is_some()
    }
}

async fn upsert_detected_messages(
    local_db: &LocalDB,
    messages: Vec<DetectedGraphMessage>,
) -> anyhow::Result<()> {
    if messages.is_empty() {
        return Ok(());
    }

    let mut storage_processor = local_db.acquire().await?;
    for message in messages {
        upsert_message(
            &mut storage_processor,
            false,
            SELF_SENDER.to_string(),
            message.actor,
            message.content,
            0,
            0,
        )
        .await?;
    }
    Ok(())
}

async fn get_confirmed_tx_monitor(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_id: Uuid,
    txid: Txid,
    tx_name: String,
) -> anyhow::Result<Option<GraphBtcTxVoutMonitor>> {
    let txid_serial = SerializableTxid::from(txid);
    let existing = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor.find_graph_btc_tx_vout_monitor(&graph_id, &txid_serial).await?
    };
    if let Some(existing) = existing
        && existing.height > 0
        && existing.vout_len > 0
    {
        return Ok(Some(existing));
    }

    let Some(tx_info) = btc_client.get_tx_info(&txid_serial.0).await? else {
        return Ok(None);
    };
    let height = tx_info.status.block_height.unwrap_or_default() as i64;
    if height <= 0 {
        return Ok(None);
    }

    let current_times = current_time_secs();
    let monitor = GraphBtcTxVoutMonitor {
        graph_id,
        tx_name,
        txid: txid_serial,
        height,
        vout_len: tx_info.vout.len() as i64,
        monitor_data: String::new(),
        created_at: current_times,
        updated_at: current_times,
    };
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.upsert_graph_btc_tx_vout_monitor(&monitor).await?;
    Ok(Some(monitor))
}

async fn detect_watchtower_flow_disprove(
    btc_client: &BTCClient,
    graph: &Graph,
) -> anyhow::Result<Option<DetectedGraphMessage>> {
    for (index, txid) in graph.operator_challenge_nack_txids.iter().enumerate() {
        if btc_client.get_tx_status(&txid.0).await?.confirmed {
            return Ok(Some(DetectedGraphMessage::new(
                Actor::Committee,
                GOATMessageContent::DisproveSent(DisproveSent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    disprove_type: DisproveTxType::OperatorChallengeNack,
                    index,
                    challenge_start_txid: None,
                    challenge_finish_txid: txid.0,
                }),
            )));
        }
    }

    if let Some(txid) = graph.operator_commit_timeout_txid.clone()
        && btc_client.get_tx_status(&txid.0).await?.confirmed
    {
        return Ok(Some(DetectedGraphMessage::new(
            Actor::Committee,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type: DisproveTxType::OperatorCommitTimeout,
                index: 0,
                challenge_start_txid: None,
                challenge_finish_txid: txid.0,
            }),
        )));
    }

    Ok(None)
}

fn is_timelock_ready(confirmed_height: i64, lock_blocks: i64, current_height: i64) -> bool {
    confirmed_height > 0 && confirmed_height + lock_blocks <= current_height
}

pub async fn get_user_init_withdraw_graphs<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
    let goat_tx_records = storage_processor
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    Ok(goat_tx_records.iter().map(|v| (v.instance_id, v.graph_id)).collect())
}

/// may trigger: KickoffReady
pub async fn detect_init_withdraw_call(local_db: &LocalDB) -> anyhow::Result<()> {
    trace!("start tick action: detect_init_withdraw_call");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        get_user_init_withdraw_graphs(&mut storage_processor).await?
    };
    info!("start tick action: detect_init_withdraw_call get graphs:{}", graphs.len());
    for (instance_id, graph_id) in graphs {
        let mut tx = local_db.start_transaction().await?;
        if let Ok(Some(graph)) = tx.find_graph(&graph_id).await {
            if graph.instance_id.ne(&instance_id) {
                warn!(
                    "Graph:{graph_id} recorded instance_id:{} not equal expected instance_id:{instance_id}",
                    graph.instance_id
                );
                continue;
            }
            upsert_message(
                &mut tx,
                false,
                SELF_SENDER.to_string(),
                Actor::Operator,
                GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
        } else {
            warn!(
                "instance_id: {instance_id} graph_id: {graph_id} fail to get graph from db or kickoff txid is none"
            );
        }
        tx.update_goat_tx_record_processing_status(
            &graph_id,
            &instance_id,
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn enqueue_kickoff_sent(local_db: &LocalDB, graph: &Graph) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    upsert_message(
        &mut storage_processor,
        false,
        SELF_SENDER.to_string(),
        Actor::All,
        GOATMessageContent::KickoffSent(KickoffSent {
            instance_id: graph.instance_id,
            graph_id: graph.graph_id,
        }),
        0,
        0,
    )
    .await
    .map(|_| ())
}

async fn enqueue_prekickoff_sent(local_db: &LocalDB, graph: &Graph) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    upsert_message(
        &mut storage_processor,
        false,
        SELF_SENDER.to_string(),
        Actor::Verifier,
        GOATMessageContent::PreKickoffSent(PreKickoffSent {
            instance_id: graph.instance_id,
            graph_id: graph.graph_id,
        }),
        0,
        0,
    )
    .await
    .map(|_| ())
}

fn is_kickoff_pending_status(status: &str) -> bool {
    status == GraphStatus::OperatorDataPushed.to_string()
        || status == GraphStatus::PreKickoff.to_string()
}

async fn detect_graph_kickoff(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &Graph,
) -> anyhow::Result<()> {
    if !is_kickoff_pending_status(&graph.status) {
        return Ok(());
    }

    let Some(kickoff_txid) = graph.kickoff_txid.clone() else {
        warn!(graph_id = %graph.graph_id, "kickoff txid is missing");
        return Ok(());
    };
    let kickoff_txid: Txid = kickoff_txid.into();
    let tx_status = btc_client.get_tx_status(&kickoff_txid).await?;
    if tx_status.confirmed {
        enqueue_kickoff_sent(local_db, graph).await?;
    } else {
        trace!(graph_id = %graph.graph_id, kickoff_txid = %kickoff_txid, "kickoff is not confirmed yet");
    }
    Ok(())
}

async fn confirmed_prekickoff_successor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &Graph,
) -> anyhow::Result<Option<Graph>> {
    let Some(next_prekickoff) = graph.next_prekickoff.clone() else {
        return Ok(None);
    };
    let next_prekickoff_txid: Txid = next_prekickoff.clone().into();
    if !btc_client.get_tx_status(&next_prekickoff_txid).await?.confirmed {
        return Ok(None);
    }

    let successor = {
        let mut storage_processor = local_db.acquire().await?;
        let Some((graph_id, instance_id, cur_prekickoff, _)) = storage_processor
            .get_graph_pre_kickoff_chain_by_cur_pre_kickoff(next_prekickoff.clone())
            .await?
        else {
            warn!(
                graph_id = %graph.graph_id,
                next_prekickoff_txid = %next_prekickoff_txid,
                "confirmed next prekickoff has no successor graph"
            );
            return Ok(None);
        };
        let successor = storage_processor.find_graph(&graph_id).await?.ok_or_else(|| {
            anyhow::anyhow!("pre-kickoff successor graph {graph_id} disappeared from storage")
        })?;
        if successor.instance_id != instance_id
            || successor.cur_prekickoff_txid != Some(cur_prekickoff)
            || successor.operator_pubkey != graph.operator_pubkey
            || successor.kickoff_index != graph.kickoff_index + 1
        {
            anyhow::bail!(
                "invalid pre-kickoff successor {} for graph {}",
                successor.graph_id,
                graph.graph_id
            );
        }
        successor
    };

    Ok(Some(successor))
}

async fn scan_kickoff_chain(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    start_graph: Graph,
    visited_graph_ids: &mut HashSet<Uuid>,
) -> anyhow::Result<()> {
    let mut graph = start_graph;
    for successor_depth in 0..=MAX_PREKICKOFF_SUCCESSORS_PER_SCAN {
        if !visited_graph_ids.insert(graph.graph_id) {
            return Ok(());
        }

        // A failed lookup for the lower-index kickoff must not hide a
        // confirmed successor pre-kickoff in the same scan.
        if let Err(error) = detect_graph_kickoff(local_db, btc_client, &graph).await {
            warn!(
                graph_id = %graph.graph_id,
                error = %error,
                "failed to scan graph kickoff; continuing pre-kickoff chain"
            );
        }
        let Some(successor) = confirmed_prekickoff_successor(local_db, btc_client, &graph).await?
        else {
            return Ok(());
        };

        if successor_depth == MAX_PREKICKOFF_SUCCESSORS_PER_SCAN {
            warn!(
                graph_id = %graph.graph_id,
                max_depth = MAX_PREKICKOFF_SUCCESSORS_PER_SCAN,
                "stopped pre-kickoff successor scan at configured depth limit"
            );
            return Ok(());
        }

        enqueue_prekickoff_sent(local_db, &successor).await?;
        graph = successor;
    }
    Ok(())
}

/// May trigger PreKickoffSent and KickoffSent.
///
/// The first OperatorDataPushed graph is the normal scan entry point for an
/// operator. A confirmed `next_prekickoff` proves that the next graph has
/// started, so follow that chain instead of letting the earlier graph hide it.
pub async fn detect_kickoff(local_db: &LocalDB, btc_client: &BTCClient) -> anyhow::Result<()> {
    trace!("start tick action: detect_kickoff");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        let mut graphs = fetch_first_graph_per_operator_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorDataPushed.to_string(),
        )
        .await?;
        // A PreKickoff graph must remain eligible until its kickoff confirms.
        graphs.extend(
            fetch_all_graphs_by_status(
                &mut storage_processor,
                &GraphStatus::PreKickoff.to_string(),
            )
            .await?,
        );
        graphs
    };
    info!("start tick action: detect_kickoff, roots: {}", graphs.len());

    let mut visited_graph_ids = HashSet::new();
    for graph in graphs {
        let graph_id = graph.graph_id;
        if let Err(error) =
            scan_kickoff_chain(local_db, btc_client, graph, &mut visited_graph_ids).await
        {
            warn!(graph_id = %graph_id, error = %error, "failed to scan kickoff chain");
        }
    }
    Ok(())
}

/// may trigger: Take1Ready, Take1Sent, ChallengeSent
pub async fn detect_take1_or_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    trace!("start tick action: detect_take1_or_challenge");

    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_all_graphs_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorKickOff.to_string(),
        )
        .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    info!(
        "start tick action: detect_take1_or_challenge, graphs: {}, current_height: {current_height}",
        graphs.len()
    );
    for graph in graphs {
        let graph_id = graph.graph_id;
        if let Err(error) =
            detect_take1_or_challenge_for_graph(local_db, btc_client, graph, current_height).await
        {
            warn!(graph_id = %graph_id, error = %error, "failed to scan operator kickoff graph");
        }
    }
    Ok(())
}

async fn detect_take1_or_challenge_for_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: Graph,
    current_height: i64,
) -> anyhow::Result<()> {
    let timelock_config = graph_timelock_config(local_db, graph.graph_id).await?;
    let lock_blocks = take1_timelock_blocks(get_network(), &timelock_config) as i64;
    if detect_kickoff_ref_disprove_tx(btc_client, local_db, &graph).await? {
        warn!(
            "process_graph_challenge detect_kickoff_ref_disprove_tx happened at graph:{}",
            graph.graph_id
        );
        return Ok(());
    }

    // process_kickoff_graph may trigger Take1Ready, Take1Sent or ChallengeSent
    if let Some((actor, message_content)) =
        process_kickoff_graph(btc_client, local_db, &graph, lock_blocks, current_height).await?
    {
        info!("process_kickoff_graph detect take1 ready or take1 sent or challenge sent");
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            SELF_SENDER.to_string(),
            actor,
            message_content,
            0,
            0,
        )
        .await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip(local_db, btc_client))]
pub async fn process_graph_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    trace!("start tick action: process_graph_challenge");

    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_all_graphs_by_status(&mut storage_processor, &GraphStatus::Challenge.to_string())
            .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    info!(
        "start tick action: process_graph_challenge, graphs: {}, current_height: {current_height}",
        graphs.len()
    );

    for graph in graphs {
        let graph_id = graph.graph_id;
        if let Err(error) =
            process_graph_challenge_for_graph(local_db, btc_client, graph, current_height).await
        {
            warn!(graph_id = %graph_id, error = %error, "failed to scan challenge graph");
        }
    }
    Ok(())
}

async fn process_graph_challenge_for_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: Graph,
    current_height: i64,
) -> anyhow::Result<()> {
    let watchtower_flow_messages =
        detect_watchtower_flow(btc_client, local_db, &graph, current_height).await?;
    if !watchtower_flow_messages.is_empty() {
        info!(
            "process_graph_challenge detected {} watchtower/pubin flow messages",
            watchtower_flow_messages.len()
        );
        upsert_detected_messages(local_db, watchtower_flow_messages).await?;
    }

    let assert_sent_messages = detect_assert_sent_flow(btc_client, local_db, &graph).await?;
    if !assert_sent_messages.is_empty() {
        info!(
            "process_graph_challenge detected {} assert/challenge-assert messages",
            assert_sent_messages.len()
        );
        upsert_detected_messages(local_db, assert_sent_messages).await?;
    }

    if let Some((actor, message_content)) =
        detect_assert_disprove_ready(btc_client, local_db, &graph, current_height).await?
    {
        info!("process_graph_challenge detect assert disprove ready");
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            SELF_SENDER.to_string(),
            actor,
            message_content,
            0,
            0,
        )
        .await?;
    }

    // take2 monitor
    if let Some((actor, message_content)) =
        detect_take2(btc_client, local_db, &graph, current_height).await?
    {
        info!("process_graph_challenge detect take2 ready or take2 sent or disprove sent");
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            SELF_SENDER.to_string(),
            actor,
            message_content,
            0,
            0,
        )
        .await?;
    }
    Ok(())
}

/// may trigger:
/// - WatchtowerChallengeInitSent
/// - WatchtowerChallengeSent
/// - WatchtowerChallengeTimeout
/// - NackReady
/// - OperatorCommitPubinReady
/// - OperatorCommitPubinTimeout
/// - AssertReady
async fn detect_watchtower_flow(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Vec<DetectedGraphMessage>> {
    let watchtower_challenge_init_txid: Txid = match graph.watchtower_challenge_init_txid.clone() {
        Some(txid) => txid.into(),
        None => {
            warn!(
                "detect_watchtower_challenge graph_id:{} watchtower_challenge_init_txid is none",
                graph.graph_id
            );
            return Ok(vec![]);
        }
    };

    let Some(monitor) = get_confirmed_tx_monitor(
        btc_client,
        local_db,
        graph.graph_id,
        watchtower_challenge_init_txid,
        MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string(),
    )
    .await?
    else {
        trace!(
            "detect_watchtower_flow graph_id:{} watchtower challenge init txid {} not confirmed",
            graph.graph_id, watchtower_challenge_init_txid
        );
        return Ok(vec![]);
    };
    let timelock_config = graph_timelock_config(local_db, graph.graph_id).await?;

    let mut messages = vec![DetectedGraphMessage::new(
        Actor::Watchtower,
        GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
            instance_id: graph.instance_id,
            graph_id: graph.graph_id,
        }),
    )];

    let watchtower_num = output_topology::watchtower_challenge_init::watchtower_num(
        monitor.vout_len.max(0) as usize,
    );
    if watchtower_num == 0 {
        return Ok(messages);
    }

    if let Some(disprove_message) = detect_watchtower_flow_disprove(btc_client, graph).await? {
        return Ok(vec![disprove_message]);
    }

    let connector_e_vout =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    let connector_e_spent_txid =
        outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, connector_e_vout).await?;
    let connector_f_spent_txid =
        outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, connector_f_vout).await?;
    let operator_commit_timeout_txid: Option<Txid> =
        graph.operator_commit_timeout_txid.clone().map(Into::into);
    let operator_commit_timeout_on_chain =
        match (connector_e_spent_txid.as_ref(), operator_commit_timeout_txid.as_ref()) {
            (Some(spent_txid), Some(timeout_txid)) => spent_txid == timeout_txid,
            _ => false,
        };
    let pubin_commit_completed =
        connector_e_spent_txid.is_some() && !operator_commit_timeout_on_chain;

    let mut all_watchtower_branches_resolved = true;
    let mut any_watchtower_timeout_ready = false;
    let mut any_nack_ready = false;
    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        let watchtower_spent_txid =
            outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, watchtower_vout)
                .await?;
        let ack_spent_txid =
            outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, ack_vout).await?;
        let timeout_txid =
            graph.watchtower_challenge_timeout_txids.get(watchtower_index).cloned().map(Into::into);
        let watchtower_spend_confirmed = match watchtower_spent_txid.as_ref() {
            Some(txid) => btc_client.get_tx_status(txid).await?.confirmed,
            None => false,
        };
        let ack_spend_confirmed = match ack_spent_txid.as_ref() {
            Some(txid) => btc_client.get_tx_status(txid).await?.confirmed,
            None => false,
        };
        let watchtower_timeout_spent = match (watchtower_spent_txid.as_ref(), timeout_txid.as_ref())
        {
            (Some(spent_txid), Some(timeout_txid)) => {
                spent_txid == timeout_txid && watchtower_spend_confirmed
            }
            _ => false,
        };

        match watchtower_spent_txid {
            Some(_) if !watchtower_spend_confirmed => {
                all_watchtower_branches_resolved = false;
            }
            Some(_) if !watchtower_timeout_spent => {
                messages.push(DetectedGraphMessage::new(
                    Actor::Operator,
                    GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                        watchtower_index,
                    }),
                ));

                if !ack_spend_confirmed {
                    all_watchtower_branches_resolved = false;
                    if connector_f_spent_txid.is_none()
                        && ack_spent_txid.is_none()
                        && is_timelock_ready(
                            monitor.height,
                            operator_ack_timelock_blocks(get_network(), &timelock_config) as i64,
                            current_height,
                        )
                    {
                        any_nack_ready = true;
                    }
                }
            }
            Some(_) => {}
            None => {
                all_watchtower_branches_resolved = false;
                if ack_spent_txid.is_none()
                    && is_timelock_ready(
                        monitor.height,
                        watchtower_challenge_timelock_blocks(get_network(), &timelock_config)
                            as i64,
                        current_height,
                    )
                {
                    any_watchtower_timeout_ready = true;
                }
            }
        }
    }

    if any_watchtower_timeout_ready {
        messages.push(DetectedGraphMessage::new(
            Actor::Operator,
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        ));
    }

    if any_nack_ready {
        messages.push(DetectedGraphMessage::new(
            Actor::Verifier,
            GOATMessageContent::NackReady(NackReady {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        ));
    }

    if all_watchtower_branches_resolved
        && connector_e_spent_txid.is_none()
        && connector_f_spent_txid.is_none()
    {
        messages.push(DetectedGraphMessage::new(
            Actor::Operator,
            GOATMessageContent::OperatorCommitPubinReady(OperatorCommitPubinReady {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        ));

        if is_timelock_ready(
            monitor.height,
            operator_commit_timelock_blocks(get_network(), &timelock_config) as i64,
            current_height,
        ) {
            messages.push(DetectedGraphMessage::new(
                Actor::Verifier,
                GOATMessageContent::OperatorCommitPubinTimeout(OperatorCommitPubinTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
            ));
        }
    }

    if all_watchtower_branches_resolved
        && pubin_commit_completed
        && let Some(operator_assert_txid) = graph.operator_assert_txid.clone()
        && !btc_client.get_tx_status(&operator_assert_txid.0).await?.confirmed
    {
        messages.push(DetectedGraphMessage::new(
            Actor::Operator,
            GOATMessageContent::AssertReady(AssertReady {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        ));
    }

    Ok(messages)
}

/// may trigger:
/// - AssertSent
/// - ChallengeAssertSent
async fn detect_assert_sent_flow(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
) -> anyhow::Result<Vec<DetectedGraphMessage>> {
    let operator_assert_txid: Txid = match graph.operator_assert_txid.clone() {
        Some(txid) => txid.into(),
        None => {
            warn!(
                "detect_assert_sent_flow graph_id:{} operator_assert_txid is none",
                graph.graph_id
            );
            return Ok(vec![]);
        }
    };

    let Some(_) = get_confirmed_tx_monitor(
        btc_client,
        local_db,
        graph.graph_id,
        operator_assert_txid,
        MONITE_BTC_TX_NAME_PROVER_ASSERT.to_string(),
    )
    .await?
    else {
        trace!(
            "detect_assert_sent_flow graph_id:{} operator assert txid {} not confirmed",
            graph.graph_id, operator_assert_txid
        );
        return Ok(vec![]);
    };

    let mut messages = vec![DetectedGraphMessage::new(
        Actor::Verifier,
        GOATMessageContent::AssertSent(AssertSent {
            instance_id: graph.instance_id,
            graph_id: graph.graph_id,
            assert_txid: operator_assert_txid,
        }),
    )];

    for (verifier_index, challenge_assert_txid) in graph.verifier_assert_txids.iter().enumerate() {
        let challenge_assert_txid: Txid = challenge_assert_txid.clone().into();
        let Some(_) = get_confirmed_tx_monitor(
            btc_client,
            local_db,
            graph.graph_id,
            challenge_assert_txid,
            format!("{MONITE_BTC_TX_NAME_VERIFIER_ASSERT}_{verifier_index}"),
        )
        .await?
        else {
            continue;
        };

        messages.push(DetectedGraphMessage::new(
            Actor::Operator,
            GOATMessageContent::ChallengeAssertSent(ChallengeAssertSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                challenge_assert_txid,
                verifier_index,
            }),
        ));
    }

    Ok(messages)
}

// may trigger disprove ready
async fn detect_assert_disprove_ready(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    let operator_assert_txid = match graph.operator_assert_txid.clone() {
        Some(operator_assert_txid) => operator_assert_txid.into(),
        None => {
            warn!(
                "detect_assert_disprove_ready graph_id:{} operator_assert_txid has none value",
                graph.graph_id
            );
            return Ok(None);
        }
    };
    if graph.verifier_assert_txids.is_empty() {
        return Ok(None);
    }

    let connector_d_vout =
        output_topology::operator_assert::connector_d(graph.verifier_assert_txids.len()) as u64;
    if outpoint_spent_txid(btc_client, &operator_assert_txid, connector_d_vout).await?.is_some() {
        trace!(
            "detect_assert_disprove_ready graph_id:{} connector_d already spent",
            graph.graph_id
        );
        return Ok(None);
    }

    let timelock_config = graph_timelock_config(local_db, graph.graph_id).await?;
    let disprove_timelock = disprove_timelock_blocks(get_network(), &timelock_config) as i64;

    for (index, verifier_assert_txid) in graph.verifier_assert_txids.iter().enumerate() {
        let verifier_assert_txid: Txid = verifier_assert_txid.clone().into();
        if outpoint_spent_txid(btc_client, &verifier_assert_txid, 0).await?.is_some() {
            continue;
        }

        let height = {
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .find_graph_btc_tx_vout_monitor(&graph.graph_id, &verifier_assert_txid.into())
                .await?
                .unwrap_or_default()
                .height
        };
        let height = if height <= 0 {
            let Some(tx_info) = btc_client.get_tx_info(&verifier_assert_txid).await? else {
                continue;
            };
            let height = tx_info.status.block_height.unwrap_or_default() as i64;
            if height <= 0 {
                continue;
            }

            let current_times = current_time_secs();
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    tx_name: format!("verifier_assert_{index}"),
                    txid: verifier_assert_txid.into(),
                    height,
                    vout_len: tx_info.vout.len() as i64,
                    monitor_data: String::new(),
                    created_at: current_times,
                    updated_at: current_times,
                })
                .await?;
            height
        } else {
            height
        };

        if height + disprove_timelock <= current_height {
            info!(
                "detect_assert_disprove_ready graph_id:{} verifier_assert index:{} is ready to disprove",
                graph.graph_id, index
            );
            return Ok(Some((
                Actor::Verifier,
                GOATMessageContent::WronglyChallengeTimeout(WronglyChallengeTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    challenge_assert_txid: verifier_assert_txid,
                    verifier_index: index,
                }),
            )));
        }
    }

    Ok(None)
}

/// Check if Take1Ready Take2Ready message needs to be sent
async fn check_operator_withdraw_ready_condition(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_id: Uuid,
    check_tx_items: Vec<(Txid, String, OperatorWithdrawType, i64, i64)>, // (txid, tag,  height, lock_blocks)
    current_height: i64,
) -> anyhow::Result<bool> {
    info!(
        "check_operator_withdraw_ready_condition for graph_id: {graph_id}, check tx size: {}, detail:{check_tx_items:?}",
        check_tx_items.len()
    );
    let mut ready = true;
    for (txid, tx_name, operator_withdraw_type, height, lock_blocks) in check_tx_items {
        let height = if height <= 0 {
            let current_times = current_time_secs();
            let (height, vout_len) = match btc_client.get_tx_info(&txid).await? {
                Some(tx_info) => (
                    tx_info.status.block_height.unwrap_or_default() as i64,
                    tx_info.vout.len() as i64,
                ),
                None => {
                    info!("graph_id:{graph_id}, {operator_withdraw_type} txid {txid} not on chain",);
                    return Ok(false);
                }
            };
            let txid_serial: SerializableTxid = txid.into();
            let mut storage_processor = local_db.acquire().await?;
            let existing =
                storage_processor.find_graph_btc_tx_vout_monitor(&graph_id, &txid_serial).await?;
            let (monitor_data, created_at, tx_name_to_use) = match existing {
                Some(existing) => (existing.monitor_data, existing.created_at, existing.tx_name),
                None => ("".to_string(), current_times, tx_name.clone()),
            };
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id,
                    tx_name: tx_name_to_use,
                    txid: txid_serial,
                    height,
                    vout_len,
                    monitor_data,
                    created_at,
                    updated_at: current_times,
                })
                .await?;
            height
        } else {
            height
        };

        info!(
            "graph_id:{graph_id}, {operator_withdraw_type} txid {txid}  at height {height} lock_blocks {lock_blocks}, current height: {current_height}  ",
        );

        if height == 0 || height > 0 && height + lock_blocks > current_height {
            ready = false;
            break;
        }
    }
    Ok(ready)
}

/// Process graph data in KickOff status
/// may return: Take1Ready, Take1Sent, ChallengeSent
async fn process_kickoff_graph(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    lock_blocks: i64,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("process_kickoff_graph: {}", graph.graph_id);
    let (kickoff_txid, take1_txid) = match (graph.kickoff_txid.clone(), graph.take1_txid.clone()) {
        (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
        _ => {
            // NOTE: revert to previous status?
            warn!("process_kickoff_graph graph_id:{}, kickoff or take1 is none", graph.graph_id);
            return Ok(None);
        }
    };
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, connector_a_vout).await? {
        Some(txid) => txid,
        None => {
            // kickoff output not spent, check if we need to send Take1Ready
            let height = {
                let mut storage_processor = local_db.acquire().await?;
                storage_processor
                    .find_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
                    .await?
                    .unwrap_or_default()
                    .height
            };
            if check_operator_withdraw_ready_condition(
                btc_client,
                local_db,
                graph.graph_id,
                vec![(
                    kickoff_txid,
                    MONITE_BTC_TX_NAME_KICKOFF.to_string(),
                    OperatorWithdrawType::Take1,
                    height,
                    lock_blocks,
                )],
                current_height,
            )
            .await?
            {
                info!(
                    "process_kickoff_graph graph_id:{}, take1 is ready to send to btc chain",
                    graph.graph_id
                );
                return Ok(Some((
                    Actor::Operator,
                    GOATMessageContent::Take1Ready(Take1Ready {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                )));
            } else {
                trace!("process_kickoff_graph graph_id:{}, take1 not ready", graph.graph_id);
            }
            return Ok(None);
        }
    };
    if spent_txid == take1_txid {
        info!(
            "process_kickoff_graph graph_id:{}, take1 is on chain, will try call contract",
            graph.graph_id
        );
        Ok(Some((
            Actor::Committee,
            GOATMessageContent::Take1Sent(Take1Sent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        info!(
            "process_kickoff_graph graph_id:{}, challenge txid: {} has been detected.",
            graph.graph_id,
            spent_txid.to_string()
        );
        // Challenge was sent
        Ok(Some((
            Actor::Operator,
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                challenge_txid: spent_txid,
            }),
        )))
    }
}

/// may trigger: DisproveSent(QuickChallenge/ChallengeIncompleteKickoff)
async fn detect_kickoff_ref_disprove_tx(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
) -> anyhow::Result<bool> {
    let mut detected = false;
    let (kickoff_txid, take1_txid, take2_txid, next_pre_kickoff): (
        Txid,
        Txid,
        Txid,
        SerializableTxid,
    ) = match (
        graph.kickoff_txid.clone(),
        graph.take1_txid.clone(),
        graph.take2_txid.clone(),
        graph.next_prekickoff.clone(),
    ) {
        (Some(kickoff_txid), Some(take1_txid), Some(take2_txid), Some(next_pre_kickoff)) => {
            (kickoff_txid.into(), take1_txid.into(), take2_txid.into(), next_pre_kickoff)
        }
        _ => {
            warn!("graph:{} kickoff_txid/take1_txid/take2_txid  has none value", graph.graph_id);
            return Ok(detected);
        }
    };
    let pre_sents = check_pre_kickoff_sent(
        local_db,
        btc_client,
        next_pre_kickoff,
        MAX_PREKICKOFF_SUCCESSORS_PER_SCAN,
    )
    .await?;
    if pre_sents > 0 {
        info!("graph_id:{} next {pre_sents} graphs's pre_kickoff has been sent!", graph.graph_id);
        detected = true;
    }
    let guardian_connector_vout = output_topology::kickoff::guardian_connector() as u64;
    if let Some(spend_txid) =
        outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout).await?
        && let Some(tx) = btc_client.get_tx(&spend_txid).await?
    {
        if spend_txid == take1_txid || spend_txid == take2_txid || tx.input.len() < 2 {
            return Ok(false);
        }

        let disprove_type = if tx.input[1].previous_output.vout == 0 {
            DisproveTxType::QuickChallenge
        } else {
            DisproveTxType::ChallengeIncompleteKickoff
        };

        info!(
            "graph_id:{} is disproved, spent txid:{}, disprove_type:{}",
            graph.graph_id, spend_txid, disprove_type
        );
        let challenge_start_txid: Option<Txid> = graph.challenge_txid.clone().map(|v| v.into());
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            SELF_SENDER.to_string(),
            Actor::Committee,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index: 0,
                challenge_start_txid,
                challenge_finish_txid: spend_txid,
            }),
            0,
            0,
        )
        .await?;
        detected = true;
    }
    Ok(detected)
}

/// may trigger: Take2Ready, Take2Sent, DisproveSent(Disprove)
async fn detect_take2(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    let (kickoff_txid, watchtower_challenge_init_txid, operator_assert_txid, take2_txid) = match (
        graph.kickoff_txid.clone(),
        graph.watchtower_challenge_init_txid.clone(),
        graph.operator_assert_txid.clone(),
        graph.take2_txid.clone(),
    ) {
        (
            Some(kickoff_txid),
            Some(watchtower_challenge_init_txid),
            Some(operator_assert_txid),
            Some(take2_txid),
        ) => (
            kickoff_txid.into(),
            watchtower_challenge_init_txid.into(),
            operator_assert_txid.into(),
            take2_txid.into(),
        ),
        _ => {
            warn!(
                "detect_take2 graph_id:{} kickoff_txid/watchtower_challenge_init_txid/operator_assert_txid/take2_txid has none value",
                graph.graph_id
            );
            return Ok(None);
        }
    };

    let connector_d_vout =
        output_topology::operator_assert::connector_d(graph.verifier_assert_txids.len()) as u64;
    if let Some(spend_txid) =
        outpoint_spent_txid(btc_client, &operator_assert_txid, connector_d_vout).await?
    {
        if spend_txid == take2_txid {
            info!("detect_take2 graph_id:{} take2 is on chain", graph.graph_id);
            return Ok(Some((
                Actor::Committee,
                GOATMessageContent::Take2Sent(Take2Sent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
            )));
        }

        if let Some(tx) = btc_client.get_tx(&spend_txid).await?
            && tx.input.len() == 2
        {
            let verifier_assert_txid = tx.input[0].previous_output.txid;
            if let Some(index) = graph
                .verifier_assert_txids
                .iter()
                .position(|txid| Txid::from(txid.clone()) == verifier_assert_txid)
            {
                info!(
                    "detect_take2 graph_id:{} disprove is on chain, spent txid:{}, index:{}",
                    graph.graph_id, spend_txid, index
                );
                return Ok(Some((
                    Actor::Committee,
                    GOATMessageContent::DisproveSent(DisproveSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                        disprove_type: DisproveTxType::Disprove,
                        index,
                        challenge_start_txid: graph.challenge_txid.clone().map(|v| v.into()),
                        challenge_finish_txid: spend_txid,
                    }),
                )));
            }
        }

        warn!(
            "detect_take2 graph_id:{} connector_d spent by pubin-disprove txid:{}",
            graph.graph_id, spend_txid
        );
        return Ok(Some((
            Actor::Committee,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type: DisproveTxType::PubinDisprove,
                index: 0,
                challenge_start_txid: None,
                challenge_finish_txid: spend_txid,
            }),
        )));
    }

    let guardian_connector_vout = output_topology::kickoff::guardian_connector() as u64;
    if outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout).await?.is_some() {
        trace!("detect_take2 graph_id:{} guardian connector already spent", graph.graph_id);
        return Ok(None);
    }

    let height = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &operator_assert_txid.into())
            .await?
            .unwrap_or_default()
            .height
    };
    let timelock_config = graph_timelock_config(local_db, graph.graph_id).await?;
    if check_operator_withdraw_ready_condition(
        btc_client,
        local_db,
        graph.graph_id,
        vec![
            (
                operator_assert_txid,
                MONITE_BTC_TX_NAME_PROVER_ASSERT.to_string(),
                OperatorWithdrawType::Take2,
                height,
                take2_timelock_blocks(get_network(), &timelock_config) as i64,
            ),
            (
                watchtower_challenge_init_txid,
                MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string(),
                OperatorWithdrawType::Take2,
                0,
                connector_f_timelock_blocks(get_network(), &timelock_config) as i64,
            ),
        ],
        current_height,
    )
    .await?
    {
        info!("detect_take2 graph_id:{} take2 is ready to send to btc chain", graph.graph_id);
        Ok(Some((
            Actor::Operator,
            GOATMessageContent::Take2Ready(Take2Ready {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        trace!("detect_take2 graph_id:{} take2 not ready", graph.graph_id);
        Ok(None)
    }
}

/// may trigger: PreKickoffSent
async fn check_pre_kickoff_sent(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    pre_kickoff: SerializableTxid,
    max_depth: usize,
) -> anyhow::Result<usize> {
    let check_graphs = {
        let mut check_graphs: Vec<(Uuid, Uuid, Txid)> = vec![];
        let mut storage_processor = local_db.acquire().await?;
        let mut remaining_depth = max_depth;
        let mut pre_kickoff = pre_kickoff;

        while remaining_depth > 0 {
            if let Some((graph_id, instance_id, cur_pre_kickoff, next_pre_kickoff)) =
                storage_processor
                    .get_graph_pre_kickoff_chain_by_cur_pre_kickoff(pre_kickoff.clone())
                    .await?
            {
                check_graphs.push((graph_id, instance_id, cur_pre_kickoff.into()));
                pre_kickoff = next_pre_kickoff;
                remaining_depth -= 1;
            } else {
                break;
            }
        }
        check_graphs
    };
    let mut pre_sents = 0;
    for (graph_id, instance_id, cur_pre_kickoff) in check_graphs {
        if btc_client.get_tx_status(&cur_pre_kickoff).await?.confirmed {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                SELF_SENDER.to_string(),
                Actor::Verifier,
                GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
            pre_sents += 1;
        }
    }
    Ok(pre_sents)
}
