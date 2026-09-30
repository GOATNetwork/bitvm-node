mod babe_setup_state_cleanup_task;
mod event_watch_task;
pub mod graph_maintenance_tasks;
pub mod instance_maintenance_tasks;
mod node_maintenance_tasks;
mod sequencer_set_hash_monitor_task;
mod spv_maintenance_tasks;

use crate::env::{
    actor_runs_babe_setup_state_cleanup, get_maintenance_run_timeout_secs, get_network,
    get_node_goat_address, get_node_pubkey, is_enable_babe_setup_state_cleanup,
    is_enable_update_spv_contract, is_relayer,
};
use crate::metrics_service::MetricsState;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::babe_setup_state_cleanup_task::babe_setup_state_cleanup_monitor;
use crate::scheduled_tasks::graph_maintenance_tasks::{
    detect_init_withdraw_call, detect_kickoff, detect_take1_or_challenge, process_graph_challenge,
};
use crate::scheduled_tasks::instance_maintenance_tasks::{
    instance_answers_monitor, instance_btc_tx_monitor, instance_committee_key_cleanup_monitor,
    instance_expiration_monitor, instance_window_expiration_monitor,
    pegin_confirm_recovery_monitor, swap_escrow_timeout_monitor,
};
use crate::scheduled_tasks::node_maintenance_tasks::node_available_pbtc_update_monitor;
use crate::scheduled_tasks::spv_maintenance_tasks::spv_header_hash_update;
use crate::utils::node_p2wsh_address;
use bitvm_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
pub use event_watch_task::{is_processing_gateway_history_events, run_watch_event_task};
pub use sequencer_set_hash_monitor_task::run_sequencer_set_hash_monitor_task;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Graph;
use store::localdb::{LocalDB, StorageProcessor};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Refreshes inexpensive dependency and funding signals used by alerting.
async fn refresh_alert_health(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    metrics_state: &MetricsState,
    actor: &Actor,
) {
    let (btc_height, goat_height, goat_spv_height, peg_btc_decimals) = tokio::join!(
        btc_client.get_height(),
        goat_client.get_latest_block_number(),
        goat_client.btc_spv_latest_height(),
        goat_client.peg_btc_decimals(),
    );
    let btc_height = match btc_height {
        Ok(height) => {
            metrics_state.record_btc_backend_probe(true);
            Some(height)
        }
        Err(error) => {
            metrics_state.record_btc_backend_probe(false);
            warn!(event = "metrics_backend_probe", backend = "btc", error = %error, "BTC backend health probe failed");
            None
        }
    };
    let goat_height_healthy = goat_height.is_ok();
    metrics_state.record_goat_backend_probe(goat_height_healthy);
    if let Err(error) = goat_height {
        warn!(event = "metrics_backend_probe", backend = "goat", operation = "get_latest_block_number", error = %error, "Goat backend health probe failed");
    }
    let goat_spv_height = match goat_spv_height {
        Ok(height) => {
            metrics_state.record_goat_backend_probe(true);
            Some(height)
        }
        Err(error) => {
            metrics_state.record_goat_backend_probe(false);
            warn!(event = "metrics_backend_probe", backend = "goat", operation = "btc_spv_latest_height", error = %error, "Goat SPV health probe failed");
            None
        }
    };
    match peg_btc_decimals {
        Ok(decimals) => {
            metrics_state.record_goat_backend_probe(true);
            metrics_state.set_peg_btc_decimals(decimals);
        }
        Err(error) => {
            metrics_state.record_goat_backend_probe(false);
            warn!(event = "metrics_backend_probe", backend = "goat", operation = "peg_btc_decimals", error = %error, "failed to load pegBTC decimals");
        }
    }
    metrics_state.apply_chain_health(btc_height, goat_spv_height);
    metrics_state.mark_backend_ready(
        btc_height.is_some() && goat_height_healthy && goat_spv_height.is_some(),
    );

    match get_node_pubkey() {
        Ok(pubkey) => {
            match btc_client.get_address_utxo(node_p2wsh_address(get_network(), &pubkey)).await {
                Ok(utxos) => {
                    metrics_state.record_btc_backend_probe(true);
                    let balance_sats = utxos.iter().map(|utxo| utxo.value.to_sat()).sum::<u64>();
                    metrics_state.apply_fee_wallet(
                        i64::try_from(balance_sats).unwrap_or(i64::MAX),
                        i64::try_from(utxos.len()).unwrap_or(i64::MAX),
                    );
                }
                Err(error) => {
                    metrics_state.record_btc_backend_probe(false);
                    warn!(event = "metrics_backend_probe", backend = "btc", operation = "get_address_utxo", error = %error, "BTC fee wallet probe failed");
                }
            }
        }
        Err(error) => {
            warn!(event = "metrics_fee_wallet", error = %error, "failed to derive fee wallet address")
        }
    }

    if let Some(goat_address) = get_node_goat_address() {
        match goat_client.native_balance(&goat_address.0).await {
            Ok(balance) => {
                metrics_state.record_goat_backend_probe(true);
                metrics_state.apply_goat_gas_balance(balance);
            }
            Err(error) => {
                metrics_state.record_goat_backend_probe(false);
                warn!(event = "metrics_backend_probe", backend = "goat", operation = "native_balance", error = %error, "Goat gas balance probe failed");
            }
        }
    }

    if *actor == Actor::Operator {
        let stake = async {
            let pubkey = get_node_pubkey()?;
            let xonly: [u8; 32] = pubkey.to_bytes()[1..33]
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid local operator public key"))?;
            let operator_address = goat_client.stake_mana_pubkey_to_address(&xonly).await?;
            let (minimum, locked) = tokio::try_join!(
                goat_client.gateway_get_min_stake_amount(),
                goat_client.stake_mana_lock_stake_of(&operator_address),
            )?;
            Ok::<_, anyhow::Error>(locked >= minimum)
        }
        .await;
        match stake {
            Ok(sufficient) => {
                metrics_state.record_goat_backend_probe(true);
                metrics_state.apply_required_stake(sufficient);
            }
            Err(error) => {
                metrics_state.record_goat_backend_probe(false);
                warn!(event = "metrics_backend_probe", backend = "goat", operation = "required_stake", error = %error, "required stake probe failed");
            }
        }
    } else {
        metrics_state.apply_required_stake(true);
    }
}

/// Return every graph in the requested status. Time-sensitive flows must not
/// let a lower-index graph hide another graph owned by the same operator.
pub(super) async fn fetch_all_graphs_by_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    graph_status: &str,
) -> anyhow::Result<Vec<Graph>> {
    storage_processor.find_graphs_by_status_group_by_operator(graph_status).await
}

/// Return the lowest-index graph for each operator in the requested status.
/// This is only suitable as the entry point for a chain-aware scan.
pub(super) async fn fetch_first_graph_per_operator_by_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    graph_status: &str,
) -> anyhow::Result<Vec<Graph>> {
    let graphs_ori = fetch_all_graphs_by_status(storage_processor, graph_status).await?;
    let mut graphs: Vec<Graph> = vec![];
    let mut pre_operator_pubkey = "".to_string();
    for graph in graphs_ori {
        if graph.operator_pubkey != pre_operator_pubkey {
            pre_operator_pubkey = graph.operator_pubkey.clone();
            graphs.push(graph);
        }
    }
    Ok(graphs)
}

async fn run_maintenance_subtask<T>(
    metrics_state: &MetricsState,
    task: &'static str,
    operation: impl Future<Output = anyhow::Result<T>>,
) {
    let started_at = Instant::now();
    match operation.await {
        Ok(_) => {
            let elapsed = started_at.elapsed();
            metrics_state.record_task_run(task, "success", elapsed);
            debug!(
                event = "maintenance_subtask_result",
                task,
                outcome = "succeeded",
                elapsed_ms = elapsed.as_millis() as u64,
                "maintenance subtask completed"
            )
        }
        Err(error) => {
            let elapsed = started_at.elapsed();
            metrics_state.record_task_run(task, "failed", elapsed);
            warn!(
                event = "maintenance_subtask_result",
                task,
                outcome = "failed",
                elapsed_ms = elapsed.as_millis() as u64,
                error_class = "maintenance",
                error = %error,
                "maintenance subtask failed after execution"
            )
        }
    }
}

enum MaintenanceRunOutcome {
    Completed,
    DeferredHistorySync,
}

async fn run(
    actor: Actor,
    local_db: &LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    metrics_state: &MetricsState,
) -> anyhow::Result<MaintenanceRunOutcome> {
    let btc_client = btc_client.as_ref();
    let goat_client = goat_client.as_ref();

    if is_enable_babe_setup_state_cleanup() && actor_runs_babe_setup_state_cleanup(&actor) {
        run_maintenance_subtask(
            metrics_state,
            "babe_setup_state_cleanup_monitor",
            babe_setup_state_cleanup_monitor(local_db),
        )
        .await;
    }

    if actor == Actor::Operator || is_relayer() {
        run_maintenance_subtask(
            metrics_state,
            "node_available_pbtc_update_monitor",
            node_available_pbtc_update_monitor(local_db, goat_client),
        )
        .await;
    }

    if is_enable_update_spv_contract() {
        run_maintenance_subtask(
            metrics_state,
            "spv_header_hash_update",
            spv_header_hash_update(btc_client, goat_client),
        )
        .await;
    }

    if is_processing_gateway_history_events(local_db, goat_client).await? {
        info!(
            event = "maintenance_subtask_result",
            task = "gateway_history_sync",
            outcome = "deferred",
            role = %actor,
            reason = "history_sync_in_progress",
            "maintenance protocol work deferred while gateway history sync is active"
        );
        return Ok(MaintenanceRunOutcome::DeferredHistorySync);
    }

    run_maintenance_subtask(
        metrics_state,
        "instance_answers_monitor",
        instance_answers_monitor(local_db, btc_client, goat_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "instance_window_expiration_monitor",
        instance_window_expiration_monitor(local_db, goat_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "instance_expiration_monitor",
        instance_expiration_monitor(local_db, btc_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "instance_btc_tx_monitor",
        instance_btc_tx_monitor(local_db, btc_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "pegin_confirm_recovery_monitor",
        pegin_confirm_recovery_monitor(local_db, btc_client, &actor),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "instance_committee_key_cleanup_monitor",
        instance_committee_key_cleanup_monitor(local_db, btc_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "swap_escrow_timeout_monitor",
        swap_escrow_timeout_monitor(local_db),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "detect_init_withdraw_call",
        detect_init_withdraw_call(local_db),
    )
    .await;
    run_maintenance_subtask(metrics_state, "detect_kickoff", detect_kickoff(local_db, btc_client))
        .await;
    run_maintenance_subtask(
        metrics_state,
        "detect_take1_or_challenge",
        detect_take1_or_challenge(local_db, btc_client),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "process_graph_challenge",
        process_graph_challenge(local_db, btc_client),
    )
    .await;
    Ok(MaintenanceRunOutcome::Completed)
}

pub async fn run_maintenance_tasks(
    actor: Actor,
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    interval: u64,
    cancellation_token: CancellationToken,
    metrics_state: MetricsState,
) -> anyhow::Result<String> {
    let mut tick: u64 = 0;
    let maintenance_run_timeout = Duration::from_secs(get_maintenance_run_timeout_secs());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                tick += 1;
                let tick_start = Instant::now();
                info!(
                    event = "maintenance_tick",
                    tick,
                    interval_secs = interval,
                    outcome = "started",
                    "maintenance task tick started"
                );
                // Execute the normal monitoring logic
                match tokio::time::timeout(
                    maintenance_run_timeout,
                    run(
                        actor.clone(),
                        &local_db,
                        btc_client.clone(),
                        goat_client.clone(),
                        &metrics_state,
                    ),
                ).await {
                    Ok(Ok(MaintenanceRunOutcome::Completed)) => {
                        metrics_state.record_task_run("maintenance", "success", tick_start.elapsed());
                        info!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "succeeded",
                            elapsed_ms = tick_start.elapsed().as_millis() as u64,
                            "maintenance task tick completed"
                        );
                    }
                    Ok(Ok(MaintenanceRunOutcome::DeferredHistorySync)) => {
                        metrics_state.record_task_run("maintenance", "success", tick_start.elapsed());
                        info!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "deferred",
                            reason = "history_sync_in_progress",
                            elapsed_ms = tick_start.elapsed().as_millis() as u64,
                            "maintenance protocol work was deferred"
                        );
                    }
                    Ok(Err(error)) => {
                        metrics_state.record_task_run("maintenance", "failed", tick_start.elapsed());
                        error!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "failed",
                            elapsed_ms = tick_start.elapsed().as_millis() as u64,
                            error = %error,
                            "maintenance task returned an error"
                        )
                    }
                    Err(_) => {
                        metrics_state.record_task_run("maintenance", "failed", tick_start.elapsed());
                        error!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "timed_out",
                            timeout_secs = maintenance_run_timeout.as_secs(),
                            elapsed_ms = tick_start.elapsed().as_millis() as u64,
                            "maintenance task tick timed out"
                        )
                    }
                }
                if tick.is_multiple_of(6) {
                    let btc_client = btc_client.clone();
                    let goat_client = goat_client.clone();
                    let metrics_state = metrics_state.clone();
                    let metrics_actor = actor.clone();
                    tokio::spawn(async move {
                        if tokio::time::timeout(
                            Duration::from_secs(30),
                            refresh_alert_health(
                                btc_client.as_ref(),
                                goat_client.as_ref(),
                                &metrics_state,
                                &metrics_actor,
                            ),
                        )
                        .await
                        .is_err()
                        {
                            warn!(event = "metrics_alert_health", "alert health probe timed out");
                        }
                    });
                    let queue_started_at = Instant::now();
                    match local_db.acquire().await {
                        Ok(mut storage) => match storage
                            .get_message_queue_stats(&actor.to_string(), current_time_secs())
                            .await
                        {
                            Ok(stats) => info!(
                                event = "message_queue_snapshot",
                                role = %actor,
                                pending_ready = stats.pending_ready,
                                pending_locked = stats.pending_locked,
                                failed = stats.failed,
                                oldest_pending_at = ?stats.oldest_pending_at,
                                elapsed_ms = queue_started_at.elapsed().as_millis() as u64,
                                "local message queue snapshot"
                            ),
                            Err(error) => error!(
                                event = "db_operation_result",
                                operation = "get_message_queue_stats",
                                outcome = "failed",
                                elapsed_ms = queue_started_at.elapsed().as_millis() as u64,
                                error = %error,
                                "failed to collect local message queue snapshot"
                            ),
                        },
                        Err(error) => error!(
                            event = "db_operation_result",
                            operation = "acquire_db_for_message_queue_snapshot",
                            outcome = "failed",
                            elapsed_ms = queue_started_at.elapsed().as_millis() as u64,
                            error = %error,
                            "failed to acquire local database for message queue snapshot"
                        ),
                    }
                }
            }
            _ = cancellation_token.cancelled() => {
                tracing::info!(
                    event = "maintenance_lifecycle",
                    outcome = "shutdown",
                    role = %actor,
                    "maintenance task received shutdown signal"
                );
                return Ok("maintenance_shutdown".to_string());
            }
        }
    }
}

fn get_timestamp_from_contract_data(input: &[u8; 32]) -> i64 {
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&input[24..32]);
    i64::from_be_bytes(timestamp_bytes)
}
