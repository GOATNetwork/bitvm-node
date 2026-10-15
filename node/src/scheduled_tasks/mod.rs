mod babe_setup_state_cleanup_task;
mod event_watch;
mod node_maintenance_tasks;
mod sequencer_set_hash_monitor_task;
mod spv_maintenance_tasks;
mod swap_maintenance_tasks;

use crate::aggregates::graph_scan::{abandon_unfinished_setups, scan_graphs_on_chain};
use crate::aggregates::instance_scan::{
    pegin_request_monitor, scan_answer_windows, scan_instances_on_bitcoin,
};
use crate::env::{
    actor_runs_babe_setup_state_cleanup, get_maintenance_run_timeout_secs, get_network,
    get_node_goat_address, get_node_pubkey, is_enable_babe_setup_state_cleanup,
    is_enable_update_spv_contract, is_relayer,
};
use crate::metrics_service::MetricsState;
use crate::scheduled_tasks::babe_setup_state_cleanup_task::babe_setup_state_cleanup_monitor;
use crate::scheduled_tasks::node_maintenance_tasks::node_available_pbtc_update_monitor;
use crate::scheduled_tasks::spv_maintenance_tasks::spv_header_hash_update;
use crate::scheduled_tasks::swap_maintenance_tasks::swap_escrow_timeout_monitor;
use crate::utils::node_p2wsh_address;
use bitvm_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use engine::EngineHandle;
pub use event_watch::{is_processing_gateway_history_events, run_watch_event_task};
pub use sequencer_set_hash_monitor_task::run_sequencer_set_hash_monitor_task;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::LocalDB;
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
    /// The history-sync check itself failed (Goat read): protocol work is
    /// deferred to the next tick, not reported as a tick error.
    DeferredHistorySyncUnknown,
}

async fn run(
    actor: Actor,
    local_db: &LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    metrics_state: &MetricsState,
    engine: &EngineHandle,
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

    let history_sync_in_progress = match is_processing_gateway_history_events(local_db, goat_client)
        .await
    {
        Ok(in_progress) => in_progress,
        Err(error) => {
            warn!(
                event = "maintenance_subtask_result",
                task = "gateway_history_sync",
                outcome = "failed",
                error_class = "maintenance",
                error = %error,
                "could not check the gateway history sync; protocol work deferred to the next tick"
            );
            return Ok(MaintenanceRunOutcome::DeferredHistorySyncUnknown);
        }
    };
    if history_sync_in_progress {
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

    // New peg-in requests become instance rows and `pegin_request` events.
    run_maintenance_subtask(
        metrics_state,
        "pegin_request_monitor",
        pegin_request_monitor(local_db, btc_client, goat_client, engine),
    )
    .await;
    // Chain facts for the Instance aggregate; the apply decides every status.
    run_maintenance_subtask(
        metrics_state,
        "instance_answer_window_scan",
        scan_answer_windows(local_db, goat_client, engine),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "instance_btc_scan",
        scan_instances_on_bitcoin(local_db, btc_client, engine, &actor),
    )
    .await;
    run_maintenance_subtask(
        metrics_state,
        "swap_escrow_timeout_monitor",
        swap_escrow_timeout_monitor(local_db),
    )
    .await;
    // Rejected and stale unregistered network events leave the inbox quota.
    run_maintenance_subtask(
        metrics_state,
        "inbox_quota_purge",
        crate::p2p_admission::purge_stale_network_events(local_db),
    )
    .await;
    // Chain facts for the Graph aggregate's peg-out phases.
    run_maintenance_subtask(
        metrics_state,
        "graph_chain_scan",
        scan_graphs_on_chain(local_db, btc_client, goat_client, engine),
    )
    .await;
    if actor == Actor::Operator {
        run_maintenance_subtask(
            metrics_state,
            "graph_setup_abandon_scan",
            abandon_unfinished_setups(local_db, btc_client, engine),
        )
        .await;
    }
    Ok(MaintenanceRunOutcome::Completed)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_maintenance_tasks(
    actor: Actor,
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    interval: u64,
    cancellation_token: CancellationToken,
    metrics_state: MetricsState,
    engine: EngineHandle,
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
                        &engine,
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
                    Ok(Ok(MaintenanceRunOutcome::DeferredHistorySyncUnknown)) => {
                        metrics_state.record_task_run("maintenance", "failed", tick_start.elapsed());
                        warn!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "deferred",
                            reason = "history_sync_check_failed",
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
