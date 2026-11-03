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
use futures::FutureExt;
pub use sequencer_set_hash_monitor_task::run_sequencer_set_hash_monitor_task;
use std::future::Future;
use std::panic::AssertUnwindSafe;
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
            metrics_state.backend_probe_failed("btc", "get_height", &error);
            None
        }
    };
    let goat_height_healthy = goat_height.is_ok();
    match &goat_height {
        Ok(_) => metrics_state.record_goat_backend_probe(true),
        Err(error) => metrics_state.backend_probe_failed("goat", "get_latest_block_number", error),
    }
    let goat_spv_height = match goat_spv_height {
        Ok(height) => {
            metrics_state.record_goat_backend_probe(true);
            Some(height)
        }
        Err(error) => {
            metrics_state.backend_probe_failed("goat", "btc_spv_latest_height", &error);
            None
        }
    };
    match peg_btc_decimals {
        Ok(decimals) => {
            metrics_state.record_goat_backend_probe(true);
            metrics_state.set_peg_btc_decimals(decimals);
        }
        Err(error) => {
            metrics_state.backend_probe_failed("goat", "peg_btc_decimals", &error);
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
                    metrics_state.backend_probe_failed("btc", "get_address_utxo", &error);
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
                metrics_state.backend_probe_failed("goat", "native_balance", &error);
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
                metrics_state.backend_probe_failed("goat", "required_stake", &error);
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
    match AssertUnwindSafe(operation).catch_unwind().await {
        Ok(Ok(_)) => {
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
        Ok(Err(error)) => {
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
        Err(payload) => {
            let elapsed = started_at.elapsed();
            metrics_state.record_task_run(task, "failed", elapsed);
            error!(
                event = "maintenance_subtask_result",
                task,
                outcome = "failed",
                elapsed_ms = elapsed.as_millis() as u64,
                error_class = "panic",
                error = crate::error::panic_message(payload.as_ref()),
                "maintenance subtask panicked; continuing with later subtasks"
            );
        }
    }
}

enum MaintenanceRunOutcome {
    Completed,
    DeferredHistorySync,
    /// History metadata is unavailable; only L2/history-dependent work is deferred.
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
    run_with_history_check(
        actor,
        local_db,
        btc_client,
        goat_client,
        metrics_state,
        engine,
        is_processing_gateway_history_events(local_db),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_with_history_check(
    actor: Actor,
    local_db: &LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    metrics_state: &MetricsState,
    engine: &EngineHandle,
    history_check: impl Future<Output = anyhow::Result<bool>>,
) -> anyhow::Result<MaintenanceRunOutcome> {
    let btc_client = btc_client.as_ref();
    let goat_client = goat_client.as_ref();
    // These safety scans run before a history/indexer/GOAT health check can defer work.
    run_maintenance_subtask(
        metrics_state,
        "graph_chain_scan",
        scan_graphs_on_chain(local_db, btc_client, goat_client, engine),
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
    run_maintenance_subtask(
        metrics_state,
        "inbox_quota_purge",
        crate::p2p_admission::purge_stale_network_events(local_db),
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

    let started = Instant::now();
    let history = match AssertUnwindSafe(history_check).catch_unwind().await {
        Ok(result) => result,
        Err(payload) => Err(anyhow::anyhow!(
            "history sync check panicked: {}",
            crate::error::panic_message(payload.as_ref())
        )),
    };
    let outcome = match history {
        Ok(false) => {
            metrics_state.record_task_run("gateway_history_sync", "success", started.elapsed());
            MaintenanceRunOutcome::Completed
        }
        Ok(true) => {
            metrics_state.record_task_run("gateway_history_sync", "deferred", started.elapsed());
            info!(
                event = "maintenance_subtask_result",
                task = "gateway_history_sync",
                outcome = "deferred",
                "L2 maintenance deferred during history sync; Bitcoin scans already ran"
            );
            MaintenanceRunOutcome::DeferredHistorySync
        }
        Err(error) => {
            metrics_state.record_task_run("gateway_history_sync", "failed", started.elapsed());
            warn!(event = "maintenance_subtask_result", task = "gateway_history_sync", outcome = "failed", error = %error,
                "L2 maintenance deferred because history state is unavailable; Bitcoin scans already ran");
            MaintenanceRunOutcome::DeferredHistorySyncUnknown
        }
    };
    if matches!(outcome, MaintenanceRunOutcome::Completed) {
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
    }
    Ok(outcome)
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
                        metrics_state.record_task_run("maintenance", "deferred", tick_start.elapsed());
                        info!(
                            event = "maintenance_tick_result",
                            tick,
                            outcome = "deferred",
                            reason = "history_sync_in_progress",
                            elapsed_ms = tick_start.elapsed().as_millis() as u64,
                            "L2 maintenance was deferred; Bitcoin safety scans completed"
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
                            "L2 maintenance was deferred; Bitcoin safety scans completed"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test]
    async fn bitcoin_scans_run_before_pending_or_failed_history_checks() {
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("maintenance.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        let (btc, _) = BTCClient::new_mock_client();
        let (goat, _) = GOATClient::new_mock_client();
        let (engine, _acks) =
            engine::EngineBuilder::new(db.clone(), engine::EngineConfig::default()).build();
        let engine = engine.handle();
        let btc = Arc::new(btc);
        let goat = Arc::new(goat);
        for failed in [false, true] {
            let registry = Arc::new(Mutex::new(libp2p_metrics::Registry::default()));
            let metrics = MetricsState::new(registry.clone());
            let outcome = run_with_history_check(
                Actor::Verifier,
                &db,
                btc.clone(),
                goat.clone(),
                &metrics,
                &engine,
                async {
                    assert_bitcoin_scans_completed(&registry);
                    if failed {
                        anyhow::bail!("indexer unavailable")
                    }
                    Ok(true)
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                (failed, outcome),
                (false, MaintenanceRunOutcome::DeferredHistorySync)
                    | (true, MaintenanceRunOutcome::DeferredHistorySyncUnknown)
            ));
            let mut output = String::new();
            prometheus_client::encoding::text::encode(&mut output, &registry.lock().unwrap())
                .unwrap();
            let expected = if failed { "failed" } else { "deferred" };
            assert!(
                output.contains(&format!("task=\"gateway_history_sync\",outcome=\"{expected}\""))
            );
            assert!(!output.contains("task=\"pegin_request_monitor\""));
            assert!(!output.contains("task=\"instance_answer_window_scan\""));
        }
        let registry = Arc::new(Mutex::new(libp2p_metrics::Registry::default()));
        let metrics = MetricsState::new(registry.clone());
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            run_with_history_check(Actor::Verifier, &db, btc, goat, &metrics, &engine, async {
                assert_bitcoin_scans_completed(&registry);
                std::future::pending::<anyhow::Result<bool>>().await
            }),
        )
        .await;
        assert!(result.is_err());
        assert_bitcoin_scans_completed(&registry);
    }

    fn assert_bitcoin_scans_completed(registry: &Arc<Mutex<libp2p_metrics::Registry>>) {
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry.lock().unwrap()).unwrap();
        for task in ["graph_chain_scan", "instance_btc_scan"] {
            assert!(
                output.contains(&format!(
                    "bitvm_node_task_runs_total{{task=\"{task}\",outcome=\"success\"}} 1"
                )),
                "{output}"
            );
        }
    }

    #[tokio::test]
    async fn panicking_subtasks_are_failed_and_later_subtasks_still_run() {
        let registry = Arc::new(Mutex::new(libp2p_metrics::Registry::default()));
        let metrics = MetricsState::new(registry.clone());
        run_maintenance_subtask::<()>(&metrics, "panicking", async {
            tokio::task::yield_now().await;
            std::panic::panic_any(17u8);
        })
        .await;
        run_maintenance_subtask::<()>(&metrics, "backend_error", async {
            anyhow::bail!("backend unavailable")
        })
        .await;
        let mut completed = false;
        run_maintenance_subtask(&metrics, "next", async {
            completed = true;
            Ok(())
        })
        .await;
        assert!(completed);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry.lock().unwrap()).unwrap();
        for (task, outcome) in
            [("panicking", "failed"), ("backend_error", "failed"), ("next", "success")]
        {
            assert!(output.contains(&format!(
                "bitvm_node_task_runs_total{{task=\"{task}\",outcome=\"{outcome}\"}} 1"
            )));
        }
        assert!(!output.contains("task=\"panicking\",outcome=\"success\""));
    }
}
