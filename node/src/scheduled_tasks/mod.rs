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
    actor_runs_babe_setup_state_cleanup, get_maintenance_subtask_timeout_secs, get_network,
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
use tracing::{info, warn};

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
) -> bool {
    run_subtask_with_timeout(
        metrics_state,
        task,
        Duration::from_secs(get_maintenance_subtask_timeout_secs()),
        operation,
    )
    .await
}

async fn run_subtask_with_timeout<T>(
    metrics: &MetricsState,
    task: &'static str,
    budget: Duration,
    operation: impl Future<Output = anyhow::Result<T>>,
) -> bool {
    let started = Instant::now();
    let (outcome, error) =
        match tokio::time::timeout(budget, AssertUnwindSafe(operation).catch_unwind()).await {
            Ok(Ok(Ok(_))) => ("success", None),
            Ok(Ok(Err(error))) => ("failed", Some(format!("{error:#}"))),
            Ok(Err(payload)) => {
                ("failed", Some(crate::error::panic_message(payload.as_ref()).to_string()))
            }
            Err(_) => ("timed_out", Some(format!("subtask exceeded {} seconds", budget.as_secs()))),
        };
    metrics.record_task_run(task, outcome, started.elapsed());
    if let Some(error) = error {
        warn!(event = "maintenance_subtask_result", task, outcome, %error,
            "maintenance subtask did not complete; continuing with later subtasks");
    }
    outcome == "success"
}

enum MaintenanceRunOutcome {
    Completed,
    Failed,
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
    let mut failed = false;
    failed |= !run_maintenance_subtask(
        metrics_state,
        "swap_escrow_timeout_monitor",
        swap_escrow_timeout_monitor(local_db),
    )
    .await;
    failed |= !run_maintenance_subtask(
        metrics_state,
        "inbox_quota_purge",
        crate::p2p_admission::purge_stale_network_events(local_db),
    )
    .await;
    if is_enable_babe_setup_state_cleanup() && actor_runs_babe_setup_state_cleanup(&actor) {
        failed |= !run_maintenance_subtask(
            metrics_state,
            "babe_setup_state_cleanup_monitor",
            babe_setup_state_cleanup_monitor(local_db),
        )
        .await;
    }

    if actor == Actor::Operator || is_relayer() {
        failed |= !run_maintenance_subtask(
            metrics_state,
            "node_available_pbtc_update_monitor",
            node_available_pbtc_update_monitor(local_db, goat_client),
        )
        .await;
    }

    if is_enable_update_spv_contract() {
        failed |= !run_maintenance_subtask(
            metrics_state,
            "spv_header_hash_update",
            spv_header_hash_update(btc_client, goat_client),
        )
        .await;
    }

    let started = Instant::now();
    let mut history_timed_out = false;
    let history = match tokio::time::timeout(
        Duration::from_secs(get_maintenance_subtask_timeout_secs()),
        AssertUnwindSafe(history_check).catch_unwind(),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Err(_) => {
            history_timed_out = true;
            Err(anyhow::anyhow!("history sync check timed out"))
        }
        Ok(Err(payload)) => Err(anyhow::anyhow!(
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
                "L2 maintenance deferred during history sync"
            );
            MaintenanceRunOutcome::DeferredHistorySync
        }
        Err(error) => {
            let outcome = if history_timed_out { "timed_out" } else { "failed" };
            metrics_state.record_task_run("gateway_history_sync", outcome, started.elapsed());
            warn!(event = "maintenance_subtask_result", task = "gateway_history_sync", outcome, error = %error,
                "L2 maintenance deferred because history state is unavailable");
            MaintenanceRunOutcome::DeferredHistorySyncUnknown
        }
    };
    if matches!(outcome, MaintenanceRunOutcome::Completed) {
        // New peg-in requests become instance rows and `pegin_request` events.
        failed |= !run_maintenance_subtask(
            metrics_state,
            "pegin_request_monitor",
            pegin_request_monitor(local_db, btc_client, goat_client, engine),
        )
        .await;
        // Chain facts for the Instance aggregate; the apply decides every status.
        failed |= !run_maintenance_subtask(
            metrics_state,
            "instance_answer_window_scan",
            scan_answer_windows(local_db, goat_client, engine),
        )
        .await;
    }
    Ok(if failed { MaintenanceRunOutcome::Failed } else { outcome })
}

async fn run_bitcoin_scans(
    actor: &Actor,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    metrics_state: &MetricsState,
    engine: &EngineHandle,
) {
    let started = Instant::now();
    let mut failed = false;
    // The Bitcoin lane progresses independently of history/indexer/GOAT maintenance checks.
    failed |= !run_maintenance_subtask(
        metrics_state,
        "graph_chain_scan",
        scan_graphs_on_chain(local_db, btc_client, goat_client, engine),
    )
    .await;
    failed |= !run_maintenance_subtask(
        metrics_state,
        "instance_btc_scan",
        scan_instances_on_bitcoin(local_db, btc_client, engine, actor),
    )
    .await;
    if *actor == Actor::Operator {
        failed |= !run_maintenance_subtask(
            metrics_state,
            "graph_setup_abandon_scan",
            abandon_unfinished_setups(local_db, btc_client, engine),
        )
        .await;
    }

    let outcome = if failed { "failed" } else { "success" };
    metrics_state.record_task_run("bitcoin_maintenance", outcome, started.elapsed());
    info!(
        event = "maintenance_tick_result",
        lane = "bitcoin",
        outcome,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Bitcoin maintenance pass finished"
    );
}

/// Each lane is serial internally. Cancelling this parent drops both in-flight passes.
async fn maintenance_lanes<B, BF, M, MF>(
    interval: Duration,
    cancel: &CancellationToken,
    mut bitcoin: B,
    mut maintenance: M,
) where
    B: FnMut() -> BF,
    BF: Future<Output = ()>,
    M: FnMut() -> MF,
    MF: Future<Output = ()>,
{
    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = async {
            tokio::join!(
                async { loop { tokio::time::sleep(interval).await; bitcoin().await; } },
                async { loop { tokio::time::sleep(interval).await; maintenance().await; } },
            );
        } => {},
    }
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
    let tick = std::sync::atomic::AtomicU64::new(0);
    maintenance_lanes(
        Duration::from_secs(interval),
        &cancellation_token,
        || run_bitcoin_scans(&actor, &local_db, &btc_client, &goat_client, &metrics_state, &engine),
        || async {
            let started = Instant::now();
            let result = run(
                actor.clone(),
                &local_db,
                btc_client.clone(),
                goat_client.clone(),
                &metrics_state,
                &engine,
            )
            .await;
            let mut outcome = match result {
                Ok(MaintenanceRunOutcome::Completed) => "success",
                Ok(MaintenanceRunOutcome::DeferredHistorySync) => "deferred",
                _ => "failed",
            };
            let tick = tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed).wrapping_add(1);
            if tick.is_multiple_of(6) {
                // This probe is bounded and belongs to the non-Bitcoin lane too.
                if !run_maintenance_subtask(&metrics_state, "alert_health", async {
                    refresh_alert_health(&btc_client, &goat_client, &metrics_state, &actor).await;
                    Ok(())
                })
                .await
                {
                    outcome = "failed";
                }
            }
            metrics_state.record_task_run("maintenance", outcome, started.elapsed());
            info!(
                event = "maintenance_tick_result",
                lane = "maintenance",
                outcome,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Maintenance pass finished"
            );
        },
    )
    .await;
    Ok("maintenance_shutdown".to_string())
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
    async fn blocked_maintenance_does_not_delay_bitcoin_ticks_and_cancels_cleanly() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let bitcoin_ticks = AtomicUsize::new(0);
        let maintenance_ticks = AtomicUsize::new(0);
        let dropped = AtomicUsize::new(0);
        struct DropCount<'a>(&'a AtomicUsize);
        impl Drop for DropCount<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let cancel = CancellationToken::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            maintenance_lanes(
                Duration::from_millis(1),
                &cancel,
                || async {
                    if bitcoin_ticks.fetch_add(1, Ordering::SeqCst) >= 3 {
                        cancel.cancel();
                    }
                },
                || async {
                    maintenance_ticks.fetch_add(1, Ordering::SeqCst);
                    let _guard = DropCount(&dropped);
                    std::future::pending::<()>().await;
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(bitcoin_ticks.load(Ordering::SeqCst), 4);
        assert_eq!(maintenance_ticks.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn subtask_timeout_does_not_cancel_later_work_or_report_success() {
        let registry = Arc::new(Mutex::new(libp2p_metrics::Registry::default()));
        let metrics = MetricsState::new(registry.clone());
        let mut failed = !run_subtask_with_timeout(
            &metrics,
            "slow",
            Duration::from_millis(1),
            std::future::pending::<anyhow::Result<()>>(),
        )
        .await;
        let mut completed = false;
        failed |= !run_maintenance_subtask(&metrics, "later", async {
            completed = true;
            Ok(())
        })
        .await;
        assert!(failed && completed);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry.lock().unwrap()).unwrap();
        assert!(output.contains("task=\"slow\",outcome=\"timed_out\""));
        assert!(output.contains("task=\"later\",outcome=\"success\""));
        assert!(!output.contains("task=\"slow\",outcome=\"success\""));
    }

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
            run_bitcoin_scans(&Actor::Verifier, &db, &btc, &goat, &metrics, &engine).await;
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
        run_bitcoin_scans(&Actor::Verifier, &db, &btc, &goat, &metrics, &engine).await;
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            run_with_history_check(
                Actor::Verifier,
                &db,
                btc.clone(),
                goat.clone(),
                &metrics,
                &engine,
                async {
                    assert_bitcoin_scans_completed(&registry);
                    std::future::pending::<anyhow::Result<bool>>().await
                },
            ),
        )
        .await;
        assert!(result.is_err());
        assert_bitcoin_scans_completed(&registry);
        // A failure must override a normal history deferral in the aggregate outcome.
        db.conn.close().await;
        let outcome =
            run_with_history_check(Actor::Verifier, &db, btc, goat, &metrics, &engine, async {
                Ok(true)
            })
            .await
            .unwrap();
        assert!(matches!(outcome, MaintenanceRunOutcome::Failed));
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
