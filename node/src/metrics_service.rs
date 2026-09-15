use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::rpc_service::{AppState, current_time_secs};
use alloy::primitives::U256;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use libp2p_metrics::Registry;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use store::{GraphStatus, InstanceBridgeInStatus, MessageState, SwapEscrowStatus};
use tokio::time::Instant;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";
const BTC_DECIMALS: u8 = 8;
const UNKNOWN_TOKEN_DECIMALS: u8 = u8::MAX;

// Some queue and P2P helpers intentionally only receive their narrow runtime context.
// A node process owns one registry, so this shared handle keeps those helpers observable.
static NODE_METRICS_STATE: OnceLock<MetricsState> = OnceLock::new();

pub fn set_node_metrics_state(metrics_state: MetricsState) {
    let _ = NODE_METRICS_STATE.set(metrics_state);
}

pub fn node_metrics_state() -> Option<&'static MetricsState> {
    NODE_METRICS_STATE.get()
}

/// Creates a duration histogram using the shared HTTP and task latency buckets.
fn duration_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.005, 2.0, 15))
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    route: String,
    status: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRouteLabels {
    method: String,
    route: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TaskOutcomeLabels {
    task: String,
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TaskLabels {
    task: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct MessageDispatchLabels {
    message_type: String,
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct OutcomeLabels {
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct EventWatchStateLabels {
    state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventWatchState {
    Healthy,
    Syncing,
    Failed,
}

impl EventWatchState {
    const ALL: [Self; 3] = [Self::Healthy, Self::Syncing, Self::Failed];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Syncing => "syncing",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Default)]
struct ReadinessState {
    startup_ready: AtomicBool,
    database_ready: AtomicBool,
    backend_ready: AtomicBool,
    event_watcher_ready: AtomicBool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct InstanceLabels {
    flow: String,
    status: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct StatusLabels {
    status: String,
}

#[derive(Clone, Debug)]
pub struct MetricsState {
    pub registry: Arc<Mutex<Registry>>,
    http_requests_total: Family<HttpRequestLabels, Counter>,
    http_request_duration_seconds: Family<HttpRouteLabels, Histogram>,
    http_requests_in_flight: Gauge,
    task_runs_total: Family<TaskOutcomeLabels, Counter>,
    task_duration_seconds: Family<TaskLabels, Histogram>,
    task_last_success_timestamp_seconds: Family<TaskLabels, Gauge>,
    message_dispatch_total: Family<MessageDispatchLabels, Counter>,
    instances: Family<InstanceLabels, Gauge>,
    graphs: Family<StatusLabels, Gauge>,
    messages: Family<StatusLabels, Gauge>,
    oldest_pending_message_age_seconds: Gauge,
    ready: Gauge,
    db_busy_retries_total: Counter,
    db_errors_total: Counter,
    pegin_oldest_active_age_seconds: Gauge,
    pegin_oldest_committee_wait_age_seconds: Gauge,
    pegout_oldest_active_age_seconds: Gauge,
    operator_available_pegbtc_sats: Gauge,
    fee_wallet_balance_sats: Gauge,
    fee_wallet_spendable_utxos: Gauge,
    graph_validation_total: Family<OutcomeLabels, Counter>,
    message_retry_total: Counter,
    p2p_publish_total: Family<OutcomeLabels, Counter>,
    p2p_receive_total: Family<OutcomeLabels, Counter>,
    p2p_oversized_messages_total: Counter,
    btc_backend_requests_total: Family<OutcomeLabels, Counter>,
    btc_backend_last_success_timestamp_seconds: Gauge,
    goat_backend_requests_total: Family<OutcomeLabels, Counter>,
    goat_backend_last_success_timestamp_seconds: Gauge,
    spv_lag_blocks: Gauge,
    event_watch_ready: Gauge,
    event_watch_state: Family<EventWatchStateLabels, Gauge>,
    event_watch_last_success_timestamp_seconds: Gauge,
    pegin_graph_setup_total: Family<OutcomeLabels, Counter>,
    pegin_confirm_total: Family<OutcomeLabels, Counter>,
    pegin_post_total: Family<OutcomeLabels, Counter>,
    pegout_disprove_total: Counter,
    withdraw_finalize_total: Family<OutcomeLabels, Counter>,
    goat_gas_balance_wei: Gauge,
    required_stake_sufficient: Gauge,
    soldering_payload_io_total: Family<OutcomeLabels, Counter>,
    btc_tx_broadcast_total: Family<OutcomeLabels, Counter>,
    event_watch_lag_blocks: Gauge,
    readiness: Arc<ReadinessState>,
    peg_btc_decimals: Arc<AtomicU8>,
}

struct InFlightGuard(Gauge);

impl Drop for InFlightGuard {
    /// Decrements the in-flight request gauge when request processing ends or is cancelled.
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl MetricsState {
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        let http_requests_total = Family::default();
        let http_request_duration_seconds: Family<HttpRouteLabels, Histogram> =
            Family::new_with_constructor(duration_histogram);
        let http_requests_in_flight = Gauge::default();
        let task_runs_total = Family::default();
        let task_duration_seconds: Family<TaskLabels, Histogram> =
            Family::new_with_constructor(duration_histogram);
        let task_last_success_timestamp_seconds = Family::default();
        let message_dispatch_total = Family::default();
        let instances = Family::default();
        let graphs = Family::default();
        let messages = Family::default();
        let oldest_pending_message_age_seconds = Gauge::default();
        let ready = Gauge::default();
        let db_busy_retries_total = Counter::default();
        let db_errors_total = Counter::default();
        let pegin_oldest_active_age_seconds = Gauge::default();
        let pegin_oldest_committee_wait_age_seconds = Gauge::default();
        let pegout_oldest_active_age_seconds = Gauge::default();
        let operator_available_pegbtc_sats = Gauge::default();
        let fee_wallet_balance_sats = Gauge::default();
        let fee_wallet_spendable_utxos = Gauge::default();
        let graph_validation_total = Family::default();
        let message_retry_total = Counter::default();
        let p2p_publish_total = Family::default();
        let p2p_receive_total = Family::default();
        let p2p_oversized_messages_total = Counter::default();
        let btc_backend_requests_total = Family::default();
        let btc_backend_last_success_timestamp_seconds = Gauge::default();
        let goat_backend_requests_total = Family::default();
        let goat_backend_last_success_timestamp_seconds = Gauge::default();
        let spv_lag_blocks = Gauge::default();
        let event_watch_ready = Gauge::default();
        let event_watch_state: Family<EventWatchStateLabels, Gauge> = Family::default();
        for state in EventWatchState::ALL {
            event_watch_state
                .get_or_create(&EventWatchStateLabels { state: state.as_str().to_owned() })
                .set(0);
        }
        let event_watch_last_success_timestamp_seconds = Gauge::default();
        let pegin_graph_setup_total = Family::default();
        let pegin_confirm_total = Family::default();
        let pegin_post_total = Family::default();
        let pegout_disprove_total = Counter::default();
        let withdraw_finalize_total = Family::default();
        let goat_gas_balance_wei = Gauge::default();
        let required_stake_sufficient = Gauge::default();
        let soldering_payload_io_total = Family::default();
        let btc_tx_broadcast_total = Family::default();
        let event_watch_lag_blocks = Gauge::default();
        let readiness = Arc::new(ReadinessState::default());
        let peg_btc_decimals = Arc::new(AtomicU8::new(UNKNOWN_TOKEN_DECIMALS));

        {
            let mut registry = registry.lock().unwrap();
            registry.register(
                "http_requests",
                "Total number of HTTP requests",
                http_requests_total.clone(),
            );
            registry.register(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
                http_request_duration_seconds.clone(),
            );
            registry.register(
                "http_requests_in_flight",
                "Number of HTTP requests currently being processed",
                http_requests_in_flight.clone(),
            );
            registry.register(
                "bitvm_node_task_runs",
                "Total number of node task runs",
                task_runs_total.clone(),
            );
            registry.register(
                "bitvm_node_task_duration_seconds",
                "Node task duration in seconds",
                task_duration_seconds.clone(),
            );
            registry.register(
                "bitvm_node_task_last_success_timestamp_seconds",
                "Unix timestamp of the last successful node task run",
                task_last_success_timestamp_seconds.clone(),
            );
            registry.register(
                "bitvm_node_message_dispatch",
                "Total number of protocol message dispatches",
                message_dispatch_total.clone(),
            );
            registry.register(
                "bitvm_node_instances",
                "Number of bridge instances by flow and status",
                instances.clone(),
            );
            registry.register("bitvm_node_graphs", "Number of graphs by status", graphs.clone());
            registry.register(
                "bitvm_node_messages",
                "Number of queued messages by state",
                messages.clone(),
            );
            registry.register(
                "bitvm_node_oldest_pending_message_age_seconds",
                "Age in seconds of the oldest pending message",
                oldest_pending_message_age_seconds.clone(),
            );
            registry.register(
                "bitvm_node_ready",
                "Whether the node is ready to process work",
                ready.clone(),
            );
            registry.register(
                "bitvm_node_db_busy_retries",
                "Total SQLite busy or locked retries",
                db_busy_retries_total.clone(),
            );
            registry.register(
                "bitvm_node_db_errors",
                "Total non-retryable database metric collection errors",
                db_errors_total.clone(),
            );
            registry.register(
                "bitvm_node_pegin_oldest_active_age_seconds",
                "Age of the oldest active Pegin",
                pegin_oldest_active_age_seconds.clone(),
            );
            registry.register(
                "bitvm_node_pegin_oldest_committee_wait_age_seconds",
                "Age of the oldest Pegin waiting for committee responses",
                pegin_oldest_committee_wait_age_seconds.clone(),
            );
            registry.register(
                "bitvm_node_pegout_oldest_active_age_seconds",
                "Age of the oldest active Pegout",
                pegout_oldest_active_age_seconds.clone(),
            );
            registry.register(
                "bitvm_node_operator_available_pegbtc_sats",
                "Locally recorded operator available pBTC in sats",
                operator_available_pegbtc_sats.clone(),
            );
            registry.register(
                "bitvm_node_fee_wallet_balance_sats",
                "Current node fee wallet balance in sats",
                fee_wallet_balance_sats.clone(),
            );
            registry.register(
                "bitvm_node_fee_wallet_spendable_utxos",
                "Current node fee wallet spendable UTXO count",
                fee_wallet_spendable_utxos.clone(),
            );
            registry.register(
                "bitvm_node_graph_validation",
                "Total graph validation outcomes",
                graph_validation_total.clone(),
            );
            registry.register(
                "bitvm_node_message_retry",
                "Total deferred protocol messages",
                message_retry_total.clone(),
            );
            registry.register(
                "bitvm_node_p2p_publish",
                "Total P2P message publish outcomes",
                p2p_publish_total.clone(),
            );
            registry.register(
                "bitvm_node_p2p_receive",
                "Total P2P message parse outcomes",
                p2p_receive_total.clone(),
            );
            registry.register(
                "bitvm_node_p2p_oversized_messages",
                "Total P2P messages exceeding the configured transmit limit",
                p2p_oversized_messages_total.clone(),
            );
            registry.register(
                "bitvm_node_btc_backend_requests",
                "Total BTC backend health probe outcomes",
                btc_backend_requests_total.clone(),
            );
            registry.register(
                "bitvm_node_btc_backend_last_success_timestamp_seconds",
                "Unix timestamp of the last successful BTC backend health probe",
                btc_backend_last_success_timestamp_seconds.clone(),
            );
            registry.register(
                "bitvm_node_goat_backend_requests",
                "Total Goat backend health probe outcomes",
                goat_backend_requests_total.clone(),
            );
            registry.register(
                "bitvm_node_goat_backend_last_success_timestamp_seconds",
                "Unix timestamp of the last successful Goat backend health probe",
                goat_backend_last_success_timestamp_seconds.clone(),
            );
            registry.register(
                "bitvm_node_spv_lag_blocks",
                "BTC tip minus Goat SPV height",
                spv_lag_blocks.clone(),
            );
            registry.register(
                "bitvm_node_event_watch_ready",
                "Compatibility gauge that is one only when every event watcher is healthy",
                event_watch_ready.clone(),
            );
            registry.register(
                "bitvm_node_event_watch_state",
                "Current event watcher state; exactly one of healthy, syncing, or failed is one",
                event_watch_state.clone(),
            );
            registry.register(
                "bitvm_node_event_watch_last_success_timestamp_seconds",
                "Unix timestamp of the last successful event watcher run",
                event_watch_last_success_timestamp_seconds.clone(),
            );
            registry.register(
                "bitvm_node_pegin_graph_setup",
                "Total Pegin graph setup outcomes",
                pegin_graph_setup_total.clone(),
            );
            registry.register(
                "bitvm_node_pegin_confirm",
                "Total PeginConfirm broadcast outcomes",
                pegin_confirm_total.clone(),
            );
            registry.register(
                "bitvm_node_pegin_post",
                "Total postPeginData outcomes",
                pegin_post_total.clone(),
            );
            registry.register(
                "bitvm_node_pegout_disprove",
                "Total confirmed Disprove terminal events",
                pegout_disprove_total.clone(),
            );
            registry.register(
                "bitvm_node_withdraw_finalize",
                "Total relayer withdraw finalize outcomes",
                withdraw_finalize_total.clone(),
            );
            registry.register(
                "bitvm_node_goat_gas_balance_wei",
                "Current Goat native gas balance in wei",
                goat_gas_balance_wei.clone(),
            );
            registry.register(
                "bitvm_node_required_stake_sufficient",
                "Whether the local role satisfies the required stake",
                required_stake_sufficient.clone(),
            );
            registry.register(
                "bitvm_node_soldering_payload_io",
                "Total soldering payload read and write outcomes",
                soldering_payload_io_total.clone(),
            );
            registry.register(
                "bitvm_node_btc_tx_broadcast",
                "Total Bitcoin transaction broadcast outcomes",
                btc_tx_broadcast_total.clone(),
            );
            registry.register(
                "bitvm_node_event_watch_lag_blocks",
                "Maximum event watcher lag in finalized Goat blocks",
                event_watch_lag_blocks.clone(),
            );
        }

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
            task_runs_total,
            task_duration_seconds,
            task_last_success_timestamp_seconds,
            message_dispatch_total,
            instances,
            graphs,
            messages,
            oldest_pending_message_age_seconds,
            ready,
            db_busy_retries_total,
            db_errors_total,
            pegin_oldest_active_age_seconds,
            pegin_oldest_committee_wait_age_seconds,
            pegout_oldest_active_age_seconds,
            operator_available_pegbtc_sats,
            fee_wallet_balance_sats,
            fee_wallet_spendable_utxos,
            graph_validation_total,
            message_retry_total,
            p2p_publish_total,
            p2p_receive_total,
            p2p_oversized_messages_total,
            btc_backend_requests_total,
            btc_backend_last_success_timestamp_seconds,
            goat_backend_requests_total,
            goat_backend_last_success_timestamp_seconds,
            spv_lag_blocks,
            event_watch_ready,
            event_watch_state,
            event_watch_last_success_timestamp_seconds,
            pegin_graph_setup_total,
            pegin_confirm_total,
            pegin_post_total,
            pegout_disprove_total,
            withdraw_finalize_total,
            goat_gas_balance_wei,
            required_stake_sufficient,
            soldering_payload_io_total,
            btc_tx_broadcast_total,
            event_watch_lag_blocks,
            readiness,
            peg_btc_decimals,
        }
    }

    /// Records a task outcome and duration, updating its success timestamp when applicable.
    pub fn record_task_run(&self, task: &str, outcome: &str, duration: Duration) {
        self.task_runs_total
            .get_or_create(&TaskOutcomeLabels {
                task: task.to_owned(),
                outcome: outcome.to_owned(),
            })
            .inc();
        self.task_duration_seconds
            .get_or_create(&TaskLabels { task: task.to_owned() })
            .observe(duration.as_secs_f64());
        if outcome == "success" {
            self.task_last_success_timestamp_seconds
                .get_or_create(&TaskLabels { task: task.to_owned() })
                .set(current_time_secs());
            if task == "event_watcher" {
                self.event_watch_last_success_timestamp_seconds.set(current_time_secs());
            }
        }
    }

    /// Records the outcome of dispatching a decoded protocol message.
    pub fn record_message_dispatch(&self, message_type: &str, outcome: &str) {
        self.message_dispatch_total
            .get_or_create(&MessageDispatchLabels {
                message_type: message_type.to_owned(),
                outcome: outcome.to_owned(),
            })
            .inc();
    }

    pub fn mark_startup_ready(&self) {
        self.readiness.startup_ready.store(true, Ordering::Relaxed);
        self.refresh_ready();
    }

    pub fn mark_database_ready(&self, ready: bool) {
        self.readiness.database_ready.store(ready, Ordering::Relaxed);
        self.refresh_ready();
    }

    pub fn mark_backend_ready(&self, ready: bool) {
        self.readiness.backend_ready.store(ready, Ordering::Relaxed);
        self.refresh_ready();
    }

    pub fn set_event_watch_state(&self, state: EventWatchState) {
        for candidate in EventWatchState::ALL {
            self.event_watch_state
                .get_or_create(&EventWatchStateLabels { state: candidate.as_str().to_owned() })
                .set(i64::from(candidate == state));
        }

        let healthy = state == EventWatchState::Healthy;
        self.readiness.event_watcher_ready.store(healthy, Ordering::Relaxed);
        self.event_watch_ready.set(i64::from(healthy));
        self.refresh_ready();
    }

    fn refresh_ready(&self) {
        let ready = self.readiness.startup_ready.load(Ordering::Relaxed)
            && self.readiness.database_ready.load(Ordering::Relaxed)
            && self.readiness.backend_ready.load(Ordering::Relaxed)
            && self.readiness.event_watcher_ready.load(Ordering::Relaxed);
        self.ready.set(i64::from(ready));
    }

    pub fn record_db_error(&self, error: &anyhow::Error) {
        if error.to_string().contains("database is locked")
            || error.to_string().contains("database is busy")
        {
            self.db_busy_retries_total.inc();
        } else {
            self.db_errors_total.inc();
        }
    }

    pub fn record_graph_validation(&self, success: bool) {
        self.graph_validation_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
    }

    pub fn record_message_retry(&self) {
        self.message_retry_total.inc();
    }

    pub fn record_p2p_publish(&self, success: bool) {
        self.p2p_publish_total.get_or_create(&OutcomeLabels { outcome: outcome(success) }).inc();
    }

    pub fn record_p2p_receive(&self, success: bool) {
        self.p2p_receive_total.get_or_create(&OutcomeLabels { outcome: outcome(success) }).inc();
    }

    pub fn record_p2p_oversized_message(&self) {
        self.p2p_oversized_messages_total.inc();
    }

    pub fn record_btc_backend_probe(&self, success: bool) {
        self.btc_backend_requests_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
        if success {
            self.btc_backend_last_success_timestamp_seconds.set(current_time_secs());
        }
    }

    pub fn record_goat_backend_probe(&self, success: bool) {
        self.goat_backend_requests_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
        if success {
            self.goat_backend_last_success_timestamp_seconds.set(current_time_secs());
        }
    }

    pub fn set_peg_btc_decimals(&self, decimals: u8) {
        self.peg_btc_decimals.store(decimals, Ordering::Relaxed);
    }

    pub fn record_pegin_graph_setup(&self, success: bool) {
        self.pegin_graph_setup_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
    }

    pub fn record_pegin_confirm(&self, success: bool) {
        self.pegin_confirm_total.get_or_create(&OutcomeLabels { outcome: outcome(success) }).inc();
    }

    pub fn record_pegin_post(&self, success: bool) {
        self.pegin_post_total.get_or_create(&OutcomeLabels { outcome: outcome(success) }).inc();
    }

    pub fn record_pegout_disprove(&self) {
        self.pegout_disprove_total.inc();
    }

    pub fn record_withdraw_finalize(&self, success: bool) {
        self.withdraw_finalize_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
    }

    pub fn apply_goat_gas_balance(&self, balance_wei: U256) {
        self.goat_gas_balance_wei.set(u256_to_gauge(balance_wei));
    }

    pub fn apply_required_stake(&self, sufficient: bool) {
        self.required_stake_sufficient.set(i64::from(sufficient));
    }

    pub fn record_soldering_payload_io(&self, success: bool) {
        self.soldering_payload_io_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
    }

    pub fn record_btc_tx_broadcast(&self, success: bool) {
        self.btc_tx_broadcast_total
            .get_or_create(&OutcomeLabels { outcome: outcome(success) })
            .inc();
    }

    pub fn apply_event_watch_lag(&self, lag_blocks: i64) {
        self.event_watch_lag_blocks.set(lag_blocks.max(0));
    }

    pub fn apply_chain_health(&self, btc_height: Option<u32>, goat_spv_height: Option<u64>) {
        if let (Some(btc_height), Some(goat_spv_height)) = (btc_height, goat_spv_height) {
            self.spv_lag_blocks.set(
                i64::try_from(u64::from(btc_height).saturating_sub(goat_spv_height))
                    .unwrap_or(i64::MAX),
            );
        }
    }

    pub fn apply_fee_wallet(&self, balance_sats: i64, utxos: i64) {
        self.fee_wallet_balance_sats.set(balance_sats);
        self.fee_wallet_spendable_utxos.set(utxos);
    }

    /// Replaces the exported database gauges with the latest grouped state counts.
    fn apply_database_metrics(&self, counts: &[store::MetricsStateCount]) {
        self.instances.clear();
        self.graphs.clear();
        self.messages.clear();
        self.oldest_pending_message_age_seconds.set(0);
        let now = current_time_secs();

        for count in counts {
            match count.category.as_str() {
                "instance" => {
                    let status = known_status::<InstanceBridgeInStatus>(&count.state);
                    self.instances
                        .get_or_create(&InstanceLabels { flow: "bridge_in".to_string(), status })
                        .inc_by(count.count);
                }
                "swap_escrow" => {
                    let status = known_status::<SwapEscrowStatus>(&count.state);
                    self.instances
                        .get_or_create(&InstanceLabels { flow: "bridge_out".to_string(), status })
                        .inc_by(count.count);
                }
                "graph" => {
                    let status = known_status::<GraphStatus>(&count.state);
                    self.graphs.get_or_create(&StatusLabels { status }).inc_by(count.count);
                }
                "message" => {
                    let status = known_status::<MessageState>(&count.state);
                    self.messages
                        .get_or_create(&StatusLabels { status: status.clone() })
                        .inc_by(count.count);
                    if status == "Pending" {
                        self.oldest_pending_message_age_seconds.set(
                            count
                                .oldest_created_at
                                .map_or(0, |created_at| now.saturating_sub(created_at).max(0)),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_alert_snapshot(&self, snapshot: &store::NodeAlertMetricsSnapshot) {
        let now = current_time_secs();
        self.pegin_oldest_active_age_seconds
            .set(age_since(snapshot.pegin_oldest_active_status_updated_at, now));
        self.pegin_oldest_committee_wait_age_seconds
            .set(age_since(snapshot.pegin_oldest_committee_wait_status_updated_at, now));
        self.pegout_oldest_active_age_seconds
            .set(age_since(snapshot.pegout_oldest_active_status_updated_at, now));
        let decimals = self.peg_btc_decimals.load(Ordering::Relaxed);
        if decimals != UNKNOWN_TOKEN_DECIMALS
            && let Some(sats) = snapshot
                .operator_available_pegbtc
                .as_deref()
                .and_then(|value| pegbtc_base_units_to_sats(value, decimals))
        {
            self.operator_available_pegbtc_sats.set(sats);
        }
    }
}

fn outcome(success: bool) -> String {
    if success { "success" } else { "failed" }.to_string()
}

fn age_since(timestamp: Option<i64>, now: i64) -> i64 {
    timestamp.map_or(0, |timestamp| now.saturating_sub(timestamp).max(0))
}

fn pegbtc_base_units_to_sats(value: &str, token_decimals: u8) -> Option<i64> {
    let value = U256::from_str(value).ok()?;
    let sats = if token_decimals >= BTC_DECIMALS {
        value / U256::from(10).pow(U256::from(token_decimals - BTC_DECIMALS))
    } else {
        value.checked_mul(U256::from(10).pow(U256::from(BTC_DECIMALS - token_decimals)))?
    };
    Some(u256_to_gauge(sats))
}

fn u256_to_gauge(value: U256) -> i64 {
    let max = U256::from(i64::MAX as u64);
    if value > max { i64::MAX } else { value.to::<u64>() as i64 }
}

/// Returns a bounded status label, mapping unexpected database values to `unknown`.
fn known_status<T: FromStr>(state: &str) -> String {
    if state.parse::<T>().is_ok() { state.to_owned() } else { "unknown".to_string() }
}

pub async fn metrics_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |route| route.as_str().to_owned());
    let method = request.method().to_string();

    state.metrics_state.http_requests_in_flight.inc();
    let in_flight = InFlightGuard(state.metrics_state.http_requests_in_flight.clone());
    let response = next.run(request).await;
    drop(in_flight);

    let status = response.status().as_u16();
    state
        .metrics_state
        .http_requests_total
        .get_or_create(&HttpRequestLabels { method: method.clone(), route: route.clone(), status })
        .inc();
    state
        .metrics_state
        .http_request_duration_seconds
        .get_or_create(&HttpRouteLabels { method, route })
        .observe(start.elapsed().as_secs_f64());
    response
}

/// Refreshes database-backed gauges and returns the encoded metrics response.
pub async fn metrics_handler(State(app_state): State<Arc<AppState>>) -> Response {
    let database_metrics = async {
        let mut storage = app_state.local_db.acquire().await?;
        let counts = storage.node_metrics_state_counts().await?;
        let snapshot = storage.node_alert_metrics_snapshot(&app_state.peer_id).await?;
        Ok::<_, anyhow::Error>((counts, snapshot))
    }
    .await;
    let (counts, snapshot) = match database_metrics {
        Ok(metrics) => {
            app_state.metrics_state.mark_database_ready(true);
            metrics
        }
        Err(error) => {
            app_state.metrics_state.mark_database_ready(false);
            app_state.metrics_state.record_db_error(&error);
            tracing::error!(error = %error, "failed to collect node database metrics");
            return (StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable\n").into_response();
        }
    };

    let mut buffer = String::new();
    let registry = app_state.metrics_state.registry.lock().unwrap();
    app_state.metrics_state.apply_database_metrics(&counts);
    app_state.metrics_state.apply_alert_snapshot(&snapshot);
    if let Err(error) = encode(&mut buffer, &registry) {
        tracing::error!(error = %error, "failed to encode node metrics");
        return (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed\n").into_response();
    }

    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE.parse().unwrap());
    (StatusCode::OK, headers, buffer).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    fn encoded(state: &MetricsState) -> String {
        let mut output = String::new();
        encode(&mut output, &state.registry.lock().unwrap()).unwrap();
        output
    }

    #[test]
    fn exports_correct_counter_name_and_bounded_database_labels() {
        let state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        state
            .http_requests_total
            .get_or_create(&HttpRequestLabels {
                method: "GET".to_string(),
                route: "unmatched".to_string(),
                status: 404,
            })
            .inc();
        state.apply_database_metrics(&[
            store::MetricsStateCount {
                category: "graph".to_string(),
                state: "unexpected-id-like-value".to_string(),
                count: 1,
                oldest_created_at: None,
                last_success_at: None,
            },
            store::MetricsStateCount {
                category: "graph".to_string(),
                state: "another-unexpected-value".to_string(),
                count: 2,
                oldest_created_at: None,
                last_success_at: None,
            },
        ]);

        let output = encoded(&state);
        assert!(output.contains("http_requests_total"));
        assert!(!output.contains("http_requests_total_total"));
        assert!(output.contains("route=\"unmatched\""));
        assert!(output.contains("bitvm_node_graphs{status=\"unknown\"} 3"));
        assert!(!output.contains("bitvm_node_graphs{status=\"OperatorPresigned\"}"));
        assert!(!output.contains("unexpected-id-like-value"));
        assert!(!output.contains("another-unexpected-value"));
    }

    #[test]
    fn records_task_and_message_metrics() {
        let state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        state.record_task_run("maintenance", "success", Duration::from_millis(25));
        state.record_task_run("history_sync", "failed", Duration::from_millis(5));
        state.record_message_dispatch("Tick", "success");

        let output = encoded(&state);
        assert!(
            output
                .contains("bitvm_node_task_runs_total{task=\"maintenance\",outcome=\"success\"} 1")
        );
        assert!(output.contains(
            "bitvm_node_message_dispatch_total{message_type=\"Tick\",outcome=\"success\"} 1"
        ));
        assert!(
            !output
                .contains("bitvm_node_task_last_success_timestamp_seconds{task=\"history_sync\"}")
        );
    }

    #[test]
    fn readiness_requires_healthy_event_watchers() {
        let state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        state.mark_startup_ready();
        state.mark_database_ready(true);
        state.mark_backend_ready(true);

        let output = encoded(&state);
        assert!(output.contains("bitvm_node_ready 0"));
        assert!(output.contains("bitvm_node_event_watch_ready 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"healthy\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"syncing\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"failed\"} 0"));

        state.set_event_watch_state(EventWatchState::Syncing);
        let output = encoded(&state);
        assert!(output.contains("bitvm_node_ready 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"healthy\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"syncing\"} 1"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"failed\"} 0"));

        state.set_event_watch_state(EventWatchState::Healthy);
        let output = encoded(&state);
        assert!(output.contains("bitvm_node_ready 1"));
        assert!(output.contains("bitvm_node_event_watch_ready 1"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"healthy\"} 1"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"syncing\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"failed\"} 0"));

        state.set_event_watch_state(EventWatchState::Failed);
        let output = encoded(&state);
        assert!(output.contains("bitvm_node_ready 0"));
        assert!(output.contains("bitvm_node_event_watch_ready 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"healthy\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"syncing\"} 0"));
        assert!(output.contains("bitvm_node_event_watch_state{state=\"failed\"} 1"));
    }
}
