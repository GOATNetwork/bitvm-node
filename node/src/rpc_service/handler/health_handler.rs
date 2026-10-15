use crate::clock::current_time_secs;
use crate::metrics_service::{BackendHealthSnapshot, EventWatchSnapshot, ReadinessSnapshot};
use crate::rpc_service::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

const DB_PING_TIMEOUT: Duration = Duration::from_secs(2);

/// `GET /v1/health`: the node's own view of its health, `200` when ready and
/// `503` otherwise. Everything is read from memory except a local database
/// ping, so the database bit does not depend on a metrics scrape.
#[derive(Serialize)]
pub struct HealthResponse {
    pub ready: bool,
    pub components: ReadinessSnapshot,
    pub backends: Vec<BackendHealthSnapshot>,
    pub event_watch: EventWatchSnapshot,
    pub spv_lag_blocks: i64,
    pub uptime_secs: u64,
    pub version: &'static str,
    pub role: String,
    pub peer_id: String,
    pub checked_at: i64,
}

#[axum::debug_handler]
pub async fn get_health(State(app_state): State<Arc<AppState>>) -> impl IntoResponse {
    let metrics = &app_state.metrics_state;
    let database_ok = tokio::time::timeout(DB_PING_TIMEOUT, app_state.local_db.conn.acquire())
        .await
        .map(|conn| conn.is_ok())
        .unwrap_or(false);
    metrics.mark_database_ready(database_ok);
    let components = metrics.readiness_snapshot();
    let body = HealthResponse {
        ready: components.ready,
        components: components.clone(),
        backends: metrics.backend_health_snapshot(),
        event_watch: metrics.event_watch_snapshot(),
        spv_lag_blocks: metrics.spv_lag_blocks(),
        uptime_secs: metrics.uptime_secs(),
        version: env!("CARGO_PKG_VERSION"),
        role: app_state.actor.to_string(),
        peer_id: app_state.peer_id.clone(),
        checked_at: current_time_secs(),
    };
    let status = if components.ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(body))
}
