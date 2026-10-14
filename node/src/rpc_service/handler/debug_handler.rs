use crate::clock::current_time_secs;
use crate::rpc_service::AppState;
use crate::rpc_service::response::{ApiErrorExt, ApiResult, ErrorResponse, ok_response};
use axum::Json;
use axum::extract::State;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct DebugStatusResponse {
    pub checked_at: i64,
    pub actor: String,
    pub peer_id: String,
    pub bitcoin_height: Option<u32>,
    pub goat_height: Option<i64>,
    pub goat_spv_height: Option<u64>,
    /// Execution engine rows by table and state; `None` without an engine.
    pub engine: Option<Vec<store::EngineStateCount>>,
}

// TODO(auth): Require operator authentication before exposing local debug state.
#[axum::debug_handler]
pub async fn get_debug_status(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<DebugStatusResponse> {
    let checked_at = current_time_secs();
    let (bitcoin_height, goat_height, goat_spv_height) = tokio::join!(
        app_state.btc_client.get_height(),
        app_state.goat_client.get_latest_block_number(),
        app_state.goat_client.btc_spv_latest_height(),
    );
    let engine = match app_state.engine.as_ref() {
        Some(engine) => Some(engine.state_counts().await.api_error("GET_DEBUG_STATUS_ERROR")?),
        None => None,
    };

    ok_response(DebugStatusResponse {
        checked_at,
        actor: app_state.actor.to_string(),
        peer_id: app_state.peer_id.clone(),
        bitcoin_height: bitcoin_height.ok(),
        goat_height: goat_height.ok(),
        goat_spv_height: goat_spv_height.ok(),
        engine,
    })
}

// TODO(auth): Require operator authentication before exposing local debug state.
/// Execution engine snapshot: row counts by state, aggregates parked on a
/// `waiting_for`, and poisoned aggregates.
#[axum::debug_handler]
pub async fn get_debug_engine(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<engine::EngineSnapshot> {
    let Some(engine) = app_state.engine.as_ref() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ENGINE_UNAVAILABLE".to_string(),
                message: "the execution engine handle is not available on this node".to_string(),
            }),
        ));
    };
    let snapshot = engine.snapshot().await.api_error("GET_DEBUG_ENGINE_ERROR")?;
    ok_response(snapshot)
}

#[derive(Deserialize)]
pub struct ClearPoisonRequest {
    pub aggregate_kind: String,
    pub aggregate_id: String,
    /// One poisoned action; every action of the aggregate when omitted.
    pub action: Option<String>,
}

#[derive(Serialize)]
pub struct ClearPoisonResponse {
    pub cleared: u64,
}

/// Manual release of poisoned actions: the held-back jobs and events run again
/// at once and the backoff count starts over.
#[axum::debug_handler]
pub async fn clear_engine_poison(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<ClearPoisonRequest>,
) -> ApiResult<ClearPoisonResponse> {
    let Some(engine) = app_state.engine.as_ref() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ENGINE_UNAVAILABLE".to_string(),
                message: "the execution engine handle is not available on this node".to_string(),
            }),
        ));
    };
    let aggregate = engine::AggregateRef::new(&request.aggregate_kind, &request.aggregate_id);
    let cleared = engine
        .clear_poison(&aggregate, request.action.as_deref())
        .await
        .api_error("CLEAR_ENGINE_POISON_ERROR")?;
    ok_response(ClearPoisonResponse { cleared })
}
