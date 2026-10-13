use crate::rpc_service::response::{ApiErrorExt, ApiResult, ErrorResponse, ok_response};
use crate::rpc_service::validation::InputValidator;
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::extract::{Path, Query, State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use store::{Graph, GraphStatus, MessageDebugOverview};

#[derive(Serialize)]
pub struct DebugStatusResponse {
    pub checked_at: i64,
    pub actor: String,
    pub peer_id: String,
    pub bitcoin_height: Option<u32>,
    pub goat_height: Option<i64>,
    pub goat_spv_height: Option<u64>,
    pub message_queue: DebugMessageQueue,
}

#[derive(Serialize)]
pub struct DebugMessageQueue {
    pub pending_ready: i64,
    pub pending_locked: i64,
    pub failed: i64,
    pub oldest_pending_at: Option<i64>,
}

#[derive(Serialize)]
pub struct GraphDebugMessagesResponse {
    pub graph_id: String,
    pub status: Option<String>,
    pub flow: String,
    pub messages: Vec<GraphDebugMessageOverview>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphMessageFlow {
    Pegin,
    Pegout,
}

#[derive(Default, Deserialize)]
pub struct GraphDebugMessagesQuery {
    /// Optional message-flow filter: `pegin` or `pegout`.
    pub flow: Option<GraphMessageFlow>,
}

impl GraphMessageFlow {
    fn matches_message_type(&self, message_type: &str) -> bool {
        match self {
            Self::Pegin => matches!(
                message_type,
                "CreateGraph"
                    | "InitGraph"
                    | "GenCircuits"
                    | "CutCircuits"
                    | "SolderingProofReady"
                    | "VerifierGraphParamsEndorsement"
                    | "NonceGeneration"
                    | "CommitteePresign"
                    | "EndorseGraph"
                    | "GraphFinalize"
            ),
            Self::Pegout => matches!(
                message_type,
                "KickoffReady"
                    | "KickoffSent"
                    | "PreKickoffSent"
                    | "ChallengeSent"
                    | "WatchtowerChallengeInitSent"
                    | "WatchtowerChallengeSent"
                    | "WatchtowerChallengeTimeout"
                    | "NackReady"
                    | "OperatorCommitPubinReady"
                    | "OperatorCommitPubinTimeout"
                    | "AssertReady"
                    | "AssertSent"
                    | "ChallengeAssertSent"
                    | "WronglyChallengeTimeout"
                    | "DisproveSent"
                    | "Take1Ready"
                    | "Take1Sent"
                    | "Take2Ready"
                    | "Take2Sent"
            ),
        }
    }
}

#[derive(Serialize)]
pub struct InstanceDebugMessagesResponse {
    pub instance_id: String,
    pub messages: Vec<GraphDebugMessageOverview>,
}

#[derive(Serialize)]
pub struct GraphDebugMessageOverview {
    pub message_id: String,
    pub actor: String,
    pub message_type: String,
    pub state: String,
    pub lock_time_until: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub reason_count: i64,
    pub last_reason: Option<GraphDebugReasonSummary>,
}

#[derive(Serialize)]
pub struct DebugMessageDetailsResponse {
    pub message: GraphDebugMessageOverview,
    pub reasons: Vec<GraphDebugReason>,
}

#[derive(Serialize)]
pub struct GraphDebugReasonSummary {
    pub code: String,
    pub detail: String,
    pub last_seen_at: i64,
}

#[derive(Serialize)]
pub struct GraphDebugReason {
    pub code: String,
    pub detail: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub occurrences: i64,
}

fn graph_debug_message_overview(message: MessageDebugOverview) -> GraphDebugMessageOverview {
    GraphDebugMessageOverview {
        message_id: message.message_id,
        actor: message.actor,
        message_type: message.msg_type,
        state: message.state,
        lock_time_until: message.lock_time_until,
        created_at: message.created_at,
        updated_at: message.updated_at,
        reason_count: message.reason_count,
        last_reason: match (
            message.last_reason_code,
            message.last_reason_detail,
            message.last_reason_seen_at,
        ) {
            (Some(code), Some(detail), Some(last_seen_at)) => {
                Some(GraphDebugReasonSummary { code, detail, last_seen_at })
            }
            _ => None,
        },
    }
}

fn graph_debug_flow(graph: Option<&Graph>) -> &'static str {
    let Some(graph) = graph else {
        return "unknown";
    };
    if graph.init_withdraw_tx_hash.is_some()
        || graph.bridge_out_start_at > 0
        || matches!(
            graph.status.parse::<GraphStatus>(),
            Ok(GraphStatus::PreKickoff
                | GraphStatus::OperatorKickOff
                | GraphStatus::Challenge
                | GraphStatus::Disprove
                | GraphStatus::OperatorTake1
                | GraphStatus::OperatorTake2)
        )
    {
        "pegout"
    } else {
        "pegin"
    }
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
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_DEBUG_STATUS_ERROR")?;
    let queue = storage_processor
        .get_message_queue_stats(&app_state.actor.to_string(), checked_at)
        .await
        .api_error("GET_DEBUG_STATUS_ERROR")?;

    ok_response(DebugStatusResponse {
        checked_at,
        actor: app_state.actor.to_string(),
        peer_id: app_state.peer_id.clone(),
        bitcoin_height: bitcoin_height.ok(),
        goat_height: goat_height.ok(),
        goat_spv_height: goat_spv_height.ok(),
        message_queue: DebugMessageQueue {
            pending_ready: queue.pending_ready,
            pending_locked: queue.pending_locked,
            failed: queue.failed,
            oldest_pending_at: queue.oldest_pending_at,
        },
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
                error: "ENGINE_DISABLED".to_string(),
                message: "execution engine is not enabled on this node".to_string(),
            }),
        ));
    };
    let snapshot = engine.snapshot().await.api_error("GET_DEBUG_ENGINE_ERROR")?;
    ok_response(snapshot)
}

// TODO(auth): Require operator authentication before exposing local debug state.
#[axum::debug_handler]
pub async fn get_graph_debug_messages(
    Path(graph_id): Path<String>,
    Query(query): Query<GraphDebugMessagesQuery>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphDebugMessagesResponse> {
    let graph_id = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_GRAPH_DEBUG_MESSAGES_ERROR")?;
    let graph = storage_processor
        .find_graph(&graph_id)
        .await
        .api_error("GET_GRAPH_DEBUG_MESSAGES_ERROR")?;
    let flow = graph_debug_flow(graph.as_ref()).to_string();
    let status = graph.map(|graph| graph.status);
    let messages = storage_processor
        .find_message_debug_overviews(&graph_id)
        .await
        .api_error("GET_GRAPH_DEBUG_MESSAGES_ERROR")?
        .into_iter()
        .filter(|message| {
            query.flow.as_ref().is_none_or(|flow| flow.matches_message_type(&message.msg_type))
        })
        .map(graph_debug_message_overview)
        .collect();

    ok_response(GraphDebugMessagesResponse {
        graph_id: graph_id.to_string(),
        status,
        flow,
        messages,
    })
}

// TODO(auth): Require operator authentication before exposing local debug state.
#[axum::debug_handler]
pub async fn get_instance_debug_messages(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceDebugMessagesResponse> {
    let instance_id = InputValidator::validate_uuid(&instance_id, "instance_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_INSTANCE_DEBUG_MESSAGES_ERROR")?;
    let messages = storage_processor
        .find_message_debug_overviews(&instance_id)
        .await
        .api_error("GET_INSTANCE_DEBUG_MESSAGES_ERROR")?
        .into_iter()
        .map(graph_debug_message_overview)
        .collect();

    ok_response(InstanceDebugMessagesResponse { instance_id: instance_id.to_string(), messages })
}

// TODO(auth): Require operator authentication before exposing local debug state.
#[axum::debug_handler]
pub async fn get_debug_message_details(
    Path(message_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<DebugMessageDetailsResponse> {
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_DEBUG_MESSAGE_DETAILS_ERROR")?;
    let message = storage_processor
        .find_message_debug_overview(&message_id)
        .await
        .api_error("GET_DEBUG_MESSAGE_DETAILS_ERROR")?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "DEBUG_MESSAGE_NOT_FOUND".to_string(),
                    message: format!("message {message_id} not found"),
                }),
            )
        })?;
    let reasons = storage_processor
        .find_message_debug_reasons(&message_id)
        .await
        .api_error("GET_DEBUG_MESSAGE_DETAILS_ERROR")?
        .into_iter()
        .map(|reason| GraphDebugReason {
            code: reason.reason_code,
            detail: reason.reason_detail,
            first_seen_at: reason.first_seen_at,
            last_seen_at: reason.last_seen_at,
            occurrences: reason.occurrences,
        })
        .collect();

    ok_response(DebugMessageDetailsResponse {
        message: graph_debug_message_overview(message),
        reasons,
    })
}
