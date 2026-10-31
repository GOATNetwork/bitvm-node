use crate::clock::current_time_secs;
use crate::rpc_service::AppState;
use crate::rpc_service::node::{
    ALIVE_TIME_JUDGE_THRESHOLD, NODE_STATUS_OFFLINE, NodeDesc, NodeListResponse,
    NodeOverViewResponse, NodeQueryParams, ToNodeDesc,
};
use crate::rpc_service::response::{ApiErrorExt, ApiResult, ok_response};
use crate::rpc_service::validation::InputValidator;
use crate::utils::reflect_goat_address;
use axum::extract::{Path, Query, State};
use bitvm_lib::actors::Actor;
use std::sync::Arc;
use store::localdb::NodeQuery;

/// Get node list
///
/// Returns a paginated list of BitVM network nodes based on query parameters. Supports filtering by
/// GOAT address, actor type, and online status. Automatically updates the current node's timestamp.
///
/// # Query Parameters
///
/// - `goat_addr`: GOAT address filter (optional) - filters nodes by their GOAT address
/// - `actor`: Actor type filter (optional) - filters by actor role (Operator, Watchtower, Verifier, All)
/// - `status`: Status filter (optional) - filters by online/offline status
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns node list with status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated node data with online status
///
/// # Use Case
///
/// Frontend applications use this to display the list of active nodes in the BitVM network,
/// showing their roles, availability, and connection information.
///
/// # Example
///
/// ```http
/// GET /v1/nodes?actor=Operator&status=online&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "nodes": [
///     {
///       "peer_id": "QmPeerId123abc...",
///       "actor": "Operator",
///       "name": "zkm",
///       "service_fee_rate": 0.001,
///       "available_peg_btc": 0,
///       "goat_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "btc_pub_key": "02abc123def456...",
///       "socket_addr": "127.0.0.1:8080",
///       "reward": 1000000,
///       "updated_at": 1699123456,
///       "status": "online"
///     }
///   ],
///   "total": 1
/// }
/// ```
#[axum::debug_handler]
pub async fn get_nodes(
    Query(query_params): Query<NodeQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<NodeListResponse> {
    // Validate pagination parameters
    let (offset, limit) =
        InputValidator::validate_pagination(query_params.offset, query_params.limit)?;

    // Validate goat_addr format (if provided)
    if let Some(ref goat_addr) = query_params.goat_addr {
        InputValidator::validate_goat_address(goat_addr, "goat_addr")?;
    }

    // Validate actor field (if provided)
    if let Some(ref actor) = query_params.actor {
        InputValidator::validate_actor(actor, "actor")?;
    }

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_NODES_ERROR")?;

    storage_process
        .update_node_timestamp(&app_state.peer_id, current_time_secs())
        .await
        .api_error("GET_NODES_ERROR")?;
    let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
    let (_, goat_addr) = reflect_goat_address(query_params.goat_addr);
    let (nodes, total) = storage_process
        .find_nodes(&NodeQuery {
            actor: query_params.actor.filter(|actor| actor != Actor::All.to_string().as_str()),
            goat_addr,
            time_threshold: query_params.status.clone().map(|_| time_threshold),
            is_in_time_threshold: query_params
                .status
                .map(|status| status != NODE_STATUS_OFFLINE)
                .unwrap_or(true),
            order: None,
            offset: Some(offset),
            limit: Some(limit),
        })
        .await
        .api_error("GET_NODES_ERROR")?;

    let node_desc_list: Vec<NodeDesc> =
        nodes.into_iter().map(|v| v.to_node_desc(time_threshold, &app_state.peer_id)).collect();

    ok_response(NodeListResponse { nodes: node_desc_list, total })
}

/// Get nodes overview statistics
///
/// Returns statistical overview of all nodes in the BitVM network, including counts by actor type
/// and online/offline status. Automatically updates the current node's timestamp.
///
/// # Returns
///
/// - `200 OK`: Successfully returns nodes overview statistics
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes aggregated statistics for all node types and their status
///
/// # Use Case
///
/// Frontend applications use this to display dashboard statistics showing network health,
/// including total node counts by role and availability status.
///
/// # Example
///
/// ```http
/// GET /v1/nodes/overview
/// ```
///
/// Response example:
/// ```json
/// {
///   "nodes_overview": {
///     "total": 18,
///     "online_operators": 8,
///     "offline_operators": 2,
///     "online_verifiers": 3,
///     "offline_verifiers": 1,
///     "online_committees": 2,
///     "offline_committees": 0,
///     "online_watchtowers": 2,
///     "offline_watchtowers": 0
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_nodes_overview(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<NodeOverViewResponse> {
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("NODES_OVERVIEW_ERROR")?;

    storage_process
        .update_node_timestamp(&app_state.peer_id, current_time_secs())
        .await
        .api_error("NODES_OVERVIEW_ERROR")?;

    let time_threshold = current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD;
    let nodes_overview =
        storage_process.node_overview(time_threshold).await.api_error("NODES_OVERVIEW_ERROR")?;

    ok_response(NodeOverViewResponse { nodes_overview })
}

/// Get node by peer ID
///
/// Returns detailed information for a specific node based on its peer_id. If the requested
/// node is the current node, automatically updates its timestamp.
///
/// # Path Parameters
///
/// - `peer_id`: The unique peer identifier of the node (IPFS-style peer ID)
///
/// # Returns
///
/// - `200 OK`: Successfully returns node details (or None if not found)
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns complete node information including actor type, addresses, and reward data
///
/// # Use Case
///
/// Applications use this to retrieve detailed information about a specific node in the network,
/// including its configuration, role, reward balance, and last active timestamp.
///
/// # Example
///
/// ```http
/// GET /v1/nodes/QmPeerId...
/// ```
///
/// Response example:
/// ```json
/// {
///   "peer_id": "QmPeerId...",
///   "actor": "Operator",
///   "node_name": "zkm",
///   "goat_addr": "0x123...",
///   "btc_pub_key": "02abc...",
///   "socket_addr": "127.0.0.1:8080",
///   "reward": 1000000,
///   "service_fee_rate": 0.001,
///   "available_peg_btc": 0,
///   "updated_at": 1640995200,
///   "created_at": 1640995200
/// }
/// ```
#[axum::debug_handler]
pub async fn get_node(
    Path(peer_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<Option<NodeDesc>> {
    // Validate peer_id format
    InputValidator::validate_peer_id(&peer_id, "peer_id")?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_NODE_ERROR")?;

    if peer_id == app_state.peer_id {
        storage_process
            .update_node_timestamp(&app_state.peer_id, current_time_secs())
            .await
            .api_error("GET_NODE_ERROR")?;
    }

    let res =
        storage_process.node_by_id(peer_id.as_str()).await.api_error("GET_NODE_ERROR")?.map(|v| {
            v.to_node_desc(current_time_secs() - ALIVE_TIME_JUDGE_THRESHOLD, &app_state.peer_id)
        });

    ok_response(res)
}
