use crate::env::{
    GraphBtcTxName, get_goat_gateway_contract_from_env, get_node_goat_address, get_node_pubkey,
};
#[cfg(feature = "rpc-debug-endpoints")]
use crate::handle::broadcast_verifier_challenge_assert_tx;
use crate::rpc_service::AppState;
use crate::rpc_service::bitvm::*;
use crate::rpc_service::node::ALIVE_TIME_JUDGE_THRESHOLD;
use crate::rpc_service::response::{
    ApiErrorExt, ApiResult, ErrorResponse, error_response, ok_response,
};
use crate::rpc_service::validation::InputValidator;
use crate::utils::{
    gen_instance_parameters_local, get_bridge_out_global_stats, load_validated_graph_definition,
    obsolete_graph, send_challenge_tx,
};
use alloy::primitives::U256;
use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::consensus::encode::serialize_hex;
use bitvm_lib::types::BitvmGcGraph;
use client::goat_chain::{PeginStatus, WithdrawStatus};
use goat::transactions::pre_signed::PreSignedTransaction;
use http::StatusCode;
use std::collections::HashSet;
use std::default::Default;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::{GraphQuery, InstanceQuery, StorageProcessor};
use store::{Graph, GraphStatus, InstanceBridgeInStatus};
use tracing::{info, warn};

fn graph_tx_index_error(
    tx_name: GraphBtcTxName,
    index: usize,
    len: usize,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "INVALID_GRAPH_TX_INDEX".to_string(),
            message: format!("Invalid index {index} for {tx_name}. Available count: {len}"),
        }),
    )
}

/// Get instance settings
///
/// Returns bridge-in amount configuration information for frontend display of available bridge amount options.
/// This endpoint provides the list of supported bridge-in amounts that users can choose from.
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance settings
/// - Response body contains available bridge-in amount list in BTC
///
/// # Use Case
///
/// Frontend applications use this to display available bridge amount options to users.
///
/// # Example
///
/// ```http
/// GET /v1/instances/settings
/// ```
///
/// Response example:
/// ```json
/// {
///   "bridge_in_amount": [0.1, 0.05, 0.02, 0.01]
/// }
/// ```
#[axum::debug_handler]
pub async fn instance_settings(
    State(_app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceSettingResponse> {
    ok_response(InstanceSettingResponse { bridge_in_amount: BRIDGE_IN_AMOUNTS.to_vec() })
}

/// Get instance list
///
/// Returns a paginated list of bridge-in instances based on query parameters. Supports filtering by
/// source address.
///
/// # Query Parameters
///
/// - `from_addr`: Source address filter (optional) - filters instances by source Bitcoin address
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance list with status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated instance data with UTXO details
///
/// # Use Case
///
/// Frontend applications use this to display user's bridge transaction history and current status.
///
/// # Example
///
/// ```http
/// GET /v1/instances?offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_wraps": [
///     {
///       "instance": {
///         "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///         "network": "testnet",
///         "from_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///         "to_addr": "0x1234567890abcdef1234567890abcdef12345678",
///         "amount": 100000000,
///         "fees": [10, 20, 30],
///         "input_utxos": "[{\"txid\":\"abc123...\",\"vout\":0,\"value\":100000000}]",
///         "status": "CommitteesAnswered",
///         "goat_tx_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///         "goat_tx_height": 8509060,
///         "user_xonly_pubkey": [2, 171, 193, 35, ...],
///         "user_change_addr": "tb1q...",
///         "user_refund_addr": "tb1q...",
///         "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///         "btc_height": 2500000,
///         "pegin_confirm_txid": "a1b2c3d4...",
///         "pegin_cancel_txid": null,
///         "committees_answers": {},
///         "pegin_data_tx_hash": "0x...",
///         "parameters": null,
///         "status_updated_at": 1699123456,
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "utxo": [
///         {
///           "txid": [171, 193, 35, ...],
///           "vout": 0,
///           "amount_sats": 100000000
///         }
///       ],
///       "confirmations": 0,
///       "target_confirmations": 6,
///       "waiting_time_in_secs": 60,
///       "post_pegin_txhash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "current_status_waiting_time_in_secs": 30,
///       "status_extra": {
///         "user_action": "None",
///         "is_failed": false,
///         "error": null
///       }
///     }
///   ],
///   "total": 1
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instances(
    Query(params): Query<InstanceListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceListResponse> {
    // Validate pagination parameters
    let (offset, limit) = InputValidator::validate_pagination(params.offset, params.limit)?;
    // Database query
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_INSTANCE_ERROR")?;

    let mut query = InstanceQuery::default();
    if let Some(from_addr) = params.from_addr {
        InputValidator::validate_btc_address(&from_addr, None, "bridge in from_addr")?;
        query = query.with_from_addr(from_addr);
    }
    query = query.with_pagination(offset, limit).with_order("created_at DESC".to_string());

    let (instances, total) =
        storage_process.find_instances(query).await.api_error("GET_INSTANCE_ERROR")?;

    if instances.is_empty() {
        warn!("get_instances instance is empty: total {}", total);
        return ok_response(InstanceListResponse::default());
    }
    let response_window_blocks = app_state
        .goat_client
        .gateway_get_response_window_blocks()
        .await
        .api_error("GET_INSTANCE_ERROR")?;
    let mut items = vec![];
    for instance in instances {
        let item = InstanceExtended::convert_from_instance(
            &app_state.btc_client,
            response_window_blocks as i64,
            instance,
        )
        .await
        .api_error("GET_INSTANCE_ERROR")?;
        items.push(item);
    }

    ok_response(InstanceListResponse { instance_wraps: items, total })
}

/// Get instance by ID
///
/// Returns detailed information for a specific bridge instance including UTXO details
/// and current processing state.
///
/// # Path Parameters
///
/// - `instance_id`: UUID of the bridge instance to retrieve
///
/// # Returns
///
/// - `200 OK`: Successfully returns instance details with UTXO and status information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns empty instance wrap if instance_id not found in database
///
/// # Use Case
///
/// Frontend applications use this to display detailed information about a specific bridge transaction,
/// including its current status and associated UTXOs.
///
/// # Example
///
/// ```http
/// GET /v1/instances/123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// Response example:
/// ```json
/// {
///   "instance_wrap": {
///     "instance": {
///       "instance_id": "123e4567-e89b-12d3-a456-426614174000",
///       "network": "testnet",
///       "from_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///       "to_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "amount": 100000000,
///       "fees": [10, 20, 30],
///       "input_utxos": "[{\"txid\":\"abc123...\",\"vout\":0,\"value\":100000000}]",
///       "status": "CommitteesAnswered",
///       "goat_tx_hash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "goat_tx_height": 8509060,
///       "user_xonly_pubkey": [2, 171, 193, 35, ...],
///       "user_change_addr": "tb1q...",
///       "user_refund_addr": "tb1q...",
///       "btc_txid": "f6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "btc_height": 2500000,
///       "pegin_confirm_txid": "a1b2c3d4...",
///       "pegin_cancel_txid": null,
///       "committees_answers": {},
///       "pegin_data_tx_hash": "0x...",
///       "parameters": null,
///       "post_pegin_txhash": "0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e",
///       "status_updated_at": 1699123456,
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "utxo": [
///       {
///         "txid": [171, 193, 35, ...],
///         "vout": 0,
///         "amount_sats": 100000000
///       }
///     ],
///     "confirmations": 0,
///     "target_confirmations": 6,
///     "waiting_time_in_secs": 60,
///     "current_status_waiting_time_in_secs": 30,
///     "status_extra": {
///       "user_action": "None",
///       "is_failed": false,
///       "error": null
///     }
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instance(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceGetResponse> {
    // Validate instance_id format
    let instance_id_uuid = InputValidator::validate_uuid(&instance_id, "instance_id")?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_INSTANCE_ERROR")?;

    if let Some(instance) =
        storage_process.find_instance(&instance_id_uuid).await.api_error("GET_INSTANCE_ERROR")?
    {
        let response_window_blocks = app_state
            .goat_client
            .gateway_get_response_window_blocks()
            .await
            .api_error("GET_INSTANCE_ERROR")?;

        let instance_wrap = Some(
            InstanceExtended::convert_from_instance(
                &app_state.btc_client,
                response_window_blocks as i64,
                instance,
            )
            .await
            .api_error("GET_INSTANCE_ERROR")?,
        );

        ok_response(InstanceGetResponse { instance_wrap })
    } else {
        tracing::info!("instance_id {} has no record in database", instance_id);
        ok_response(InstanceGetResponse { instance_wrap: None })
    }
}

/// Get instances overview statistics
///
/// Returns statistical overview of all bridge instances including total bridge-in/bridge-out amounts,
/// transaction counts, and node status information.
///
/// # Returns
///
/// - `200 OK`: Successfully returns overview statistics
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes aggregated statistics for bridge operations and node status
///
/// # Use Case
///
/// Frontend applications use this to display dashboard statistics showing overall system activity,
/// including total bridged amounts, transaction counts, and network health.
///
/// # Example
///
/// ```http
/// GET /v1/instances/overview
/// ```
///
/// Response example:
/// ```json
/// {
///   "instances_overview": {
///     "total_bridge_in_amount": 3000000,
///     "total_bridge_in_txn": 1,
///     "total_bridge_out_amount": 2000000,
///     "total_bridge_out_txn": 2,
///     "total_peg_out_amount": 1000000,
///     "total_peg_out_txn": 1,
///     "online_nodes": 3,
///     "total_nodes": 4
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_instances_overview(
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<InstanceOverviewResponse> {
    let mut storage_process =
        app_state.local_db.acquire().await.api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (bridge_in_sum, bridge_in_count) = storage_process
        .get_sum_bridge_in_txn(&[InstanceBridgeInStatus::RelayerL2Minted.to_string()])
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let bridge_out_global_stats = get_bridge_out_global_stats(&mut storage_process)
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (pegout_sum, pegout_count) = storage_process
        .get_sum_peg_out(&[
            GraphStatus::OperatorTake1.to_string(),
            GraphStatus::OperatorTake2.to_string(),
            GraphStatus::Disprove.to_string(),
        ])
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    let (total, alive) = storage_process
        .get_nodes_info(ALIVE_TIME_JUDGE_THRESHOLD)
        .await
        .api_error("INSTANCE_OVERVIEW_ERROR")?;

    ok_response(InstanceOverviewResponse {
        instances_overview: InstanceOverview {
            total_bridge_in_amount: bridge_in_sum,
            total_bridge_in_txn: bridge_in_count,
            total_bridge_out_amount: U256::from_str(&bridge_out_global_stats.claim_amount).unwrap(),
            total_bridge_out_txn: bridge_out_global_stats.claim_txn,
            total_peg_out_amount: pegout_sum,
            total_peg_out_txn: pegout_count,
            online_nodes: alive,
            total_nodes: total,
        },
    })
}

/// Get graph by ID
///
/// Returns detailed information for a specific BitVM graph including transaction status
/// and waiting time information.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM graph to retrieve
///
/// # Returns
///
/// - `200 OK`: Successfully returns graph details with extended information
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Returns None graph if graph_id not found in database
///
/// # Use Case
///
/// Applications use this to retrieve detailed information about a specific BitVM graph,
/// including its current status and estimated waiting time.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000
/// ```
///
/// Response example:
/// ```json
/// {
///     "graph": {
///       "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///       "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///       "kickoff_index": 10,
///       "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///       "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///       "amount": 2000000,
///       "challenge_amount": 1000000,
///       "status": "OperatorPresigned",
///       "sub_status": "",
///       "operator_pubkey": "03abc123...",
///       "next_prekickoff": null,
///       "cur_prekickoff_txid": "a1b2c3d4...",
///       "force_skip_kickoff_txid": null,
///       "quick_challenge_txid": null,
///       "challenge_incomplete_kickoff_txid": null,
///       "pegin_txid": null,
///       "kickoff_txid": null,
///       "take1_txid": null,
///       "challenge_txid": null,
///       "take2_txid": null,
///       "watchtower_challenge_init_txid": null,
///       "operator_assert_txid": null,
///       "verifier_assert_txids": [],
///       "disprove_txids": [],
///       "watchtower_challenge_timeout_txids": [],
///       "operator_challenge_nack_txids": [],
///       "operator_commit_timeout_txid": null,
///       "init_withdraw_tx_hash": null,
///       "bridge_out_start_at": 1699123456,
///       "status_updated_at": 1699123456,
///       "created_at": 1699123456,
///       "updated_at": 1699123456
///     },
///     "challenge_sub_status": "Assert",
///     "waiting_time_in_secs": 1000,
///     "proof_status": "Pending"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPH_ERROR")?;

    if let Some(graph) =
        storage_process.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_ERROR")?
    {
        let graph_extended = GraphExtended::convert_from_graph(&app_state.btc_client, graph)
            .await
            .api_error("GET_GRAPH_ERROR")?;

        ok_response(graph_extended)
    } else {
        tracing::warn!("graph:{} is not record in db", graph_id);
        ok_response(GraphExtended::default())
    }
}

/// Get graph list
///
/// Get graph list based on query parameters, supports various filtering conditions and pagination.
/// Each graph includes status and waiting time information.
///
/// # Query Parameters
///
/// - `from_addr`: Source address filter (optional) - filters graphs by source address
/// - `status`: Status filter (optional) - filters graphs by current status
/// - `offset`: Pagination offset (default: 0) - number of items to skip
/// - `limit`: Items per page (default: 10) - maximum number of items to return
///
/// # Returns
///
/// - `200 OK`: Successfully returns graph list with status and waiting time
/// - `500 Internal Server Error`: Server internal error or database operation failed
/// - Response includes total count and paginated graph data
///
/// # Example
///
/// ```http
/// GET /v1/graphs?status=OperatorPresigned&offset=0&limit=10
/// ```
///
/// Response example:
/// ```json
/// {
///   "graphs": [
///     {
///       "graph": {
///         "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///         "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///         "kickoff_index": 10,
///         "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///         "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///         "amount": 2000000,
///         "challenge_amount": 1000000,
///         "status": "OperatorPresigned",
///         "sub_status": "",
///         "operator_pubkey": "03abc123...",
///         "next_prekickoff": null,
///         "cur_prekickoff_txid": "a1b2c3d4...",
///         "force_skip_kickoff_txid": null,
///         "quick_challenge_txid": null,
///         "challenge_incomplete_kickoff_txid": null,
///         "pegin_txid": null,
///         "kickoff_txid": null,
///         "take1_txid": null,
///         "challenge_txid": null,
///         "take2_txid": null,
///         "watchtower_challenge_init_txid": null,
///         "operator_assert_txid": null,
///         "verifier_assert_txids": [],
///         "disprove_txids": [],
///         "watchtower_challenge_timeout_txids": [],
///         "operator_challenge_nack_txids": [],
///         "operator_commit_timeout_txid": null,
///         "init_withdraw_tx_hash": null,
///         "bridge_out_start_at": 1699123456,
///         "status_updated_at": 1699123456,
///         "created_at": 1699123456,
///         "updated_at": 1699123456
///       },
///       "challenge_sub_status": "Assert",
///       "waiting_time_in_secs": 1000,
///       "proof_status": "Pending"
///     }
///   ],
///   "total": 1
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graphs(
    Query(params): Query<GraphQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphListResponse> {
    let mut resp = GraphListResponse::default();
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPHS_ERROR")?;

    let filter_params: GraphQuery = params.into();
    let (graphs, total) =
        storage_process.find_graphs(filter_params).await.api_error("GET_GRAPHS_ERROR")?;

    resp.total = total;
    if graphs.is_empty() {
        return ok_response(resp);
    }

    let mut converted_graphs = Vec::new();
    for graph in graphs {
        let graph_extended = GraphExtended::convert_from_graph(&app_state.btc_client, graph)
            .await
            .api_error("GET_GRAPHS_ERROR")?;
        converted_graphs.push(graph_extended);
    }
    resp.graphs = converted_graphs;

    ok_response(resp)
}

/// Get ready to kickoff graph
///
/// Returns a BitVM graph that is ready for the operator to kickoff. This endpoint is used by
/// operators to query available graphs that need kickoff processing.
///
/// # Query Parameters
///
/// - `btc_pub_key`: Operator's Bitcoin public key (required) - identifies the operator
/// - `goat_addr`: GOAT address filter (optional) - filters by source address
///
/// # Returns
///
/// - `200 OK`: Successfully returns ready graph or reason why no graph is ready
/// - `500 Internal Server Error`: Server internal error or missing required parameters
/// - Response includes graph data if available, or reason why no graph is ready
///
/// # Use Case
///
/// Operators use this endpoint to poll for graphs that are in OperatorDataPushed status
/// and ready for kickoff processing. The operator can start the kickoff process once a
/// suitable graph is found.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/ready-to-kickoff?btc_pub_key=03abc...&goat_addr=0x123...
/// ```
///
/// Response example:
/// ```json
/// {
///   "graph": {
///     "graph_id": "123e4567-e89b-12d3-a456-426614174000",
///     "instance_id": "987e6543-e89b-12d3-a456-426614174000",
///     "kickoff_index": 10,
///     "from_addr": "0x1234567890abcdef1234567890abcdef12345678",
///     "to_addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///     "amount": 2000000,
///     "challenge_amount": 1000000,
///     "status": "OperatorDataPushed",
///     "sub_status": "",
///     "operator_pubkey": "03abc...",
///     "next_prekickoff": null,
///     "cur_prekickoff_txid": null,
///     "force_skip_kickoff_txid": null,
///     "quick_challenge_txid": null,
///     "challenge_incomplete_kickoff_txid": null,
///     "pegin_txid": null,
///     "kickoff_txid": null,
///     "take1_txid": null,
///     "challenge_txid": null,
///     "take2_txid": null,
///     "watchtower_challenge_init_txid": null,
///     "operator_assert_txid": null,
///     "verifier_assert_txids": [],
///     "disprove_txids": [],
///     "watchtower_challenge_timeout_txids": [],
///     "operator_challenge_nack_txids": [],
///     "operator_commit_timeout_txid": null,
///     "init_withdraw_tx_hash": null,
///     "bridge_out_start_at": 0,
///     "status_updated_at": 1699123456,
///     "created_at": 1699123456,
///     "updated_at": 1699123456
///   },
///   "no_ready_reason": null
/// }
/// ```
#[axum::debug_handler]
pub async fn get_ready_to_kickoff_graph(
    Query(params): Query<GraphReadyToKickoffRequest>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphReadyToKickoffResponse> {
    let mut graph_query = GraphQuery::default()
        .with_status(GraphStatus::OperatorDataPushed.to_string())
        .with_order("kickoff_index ASC".to_string())
        .with_raw_condition("init_withdraw_tx_hash IS NULL".to_string())
        .with_limit(1);
    if params.btc_pub_key.is_none() && params.goat_addr.is_none() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET READT_KICKOFF_GRAPHS_ERROR".to_string(),
                message: "Wrong input: btc_pub_key and goat_addr should not all been none "
                    .to_string(),
            }),
        ));
    } else {
        if let Some(ref goat_addr) = params.goat_addr {
            graph_query = graph_query
                .with_from_addr(InputValidator::validate_goat_address(goat_addr, "goat_addr")?);
        }
        if let Some(ref btc_pub_key) = params.btc_pub_key {
            graph_query = graph_query.with_operator_pubkey(InputValidator::validate_btc_pubkey(
                btc_pub_key,
                "btc_pub_key",
            )?);
        }
    }

    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

    let graphs = storage_processor
        .get_operator_graphs(graph_query)
        .await
        .api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

    if graphs.is_empty() {
        return ok_response(GraphReadyToKickoffResponse { graph: None, no_ready_reason: None });
    }

    let graph = graphs[0].clone();
    if graph.kickoff_index > 0 {
        let pre_graphs = storage_processor
            .get_operator_graphs(
                GraphQuery::default()
                    .with_operator_pubkey(graph.operator_pubkey.clone())
                    .with_kickoff_index(graph.kickoff_index - 1),
            )
            .await
            .api_error("GET_READY_KICKOFF_GRAPHS_ERROR")?;

        if !pre_graphs.is_empty()
            && [
                GraphStatus::OperatorDataPushed.to_string(),
                GraphStatus::OperatorKickOff.to_string(),
                GraphStatus::Challenge.to_string(),
            ]
            .contains(&pre_graphs[0].status)
        {
            return ok_response(GraphReadyToKickoffResponse {
                graph: None,
                no_ready_reason: Some(pre_graphs[0].graph_id.to_string()),
            });
        }
    }

    ok_response(GraphReadyToKickoffResponse { graph: Some(graph), no_ready_reason: None })
}

/// Get graph Bitcoin transaction progress data
///
/// Helper function to retrieve progress tracking data for specific BitVM graph transactions.
/// This function monitors transaction vout status and extracts progress information for
/// watchtower challenges and assert operations.
///
/// # Parameters
///
/// - `storage_processor`: Database storage processor for querying transaction monitoring data
/// - `btc_tx_name`: The type of Bitcoin transaction to query
/// - `graph`: The graph instance containing transaction IDs
///
/// # Returns
///
/// - `Ok((progress_data_vec, fail_reason))`: Tuple of progress data steps and optional failure reason
/// - `Err`: Error if database query fails
pub(crate) async fn get_graph_btc_tx_process_data<'a>(
    _storage_processor: &mut StorageProcessor<'a>,
    _btc_tx_name: GraphBtcTxName,
    _graph: &Graph,
) -> anyhow::Result<(Vec<ProgressData>, Option<String>)> {
    Ok((vec![], None))
}

/// Get graph transaction by name
///
/// Returns raw Bitcoin transaction data and progress information for a specific transaction
/// within a BitVM graph. Supports querying various transaction types including kickoff,
/// challenge, and take transactions.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM graph
///
/// # Query Parameters
///
/// - `tx_name`: Name of the transaction to retrieve, using the `*.hex` names from `GraphBtcTxName`
/// - `index`: Optional verifier index for `verifier-assert.hex` and `disprove.hex`
///
/// # Returns
///
/// - `200 OK`: Successfully returns transaction raw data and progress information
/// - `500 Internal Server Error`: Server internal error or invalid parameters
/// - Returns serialized transaction hex and progress tracking data
///
/// # Use Case
///
/// Applications use this to retrieve specific transaction details from a graph, including
/// the raw transaction data for broadcasting and progress information for multi-step processes.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/tx?tx_name=watchtower-challenge-init.hex
/// ```
///
/// Response example (for WatchtowerChallengeInit transaction):
/// ```json
/// {
///   "btc_tx_data": {
///     "raw_data": "020000000001...",
///     "progresses": [],
///     "fail_reason": null
///   }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_tx(
    Query(params): Query<GraphTxGetParams>,
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphTxGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    // Validate tx_name format
    let tx_name = InputValidator::validate_tx_name(&params.tx_name)?;

    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_GRAPH_TX_ERROR")?;

    let graph = storage_process.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_TX_ERROR")?;

    if let Some(graph) = graph {
        let (progresses, fail_reason) =
            get_graph_btc_tx_process_data(&mut storage_process, tx_name, &graph)
                .await
                .api_error("GET_GRAPH_TX_ERROR")?;

        let simplified_bitvm_graph =
            load_validated_graph_definition(&mut storage_process, graph.instance_id, graph_id_uuid)
                .await
                .api_error("GET_GRAPH_TXN_ERROR")?
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "GET_GRAPH_TXN_ERROR".to_string(),
                            message: format!("graph:{graph_id} raw data is not record in db"),
                        }),
                    )
                })?;

        let bitvm_graph: BitvmGcGraph = BitvmGcGraph::from_simplified(&simplified_bitvm_graph)
            .api_error("GET_GRAPH_TX_ERROR")?;
        let tx_index = params.index.unwrap_or(0);

        let raw_data = match tx_name {
            GraphBtcTxName::CurPreKickoff => serialize_hex(bitvm_graph.cur_prekickoff.tx()),
            GraphBtcTxName::NextPreKickoff => serialize_hex(bitvm_graph.next_prekickoff.tx()),
            GraphBtcTxName::ForceSkipKickoff => serialize_hex(bitvm_graph.force_skip_kickoff.tx()),
            GraphBtcTxName::QuickChallenge => serialize_hex(bitvm_graph.quick_challenge.tx()),
            GraphBtcTxName::ChallengeIncompleteKickoff => {
                serialize_hex(bitvm_graph.challenge_incomplete_kickoff.tx())
            }
            GraphBtcTxName::Pegin => serialize_hex(bitvm_graph.pegin.tx()),
            GraphBtcTxName::Kickoff => serialize_hex(bitvm_graph.kickoff.tx()),
            GraphBtcTxName::Take1 => serialize_hex(bitvm_graph.take1.tx()),
            GraphBtcTxName::Challenge => {
                if let Some(challenge_txid) = graph.challenge_txid
                    && let Ok(Some(tx)) = app_state.btc_client.get_tx(&challenge_txid.0).await
                {
                    serialize_hex(&tx)
                } else {
                    serialize_hex(bitvm_graph.challenge.tx())
                }
            }
            GraphBtcTxName::WatchtowerChallengeInit => {
                serialize_hex(bitvm_graph.watchtower_challenge_init.tx())
            }
            GraphBtcTxName::OperatorAssert => serialize_hex(bitvm_graph.operator_assert.tx()),
            GraphBtcTxName::VerifierAssert => {
                let tx = bitvm_graph.verifier_asserts.get(tx_index).ok_or_else(|| {
                    graph_tx_index_error(tx_name, tx_index, bitvm_graph.verifier_asserts.len())
                })?;
                serialize_hex(tx.tx())
            }
            GraphBtcTxName::Disprove => {
                let tx = bitvm_graph.disproves.get(tx_index).ok_or_else(|| {
                    graph_tx_index_error(tx_name, tx_index, bitvm_graph.disproves.len())
                })?;
                serialize_hex(tx.tx())
            }
            GraphBtcTxName::Take2 => serialize_hex(bitvm_graph.take2.tx()),
        };

        ok_response(GraphTxGetResponse {
            btc_tx_data: BtcTxData { raw_data, progresses, fail_reason },
        })
    } else {
        tracing::warn!("graph:{} is not record in db", graph_id);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET_GRAPH_TX_ERROR".to_string(),
                message: format!("graph:{graph_id} is not record in db"),
            }),
        ))
    }
}

/// Get all graph transactions
///
/// Returns raw Bitcoin transaction data and progress information for all transactions
/// in a BitVM graph. This includes all transaction types currently present in `BitvmGcGraph`,
/// including verifier assert and disprove vectors.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM graph
///
/// # Query Parameters
///
/// - Currently no query parameters are required
///
/// # Returns
///
/// - `200 OK`: Successfully returns all transaction raw data with progress information
/// - `500 Internal Server Error`: Server internal error or graph not found
/// - Response includes serialized hex data for all graph transactions and their progress tracking
///
/// # Use Case
///
/// Applications use this to retrieve all transaction details from a graph in a single request,
/// which is useful for displaying the complete transaction flow and status of a BitVM graph.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/txn
/// ```
///
/// Response example:
/// ```json
/// {
///   "cur_prekickoff": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "next_prekickoff": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "force_skip_kickoff": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "quick_challenge": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "challenge_incomplete_kickoff": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "pegin": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "kickoff": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "take1": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "challenge": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "watchtower_challenge_init": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "operator_assert": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null },
///   "verifier_asserts": [{ "raw_data": "020000000001...", "progresses": [], "fail_reason": null }],
///   "disproves": [{ "raw_data": "020000000001...", "progresses": [], "fail_reason": null }],
///   "take2": { "raw_data": "020000000001...", "progresses": [], "fail_reason": null }
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_txn(
    Path(graph_id): Path<String>,
    Query(params): Query<GraphTxnGetParams>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphTxnGetResponse> {
    // Validate graph_id format
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_GRAPH_TXN_ERROR")?;
    if let Some(graph) =
        storage_processor.find_graph(&graph_id_uuid).await.api_error("GET_GRAPH_TXN_ERROR")?
    {
        let kickoff_index = graph.kickoff_index + params.cursor as i64;
        let graph = if kickoff_index != graph.kickoff_index {
            let graph_arrays = storage_processor
                .get_operator_graphs(
                    GraphQuery::default()
                        .with_operator_pubkey(graph.operator_pubkey)
                        .with_kickoff_index(kickoff_index)
                        .with_limit(1),
                )
                .await
                .api_error("GET_OPERATOR_GRAPHS")?;
            if graph_arrays.is_empty() {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "GET_GRAPH_TXN_ERROR".to_string(),
                        message: format!(
                            "graph:{graph_id} with cursor:{} is not record in db",
                            params.cursor
                        ),
                    }),
                ));
            }
            graph_arrays[0].clone()
        } else {
            graph
        };

        let simplified_bitvm_graph = load_validated_graph_definition(
            &mut storage_processor,
            graph.instance_id,
            graph.graph_id,
        )
        .await
        .api_error("GET_GRAPH_TXN_ERROR")?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "GET_GRAPH_TXN_ERROR".to_string(),
                    message: format!(
                        "graph:{graph_id} with cursor:{} raw data is not record in db",
                        params.cursor
                    ),
                }),
            )
        })?;
        let bitvm_graph: BitvmGcGraph = BitvmGcGraph::from_simplified(&simplified_bitvm_graph)
            .api_error("GET_GRAPH_TXN_ERROR")?;

        let (wt_progresses, wt_fail_reason) = get_graph_btc_tx_process_data(
            &mut storage_processor,
            GraphBtcTxName::WatchtowerChallengeInit,
            &graph,
        )
        .await
        .api_error("GET_GRAPH_TXN_ERROR")?;

        let (assert_progresses, assert_fail_reason) = get_graph_btc_tx_process_data(
            &mut storage_processor,
            GraphBtcTxName::OperatorAssert,
            &graph,
        )
        .await
        .api_error("GET_GRAPH_TXN_ERROR")?;

        let mut resp = GraphTxnGetResponse {
            cur_prekickoff: BtcTxData::new(serialize_hex(bitvm_graph.cur_prekickoff.tx())),
            next_prekickoff: BtcTxData::new(serialize_hex(bitvm_graph.next_prekickoff.tx())),
            force_skip_kickoff: BtcTxData::new(serialize_hex(bitvm_graph.force_skip_kickoff.tx())),
            quick_challenge: BtcTxData::new(serialize_hex(bitvm_graph.quick_challenge.tx())),
            challenge_incomplete_kickoff: BtcTxData::new(serialize_hex(
                bitvm_graph.challenge_incomplete_kickoff.tx(),
            )),
            pegin: BtcTxData::new(serialize_hex(bitvm_graph.pegin.tx())),
            kickoff: BtcTxData::new(serialize_hex(bitvm_graph.kickoff.tx())),
            take1: BtcTxData::new(serialize_hex(bitvm_graph.take1.tx())),
            challenge: BtcTxData::new(serialize_hex(bitvm_graph.challenge.tx())),
            watchtower_challenge_init: BtcTxData::new(serialize_hex(
                bitvm_graph.watchtower_challenge_init.tx(),
            ))
            .with_progresses(wt_progresses)
            .with_fail_reason(wt_fail_reason),
            operator_assert: BtcTxData::new(serialize_hex(bitvm_graph.operator_assert.tx()))
                .with_progresses(assert_progresses)
                .with_fail_reason(assert_fail_reason),
            verifier_asserts: bitvm_graph
                .verifier_asserts
                .iter()
                .map(|tx| BtcTxData::new(serialize_hex(tx.tx())))
                .collect(),
            disproves: bitvm_graph
                .disproves
                .iter()
                .map(|tx| BtcTxData::new(serialize_hex(tx.tx())))
                .collect(),
            take2: BtcTxData::new(serialize_hex(bitvm_graph.take2.tx())),
        };

        if let Some(challenge_txid) = graph.challenge_txid
            && let Ok(Some(tx)) = app_state.btc_client.get_tx(&challenge_txid.0).await
        {
            resp.challenge.raw_data = serialize_hex(&tx);
        }

        ok_response(resp)
    } else {
        warn!("graph:{} is not record in db", graph_id);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "GET_GRAPH_TXN_ERROR".to_string(),
                message: format!(
                    "graph:{graph_id} with cursor:{} is not record in db",
                    params.cursor
                ),
            }),
        ))
    }
}

/// Get neighboring graph IDs
///
/// Returns the previous and next graphs (by kickoff index) for the same operator,
/// which allows the UI to implement previous/next navigation when browsing graph details.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the current BitVM graph
///
/// # Returns
///
/// - `200 OK`: Successfully returns the current graph ID plus its previous and next neighbors
/// - `500 Internal Server Error`: Parameter validation failed or database query failed
///
/// # Use Case
///
/// Frontend can call this endpoint when showing a graph detail page to quickly fetch
/// the `previous_id` and `next_id` for navigation controls.
///
/// # Example
///
/// ```http
/// GET /v1/graphs/123e4567-e89b-12d3-a456-426614174000/neighbor-ids
/// ```
///
/// Response example:
/// ```json
/// {
///   "current_id": "123e4567-e89b-12d3-a456-426614174000",
///   "previous_id": "123e4567-e89b-12d3-a456-426614173999",
///   "next_id": "123e4567-e89b-12d3-a456-426614174001"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_graph_neighbor_ids(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<GraphNeighborIdsResponse> {
    let current_id = InputValidator::validate_uuid(&graph_id, "graph_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_GRAPH_NEIGHBOR_ERROR")?;
    let id_with_kickoff_indexes = storage_processor
        .find_graph_neighbor_ids(current_id, 1)
        .await
        .api_error("GET_GRAPH_NEIGHBOR_ERROR")?;
    let mut res = GraphNeighborIdsResponse { current_id, previous_id: None, next_id: None };
    for (i, (_kickoff_index, graph_id)) in id_with_kickoff_indexes.iter().enumerate() {
        if i == 0 && *graph_id != current_id {
            res.previous_id = Some(*graph_id);
        }
        if i > 0 && *graph_id != current_id {
            res.next_id = Some(*graph_id);
        }
    }
    ok_response(res)
}

/// Get unsigned pegin transactions
///
/// Returns the unsigned pegin deposit transaction (prepare) and pegin refund transaction (cancel)
/// for a given instance, which allows users to sign and broadcast these transactions for pegin operations.
///
/// # Path Parameters
///
/// - `instance_id`: UUID of the BitVM instance
///
/// # Returns
///
/// - `200 OK`: Successfully returns the unsigned pegin transactions (if instance exists)
/// - `500 Internal Server Error`: Parameter validation failed or database query failed
///
/// # Use Case
///
/// Frontend can call this endpoint to get the unsigned pegin transactions for an instance,
/// allowing users to sign and broadcast the `pegin_prepare` transaction to deposit funds,
/// or the `pegin_cancel` transaction to refund if needed.
///
/// # Example
///
/// ```http
/// GET /v1/instances/123e4567-e89b-12d3-a456-426614174000/unsigned-pegin-txn
/// ```
///
/// Response example:
/// ```json
/// {
///   "pegin_prepare": "0200000001...",
///   "pegin_cancel_psbt": "0200000001..."
/// }
/// ```
#[axum::debug_handler]
// TODO(auth): Require authorization before returning a locally constructed cancellation PSBT.
pub async fn get_unsigned_pegin_txn(
    Path(instance_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<UnsignPeginTxnResponse> {
    let current_id = InputValidator::validate_uuid(&instance_id, "instance_id")?;
    let mut storage_processor =
        app_state.local_db.acquire().await.api_error("GET_UNSIGNED_PEGIN_ERROR")?;
    let mut res = UnsignPeginTxnResponse::default();
    if let Some(instance) =
        storage_processor.find_instance(&current_id).await.api_error("GET_UNSIGNED_PEGIN_ERROR")?
        && [
            InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string(),
            InstanceBridgeInStatus::Presigned.to_string(),
            InstanceBridgeInStatus::PresignedFailed.to_string(),
            InstanceBridgeInStatus::Timeout.to_string(),
        ]
        .contains(&instance.status)
    {
        let instance_parameters =
            gen_instance_parameters_local(&instance).api_error("GET_UNSIGNED_PEGIN_ERROR")?;
        let (pegin_deposit_tx, _, _) =
            instance_parameters.build_pegin_tx().api_error("GET_UNSIGNED_PEGIN_ERROR")?;
        res.pegin_prepare = Some(serialize_hex(pegin_deposit_tx.tx()));
        res.pegin_cancel_psbt = Some(hex::encode(
            instance_parameters
                .build_pegin_cancel_psbt()
                .api_error("GET_UNSIGNED_PEGIN_ERROR")?
                .serialize(),
        ));
    } else {
        warn!(
            "instance:{instance_id} is not record in db or instance status neq CommitteesAnswered"
        );
    }
    ok_response(res)
}

/// Send challenge transaction for a graph
///
/// Loads the graph from DB, rebuilds the full BitVM graph, and broadcasts
/// the Challenge transaction on Bitcoin.
///
/// # Path Parameters
///
/// - `graph_id`: UUID of the BitVM graph to challenge
///
/// # Returns
///
/// - `200 OK`: Challenge transaction broadcasted successfully, returns txid
/// - `500 Internal Server Error`: Graph not found or broadcast failed
#[axum::debug_handler]
pub async fn send_challenge(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<SendChallengeResponse> {
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;

    let mut storage_process =
        app_state.local_db.acquire().await.api_error("SEND_CHALLENGE_ERROR")?;

    let graph = storage_process
        .find_graph(&graph_id_uuid)
        .await
        .api_error("SEND_CHALLENGE_ERROR")?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "SEND_CHALLENGE_ERROR".to_string(),
                    message: format!("graph:{graph_id} not found in db"),
                }),
            )
        })?;

    let simplified_bitvm_graph =
        load_validated_graph_definition(&mut storage_process, graph.instance_id, graph_id_uuid)
            .await
            .api_error("SEND_CHALLENGE_ERROR")?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "SEND_CHALLENGE_ERROR".to_string(),
                        message: format!("graph:{graph_id} raw data not found in db"),
                    }),
                )
            })?;

    let bitvm_graph: BitvmGcGraph =
        BitvmGcGraph::from_simplified(&simplified_bitvm_graph).api_error("SEND_CHALLENGE_ERROR")?;

    let txid = send_challenge_tx(&app_state.btc_client, &bitvm_graph)
        .await
        .api_error("SEND_CHALLENGE_ERROR")?;

    ok_response(SendChallengeResponse { challenge_txid: txid.to_string() })
}

/// Force the local verifier to broadcast its ChallengeAssert transaction for a graph.
///
/// This is a test endpoint. Unlike the normal AssertSent verifier flow, it does
/// not skip ChallengeAssert when the operator assert proof is valid.
#[cfg(feature = "rpc-debug-endpoints")]
#[axum::debug_handler]
pub async fn send_verifier_challenge(
    Path(graph_id): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<SendVerifierChallengeResponse> {
    let graph_id_uuid = InputValidator::validate_uuid(&graph_id, "graph_id")?;

    let mut storage_process =
        app_state.local_db.acquire().await.api_error("SEND_VERIFIER_CHALLENGE_ERROR")?;

    let graph = storage_process
        .find_graph(&graph_id_uuid)
        .await
        .api_error("SEND_VERIFIER_CHALLENGE_ERROR")?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "SEND_VERIFIER_CHALLENGE_ERROR".to_string(),
                    message: format!("graph:{graph_id} not found in db"),
                }),
            )
        })?;

    let simplified_bitvm_graph =
        load_validated_graph_definition(&mut storage_process, graph.instance_id, graph_id_uuid)
            .await
            .api_error("SEND_VERIFIER_CHALLENGE_ERROR")?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "SEND_VERIFIER_CHALLENGE_ERROR".to_string(),
                        message: format!("graph:{graph_id} raw data not found in db"),
                    }),
                )
            })?;

    let bitvm_graph: BitvmGcGraph = BitvmGcGraph::from_simplified(&simplified_bitvm_graph)
        .api_error("SEND_VERIFIER_CHALLENGE_ERROR")?;

    let assert_txid = bitvm_graph.operator_assert.tx().compute_txid();
    let assert_tx = app_state
        .btc_client
        .get_tx(&assert_txid)
        .await
        .api_error("SEND_VERIFIER_CHALLENGE_ERROR")?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "SEND_VERIFIER_CHALLENGE_ERROR".to_string(),
                    message: format!("operator assert tx {assert_txid} not found on Bitcoin"),
                }),
            )
        })?;

    let strict = true;
    let (challenge_assert_txid, verifier_index) = broadcast_verifier_challenge_assert_tx(
        &app_state.local_db,
        &app_state.btc_client,
        &bitvm_graph,
        simplified_bitvm_graph.parameters.instance_parameters.instance_id,
        graph_id_uuid,
        &assert_tx,
        strict,
    )
    .await
    .api_error("SEND_VERIFIER_CHALLENGE_ERROR")?
    .ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "SEND_VERIFIER_CHALLENGE_ERROR".to_string(),
                message: format!(
                    "local verifier cannot broadcast ChallengeAssert for graph {graph_id}"
                ),
            }),
        )
    })?;

    ok_response(SendVerifierChallengeResponse {
        challenge_assert_txid: challenge_assert_txid.to_string(),
        verifier_index,
    })
}

const BTC_DECIMALS: u8 = 8;

fn sats_to_token_amount(amount_sats: u64, token_decimals: u8) -> U256 {
    if token_decimals >= BTC_DECIMALS {
        U256::from(amount_sats) * U256::from(10).pow(U256::from(token_decimals - BTC_DECIMALS))
    } else {
        U256::from(amount_sats / 10u64.pow(u32::from(BTC_DECIMALS - token_decimals)))
    }
}

/// Initiate operator pegout (Gateway.initWithdraw)
///
/// Selects an eligible graph (or uses the provided graph_id), checks L2 pegin/withdraw
/// status, ensures pegBTC allowance, and calls Gateway.initWithdraw.
///
/// # Request Body
///
/// - `graph_id`: Optional preferred UUID of the graph to pegout. If it has
///   already been claimed by another graph, the next eligible graph is used.
/// - `dry_run`: If true, validate but skip the actual initWithdraw call (default: false)
/// - `skip_locked`: If true, skip a candidate whose instance is locked by another
///   withdrawal, including a stale locked predecessor (default: false).
///
/// # Returns
///
/// - `200 OK`: Pegout initiated (or validated in dry-run mode)
/// - `500 Internal Server Error`: No eligible graph, L2 status invalid, or initWithdraw failed
#[axum::debug_handler]
pub async fn pegout(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<PegoutRequest>,
) -> ApiResult<PegoutResponse> {
    let operator_pubkey = get_node_pubkey().api_error("PEGOUT_ERROR")?.to_string();
    let operator_goat_addr = get_node_goat_address()
        .ok_or_else(|| {
            anyhow::anyhow!("missing operator goat address; set GOAT_PRIVATE_KEY or GOAT_ADDRESS")
        })
        .api_error("PEGOUT_ERROR")?;
    let gateway_addr = get_goat_gateway_contract_from_env();

    let mut preferred_graph_id = payload
        .graph_id
        .as_deref()
        .map(|graph_id| InputValidator::validate_uuid(graph_id, "graph_id"))
        .transpose()?;
    let mut skipped_graph_ids = HashSet::new();

    // A claimed instance can leave an old OperatorDataPushed graph in the
    // local projection until the terminal withdraw event is observed. Reconcile
    // it and select another candidate instead of failing pegout.
    let (graph, pegin_data) = loop {
        let graph = {
            let mut storage_process =
                app_state.local_db.acquire().await.api_error("PEGOUT_ERROR")?;
            if let Some(graph_id) = preferred_graph_id {
                let graph = storage_process
                    .find_graph(&graph_id)
                    .await
                    .api_error("PEGOUT_ERROR")?
                    .ok_or_else(|| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "PEGOUT_ERROR".to_string(),
                                message: format!("graph {graph_id} not found"),
                            }),
                        )
                    })?;
                if graph.operator_pubkey != operator_pubkey {
                    return error_response(
                        "PEGOUT_ERROR".to_string(),
                        format!("graph {} not owned by this operator", graph.graph_id),
                    );
                }
                if graph.status != GraphStatus::OperatorDataPushed.to_string() {
                    return error_response(
                        "PEGOUT_ERROR".to_string(),
                        format!(
                            "graph {} status {} is not OperatorDataPushed",
                            graph.graph_id, graph.status
                        ),
                    );
                }
                if graph.init_withdraw_tx_hash.is_some() {
                    return error_response(
                        "PEGOUT_ERROR".to_string(),
                        format!("graph {} already initialized withdraw", graph.graph_id),
                    );
                }
                graph
            } else {
                let graphs = storage_process
                    .get_operator_graphs(
                        GraphQuery::default()
                            .with_operator_pubkey(operator_pubkey.clone())
                            .with_status(GraphStatus::OperatorDataPushed.to_string())
                            .with_raw_condition("init_withdraw_tx_hash IS NULL".to_string())
                            .with_order("kickoff_index ASC".to_string()),
                    )
                    .await
                    .api_error("PEGOUT_ERROR")?;
                graphs
                    .into_iter()
                    .find(|graph| !skipped_graph_ids.contains(&graph.graph_id))
                    .ok_or_else(|| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "PEGOUT_ERROR".to_string(),
                                message: format!(
                                    "no eligible graph found for operator {operator_pubkey}"
                                ),
                            }),
                        )
                    })?
            }
        };

        let pegin_data = app_state
            .goat_client
            .gateway_get_pegin_data(&graph.instance_id)
            .await
            .api_error("PEGOUT_ERROR")?;
        match pegin_data.status {
            PeginStatus::Claimed => {
                let withdraw_data = app_state
                    .goat_client
                    .gateway_get_withdraw_data(&graph.graph_id)
                    .await
                    .api_error("PEGOUT_ERROR")?;
                if withdraw_data.status == WithdrawStatus::None {
                    let mut storage_process =
                        app_state.local_db.acquire().await.api_error("PEGOUT_ERROR")?;
                    let obsoleted =
                        obsolete_graph(&mut storage_process, graph.instance_id, graph.graph_id)
                            .await
                            .api_error("PEGOUT_ERROR")?;
                    warn!(
                        instance_id = %graph.instance_id,
                        skipped_graph_id = %graph.graph_id,
                        obsoleted,
                        "skipped obsolete graph while selecting pegout candidate"
                    );
                }
                skipped_graph_ids.insert(graph.graph_id);
                preferred_graph_id = None;
                continue;
            }
            PeginStatus::Locked if !payload.skip_locked => {
                return error_response(
                    "PEGOUT_IN_PROGRESS".to_string(),
                    format!(
                        "graph {} instance {} is locked by an in-progress withdrawal; retry later or set skip_locked=true",
                        graph.graph_id, graph.instance_id
                    ),
                );
            }
            PeginStatus::Locked => {
                info!(
                    instance_id = %graph.instance_id,
                    skipped_graph_id = %graph.graph_id,
                    "skipped graph whose instance is locked by another withdrawal"
                );
                skipped_graph_ids.insert(graph.graph_id);
                preferred_graph_id = None;
                continue;
            }
            _ => {}
        }

        if graph.kickoff_index > 0 {
            let previous_graph = {
                let mut storage_process =
                    app_state.local_db.acquire().await.api_error("PEGOUT_ERROR")?;
                storage_process
                    .get_operator_graphs(
                        GraphQuery::default()
                            .with_operator_pubkey(graph.operator_pubkey.clone())
                            .with_kickoff_index(graph.kickoff_index - 1),
                    )
                    .await
                    .api_error("PEGOUT_ERROR")?
                    .into_iter()
                    .next()
            };

            if let Some(previous_graph) = previous_graph {
                let previous_status = match GraphStatus::from_str(&previous_graph.status) {
                    Ok(status) => status,
                    Err(_) => {
                        return error_response(
                            "PEGOUT_ERROR".to_string(),
                            format!(
                                "graph {} has an unknown previous graph {} status {}",
                                graph.graph_id, previous_graph.graph_id, previous_graph.status
                            ),
                        );
                    }
                };
                match previous_status {
                    // A higher-index graph can only reach OperatorDataPushed after these
                    // graphs have become stale, so they must not block its withdrawal.
                    GraphStatus::OperatorPresigned | GraphStatus::CommitteePresigned => {}
                    GraphStatus::Obsoleted
                    | GraphStatus::Skipped
                    | GraphStatus::OperatorTake1
                    | GraphStatus::OperatorTake2
                    | GraphStatus::Disprove => {}
                    GraphStatus::OperatorDataPushed => {
                        let previous_pegin_data = app_state
                            .goat_client
                            .gateway_get_pegin_data(&previous_graph.instance_id)
                            .await
                            .api_error("PEGOUT_ERROR")?;
                        let previous_withdraw_data = app_state
                            .goat_client
                            .gateway_get_withdraw_data(&previous_graph.graph_id)
                            .await
                            .api_error("PEGOUT_ERROR")?;
                        match previous_pegin_data.status {
                            PeginStatus::Claimed => {}
                            PeginStatus::Locked
                                if previous_withdraw_data.status == WithdrawStatus::None
                                    && payload.skip_locked =>
                            {
                                info!(
                                    instance_id = %graph.instance_id,
                                    graph_id = %graph.graph_id,
                                    previous_graph_id = %previous_graph.graph_id,
                                    "previous graph is locked by another withdrawal; continuing pegout"
                                );
                            }
                            PeginStatus::Locked
                                if previous_withdraw_data.status == WithdrawStatus::None =>
                            {
                                return error_response(
                                    "PEGOUT_IN_PROGRESS".to_string(),
                                    format!(
                                        "graph {} is blocked because previous graph {} is locked by another withdrawal; retry later or set skip_locked=true",
                                        graph.graph_id, previous_graph.graph_id
                                    ),
                                );
                            }
                            PeginStatus::Withdrawable => {
                                return error_response(
                                    "PEGOUT_ERROR".to_string(),
                                    format!(
                                        "graph {} not ready: previous graph {} is still withdrawable",
                                        graph.graph_id, previous_graph.graph_id
                                    ),
                                );
                            }
                            previous_pegin_status => {
                                return error_response(
                                    "PEGOUT_ERROR".to_string(),
                                    format!(
                                        "graph {} not ready: previous graph {} is in status {} with pegin status {:?} and withdraw status {:?}",
                                        graph.graph_id,
                                        previous_graph.graph_id,
                                        previous_graph.status,
                                        previous_pegin_status,
                                        previous_withdraw_data.status
                                    ),
                                );
                            }
                        }
                    }
                    GraphStatus::PreKickoff
                    | GraphStatus::OperatorKickOff
                    | GraphStatus::Challenge => {
                        return error_response(
                            "PEGOUT_ERROR".to_string(),
                            format!(
                                "graph {} not ready: previous graph {} is in active pegout status {}",
                                graph.graph_id, previous_graph.graph_id, previous_graph.status
                            ),
                        );
                    }
                    _ => {
                        return error_response(
                            "PEGOUT_ERROR".to_string(),
                            format!(
                                "graph {} not ready: previous graph {} has unexpected status {}",
                                graph.graph_id, previous_graph.graph_id, previous_graph.status
                            ),
                        );
                    }
                }
            }
        }

        break (graph, pegin_data);
    };

    let amount = graph.amount;
    if amount <= 0 {
        return error_response(
            "PEGOUT_ERROR".to_string(),
            format!("graph {} has invalid amount {}", graph.graph_id, amount),
        );
    }

    // Check L2 pegin status
    if pegin_data.status != PeginStatus::Withdrawable {
        return error_response(
            "PEGOUT_ERROR".to_string(),
            format!(
                "graph {} instance {} pegin status is {:?}, not Withdrawable",
                graph.graph_id, graph.instance_id, pegin_data.status
            ),
        );
    }

    // Check L2 withdraw status
    let withdraw_data = app_state
        .goat_client
        .gateway_get_withdraw_data(&graph.graph_id)
        .await
        .api_error("PEGOUT_ERROR")?;
    if withdraw_data.status != WithdrawStatus::None {
        return error_response(
            "PEGOUT_ERROR".to_string(),
            format!(
                "graph {} withdraw status is {:?}, not None",
                graph.graph_id, withdraw_data.status
            ),
        );
    }

    if payload.dry_run {
        return ok_response(PegoutResponse {
            graph_id: graph.graph_id.to_string(),
            instance_id: graph.instance_id.to_string(),
            kickoff_index: graph.kickoff_index,
            amount,
            tx_hash: None,
            dry_run: true,
        });
    }

    // Mirror Gateway._amountFromSats using the on-chain pegin amount and pegBTC decimals.
    let peg_btc_decimals =
        app_state.goat_client.peg_btc_decimals().await.api_error("PEGOUT_ERROR")?;
    let amount_u256 = sats_to_token_amount(pegin_data.pegin_amount_sats, peg_btc_decimals);
    let balance = app_state
        .goat_client
        .peg_btc_balance(&operator_goat_addr.0)
        .await
        .api_error("PEGOUT_ERROR")?;
    if balance < amount_u256 {
        return error_response(
            "PEGOUT_ERROR".to_string(),
            format!(
                "insufficient pegBTC balance: need {amount_u256} base units ({} sats, {peg_btc_decimals} decimals), available {balance}",
                pegin_data.pegin_amount_sats
            ),
        );
    }

    let allowance = app_state
        .goat_client
        .peg_btc_allowance(&operator_goat_addr.0, &gateway_addr.0)
        .await
        .api_error("PEGOUT_ERROR")?;
    if allowance < amount_u256 {
        app_state
            .goat_client
            .peg_btc_approve(&gateway_addr.0, amount_u256)
            .await
            .api_error("PEGOUT_ERROR")?;
    }

    // Call Gateway.initWithdraw
    let tx_hash = app_state
        .goat_client
        .gateway_init_withdraw(&graph.instance_id, &graph.graph_id)
        .await
        .api_error("PEGOUT_ERROR")?;

    ok_response(PegoutResponse {
        graph_id: graph.graph_id.to_string(),
        instance_id: graph.instance_id.to_string(),
        kickoff_index: graph.kickoff_index,
        amount,
        tx_hash: Some(tx_hash),
        dry_run: false,
    })
}

// fn is_segwit_address(address: &str, network: &str) -> anyhow::Result<bool> {
//     let addr: Address<NetworkUnchecked> = Address::from_str(address)?;
//     let addr = addr.require_network(Network::from_str(network)?)?;
//     Ok(matches!(
//         addr.address_type(),
//         Some(AddressType::P2wpkh) | Some(AddressType::P2wsh) | Some(AddressType::P2tr)
//     ))
// }
