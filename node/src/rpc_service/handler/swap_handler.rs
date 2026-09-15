use crate::rpc_service::AppState;
use crate::rpc_service::response::{ApiErrorExt, ApiResult, ok_response};
use crate::rpc_service::swap::*;
use crate::rpc_service::validation::InputValidator;
use axum::extract::{Path, Query, State};
use std::sync::Arc;
use store::localdb::SwapEscrowQuery;
use store::normalize_escrow_hash;
use tracing::info;

/// Get swap escrow list
///
/// Returns a paginated list of swap-based bridge-out escrows, newest first.
///
/// # Query Parameters
///
/// - `from_addr`: offerer GOAT address filter (optional)
/// - `offset`: pagination offset (default: 0)
/// - `limit`: items per page (default: 10)
///
/// # Example
///
/// ```http
/// GET /v1/swaps?offset=0&limit=10
/// ```
#[axum::debug_handler]
pub async fn get_swaps(
    Query(params): Query<SwapListRequest>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<SwapListResponse> {
    let (offset, limit) = InputValidator::validate_pagination(params.offset, params.limit)?;
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_SWAPS_ERROR")?;

    let mut query = SwapEscrowQuery::default()
        .with_order("created_at DESC".to_string())
        .with_pagination(offset, limit);
    if let Some(from_addr) = params.from_addr {
        let from_addr = InputValidator::validate_goat_address(&from_addr, "from_addr")?;
        query = query.with_offerer_addr(from_addr);
    }

    let (escrows, total) =
        storage_process.find_swap_escrows(query).await.api_error("GET_SWAPS_ERROR")?;
    if escrows.is_empty() {
        return ok_response(SwapListResponse::default());
    }

    let btc_current_height =
        app_state.btc_client.get_height().await.api_error("GET_SWAPS_ERROR")?;
    let mut swaps = Vec::with_capacity(escrows.len());
    for escrow in escrows {
        swaps.push(
            SwapEscrowExtended::convert_from_swap_escrow(
                &app_state.btc_client,
                btc_current_height,
                escrow,
            )
            .await,
        );
    }
    ok_response(SwapListResponse { swaps, total })
}

/// Get swap escrow by escrow hash
///
/// Returns the full record for one swap escrow, including the hex abi-encoded
/// EscrowData captured from its on-chain Initialize transaction (if the event
/// has been observed).
///
/// # Path Parameters
///
/// - `escrow_hash`: 0x-prefixed 32-byte hex escrow hash
///
/// # Example
///
/// ```http
/// GET /v1/swaps/0xf6d6523a4344806aca5c66f23554bc574cb93634572f5e115cc630b3d8db3c6e
/// ```
#[axum::debug_handler]
pub async fn get_swap(
    Path(escrow_hash): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> ApiResult<SwapGetResponse> {
    let escrow_hash = normalize_escrow_hash(&InputValidator::validate_hex(
        &escrow_hash,
        true,
        32,
        "escrow_hash",
    )?);
    let mut storage_process = app_state.local_db.acquire().await.api_error("GET_SWAP_ERROR")?;

    let Some(escrow) =
        storage_process.find_swap_escrow(&escrow_hash).await.api_error("GET_SWAP_ERROR")?
    else {
        info!("swap escrow {escrow_hash} has no record in database");
        return ok_response(SwapGetResponse { swap: None });
    };
    let btc_current_height = app_state.btc_client.get_height().await.api_error("GET_SWAP_ERROR")?;
    let swap = SwapEscrowExtended::convert_from_swap_escrow(
        &app_state.btc_client,
        btc_current_height,
        escrow,
    )
    .await;
    ok_response(SwapGetResponse { swap: Some(swap) })
}
