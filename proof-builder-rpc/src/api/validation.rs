use crate::api::response::ErrorResponse;
use axum::Json;
use axum::http::StatusCode;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use client::goat_chain::GraphData;
use proof_builder::OperatorProofRequest;
use std::str::FromStr;
use uuid::Uuid;

/// Input validation error response
/// Validation result type
pub(crate) type ValidationResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;

/// Input validation utilities
pub(crate) struct InputValidator;

impl InputValidator {
    /// Validate UUID format
    pub(crate) fn validate_uuid(uuid_str: &str, field_name: &str) -> ValidationResult<Uuid> {
        if uuid_str.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_UUID".to_string(),
                    message: format!("{field_name} cannot be empty"),
                }),
            ));
        }

        // Check UUID format
        match Uuid::parse_str(uuid_str) {
            Ok(uuid) => Ok(uuid),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_UUID_FORMAT".to_string(),
                    message: format!("{field_name} is not a valid UUID format"),
                }),
            )),
        }
    }

    /// Validate UUID format
    pub(crate) fn validate_btc_txid(txid: &str, field_name: &str) -> ValidationResult<Txid> {
        match Txid::from_str(txid) {
            Ok(txid) => Ok(txid),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_BTC_TXID".to_string(),
                    message: format!("{field_name} is not a valid BTC txid"),
                }),
            )),
        }
    }

    /// Checks the operator task inputs that the proof loop cannot repair later
    /// against the graph registered on GOAT.
    pub(crate) fn validate_operator_task(
        request: &OperatorProofRequest,
        graph_data: &GraphData,
    ) -> ValidationResult<()> {
        let invalid = |error: &str, message: String| {
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: error.to_string(), message }),
            ))
        };
        if BlockHash::from_str(&request.operator_committed_blockhash).is_err() {
            return invalid(
                "INVALID_BLOCK_HASH",
                "operator_committed_blockhash is not a valid block hash".to_string(),
            );
        }
        let init_txid = Self::validate_btc_txid(
            &request.watchtower_challenge_init_txid,
            "watchtower_challenge_init_txid",
        )?;
        if init_txid.to_byte_array() != graph_data.watchtower_challenge_init_txid {
            return invalid(
                "INVALID_WATCHTOWER_CHALLENGE_INIT_TXID",
                "watchtower_challenge_init_txid does not match the graph".to_string(),
            );
        }
        let watchtowers = graph_data.watchtower_challenge_timeout_txids.len();
        if watchtowers == 0 || request.watchtower_challenge_pubkeys.len() != watchtowers {
            return invalid(
                "INVALID_WATCHTOWER_LIST",
                format!(
                    "expected {watchtowers} graph watchtowers, got {}",
                    request.watchtower_challenge_pubkeys.len()
                ),
            );
        }
        Ok(())
    }

    /// Validate pagination parameters
    #[allow(dead_code)]
    pub(crate) fn validate_pagination(
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> ValidationResult<(u32, u32)> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(10);

        if offset > 10000 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_OFFSET".to_string(),
                    message: "offset cannot exceed 10000".to_string(),
                }),
            ));
        }

        if limit == 0 || limit > 100 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_LIMIT".to_string(),
                    message: "limit must be between 1 and 100".to_string(),
                }),
            ));
        }

        Ok((offset, limit))
    }

    /// Validate numeric range
    #[allow(dead_code)]
    pub(crate) fn validate_amount(amount: i64, field_name: &str) -> ValidationResult<()> {
        if amount <= 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "INVALID_AMOUNT".to_string(),
                    message: format!("{field_name} must be greater than 0"),
                }),
            ));
        }

        if amount > 21_000_000_000_000 {
            // 21M BTC in satoshis
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "AMOUNT_TOO_LARGE".to_string(),
                    message: format!("{field_name} exceeds maximum allowed value"),
                }),
            ));
        }

        Ok(())
    }
}
