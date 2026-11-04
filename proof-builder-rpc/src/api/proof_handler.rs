use crate::api::ApiState;
use crate::api::auth::AuthResult;
use crate::api::metrics_service::ApiResultGuard;
use crate::api::response::{ApiErrorExt, ApiResult, ok_response};
use crate::api::routes;
use crate::api::validation::InputValidator;
use crate::task::{
    add_operator_task, add_watchtower_task, find_operator_task, find_watchtower_task,
    update_operator_task_state, update_watchtower_task_state,
};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use proof_builder::api_auth::ProofBuilderAuthRole;
use proof_builder::{
    ChainProofDescRequest, OperatorProofDescRequest, OperatorProofRequest, OperatorProofResponse,
    OperatorProofTimeoutUpdateRequest, OperatorProofTimeoutUpdateResponse, ProofData, ProofDesc,
    ProofDescResponse, ProofType, WatchtowerProofRequest, WatchtowerProofResponse,
    WatchtowerProofTimeoutUpdateRequest, WatchtowerProofTimeoutUpdateResponse,
};
use std::sync::Arc;
use store::ProofState;
use tracing::info;

/// Marks validation failures as invalid API results while preserving the original result.
fn record_invalid<T, E>(api_result: &mut ApiResultGuard, result: Result<T, E>) -> Result<T, E> {
    result.inspect_err(|_| api_result.set("invalid"))
}

/// Records local authorization failures separately from unavailable chain queries.
fn record_auth_result<T>(api_result: &mut ApiResultGuard, result: AuthResult<T>) -> AuthResult<T> {
    result.inspect_err(|(status, _)| {
        api_result.set(match *status {
            StatusCode::BAD_REQUEST => "invalid",
            StatusCode::SERVICE_UNAVAILABLE => "unavailable",
            _ => "unauthorized",
        });
    })
}

#[axum::debug_handler]
pub(super) async fn get_chain_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<ChainProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
    let mut api_result = api_state.metrics_state.api_result("chain_desc");
    let mut storage_process =
        api_state.local_db.acquire().await.api_error("GET_CHAIN_PROOF_ERROR")?;

    let proof = if let Some(height) = payload.height {
        storage_process
            .find_long_running_task_proof_including_block_number(
                height,
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    } else {
        storage_process
            .find_latest_long_running_task_proof_by_name(
                payload.proof_type.get_chain_name().to_string(),
            )
            .await
            .api_error("GET_CHAIN_PROOF_ERROR")?
    };

    match proof {
        Some(proof) => {
            let prev_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_start - 1,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_end - 1);
            let next_proof_number = storage_process
                .find_long_running_task_proof_including_block_number(
                    proof.block_end,
                    payload.proof_type.get_chain_name().to_string(),
                )
                .await
                .api_error("GET_CHAIN_PROOF_ERROR")?
                .map(|v| v.block_start);

            api_result.set(if proof.proof_state == ProofState::Proven.to_i64() {
                "ready"
            } else if proof.proof_state == ProofState::Failed.to_i64() {
                "failed"
            } else {
                "pending"
            });
            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: proof.block_start,
                    block_end: proof.block_end,
                    proof_type: payload.proof_type.to_string(),
                    state: ProofState::from_i64(proof.proof_state)
                        .unwrap_or(ProofState::New)
                        .to_string(),
                    proving_cycles: proof.cycles,
                    proving_time: proof.proving_time,
                    total_time_to_proof: proof.total_time_to_proof,
                    proof_size: proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: proof.zkm_version,
                    pub_values: proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number,
                    next_proof_number,
                    created_at: proof.created_at,
                    updated_at: proof.updated_at,
                }),
                error: None,
            })
        }

        None => {
            api_result.set("not_found");
            ok_response(ProofDescResponse {
                proof_desc: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn get_operator_proof_task_desc(
    State(api_state): State<Arc<ApiState>>,
    Query(payload): Query<OperatorProofDescRequest>,
) -> ApiResult<ProofDescResponse> {
    let mut api_result = api_state.metrics_state.api_result("operator_desc");
    let instance_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.instance_id, "instance_id"),
    )?;
    let graph_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.graph_id, "graph_id"),
    )?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof) => {
            api_result.set(if operator_proof.proof_state == ProofState::Proven.to_i64() {
                "ready"
            } else if operator_proof.proof_state == ProofState::Failed.to_i64() {
                "failed"
            } else {
                "pending"
            });
            info!("Get Operator Proof:{operator_proof:?}");
            ok_response(ProofDescResponse {
                proof_desc: Some(ProofDesc {
                    block_start: operator_proof.execution_layer_block_number,
                    block_end: operator_proof.execution_layer_block_number + 1,
                    proof_type: "Operator".to_string(),
                    state: ProofState::from_i64(operator_proof.proof_state)
                        .unwrap_or(ProofState::New)
                        .to_string(),
                    proving_cycles: operator_proof.cycles,
                    proving_time: operator_proof.proving_time,
                    total_time_to_proof: operator_proof.total_time_to_proof,
                    proof_size: operator_proof.proof_size as f64 / 1000.0, // use KiB
                    zkm_version: operator_proof.zkm_version,
                    pub_values: operator_proof.public_value_hex.unwrap_or("".to_string()),
                    prev_proof_number: None,
                    next_proof_number: None,
                    created_at: operator_proof.created_at,
                    updated_at: operator_proof.updated_at,
                }),
                error: None,
            })
        }
        None => {
            api_result.set("not_found");
            ok_response(ProofDescResponse {
                proof_desc: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn post_operator_proof_task(
    State(api_state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<OperatorProofRequest>,
) -> ApiResult<OperatorProofResponse> {
    let mut api_result = api_state.metrics_state.api_result("operator_submit");
    let signer = record_auth_result(
        &mut api_result,
        api_state.auth.authenticate(
            &headers,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF,
            &payload,
            None,
        ),
    )?;
    let instance_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.instance_id, "instance_id"),
    )?;
    let graph_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.graph_id, "graph_id"),
    )?;
    let graph_data = record_auth_result(
        &mut api_result,
        api_state
            .auth
            .authorize_operator(
                &signer,
                payload.gateway_address.as_deref(),
                &instance_id,
                &graph_id,
            )
            .await,
    )?;
    let operator_proof = find_operator_task(&api_state.local_db, instance_id, graph_id)
        .await
        .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
    match operator_proof {
        Some(operator_proof)
            if operator_proof.proof_state == ProofState::Proven.to_i64()
                && operator_proof.path_to_proof.is_some() =>
        {
            api_result.set("ready");
            ok_response(OperatorProofResponse {
                proof_data: Some(ProofData::load_proof_data(
                    &operator_proof.path_to_proof.unwrap(),
                    ProofType::Operator,
                )),
                error: None,
            })
        }
        Some(operator_proof) => {
            api_result.set(if operator_proof.proof_state == ProofState::Failed.to_i64() {
                "failed"
            } else {
                "pending"
            });
            ok_response(OperatorProofResponse {
                proof_data: None,
                error: Some(format!(
                    "The proof is not ready, state {}, path:{:?}",
                    operator_proof.proof_state, operator_proof.path_to_proof
                )),
            })
        }

        None => {
            record_invalid(
                &mut api_result,
                InputValidator::validate_operator_task(&payload, &graph_data),
            )?;
            add_operator_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.operator_committed_blockhash,
                payload.execution_layer_block_number,
                payload.watchtower_challenge_txids.clone(),
                payload.included_watchtowers.clone(),
                payload.watchtower_challenge_init_txid.clone(),
                payload.watchtower_challenge_pubkeys.clone(),
            )
            .await
            .api_error("POST_OPERATOR_PROOF_TASK_ERROR")?;
            api_result.set("created");
            ok_response(OperatorProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn update_operator_proof_task_timeout(
    State(api_state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<OperatorProofTimeoutUpdateRequest>,
) -> ApiResult<OperatorProofTimeoutUpdateResponse> {
    let mut api_result = api_state.metrics_state.api_result("operator_timeout");
    let signer = record_auth_result(
        &mut api_result,
        api_state.auth.authenticate(
            &headers,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &payload,
            None,
        ),
    )?;
    let instance_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.instance_id, "instance_id"),
    )?;
    let graph_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.graph_id, "graph_id"),
    )?;
    record_auth_result(
        &mut api_result,
        api_state
            .auth
            .authorize_operator(
                &signer,
                payload.gateway_address.as_deref(),
                &instance_id,
                &graph_id,
            )
            .await,
    )?;
    match update_operator_task_state(
        &api_state.local_db,
        instance_id,
        graph_id,
        ProofState::New,
        ProofState::Failed,
    )
    .await
    {
        Ok(rows_affected) => {
            api_result.set(if rows_affected == 0 { "not_found" } else { "updated" });
            ok_response(OperatorProofTimeoutUpdateResponse {
                instance_id: instance_id.to_string(),
                graph_id: graph_id.to_string(),
                data: Some(format!("{rows_affected} rows affected")),
                error: None,
            })
        }
        Err(error) => {
            api_result.set("failed");
            ok_response(OperatorProofTimeoutUpdateResponse {
                instance_id: instance_id.to_string(),
                graph_id: graph_id.to_string(),
                data: None,
                error: Some(format!("update error: {error}")),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn post_watchtower_proof_task(
    State(api_state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<WatchtowerProofRequest>,
) -> ApiResult<WatchtowerProofResponse> {
    let mut api_result = api_state.metrics_state.api_result("watchtower_submit");
    let signer = record_auth_result(
        &mut api_result,
        api_state.auth.authenticate(
            &headers,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF,
            &payload,
            Some(&payload.public_key),
        ),
    )?;
    let instance_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.instance_id, "instance_id"),
    )?;
    let graph_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.graph_id, "graph_id"),
    )?;
    record_auth_result(
        &mut api_result,
        api_state.auth.authorize_watchtower(&signer, payload.gateway_address.as_deref()).await,
    )?;
    let challenge_init_txid = record_invalid(
        &mut api_result,
        InputValidator::validate_btc_txid(&payload.challenge_init_txid, "challenge_init_txid"),
    )?
    .to_string();

    let watchtower_proof =
        find_watchtower_task(&api_state.local_db, instance_id, graph_id, &payload.public_key)
            .await
            .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;

    match watchtower_proof {
        Some(watchtower_proof)
            if watchtower_proof.proof_state == ProofState::Proven.to_i64()
                && watchtower_proof.path_to_proof.is_some() =>
        {
            api_result.set("ready");
            ok_response(WatchtowerProofResponse {
                proof_data: Some(ProofData::load_proof_data(
                    &watchtower_proof.path_to_proof.unwrap(),
                    ProofType::Watchtower,
                )),
                error: None,
            })
        }
        Some(watchtower_proof) => {
            api_result.set(if watchtower_proof.proof_state == ProofState::Failed.to_i64() {
                "failed"
            } else {
                "pending"
            });
            ok_response(WatchtowerProofResponse {
                proof_data: None,
                error: Some(format!(
                    "No proof is not ready, state {}, path:{:?}",
                    watchtower_proof.proof_state, watchtower_proof.path_to_proof
                )),
            })
        }

        None => {
            add_watchtower_task(
                &api_state.local_db,
                instance_id,
                graph_id,
                payload.public_key,
                challenge_init_txid,
                payload.execution_layer_block_number,
            )
            .await
            .api_error("POST_WATCHTOWER_PROOF_TASK_ERROR")?;
            api_result.set("created");
            ok_response(WatchtowerProofResponse {
                proof_data: None,
                error: Some("No proof found".to_string()),
            })
        }
    }
}

#[axum::debug_handler]
pub(super) async fn update_watchtower_proof_task_timeout(
    State(api_state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<WatchtowerProofTimeoutUpdateRequest>,
) -> ApiResult<WatchtowerProofTimeoutUpdateResponse> {
    let mut api_result = api_state.metrics_state.api_result("watchtower_timeout");
    let signer = record_auth_result(
        &mut api_result,
        api_state.auth.authenticate(
            &headers,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &payload,
            Some(&payload.public_key),
        ),
    )?;
    let instance_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.instance_id, "instance_id"),
    )?;
    let graph_id = record_invalid(
        &mut api_result,
        InputValidator::validate_uuid(&payload.graph_id, "graph_id"),
    )?;
    record_auth_result(
        &mut api_result,
        api_state.auth.authorize_watchtower(&signer, payload.gateway_address.as_deref()).await,
    )?;
    match update_watchtower_task_state(
        &api_state.local_db,
        instance_id,
        graph_id,
        &payload.public_key,
        ProofState::New,
        ProofState::Failed,
    )
    .await
    {
        Ok(rows_affected) => {
            api_result.set(if rows_affected == 0 { "not_found" } else { "updated" });
            ok_response(WatchtowerProofTimeoutUpdateResponse {
                instance_id: instance_id.to_string(),
                graph_id: graph_id.to_string(),
                public_key: payload.public_key.clone(),
                data: Some(format!("{rows_affected} rows affected")),
                error: None,
            })
        }
        Err(error) => {
            api_result.set("failed");
            ok_response(WatchtowerProofTimeoutUpdateResponse {
                instance_id: instance_id.to_string(),
                graph_id: graph_id.to_string(),
                public_key: payload.public_key.clone(),
                data: None,
                error: Some(format!("update error: {error}")),
            })
        }
    }
}
