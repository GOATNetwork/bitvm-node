mod auth;
pub(crate) mod metrics_service;
mod proof_handler;
mod response;
pub(crate) mod routes;
mod validation;

use crate::api::auth::RequestAuthorizer;
use crate::api::metrics_service::{ApiMetricsState, metrics_handler, metrics_middleware};
use crate::api::proof_handler::{
    get_chain_proof_task_desc, get_operator_proof_task_desc, post_operator_proof_task,
    post_watchtower_proof_task, update_operator_proof_task_timeout,
    update_watchtower_proof_task_timeout,
};
use anyhow::Context;
use axum::http::{Method, StatusCode};
use axum::routing::{get, post};
use axum::{Router, middleware};
use std::sync::Arc;
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};

pub(crate) use auth::{AuthorizationChain, AuthorizationChains};

pub(crate) struct ApiState {
    pub local_db: LocalDB,
    pub metrics_state: ApiMetricsState,
    auth: RequestAuthorizer,
}

impl ApiState {
    /// Creates shared API state from the database, metrics, and live authorization chain.
    pub(crate) fn new(
        local_db: LocalDB,
        metrics_state: ApiMetricsState,
        authorization_chains: AuthorizationChains,
    ) -> Arc<ApiState> {
        Arc::new(ApiState {
            local_db,
            metrics_state,
            auth: RequestAuthorizer::new(authorization_chains),
        })
    }
}

/// Serves the business RPC routes at `addr` with shared state until cancellation.
pub(crate) async fn serve_with_app_state(
    addr: String,
    api_state: Arc<ApiState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let instrumented_routes = Router::new()
        .route(routes::ROOT, get(root))
        .route(routes::v1::PROOFS_CHAIN_PROOFS_DESC, get(get_chain_proof_task_desc))
        .route(routes::v1::PROOFS_WATCHTOWER_PROOF, post(post_watchtower_proof_task))
        .route(
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            post(update_watchtower_proof_task_timeout),
        )
        .route(routes::v1::PROOFS_OPERATOR_PROOF, post(post_operator_proof_task))
        .route(routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT, post(update_operator_proof_task_timeout))
        .route(routes::v1::PROOFS_OPERATOR_PROOF_DESC, get(get_operator_proof_task_desc))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(api_state.clone(), metrics_middleware));
    let server = instrumented_routes
        .layer(CorsLayer::new().allow_headers(Any).allow_origin(Any).allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .with_state(api_state);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("RPC listening on {}", listener.local_addr()?);
    tokio::select! {
        result = axum::serve(listener, server) => {
            match result {
                Ok(_) => Ok("RPC server finished normally".to_string()),
                Err(e) => {
                    tracing::error!("RPC server error: {}", e);
                    Err(anyhow::anyhow!("RPC server error: {e}"))
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            tracing::info!("RPC service received shutdown signal");
            Ok("rpc_shutdown".to_string())
        }
    }
}

/// Binds the dedicated Prometheus metrics listener before background tasks start.
pub(crate) async fn bind_metrics_listener(addr: &str) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener to {addr}"))
}

/// Serves only `/metrics` from the pre-bound listener with the shared API state.
pub(crate) async fn serve_metrics(
    listener: TcpListener,
    api_state: Arc<ApiState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let router = Router::new().route(routes::METRICS, get(metrics_handler)).with_state(api_state);
    let listening_addr =
        listener.local_addr().context("failed to determine metrics listener address")?;
    tracing::info!(
        address = %listening_addr,
        path = routes::METRICS,
        "Metrics listener started"
    );

    tokio::select! {
        result = axum::serve(listener, router) => {
            match result {
                Ok(_) => Ok("Metrics server finished normally".to_string()),
                Err(e) => {
                    tracing::error!("Metrics server error: {}", e);
                    Err(anyhow::anyhow!("Metrics server error: {e}"))
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            tracing::info!("Metrics service received shutdown signal");
            Ok("metrics_shutdown".to_string())
        }
    }
}
async fn root() -> &'static str {
    "Hello, World!"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::{
        AuthorizationChain, AuthorizationChains, test_support::TestAuthorizationChain,
    };
    use alloy_primitives::Address;
    use proof_builder::api_auth::{
        ProofBuilderAuthHeaders, ProofBuilderAuthRole, sign_proof_builder_request,
    };
    use proof_builder::{
        OperatorProofRequest, OperatorProofTimeoutUpdateRequest, WatchtowerProofRequest,
        WatchtowerProofTimeoutUpdateRequest,
    };
    use secp256k1::{Keypair, SECP256K1};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    fn available_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn get(addr: &str, path: &str) -> anyhow::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    async fn post(
        addr: &str,
        path: &str,
        body: &str,
        auth: Option<&ProofBuilderAuthHeaders>,
    ) -> anyhow::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let auth_headers = auth
            .map(|auth| {
                auth.to_header_pairs()
                    .into_iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>()
            })
            .unwrap_or_default();
        stream
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_headers}Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
    }

    fn gateway(seed: u8) -> Address {
        Address::from_slice(&[seed; 20])
    }

    fn authorization_chains(
        gateway: Address,
        chain: Arc<TestAuthorizationChain>,
    ) -> AuthorizationChains {
        let chain: Arc<dyn AuthorizationChain> = chain;
        std::collections::HashMap::from([(gateway, chain)])
    }

    async fn spawn_metrics_listener(
        api_state: Arc<ApiState>,
        cancellation_token: CancellationToken,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<String>>)> {
        let listener = bind_metrics_listener("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let handle = tokio::spawn(serve_metrics(listener, api_state, cancellation_token));
        Ok((addr, handle))
    }

    #[tokio::test]
    async fn metrics_are_served_only_by_the_dedicated_listener() -> anyhow::Result<()> {
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let api_state = ApiState::new(
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            authorization_chains(gateway(1), Arc::new(TestAuthorizationChain::default())),
        );
        let server = tokio::spawn(serve_with_app_state(
            addr.clone(),
            api_state.clone(),
            cancellation_token.clone(),
        ));
        let (metrics_addr, metrics_server) =
            spawn_metrics_listener(api_state, cancellation_token.clone()).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(get(&addr, "/").await?.starts_with("HTTP/1.1 200"));
        assert!(get(&addr, "/missing").await?.starts_with("HTTP/1.1 404"));
        assert!(get(&addr, "/metrics").await?.starts_with("HTTP/1.1 404"));
        assert!(get(&metrics_addr, "/").await?.starts_with("HTTP/1.1 404"));
        assert!(
            get(&metrics_addr, routes::v1::PROOFS_CHAIN_PROOFS_DESC)
                .await?
                .starts_with("HTTP/1.1 404")
        );
        let first_scrape = get(&metrics_addr, "/metrics").await?;
        let second_scrape = get(&metrics_addr, "/metrics").await?;

        assert!(first_scrape.starts_with("HTTP/1.1 200"));
        assert!(
            first_scrape
                .to_ascii_lowercase()
                .contains("content-type: application/openmetrics-text;charset=utf-8;version=1.0.0")
        );
        assert!(
            first_scrape
                .contains("http_requests_total{method=\"GET\",route=\"/\",status=\"200\"} 1")
        );
        assert!(
            first_scrape.contains(
                "http_requests_total{method=\"GET\",route=\"unmatched\",status=\"404\"} 2"
            )
        );
        assert!(first_scrape.contains("http_requests_in_flight 0"));
        assert!(!first_scrape.contains("route=\"/metrics\""));
        assert!(!second_scrape.contains("route=\"/metrics\""));

        cancellation_token.cancel();
        server.await??;
        assert_eq!(metrics_server.await??, "metrics_shutdown");
        Ok(())
    }

    #[tokio::test]
    async fn metrics_listener_reports_bind_conflicts() -> anyhow::Result<()> {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = occupied.local_addr()?.to_string();
        let error = bind_metrics_listener(&addr).await.unwrap_err();
        assert!(
            error.to_string().contains(&format!("failed to bind metrics listener to {addr}")),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn operator_and_watchtower_task_routes_enforce_role_authentication() -> anyhow::Result<()>
    {
        let operator = keypair(7);
        let watchtower = keypair(9);
        let other_watchtower = keypair(11);
        let instance_id = "00112233-4455-6677-8899-aabbccddeeff".to_string();
        let graph_id = "11112233-4455-6677-8899-aabbccddeeff".to_string();
        let authorization_chain = Arc::new(TestAuthorizationChain::default());
        authorization_chain.set_graph(
            Uuid::parse_str(&instance_id)?,
            Uuid::parse_str(&graph_id)?,
            operator.x_only_public_key().0,
        );
        authorization_chain.add_watchtower(watchtower.x_only_public_key().0);
        let gateway_address = gateway(1);
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let api_state = ApiState::new(
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            authorization_chains(gateway_address, authorization_chain),
        );
        let server =
            tokio::spawn(serve_with_app_state(addr.clone(), api_state, cancellation_token.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let operator_submit = OperatorProofRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
            gateway_address: Some(gateway_address.to_string()),
            operator_committed_blockhash: "11".repeat(32),
            execution_layer_block_number: 1,
            watchtower_challenge_txids: vec![],
            included_watchtowers: vec![],
            watchtower_challenge_init_txid: "22".repeat(32),
            watchtower_challenge_pubkeys: vec![],
        };
        let operator_submit_body = serde_json::to_string(&operator_submit)?;
        assert!(
            post(&addr, routes::v1::PROOFS_OPERATOR_PROOF, &operator_submit_body, None,)
                .await?
                .starts_with("HTTP/1.1 401")
        );
        let operator_submit_auth = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF,
            &operator_submit,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_OPERATOR_PROOF,
                &operator_submit_body,
                Some(&operator_submit_auth),
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );

        let operator_timeout = OperatorProofTimeoutUpdateRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
            gateway_address: None,
        };
        let operator_timeout_body = serde_json::to_string(&operator_timeout)?;
        let wrong_role_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
                &operator_timeout_body,
                Some(&wrong_role_auth),
            )
            .await?
            .starts_with("HTTP/1.1 403")
        );
        let operator_timeout_auth = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout,
        )?;
        let operator_timeout_response = post(
            &addr,
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &operator_timeout_body,
            Some(&operator_timeout_auth),
        )
        .await?;
        assert!(operator_timeout_response.starts_with("HTTP/1.1 200"));
        assert!(operator_timeout_response.contains("1 rows affected"));

        let watchtower_submit = WatchtowerProofRequest {
            instance_id: instance_id.clone(),
            graph_id: graph_id.clone(),
            gateway_address: Some(gateway_address.to_string()),
            public_key: watchtower.public_key().to_string(),
            challenge_init_txid: "33".repeat(32),
            execution_layer_block_number: 1,
        };
        let watchtower_submit_body = serde_json::to_string(&watchtower_submit)?;
        let watchtower_submit_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF,
            &watchtower_submit,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_WATCHTOWER_PROOF,
                &watchtower_submit_body,
                Some(&watchtower_submit_auth),
            )
            .await?
            .starts_with("HTTP/1.1 200")
        );

        let watchtower_timeout = WatchtowerProofTimeoutUpdateRequest {
            instance_id,
            graph_id,
            gateway_address: Some(gateway_address.to_string()),
            public_key: watchtower.public_key().to_string(),
        };
        let watchtower_timeout_body = serde_json::to_string(&watchtower_timeout)?;
        let watchtower_timeout_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &watchtower_timeout,
        )?;
        let watchtower_timeout_response = post(
            &addr,
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &watchtower_timeout_body,
            Some(&watchtower_timeout_auth),
        )
        .await?;
        assert!(watchtower_timeout_response.starts_with("HTTP/1.1 200"));
        assert!(watchtower_timeout_response.contains("1 rows affected"));

        let mismatched_timeout = WatchtowerProofTimeoutUpdateRequest {
            public_key: other_watchtower.public_key().to_string(),
            ..watchtower_timeout
        };
        let mismatched_timeout_body = serde_json::to_string(&mismatched_timeout)?;
        let mismatched_timeout_auth = sign_proof_builder_request(
            &watchtower,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
            &mismatched_timeout,
        )?;
        assert!(
            post(
                &addr,
                routes::v1::PROOFS_WATCHTOWER_PROOF_TIMEOUT,
                &mismatched_timeout_body,
                Some(&mismatched_timeout_auth),
            )
            .await?
            .starts_with("HTTP/1.1 403")
        );

        cancellation_token.cancel();
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_routes_reject_missing_invalid_unknown_and_wrong_deployment()
    -> anyhow::Result<()> {
        let operator = keypair(7);
        let instance_id = "00112233-4455-6677-8899-aabbccddeeff".to_string();
        let graph_id = "11112233-4455-6677-8899-aabbccddeeff".to_string();
        let gateway_a = gateway(1);
        let gateway_b = gateway(2);
        let gateway_unknown = gateway(3);
        let chain_a = Arc::new(TestAuthorizationChain::default());
        chain_a.set_graph(
            Uuid::parse_str(&instance_id)?,
            Uuid::parse_str(&graph_id)?,
            operator.x_only_public_key().0,
        );
        let chain_a: Arc<dyn AuthorizationChain> = chain_a;
        let chain_b: Arc<dyn AuthorizationChain> = Arc::new(TestAuthorizationChain::default());
        let authorization_chains =
            std::collections::HashMap::from([(gateway_a, chain_a), (gateway_b, chain_b)]);
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let api_state = ApiState::new(
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            authorization_chains,
        );
        let server = tokio::spawn(serve_with_app_state(
            addr.clone(),
            api_state.clone(),
            cancellation_token.clone(),
        ));
        let (metrics_addr, metrics_server) =
            spawn_metrics_listener(api_state, cancellation_token.clone()).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        for (gateway_address, expected_status) in [
            (None, "400"),
            (Some("invalid".to_string()), "400"),
            (Some(gateway_unknown.to_string()), "403"),
            (Some(gateway_b.to_string()), "403"),
            (Some(gateway_a.to_string()), "200"),
        ] {
            let request = OperatorProofTimeoutUpdateRequest {
                instance_id: instance_id.clone(),
                graph_id: graph_id.clone(),
                gateway_address,
            };
            let body = serde_json::to_string(&request)?;
            let auth = sign_proof_builder_request(
                &operator,
                ProofBuilderAuthRole::Operator,
                "POST",
                routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
                &request,
            )?;
            let response =
                post(&addr, routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT, &body, Some(&auth)).await?;
            assert!(response.starts_with(&format!("HTTP/1.1 {expected_status}")));
        }

        let metrics = get(&metrics_addr, "/metrics").await?;
        assert!(metrics.contains("operation=\"operator_timeout\",result=\"invalid\""));
        assert!(metrics.contains("operation=\"operator_timeout\",result=\"unauthorized\""));

        cancellation_token.cancel();
        server.await??;
        metrics_server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn authorization_query_failure_returns_503_and_records_unavailable() -> anyhow::Result<()>
    {
        let operator = keypair(7);
        let authorization_chain = Arc::new(TestAuthorizationChain::default());
        authorization_chain.set_fail_queries(true);
        let gateway_address = gateway(1);
        let addr = available_addr();
        let cancellation_token = CancellationToken::new();
        let api_state = ApiState::new(
            store::create_local_db("sqlite::memory:").await,
            ApiMetricsState::new(),
            authorization_chains(gateway_address, authorization_chain),
        );
        let server = tokio::spawn(serve_with_app_state(
            addr.clone(),
            api_state.clone(),
            cancellation_token.clone(),
        ));
        let (metrics_addr, metrics_server) =
            spawn_metrics_listener(api_state, cancellation_token.clone()).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let request = OperatorProofTimeoutUpdateRequest {
            instance_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            graph_id: "11112233-4455-6677-8899-aabbccddeeff".to_string(),
            gateway_address: Some(gateway_address.to_string()),
        };
        let body = serde_json::to_string(&request)?;
        let auth = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT,
            &request,
        )?;
        let response =
            post(&addr, routes::v1::PROOFS_OPERATOR_PROOF_TIMEOUT, &body, Some(&auth)).await?;
        assert!(response.starts_with("HTTP/1.1 503"));

        let metrics = get(&metrics_addr, "/metrics").await?;
        assert!(metrics.contains("operation=\"operator_timeout\",result=\"unavailable\""));

        cancellation_token.cancel();
        server.await??;
        metrics_server.await??;
        Ok(())
    }
}
