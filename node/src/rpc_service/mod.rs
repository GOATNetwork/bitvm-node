pub mod auth;
mod bitvm;
mod cors_config;
pub mod handler;
mod node;
mod response;
pub mod routes;
mod swap;
pub(super) mod utils;
pub mod validation;

use crate::env::{get_btc_url_from_env, get_goat_network, get_network, goat_config_from_env};
use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::auth::require_request_auth;
use crate::rpc_service::cors_config::CorsConfig;
use crate::rpc_service::handler::{
    get_chain_proof_desc, get_graph, get_graph_neighbor_ids, get_graph_tx, get_graph_txn,
    get_graphs, get_instance, get_instances, get_instances_overview, get_node, get_nodes,
    get_nodes_overview, get_operator_proof_desc, get_ready_to_kickoff_graph, get_swap, get_swaps,
    get_unsigned_pegin_txn, instance_settings, pegout, send_challenge,
};
#[cfg(feature = "rpc-debug-endpoints")]
use crate::rpc_service::handler::{
    get_debug_message_details, get_debug_status, get_graph_debug_messages,
    get_instance_debug_messages, send_verifier_challenge,
};
use anyhow::Context;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use bitvm_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::http_client::async_client::HttpAsyncClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Create secure CORS layer
pub fn create_secure_cors_layer() -> CorsLayer {
    let cors_config = CorsConfig::from_env();

    // Validate configuration security
    let warnings = cors_config.validate_security();
    for warning in warnings {
        tracing::warn!("CORS security warning: {}", warning);
    }

    cors_config.create_cors_layer()
}

pub struct AppState {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub goat_client: GOATClient,
    pub http_client: HttpAsyncClient,
    pub metrics_state: MetricsState,
    pub actor: Actor,
    pub peer_id: String,
    rpc_auth_nonces: Mutex<HashMap<String, i64>>,
}

impl AppState {
    pub async fn create_arc_app_state(
        local_db: LocalDB,
        actor: Actor,
        peer_id: String,
        metrics_state: MetricsState,
    ) -> anyhow::Result<Arc<AppState>> {
        let btc_client = BTCClient::new(get_network(), get_btc_url_from_env().as_deref());
        let goat_client = GOATClient::new(goat_config_from_env().await, get_goat_network());
        let http_client = HttpAsyncClient::new(None);
        Ok(Arc::new(AppState {
            local_db,
            btc_client,
            goat_client,
            metrics_state,
            actor,
            peer_id,
            http_client,
            rpc_auth_nonces: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn create_arc_mock_app_state(
        local_db: LocalDB,
        actor: Actor,
        peer_id: String,
        metrics_state: MetricsState,
    ) -> anyhow::Result<Arc<AppState>> {
        let (btc_client, btc_mock_adaptor) = BTCClient::new_mock_client();
        btc_mock_adaptor.set_height(900_000);

        let (goat_client, goat_mock_adaptor) = GOATClient::new_mock_client();
        goat_mock_adaptor.set_latest_block_number(1_000_000);
        goat_mock_adaptor.set_finalized_block_number(999_990);

        Ok(Arc::new(AppState {
            local_db,
            btc_client,
            goat_client,
            metrics_state,
            actor,
            peer_id,
            http_client: HttpAsyncClient::new(None),
            rpc_auth_nonces: Mutex::new(HashMap::new()),
        }))
    }
}

/// Root path handler
///
/// Returns a simple welcome message for health checks and basic connection testing.
///
/// # Returns
///
/// - `200 OK`: Returns welcome message
///
/// # Example
///
/// ```http
/// GET /
/// ```
///
/// Response example: "Hello World"
///
async fn root() -> &'static str {
    "Hello, World!"
}

pub(crate) fn build_business_router(app_state: Arc<AppState>) -> Router {
    let public_routes = Router::new()
        .route(routes::ROOT, get(root))
        .route(routes::v1::NODES_BASE, get(get_nodes))
        .route(routes::v1::NODES_BY_ID, get(get_node))
        .route(routes::v1::NODES_OVERVIEW, get(get_nodes_overview))
        .route(routes::v1::INSTANCES_SETTINGS, get(instance_settings))
        .route(routes::v1::INSTANCES_BASE, get(get_instances))
        .route(routes::v1::INSTANCES_BY_ID, get(get_instance))
        .route(routes::v1::INSTANCES_OVERVIEW, get(get_instances_overview))
        .route(routes::v1::INSTANCES_UNSIGNED_PEGIN_TXN, get(get_unsigned_pegin_txn))
        .route(routes::v1::SWAPS_BASE, get(get_swaps))
        .route(routes::v1::SWAPS_BY_ESCROW_HASH, get(get_swap))
        .route(routes::v1::GRAPHS_BY_ID, get(get_graph))
        .route(routes::v1::GRAPHS_BASE, get(get_graphs))
        .route(routes::v1::GRAPHS_READY_TO_KICKOFF, get(get_ready_to_kickoff_graph))
        .route(routes::v1::GRAPHS_TXN_BY_ID, get(get_graph_txn))
        .route(routes::v1::GRAPHS_TX_BY_ID, get(get_graph_tx))
        .route(routes::v1::GRAPHS_NEIGHBOR_IDS, get(get_graph_neighbor_ids))
        .route(routes::v1::PROOFS_CHAIN_PROOFS_DESC, get(get_chain_proof_desc))
        .route(routes::v1::PROOFS_OPERATOR_PROOF_DESC, get(get_operator_proof_desc));

    #[cfg(feature = "rpc-debug-endpoints")]
    let public_routes = public_routes
        .route(routes::v1::DEBUG_STATUS, get(get_debug_status))
        .route(routes::v1::DEBUG_GRAPH_MESSAGES, get(get_graph_debug_messages))
        .route(routes::v1::DEBUG_INSTANCE_MESSAGES, get(get_instance_debug_messages))
        .route(routes::v1::DEBUG_MESSAGE_DETAILS, get(get_debug_message_details));

    let signed_routes = Router::new()
        .route(routes::v1::GRAPHS_SEND_CHALLENGE, post(send_challenge))
        .route(routes::v1::PEGOUT, post(pegout));

    #[cfg(feature = "rpc-debug-endpoints")]
    let signed_routes = signed_routes
        .route(routes::v1::GRAPHS_SEND_VERIFIER_CHALLENGE, post(send_verifier_challenge));

    let signed_routes = signed_routes
        .route_layer(middleware::from_fn_with_state(app_state.clone(), require_request_auth));

    public_routes.merge(signed_routes).layer(create_secure_cors_layer()).with_state(app_state)
}

pub async fn serve_with_app_state(
    addr: String,
    app_state: Arc<AppState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let node_span = tracing::Span::current();
    let server = build_business_router(app_state.clone())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(move |request: &Request<Body>| {
                    tracing::info_span!(
                        parent: &node_span,
                        "http_request",
                        method = %request.method(),
                        path = request.uri().path(),
                        version = ?request.version(),
                    )
                })
                .on_request(|request: &Request<Body>, _span: &tracing::Span| {
                    tracing::info!(
                        event = "http_request",
                        method = %request.method(),
                        path = request.uri().path(),
                        content_type = ?request.headers().get("content-type"),
                        "RPC request received"
                    );
                })
                .on_response(
                    |response: &Response<Body>, latency: Duration, _span: &tracing::Span| {
                        tracing::info!(
                            event = "http_response",
                            status = %response.status(),
                            elapsed_ms = latency.as_millis() as u64,
                            "RPC response sent"
                        );
                    },
                )
                .on_failure(
                    |error: ServerErrorsFailureClass, latency: Duration, _span: &tracing::Span| {
                        tracing::error!(
                            event = "http_request_failure",
                            error_class = ?error,
                            elapsed_ms = latency.as_millis() as u64,
                            "RPC request failed"
                        );
                    },
                ),
        )
        .layer(middleware::from_fn_with_state(app_state, metrics_middleware));

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind RPC listener to {addr}"))?;
    let listening_addr =
        listener.local_addr().context("failed to determine RPC listener address")?;
    tracing::info!(
        event = "rpc_listening",
        address = %listening_addr,
        "RPC listener started"
    );

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

pub async fn serve(
    addr: String,
    local_db: LocalDB,
    actor: Actor,
    peer_id: String,
    metrics_state: MetricsState,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let app_state = AppState::create_arc_app_state(local_db, actor, peer_id, metrics_state).await?;
    serve_with_app_state(addr, app_state, cancellation_token).await
}

/// Validates the path the dedicated metrics listener will expose.
///
/// Rejects anything `axum` cannot register as a literal route, so a bad
/// `--metrics-path` fails at startup instead of panicking inside the router.
pub fn validate_metrics_path(path: &str) -> anyhow::Result<()> {
    if !path.starts_with('/') {
        anyhow::bail!("metrics path must start with '/', got {path:?}");
    }
    if path.contains(['?', '#', '{', '}', '*', ':']) {
        anyhow::bail!(
            "metrics path must not contain query, fragment or route parameter characters, got {path:?}"
        );
    }
    if path.chars().any(char::is_whitespace) {
        anyhow::bail!("metrics path must not contain whitespace, got {path:?}");
    }
    Ok(())
}

/// Binds the dedicated Prometheus metrics listener.
///
/// Binding happens before the node spawns its background tasks so a misconfigured
/// or already used metrics port aborts startup with an explicit error.
pub async fn bind_metrics_listener(addr: &str) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener to {addr}"))
}

/// Serves the metrics-only router on an already bound listener.
///
/// The router exposes `metrics_path` and nothing else: no business or debug
/// routes, no CORS and no request metrics middleware, so scrapes never show up
/// in the HTTP request metrics they read.
pub async fn serve_metrics(
    listener: TcpListener,
    metrics_path: String,
    app_state: Arc<AppState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    validate_metrics_path(&metrics_path)?;
    let router =
        Router::new().route(metrics_path.as_str(), get(metrics_handler)).with_state(app_state);

    let listening_addr =
        listener.local_addr().context("failed to determine metrics listener address")?;
    tracing::info!(
        event = "metrics_listening",
        address = %listening_addr,
        path = %metrics_path,
        "metrics listener started"
    );

    tokio::select! {
        result = axum::serve(listener, router) => {
            match result {
                Ok(_) => Ok("metrics server finished normally".to_string()),
                Err(e) => {
                    tracing::error!("metrics server error: {}", e);
                    Err(anyhow::anyhow!("metrics server error: {e}"))
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            tracing::info!("metrics service received shutdown signal");
            Ok("metrics_shutdown".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::env::{
        ENV_BITVM_SECRET, ENV_GOAT_CHAIN_URL, ENV_GOAT_GATEWAY_CONTRACT_ADDRESS,
        ENV_PROOF_SEVER_URL, get_network,
    };
    use crate::metrics_service::MetricsState;
    use crate::rpc_service::auth::{
        AUTH_NONCE_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER, sign_request_auth,
    };
    use crate::rpc_service::bitvm::{
        BRIDGE_IN_AMOUNTS, GraphGetResponse, GraphListResponse, InstanceGetResponse,
        InstanceListResponse, InstanceOverviewResponse, InstanceSettingResponse,
    };
    use crate::rpc_service::node::{NodeListResponse, NodeOverViewResponse};
    use crate::rpc_service::{self, Actor, current_time_secs, routes};
    use crate::utils::{
        generate_local_key, generate_random_bytes, get_rand_btc_address_p2wpkh,
        get_rand_goat_address, temp_sqlite_db_path,
    };
    use alloy::primitives::U256;
    use client::Utxo;
    use http::Method;
    use prometheus_client::registry::Registry;
    use reqwest::Client;
    use secp256k1::{Keypair, SECP256K1, Secp256k1};
    use serde_json::Value;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use store::localdb::{GraphRuntimeUpdate, LocalDB, StorageProcessor};
    use store::{
        Graph, GraphStatus, GraphStatusSource, Instance, InstanceBridgeInStatus, Node,
        create_local_db,
    };
    use tokio::time::sleep;
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info};
    use tracing_subscriber::EnvFilter;
    use uuid::Uuid;

    struct ApiTestItem {
        pub tag: String,
        pub url: String,
        pub json_payload: Option<Value>,
        pub method: Method,
        pub expe_res: bool,
        pub resp_validation: Option<Box<dyn Fn(String) -> bool>>,
    }

    impl ApiTestItem {
        async fn do_test(&self, client: &Client) -> anyhow::Result<()> {
            eprintln!("Start test api: {}", self.tag);
            info!("Start test api: {}", self.tag);
            let mut request_builder = match self.method {
                Method::POST => client.post(self.url.clone()),
                Method::GET => client.get(self.url.clone()),
                Method::PUT => client.put(self.url.clone()),
                Method::DELETE => client.delete(self.url.clone()),
                _ => {
                    anyhow::bail!("wrong method");
                }
            };
            if let Some(json_payload) = self.json_payload.clone() {
                request_builder = request_builder.json(&json_payload);
            }

            let resp = request_builder.send().await?;
            let actual_status = resp.status().is_success();
            if actual_status != self.expe_res {
                let data = resp.text().await?;
                eprintln!(
                    "Test api '{}' failed: expected status {}, got {}, resp: {data}",
                    self.tag, self.expe_res, actual_status
                );
                error!(
                    "Test api '{}' failed: expected status {}, got {}, resp: {data}",
                    self.tag, self.expe_res, actual_status
                );
                anyhow::bail!(
                    "Test failed: expected status {}, got {}",
                    self.expe_res,
                    actual_status
                );
            }

            if let Some(validate_fn) = &self.resp_validation {
                let text = resp.text().await?;
                if !validate_fn(text) {
                    eprintln!("Test api '{}' fail validate_fn", self.tag);
                    error!("Test api '{}' fail validate_fn", self.tag);
                    anyhow::bail!("Test api '{}' fail validate_fn", self.tag);
                }
            }

            Ok(())
        }
    }

    async fn do_batch_tests(
        batch_tag: &str,
        client: &Client,
        items: &[ApiTestItem],
    ) -> anyhow::Result<()> {
        info!("Start batch test:{batch_tag}");
        for item in items {
            item.do_test(client).await?;
        }
        info!("Finish batch test:{batch_tag}");
        Ok(())
    }
    fn init(remote_proof_server: Option<String>) {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
            std::env::set_var(ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
            std::env::set_var(
                ENV_GOAT_GATEWAY_CONTRACT_ADDRESS,
                "0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f",
            );
            if let Some(remote_proof_server) = remote_proof_server {
                std::env::set_var(ENV_PROOF_SEVER_URL, remote_proof_server);
            }
        }
        let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    }

    fn available_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn spawn_metrics_listener(
        app_state: Arc<rpc_service::AppState>,
        metrics_path: &str,
        cancellation_token: CancellationToken,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<String>>)> {
        let listener = rpc_service::bind_metrics_listener("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let metrics_path = metrics_path.to_string();
        let handle = tokio::spawn(rpc_service::serve_metrics(
            listener,
            metrics_path,
            app_state,
            cancellation_token,
        ));
        Ok((addr, handle))
    }

    async fn mock_app_state() -> anyhow::Result<Arc<rpc_service::AppState>> {
        let local_db = create_local_db(&temp_sqlite_db_path()).await;
        let metrics_state = MetricsState::new(Arc::new(Mutex::new(Registry::default())));
        rpc_service::AppState::create_arc_mock_app_state(
            local_db,
            Actor::Verifier,
            generate_local_key().public().to_peer_id().to_string(),
            metrics_state,
        )
        .await
    }

    fn set_test_auth_key() -> Keypair {
        let keypair = Keypair::from_seckey_slice(SECP256K1, &[0x42; 32]).unwrap();
        unsafe {
            std::env::set_var(ENV_BITVM_SECRET, hex::encode(keypair.secret_key().secret_bytes()))
        };
        keypair
    }

    async fn spawn_business_listener(
        cancellation_token: CancellationToken,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let app_state = mock_app_state().await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let server = rpc_service::build_business_router(app_state);
        let handle = tokio::spawn(async move {
            let _ = tokio::select! {
                result = axum::serve(listener, server) => result,
                _ = cancellation_token.cancelled() => Ok(()),
            };
        });
        Ok((addr, handle))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_request_nonce_is_rejected_after_first_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let keypair = set_test_auth_key();
        let cancellation_token = CancellationToken::new();
        let (addr, server) = spawn_business_listener(cancellation_token.clone()).await?;
        let graph_id = Uuid::new_v4();
        let request_target = format!("/v1/graphs/{graph_id}/send-challenge");
        let url = format!("http://{addr}{request_target}");
        let (timestamp, nonce, signature) =
            sign_request_auth(&keypair, &Method::POST, &request_target, &[]);
        let client = Client::new();

        let first = client
            .post(&url)
            .header(AUTH_TIMESTAMP_HEADER, &timestamp)
            .header(AUTH_NONCE_HEADER, &nonce)
            .header(AUTH_SIGNATURE_HEADER, &signature)
            .send()
            .await?;
        assert_eq!(first.status().as_u16(), 500);

        let replay = client
            .post(&url)
            .header(AUTH_TIMESTAMP_HEADER, &timestamp)
            .header(AUTH_NONCE_HEADER, &nonce)
            .header(AUTH_SIGNATURE_HEADER, &signature)
            .send()
            .await?;
        assert_eq!(replay.status().as_u16(), 409);
        let replay_body: Value = replay.json().await?;
        assert_eq!(replay_body["error"], "AUTH_REPLAY");

        cancellation_token.cancel();
        server.await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn debug_routes_follow_rpc_debug_endpoints_feature()
    -> Result<(), Box<dyn std::error::Error>> {
        let cancellation_token = CancellationToken::new();
        let (addr, server) = spawn_business_listener(cancellation_token.clone()).await?;
        let client = Client::new();
        let id = Uuid::new_v4();

        let status = client.get(format!("http://{addr}/v1/debug/status")).send().await?;
        let graph_messages =
            client.get(format!("http://{addr}/v1/debug/graphs/{id}/messages")).send().await?;
        let instance_messages =
            client.get(format!("http://{addr}/v1/debug/instances/{id}/messages")).send().await?;
        let message_details =
            client.get(format!("http://{addr}/v1/debug/messages/missing")).send().await?;
        let verifier_challenge = client
            .post(format!("http://{addr}/v1/graphs/{id}/send-verifier-challenge"))
            .send()
            .await?;

        if cfg!(feature = "rpc-debug-endpoints") {
            assert_eq!(status.status().as_u16(), 200);
            assert_eq!(graph_messages.status().as_u16(), 200);
            assert_eq!(instance_messages.status().as_u16(), 200);
            assert_eq!(message_details.status().as_u16(), 404);
            let message_body: Value = message_details.json().await?;
            assert_eq!(message_body["error"], "DEBUG_MESSAGE_NOT_FOUND");
            assert_eq!(verifier_challenge.status().as_u16(), 401);
        } else {
            assert_eq!(status.status().as_u16(), 404);
            assert_eq!(graph_messages.status().as_u16(), 404);
            assert_eq!(instance_messages.status().as_u16(), 404);
            assert_eq!(message_details.status().as_u16(), 404);
            assert_eq!(verifier_challenge.status().as_u16(), 404);
        }

        cancellation_token.cancel();
        server.await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metrics_are_served_only_by_the_dedicated_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let addr = available_addr();
        let app_state = mock_app_state().await?;
        let cancellation_token = CancellationToken::new();
        let server = tokio::spawn(rpc_service::serve_with_app_state(
            addr.clone(),
            app_state.clone(),
            cancellation_token.clone(),
        ));
        let (metrics_addr, metrics_server) =
            spawn_metrics_listener(app_state, "/metrics", cancellation_token.clone()).await?;
        sleep(Duration::from_millis(100)).await;

        let client = Client::new();
        client.get(format!("http://{addr}/")).send().await?.error_for_status()?;
        let unmatched = client.get(format!("http://{addr}/missing")).send().await?;
        assert_eq!(unmatched.status().as_u16(), 404);

        // The business listener no longer exposes metrics at all.
        let business_metrics = client.get(format!("http://{addr}/metrics")).send().await?;
        assert_eq!(business_metrics.status().as_u16(), 404);

        // The metrics listener exposes nothing but the metrics path.
        for path in ["/", "/v1/nodes", "/v1/debug/status"] {
            let response = client.get(format!("http://{metrics_addr}{path}")).send().await?;
            assert_eq!(
                response.status().as_u16(),
                404,
                "unexpected route on metrics listener: {path}"
            );
        }

        let first = client.get(format!("http://{metrics_addr}/metrics")).send().await?;
        assert_eq!(first.status().as_u16(), 200);
        assert_eq!(
            first.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );
        let first_scrape = first.text().await?;
        let second_scrape =
            client.get(format!("http://{metrics_addr}/metrics")).send().await?.text().await?;

        assert!(
            first_scrape
                .contains("http_requests_total{method=\"GET\",route=\"/\",status=\"200\"} 1")
        );
        // `/missing` and the rejected `/metrics` request on the business listener.
        assert!(
            first_scrape.contains(
                "http_requests_total{method=\"GET\",route=\"unmatched\",status=\"404\"} 2"
            )
        );
        assert!(first_scrape.contains("http_requests_in_flight 0"));
        // Requests served by the metrics listener are not counted at all.
        assert!(!first_scrape.contains("route=\"/metrics\""));
        assert_eq!(first_scrape, second_scrape);

        cancellation_token.cancel();
        server.await??;
        assert_eq!(metrics_server.await??, "metrics_shutdown");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metrics_listener_honors_custom_path() -> Result<(), Box<dyn std::error::Error>> {
        let app_state = mock_app_state().await?;
        let cancellation_token = CancellationToken::new();
        let (metrics_addr, metrics_server) =
            spawn_metrics_listener(app_state, "/internal/metrics", cancellation_token.clone())
                .await?;
        sleep(Duration::from_millis(100)).await;

        let client = Client::new();
        let response = client.get(format!("http://{metrics_addr}/internal/metrics")).send().await?;
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.text().await?.contains("http_requests_in_flight"));
        let default_path = client.get(format!("http://{metrics_addr}/metrics")).send().await?;
        assert_eq!(default_path.status().as_u16(), 404);

        cancellation_token.cancel();
        metrics_server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn metrics_listener_reports_bind_conflicts() -> Result<(), Box<dyn std::error::Error>> {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = occupied.local_addr()?.to_string();
        let error = rpc_service::bind_metrics_listener(&addr).await.unwrap_err();
        assert!(
            error.to_string().contains(&format!("failed to bind metrics listener to {addr}")),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn metrics_path_validation_rejects_unusable_paths() {
        for path in ["/metrics", "/", "/internal/metrics"] {
            assert!(
                rpc_service::validate_metrics_path(path).is_ok(),
                "rejected valid path: {path}"
            );
        }
        for path in ["metrics", "", "/metrics?scrape=1", "/metrics#frag", "/{id}", "/met rics"] {
            assert!(
                rpc_service::validate_metrics_path(path).is_err(),
                "accepted invalid path: {path}"
            );
        }
    }

    async fn init_nodes_data(local_db: &LocalDB, nodes: &[Node]) -> anyhow::Result<()> {
        let mut tx = local_db.start_transaction().await?;
        for node in nodes {
            tx.upsert_node(node).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn seed_graph_runtime(
        tx: &mut StorageProcessor<'_>,
        graph: &Graph,
    ) -> anyhow::Result<()> {
        let target_status = GraphStatus::from_str(&graph.status)?;
        let sub_status = graph.sub_status.clone();
        let challenge_txid = graph.challenge_txid.clone();
        let init_withdraw_tx_hash = graph.init_withdraw_tx_hash.clone();
        let bridge_out_start_at = graph.bridge_out_start_at;
        let proceed_withdraw_height = graph.proceed_withdraw_height;

        let mut definition = graph.clone();
        definition.status = GraphStatus::OperatorPresigned.to_string();
        definition.sub_status.clear();
        definition.challenge_txid = None;
        definition.init_withdraw_tx_hash = None;
        definition.bridge_out_start_at = 0;
        definition.proceed_withdraw_height = 0;
        tx.upsert_graph_definition(&definition).await?;

        if target_status != GraphStatus::OperatorPresigned {
            tx.transition_graph_status(
                graph.instance_id,
                graph.graph_id,
                target_status,
                GraphStatusSource::ChainReconcile,
                (!sub_status.is_empty()).then_some(sub_status),
            )
            .await?;
        }

        let mut runtime = GraphRuntimeUpdate::new(graph.instance_id, graph.graph_id);
        if let Some(challenge_txid) = challenge_txid {
            runtime = runtime.with_challenge_txid(challenge_txid);
        }
        if let Some(init_withdraw_tx_hash) = init_withdraw_tx_hash {
            runtime = runtime.with_init_withdraw_tx_hash(init_withdraw_tx_hash);
        }
        if bridge_out_start_at != 0 {
            runtime = runtime.with_bridge_out_start_at(bridge_out_start_at);
        }
        if proceed_withdraw_height != 0 {
            runtime = runtime.with_proceed_withdraw_height(proceed_withdraw_height);
        }
        tx.update_graph_runtime(&runtime).await?;
        Ok(())
    }

    async fn init_instance_graph_data(
        local_db: &LocalDB,
        instances: &[Instance],
        graphs: &[Graph],
    ) -> anyhow::Result<()> {
        let mut tx = local_db.start_transaction().await?;
        for instance in instances {
            tx.upsert_instance(instance).await?;
        }
        for graph in graphs {
            seed_graph_runtime(&mut tx, graph).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nodes_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        let mut nodes = Vec::<Node>::new();
        let (_, public_key) = Secp256k1::new().generate_keypair(&mut rand::thread_rng());
        let pub_key = public_key.to_string();
        let actor = Actor::Verifier;
        nodes.push(Node {
            peer_id: generate_local_key().public().to_peer_id().to_string(),
            actor: actor.to_string(),
            node_name: "ZKM".to_string(),
            goat_addr: get_rand_goat_address(),
            btc_pub_key: pub_key.clone(),
            socket_addr: "".to_string(),
            reward: "0".to_string(),
            service_fee_rate: 0.0,
            available_peg_btc: U256::from_str("4700000000000000000000000")
                .unwrap_or_default()
                .to_string(),
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        });
        let goat_addr = get_rand_goat_address();
        nodes.push(Node {
            peer_id: generate_local_key().public().to_peer_id().to_string(),
            actor: Actor::Committee.to_string(),
            node_name: "ZKM".to_string(),
            goat_addr: goat_addr.clone(),
            btc_pub_key: pub_key.clone(),
            socket_addr: "".to_string(),
            reward: "0".to_string(),
            service_fee_rate: 0.0,
            available_peg_btc: U256::from_str("4700000000000000000000000")
                .unwrap_or_default()
                .to_string(),
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        });

        let local_db = create_local_db(&temp_sqlite_db_path()).await;
        init_nodes_data(&local_db, &nodes).await?;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db,
            Actor::Verifier,
            generate_local_key().public().to_peer_id().to_string(),
            MetricsState::new(Arc::new(Mutex::new(Registry::default()))),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(3)).await;
        let api_test_items = [
            ApiTestItem {
                tag: format!("{} get node", routes::v1::NODES_BASE),
                url: format!("http://{addr}{}?actor={}", routes::v1::NODES_BASE, actor),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<NodeListResponse>(&text),
                        Ok(node_resp) if node_resp.nodes.len() == 1
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} get node overview", routes::v1::NODES_OVERVIEW),
                url: format!("http://{addr}{}", routes::v1::NODES_OVERVIEW),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<NodeOverViewResponse>(&text),
                        Ok(node_overview) if node_overview.nodes_overview.online_verifiers == 1 &&
                        node_overview.nodes_overview.online_committees == 1
                    )
                })),
            },
        ];
        do_batch_tests("node apis", &Client::new(), &api_test_items).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bitvm_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        let actor = Actor::Verifier;
        let local_key = generate_local_key();
        let peer_id = local_key.public().to_peer_id().to_string();
        let local_db = create_local_db(&temp_sqlite_db_path()).await;
        let bridge_in_instance_id = Uuid::new_v4();
        let bridge_in_from = get_rand_btc_address_p2wpkh(get_network());
        let bridge_in_to = get_rand_goat_address();
        let bridge_in_amount = 20000000;
        let utxo: Vec<Utxo> = vec![Utxo {
            txid: generate_random_bytes(32).try_into().unwrap(),
            vout: 1,
            amount_sats: bridge_in_amount as u64,
        }];
        let mut instances = Vec::<Instance>::new();
        let mut graphs = Vec::<Graph>::new();
        instances.push(Instance {
            instance_id: bridge_in_instance_id,
            network: get_network().to_string(),
            from_addr: bridge_in_from.clone(),
            to_addr: bridge_in_to.clone(),
            amount: bridge_in_amount,
            fees: Default::default(),
            input_utxos: serde_json::to_string(&utxo).unwrap(),
            status: InstanceBridgeInStatus::RelayerL2Minted.to_string(),
            goat_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            goat_tx_height: 1000,
            user_xonly_pubkey: Default::default(),
            user_change_addr: get_rand_btc_address_p2wpkh(get_network()),
            user_refund_addr: get_rand_btc_address_p2wpkh(get_network()),
            btc_txid: None,
            btc_height: 0,
            pegin_confirm_txid: None,
            pegin_cancel_txid: None,
            committees_answers: Default::default(),
            pegin_data_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            parameters: None,
            post_pegin_txhash: None,
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });

        instances.push(Instance {
            instance_id: Uuid::new_v4(),
            network: get_network().to_string(),
            from_addr: bridge_in_from.clone(),
            to_addr: bridge_in_to.clone(),
            amount: bridge_in_amount,
            fees: Default::default(),
            input_utxos: serde_json::to_string(&utxo).unwrap(),
            status: InstanceBridgeInStatus::RelayerL1Broadcasted.to_string(),
            goat_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            goat_tx_height: 1000,
            user_xonly_pubkey: Default::default(),
            user_change_addr: get_rand_btc_address_p2wpkh(get_network()),
            user_refund_addr: get_rand_btc_address_p2wpkh(get_network()),
            btc_txid: None,
            btc_height: 0,
            pegin_confirm_txid: None,
            pegin_cancel_txid: None,
            committees_answers: Default::default(),
            pegin_data_tx_hash: format!("0x{}", hex::encode(generate_random_bytes(32))),
            parameters: None,
            post_pegin_txhash: None,
            status_updated_at: current_time_secs(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });
        let graph_id = Uuid::new_v4();
        let graph_status = GraphStatus::OperatorTake1.to_string();
        let graph_to = get_rand_btc_address_p2wpkh(get_network());
        let graph_from = get_rand_goat_address();

        graphs.push(Graph {
            graph_id,
            instance_id: bridge_in_instance_id,
            kickoff_index: 0,
            from_addr: graph_from.clone(),
            to_addr: graph_to.clone(),
            amount: bridge_in_amount,
            challenge_amount: bridge_in_amount,
            status: graph_status.clone(),
            sub_status: "".to_string(),
            operator_pubkey: "".to_string(),
            definition_hash: format!("fixture-{graph_id}"),
            next_prekickoff: None,
            cur_prekickoff_txid: None,
            force_skip_kickoff_txid: None,
            quick_challenge_txid: None,
            challenge_incomplete_kickoff_txid: None,
            pegin_txid: None,
            kickoff_txid: None,
            take1_txid: None,
            challenge_txid: None,
            take2_txid: None,
            operator_assert_txid: None,
            verifier_assert_txids: vec![],
            disprove_txids: vec![],
            watchtower_challenge_timeout_txids: vec![],
            operator_challenge_nack_txids: vec![],
            operator_commit_timeout_txid: None,
            watchtower_challenge_init_txid: None,
            init_withdraw_tx_hash: Some(format!("0x{}", hex::encode(generate_random_bytes(32)))),
            bridge_out_start_at: current_time_secs() + 100,
            status_updated_at: current_time_secs(),
            proceed_withdraw_height: 0,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });
        let finalized_graph_id = Uuid::new_v4();
        graphs.push(Graph {
            graph_id: finalized_graph_id,
            instance_id: bridge_in_instance_id,
            kickoff_index: 0,
            from_addr: graph_from.clone(),
            to_addr: graph_to.clone(),
            amount: bridge_in_amount,
            challenge_amount: bridge_in_amount,
            status: GraphStatus::CommitteePresigned.to_string(),
            sub_status: "".to_string(),
            operator_pubkey: "".to_string(),
            definition_hash: format!("fixture-{finalized_graph_id}"),
            next_prekickoff: None,
            cur_prekickoff_txid: None,
            force_skip_kickoff_txid: None,
            quick_challenge_txid: None,
            challenge_incomplete_kickoff_txid: None,
            pegin_txid: None,
            kickoff_txid: None,
            take1_txid: None,
            challenge_txid: None,
            take2_txid: None,
            operator_assert_txid: None,
            verifier_assert_txids: vec![],
            disprove_txids: vec![],
            watchtower_challenge_timeout_txids: vec![],
            operator_challenge_nack_txids: vec![],
            operator_commit_timeout_txid: None,
            watchtower_challenge_init_txid: None,
            init_withdraw_tx_hash: None,
            bridge_out_start_at: 0,
            status_updated_at: current_time_secs(),
            proceed_withdraw_height: 0,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        });

        init_instance_graph_data(&local_db, &instances, &graphs).await?;

        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db.clone(),
            actor.clone(),
            peer_id.clone(),
            MetricsState::new(Arc::new(Mutex::new(Registry::default()))),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(3)).await;

        let target_instance_id = bridge_in_instance_id;
        let api_test_items = vec![
            ApiTestItem {
                tag: routes::v1::INSTANCES_SETTINGS.to_string(),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_SETTINGS),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceSettingResponse>(&text),
                        Ok(instances_setting) if instances_setting.bridge_in_amount == BRIDGE_IN_AMOUNTS.to_vec()
                    )
                })),
            },
            ApiTestItem {
                tag: routes::v1::INSTANCES_BY_ID.to_string(),
                url: format!(
                    "http://{addr}{}/{}",
                    routes::v1::INSTANCES_BASE,
                    bridge_in_instance_id
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    if let Ok(instance_res) = serde_json::from_str::<InstanceGetResponse>(&text)
                        && let Some(instance_wrap) = instance_res.instance_wrap
                        && instance_wrap.instance.instance_id.eq(&target_instance_id)
                    {
                        true
                    } else {
                        false
                    }
                })),
            },
            ApiTestItem {
                tag: format!("{} get instances", routes::v1::INSTANCES_BASE),
                url: format!(
                    "http://{addr}{}?from_addr={}",
                    routes::v1::INSTANCES_BASE,
                    bridge_in_from,
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(|text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceListResponse>(&text),
                        Ok(instance_list) if instance_list.total == 2
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} info", routes::v1::INSTANCES_OVERVIEW),
                url: format!("http://{addr}{}", routes::v1::INSTANCES_OVERVIEW,),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    matches!(
                        serde_json::from_str::<InstanceOverviewResponse>(&text),
                        Ok(instance_overview) if instance_overview.instances_overview.total_bridge_in_amount == bridge_in_amount
                    )
                })),
            },
            ApiTestItem {
                tag: format!("{} info", routes::v1::GRAPHS_BY_ID),
                url: format!("http://{addr}{}/{}", routes::v1::GRAPHS_BASE, graph_id),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    if let Ok(graph_res) = serde_json::from_str::<GraphGetResponse>(&text)
                        && let Some(graph) = graph_res.graph
                        && graph.graph_id == graph_id
                    {
                        true
                    } else {
                        false
                    }
                })),
            },
            ApiTestItem {
                tag: format!("{} get graphs info", routes::v1::GRAPHS_BASE),
                url: format!(
                    "http://{addr}{}?status={}&from_addr={}&graph_id={}",
                    routes::v1::GRAPHS_BASE,
                    graph_status,
                    graph_from,
                    graph_id
                ),
                json_payload: None,
                method: Method::GET,
                expe_res: true,
                resp_validation: Some(Box::new(move |text| -> bool {
                    matches!(
                        serde_json::from_str::<GraphListResponse>(&text),
                        Ok(graph_list) if graph_list.total == 1
                    )
                })),
            },
        ];
        do_batch_tests("bitvm apis", &Client::new(), &api_test_items).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_proof_api() -> Result<(), Box<dyn std::error::Error>> {
        init(None);
        let addr = available_addr();
        info!("Start api server");
        let committee = Actor::Committee;
        let committee_peer_id = generate_local_key().public().to_peer_id().to_string();
        let local_db = create_local_db(&temp_sqlite_db_path()).await;
        tokio::spawn(rpc_service::serve(
            addr.clone(),
            local_db,
            committee,
            committee_peer_id,
            MetricsState::new(Arc::new(Mutex::new(Registry::default()))),
            CancellationToken::new(),
        ));
        sleep(Duration::from_secs(3)).await;
        let client = reqwest::Client::new();

        let api_test_items = [ApiTestItem {
            tag: format!("{} get proofs desc", routes::v1::PROOFS_CHAIN_PROOFS_DESC),
            url: format!(
                "http://{addr}{}?proof_type=header_chain",
                routes::v1::PROOFS_CHAIN_PROOFS_DESC
            ),
            json_payload: None,
            method: Method::GET,
            expe_res: true,
            resp_validation: None,
        }];
        do_batch_tests("node apis", &client, &api_test_items).await?;
        Ok(())
    }
}
