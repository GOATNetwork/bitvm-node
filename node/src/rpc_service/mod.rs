pub mod auth;
mod bitvm;
mod cors_config;
pub mod handler;
mod node;
mod response;
pub mod routes;
mod swap;
#[cfg(test)]
mod tests;
pub(super) mod utils;
pub mod validation;

use crate::env::{get_btc_url_from_env, get_goat_network, get_network, goat_config_from_env};
use crate::metrics_service::{MetricsState, metrics_handler, metrics_middleware};
use crate::rpc_service::auth::require_request_auth;
use crate::rpc_service::cors_config::CorsConfig;
#[cfg(feature = "rpc-debug-endpoints")]
use crate::rpc_service::handler::{
    clear_engine_poison, get_debug_engine, get_debug_status, send_challenge,
    send_verifier_challenge,
};
use crate::rpc_service::handler::{
    get_chain_proof_desc, get_graph, get_graph_neighbor_ids, get_graph_tx, get_graph_txn,
    get_graphs, get_instance, get_instances, get_instances_overview, get_node, get_nodes,
    get_nodes_overview, get_operator_proof_desc, get_ready_to_kickoff_graph, get_swap, get_swaps,
    get_unsigned_pegin_txn, instance_settings, pegout,
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
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

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
    /// Present when the execution engine is enabled (debug and status endpoints).
    pub engine: Option<engine::EngineHandle>,
    rpc_auth_nonces: Mutex<HashMap<String, i64>>,
}

impl AppState {
    pub async fn create_arc_app_state(
        local_db: LocalDB,
        actor: Actor,
        peer_id: String,
        metrics_state: MetricsState,
        engine: Option<engine::EngineHandle>,
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
            engine,
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
            engine: None,
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
        .route(routes::v1::DEBUG_ENGINE, get(get_debug_engine));

    let signed_routes = Router::new().route(routes::v1::PEGOUT, post(pegout));

    #[cfg(feature = "rpc-debug-endpoints")]
    let signed_routes = signed_routes
        .route(routes::v1::GRAPHS_SEND_CHALLENGE, post(send_challenge))
        .route(routes::v1::GRAPHS_SEND_VERIFIER_CHALLENGE, post(send_verifier_challenge))
        .route(routes::v1::DEBUG_ENGINE_CLEAR_POISON, post(clear_engine_poison));

    let signed_routes = signed_routes
        .route_layer(middleware::from_fn_with_state(app_state.clone(), require_request_auth));

    public_routes.merge(signed_routes).layer(create_secure_cors_layer()).with_state(app_state)
}

pub async fn serve_with_app_state(
    addr: String,
    app_state: Arc<AppState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind RPC listener to {addr}"))?;
    serve_with_listener(listener, app_state, cancellation_token).await
}

async fn serve_with_listener(
    listener: TcpListener,
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
