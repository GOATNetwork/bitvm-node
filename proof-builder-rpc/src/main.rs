mod api;
mod config;
mod task;

use crate::task::{is_start_generate_proof_tasks, run_generate_proof_tasks};
use alloy_primitives::Address;
use anyhow::Context;
use api::metrics_service::ApiMetricsState;
use api::{AuthorizationChain, AuthorizationChains};
use clap::Parser;
use client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork};
use futures::future;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::ProofBuilderConfig;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Local RPC service address
    #[arg(long, default_value = "0.0.0.0:7777")]
    pub rpc_addr: String,

    /// Dedicated Prometheus metrics listener address.
    ///
    /// Unset disables metrics; the business RPC never serves them.
    #[arg(long)]
    pub metrics_addr: Option<String>,

    /// Local Sqlite database file path
    #[arg(long, env, default_value = "sqlite:/tmp/bitvm-node.db")]
    pub database_url: String,

    #[arg(long, default_value = "proof-builder.toml")]
    pub config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let opt = Opts::parse();

    let cfg = ProofBuilderConfig::new(&opt.config)?;
    println!("proof builder config: {:?}", cfg);

    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let metrics_listener = match opt.metrics_addr.as_deref() {
        Some(metrics_addr) => Some(api::bind_metrics_listener(metrics_addr).await?),
        None => None,
    };
    let authorization_chains = goat_clients_from_env().await?;
    // Create cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();
    info!("load db {}", opt.database_url);
    let local_db = store::create_local_db(&opt.database_url).await;
    let metrics_state = ApiMetricsState::new();
    let api_state =
        api::ApiState::new(local_db.clone(), metrics_state.clone(), authorization_chains);
    let mut task_handles: Vec<JoinHandle<anyhow::Result<String, String>>> = vec![];
    let cancel_token_clone = cancellation_token.clone();
    let opt_rpc_addr = opt.rpc_addr.clone();
    let rpc_api_state = api_state.clone();
    info!(
        rpc_addr = %opt.rpc_addr,
        metrics_addr = opt.metrics_addr.as_deref().unwrap_or("disabled"),
        "start api server"
    );
    task_handles.push(tokio::spawn(async move {
        match api::serve_with_app_state(opt_rpc_addr, rpc_api_state, cancel_token_clone).await {
            Ok(tag) => Ok(tag),
            Err(e) => {
                tracing::error!("RPC service error: {}", e);
                Err("rpc_error".to_string())
            }
        }
    }));
    if let Some(listener) = metrics_listener {
        let cancel_token_clone = cancellation_token.clone();
        task_handles.push(tokio::spawn(async move {
            match api::serve_metrics(listener, api_state, cancel_token_clone).await {
                Ok(tag) => Ok(tag),
                Err(e) => {
                    tracing::error!("Metrics service error: {}", e);
                    Err("metrics_error".to_string())
                }
            }
        }));
    }
    if is_start_generate_proof_tasks(&cfg) {
        info!("start generate proof tasks");
        let cancel_token_clone = cancellation_token.clone();
        task_handles.push(tokio::spawn(async move {
            match run_generate_proof_tasks(cfg, local_db, metrics_state, 1, cancel_token_clone)
                .await
            {
                Ok(tag) => Ok(tag),
                Err(e) => {
                    tracing::error!("Main program is exiting: {e:?}");
                    Err(e.to_string())
                }
            }
        }));
    }

    // Wait for shutdown signal or any task completion
    let task_count = task_handles.len();
    tokio::select! {
        (result, index, remaining_handles) = future::select_all(task_handles) => {
            // Log the specific failure
            let failure_reason = match &result {
                Ok(Ok(tag)) => {
                    tracing::warn!("Task {} completed unexpectedly: {}", index, tag);
                    "unexpected completion"
                }
                Ok(Err(error)) => {
                    tracing::error!("Task {} failed with business error: {}", index, error);
                    "business error"
                }
                Err(join_error) => {
                    tracing::error!("Task {} failed with join error: {}", index, join_error);
                    "join error"
                }
            };

            tracing::info!("Triggering shutdown due to {} in task {}/{}", failure_reason, index + 1, task_count);

            // Initiate graceful shutdown
            cancellation_token.cancel();

            // Wait a moment for graceful shutdown, then force abort remaining tasks
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force abort any tasks that didn't respond to cancellation
            remaining_handles.into_iter().for_each(|handle| handle.abort());

            tracing::info!("All tasks stopped");

            // Handle panic propagation
            if let Err(join_error) = result && join_error.is_panic() {
                    std::panic::resume_unwind(join_error.into_panic());

            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            cancellation_token.cancel();

            // Give tasks some time to shutdown gracefully
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            tracing::info!("Graceful shutdown completed");
        }
    }
    Ok(())
}

/// Builds one read-only GOAT client per configured Gateway for live authorization.
async fn goat_clients_from_env() -> anyhow::Result<AuthorizationChains> {
    let network = match std::env::var("GOAT_NETWORK")
        .context("GOAT_NETWORK is required for Proof Builder authorization")?
        .as_str()
    {
        "main" => GoatNetwork::Main,
        "test" => GoatNetwork::Test,
        value => anyhow::bail!("invalid GOAT_NETWORK {value:?}; expected main or test"),
    };
    let rpc_url = std::env::var("GOAT_CHAIN_URL")
        .context("GOAT_CHAIN_URL is required for Proof Builder authorization")?
        .parse()
        .context("invalid GOAT_CHAIN_URL")?;
    let gateway_addresses = parse_gateway_addresses(
        &std::env::var("GOAT_GATEWAY_CONTRACT_ADDRESS")
            .context("GOAT_GATEWAY_CONTRACT_ADDRESS is required for Proof Builder authorization")?,
    )?;

    let base_config =
        GoatInitConfig::new(rpc_url).await.context("failed to query GOAT chain id")?;
    let mut chains = AuthorizationChains::with_capacity(gateway_addresses.len());
    for gateway_address in gateway_addresses {
        let gateway_config = base_config.clone().with_gateway_address(Some(gateway_address));
        let discovery_client = GOATClient::new(gateway_config.clone(), network);
        let committee_management =
            discovery_client.gateway_get_committee_management().await.with_context(|| {
                format!("failed to discover CommitteeManagement from Gateway {gateway_address}")
            })?;
        anyhow::ensure!(
            committee_management != [0; 20],
            "Gateway {gateway_address} returned a zero CommitteeManagement address"
        );
        let config = gateway_config
            .with_committee_management_address(Some(Address::from_slice(&committee_management)));
        let chain: Arc<dyn AuthorizationChain> = Arc::new(GOATClient::new(config, network));
        chains.insert(gateway_address, chain);
    }
    Ok(chains)
}

/// Parses and validates the comma-separated Gateway deployment list.
fn parse_gateway_addresses(value: &str) -> anyhow::Result<Vec<Address>> {
    let mut addresses = Vec::new();
    let mut seen = HashSet::new();
    for (index, raw_address) in value.split(',').enumerate() {
        let raw_address = raw_address.trim();
        anyhow::ensure!(
            !raw_address.is_empty(),
            "GOAT_GATEWAY_CONTRACT_ADDRESS entry {} must not be empty",
            index + 1
        );
        let address = raw_address.parse::<Address>().with_context(|| {
            format!("invalid GOAT_GATEWAY_CONTRACT_ADDRESS entry {raw_address:?}")
        })?;
        anyhow::ensure!(
            address != Address::ZERO,
            "GOAT_GATEWAY_CONTRACT_ADDRESS entry {} must not be the zero address",
            index + 1
        );
        anyhow::ensure!(
            seen.insert(address),
            "duplicate GOAT_GATEWAY_CONTRACT_ADDRESS entry {raw_address:?}"
        );
        addresses.push(address);
    }
    Ok(addresses)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal, starting graceful shutdown...");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_multiple_gateway_addresses() {
        let first = Address::from_slice(&[1; 20]);
        let second = Address::from_slice(&[2; 20]);

        assert_eq!(parse_gateway_addresses(&first.to_string()).unwrap(), vec![first]);
        assert_eq!(
            parse_gateway_addresses(&format!("  {first} , {second}  ")).unwrap(),
            vec![first, second]
        );
    }

    #[test]
    fn rejects_invalid_zero_empty_and_duplicate_gateway_addresses() {
        let address = Address::from_slice(&[1; 20]);

        assert!(parse_gateway_addresses("").is_err());
        assert!(parse_gateway_addresses(&format!("{address},")).is_err());
        assert!(parse_gateway_addresses("invalid").is_err());
        assert!(parse_gateway_addresses(&Address::ZERO.to_string()).is_err());
        assert!(parse_gateway_addresses(&format!("{address},{address}")).is_err());
    }
}
