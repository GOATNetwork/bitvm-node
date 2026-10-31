#![feature(trivial_bounds)]
use base64::Engine;
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use bitvm_noded::env::{
    self, ENV_PEER_KEY, SEQUENCER_SET_MONITOR_INTERVAL_SECS, check_node_info, get_btc_url_from_env,
    get_goat_network, get_network, get_node_pubkey, goat_config_from_env,
    validate_soldering_proof_payload_store_config,
};
use clap::{Parser, Subcommand};
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use libp2p::PeerId;
use libp2p_metrics::Registry;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

use bitvm_noded::utils::{
    self, generate_local_key, save_local_info, set_node_external_socket_addr_env,
};
use bitvm_noded::{
    rpc_service, run_kickoff_scan_task, run_maintenance_tasks, run_sequencer_set_hash_monitor_task,
    run_watch_event_task,
};

use anyhow::Result;
use bitvm_noded::metrics_service::{MetricsState, set_node_metrics_state};
use bitvm_noded::middleware::swarm::{BitvmNetworkManager, BitvmSwarmConfig};
use bitvm_noded::p2p_msg_handler::BitvmNodeProcessor;
use client::http_client::async_client::HttpAsyncClient;
use futures::future;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Setup the bootnode p2p port
    #[arg(long, default_value = "0")]
    p2p_port: u16,

    /// Local RPC service address
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

    /// Local Sqlite database file path
    #[arg(long, default_value = "sqlite:/tmp/bitvm-node.db")]
    pub db_path: String,

    /// Peer nodes as the bootnodes
    #[arg(long)]
    bootnodes: Vec<String>,

    /// Dedicated Prometheus metrics listener address, e.g. `10.0.0.7:9108`.
    ///
    /// Unset disables the metrics listener entirely. Bind a private address and a
    /// port unique to this process; the business RPC never serves metrics.
    #[arg(long)]
    metrics_addr: Option<String>,

    /// Metric endpoint path served by the dedicated metrics listener.
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    /// Whether to run the libp2p Kademlia protocol and join the BitVM DHT.
    #[arg(long, default_value = "true")]
    enable_kademlia: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Key(KeyArg),
    Peer(PeerArg),
}

#[derive(Parser, Debug, Clone)]
struct KeyArg {
    #[arg(long, default_value = "ed25519")]
    kind: String,
    #[command(subcommand)]
    cmd: KeyCommands,
}

#[derive(Parser, Debug, Clone)]
struct PeerArg {
    #[clap(subcommand)]
    peer_cmd: PeerCommands,
}

#[derive(Parser, Debug, Clone)]
enum PeerCommands {
    GetPeers {
        #[clap(long)]
        peer_id: Option<PeerId>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum KeyCommands {
    /// Generate peer secret key and peer id
    Peer,
    /// Generate the funding address with the Hex-Encoded private key in .env
    FundingAddress,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    let actor = env::get_actor();
    let opt = Opts::parse();
    if let Some(Commands::Key(key_arg)) = opt.cmd {
        match key_arg.cmd {
            KeyCommands::Peer => {
                let local_key = generate_local_key();
                let base64_key = base64::engine::general_purpose::STANDARD
                    .encode(&local_key.to_protobuf_encoding()?);
                let peer_id = local_key.public().to_peer_id().to_string();
                println!("{ENV_PEER_KEY}={base64_key}");
                println!("PEER_ID={peer_id}");
            }
            KeyCommands::FundingAddress => {
                let public_key = get_node_pubkey()?;
                let p2wsh_addr = utils::node_p2wsh_address(get_network(), &public_key);
                println!("Funding P2WSH address (for operator and verifier): {p2wsh_addr}");
            }
        }
        return Ok(());
    }
    let _ = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
    let min_required_verifier = env::get_min_required_verifier()?;
    validate_soldering_proof_payload_store_config(&actor)?;

    let is_publisher = actor == Actor::Publisher || actor == Actor::All;
    let sequencer_set_monitor_start_cosmos_block =
        env::get_sequencer_set_monitor_start_cosmos_block_from_env();
    if is_publisher && sequencer_set_monitor_start_cosmos_block.is_none() {
        return Err(anyhow::anyhow!(
            "sequencer_set_monitor_start_cosmos_block is required when sequencer set monitor is enabled"
        )
        .into());
    }
    // Bind the metrics listener before any background task starts, so an invalid path
    // or an unavailable metrics port aborts startup with an explicit error.
    let metrics_listener = match opt.metrics_addr.as_deref() {
        Some(metrics_addr) => {
            rpc_service::validate_metrics_path(&opt.metrics_path)?;
            Some(rpc_service::bind_metrics_listener(metrics_addr).await?)
        }
        None => None,
    };

    let mut metric_registry = Registry::default();

    // Create cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();
    let mut task_handles: Vec<JoinHandle<Result<String, String>>> = vec![];
    let mut task_names: Vec<&'static str> = vec![];
    // init bitvmswarm
    let bitvm_network_manager = BitvmNetworkManager::new(
        BitvmSwarmConfig {
            local_key: env::get_peer_key(),
            p2p_port: opt.p2p_port,
            bootnodes: opt.bootnodes,
            topic_names: vec![
                Actor::Committee.to_string(),
                Actor::Verifier.to_string(),
                Actor::Operator.to_string(),
                Actor::Watchtower.to_string(),
                Actor::All.to_string(),
            ],
            heartbeat_interval: env::HEARTBEAT_INTERVAL_SECOND,
            regular_task_interval: env::REGULAR_TASK_INTERVAL_SECOND,
        },
        &mut metric_registry,
    )?;
    let peer_id_string = bitvm_network_manager.get_peer_id_string();
    let bitcoin_network = get_network().to_string();
    let node_span = tracing::info_span!(
        "node",
        service = "bitvm-noded",
        role = %actor,
        peer_id = %peer_id_string,
        bitcoin_network = %bitcoin_network,
        version = env!("CARGO_PKG_VERSION"),
    );
    let _node_span_guard = node_span.enter();
    let local_db = store::create_local_db(&opt.db_path).await;
    let metric_registry = Arc::new(Mutex::new(metric_registry));
    let metrics_state = MetricsState::new(metric_registry);
    set_node_metrics_state(metrics_state.clone());
    let handler = BitvmNodeProcessor {
        local_db: local_db.clone(),
        btc_client: Arc::new(BTCClient::new(get_network(), get_btc_url_from_env().as_deref())),
        goat_client: Arc::new(GOATClient::new(
            env::goat_config_from_env().await,
            env::get_goat_network(),
        )),
        http_client: HttpAsyncClient::new(None),
        soldering_builder: matches!(actor, Actor::Verifier | Actor::Operator)
            .then(|| Arc::new(BabeBundleBuilder::new())),
        metrics_state: metrics_state.clone(),
    };

    tracing::info!(
        event = "service_started",
        service = "bitvm-noded",
        role = %actor,
        peer_id = %peer_id_string,
        bitcoin_network = ?get_network(),
        version = env!("CARGO_PKG_VERSION"),
        rpc_addr = %opt.rpc_addr,
        metrics_addr = opt.metrics_addr.as_deref().unwrap_or("disabled"),
        min_required_verifier,
        "node initialization completed"
    );

    let actor_clone2 = actor.clone();
    let actor_clone3 = actor.clone();
    let local_db_clone2 = local_db.clone();
    let local_db_clone3 = local_db.clone();
    let local_db_clone4 = local_db.clone();
    let local_db_clone5 = local_db.clone();
    let opt_rpc_addr = opt.rpc_addr.clone();

    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    if actor == Actor::Operator {
        set_node_external_socket_addr_env(&opt.rpc_addr).await?;
    }
    // validate node info
    check_node_info().await;
    save_local_info(&local_db).await;
    metrics_state.mark_startup_ready();

    // Both listeners share the same application and metrics state.
    let app_state = rpc_service::AppState::create_arc_app_state(
        local_db.clone(),
        actor.clone(),
        peer_id_string.clone(),
        metrics_state.clone(),
    )
    .await?;

    // Spawn RPC service task with cancellation support
    let cancel_token_clone = cancellation_token.clone();
    let rpc_task_span = node_span.clone();
    let rpc_app_state = app_state.clone();
    task_handles.push(tokio::spawn(
        async move {
            match rpc_service::serve_with_app_state(opt_rpc_addr, rpc_app_state, cancel_token_clone)
                .await
            {
                Ok(tag) => Ok(tag),
                Err(error) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "rpc_service",
                        outcome = "failed",
                        error_class = "rpc",
                        error = %error,
                        "RPC service task exited with an error"
                    );
                    Err("rpc_error".to_string())
                }
            }
        }
        .instrument(rpc_task_span),
    ));
    task_names.push("rpc_service");

    if let Some(listener) = metrics_listener {
        let cancel_token_clone = cancellation_token.clone();
        let metrics_task_span = node_span.clone();
        let metrics_app_state = app_state.clone();
        let metrics_path = opt.metrics_path.clone();
        task_handles.push(tokio::spawn(
            async move {
                match rpc_service::serve_metrics(
                    listener,
                    metrics_path,
                    metrics_app_state,
                    cancel_token_clone,
                )
                .await
                {
                    Ok(tag) => Ok(tag),
                    Err(error) => {
                        tracing::error!(
                            event = "core_task_wrapper_error",
                            service = "bitvm-noded",
                            task = "metrics_service",
                            outcome = "failed",
                            error_class = "metrics",
                            error = %error,
                            "metrics service task exited with an error"
                        );
                        Err("metrics_error".to_string())
                    }
                }
            }
            .instrument(metrics_task_span),
        ));
        task_names.push("metrics_service");
    }
    // if actor == Actor::Committee || actor == Actor::Operator {
    let cancel_token_clone = cancellation_token.clone();
    let event_watcher_task_span = node_span.clone();
    let event_watcher_metrics = metrics_state.clone();
    task_handles.push(tokio::spawn(
        async move {
            let goat_init_config = goat_config_from_env().await;
            let goat_client =
                Arc::new(GOATClient::new(goat_init_config.clone(), get_goat_network()));
            let btc_client =
                Arc::new(BTCClient::new(get_network(), get_btc_url_from_env().as_deref()));
            match run_watch_event_task(
                actor_clone2,
                local_db_clone2,
                btc_client,
                goat_client,
                5,
                cancel_token_clone,
                goat_init_config,
                event_watcher_metrics,
            )
            .await
            {
                Ok(tag) => Ok(tag),
                Err(error) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "event_watcher",
                        outcome = "failed",
                        error_class = "watcher",
                        error = %error,
                        "event watcher task exited with an error"
                    );
                    Err("watch_error".to_string())
                }
            }
        }
        .instrument(event_watcher_task_span),
    ));
    task_names.push("event_watcher");

    if is_publisher {
        let start_cosmos_block = sequencer_set_monitor_start_cosmos_block.unwrap();
        let cosmos_rpc_url = env::get_cosmos_rpc_url_from_env();
        let cancel_token_clone = cancellation_token.clone();
        task_handles.push(tokio::spawn(async move {
            let goat_client =
                Arc::new(GOATClient::new(goat_config_from_env().await, get_goat_network()));
            match run_sequencer_set_hash_monitor_task(
                local_db_clone4,
                goat_client,
                cosmos_rpc_url,
                start_cosmos_block,
                SEQUENCER_SET_MONITOR_INTERVAL_SECS,
                cancel_token_clone,
            )
            .await
            {
                Ok(tag) => Ok(tag),
                Err(error) => {
                    tracing::error!("Sequencer set monitor task error: {}", error);
                    Err("sequencer_set_monitor_error".to_string())
                }
            }
        }));
        task_names.push("sequencer_set_monitor");
    }
    // }

    let cancel_token_clone = cancellation_token.clone();
    let maintenance_task_span = node_span.clone();
    let maintenance_metrics = metrics_state.clone();
    task_handles.push(tokio::spawn(
        async move {
            let goat_client =
                Arc::new(GOATClient::new(goat_config_from_env().await, get_goat_network()));
            let btc_client =
                Arc::new(BTCClient::new(get_network(), get_btc_url_from_env().as_deref()));
            match run_maintenance_tasks(
                actor_clone3,
                local_db_clone3,
                btc_client,
                goat_client,
                10,
                cancel_token_clone,
                maintenance_metrics,
            )
            .await
            {
                Ok(tag) => Ok(tag),
                Err(error) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "maintenance",
                        outcome = "failed",
                        error_class = "maintenance",
                        error = %error,
                        "maintenance task exited with an error"
                    );
                    Err("maintenance_error".to_string())
                }
            }
        }
        .instrument(maintenance_task_span),
    ));
    task_names.push("maintenance");

    let cancel_token_clone = cancellation_token.clone();
    let kickoff_scan_span = node_span.clone();
    let kickoff_scan_metrics = metrics_state.clone();
    task_handles.push(tokio::spawn(
        async move {
            let goat_client =
                Arc::new(GOATClient::new(goat_config_from_env().await, get_goat_network()));
            let btc_client =
                Arc::new(BTCClient::new(get_network(), get_btc_url_from_env().as_deref()));
            match run_kickoff_scan_task(
                local_db_clone5,
                btc_client,
                goat_client,
                10,
                cancel_token_clone,
                kickoff_scan_metrics,
            )
            .await
            {
                Ok(tag) => Ok(tag),
                Err(error) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "kickoff_scan",
                        outcome = "failed",
                        error_class = "maintenance",
                        error = %error,
                        "kickoff scan task exited with an error"
                    );
                    Err("kickoff_scan_error".to_string())
                }
            }
        }
        .instrument(kickoff_scan_span),
    ));
    task_names.push("kickoff_scan");

    let swarm_actor = actor.clone();
    let cancel_token_clone = cancellation_token.clone();
    let p2p_task_span = node_span.clone();
    let p2p_blocking_span = p2p_task_span.clone();
    task_handles.push(tokio::spawn(
        async move {
            let result = tokio::task::spawn_blocking(move || {
                let _span_guard = p2p_blocking_span.enter();
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    start_handle_swarm_msg_task(
                        swarm_actor,
                        bitvm_network_manager,
                        handler,
                        cancel_token_clone,
                    )
                    .await
                })
            })
            .await;
            match result {
                Ok(Ok(tag)) => Ok(tag),
                Ok(Err(error)) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "p2p_swarm",
                        outcome = "failed",
                        error_class = "p2p",
                        error = %error,
                        "p2p swarm task exited with an error"
                    );
                    Err("swarm_error".to_string())
                }
                Err(error) => {
                    tracing::error!(
                        event = "core_task_wrapper_error",
                        service = "bitvm-noded",
                        task = "p2p_swarm",
                        outcome = "failed",
                        error_class = "join",
                        error = %error,
                        "p2p swarm blocking task failed to join"
                    );
                    Err("swarm_spawn_error".to_string())
                }
            }
        }
        .instrument(p2p_task_span),
    ));
    task_names.push("p2p_swarm");

    let heartbeat_actor = actor.clone();
    let heartbeat_peer_id = peer_id_string.clone();
    let cancel_token_clone = cancellation_token.clone();
    let heartbeat_task_span = node_span.clone();
    task_handles.push(tokio::spawn(
        async move {
            let started_at = Instant::now();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                        tracing::info!(
                            event = "service_heartbeat",
                            service = "bitvm-noded",
                            role = %heartbeat_actor,
                            peer_id = %heartbeat_peer_id,
                            uptime_secs = started_at.elapsed().as_secs(),
                            "node service heartbeat"
                        );
                    }
                    _ = cancel_token_clone.cancelled() => {
                        return Ok("heartbeat stopped after cancellation".to_string());
                    }
                }
            }
        }
        .instrument(heartbeat_task_span),
    ));
    task_names.push("heartbeat");

    // Wait for shutdown signal or any task completion
    let task_count = task_handles.len();
    tracing::info!(
        event = "service_ready",
        service = "bitvm-noded",
        role = %actor,
        peer_id = %peer_id_string,
        task_count,
        "all node background tasks have been started"
    );

    tokio::select! {
        (result, index, remaining_handles) = future::select_all(task_handles) => {
            let task_name = task_names[index];
            // Log the specific failure
            let failure_reason = match &result {
                Ok(Ok(tag)) => {
                    tracing::warn!(
                        event = "core_task_result",
                        service = "bitvm-noded",
                        task = task_name,
                        outcome = "unexpected_completion",
                        detail = %tag,
                        "node background task completed unexpectedly"
                    );
                    "unexpected completion"
                }
                Ok(Err(error)) => {
                    tracing::error!(
                        event = "core_task_result",
                        service = "bitvm-noded",
                        task = task_name,
                        outcome = "business_error",
                        error = %error,
                        "node background task failed"
                    );
                    "business error"
                }
                Err(join_error) => {
                    tracing::error!(
                        event = "core_task_result",
                        service = "bitvm-noded",
                        task = task_name,
                        outcome = "join_error",
                        error = %join_error,
                        "node background task failed to join"
                    );
                    "join error"
                }
            };

            tracing::info!(
                event = "service_shutdown",
                service = "bitvm-noded",
                trigger = "core_task_result",
                task = task_name,
                reason = failure_reason,
                task_count,
                "triggering node shutdown after background task result"
            );

            // Initiate graceful shutdown
            cancellation_token.cancel();

            // Wait a moment for graceful shutdown, then force abort remaining tasks
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Force abort any tasks that didn't respond to cancellation
            remaining_handles.into_iter().for_each(|handle| handle.abort());

            tracing::info!(
                event = "service_shutdown",
                service = "bitvm-noded",
                outcome = "tasks_stopped",
                "all node background tasks stopped"
            );

            // Handle panic propagation
            if let Err(join_error) = result && join_error.is_panic() {
                    std::panic::resume_unwind(join_error.into_panic());

            }
        }
        _ = shutdown_signal() => {
            tracing::info!(
                event = "service_shutdown",
                service = "bitvm-noded",
                outcome = "started",
                trigger = "signal",
                "received shutdown signal; initiating graceful shutdown"
            );
            cancellation_token.cancel();

            // Give tasks some time to shutdown gracefully
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            tracing::info!(
                event = "service_shutdown",
                service = "bitvm-noded",
                outcome = "completed",
                "node graceful shutdown completed"
            );
        }
    }

    Ok(())
}

/// Listen for shutdown signals (Ctrl+C, SIGTERM, etc.)
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
            tracing::info!(
                event = "service_shutdown_signal",
                signal = "SIGINT",
                "received Ctrl+C signal"
            );
        },
        _ = terminate => {
            tracing::info!(
                event = "service_shutdown_signal",
                signal = "SIGTERM",
                "received SIGTERM signal"
            );
        },
    }
}

pub async fn start_handle_swarm_msg_task(
    actor: Actor,
    mut swarm: BitvmNetworkManager,
    handler: BitvmNodeProcessor,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    swarm.run(actor, handler, cancellation_token).await
}
