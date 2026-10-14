mod api;
mod config;
mod fleet;
mod prover;
mod storage;
mod task;

use crate::fleet::{FleetEnv, ProgramRecord, ProgramsFile, StorageLock};
use crate::prover::ProverRuntime;
use crate::storage::Level;
use crate::task::{TaskOptions, is_start_generate_proof_tasks, run_generate_proof_tasks};
use alloy_primitives::Address;
use anyhow::Context;
use api::metrics_service::ApiMetricsState;
use api::{AuthorizationChain, AuthorizationChains};
use clap::Parser;
use client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork};
use commit_chain_proof::CommitChainProofBuilder;
use futures::future;
use header_chain_proof::HeaderChainProofBuilder;
use operator_proof::OperatorProofBuilder;
use proof_builder::ProofBuilder;
use state_chain_proof::StateChainProofBuilder;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use watchtower_proof::WatchtowerProofBuilder;
use zkm_sdk::{HashableKey, ProverClient, ZKM_CIRCUIT_VERSION};

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

    /// Print the guest program bundle (ELF digests, program IDs, verifying keys and the
    /// Fleet app id) as JSON, then exit.
    #[arg(long)]
    pub print_programs: bool,

    /// Check that the database, config and pending state-chain snapshots keep every proof
    /// path inside this storage root, then exit.
    #[arg(long, value_name = "STORAGE_ROOT")]
    pub check_storage: Option<PathBuf>,

    /// How long shutdown waits for the proof in progress to be published and committed.
    #[arg(long, default_value_t = 600)]
    pub drain_timeout_secs: u64,

    /// Consecutive non-retryable failures before an operator or watchtower task is failed.
    #[arg(long, default_value_t = 2)]
    pub max_proof_attempts: u32,

    /// Unproved state-chain batches prepared ahead of the prover (0 = unlimited).
    #[arg(long, default_value_t = 2)]
    pub state_chain_max_pending_batches: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Only the process environment selects Fleet mode; a `.env` file cannot.
    let fleet_env = FleetEnv::from_lookup(|key| std::env::var(key).ok())?;
    if fleet_env.as_ref().is_some_and(|env| env.exit_with_parent) {
        fleet::exit_with_parent()?;
    }
    dotenv::dotenv().ok();
    let opt = Opts::parse();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    if opt.print_programs {
        return print_programs().await;
    }

    let cfg = ProofBuilderConfig::new(&opt.config)?;
    println!("proof builder config: {:?}", cfg);

    if let Some(root) = &opt.check_storage {
        return check_storage(root, &cfg, &opt.database_url).await;
    }

    let (runtime, _storage_lock) = match &fleet_env {
        Some(env) => {
            let (runtime, lock) = start_fleet_worker(env, &opt).await?;
            (runtime, Some(lock))
        }
        None => (ProverRuntime::sdk(opt.max_proof_attempts), None),
    };
    remove_stale_tmp_files(&cfg);

    let metrics_listener = match opt.metrics_addr.as_deref() {
        Some(metrics_addr) => Some(api::bind_metrics_listener(metrics_addr).await?),
        None => None,
    };
    let authorization_chains = goat_clients_from_env().await?;
    // Proof tasks stop first; the API keeps serving while the proof in progress drains.
    let task_token = CancellationToken::new();
    let api_token = CancellationToken::new();
    info!("load db {}", opt.database_url);
    let local_db = store::create_local_db(&opt.database_url).await;
    let metrics_state = ApiMetricsState::new();
    let api_state =
        api::ApiState::new(local_db.clone(), metrics_state.clone(), authorization_chains);
    let mut task_handles: Vec<JoinHandle<anyhow::Result<String, String>>> = vec![];
    let cancel_token_clone = api_token.clone();
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
        let cancel_token_clone = api_token.clone();
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
        let cancel_token_clone = task_token.clone();
        let options = TaskOptions {
            runtime: runtime.clone(),
            state_chain_max_pending_batches: opt.state_chain_max_pending_batches,
        };
        task_handles.push(tokio::spawn(async move {
            match run_generate_proof_tasks(
                cfg,
                local_db,
                metrics_state,
                options,
                1,
                cancel_token_clone,
            )
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
    let mut tasks = future::select_all(task_handles);
    let (failure, panic, mut remaining) = tokio::select! {
        (result, index, remaining) = &mut tasks => {
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
            let panic = match result {
                Err(join_error) if join_error.is_panic() => Some(join_error.into_panic()),
                _ => None,
            };
            (Some(failure_reason), panic, remaining)
        }
        _ = shutdown_signal() => {
            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            (None, None, Vec::new())
        }
    };

    // Start no further proofs, let the one in progress publish and commit, then stop.
    task_token.cancel();
    // A finished select hands back the other tasks; an interrupted one still holds them.
    remaining.extend(tasks.into_inner());
    let drain_timeout = Duration::from_secs(opt.drain_timeout_secs);
    let drained = shut_down(&runtime, &api_token, remaining, drain_timeout, API_GRACE).await;
    if let Some(payload) = &panic {
        tracing::error!("a task panicked: {}", panic_message(payload.as_ref()));
    }
    if let Some(reason) = failure {
        tracing::error!("proof builder stopped after a task {reason}");
    }
    // Exit explicitly. Returning would drop the runtime, which waits without limit for a
    // proof still running on a blocking thread: a stuck GPU call would keep the worker
    // alive, and Fleet only restarts a worker whose process has exited.
    std::process::exit(exit_code(failure.is_some(), drained, panic.is_some()))
}

/// How long the API may finish in-flight requests after proving has stopped.
const API_GRACE: Duration = Duration::from_secs(2);

/// Stops new proofs and waits up to `drain_timeout` for the one in progress to commit, then
/// stops the API and aborts the remaining tasks. Returns whether the proof drained; a proof
/// still running afterwards is abandoned and retried after restart.
async fn shut_down(
    runtime: &ProverRuntime,
    api_token: &CancellationToken,
    tasks: Vec<JoinHandle<anyhow::Result<String, String>>>,
    drain_timeout: Duration,
    api_grace: Duration,
) -> bool {
    runtime.begin_shutdown();
    if runtime.in_flight() > 0 {
        info!(
            timeout_secs = drain_timeout.as_secs(),
            "waiting for the proof in progress to commit"
        );
    }
    let drained = runtime.drain(drain_timeout).await;
    if !drained {
        warn!(
            "drain timed out; exiting without the unfinished proof, which is retried after restart"
        );
    }
    api_token.cancel();
    tokio::time::sleep(api_grace).await;
    tasks.into_iter().for_each(|handle| handle.abort());
    tracing::info!("All tasks stopped");
    drained
}

/// 0 after a clean stop, 1 after a task failure or an abandoned proof, 101 after a panic.
fn exit_code(failed: bool, drained: bool, panicked: bool) -> i32 {
    if panicked {
        101
    } else if failed || !drained {
        1
    } else {
        0
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("unknown panic")
}

/// Validates the Fleet worker environment and connects to the replica's GPU server.
async fn start_fleet_worker(
    env: &FleetEnv,
    opt: &Opts,
) -> anyhow::Result<(ProverRuntime, StorageLock)> {
    let lock = fleet::lock_storage_root(&env.storage_root)?;
    fleet::check_storage_paths(&env.storage_root, &std::env::current_dir()?, &opt.database_url)?;
    let programs = ProgramsFile::load(&env.programs_file)?;
    let embedded: Vec<_> = fleet::bundle_programs()
        .iter()
        .map(|(name, elf)| (*name, fleet::sha256_hex(elf)))
        .collect();
    programs.check_embedded(&env.app_id, &embedded, zkm_primitives::io::zkm_imm_wrap_vk_mode())?;
    if std::env::var("ZKM_PROVER").is_ok() {
        warn!("ZKM_PROVER is ignored: Fleet supplies this worker's GPU server");
    }
    info!(
        app = %format!("{}/{}", env.tenant, env.app_id),
        namespace = %env.namespace,
        storage_root = %env.storage_root.display(),
        gpu_endpoint = %env.gpu_endpoint,
        "starting proof builder as a Fleet app worker"
    );
    let runtime =
        ProverRuntime::fleet(env.gpu_endpoint.clone(), programs, opt.max_proof_attempts).await?;
    Ok((runtime, lock))
}

/// Prints the program bundle by setting every program up on the CPU prover.
async fn print_programs() -> anyhow::Result<()> {
    let file = tokio::task::spawn_blocking(|| -> anyhow::Result<ProgramsFile> {
        fn record<B: ProofBuilder>(name: &str, builder: &B) -> anyhow::Result<ProgramRecord> {
            Ok(ProgramRecord {
                name: name.to_string(),
                elf_sha256: fleet::sha256_hex(&builder.pk().elf),
                program_id: hex::encode(builder.program_id()?),
                vk_hash: builder.vk().bytes32(),
            })
        }
        let client = Arc::new(ProverClient::cpu());
        let mut programs = Vec::new();
        for (name, elf) in fleet::bundle_programs() {
            let program = match name {
                "commit-chain" => {
                    record(name, &CommitChainProofBuilder::with_client(client.clone()))?
                }
                "header-chain" => {
                    record(name, &HeaderChainProofBuilder::with_client(client.clone()))?
                }
                "operator" => record(name, &OperatorProofBuilder::with_client(client.clone()))?,
                "state-chain" => {
                    record(name, &StateChainProofBuilder::with_client(client.clone()))?
                }
                "watchtower" => record(name, &WatchtowerProofBuilder::with_client(client.clone()))?,
                other => anyhow::bail!("unknown program {other}"),
            };
            anyhow::ensure!(
                program.elf_sha256 == fleet::sha256_hex(elf),
                "{name} proving key does not embed its ELF"
            );
            programs.push(program);
        }
        let digests: Vec<_> =
            programs.iter().map(|p| (p.name.as_str(), p.elf_sha256.clone())).collect();
        Ok(ProgramsFile {
            bundle_id: fleet::bundle_id(&fleet::bundle_manifest(&digests)),
            zkm_circuit_version: ZKM_CIRCUIT_VERSION.to_string(),
            imm_wrap_vk: zkm_primitives::io::zkm_imm_wrap_vk_mode(),
            programs,
        })
    })
    .await??;
    println!("{}", serde_json::to_string_pretty(&file)?);
    Ok(())
}

/// Reports the storage check and fails when any proof path needs attention.
async fn check_storage(
    root: &Path,
    cfg: &ProofBuilderConfig,
    database_url: &str,
) -> anyhow::Result<()> {
    let database = fleet::sqlite_file(database_url)?;
    anyhow::ensure!(database.exists(), "database {} does not exist", database.display());
    // Open without migrating: the check never changes the database it inspects.
    let local_db = store::localdb::LocalDB::new(database_url, true).await;
    let findings = storage::check_storage(root, cfg, &local_db).await?;
    for finding in &findings {
        let level = match finding.level {
            Level::Ok => "ok",
            Level::Legacy => "legacy",
            Level::Warning => "warning",
            Level::Error => "error",
        };
        println!("[{level}] {}", finding.message);
    }
    let count = |level| findings.iter().filter(|f| f.level == level).count();
    let errors = count(Level::Error);
    println!(
        "storage check: {} ok, {} legacy, {} warnings, {errors} errors",
        count(Level::Ok),
        count(Level::Legacy),
        count(Level::Warning)
    );
    anyhow::ensure!(errors == 0, "storage check found {errors} errors");
    Ok(())
}

/// Removes temporary files that interrupted proof writes left in the proof directories.
fn remove_stale_tmp_files(cfg: &ProofBuilderConfig) {
    let outputs = [
        &cfg.header_chain.output_proof,
        &cfg.commit_chain.output_proof,
        &cfg.state_chain.output_proof,
        &cfg.state_chain.input_proof,
        &cfg.watchtower.output,
        &cfg.operator.output,
    ];
    let dirs: BTreeSet<_> = outputs
        .iter()
        .filter_map(|path| Path::new(path.as_str()).parent())
        .map(|dir| if dir.as_os_str().is_empty() { Path::new(".") } else { dir })
        .filter(|dir| dir.is_dir())
        .collect();
    for dir in dirs {
        match proof_builder::artifacts::remove_stale_tmp_files(dir) {
            Ok(0) => {}
            Ok(removed) => info!(dir = %dir.display(), removed, "removed interrupted proof writes"),
            Err(error) => {
                warn!(dir = %dir.display(), %error, "failed to clean interrupted proof writes")
            }
        }
    }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_returns_when_a_proof_is_stuck() {
        let runtime = ProverRuntime::sdk(2);
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let unit = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .run(prover::blocking(move || {
                        let _ = stuck.recv();
                    }))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        let api_token = CancellationToken::new();
        let drained =
            shut_down(&runtime, &api_token, Vec::new(), Duration::from_millis(100), Duration::ZERO)
                .await;
        assert!(!drained);
        assert!(api_token.is_cancelled());
        assert!(started.elapsed() < Duration::from_secs(5), "shutdown must not wait for the proof");
        assert_eq!(exit_code(false, drained, false), 1);
        // Let the blocking thread finish so the test runtime can stop.
        release.send(()).unwrap();
        unit.await.unwrap().unwrap().unwrap();
    }

    #[test]
    fn exit_code_reports_failures_abandoned_proofs_and_panics() {
        assert_eq!(exit_code(false, true, false), 0);
        assert_eq!(exit_code(true, true, false), 1);
        assert_eq!(exit_code(false, false, false), 1);
        assert_eq!(exit_code(true, false, true), 101);
    }

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
