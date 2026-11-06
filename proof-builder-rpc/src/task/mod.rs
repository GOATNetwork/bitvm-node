#![allow(clippy::too_many_arguments)] // Task persistence APIs mirror the proof metadata schema.

mod commit_chain_proof;
mod header_chain_proof;
mod operator_proof;
mod state_chain_proof;
mod watchtower_proof;
use crate::api::metrics_service::ApiMetricsState;
use crate::config::ProofBuilderConfig;
use crate::prover::{Cancelled, Failure, ProveError, ProverRuntime};
use crate::task::{
    commit_chain_proof::spawn_commit_chain_proof_task,
    header_chain_proof::spawn_header_chain_proof_task, operator_proof::spawn_operator_proof_task,
    state_chain_proof::spawn_state_chain_proof_task, watchtower_proof::spawn_watchtower_proof_task,
};
use ::commit_chain_proof::CommitChainProofBuilder;
use ::header_chain_proof::HeaderChainProofBuilder;
use ::state_chain_proof::StateChainProofBuilder;
use bitcoin::{BlockHash, Network, PublicKey, Txid};
use client::btc_chain::BTCClient;
use secp256k1::XOnlyPublicKey;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Instant, UNIX_EPOCH};
use uuid::Uuid;

use futures::future::Either;
use proof_builder::{OnDemandTask, ProofBuilder, ProofRequest};
use store::localdb::LocalDB;
use store::{
    LongRunningTaskProof, OnDemandProofCompletion, OnDemandProofTable, OperatorProof, ProofState,
    WatchtowerProof,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub(crate) fn is_start_generate_proof_tasks(cfg: &ProofBuilderConfig) -> bool {
    cfg.header_chain.enable
        || cfg.commit_chain.enable
        || cfg.state_chain.enable
        || cfg.watchtower.enable
        || cfg.operator.enable
}

/// Settings shared by the proof tasks.
#[derive(Clone)]
pub(crate) struct TaskOptions {
    pub runtime: ProverRuntime,
    /// Unproved state-chain batches prepared ahead of the prover (0 = unlimited).
    pub state_chain_max_pending_batches: i64,
}

pub(crate) async fn run_generate_proof_tasks(
    cfg: ProofBuilderConfig,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    options: TaskOptions,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<String> {
    let runtime = options.runtime.clone();
    let header_chain_proof_future = if cfg.header_chain.enable {
        Either::Left(spawn_header_chain_proof_task(
            runtime.clone(),
            cfg.header_chain.clone(),
            local_db.clone(),
            metrics_state.clone(),
            interval,
            0,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let commit_chain_proof_future = if cfg.commit_chain.enable {
        Either::Left(spawn_commit_chain_proof_task(
            runtime.clone(),
            cfg.commit_chain.clone(),
            local_db.clone(),
            metrics_state.clone(),
            interval,
            interval / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let state_chain_proof_future = if cfg.state_chain.enable {
        Either::Left(spawn_state_chain_proof_task(
            options.clone(),
            cfg.state_chain.clone(),
            local_db.clone(),
            metrics_state.clone(),
            interval,
            interval / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let operator_proof_future = if cfg.operator.enable {
        Either::Left(spawn_operator_proof_task(
            runtime.clone(),
            cfg.operator.clone(),
            local_db.clone(),
            metrics_state.clone(),
            interval,
            interval / 2,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    let watchtower_proof_future = if cfg.watchtower.enable {
        Either::Left(spawn_watchtower_proof_task(
            runtime.clone(),
            cfg.watchtower.clone(),
            local_db.clone(),
            metrics_state,
            interval,
            interval * 3 / 4,
            cancellation_token.clone(),
        ))
    } else {
        Either::Right(std::future::pending::<Result<anyhow::Result<_>, tokio::task::JoinError>>())
    };

    tokio::select! {
        result = header_chain_proof_future => {
            match result {
                Ok(Ok(_resp)) => {
                    info!("Header chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Header chain generate proof task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Header chain proof generate task panic: {:?}", e);
                    anyhow::bail!("Header chain proof generate task panic: {:?}", e);
                }
            }
        }
        result = commit_chain_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Commit chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Commit chain proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Commit chain proof generate task panic: {:?}", e);
                    anyhow::bail!("Commit chain proof generate task panic: {:?}", e);
                }
            }
        },
        result = state_chain_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("State chain proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("State chain proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("State chain proof generate task panic: {:?}", e);
                    anyhow::bail!("State chain proof generate task panic: {:?}", e);
                }
            }
        }
        result = operator_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Operator proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Operator proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Operator proof generate task panic: {:?}", e);
                    anyhow::bail!("Operator proof generate task panic: {:?}", e);
                }
            }
        }
        result = watchtower_proof_future => {
            match result {
                Ok(Ok(_)) => {
                    info!("Watchtower proof generate task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Watchtower proof generate task error: {}", e);
                    return Err(e);
                }
                Err(e) => {
                   error!("Watchtower proof generate task panic: {:?}", e);
                    anyhow::bail!("Watchtower proof generate task panic: {:?}", e);
                }
            }
        }
    }

    Ok("tasks_completed".to_string())
}

/// What happened to one on-demand proof attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnDemandOutcome {
    Proven,
    /// The task was no longer `New` (its request timed out), or proving stopped for
    /// shutdown. Nothing was recorded.
    Cancelled,
    /// The task stays `New` for the next round: a fatal failure below the attempt limit,
    /// a transient failure (which does not count), or an unavailable prover outside Fleet.
    Deferred,
    Failed,
}

/// One operator or watchtower proof to produce.
pub(crate) struct OnDemandJob<B> {
    pub table: OnDemandProofTable,
    pub task_index: i64,
    pub output: String,
    pub builder: Arc<B>,
    pub ctx: ProofRequest,
}

enum OnDemandUnit {
    NotNew,
    Proven,
    Failed(ProveError),
}

/// Proves one on-demand task under the GPU gate.
///
/// The result is recorded only while the task is still `New`, so a timeout that arrives
/// while the proof queues or runs wins. A failed proof marks the task failed after the
/// runtime's attempt limit. A prover failure leaves the task `New`; in Fleet mode it
/// returns an error so the worker exits and Fleet restarts the GPU server.
pub(crate) async fn prove_on_demand<B>(
    runtime: &ProverRuntime,
    local_db: &LocalDB,
    job: OnDemandJob<B>,
    attempts: &mut HashMap<i64, u32>,
    metrics_state: &ApiMetricsState,
    proof_type: &str,
) -> anyhow::Result<OnDemandOutcome>
where
    B: ProofBuilder + Send + Sync + 'static,
{
    let picked_at = Instant::now();
    let OnDemandJob { table, task_index, output, builder, ctx } = job;
    let unit = {
        let (runtime, local_db, output) = (runtime.clone(), local_db.clone(), output.clone());
        async move {
            // Recheck after waiting for the gate: the request may have timed out meanwhile.
            let state =
                local_db.acquire().await?.get_on_demand_proof_state(table, task_index).await?;
            if state != Some(ProofState::New.to_i64()) {
                return Ok(OnDemandUnit::NotNew);
            }
            let proved = match runtime.prove_and_save(builder, ctx).await {
                Ok(proved) => proved,
                Err(error) => return Ok(OnDemandUnit::Failed(error)),
            };
            let completion = OnDemandProofCompletion {
                path_to_proof: output,
                public_value_hex: proved.public_value_hex,
                proof_size: proved.proof_size as i64,
                cycles: proved.cycles as i64,
                proof_state: ProofState::Proven.to_i64(),
                total_time_to_proof: picked_at.elapsed().as_millis() as i64,
                proving_time: proved.proving_time as i64,
                zkm_version: proved.zkm_version,
            };
            let affected = local_db
                .acquire()
                .await?
                .complete_on_demand_proof_if_new(table, task_index, &completion)
                .await?;
            Ok::<_, anyhow::Error>(if affected > 0 {
                OnDemandUnit::Proven
            } else {
                OnDemandUnit::NotNew
            })
        }
    };
    let unit = match runtime.run(unit).await {
        Ok(result) => result?,
        Err(Cancelled) => return Ok(OnDemandOutcome::Cancelled),
    };
    let elapsed = picked_at.elapsed();
    let error = match unit {
        OnDemandUnit::Proven => {
            attempts.remove(&task_index);
            metrics_state.record_attempt(proof_type, "success", elapsed);
            return Ok(OnDemandOutcome::Proven);
        }
        OnDemandUnit::NotNew => {
            attempts.remove(&task_index);
            info!(task_index, "{proof_type} task is no longer pending; its proof is not recorded");
            metrics_state.record_attempt(proof_type, "cancelled", elapsed);
            return Ok(OnDemandOutcome::Cancelled);
        }
        OnDemandUnit::Failed(error) => error,
    };
    metrics_state.record_attempt(proof_type, failure_outcome(&error), elapsed);
    let error = match error {
        ProveError::Prove(error, Failure::Fatal) => error,
        ProveError::Prove(error, Failure::Transient) => {
            warn!(task_index, "{proof_type} prover call failed transiently; retrying: {error:#}");
            return Ok(OnDemandOutcome::Deferred);
        }
        ProveError::Prove(error, Failure::ProverUnavailable) if !runtime.is_fleet() => {
            warn!(task_index, "{proof_type} prover is unavailable; retrying: {error:#}");
            return Ok(OnDemandOutcome::Deferred);
        }
        error => {
            return Err(stop_for_failure(
                runtime,
                error,
                &format!("{proof_type} task {task_index}"),
            ));
        }
    };
    let attempt = attempts.entry(task_index).or_default();
    *attempt += 1;
    error!(task_index, attempt = *attempt, "{proof_type} proof failed: {error:#}");
    if *attempt < runtime.max_attempts() {
        return Ok(OnDemandOutcome::Deferred);
    }
    attempts.remove(&task_index);
    let completion = OnDemandProofCompletion {
        path_to_proof: output,
        proof_state: ProofState::Failed.to_i64(),
        total_time_to_proof: elapsed.as_millis() as i64,
        ..Default::default()
    };
    let affected = local_db
        .acquire()
        .await?
        .complete_on_demand_proof_if_new(table, task_index, &completion)
        .await?;
    Ok(if affected > 0 { OnDemandOutcome::Failed } else { OnDemandOutcome::Cancelled })
}

/// Closes a task whose inputs can never be proven, so the queue moves past it.
pub(crate) async fn fail_invalid_on_demand_task(
    local_db: &LocalDB,
    table: OnDemandProofTable,
    task_index: i64,
    reason: &str,
) -> anyhow::Result<()> {
    warn!(task_index, "{} task cannot be proven; marking it failed: {reason}", table.table_name());
    let completion =
        OnDemandProofCompletion { proof_state: ProofState::Failed.to_i64(), ..Default::default() };
    local_db
        .acquire()
        .await?
        .complete_on_demand_proof_if_new(table, task_index, &completion)
        .await?;
    Ok(())
}

/// The proof attempt metric outcome of a failure.
pub(crate) fn failure_outcome(error: &ProveError) -> &'static str {
    match error {
        ProveError::Prove(_, Failure::Transient) => "transient",
        ProveError::Prove(_, Failure::ProverUnavailable) => "unavailable",
        ProveError::Prove(_, Failure::Fatal) | ProveError::Save(_) => "failed",
    }
}

/// Stops proving after a failure that must not be retried in place: a proof that could
/// not be published, or (in Fleet mode) a prover failure that needs a fresh GPU server.
fn stop_for_failure(runtime: &ProverRuntime, error: ProveError, what: &str) -> anyhow::Error {
    runtime.begin_shutdown();
    match error {
        ProveError::Save(error) => error.context(format!("failed to publish the proof of {what}")),
        ProveError::Prove(error, _) => error
            .context(format!("prover failed on {what}; exiting so Fleet restarts the GPU server")),
    }
}

/// Handles a failed chain proof. The batch is retried next round unless the failure
/// must stop the worker (see [`stop_for_failure`]).
pub(crate) fn settle_chain_failure(
    runtime: &ProverRuntime,
    error: ProveError,
    chain: &str,
) -> anyhow::Result<()> {
    match error {
        ProveError::Prove(error, failure)
            if failure != Failure::ProverUnavailable || !runtime.is_fleet() =>
        {
            error!("{chain} proof failed; retrying the batch: {error:#}");
            Ok(())
        }
        error => Err(stop_for_failure(runtime, error, &format!("a {chain} batch"))),
    }
}

pub(crate) async fn fetch_next_commit_task_index(local_db: &LocalDB) -> anyhow::Result<usize> {
    let mut storage_processor = local_db.acquire().await?;
    let proofs = storage_processor
        .find_all_running_task_proofs_by_name(CommitChainProofBuilder::name())
        .await?;
    Ok(proofs.len())
}

pub(crate) async fn fetch_latest_long_running_task(
    local_db: &LocalDB,
    chain_name: String,
) -> anyhow::Result<Option<LongRunningTaskProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.find_latest_long_running_task_proof_by_name(chain_name).await
}

pub(crate) async fn fetch_latest_long_running_task_by_state(
    local_db: &LocalDB,
    chain_name: String,
    proof_state: i64,
) -> anyhow::Result<Option<LongRunningTaskProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .find_latest_long_running_task_proof_by_name_and_state(chain_name, proof_state)
        .await
}

/// The outcome of preparing the next on-demand task.
#[derive(Debug)]
pub(crate) enum OnDemandFetch {
    /// Inputs are ready; prove the task.
    Ready(Box<OnDemandTask>),
    /// Inputs are not available yet; move on and retry the task on a later pass.
    NotReady(i64),
    /// Inputs can never become valid; the task is closed as failed.
    Invalid(i64, String),
}

/// A task whose stored inputs can never be proven.
#[derive(Debug)]
struct InvalidTask(String);

impl std::fmt::Display for InvalidTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidTask {}

fn invalid_task(reason: String) -> anyhow::Error {
    InvalidTask(reason).into()
}

enum OnDemandRow {
    Operator(OperatorProof),
    Watchtower(WatchtowerProof),
}

impl OnDemandRow {
    fn id(&self) -> i64 {
        match self {
            Self::Operator(task) => task.id,
            Self::Watchtower(task) => task.id,
        }
    }
}

/// Where the next on-demand fetch starts. Fetches alternate between a forward
/// cursor, which only moves ahead (wrapping at the end of the queue), and a
/// retry cursor, which walks from the oldest task up to where the forward
/// cursor stood when that pass began. A long run of tasks that are not ready
/// cannot keep a later task from its turn, and every task skipped earlier is
/// revisited on each retry pass, even while new tasks keep coming.
pub(crate) struct OnDemandCursor {
    forward: i64,
    retry: i64,
    /// The forward position when the current retry pass began; the pass
    /// starts over once it reaches it.
    retry_end: i64,
    retry_turn: bool,
}

impl OnDemandCursor {
    pub(crate) fn new() -> Self {
        Self { forward: 0, retry: 0, retry_end: 0, retry_turn: false }
    }

    /// The id the next fetch starts after.
    pub(crate) fn after_id(&self) -> i64 {
        if self.retry_turn { self.retry } else { self.forward }
    }

    /// Records the task just handed out and passes the turn to the other cursor.
    pub(crate) fn advance(&mut self, task_index: i64) {
        if self.retry_turn {
            // The forward cursor moves as fast as this one, so a pass ends at
            // a fixed point, not at the moving forward cursor. A fetch that
            // wrapped also ends the pass.
            if task_index >= self.retry_end || task_index <= self.retry {
                self.retry = 0;
                self.retry_end = self.forward;
            } else {
                self.retry = task_index;
            }
        } else {
            self.forward = task_index;
        }
        self.retry_turn = !self.retry_turn;
    }

    /// Starts both cursors from the oldest task; used when no task is `New`.
    pub(crate) fn rescan(&mut self) {
        *self = Self::new();
    }
}

/// The first `New` task after `after_id`, wrapping to the start of the queue
/// so one task that cannot be prepared does not block the others.
async fn next_on_demand_row(
    storage_processor: &mut store::localdb::StorageProcessor<'_>,
    is_watchtower: bool,
    after_id: i64,
) -> anyhow::Result<Option<OnDemandRow>> {
    for after in [after_id, 0] {
        let row = if is_watchtower {
            storage_processor.find_next_watchtower_proof(after).await?.map(OnDemandRow::Watchtower)
        } else {
            storage_processor.find_next_operator_proof(after).await?.map(OnDemandRow::Operator)
        };
        if row.is_some() || after == 0 {
            return Ok(row);
        }
    }
    Ok(None)
}

async fn read_watchtower_challenge_details<'a>(
    storage_processor: &mut store::localdb::StorageProcessor<'a>,
    row: OnDemandRow,
) -> anyhow::Result<(
    i64,
    i64,
    Option<String>,
    Vec<Option<String>>,
    Vec<bool>,
    Vec<String>,
    Option<String>,
    Option<String>,
)> {
    let (
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        operator_committed_blockhash,
    ) = match row {
        OnDemandRow::Watchtower(task) => {
            tracing::info!("watchtower task: {task:?}");
            // NOTE: we use watchtower challenge init txid to calculate the height
            let watchtower_challenge_txids: Vec<Option<String>> =
                vec![Some(task.challenge_init_txid.0.to_string())];
            let pubkeys: Vec<String> = vec![task.public_key.clone()];
            (
                task.id,
                task.execution_layer_block_number,
                None,
                watchtower_challenge_txids,
                vec![true],
                pubkeys,
                Some(task.graph_id.as_simple().to_string()),
                None,
            )
        }
        OnDemandRow::Operator(task) => {
            //fetch watchtower info
            tracing::info!("operator task: {task:?}");
            let watchtower_info: Vec<WatchtowerProof> = storage_processor
                .find_watchtower_proof_by_instance_and_graph(&task.instance_id, &task.graph_id)
                .await?;
            tracing::info!("watchtower info: {watchtower_info:?}");
            let challenge_init_txids: Vec<String> = watchtower_info
                .iter()
                .map(|w| w.challenge_init_txid.0.to_string())
                .collect::<Vec<_>>();
            if challenge_init_txids.is_empty() {
                return Err(invalid_task(format!(
                    "No watchtower challenge info found for instance {} and graph_id {}",
                    task.instance_id, task.graph_id
                )));
            }
            if let Some(first) = challenge_init_txids.first()
                && !challenge_init_txids.iter().all(|x| first == x)
            {
                return Err(invalid_task(format!(
                    "Inconsistent watchtower challenge info from instance {} and graph_id {}",
                    task.instance_id, task.graph_id
                )));
            }
            let challenge_txids: Vec<Option<String>> = watchtower_info
                .iter()
                .map(|w| w.included.then(|| w.challenge_txid.0.to_string()))
                .collect::<Vec<_>>();
            let challenge_public_keys: Vec<String> =
                watchtower_info.iter().map(|w| w.public_key.clone()).collect::<Vec<_>>();
            let included_watchtowers: Vec<bool> =
                watchtower_info.iter().map(|w| w.included).collect::<Vec<_>>();
            (
                task.id,
                task.execution_layer_block_number,
                challenge_init_txids.first().cloned(),
                challenge_txids,
                included_watchtowers,
                challenge_public_keys,
                Some(task.graph_id.as_simple().to_string()),
                Some(task.operator_committed_blockhash),
            )
        }
    };

    tracing::info!(
        "operator_committed_blockhash {operator_committed_blockhash:?}, execution_layer_block_number {execution_layer_block_number}"
    );
    Ok((
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        operator_committed_blockhash,
    ))
}

/// Fetches and prepares the next watchtower or operator task after `after_id`.
/// Returns `None` when no task is `New`.
#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn fetch_on_demand_task(
    local_db: &LocalDB,
    is_watchtower: bool,
    after_id: i64,
    bitcoin_network: Network,
    esplora_url: &str,
) -> anyhow::Result<Option<OnDemandFetch>> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(row) = next_on_demand_row(&mut storage_processor, is_watchtower, after_id).await?
    else {
        return Ok(None);
    };
    let task_index = row.id();
    let prepared = prepare_on_demand_task(
        &mut storage_processor,
        row,
        is_watchtower,
        bitcoin_network,
        esplora_url,
    )
    .await;
    Ok(Some(match prepared {
        Ok(Some(task)) => OnDemandFetch::Ready(Box::new(task)),
        Ok(None) => OnDemandFetch::NotReady(task_index),
        Err(error) => match error.downcast::<InvalidTask>() {
            Ok(InvalidTask(reason)) => OnDemandFetch::Invalid(task_index, reason),
            Err(error) => {
                warn!(task_index, "on-demand task inputs are unavailable: {error:#}");
                OnDemandFetch::NotReady(task_index)
            }
        },
    }))
}

async fn prepare_on_demand_task(
    storage_processor: &mut store::localdb::StorageProcessor<'_>,
    row: OnDemandRow,
    is_watchtower: bool,
    bitcoin_network: Network,
    esplora_url: &str,
) -> anyhow::Result<Option<OnDemandTask>> {
    let (
        task_index,
        execution_layer_block_number,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        operator_committed_blockhash,
    ) = read_watchtower_challenge_details(storage_processor, row).await?;

    if !is_watchtower && operator_committed_blockhash.is_none() {
        tracing::warn!("Watchtower challenge tx is not confirmed yet.");
        return Ok(None);
    }

    // If we finish the sequencer set commitment shortly, the latest commit txid is confirmed after `btc_block_number`, which leads to the latest_commit_txid not included in header chain proof.

    let mut largest_btc_block_height = 0;
    let btc_client = BTCClient::new(bitcoin_network, Some(esplora_url));
    for txid in watchtower_challenge_txids.iter().flatten() {
        let txid = Txid::from_str(txid)?;
        let block_height = match btc_client.get_tx_status(&txid).await {
            Ok(tx_status) => {
                if let Some(block_height) = tx_status.block_height {
                    block_height
                } else {
                    tracing::warn!(
                        "Challenge tx {txid} is not confirmed yet, wait for the next round"
                    );
                    return Ok(None);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Challenge tx {txid} is not found in BTC node, it might be mempool tx, wait for the next round, error: {e}"
                );
                return Ok(None);
            }
        };
        if block_height > largest_btc_block_height {
            largest_btc_block_height = block_height;
        }
    }

    let btc_proof_height = if is_watchtower {
        largest_btc_block_height
    } else {
        let hash = operator_committed_blockhash.as_ref().unwrap();
        let hash = BlockHash::from_str(hash).map_err(|error| {
            invalid_task(format!("invalid committed block hash {hash}: {error}"))
        })?;
        let committed_height = match btc_client.get_block_by_hash(&hash).await {
            Ok(Some(block)) => block.bip34_block_height().map_err(|error| {
                invalid_task(format!("committed block {hash} has no BIP34 height: {error}"))
            })? as u32,
            Ok(None) => {
                tracing::warn!(
                    "Operator committed block hash {hash} is not found in BTC, it might be mempool tx, wait for the next round"
                );
                return Ok(None);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch operator committed block height by hash {hash}, error: {e}"
                );
                return Ok(None);
            }
        };
        if committed_height < largest_btc_block_height {
            return Err(invalid_task(format!(
                "operator committed block height {committed_height} is lower than challenge tx height {largest_btc_block_height}"
            )));
        }
        committed_height
    };

    let header_chain_input_proof = match storage_processor
        .find_long_running_task_proof_including_block_number(
            btc_proof_height as i64,
            HeaderChainProofBuilder::name(),
        )
        .await?
    {
        Some(d) => d,
        None => {
            tracing::warn!(
                "Header chain proof is not ready for block: {}, proof not ready",
                btc_proof_height
            );
            return Ok(None);
        }
    };
    tracing::info!("header_chain_input_proof: {header_chain_input_proof:?}");
    let header_chain_input_proof = header_chain_input_proof.path_to_proof.unwrap();

    // state chain: find the proof that includes the execution_layer_block_number
    // * Watchtower can use the latest statechain
    // * Operator must use the height at which it's proceedWithdraw is confirmed.
    tracing::info!("execution_layer_block_number: {execution_layer_block_number}");
    let state_chain_input_proof_result = if execution_layer_block_number > 0 {
        storage_processor
            .find_long_running_task_proof_including_block_number(
                execution_layer_block_number,
                StateChainProofBuilder::name(),
            )
            .await?
    } else {
        storage_processor
            .find_latest_long_running_task_proof_by_name_and_state(
                StateChainProofBuilder::name(),
                ProofState::Proven.to_i64(),
            )
            .await?
    };

    let state_chain_input_proof = match state_chain_input_proof_result {
        Some(d) => {
            if d.proof_state != ProofState::Proven.to_i64() {
                tracing::info!(
                    "State chain proof is not ready for block: {execution_layer_block_number}, proof not ready"
                );
                return Ok(None);
            } else {
                d
            }
        }
        None => {
            tracing::info!(
                "State chain proof is not ready for block: {execution_layer_block_number}, record not found"
            );
            return Ok(None);
        }
    };
    let state_chain_input_proof = state_chain_input_proof.path_to_proof.unwrap();

    // commit chain
    let commit_chain_input_proof = match storage_processor
        .find_long_running_task_proof_including_block_number(
            btc_proof_height as i64,
            CommitChainProofBuilder::name(),
        )
        .await?
    {
        Some(d) => d,
        None => {
            tracing::error!("Commit chain input proof is not ready");
            return Ok(None);
        }
    };
    tracing::info!("commit_chain_input_proof: {commit_chain_input_proof:?}");
    let commit_chain_input_proof = commit_chain_input_proof.path_to_proof.unwrap();
    let commits_file = format!("{commit_chain_input_proof}.commits");
    let commits: Vec<commit_chain::CircuitCommit> =
        match serde_json::from_str(&std::fs::read_to_string(&commits_file)?) {
            Ok(commits) => commits,
            Err(err) => {
                tracing::warn!("Failed to read commit-chain commits, error: {err}");
                return Ok(None);
            }
        };
    let latest_sequencer_commit_txid = match commits.first() {
        Some(commit) => commit.commit_txn.compute_txid().to_string(),
        None => {
            tracing::warn!("Commit-chain proof does not contain any commits yet");
            return Ok(None);
        }
    };
    Ok(Some(OnDemandTask {
        task_index,
        latest_sequencer_commit_txid,
        header_chain_input_proof,
        commit_chain_input_proof,
        state_chain_input_proof,
        watchtower_challenge_init_txid,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_public_keys,
        graph_id,
        operator_committed_blockhash,
    }))
}

/// table schema: (start, end, path_to_proof, cycles, update_time, table_name)
/// * table_name: header-chain | state-chain | commit-chain
pub(crate) async fn create_long_running_task(
    local_db: &LocalDB,
    start: i64,
    batch_size: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    chain_name: String,
    total_time_to_proof: i64,
    proving_time: i64,
    proof_state: ProofState,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .create_long_running_task_proof(&LongRunningTaskProof {
            block_start: start,
            block_end: start + batch_size,
            chain_name,
            path_to_proof: Some(path_to_proof),
            public_value_hex: Some(public_value_hex),
            proof_size,
            cycles: cycles as i64,
            proof_state: proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            zkm_version,
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await
}

/// Persists a Commit proof, replacing prior Commit records for a Genesis replay.
pub(crate) async fn create_commit_chain_proof(
    local_db: &LocalDB,
    start: i64,
    batch_size: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    chain_name: String,
    replace_existing: bool,
    total_time_to_proof: i64,
    proving_time: i64,
    proof_state: ProofState,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.start_transaction().await?;
    if replace_existing {
        storage_processor
            .delete_long_running_task_proofs_by_name(&CommitChainProofBuilder::name())
            .await?;
    } else {
        // We use start directly since block_end is initialized by u64::MAX.
        let previous_proof = storage_processor
            .find_long_running_task_proof_including_block_number(start, chain_name.clone())
            .await?;
        tracing::info!("previous_proof: {previous_proof:?}");
        if let Some(previous_proof) = previous_proof {
            let prev_batch_size = start - previous_proof.block_start;
            tracing::info!("update previous proof from {start} batch_size: {prev_batch_size}");
            storage_processor
                .update_long_running_task_proof_state(
                    previous_proof.block_start,
                    &previous_proof.chain_name,
                    prev_batch_size,
                    previous_proof.proof_state,
                )
                .await?;
        }
    }
    let affected = storage_processor
        .create_long_running_task_proof(&LongRunningTaskProof {
            block_start: start,
            block_end: start + batch_size,
            chain_name,
            path_to_proof: Some(path_to_proof),
            public_value_hex: Some(public_value_hex),
            proof_size,
            cycles: cycles as i64,
            proof_state: proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            zkm_version,
            extra: None,
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
        })
        .await?;
    storage_processor.commit().await?;
    Ok(affected)
}

pub(crate) async fn update_long_running_task(
    local_db: &LocalDB,
    start_index: i64,
    batch_size: i64,
    path_to_proof: String,
    public_value_hex: String,
    proof_size: i64,
    cycles: u64,
    proof_state: ProofState,
    chain_name: String,
    proving_time: i64,
    zkm_version: String,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    let task = storage_processor
        .find_long_running_task_proof_including_block_number(start_index, chain_name.clone())
        .await?;
    if task.is_none() {
        anyhow::bail!(
            "Long running task not found for chain: {chain_name}, start_index: {start_index}"
        );
    }
    let total_time_to_proof = (current_time_secs() - task.unwrap().created_at) * 1000;
    storage_processor
        .update_long_running_task_proof_success(
            start_index,
            &chain_name,
            batch_size,
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles as i64,
            proof_state.to_i64(),
            total_time_to_proof,
            proving_time,
            &zkm_version,
        )
        .await
}

/// The stored form of a Watchtower key: compressed with even parity, as in
/// the Operator's graph list. Only the x-only key matters to the circuit.
pub(crate) fn watchtower_task_key(public_key: &XOnlyPublicKey) -> String {
    format!("02{public_key}")
}

/// table schema: (index, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid, path_to_proof, cycles, state, update_time)
/// * index: incremental id
/// * state: 0-new, 1-doing, 2-done, 3-failed
///
/// Invoked by API.
///
/// Adds a Watchtower task. Returns `false` when the graph's Operator task
/// already fixed its Watchtower list and this key has no slot in it.
pub(crate) async fn add_watchtower_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: String,
    challenge_init_txid: String,
    execution_layer_block_number: i64,
) -> anyhow::Result<bool> {
    let mut storage_processor = local_db.start_transaction().await?;
    // The Operator task creates a row for every slot of the graph, so once it
    // exists any key without a row is not one of the graph's Watchtowers.
    if storage_processor
        .find_operator_proof_by_instance_and_graph(&instance_id, &graph_id)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    storage_processor
        .create_watchtower_proof(&WatchtowerProof {
            id: 1,
            instance_id,
            graph_id,
            public_key,
            challenge_init_txid: Txid::from_str(&challenge_init_txid)?.into(),
            proof_state: ProofState::New.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            execution_layer_block_number,
            included: true,
            ..Default::default()
        })
        .await?;
    storage_processor.commit().await?;
    Ok(true)
}

pub(crate) async fn find_watchtower_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: &str,
) -> anyhow::Result<Option<WatchtowerProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .find_watchtower_proof_by_instance_and_graph_and_pubkey(&instance_id, &graph_id, public_key)
        .await
}

pub(crate) async fn update_watchtower_task_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    public_key: &str,
    old_proof_state: ProofState,
    new_proof_state: ProofState,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .update_watchtower_proof_state_with_instance_graph_pubkey(
            &instance_id,
            &graph_id,
            public_key,
            old_proof_state.to_i64(),
            new_proof_state.to_i64(),
        )
        .await
}

/// table schema: (index, instance_id, graph_id, execution_layer_block_number, path_to_proof, cycles, state, update_time)
/// * state: 0-new, 1-doing, 2-done, 3-failed
/// * execution_layer_block_number: proceedWithdraw's block number
/// * index: incremental id
/// Invocated by API
#[tracing::instrument(level = "info", skip(local_db))]
pub(crate) async fn add_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    operator_committed_blockhash: String,
    execution_layer_block_number: i64,
    watchtower_challenge_txids: Vec<Option<String>>,
    included_watchtowers: Vec<bool>,
    watchtower_challenge_init_txid: String,
    watchtower_challenge_pubkeys: Vec<String>,
) -> anyhow::Result<u64> {
    let graph_watchtower_xonly_keys = validate_indexed_watchtower_challenges(
        &watchtower_challenge_txids,
        &included_watchtowers,
        &watchtower_challenge_pubkeys,
    )?;
    let mut storage_processor = local_db.start_transaction().await?;

    let existing_watchtower_proof_task = storage_processor
        .find_watchtower_proof_by_instance_and_graph(&instance_id, &graph_id)
        .await?;
    tracing::info!("existing_watchtower_proof_task: {:?}", existing_watchtower_proof_task);
    let mut existing_watchtower_indices = HashSet::new();
    for task in &existing_watchtower_proof_task {
        let node_index = parse_xonly_public_key(&task.public_key).ok().and_then(|xonly_key| {
            graph_watchtower_xonly_keys.iter().position(|graph_key| *graph_key == xonly_key)
        });
        // A registered Watchtower may submit for any graph; a key outside this
        // graph's list has no slot and is dropped instead of failing the task.
        let Some(node_index) = node_index else {
            tracing::warn!(
                "dropping watchtower task {} with key {} outside graph {}",
                task.id,
                task.public_key,
                graph_id
            );
            storage_processor.delete_watchtower_proof(task.id).await?;
            continue;
        };
        if !existing_watchtower_indices.insert(node_index) {
            anyhow::bail!(
                "multiple watchtower proof tasks map to node index {node_index} in graph {graph_id}"
            );
        }
        storage_processor
            .update_watchtower_proof_node_index(task.id, &instance_id, &graph_id, node_index as i32)
            .await?;
    }

    let missing_watchtower_indices: Vec<usize> = (0..graph_watchtower_xonly_keys.len())
        .filter(|node_index| !existing_watchtower_indices.contains(node_index))
        .collect();
    tracing::info!("missing_watchtower_indices: {:?}", missing_watchtower_indices);
    // insert timeout watchtower proof task with failed state.
    for node_index in missing_watchtower_indices {
        let stored_txid = watchtower_challenge_txids[node_index]
            .as_deref()
            .unwrap_or(&watchtower_challenge_init_txid);
        let task = WatchtowerProof {
            id: 1,
            instance_id,
            graph_id,
            challenge_init_txid: Txid::from_str(&watchtower_challenge_init_txid)?.into(),
            challenge_txid: Txid::from_str(stored_txid)?.into(),
            proof_state: ProofState::Failed.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            execution_layer_block_number,
            // The Graph key identifies the missing Watchtower slot.
            public_key: watchtower_task_key(&XOnlyPublicKey::from_slice(
                &graph_watchtower_xonly_keys[node_index],
            )?),
            node_index: node_index as i32,
            included: included_watchtowers[node_index],
            ..Default::default()
        };
        let affected = storage_processor.create_watchtower_proof(&task).await?;
        tracing::info!(
            "mark timeout watchtower proof as failed, node_index: {node_index}, affected rows: {affected}",
        );
    }

    // update watchtower's challenge txid.
    for (i, txid) in watchtower_challenge_txids.iter().enumerate() {
        let stored_txid = txid.as_deref().unwrap_or(&watchtower_challenge_init_txid);
        let affected = storage_processor
            .update_watchtower_proof_challenge_txid(
                &instance_id,
                &graph_id,
                i as i32,
                stored_txid,
                included_watchtowers[i],
            )
            .await?;
        tracing::info!("update watchtower proof, node_index: {i} affected rows: {affected}",);
    }

    let affected_rows = storage_processor
        .create_operator_proof(&OperatorProof {
            id: 1,
            instance_id,
            graph_id,
            execution_layer_block_number,
            proof_state: ProofState::New.to_i64(),
            created_at: current_time_secs(),
            updated_at: current_time_secs(),
            cycles: 0,
            operator_committed_blockhash,
            ..Default::default()
        })
        .await?;
    storage_processor.commit().await?;
    Ok(affected_rows)
}

fn validate_indexed_watchtower_challenges(
    challenge_txids: &[Option<String>],
    included_watchtowers: &[bool],
    challenge_pubkeys: &[String],
) -> anyhow::Result<Vec<[u8; 32]>> {
    if challenge_txids.len() != included_watchtowers.len()
        || challenge_txids.len() != challenge_pubkeys.len()
    {
        anyhow::bail!(
            "watchtower challenge txids, included bitmap, and public keys must have equal lengths"
        );
    }
    let mut seen_keys = HashSet::new();
    let mut xonly_keys = Vec::with_capacity(challenge_pubkeys.len());
    for (index, public_key) in challenge_pubkeys.iter().enumerate() {
        let xonly_key = parse_xonly_public_key(public_key).map_err(|error| {
            anyhow::anyhow!("invalid watchtower public key at index {index}: {error}")
        })?;
        anyhow::ensure!(
            seen_keys.insert(xonly_key),
            "duplicate watchtower x-only public key at index {index}"
        );
        xonly_keys.push(xonly_key);
    }

    let mut seen = HashSet::new();
    for (index, (txid, included)) in challenge_txids.iter().zip(included_watchtowers).enumerate() {
        match (txid, included) {
            (Some(txid), true) => {
                Txid::from_str(txid)?;
                if !seen.insert(txid) {
                    anyhow::bail!("duplicate watchtower challenge txid at index {index}");
                }
            }
            (None, false) => {}
            (Some(_), false) | (None, true) => {
                anyhow::bail!(
                    "watchtower challenge txid and included flag disagree at index {index}"
                );
            }
        }
    }
    Ok(xonly_keys)
}

fn parse_xonly_public_key(public_key: &str) -> anyhow::Result<[u8; 32]> {
    Ok(PublicKey::from_str(public_key)?.inner.x_only_public_key().0.serialize())
}

pub(crate) async fn find_operator_task(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> anyhow::Result<Option<OperatorProof>> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor.find_operator_proof_by_instance_and_graph(&instance_id, &graph_id).await
}

pub(crate) async fn update_operator_task_state(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    old_proof_state: ProofState,
    new_proof_state: ProofState,
) -> anyhow::Result<u64> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .update_operator_proof_state_with_instance_graph(
            &instance_id,
            &graph_id,
            old_proof_state.to_i64(),
            new_proof_state.to_i64(),
        )
        .await
}

#[inline(always)]
pub(crate) fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use store::create_local_db;
    use uuid::Uuid;

    /// Mirrors `next_on_demand_row`: the first id after `after`, wrapping.
    fn next_task(ids: &[i64], after: i64) -> Option<i64> {
        ids.iter().copied().find(|id| *id > after).or_else(|| ids.first().copied())
    }

    /// Polls until `ready` is handed out; returns the number of polls taken.
    fn polls_until(cursor: &mut OnDemandCursor, ids: &[i64], ready: i64, limit: usize) -> usize {
        for poll in 1..=limit {
            let task = next_task(ids, cursor.after_id()).unwrap();
            if task == ready {
                return poll;
            }
            cursor.advance(task);
        }
        panic!("task {ready} was not reached within {limit} polls");
    }

    #[test]
    fn a_long_not_ready_prefix_does_not_starve_the_tail() {
        // 600 tasks that never become ready, then a ready one. At one poll a
        // second this prefix outlasts any fixed rescan interval.
        let ids: Vec<i64> = (1..=601).collect();
        // The forward cursor moves on every other poll.
        let polls = polls_until(&mut OnDemandCursor::new(), &ids, 601, 2 * 601);
        assert!(polls > 600, "the prefix is still visited first");
    }

    #[test]
    fn a_skipped_task_is_revisited_while_new_tasks_keep_coming() {
        // A new task arrives on every poll, so the forward cursor never wraps.
        // Task 1 is handed out on the first poll; it must come round again.
        let mut ids: Vec<i64> = (1..=10).collect();
        let mut cursor = OnDemandCursor::new();
        let mut revisited_at = None;
        for poll in 1..=40 {
            let task = next_task(&ids, cursor.after_id()).unwrap();
            if task == 1 && poll > 1 {
                revisited_at = Some(poll);
                break;
            }
            cursor.advance(task);
            ids.push(ids.last().unwrap() + 1);
        }
        assert!(revisited_at.is_some(), "task 1 was never revisited");
        cursor.rescan();
        assert_eq!(cursor.after_id(), 0);
    }

    #[test]
    fn an_old_task_becoming_ready_later_is_revisited_under_continuous_arrivals() {
        let mut ids: Vec<i64> = (1..=10).collect();
        let mut cursor = OnDemandCursor::new();
        let mut visits = Vec::new();

        // Every row stays New/NotReady, except task 1 whose external inputs
        // become available at poll 10. New arrivals keep the forward scan from
        // wrapping. Revisiting task 1 before poll 10 cannot service it.
        for poll in 1..=10_000 {
            let task = next_task(&ids, cursor.after_id()).unwrap();
            if task == 1 {
                visits.push(poll);
                if poll >= 10 {
                    return;
                }
            }
            cursor.advance(task);
            ids.push(ids.last().unwrap() + 1);
        }

        panic!("task 1 became ready at poll 10 but was never retried; visits: {visits:?}");
    }

    #[tokio::test]
    async fn test_add_watchtower_task() {
        let db_path = std::env::var("TEST_DB")
            .unwrap_or("sqlite:/tmp/.bitvm-node-sd.db?mode=rwc".to_string());
        let local_db = create_local_db(&db_path).await;
        let instance_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let public_key =
            "0272efe7ccae21d2541ad85d4f2961f2e5593c29dc8bc37bf87035fc2d5527a651".to_string();
        let challenge_init_txid =
            "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246".to_string();
        let number = 9511055;
        add_watchtower_task(
            &local_db,
            instance_id,
            graph_id,
            public_key,
            challenge_init_txid,
            number,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_add_operator_proof() {
        tracing_subscriber::fmt::init();
        let db_path =
            std::env::var("TEST_DB").unwrap_or("sqlite:.bitvm-node-sd.db?mode=rwc".to_string());
        let local_db = create_local_db(&db_path).await;
        let instance_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let graph_id = Uuid::from_str("00112233445566778899aabbccddeeff").unwrap();
        let number = 9511055;
        let watchtower_challenge_txids = vec![
            Some("4506cf35cd70b3006fe3ce4a87ca1f9b0a76f348cfb529423e2d4c163c28d604".to_string()),
            None,
        ];
        let operator_committed_blockhash =
            "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246".to_string();

        let watchtower_challenge_init_txid =
            "7f7b4344adb1b8937ddb7124e4f8bba80ee9adf5e8119de76ca8736816bda246".to_string();
        let watchtower_challenge_pubkeys = vec![
            "0272efe7ccae21d2541ad85d4f2961f2e5593c29dc8bc37bf87035fc2d5527a651".to_string(),
            "03a34f3558f2b2f2e6c3d3f4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f".to_string(),
        ];

        let included_watchtowers = vec![true, false];
        add_operator_task(
            &local_db,
            instance_id,
            graph_id,
            operator_committed_blockhash,
            number,
            watchtower_challenge_txids,
            included_watchtowers,
            watchtower_challenge_init_txid,
            watchtower_challenge_pubkeys,
        )
        .await
        .unwrap();

        //use crate::task::read_watchtower_challenge_details;
        //let is_watchtower = false;
        //let bitcoin_network = bitcoin::Network::Regtest;
        //let esplora_url = "http://localhost:13002";
        //let mut storage_processor = local_db.acquire().await.unwrap();
        //let result = read_watchtower_challenge_details(&mut storage_processor, is_watchtower, bitcoin_network, esplora_url).await.unwrap();
        //println!("result: {:?}", result);
        //assert!(result.3.len() == 2);
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use store::create_local_db;

    // Nothing listens here, so every Bitcoin lookup fails as a transient error.
    const UNREACHABLE_ESPLORA: &str = "http://127.0.0.1:9";

    async fn operator_task(local_db: &LocalDB, with_watchtower: bool) -> i64 {
        let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
        let mut storage = local_db.acquire().await.unwrap();
        if with_watchtower {
            let txid = Txid::from_str(&"22".repeat(32)).unwrap();
            let watchtower = WatchtowerProof {
                instance_id,
                graph_id,
                public_key: "pk".to_string(),
                challenge_init_txid: txid.into(),
                challenge_txid: txid.into(),
                proof_state: ProofState::Failed.to_i64(),
                ..Default::default()
            };
            storage.create_watchtower_proof(&watchtower).await.unwrap();
        }
        let task = OperatorProof {
            instance_id,
            graph_id,
            operator_committed_blockhash: "11".repeat(32),
            proof_state: ProofState::New.to_i64(),
            ..Default::default()
        };
        storage.create_operator_proof(&task).await.unwrap();
        storage
            .find_operator_proof_by_instance_and_graph(&instance_id, &graph_id)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    async fn fetch(local_db: &LocalDB, after_id: i64) -> OnDemandFetch {
        fetch_on_demand_task(local_db, false, after_id, Network::Regtest, UNREACHABLE_ESPLORA)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn a_task_that_cannot_be_prepared_does_not_block_the_queue() {
        let local_db = create_local_db("sqlite::memory:").await;
        // No watchtower rows: this task can never be proven.
        let invalid = operator_task(&local_db, false).await;
        // Its Bitcoin data is not reachable yet: retried on a later pass.
        let waiting = operator_task(&local_db, true).await;

        let OnDemandFetch::Invalid(task_index, _) = fetch(&local_db, 0).await else {
            panic!("the first task should be invalid");
        };
        assert_eq!(task_index, invalid);
        fail_invalid_on_demand_task(&local_db, OnDemandProofTable::Operator, invalid, "test")
            .await
            .unwrap();
        assert!(
            matches!(fetch(&local_db, invalid).await, OnDemandFetch::NotReady(id) if id == waiting)
        );
        // Past the end the queue wraps around, and the failed task is gone.
        assert!(
            matches!(fetch(&local_db, waiting).await, OnDemandFetch::NotReady(id) if id == waiting)
        );
        assert_eq!(
            local_db
                .acquire()
                .await
                .unwrap()
                .get_on_demand_proof_state(OnDemandProofTable::Operator, invalid)
                .await
                .unwrap(),
            Some(ProofState::Failed.to_i64())
        );
    }
}

#[cfg(test)]
mod watchtower_slot_tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};
    use store::create_local_db;

    fn key(seed: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap().x_only_public_key().0
    }

    async fn add(local_db: &LocalDB, graph_id: Uuid, key: &XOnlyPublicKey) -> anyhow::Result<bool> {
        add_watchtower_task(
            local_db,
            Uuid::nil(),
            graph_id,
            watchtower_task_key(key),
            "22".repeat(32),
            1,
        )
        .await
    }

    #[tokio::test]
    async fn operator_task_keeps_only_the_graphs_watchtower_slots() {
        let local_db = create_local_db("sqlite::memory:").await;
        let graph_id = Uuid::new_v4();
        let (member, outsider) = (key(1), key(2));
        assert!(add(&local_db, graph_id, &outsider).await.unwrap());
        assert!(add(&local_db, graph_id, &member).await.unwrap());
        // One row per key, whatever spelling the Watchtower used.
        assert!(add(&local_db, graph_id, &member).await.is_err());

        // The Operator lists the member as compressed with odd parity.
        let member_odd = format!("03{member}");
        add_operator_task(
            &local_db,
            Uuid::nil(),
            graph_id,
            "11".repeat(32),
            1,
            vec![None],
            vec![false],
            "22".repeat(32),
            vec![member_odd],
        )
        .await
        .unwrap();

        let rows = local_db
            .acquire()
            .await
            .unwrap()
            .find_watchtower_proof_by_instance_and_graph(&Uuid::nil(), &graph_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].public_key, watchtower_task_key(&member));
        assert_eq!(rows[0].node_index, 0);
        // The list is fixed now; a key outside it cannot add a task.
        assert!(!add(&local_db, graph_id, &outsider).await.unwrap());
    }
}
