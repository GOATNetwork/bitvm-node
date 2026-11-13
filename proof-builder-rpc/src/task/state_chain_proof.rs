use crate::prover::{Cancelled, ProverRuntime};
use crate::prover::{Failure, ProveError};
use crate::task::ProofState::{Failed, New, Proven, Proving};
use crate::task::fetch_latest_long_running_task_by_state;
use crate::task::{
    TaskOptions, create_long_running_task, failure_outcome, settle_chain_failure,
    update_long_running_task,
};
use crate::{ProofBuilderConfig, task::fetch_latest_long_running_task};
use proof_builder::{ProofBuilder, ProofRequest};
use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};
use std::sync::Arc;
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api::metrics_service::{ApiMetricsState, STATE_CHAIN_PROOF};

/// Consecutive fatal failures of one batch before its snapshot is dropped and fetched
/// again: the configured RPC may have served wrong block data.
const FATAL_RUNS_PER_BATCH: u32 = 3;
/// Resets of one batch before the prover gives up on it and only alerts.
const RESETS_PER_BATCH: u32 = 3;

/// Held by the ctx builder for each batch it prepares and by the prover for a reset,
/// so a reset never races a batch row the builder is about to create.
type BatchLock = Arc<Mutex<()>>;

/// Drop every unproven batch from `start` with its snapshot; the ctx builder then
/// prepares them again from the last proven batch.
async fn reset_state_chain_batches(
    local_db: &LocalDB,
    snap_path: &str,
    start: u64,
) -> anyhow::Result<usize> {
    let starts = local_db
        .acquire()
        .await?
        .delete_unproven_long_running_task_proofs(&StateChainProofBuilder::name(), start as i64)
        .await?;
    for batch in &starts {
        for suffix in ["args", "ctx"] {
            let path = format!("{snap_path}/{batch}.{suffix}");
            match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into());
                }
                _ => {}
            }
        }
    }
    Ok(starts.len())
}

/// Whether the prover already has `max_pending` unproved batches waiting.
async fn state_chain_backlog_full(local_db: &LocalDB, max_pending: i64) -> anyhow::Result<bool> {
    if max_pending <= 0 {
        return Ok(false);
    }
    let latest_proven = fetch_latest_long_running_task_by_state(
        local_db,
        StateChainProofBuilder::name(),
        Proven.to_i64(),
    )
    .await?;
    // Unfinished rows before the latest proven batch are history, not backlog.
    let from = latest_proven.map_or(0, |task| task.block_end);
    let pending = local_db
        .acquire()
        .await?
        .count_pending_long_running_task_proofs(&StateChainProofBuilder::name(), from)
        .await?;
    Ok(pending >= max_pending)
}

#[tracing::instrument(level = "info", skip(local_db, cancellation_token))]
async fn spawn_state_chain_ctx_builder(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    init_interval: u64,
    max_pending: i64,
    batch_lock: BatchLock,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let configured = args.clone();
    let mut args = args;
    let mut interval = init_interval;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                let _batch = batch_lock.lock().await;
                if state_chain_backlog_full(&local_db, max_pending).await? {
                    tracing::debug!("ctx builder: {max_pending} batches await the prover");
                    continue;
                }
                let next_task = fetch_latest_long_running_task(
                    &local_db,
                    StateChainProofBuilder::name()
                ).await?;

                if let Some(next_task) = next_task {
                    // check if we should use the args from the config file.
                    if args.start > next_task.block_start as u64 && next_task.block_end == 0 {
                        tracing::info!("Use args from config file for the first task, start: {}, batch_size: {}", args.start, args.batch_size);
                    } else {
                        args.start = next_task.block_end as u64;
                        args.input_proof = next_task.path_to_proof.unwrap();
                        args.output_proof = format!(
                            "{}/{}-{}.bin",
                            std::path::Path::new(&args.output_proof)
                                .parent().unwrap()
                                .to_str().unwrap(),
                            args.start,
                            args.batch_size
                        );
                        args.init_input = false;
                    }
                } else {
                    // Nothing stored, or a reset dropped every batch: start over.
                    args = configured.clone();
                }

                tracing::info!("ctx builder: fetching blocks, args={args:?}");

                let blocks = match fetch_state_chain(
                    &args.l2_contract_addresses,
                    args.start,
                    args.batch_size,
                    &args.execution_layer_rpc,
                    &args.blocks,
                    &args.goat_network,
                    &args.cosmos_rpc_url,
                    args.fetch_concurrency,
                ).await {
                    Ok(d) => d,
                    Err(e) => {
                        if let Some(proof_builder::ProofError::InputNotReady(ee)) = e.downcast_ref::<proof_builder::ProofError>() {
                            interval = *ee;
                            tracing::error!("fetch state chain: {e}, sleeping {interval}s");
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                };
                interval = init_interval;

                let ctx = ProofRequest::StateChainProofRequest {
                    init_input: args.init_input,
                    input_proof: args.input_proof.clone(),
                    output_proof: args.output_proof.clone(),
                    start: args.start,
                    l2_contract_addresses: args.l2_contract_addresses.clone(),
                    batch_size: args.batch_size,
                    blocks,
                };

                let snap_path = std::path::Path::new(&args.input_proof).parent().unwrap().to_str().unwrap();
                tracing::info!("fetch snap_path: {snap_path:?}");
                // Snapshots are complete before the batch row that makes the prover read them.
                proof_builder::artifacts::atomic_write(
                    format!("{}/{}.args", snap_path, args.start),
                    serde_json::to_string(&args)?.as_bytes(),
                )?;
                proof_builder::artifacts::atomic_write(
                    format!("{}/{}.ctx", snap_path, args.start),
                    serde_json::to_string(&ctx)?.as_bytes(),
                )?;

                let affected = match create_long_running_task(
                    &local_db,
                    args.start as i64,
                    args.batch_size as i64,
                    args.output_proof.clone(),
                    "".to_string(),
                    0,
                    0,
                    StateChainProofBuilder::name(),
                    0,
                    0,
                    New,
                    "".to_string(),
                ).await {
                    Ok(affected) => affected,
                    Err(e) => {
                        tracing::error!("Create long running task error: {e:?}");
                        continue;
                    }
                };
                tracing::info!("Created long running task for state chain proof ctx builder, affected rows: {affected}");
                args = ProofBuilderConfig::run_next(args, StateChainProofBuilder::name())?;
            }
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("ctx builder cancelled");
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(runtime, local_db, metrics_state, cancellation_token))]
async fn spawn_state_chain_prover(
    runtime: ProverRuntime,
    start_index: u64,
    batch_size: u64,
    input_proof: String,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    batch_lock: BatchLock,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let builder = runtime.builder(StateChainProofBuilder::with_client).await?;

    let mut start_index = start_index;
    // Of the batch at `start_index`.
    let (mut fatal_runs, mut resets) = (0, 0);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                let snap_path = std::path::Path::new(&input_proof).parent().unwrap().to_str().unwrap();
                if fatal_runs >= FATAL_RUNS_PER_BATCH && resets >= RESETS_PER_BATCH {
                    if fatal_runs == FATAL_RUNS_PER_BATCH {
                        fatal_runs += 1;
                        tracing::error!(block_start = start_index, resets, "state chain batch keeps failing after fresh fetches; proving stopped until restart");
                    }
                    metrics_state.record_attempt(STATE_CHAIN_PROOF, "stalled", Duration::ZERO);
                    continue;
                }
                if fatal_runs >= FATAL_RUNS_PER_BATCH {
                    let _batch = batch_lock.lock().await;
                    let dropped = reset_state_chain_batches(&local_db, snap_path, start_index).await?;
                    resets += 1;
                    fatal_runs = 0;
                    tracing::error!(block_start = start_index, dropped, resets, "state chain batch failed {FATAL_RUNS_PER_BATCH} times; fetching it again");
                    metrics_state.record_attempt(STATE_CHAIN_PROOF, "batch_reset", Duration::ZERO);
                    continue;
                }
                tracing::info!("prover: start proving, block_start: {start_index}, batch_size: {batch_size}");

                let args: state_chain_proof::Args = match std::fs::read(format!("{}/{}.args", snap_path, start_index)) {
                    Ok(x) => match serde_json::from_slice(&x) {
                        Ok(args) => args,
                        Err(e) => {
                            tracing::error!("Deserialize args error: {e:?}, path: {snap_path}/{start_index}.args");
                            continue;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Read args: {snap_path}, {e:?}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                let ctx: ProofRequest = match std::fs::read(format!("{}/{}.ctx", snap_path, start_index)) {
                    Ok(x) => match serde_json::from_slice(&x) {
                        Ok(ctx) => ctx,
                        Err(e) => {
                            tracing::warn!("Deserialize ctx error: {e:?}, path: {snap_path}/{start_index}.ctx");
                            continue;
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Read ctx: {snap_path}/{start_index}.ctx, {e:?}");
                        continue;
                    }
                };

                let affteced = match update_long_running_task(
                    &local_db,
                    start_index as i64,
                    batch_size as i64,
                    args.output_proof.clone(),
                    "".to_string(),
                    0,
                    0,
                    Proving,
                    StateChainProofBuilder::name(),
                    0,
                    "".to_string(),
                ).await {
                    Ok(affected) => affected,
                    Err(e) => {
                        tracing::error!("Update long running task to proving state error: {e:?}");
                        continue;
                    }
                };
                tracing::info!("Updated long running task to proving state, affected rows: {affteced}");

                let attempt_start = tokio::time::Instant::now();
                let unit = {
                    let (runtime, local_db, builder) = (runtime.clone(), local_db.clone(), builder.clone());
                    let output_proof = args.output_proof.clone();
                    async move {
                        let proved = match runtime.prove_and_save(builder, ctx).await {
                            Ok(proved) => proved,
                            Err(error) => return Ok(Err(error)),
                        };
                        let affected = update_long_running_task(
                            &local_db,
                            start_index as i64,
                            batch_size as i64,
                            output_proof,
                            proved.public_value_hex,
                            proved.proof_size as i64,
                            proved.cycles,
                            Proven,
                            StateChainProofBuilder::name(),
                            proved.proving_time as i64,
                            proved.zkm_version,
                        )
                        .await?;
                        Ok::<_, anyhow::Error>(Ok(affected))
                    }
                };
                let affected = match runtime.run(unit).await {
                    Err(Cancelled) => continue,
                    Ok(Err(error)) => {
                        metrics_state.record_attempt(STATE_CHAIN_PROOF, "failed", attempt_start.elapsed());
                        tracing::error!("State chain proof attempt failed: {error}");
                        continue;
                    }
                    Ok(Ok(Err(error))) => {
                        metrics_state.record_attempt(STATE_CHAIN_PROOF, failure_outcome(&error), attempt_start.elapsed());
                        // Only fatal failures count against the snapshot.
                        if matches!(error, ProveError::Prove(_, Failure::Fatal)) {
                            fatal_runs += 1;
                        }
                        settle_chain_failure(&runtime, error, &StateChainProofBuilder::name())?;
                        continue;
                    }
                    Ok(Ok(Ok(affected))) => affected,
                };
                let outcome = if affected > 0 { "success" } else { "failed" };
                metrics_state.record_attempt(STATE_CHAIN_PROOF, outcome, attempt_start.elapsed());
                tracing::info!("Updated long running task to proven state, affected rows: {affected}");
                start_index += batch_size;
                (fatal_runs, resets) = (0, 0);
            }
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("prover cancelled");
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(options, local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_state_chain_proof_task(
    options: TaskOptions,
    args: state_chain_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(initial_delay)).await;

        let batch_lock = BatchLock::default();
        let ctx_builder = tokio::spawn(spawn_state_chain_ctx_builder(
            args.clone(),
            local_db.clone(),
            interval + 1,
            options.state_chain_max_pending_batches,
            batch_lock.clone(),
            cancellation_token.clone(),
        ));

        let mut cur_task = fetch_latest_long_running_task_by_state(
            &local_db,
            StateChainProofBuilder::name(),
            Proven.to_i64(),
        )
        .await?;

        let cur_task_failed = fetch_latest_long_running_task_by_state(
            &local_db,
            StateChainProofBuilder::name(),
            Failed.to_i64(),
        )
        .await?;

        if let Some(task_failed) = cur_task_failed
            && let Some(ref task) = cur_task
        {
            if task.block_start == task_failed.block_start
                && task.block_end == task_failed.block_end
            {
                cur_task = Some(task_failed);
            } else if task.block_start < args.start as i64 {
                // load from config
                cur_task = None;
            }
        };

        let mut args = args.clone();
        if let Some(cur_task) = cur_task {
            args.start = cur_task.block_end as u64;
            args.input_proof = cur_task.path_to_proof.unwrap();
            args.output_proof = format!(
                "{}/{}-{}.bin",
                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                args.start,
                args.batch_size
            );
            args.init_input = false;
        }

        let input_proof = args.input_proof.clone();
        let prover = tokio::spawn(spawn_state_chain_prover(
            options.runtime.clone(),
            args.start,
            args.batch_size,
            input_proof,
            local_db.clone(),
            metrics_state,
            interval,
            batch_lock,
            cancellation_token.clone(),
        ));

        tokio::select! {
            res = ctx_builder => {
                res??;
            }
            res = prover => {
                res??;
            }
            _ = cancellation_token.cancelled() => {
                tracing::warn!("state chain proof task cancelled");
            }
        }

        Ok(())
    })
}

#[cfg(test)]
mod reset_tests {
    use super::*;
    use store::{LongRunningTaskProof, create_local_db};

    #[tokio::test]
    async fn a_reset_drops_the_unproven_batches_and_their_snapshots() {
        let local_db = create_local_db("sqlite::memory:").await;
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().to_str().unwrap();
        let mut storage = local_db.acquire().await.unwrap();
        for (start, state) in [(0, Proven), (10, Proving), (20, New)] {
            storage
                .create_long_running_task_proof(&LongRunningTaskProof {
                    block_start: start,
                    block_end: start + 10,
                    chain_name: StateChainProofBuilder::name(),
                    proof_state: state.to_i64(),
                    ..Default::default()
                })
                .await
                .unwrap();
            for suffix in ["args", "ctx"] {
                std::fs::write(format!("{snap}/{start}.{suffix}"), b"{}").unwrap();
            }
        }
        drop(storage);

        assert_eq!(reset_state_chain_batches(&local_db, snap, 10).await.unwrap(), 2);
        // The builder restarts after the proven batch.
        let latest = fetch_latest_long_running_task(&local_db, StateChainProofBuilder::name())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((latest.block_start, latest.block_end), (0, 10));
        let mut left: Vec<_> = std::fs::read_dir(snap)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["0.args", "0.ctx"]);
    }
}
