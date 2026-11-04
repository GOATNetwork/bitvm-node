use crate::ProofBuilderConfig;
use crate::prover::ProverRuntime;
use crate::task::{
    OnDemandFetch, OnDemandJob, OnDemandOutcome, fail_invalid_on_demand_task, fetch_on_demand_task,
    prove_on_demand,
};
use proof_builder::{ProofBuilder, ProofRequest};
use std::collections::HashMap;
use std::time::Duration;
use store::OnDemandProofTable;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use watchtower_proof::{WatchtowerProofBuilder, fetch_target_block};

use crate::api::metrics_service::{ApiMetricsState, WATCHTOWER_PROOF};

#[tracing::instrument(level = "info", skip(runtime, local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_watchtower_proof_task(
    runtime: ProverRuntime,
    args: watchtower_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<watchtower_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Watchtower proof generate task cancelled");
            }
        }

        let builder = runtime.builder(WatchtowerProofBuilder::with_client).await?;
        // Consecutive failed attempts per task, reset when a task finishes.
        let mut attempts = HashMap::new();
        // The last task handed out; the next fetch starts after it.
        let mut after_id = 0;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    // fetch args from the database by instance id and graph id.
                    let task_index;
                    match fetch_on_demand_task(
                        &local_db,
                        true,
                        after_id,
                        args.bitcoin_network,
                        &args.esplora_url,
                    ).await {
                        Ok(Some(OnDemandFetch::Ready(next_task))) => {
                            after_id = next_task.task_index;
                            args.latest_sequencer_commit_txid = next_task.latest_sequencer_commit_txid;
                            args.header_chain_input_proof = next_task.header_chain_input_proof;
                            args.commit_chain_input_proof = next_task.commit_chain_input_proof;
                            args.state_chain_input_proof = next_task.state_chain_input_proof;
                            args.output = format!("{}/{}.bin",
                                std::path::Path::new(&args.output).parent().unwrap().to_str().unwrap(),
                                next_task.task_index,
                            );
                            task_index = next_task.task_index;
                        },
                        Ok(Some(OnDemandFetch::NotReady(task_index))) => {
                            after_id = task_index;
                            continue;
                        }
                        Ok(Some(OnDemandFetch::Invalid(task_index, reason))) => {
                            after_id = task_index;
                            if let Err(e) = fail_invalid_on_demand_task(
                                &local_db, OnDemandProofTable::Watchtower, task_index, &reason,
                            ).await {
                                tracing::error!("Failed to close watchtower task {task_index}, error: {e}");
                            }
                            continue;
                        }
                        Ok(None) => {
                            after_id = 0;
                            tracing::warn!("No on demand task found for watchtower proof, wait for the next round");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("Failed to fetch on demand task for watchtower proof, error: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                    info!("Watchtower proof generate task: generate proof, args: {args:?}");

                    let (block_pos, target_block, latest_sequencer_commit_tx) =
                        match fetch_target_block(&args.esplora_url, &args.latest_sequencer_commit_txid, args.bitcoin_network).await {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::error!("Fetch target block error: {e}");
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                        };
                    let ctx = ProofRequest::WatchtowerProofRequest {
                            genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
                            latest_sequencer_commit_txid: args.latest_sequencer_commit_txid.clone(),
                            header_chain_input_proof: args.header_chain_input_proof.clone(),
                            commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                            state_chain_input_proof: args.state_chain_input_proof.clone(),
                            output: args.output.clone(),
                            target_block,
                            block_pos,
                            latest_sequencer_commit_tx,
                    };
                    let job = OnDemandJob {
                        table: OnDemandProofTable::Watchtower,
                        task_index,
                        output: args.output.clone(),
                        builder: builder.clone(),
                        ctx,
                    };
                    let outcome =
                        prove_on_demand(&runtime, &local_db, job, &mut attempts, &metrics_state, WATCHTOWER_PROOF)
                            .await?;
                    tracing::info!("watchtower task {task_index}: {outcome:?}");
                    if outcome == OnDemandOutcome::Deferred {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    args = ProofBuilderConfig::run_next(args, WatchtowerProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Watchtower proof generate task cancelled");
                }
            }
        }
    })
}
