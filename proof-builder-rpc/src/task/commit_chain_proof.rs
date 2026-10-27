use crate::ProofBuilderConfig;
use crate::prover::{Cancelled, ProverRuntime};
use crate::task::create_commit_chain_proof;
use crate::task::fetch_latest_long_running_task;
use crate::task::fetch_next_commit_task_index;
use crate::task::{failure_outcome, settle_chain_failure};
use commit_chain_proof::CommitChainProofBuilder;
use commit_chain_proof::fetch_commit_chain;
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::api::metrics_service::{ApiMetricsState, COMMIT_CHAIN_PROOF};

#[tracing::instrument(level = "info", skip(runtime, local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_commit_chain_proof_task(
    runtime: ProverRuntime,
    args: commit_chain_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<commit_chain_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Commit chain proof generate task cancelled");
            }
        }

        let builder = runtime.builder(CommitChainProofBuilder::with_client).await?;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    let init_input = args.init_input;
                    if !init_input {
                        let next_task = fetch_latest_long_running_task(&local_db, CommitChainProofBuilder::name()).await?;
                        if let Some(next_task) = next_task {
                            info!("Commit chain's next task: {next_task:?}");
                            args.start = fetch_next_commit_task_index(&local_db).await?;
                            args.input_proof = next_task.path_to_proof.unwrap();
                            args.commit_info = format!(
                                "{}/commit_info.json.{}",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                            );
                            args.output_proof = format!(
                                "{}/{}-{}.bin",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                                args.batch_size
                            );
                            args.commits = format!(
                                "{}/{}-{}.bin.commits",
                                std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                                args.start,
                                args.batch_size
                            );
                            args.init_input = false;
                        }
                    }
                    info!("Commit chain proof generate task: generate proof, args: {args:?}");

                    let commits = match fetch_commit_chain(&args.esplora_url, &args.commit_info, &args.commits, args.bitcoin_network).await {
                        Ok(d) => d,
                        Err(err) => {
                            tracing::warn!("Fetch commit chain error, {err:?}, continuing");
                            continue;
                        }
                    };
                    let block_start = commits.first().unwrap().block_height as i64;
                    let ctx =
                        ProofRequest::CommitChainProofRequest {
                            init_input,
                            input_proof: args.input_proof.clone(),
                            output_proof: args.output_proof.clone(),
                            commit_info: args.commit_info.clone(),
                            commits,
                    };
                    let started = tokio::time::Instant::now();
                    let unit = {
                        let (runtime, local_db, builder) = (runtime.clone(), local_db.clone(), builder.clone());
                        let output_proof = args.output_proof.clone();
                        async move {
                            let proved = match runtime.prove_and_save(builder, ctx).await {
                                Ok(proved) => proved,
                                Err(error) => return Ok(Err(error)),
                            };
                            let affected = create_commit_chain_proof(
                                &local_db,
                                block_start,
                                0xffffffff_i64 - block_start,
                                output_proof,
                                proved.public_value_hex,
                                proved.proof_size as i64,
                                proved.cycles,
                                CommitChainProofBuilder::name(),
                                init_input,
                                started.elapsed().as_millis() as i64,
                                proved.proving_time as i64,
                                store::ProofState::Proven,
                                proved.zkm_version,
                            )
                            .await?;
                            Ok::<_, anyhow::Error>(Ok(affected))
                        }
                    };
                    match runtime.run(unit).await {
                        Err(Cancelled) => continue,
                        Ok(Err(error)) => {
                            metrics_state.record_attempt(COMMIT_CHAIN_PROOF, "failed", started.elapsed());
                            return Err(error);
                        }
                        Ok(Ok(Err(error))) => {
                            metrics_state.record_attempt(COMMIT_CHAIN_PROOF, failure_outcome(&error), started.elapsed());
                            settle_chain_failure(&runtime, error, &CommitChainProofBuilder::name())?;
                            continue;
                        }
                        Ok(Ok(Ok(affected))) => {
                            let outcome = if affected > 0 { "success" } else { "failed" };
                            metrics_state.record_attempt(COMMIT_CHAIN_PROOF, outcome, started.elapsed());
                        }
                    }
                    args = ProofBuilderConfig::run_next(args, CommitChainProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Commit chain proof generate task cancelled");
                }
            }
        }
    })
}
