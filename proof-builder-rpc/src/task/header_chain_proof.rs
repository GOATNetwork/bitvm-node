use header_chain_proof::{HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{ProofBuilder, ProofRequest};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::api::metrics_service::{ApiMetricsState, HEADER_CHAIN_PROOF};
use crate::config::ProofBuilderConfig;
use crate::prover::{Cancelled, ProverRuntime};
use crate::task::{
    create_long_running_task, failure_outcome, fetch_latest_long_running_task, settle_chain_failure,
};

#[tracing::instrument(level = "info", skip(runtime, local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_header_chain_proof_task(
    runtime: ProverRuntime,
    args: header_chain_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<header_chain_proof::Args>> {
    let mut args = args.clone();
    let mut large_interval = interval;
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Header chain proof generate task cancelled");
            }
        }
        assert_eq!(
            args.batch_size, 1,
            "Header chain proof batch size must be 1, current batch size: {}",
            args.batch_size
        );

        let builder = runtime.builder(HeaderChainProofBuilder::with_client).await?;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(large_interval)) => {
                    let next_task = fetch_latest_long_running_task(&local_db, HeaderChainProofBuilder::name()).await?;
                    if let Some(next_task) = next_task {
                        info!("Header chain's next task: {next_task:?}");
                        args.start = next_task.block_end as usize;
                        args.input_proof = next_task.path_to_proof.unwrap();
                        args.output_proof = format!(
                            "{}/{}-{}.bin",
                            std::path::Path::new(&args.output_proof).parent().unwrap().to_str().unwrap(),
                            args.start,
                            args.batch_size
                        );
                        args.init_input = false;
                    }
                    info!("Header chain proof generate task: generate proof, args: {args:?}");
                    let total_block_headers = match fetch_header_chain(
                        &args.esplora_url,
                        args.start,
                        args.batch_size,
                        &args.block_headers,
                        args.force_fetch,
                        args.bitcoin_network,
                    ).await {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Fetch header blocks error, {err:?}");
                            large_interval = 30;
                            continue;
                        }
                    };
                    large_interval = interval;

                    let ctx =
                       ProofRequest::HeaderChainProofRequest {
                           init_input: args.init_input,
                           input_proof: args.input_proof.clone(),
                           output_proof: args.output_proof.clone(),
                           start: args.start,
                           batch_size: args.batch_size,
                           total_block_headers,
                    };
                    let started = tokio::time::Instant::now();
                    let unit = {
                        let (runtime, local_db, builder) = (runtime.clone(), local_db.clone(), builder.clone());
                        let (start, batch_size) = (args.start as i64, args.batch_size as i64);
                        let output_proof = args.output_proof.clone();
                        async move {
                            let proved = match runtime.prove_and_save(builder, ctx).await {
                                Ok(proved) => proved,
                                Err(error) => return Ok(Err(error)),
                            };
                            let affected = create_long_running_task(
                                &local_db,
                                start,
                                batch_size,
                                output_proof,
                                proved.public_value_hex,
                                proved.proof_size as i64,
                                proved.cycles,
                                HeaderChainProofBuilder::name(),
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
                            metrics_state.record_attempt(HEADER_CHAIN_PROOF, "failed", started.elapsed());
                            return Err(error);
                        }
                        Ok(Ok(Err(error))) => {
                            metrics_state.record_attempt(HEADER_CHAIN_PROOF, failure_outcome(&error), started.elapsed());
                            settle_chain_failure(&runtime, error, &HeaderChainProofBuilder::name())?;
                            continue;
                        }
                        Ok(Ok(Ok(affected))) => {
                            let outcome = if affected > 0 { "success" } else { "failed" };
                            metrics_state.record_attempt(HEADER_CHAIN_PROOF, outcome, started.elapsed());
                        }
                    }
                    args = ProofBuilderConfig::run_next(args, HeaderChainProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Header chain proof generate task cancelled");
                }
            }
        }
    })
}
