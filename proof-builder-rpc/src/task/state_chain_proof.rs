use crate::task::ProofState::{Failed, New, Proven, Proving};
use crate::task::fetch_latest_long_running_task_by_state;
use crate::task::{create_long_running_task, update_long_running_task};
use crate::{ProofBuilderConfig, task::fetch_latest_long_running_task};
use proof_builder::{state_chain_el_anchor_unix_secs, ProofBuilder, ProofRequest};
use state_chain_proof::{StateChainProofBuilder, fetch_state_chain};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api::metrics_service::{ApiMetricsState, STATE_CHAIN_PROOF};

#[tracing::instrument(level = "info", skip(local_db, cancellation_token))]
async fn spawn_state_chain_ctx_builder(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    init_interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let mut args = args;
    let mut interval = init_interval;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
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
                }

                tracing::info!("ctx builder: fetching blocks, args={args:?}");

                let blocks = match fetch_state_chain(
                    &args.l2_contract_addresses,
                    &args.proceed_withdraw_method_ids,
                    args.start,
                    args.batch_size,
                    &args.execution_layer_rpc,
                    &args.blocks,
                    &args.goat_network,
                    &args.cosmos_rpc_url,
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
                std::fs::write(format!("{}/{}.args", snap_path, args.start), serde_json::to_string(&args)?)?;
                std::fs::write(format!("{}/{}.ctx", snap_path, args.start), serde_json::to_string(&ctx)?)?;

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

#[tracing::instrument(level = "info", skip(local_db, metrics_state, cancellation_token))]
async fn spawn_state_chain_prover(
    start_index: u64,
    batch_size: u64,
    input_proof: String,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let builder = StateChainProofBuilder::new();

    let mut start_index = start_index;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                tracing::info!("prover: start proving, block_start: {start_index}, batch_size: {batch_size}");

                let snap_path = std::path::Path::new(&input_proof).parent().unwrap().to_str().unwrap();
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

                let el_anchor = match state_chain_el_anchor_unix_secs(&ctx) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("EL block anchor for total_time_to_proof: {e:?}");
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
                    el_anchor,
                ).await {
                    Ok(affected) => affected,
                    Err(e) => {
                        tracing::error!("Update long running task to proving state error: {e:?}");
                        continue;
                    }
                };
                tracing::info!("Updated long running task to proving state, affected rows: {affteced}");

                let attempt_start = tokio::time::Instant::now();
                let attempt: anyhow::Result<u64> = async {
                    let (input, proof, cycles, proving_time) = builder.build_proof(&ctx)?;
                    let zkm_version = proof.zkm_version.clone();
                    let (public_value_hex, proof_size) =
                        builder.save_proof(&ctx, &input, cycles, proof)?;
                    update_long_running_task(
                        &local_db,
                        start_index as i64,
                        batch_size as i64,
                        args.output_proof.clone(),
                        public_value_hex,
                        proof_size as i64,
                        cycles,
                        Proven,
                        StateChainProofBuilder::name(),
                        proving_time as i64,
                        zkm_version,
                    )
                    .await
                }
                .await;
                let outcome = if matches!(&attempt, Ok(affected) if *affected > 0) {
                    "success"
                } else {
                    "failed"
                };

                let affteced = match update_long_running_task(
                    &local_db,
                    start_index as i64,
                    batch_size as i64,
                    args.output_proof.clone(),
                    public_value_hex,
                    proof_size as i64,
                    cycles,
                    Proven,
                    StateChainProofBuilder::name(),
                    proving_time as i64,
                    zkm_version,
                    el_anchor,
                ).await {
                    Ok(affected) => affected,
                    Err(error) => {
                        tracing::error!("State chain proof attempt failed: {error}");
                        continue;
                    }
                };
                tracing::info!("Updated long running task to proven state, affected rows: {affected}");
                start_index += batch_size;
            }
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("prover cancelled");
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_state_chain_proof_task(
    args: state_chain_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(initial_delay)).await;

        let ctx_builder = tokio::spawn(spawn_state_chain_ctx_builder(
            args.clone(),
            local_db.clone(),
            interval + 1,
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
            args.start,
            args.batch_size,
            input_proof,
            local_db.clone(),
            metrics_state,
            interval,
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
