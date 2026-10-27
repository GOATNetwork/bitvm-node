use crate::prover::ProverRuntime;
use crate::{
    config::ProofBuilderConfig,
    task::{OnDemandJob, OnDemandOutcome, fetch_on_demand_task, prove_on_demand},
};
use bitcoin_light_client_circuit::le_bits_to_u256;
use operator_proof::{OperatorProofBuilder, fetch_target_block_and_watchtower_tx};
use proof_builder::{ProofBuilder, ProofRequest};
use std::collections::HashMap;
use std::time::Duration;
use store::OnDemandProofTable;
use store::localdb::LocalDB;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
use util::hex_parse;
use zkm_sdk::HashableKey;

use crate::api::metrics_service::{ApiMetricsState, OPERATOR_PROOF};

#[tracing::instrument(level = "info", skip(runtime, local_db, metrics_state, cancellation_token))]
pub(crate) fn spawn_operator_proof_task(
    runtime: ProverRuntime,
    args: operator_proof::Args,
    local_db: LocalDB,
    metrics_state: ApiMetricsState,
    interval: u64,
    initial_delay: u64,
    cancellation_token: CancellationToken,
) -> JoinHandle<anyhow::Result<operator_proof::Args>> {
    let mut args = args.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(initial_delay)) => {}
            _ = cancellation_token.cancelled() => {
                anyhow::bail!("Operator proof generate task cancelled");
            }
        }

        let builder = runtime.builder(OperatorProofBuilder::with_client).await?;
        // Consecutive failed attempts per task, reset when a task finishes.
        let mut attempts = HashMap::new();
        info!("operator vk hash {:?}", builder.vk().bytes32());
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    // fetch args from the database.
                    let task_index;
                    match fetch_on_demand_task(
                        &local_db, false, args.bitcoin_network, &args.esplora_url,
                    ).await {
                        Ok(Some(next_task)) => {
                            args.latest_sequencer_commit_txid = next_task.latest_sequencer_commit_txid;
                            args.header_chain_input_proof = next_task.header_chain_input_proof;
                            args.commit_chain_input_proof = next_task.commit_chain_input_proof;
                            args.state_chain_input_proof = next_task.state_chain_input_proof;
                            args.operator_committed_blockhash = next_task.operator_committed_blockhash.unwrap();
                            args.graph_id = next_task.graph_id.unwrap();
                            args.output = format!("{}/{}.bin",
                                std::path::Path::new(&args.output).parent().unwrap().to_str().unwrap(),
                                args.graph_id
                            );
                            args.watchtower_challenge_init_txid = next_task.watchtower_challenge_init_txid.unwrap().clone();
                            args.watchtower_challenge_txids = next_task
                                .watchtower_challenge_txids
                                .iter()
                                .map(|txid| txid.as_deref().unwrap_or(""))
                                .collect::<Vec<_>>()
                                .join(",");
                            args.watchtower_public_keys = next_task.watchtower_public_keys.join(",");
                            // LE array to string, e.g. [1, 1, 1, 0] => 7
                            args.included_watchtowers = le_bits_to_u256(&next_task.included_watchtowers).to_string();
                            task_index = next_task.task_index;
                        }
                        Ok(None) => {
                            tracing::warn!("No on demand task found for operator proof, wait for the next round");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("Failed to fetch on demand task for operator proof, error: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    info!("Operator proof generate task: generate proof, args: {args:?}");

                    let (
                        block_pos_ss_commit,
                        target_block_ss_commit,
                        operator_committed_blockhash,
                        operator_latest_sequencer_commit_txn,
                        graph_watchtower_xonly_public_keys,
                        watchtower_challenge_init_txid,
                        watchtower_challenge_init_txn,
                        watchtower_challenge_witnesses,
                    ) = match fetch_target_block_and_watchtower_tx(
                        &args.esplora_url,
                        &args.latest_sequencer_commit_txid,
                        &args.operator_committed_blockhash,
                        &args.watchtower_challenge_init_txid,
                        &args.watchtower_challenge_txids,
                        &args.watchtower_public_keys,
                        args.bitcoin_network,
                    )
                    .await {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!("Fetch target block and watchtower txns error, {err:?}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    let ctx = ProofRequest::OperatorProofRequest {
                        included_watchtowers: args.included_watchtowers.clone(),
                        graph_id: hex_parse::<16>(&args.graph_id).unwrap(),
                        genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),

                        header_chain_input_proof: args.header_chain_input_proof.clone(),
                        commit_chain_input_proof: args.commit_chain_input_proof.clone(),
                        state_chain_input_proof: args.state_chain_input_proof.clone(),
                        execution_layer_block_number: args.execution_layer_block_number,

                        output: args.output.clone(),

                        block_pos_ss_commit,
                        target_block_ss_commit,
                        operator_latest_sequencer_commit_txn,

                        operator_committed_blockhash,

                        graph_watchtower_xonly_public_keys,
                        watchtower_challenge_init_txid,
                        watchtower_challenge_init_txn,
                        watchtower_challenge_witnesses,
                    };
                    let job = OnDemandJob {
                        table: OnDemandProofTable::Operator,
                        task_index,
                        output: args.output.clone(),
                        builder: builder.clone(),
                        ctx,
                    };
                    let outcome =
                        prove_on_demand(&runtime, &local_db, job, &mut attempts, &metrics_state, OPERATOR_PROOF)
                            .await?;
                    tracing::info!("operator task {task_index}: {outcome:?}");
                    if outcome == OnDemandOutcome::Deferred {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    args = ProofBuilderConfig::run_next(args, OperatorProofBuilder::name())?;
                }
                _ = cancellation_token.cancelled() => {
                    anyhow::bail!("Operator proof generate task cancelled");
                }
            }
        }
    })
}
