//! Generate operator proof
use clap::Parser;
use operator_proof::{
    Args, OperatorProofBuilder, build_withdrawal_proof, fetch_target_block_and_watchtower_tx,
};
use proof_builder::{ProofBuilder, ProofRequest};
use state_chain::WithdrawalRecord;
use std::str::FromStr;
use util::hex_parse;
use zkm_sdk::HashableKey;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    let builder = OperatorProofBuilder::new();
    if args.print_program_id {
        println!("OPERATOR_PROGRAM_ID={}", hex::encode(builder.program_id().unwrap()));
        eprintln!("OPERATOR_VK_HASH={}", builder.vk().bytes32());
        return;
    }

    let (
        block_pos_ss_commit,
        target_block_ss_commit,
        operator_committed_blockhash,
        operator_latest_sequencer_commit_txn,
        graph_watchtower_xonly_public_keys,
        watchtower_challenge_init_txid,
        watchtower_challenge_init_txn,
        watchtower_challenge_witnesses,
    ) = fetch_target_block_and_watchtower_tx(
        &args.esplora_url,
        &args.latest_sequencer_commit_txid,
        &args.operator_committed_blockhash,
        &args.watchtower_challenge_init_txid,
        &args.watchtower_challenge_txids,
        &args.watchtower_public_keys,
        args.bitcoin_network,
    )
    .await
    .unwrap();

    let graph_id = hex_parse::<16>(&args.graph_id).unwrap();
    let gateway_address =
        alloy_primitives::Address::from_str(&args.gateway_address).unwrap().into_array();
    let records: Vec<WithdrawalRecord> =
        serde_json::from_slice(&std::fs::read(&args.withdrawal_records).unwrap()).unwrap();
    let withdrawal_proof = build_withdrawal_proof(&records, gateway_address, graph_id).unwrap();

    let ctx = ProofRequest::OperatorProofRequest {
        included_watchtowers: args.included_watchtowers.clone(),
        graph_id,
        genesis_sequencer_commit_txid: args.genesis_sequencer_commit_txid.clone(),
        gateway_address,
        withdrawal_proof,

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
    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("Operator proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
