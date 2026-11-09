#![feature(trim_prefix_suffix)]
use clap::Parser;
use proof_builder::{ProofBuilder, ProofRequest};

use state_chain_proof::{Args, StateChainProofBuilder, fetch_state_chain};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    tracing::info!("args: {:?}", args);
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    let builder = StateChainProofBuilder::new();
    if args.print_program_id {
        println!("{}", hex::encode(builder.program_id().unwrap()));
        return;
    }

    let blocks = fetch_state_chain(
        &args.l2_contract_addresses,
        args.start,
        args.batch_size,
        &args.execution_layer_rpc,
        &args.blocks,
        &args.goat_network,
        &args.cosmos_rpc_url,
        args.fetch_concurrency,
    )
    .await
    .unwrap();

    let ctx = ProofRequest::StateChainProofRequest {
        init_input: args.init_input,
        input_proof: args.input_proof.clone(),
        output_proof: args.output_proof.clone(),
        start: args.start,
        l2_contract_addresses: args.l2_contract_addresses.clone(),
        batch_size: args.batch_size,
        blocks,
    };
    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("header chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
