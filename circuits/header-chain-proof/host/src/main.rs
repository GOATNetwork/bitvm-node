//! Generate header chain proof
use header_chain_proof::{Args, HeaderChainProofBuilder, fetch_header_chain};
use proof_builder::{ProofBuilder, ProofRequest};

use clap::Parser;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    tracing::info!("args: {args:?}");

    let builder = HeaderChainProofBuilder::new();
    if args.print_program_id {
        println!("{}", hex::encode(builder.program_id().unwrap()));
        return;
    }

    let total_block_headers = fetch_header_chain(
        &args.esplora_url,
        args.start,
        args.batch_size,
        &args.block_headers,
        args.force_fetch || args.prefer_local_headers_on_init,
        args.bitcoin_network,
        args.prefer_local_headers_on_init && args.is_genesis_batch(),
    )
    .await
    .unwrap();

    let ctx = ProofRequest::HeaderChainProofRequest {
        init_input: args.init_input,
        input_proof: args.input_proof.clone(),
        output_proof: args.output_proof.clone(),
        start: args.start,
        batch_size: args.batch_size,
        total_block_headers,
    };
    let (input, proof, cycles, _) = builder.build_proof(&ctx).unwrap();
    tracing::info!("header chain proof cycles: {cycles}");
    builder.save_proof(&ctx, &input, cycles, proof).unwrap();
}
