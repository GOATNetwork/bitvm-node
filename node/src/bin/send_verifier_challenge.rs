//! verifier-challenge: force a verifier ChallengeAssert transaction via node API.
//!
//! Purpose:
//! - Call the verifier node's test endpoint to broadcast its ChallengeAssert
//!   transaction after an operator assert.
//!
//! Env:
//! - BITVM_SECRET: the node's secret key, used to sign the auth headers
//!
//! Args:
//! - --rpc-url: verifier node API base URL (default: http://localhost:8080)
//! - --graph-id: target graph UUID
//!
//! Example:
//! - cargo run -p bitvm-noded --bin verifier-challenge -- \
//!   --rpc-url http://localhost:8910 \
//!   --graph-id <uuid>

use anyhow::{Context, Result};
use bitvm_noded::env::get_bitvm_key;
use bitvm_noded::rpc_service::auth::{
    AUTH_NONCE_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER, sign_request_auth,
};
use clap::Parser;
use http::Method;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(
    name = "verifier-challenge",
    version,
    about = "Force a verifier ChallengeAssert transaction for a graph (via node API)",
    long_about = "Force a verifier ChallengeAssert transaction for a graph via the verifier node's REST API.\n\nThe verifier node must be running and reachable at the given --rpc-url."
)]
struct Args {
    /// Graph UUID to challenge
    #[arg(long)]
    graph_id: uuid::Uuid,

    /// Verifier node API base URL
    #[arg(long, default_value = "http://localhost:8080")]
    rpc_url: String,
}

#[derive(Debug, Deserialize)]
struct SendVerifierChallengeResponse {
    challenge_assert_txid: String,
    verifier_index: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let request_target = format!("/v1/graphs/{}/send-verifier-challenge", args.graph_id);
    let url = format!("{}{}", args.rpc_url.trim_end_matches('/'), request_target);

    let keypair = get_bitvm_key().context("failed to load BITVM_SECRET")?;
    let (timestamp, nonce, signature) =
        sign_request_auth(&keypair, &Method::POST, &request_target, &[]);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header(AUTH_TIMESTAMP_HEADER, &timestamp)
        .header(AUTH_NONCE_HEADER, &nonce)
        .header(AUTH_SIGNATURE_HEADER, &signature)
        .send()
        .await
        .with_context(|| format!("failed to reach verifier node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API returned {status}: {body}");
    }

    let body: SendVerifierChallengeResponse =
        resp.json().await.context("failed to parse API response")?;
    println!(
        "Verifier ChallengeAssert tx broadcasted: {} (verifier_index={})",
        body.challenge_assert_txid, body.verifier_index
    );
    Ok(())
}
