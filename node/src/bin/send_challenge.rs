//! challenge: broadcast a Challenge transaction for a graph via the node API.
//!
//! Purpose:
//! - Call the node's send-challenge API endpoint to broadcast the Challenge
//!   transaction on Bitcoin. No direct DB access is needed.
//!
//! Env:
//! - BITVM_SECRET: the node's secret key, used to sign the auth headers
//!
//! Args:
//! - --rpc-url: node API base URL (default: http://localhost:8080)
//! - --graph-id: target graph UUID
//!
//! Example:
//! - cargo run -p bitvm-noded --bin challenge -- \
//!   --rpc-url http://localhost:8080 \
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
    name = "send-challenge",
    version,
    about = "Broadcast a Challenge transaction for a graph (via node API)",
    long_about = "Broadcast a Challenge transaction for a graph via the node's REST API.\n\nThe node must be running and reachable at the given --rpc-url."
)]
struct Args {
    /// Graph UUID to challenge
    #[arg(long)]
    graph_id: uuid::Uuid,

    /// Node API base URL
    #[arg(long, default_value = "http://localhost:8080")]
    rpc_url: String,
}

#[derive(Debug, Deserialize)]
struct SendChallengeResponse {
    challenge_txid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let request_target = format!("/v1/graphs/{}/send-challenge", args.graph_id);
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
        .with_context(|| format!("failed to reach node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API returned {status}: {body}");
    }

    let body: SendChallengeResponse = resp.json().await.context("failed to parse API response")?;
    println!("Challenge tx broadcasted: {}", body.challenge_txid);
    Ok(())
}
