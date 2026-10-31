//! pegout: operator pegout helper (Gateway.initWithdraw) via the node API.
//!
//! Modes:
//! - once: single pegout for one graph
//! - batch: repeat until target amount reached or no eligible graphs
//!
//! The operator node must be running and reachable at the given --rpc-url.
//! BITVM_SECRET must be set on this client to sign the auth headers.
//!
//! Args:
//! - --rpc-url: node API base URL (default: http://localhost:8080)
//!
//! Example:
//! - cargo run -p bitvm-noded --bin pegout -- \
//!   --rpc-url http://localhost:8080 once --graph-id <uuid>

use anyhow::{Context, Result, bail};
use bitvm_noded::env::get_bitvm_key;
use bitvm_noded::rpc_service::auth::{
    AUTH_NONCE_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER, sign_request_auth,
};
use clap::{Parser, Subcommand};
use http::Method;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "send-pegout",
    version,
    about = "Operator pegout helper (via node API)",
    long_about = "Initiate pegout by calling the node's REST API.\n\nThe operator node must be running and reachable at the given --rpc-url."
)]
struct Args {
    /// Node API base URL
    #[arg(long, default_value = "http://localhost:8080")]
    rpc_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initiate a single pegout on the next eligible graph
    Once {
        /// Optional explicit graph id; if not provided, the node picks the next eligible graph
        #[arg(long)]
        graph_id: Option<Uuid>,

        /// Dry run (validate but do not call Gateway.initWithdraw)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Skip candidates blocked by another withdrawal, including stale predecessors
        #[arg(long, default_value_t = false)]
        skip_locked: bool,
    },
    /// Initiate pegouts repeatedly until target amount reached
    Batch {
        /// Stop after total pegout amount reaches this target (sats)
        #[arg(long)]
        max_total_amount_sats: u64,

        /// Optional limit on number of pegouts to initiate
        #[arg(long, default_value_t = 0)]
        max_count: u32,

        /// Dry run (validate but do not call Gateway.initWithdraw)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Skip candidates blocked by another withdrawal, including stale predecessors
        #[arg(long, default_value_t = false)]
        skip_locked: bool,

        /// Poll interval seconds for checking graph readiness between pegouts
        #[arg(long, default_value_t = 300)]
        poll_interval_secs: u64,

        /// Max wait seconds for a graph to become ready before stopping
        #[arg(long, default_value_t = 36000)]
        max_wait_secs: u64,
    },
}

#[derive(Debug, Serialize)]
struct PegoutApiRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_id: Option<String>,
    dry_run: bool,
    skip_locked: bool,
}

#[derive(Debug, Deserialize)]
struct PegoutApiResponse {
    graph_id: String,
    instance_id: String,
    kickoff_index: i64,
    amount: i64,
    tx_hash: Option<String>,
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct GraphApiResponse {
    graph: Option<GraphData>,
}

#[derive(Debug, Deserialize)]
struct GraphData {
    status: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
    message: String,
}

async fn call_pegout(
    client: &reqwest::Client,
    base_url: &str,
    graph_id: Option<Uuid>,
    dry_run: bool,
    skip_locked: bool,
) -> Result<PegoutApiResponse> {
    let request_target = "/v1/graphs/pegout";
    let url = format!("{}{}", base_url.trim_end_matches('/'), request_target);
    let body =
        PegoutApiRequest { graph_id: graph_id.map(|id| id.to_string()), dry_run, skip_locked };
    let body = serde_json::to_vec(&body).context("failed to serialize pegout API request")?;

    let keypair = get_bitvm_key().context("failed to load BITVM_SECRET")?;
    let (timestamp, nonce, signature) =
        sign_request_auth(&keypair, &Method::POST, request_target, &body);

    let resp = client
        .post(&url)
        .header(AUTH_TIMESTAMP_HEADER, &timestamp)
        .header(AUTH_NONCE_HEADER, &nonce)
        .header(AUTH_SIGNATURE_HEADER, &signature)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to reach node API at {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            bail!("API error ({}): {}", api_err.error, api_err.message);
        }
        bail!("API returned {status}: {body}");
    }

    resp.json().await.context("failed to parse pegout API response")
}

async fn get_graph_status(
    client: &reqwest::Client,
    base_url: &str,
    graph_id: &str,
) -> Result<Option<String>> {
    let url = format!("{}/v1/graphs/{}", base_url.trim_end_matches('/'), graph_id);
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let data: GraphApiResponse = resp.json().await?;
    Ok(data.graph.map(|g| g.status))
}

fn print_pegout_result(resp: &PegoutApiResponse) {
    if resp.dry_run {
        println!(
            "dry-run: graph {} (instance {} kickoff_index {}) amount {} sats",
            resp.graph_id, resp.instance_id, resp.kickoff_index, resp.amount
        );
    } else {
        println!(
            "initWithdraw submitted: graph {} tx_hash {}",
            resp.graph_id,
            resp.tx_hash.as_deref().unwrap_or("N/A")
        );
    }
}

const IN_PROGRESS_STATUSES: &[&str] = &["OperatorDataPushed", "OperatorKickOff", "Challenge"];

async fn wait_for_graph_ready(
    client: &reqwest::Client,
    base_url: &str,
    graph_id: &str,
    poll_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    let mut waited = 0u64;
    loop {
        if let Some(status) = get_graph_status(client, base_url, graph_id).await? {
            if !IN_PROGRESS_STATUSES.contains(&status.as_str()) {
                eprintln!("graph {graph_id} ready, status: {status}");
                return Ok(());
            }
            eprintln!("waiting for graph {graph_id} (status: {status})");
        } else {
            eprintln!("graph {graph_id} not found, proceeding");
            return Ok(());
        }
        if waited >= max_wait_secs {
            bail!("waited {max_wait_secs}s but graph {graph_id} still not ready");
        }
        sleep(Duration::from_secs(poll_interval_secs)).await;
        waited = waited.saturating_add(poll_interval_secs);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let client = reqwest::Client::new();
    let base_url = &args.rpc_url;

    match args.command {
        Commands::Once { graph_id, dry_run, skip_locked } => {
            let resp = call_pegout(&client, base_url, graph_id, dry_run, skip_locked).await?;
            print_pegout_result(&resp);
        }
        Commands::Batch {
            max_total_amount_sats,
            max_count,
            dry_run,
            skip_locked,
            poll_interval_secs,
            max_wait_secs,
        } => {
            if max_total_amount_sats == 0 {
                bail!("max_total_amount_sats must be > 0 for batch mode");
            }

            let mut total_sent: u64 = 0;
            let mut count: u32 = 0;

            loop {
                if max_count > 0 && count >= max_count {
                    eprintln!("batch stop: reached max_count {max_count}");
                    break;
                }
                if total_sent >= max_total_amount_sats {
                    eprintln!("batch stop: reached target total {max_total_amount_sats} sats");
                    break;
                }

                match call_pegout(&client, base_url, None, true, skip_locked).await {
                    Ok(preflight) => {
                        let amount = u64::try_from(preflight.amount)
                            .context("pegout API returned a negative amount")?;
                        if total_sent.saturating_add(amount) > max_total_amount_sats {
                            eprintln!(
                                "batch stop: next amount {amount} would exceed target {max_total_amount_sats}",
                            );
                            break;
                        }

                        if dry_run {
                            print_pegout_result(&preflight);
                            eprintln!(
                                "batch dry-run stops after the next eligible graph because dry-run does not advance graph state"
                            );
                            break;
                        }

                        let graph_id = Uuid::parse_str(&preflight.graph_id)
                            .context("pegout API returned an invalid graph id")?;
                        let resp =
                            call_pegout(&client, base_url, Some(graph_id), false, skip_locked)
                                .await?;
                        print_pegout_result(&resp);
                        total_sent = total_sent.saturating_add(amount);
                        count = count.saturating_add(1);
                        eprintln!("batch progress: count {count}, total {total_sent} sats");

                        wait_for_graph_ready(
                            &client,
                            base_url,
                            &resp.graph_id,
                            poll_interval_secs,
                            max_wait_secs,
                        )
                        .await?;
                    }
                    Err(e) => {
                        eprintln!("batch stop: {e}");
                        break;
                    }
                }
            }

            eprintln!("batch complete: {count} pegouts, {total_sent} total sats");
        }
    }

    Ok(())
}
