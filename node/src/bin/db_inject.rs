//! update-db: inject a GOAT message into the local DB.
//!
//! Purpose:
//! - Insert a GOATMessageContent payload into the local SQLite DB so the node
//!   can process it as if it were received from the network.
//!
//! Key args:
//! - --db-path: local SQLite path (e.g., sqlite:/tmp/bitvm-node.db)
//! - --actor: Committee | Operator | Verifier | Watchtower | All
//! - --message-json or --message-file (one required)
//! - --business-id (optional; inferred from content when unambiguous)
//!
//! Example:
//! - cargo run -p bitvm-noded --bin update-db -- \
//!   --db-path sqlite:/tmp/bitvm-node.db \
//!   --actor Operator \
//!   --message-file ./message.json
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use uuid::Uuid;

use bitvm_lib::actors::Actor;
use bitvm_noded::action::*;
use bitvm_noded::utils::upsert_message;
use store::create_local_db;

#[derive(Parser, Debug)]
#[command(name = "db-inject", about = "Insert a GOAT message into the local DB for processing")]
struct Args {
    /// db path
    #[arg(long)]
    db_path: String,

    /// Target actor (Committee, Operator, Verifier, Watchtower, All)
    #[arg(long, value_parser = parse_actor)]
    actor: Actor,

    /// Business id used for message_id (graph_id or instance_id). If omitted, infer it when unambiguous.
    #[arg(long)]
    business_id: Option<String>,

    /// Optional sub-type used when generating message_id
    #[arg(long)]
    sub_type: Option<String>,

    /// from_peer column, defaults to "Manual"
    #[arg(long, default_value = "Manual")]
    from_peer: String,

    /// Message weight (default 0)
    #[arg(long, default_value_t = 0)]
    weight: i64,

    /// Lock time in seconds before the message becomes processable (default 0)
    #[arg(long, default_value_t = 0)]
    lock_secs: i64,

    /// Skip update if the same message_id already exists (default false => upsert)
    #[arg(long, default_value_t = false)]
    skip_if_exists: bool,

    /// Inline JSON for GOATMessageContent (mutually exclusive with --message-file)
    #[arg(long, conflicts_with = "message_file")]
    message_json: Option<String>,

    /// Path to a JSON file containing GOATMessageContent
    #[arg(long)]
    message_file: Option<PathBuf>,
}

fn parse_actor(raw: &str) -> std::result::Result<Actor, String> {
    Actor::from_str(raw).map_err(|_| format!("invalid actor: {raw}"))
}

fn infer_business_id(content: &GOATMessageContent) -> Option<Uuid> {
    match content {
        GOATMessageContent::PeginRequest(v) => Some(v.instance_id),
        GOATMessageContent::ConfirmInstance(v) => Some(v.instance_id),
        GOATMessageContent::InitGraph(v) => Some(v.graph_id),
        GOATMessageContent::GenCircuits(v) => Some(v.graph_id),
        GOATMessageContent::CutCircuits(v) => Some(v.graph_id),
        GOATMessageContent::SolderingProofReady(v) => Some(v.graph_id),
        GOATMessageContent::GraphSetupAck(_) => None,
        GOATMessageContent::VerifierGraphParamsEndorsement(v) => Some(v.graph_id),
        GOATMessageContent::CreateGraph(v) => Some(v.graph_id),
        GOATMessageContent::NonceGeneration(v) => Some(v.graph_id),
        GOATMessageContent::AggNonceConsensus(v) => Some(v.graph_id),
        GOATMessageContent::CommitteePresign(v) => Some(v.graph_id),
        GOATMessageContent::EndorseGraph(v) => Some(v.graph_id),
        GOATMessageContent::GraphFinalize(v) => Some(v.graph_id),
        GOATMessageContent::PeginConfirmNonce(v) => Some(v.instance_id),
        GOATMessageContent::PeginConfirmNonceConsensus(v) => Some(v.instance_id),
        GOATMessageContent::PeginConfirmPartialSig(v) => Some(v.instance_id),
        GOATMessageContent::PostReady(v) => Some(v.instance_id),
        GOATMessageContent::KickoffReady(v) => Some(v.graph_id),
        GOATMessageContent::KickoffSent(v) => Some(v.graph_id),
        GOATMessageContent::PreKickoffSent(v) => Some(v.graph_id),
        GOATMessageContent::ChallengeSent(v) => Some(v.graph_id),
        GOATMessageContent::WatchtowerChallengeInitSent(v) => Some(v.graph_id),
        GOATMessageContent::WatchtowerChallengeSent(v) => Some(v.graph_id),
        GOATMessageContent::WatchtowerChallengeTimeout(v) => Some(v.graph_id),
        GOATMessageContent::NackReady(v) => Some(v.graph_id),
        GOATMessageContent::OperatorCommitPubinReady(v) => Some(v.graph_id),
        GOATMessageContent::OperatorCommitPubinTimeout(v) => Some(v.graph_id),
        GOATMessageContent::AssertReady(v) => Some(v.graph_id),
        GOATMessageContent::AssertSent(v) => Some(v.graph_id),
        GOATMessageContent::ChallengeAssertSent(v) => Some(v.graph_id),
        GOATMessageContent::WronglyChallengeTimeout(v) => Some(v.graph_id),
        GOATMessageContent::DisproveSent(v) => Some(v.graph_id),
        GOATMessageContent::Take1Ready(v) => Some(v.graph_id),
        GOATMessageContent::Take1Sent(v) => Some(v.graph_id),
        GOATMessageContent::Take2Ready(v) => Some(v.graph_id),
        GOATMessageContent::Take2Sent(v) => Some(v.graph_id),
        GOATMessageContent::SyncGraphRequest(v) => Some(v.graph_id),
        GOATMessageContent::SyncGraph(v) => Some(v.graph_id),
        // This payload may refer to multiple graphs, so it has no canonical
        // business id. Require callers to provide --business-id explicitly.
        GOATMessageContent::InstanceDiscarded(_) => None,
        GOATMessageContent::RequestNodeInfo(_) | GOATMessageContent::ResponseNodeInfo(_) => None,
        GOATMessageContent::Tick => None,
    }
}

fn load_message_json(args: &Args) -> Result<String> {
    if let Some(ref inline) = args.message_json {
        return Ok(inline.clone());
    }
    if let Some(ref path) = args.message_file {
        return fs::read_to_string(path).context("read message file");
    }
    Err(anyhow!("either --message-json or --message-file is required"))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let raw_json = load_message_json(&args)?;
    let content: GOATMessageContent =
        serde_json::from_str(&raw_json).context("parse GOATMessageContent JSON")?;

    let business_id = match &args.business_id {
        Some(raw) => Uuid::parse_str(raw).context("parse business_id as UUID")?,
        None => infer_business_id(&content)
            .ok_or_else(|| anyhow!("business_id not provided and cannot be inferred"))?,
    };

    let actor = args.actor;
    let local_db = create_local_db(&args.db_path).await;
    let mut storage_processor = local_db.acquire().await?;
    let is_update = !args.skip_if_exists;

    upsert_message(
        &mut storage_processor,
        is_update,
        business_id,
        args.sub_type.clone(),
        args.from_peer.clone(),
        actor.clone(),
        content,
        args.weight,
        args.lock_secs,
    )
    .await?;

    println!(
        "Inserted message for actor={actor} business_id={business_id} db_path={} update={} lock_secs={} weight={}",
        args.db_path, is_update, args.lock_secs, args.weight
    );
    Ok(())
}
