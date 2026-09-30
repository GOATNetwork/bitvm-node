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

    let actor = args.actor;
    let message_type = content.event_type();
    let local_db = create_local_db(&args.db_path).await;
    let mut storage_processor = local_db.acquire().await?;
    let is_update = !args.skip_if_exists;

    upsert_message(
        &mut storage_processor,
        is_update,
        args.from_peer.clone(),
        actor.clone(),
        content,
        args.weight,
        args.lock_secs,
    )
    .await?;

    println!(
        "Inserted message for actor={actor} message_type={} db_path={} update={} lock_secs={} weight={}",
        message_type, args.db_path, is_update, args.lock_secs, args.weight
    );
    Ok(())
}
