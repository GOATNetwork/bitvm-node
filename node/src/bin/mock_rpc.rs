//! Local-only mock RPC service for interface testing.
//!
//! This starts the Axum RPC routes without P2P, chain watchers, or maintenance tasks,
//! and seeds SQLite with deterministic demo rows.

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use anyhow::{Context, Result};
use bitcoin::Network;
use bitvm_lib::actors::Actor;
use bitvm_noded::env::{
    ENV_BITCOIN_NETWORK, ENV_BITVM_SECRET, ENV_GOAT_ADDRESS, ENV_GOAT_GATEWAY_CONTRACT_ADDRESS,
    ENV_GOAT_NETWORK, ENV_GOAT_SWAP_CONTRACT_ADDRESS,
};
use bitvm_noded::metrics_service::MetricsState;
use bitvm_noded::rpc_service::{self, AppState, current_time_secs};
use bitvm_noded::utils::{generate_local_key, get_rand_btc_address_p2wpkh, get_rand_goat_address};
use clap::Parser;
use client::Utxo;
use prometheus_client::registry::Registry;
use secp256k1::Secp256k1;
use store::localdb::{GraphRuntimeUpdate, StorageProcessor};
use store::{
    BridgeOutGlobalStats, Graph, GraphStatus, GraphStatusSource, Instance, InstanceBridgeInStatus,
    Node, SwapEscrow, SwapEscrowStatus, UInt64Array3, create_local_db,
};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const MOCK_GATEWAY_CONTRACT: &str = "0x1111111111111111111111111111111111111111";
const MOCK_SWAP_CONTRACT: &str = "0x2222222222222222222222222222222222222222";

#[derive(Debug, Parser)]
#[command(author, version, about = "Start a local mock BitVM RPC service")]
struct Opts {
    /// Local RPC service address.
    #[arg(long, default_value = "127.0.0.1:18080")]
    rpc_addr: String,

    /// SQLite database URL or file path. Defaults to a timestamped /tmp database.
    #[arg(long)]
    db_path: Option<String>,

    /// Current node role exposed through AppState.
    #[arg(long, default_value = "Verifier", value_parser = parse_actor)]
    actor: Actor,
}

#[derive(Debug)]
struct MockSeedSummary {
    bridge_in_instance_id: Uuid,
    swap_escrow_hash: String,
    ready_graph_id: Uuid,
    challenge_graph_id: Uuid,
    operator_pubkey: String,
    graph_from_addr: String,
}

fn parse_actor(raw: &str) -> std::result::Result<Actor, String> {
    Actor::from_str(raw).map_err(|_| format!("invalid actor: {raw}"))
}

fn default_db_path() -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|v| v.as_secs()).unwrap_or(0);
    format!("sqlite:/tmp/bitvm-node-mock-{ts}.db")
}

fn normalize_db_path(path: Option<String>) -> String {
    let path = path.unwrap_or_else(default_db_path);
    if path.starts_with("sqlite:") { path } else { format!("sqlite:{path}") }
}

fn set_env_default(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

fn configure_mock_env() {
    set_env_default("RUST_LOG", "info");
    set_env_default(ENV_BITCOIN_NETWORK, "testnet4");
    set_env_default(ENV_GOAT_NETWORK, "test");
    set_env_default(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, MOCK_GATEWAY_CONTRACT);
    set_env_default(ENV_GOAT_SWAP_CONTRACT_ADDRESS, MOCK_SWAP_CONTRACT);
    set_env_default(ENV_BITVM_SECRET, "seed:mock-rpc-service");
    set_env_default(ENV_GOAT_ADDRESS, "0x3333333333333333333333333333333333333333");
}

fn mock_uuid(raw: &str) -> Uuid {
    Uuid::parse_str(raw).expect("valid mock UUID")
}

fn mock_tx_hash(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn mock_goat_addr(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 20]))
}

fn mock_btc_pubkey() -> String {
    let (_, public_key) = Secp256k1::new().generate_keypair(&mut rand::thread_rng());
    public_key.to_string()
}

fn mock_peer_id() -> String {
    generate_local_key().public().to_peer_id().to_string()
}

fn seeded_node(
    peer_id: String,
    actor: Actor,
    node_name: &str,
    btc_pub_key: String,
    now: i64,
) -> Node {
    Node {
        peer_id,
        actor: actor.to_string(),
        node_name: node_name.to_string(),
        goat_addr: get_rand_goat_address(),
        btc_pub_key,
        socket_addr: "127.0.0.1:18080".to_string(),
        reward: "0".to_string(),
        service_fee_rate: 0.001,
        available_peg_btc: U256::from(4_700_000_000_000_000_000_000_000_u128).to_string(),
        updated_at: now,
        created_at: now,
    }
}

fn seeded_bridge_in_instance(
    instance_id: Uuid,
    status: InstanceBridgeInStatus,
    amount: i64,
    now: i64,
    utxo_byte: u8,
) -> Result<Instance> {
    let utxo = vec![Utxo { txid: [utxo_byte; 32], vout: 0, amount_sats: amount as u64 }];
    Ok(Instance {
        instance_id,
        network: Network::Testnet4.to_string(),
        from_addr: get_rand_btc_address_p2wpkh(Network::Testnet4),
        to_addr: mock_goat_addr(0x31),
        amount,
        fees: UInt64Array3([1_000, 2_000, 3_000]),
        input_utxos: serde_json::to_string(&utxo)?,
        status: status.to_string(),
        goat_tx_hash: mock_tx_hash(0xa1),
        goat_tx_height: 123_456,
        user_change_addr: get_rand_btc_address_p2wpkh(Network::Testnet4),
        user_refund_addr: get_rand_btc_address_p2wpkh(Network::Testnet4),
        pegin_data_tx_hash: mock_tx_hash(0xa2),
        post_pegin_txhash: Some(mock_tx_hash(0xa3)),
        status_updated_at: now - 120,
        created_at: now - 3_600,
        updated_at: now,
        ..Default::default()
    })
}

fn seeded_swap_escrow(escrow_hash: String, now: i64) -> SwapEscrow {
    SwapEscrow {
        escrow_hash,
        network: Network::Testnet4.to_string(),
        status: SwapEscrowStatus::Initialize.to_string(),
        offerer_addr: mock_goat_addr(0x41),
        claimer_addr: mock_goat_addr(0x42),
        btc_addr: get_rand_btc_address_p2wpkh(Network::Testnet4),
        token: mock_goat_addr(0x43),
        amount: "25000000".to_string(),
        refund_deadline: now + 3_600,
        escrow_data: Some(hex::encode([0xe1; 64])),
        init_tx_hash: mock_tx_hash(0xb1),
        init_tx_height: 123_500,
        status_updated_at: now - 60,
        created_at: now - 900,
        updated_at: now,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn seeded_graph(
    graph_id: Uuid,
    instance_id: Uuid,
    kickoff_index: i64,
    status: GraphStatus,
    operator_pubkey: &str,
    from_addr: &str,
    now: i64,
    init_withdraw_tx_hash: Option<String>,
    sub_status: String,
) -> Graph {
    Graph {
        graph_id,
        instance_id,
        kickoff_index,
        from_addr: from_addr.to_string(),
        to_addr: get_rand_btc_address_p2wpkh(Network::Testnet4),
        amount: 10_000_000,
        challenge_amount: 1_000_000,
        status: status.to_string(),
        sub_status,
        operator_pubkey: operator_pubkey.to_string(),
        definition_hash: format!("mock-{graph_id}"),
        init_withdraw_tx_hash,
        bridge_out_start_at: now - 300,
        status_updated_at: now - 120,
        proceed_withdraw_height: 899_980,
        created_at: now - 7_200,
        updated_at: now,
        ..Default::default()
    }
}

async fn seed_graph_runtime(tx: &mut StorageProcessor<'_>, graph: &Graph) -> Result<()> {
    let target_status = GraphStatus::from_str(&graph.status)
        .map_err(|_| anyhow::anyhow!("invalid mock graph status {}", graph.status))?;
    let sub_status = graph.sub_status.clone();
    let challenge_txid = graph.challenge_txid.clone();
    let init_withdraw_tx_hash = graph.init_withdraw_tx_hash.clone();
    let bridge_out_start_at = graph.bridge_out_start_at;
    let proceed_withdraw_height = graph.proceed_withdraw_height;

    let mut definition = graph.clone();
    definition.status = GraphStatus::OperatorPresigned.to_string();
    definition.sub_status.clear();
    definition.challenge_txid = None;
    definition.init_withdraw_tx_hash = None;
    definition.bridge_out_start_at = 0;
    definition.proceed_withdraw_height = 0;
    tx.upsert_graph_definition(&definition).await?;

    if target_status != GraphStatus::OperatorPresigned {
        tx.transition_graph_status(
            graph.instance_id,
            graph.graph_id,
            target_status,
            GraphStatusSource::ChainReconcile,
            (!sub_status.is_empty()).then_some(sub_status),
        )
        .await?;
    }

    let mut runtime = GraphRuntimeUpdate::new(graph.instance_id, graph.graph_id);
    if let Some(challenge_txid) = challenge_txid {
        runtime = runtime.with_challenge_txid(challenge_txid);
    }
    if let Some(init_withdraw_tx_hash) = init_withdraw_tx_hash {
        runtime = runtime.with_init_withdraw_tx_hash(init_withdraw_tx_hash);
    }
    if bridge_out_start_at != 0 {
        runtime = runtime.with_bridge_out_start_at(bridge_out_start_at);
    }
    if proceed_withdraw_height != 0 {
        runtime = runtime.with_proceed_withdraw_height(proceed_withdraw_height);
    }
    tx.update_graph_runtime(&runtime).await?;
    Ok(())
}

async fn seed_mock_data(
    local_db: &store::localdb::LocalDB,
    current_peer_id: &str,
    actor: Actor,
) -> Result<MockSeedSummary> {
    let now = current_time_secs();
    let operator_pubkey = mock_btc_pubkey();
    let graph_from_addr = mock_goat_addr(0x51);
    let bridge_in_instance_id = mock_uuid("11111111-1111-1111-1111-111111111111");
    let bridge_in_pending_id = mock_uuid("11111111-1111-1111-1111-111111111112");
    let ready_graph_id = mock_uuid("33333333-3333-3333-3333-333333333333");
    let challenge_graph_id = mock_uuid("33333333-3333-3333-3333-333333333334");
    let escrow_hash = mock_tx_hash(0xc1);

    let current_node =
        seeded_node(current_peer_id.to_string(), actor, "mock-current", mock_btc_pubkey(), now);
    let committee_node =
        seeded_node(mock_peer_id(), Actor::Committee, "mock-committee", mock_btc_pubkey(), now);
    let operator_node =
        seeded_node(mock_peer_id(), Actor::Operator, "mock-operator", operator_pubkey.clone(), now);
    let watchtower_node =
        seeded_node(mock_peer_id(), Actor::Watchtower, "mock-watchtower", mock_btc_pubkey(), now);

    let bridge_in_success = seeded_bridge_in_instance(
        bridge_in_instance_id,
        InstanceBridgeInStatus::RelayerL2Minted,
        10_000_000,
        now,
        0x11,
    )?;
    let bridge_in_pending = seeded_bridge_in_instance(
        bridge_in_pending_id,
        InstanceBridgeInStatus::UserInited,
        1_000_000,
        now,
        0x12,
    )?;
    let swap_escrow = seeded_swap_escrow(escrow_hash.clone(), now);

    let none_sub_status = r#"{"watchtower_challenge_status":[],"verifier_challenge_status":[],"disprove_type":null,"disprove_index":-1}"#.to_string();
    let challenge_sub_status = r#"{"watchtower_challenge_status":[true,false],"verifier_challenge_status":["None"],"disprove_type":null,"disprove_index":-1}"#.to_string();
    let ready_graph = seeded_graph(
        ready_graph_id,
        bridge_in_instance_id,
        0,
        GraphStatus::OperatorDataPushed,
        &operator_pubkey,
        &graph_from_addr,
        now,
        None,
        none_sub_status.clone(),
    );
    let challenge_graph = seeded_graph(
        challenge_graph_id,
        bridge_in_instance_id,
        1,
        GraphStatus::Challenge,
        &operator_pubkey,
        &graph_from_addr,
        now,
        Some(mock_tx_hash(0xd1)),
        challenge_sub_status,
    );

    let mut tx = local_db.start_transaction().await?;
    for node in [current_node, committee_node, operator_node, watchtower_node] {
        tx.upsert_node(&node).await?;
    }
    for instance in [bridge_in_success, bridge_in_pending] {
        tx.upsert_instance(&instance).await?;
    }
    tx.insert_swap_escrow_if_absent(&swap_escrow).await?;
    for graph in [ready_graph, challenge_graph] {
        seed_graph_runtime(&mut tx, &graph).await?;
    }
    tx.upsert_bridge_out_global_stats(&BridgeOutGlobalStats {
        id: 1,
        initial_txn: 1,
        initial_amount: "25000000".to_string(),
        claim_txn: 1,
        claim_amount: "12000000".to_string(),
        refund_txn: 0,
        refund_amount: "0".to_string(),
        created_at: now,
        updated_at: now,
    })
    .await?;
    tx.commit().await?;

    Ok(MockSeedSummary {
        bridge_in_instance_id,
        swap_escrow_hash: escrow_hash,
        ready_graph_id,
        challenge_graph_id,
        operator_pubkey,
        graph_from_addr,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    configure_mock_env();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let opts = Opts::parse();
    let db_path = normalize_db_path(opts.db_path);
    let local_key = generate_local_key();
    let peer_id = local_key.public().to_peer_id().to_string();
    let local_db = create_local_db(&db_path).await;
    let seed_summary =
        seed_mock_data(&local_db, &peer_id, opts.actor.clone()).await.context("seed mock data")?;

    let registry = Arc::new(Mutex::new(Registry::default()));
    let app_state = AppState::create_arc_mock_app_state(
        local_db,
        opts.actor,
        peer_id,
        MetricsState::new(registry),
    )
    .await?;
    let cancellation_token = CancellationToken::new();
    let shutdown_token = cancellation_token.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            shutdown_token.cancel();
        }
    });

    println!("Mock RPC listening on http://{}", opts.rpc_addr);
    println!("DB path: {db_path}");
    println!("Gateway contract: {MOCK_GATEWAY_CONTRACT}");
    println!("Swap contract: {MOCK_SWAP_CONTRACT}");
    println!("Bridge-in instance: {}", seed_summary.bridge_in_instance_id);
    println!("Swap escrow: {}", seed_summary.swap_escrow_hash);
    println!("Ready graph: {}", seed_summary.ready_graph_id);
    println!("Challenge graph: {}", seed_summary.challenge_graph_id);
    println!("Operator pubkey: {}", seed_summary.operator_pubkey);
    println!("Graph from_addr: {}", seed_summary.graph_from_addr);

    rpc_service::serve_with_app_state(opts.rpc_addr, app_state, cancellation_token).await?;
    Ok(())
}
