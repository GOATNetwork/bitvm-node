#![allow(dead_code)]
use crate::action::NodeInfo;
use alloy::primitives::Address as EvmAddress;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use base64::Engine;
use bitcoin::{Network, PublicKey, key::Keypair};
use bitvm_lib::actors::Actor;
use bitvm_lib::keys::NodeMasterKey;
use bitvm_lib::timelocks::{default_connector_z_timelock_blocks, estimated_block_interval_secs};
use client::goat_chain::utils::{
    get_committee_management_contract, get_gateway_relay_contracts, is_validate_committee,
};
use client::goat_chain::{GoatInitConfig, GoatNetwork};
use libp2p::PeerId;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::str::FromStr;
use strum::{Display, EnumString};
use tracing::{info, warn};
use util::hex_parse;
use zeroize::Zeroizing;

pub const ENV_BTC_CHAIN_URL: &str = "BTC_CHAIN_URL";
pub const ENV_GOAT_CHAIN_URL: &str = "GOAT_CHAIN_URL";
pub const ENV_PROOF_BUILD_URL: &str = "GOAT_PROOF_BUILD_URL";
pub const ENV_GOAT_GATEWAY_CONTRACT_ADDRESS: &str = "GOAT_GATEWAY_CONTRACT_ADDRESS";
pub const ENV_GOAT_SWAP_CONTRACT_ADDRESS: &str = "GOAT_SWAP_CONTRACT_ADDRESS";
pub const ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS: &str =
    "GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS";
pub const ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS: &str =
    "ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS";
pub const ENV_ENABLE_RELAYER: &str = "ENABLE_RELAYER";
pub const ENV_ENABLE_UPDATE_SPV_CONTRACT: &str = "ENABLE_UPDATE_SPV_CONTRACT";
pub const ENV_ENABLE_BABE_SETUP_STATE_CLEANUP: &str = "ENABLE_BABE_SETUP_STATE_CLEANUP";
pub const ENV_BTC_BLOCK_CONFIRMS: &str = "BTC_BLOCK_CONFIRMS";
pub const ENV_GOAT_PRIVATE_KEY: &str = "GOAT_PRIVATE_KEY";

pub const ENV_GOAT_GATEWAY_EVENT_THE_GRAPH_URL: &str = "GOAT_GATEWAY_EVENT_THE_GRAPH_URL";
pub const ENV_GOAT_GATEWAY_EVENT_FILTER_FROM: &str = "GOAT_GATEWAY_EVENT_FILTER_FROM";
pub const ENV_GOAT_GATEWAY_EVENT_FILTER_GAP: &str = "GOAT_GATEWAY_EVENT_FILTER_GAP";

pub const ENV_GOAT_SWAP_EVENT_THE_GRAPH_URL: &str = "GOAT_SWAP_EVENT_THE_GRAPH_URL";
pub const ENV_GOAT_SWAP_EVENT_FILTER_FROM: &str = "GOAT_SWAP_EVENT_FILTER_FROM";
pub const ENV_GOAT_SWAP_EVENT_FILTER_GAP: &str = "GOAT_SWAP_EVENT_FILTER_GAP";

/// Operator Challenge
pub const ENV_NODE_NAME: &str = "NODE_NAME";
pub const DEFAULT_NODE_NAME: &str = "ZKM";
pub const ENV_OPERATOR_NODE_SERVICE_FEE_RATE: &str = "OPERATOR_NODE_SERVICE_FEE";
pub const DEFAULT_OPERATOR_NODE_SERVICE_FEE_RATE: f64 = 0.001;
pub const ENV_GOAT_ADDRESS: &str = "GOAT_ADDRESS";
/// Operator(private key), Relayer(private key),  Committee(seed)
pub const ENV_BITVM_SECRET: &str = "BITVM_SECRET";
/// All actors
pub const ENV_PEER_KEY: &str = "PEER_KEY";
pub const ENV_PROOF_SEVER_URL: &str = "PROOF_SEVER_URL";
pub const ENV_ACTOR: &str = "ACTOR";
pub const ENV_IPFS_ENDPOINT: &str = "IPFS_ENDPOINT";
pub const ENV_COMMITTEE_NUM: &str = "COMMITTEE_NUM";
pub const ENV_MIN_REQUIRED_VERIFIER: &str = "MIN_REQUIRED_VERIFIER";
pub const ENV_VERIFIER_CANDIDATE_BACKUP_COUNT: &str = "VERIFIER_CANDIDATE_BACKUP_COUNT";
pub const ENV_VERIFIER_CANDIDATE_COLLECTION_WINDOW_SECS: &str =
    "VERIFIER_CANDIDATE_COLLECTION_WINDOW_SECS";
pub const ENV_P2P_GRAPH_SETUP_RETRY_INTERVAL_SECS: &str = "P2P_GRAPH_SETUP_RETRY_INTERVAL_SECS";
pub const ENV_P2P_GRAPH_SETUP_RETRY_WINDOW_SECS: &str = "P2P_GRAPH_SETUP_RETRY_WINDOW_SECS";
pub const ENV_EXTERNAL_SOCKET_ADDR: &str = "EXTERNAL_SOCKET_ADDR";
pub const COMMITTEE_INSTANCE_KEYS_DIR: &str = "cache/committee-instance-keys/";
pub const SCRIPT_CACHE_FILE_NAME: &str = "cache/partial_script.bin";
pub const ASSERT_COMMITS_CACHE_DIR: &str = "cache/assert_commits_cache/";
pub const IPFS_GRAPH_CACHE_DIR: &str = "cache/graph_cache/";
pub const DUST_AMOUNT: u64 = goat::transactions::base::DUST_AMOUNT;
pub const MAX_CUSTOM_INPUTS: usize = 100;

pub const DEFAULT_CONFIRMATION_TARGET: u16 = 1;
pub const DEFAULT_MIN_REQUIRED_VERIFIER: usize = 1;
pub const DEFAULT_VERIFIER_CANDIDATE_BACKUP_COUNT: usize = 2;
pub const DEFAULT_VERIFIER_CANDIDATE_COLLECTION_WINDOW_SECS: i64 = 15;
pub const DEFAULT_P2P_GRAPH_SETUP_RETRY_INTERVAL_SECS: i64 = 10;
pub const DEFAULT_P2P_GRAPH_SETUP_RETRY_WINDOW_SECS: i64 = 180;

pub const ENV_BITCOIN_NETWORK: &str = "BITCOIN_NETWORK";
pub const ENV_GOAT_NETWORK: &str = "GOAT_NETWORK";

pub const ENV_WATCHTOWER_PROOF_WAIT_SECS: &str = "WATCHTOWER_PROOF_WAIT_SECS";
pub const ENV_OPERATOR_PROOF_WAIT_SECS: &str = "OPERATOR_PROOF_WAIT_SECS";
pub const ENV_OPERATOR_VK_HASH: &str = "OPERATOR_VK_HASH";
pub const ENV_OPERATOR_ZKM_VERSION: &str = "OPERATOR_ZKM_VERSION";
pub const DEFAULT_WATCHTOWER_PROOF_WAIT_SECS: usize = 60;
pub const DEFAULT_OPERATOR_PROOF_WAIT_SECS: usize = 60;
pub const ENV_FGC_GATES_PATH: &str = "FGC_GATES_PATH";
pub const ENV_FGC_OUT_INDICES_PATH: &str = "FGC_OUT_INDICES_PATH";
pub const ENV_SGC_GATES_PATH: &str = "SGC_GATES_PATH";
pub const ENV_SGC_OUT_INDICES_PATH: &str = "SGC_OUT_INDICES_PATH";
pub const ENV_FGC_COMPACT_GATES_PATH: &str = "FGC_COMPACT_GATES_PATH";
pub const ENV_FGC_COMPACT_OUT_INDICES_PATH: &str = "FGC_COMPACT_OUT_INDICES_PATH";
pub const ENV_SGC_COMPACT_GATES_PATH: &str = "SGC_COMPACT_GATES_PATH";
pub const ENV_SGC_COMPACT_OUT_INDICES_PATH: &str = "SGC_COMPACT_OUT_INDICES_PATH";
pub const ENV_BABE_SETUP_STATE_DIR: &str = "BABE_SETUP_STATE_DIR";
pub const ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH: &str = "SOLDERING_PROOF_PAYLOAD_STORE_PATH";

pub const ENV_ALWAYS_CHALLENGE: &str = "ALWAYS_CHALLENGE";
pub const ENV_GENESIS_SEQUENCER_COMMIT_TXID: &str = "GENESIS_SEQUENCER_COMMIT_TXID";
pub const ENV_SEQUENCER_SET_MONITOR_START_COSMOS_BLOCK: &str =
    "SEQUENCER_SET_MONITOR_START_COSMOS_BLOCK";
pub const ENV_COSMOS_RPC_URL: &str = "COSMOS_RPC_URL";
pub const DEFAULT_COSMOS_RPC_URL: &str = "https://rpc.testnet3.goat.network/goat-rpc";

// fee estimate
// TODO: more precise fee estimation
pub const CHEKSIG_P2WSH_INPUT_VBYTES: u64 = 100;
pub const CHEKSIG_P2TR_INPUT_VBYTES: u64 = 100;
pub const P2WSH_OUTPUT_VBYTES: u64 = 50;
pub const P2TR_OUTPUT_VBYTES: u64 = 50;
pub const P2A_OUTPUT_VBYTES: u64 = 50;
pub const PRE_KICKOFF_BASE_VBYTES: u64 = 300;
pub const PEGIN_BASE_VBYTES: u64 = 300;
pub const CHALLENGE_BASE_VBYTES: u64 = 300;
pub const ANCHOR_CHILD_BASE_VBYTES: u64 = 200;

// reduce costs to facilitate testing
pub const MIN_SATKE_AMOUNT: u64 = 4_000_000; // 0.04 BTC
pub const MIN_CHALLENGE_AMOUNT: u64 = 1_000_000; // 0.01 BTC
pub const STAKE_RATE: u64 = 0; // 0%
pub const CHALLENGE_RATE: u64 = 0; // 0%

pub const RATE_MULTIPLIER: u64 = 10000;

const COMMITTEE_MEMBER_NUMBER: usize = 2;

pub const MESSAGE_BROADCAST_MAX_TIMES: i64 = 3;
pub const MESSAGE_RESEND_INTERVAL_SECOND: i64 = 60 * 5;
pub const MESSAGE_EXPIRE_TIME: i64 = 3600 * 24 * 15; // 15 days for test

pub const MESSAGE_SAVE_INTERVAL_SECOND: i64 = 3600 * 24 * 3;

pub const GRAPH_OPERATOR_DATA_UPLOAD_TIME_EXPIRED: i64 = 3600 * 48;

pub const SYNC_GRAPH_INTERVAL: u64 = 3;
pub const SYNC_GRAPH_MAX_WAIT_SECS: u64 = 30;

// use to judge load history event thread is dead
pub const LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS: i64 = 600;

pub const GATEWAY_RATE_MULTIPLIER: u64 = 10000;

pub const HEARTBEAT_INTERVAL_SECOND: u64 = 60 * 5;
pub const REGULAR_TASK_INTERVAL_SECOND: u64 = 20;
pub const SEQUENCER_SET_MONITOR_INTERVAL_SECS: u64 = 5;
pub const ENV_INSTANCE_MAINTENANCE_BATCH_SIZE: &str = "INSTANCE_MAINTENANCE_BATCH_SIZE";
pub const DEFAULT_INSTANCE_MAINTENANCE_BATCH_SIZE: u32 = 50;
pub const ENV_MAINTENANCE_RUN_TIMEOUT_SECS: &str = "MAINTENANCE_RUN_TIMEOUT_SECS";
pub const DEFAULT_MAINTENANCE_RUN_TIMEOUT_SECS: u64 = 60;
pub const ENV_P2P_INBOX_BATCH_SIZE: &str = "P2P_INBOX_BATCH_SIZE";
pub const DEFAULT_P2P_INBOX_BATCH_SIZE: i64 = 16;
pub const ENV_P2P_OUTBOX_BATCH_SIZE: &str = "P2P_OUTBOX_BATCH_SIZE";
pub const DEFAULT_P2P_OUTBOX_BATCH_SIZE: i64 = 16;
pub const ENV_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE: &str = "ENABLE_COMMITTEE_INSTANCE_KEY_DELETE";
pub const DEFAULT_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE: bool = false;
pub const ENV_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS: &str =
    "COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS";
pub const DEFAULT_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS: i64 = 32;

pub fn get_network() -> Network {
    let network = std::env::var(ENV_BITCOIN_NETWORK).unwrap_or("testnet4".to_string());
    match network.as_str() {
        "bitcoin" => Network::Bitcoin,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => {
            warn!(
                "Unknown BTC network: {network}, expect bitcoin, testnet4, signet or regtest, return testnet by default"
            );
            Network::Testnet4
        }
    }
}

pub fn get_instance_presigned_time_expired_secs() -> i64 {
    let network = get_network();
    let connector_z_blocks = default_connector_z_timelock_blocks(network) as i64;
    estimated_block_interval_secs(network) * connector_z_blocks * 2 / 3
}

pub fn get_goat_network() -> GoatNetwork {
    let network = std::env::var(ENV_GOAT_NETWORK).unwrap_or("test".to_string());
    match network.as_str() {
        "main" => GoatNetwork::Main,
        "test" => GoatNetwork::Test,
        _ => {
            warn!("Unknown GOAT network: {network}, expect main, or test, return test by default");
            GoatNetwork::Test
        }
    }
}

/// Get the entropy of WOTS keys for current node
///   Note: SEED should be used on production environment
pub fn get_bitvm_secret() -> String {
    let bitvm_secret = std::env::var(ENV_BITVM_SECRET).expect("{ENV_BITVM_SECRET} is missing");
    if !bitvm_secret.starts_with("seed:") {
        return bitvm_secret;
    }
    // derive private key from seed
    let hashed = Sha256::digest(bitvm_secret.as_bytes());
    let sk = secp256k1::SecretKey::from_slice(&hashed).expect("valid secret key");
    hex::encode(sk.secret_bytes()).to_string()
}

pub fn get_bitvm_key() -> anyhow::Result<Keypair> {
    // TODO: what if node restart with different BITVM_SECRET ?
    let bitvm_secret = get_bitvm_secret();
    Ok(Keypair::from_seckey_str_global(&bitvm_secret)?)
}

pub fn get_node_pubkey() -> anyhow::Result<PublicKey> {
    Ok(NodeMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

pub fn get_actor() -> Actor {
    Actor::from_str(std::env::var(ENV_ACTOR).unwrap_or("Verifier".to_string()).as_str())
        .expect("Expect one of Committee, Verifier, Operator or Relayer")
}

pub fn get_peer_key() -> String {
    std::env::var(ENV_PEER_KEY).expect("Peer key is missing")
}

pub fn get_peer_id() -> String {
    let local_key = get_peer_key();
    let key_pair = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(local_key).expect("fail to decode base64"),
    ))
    .expect("failed to gen keypair");
    key_pair.public().to_peer_id().to_string()
}

pub fn is_relayer() -> bool {
    let enable_relayer = match std::env::var(ENV_ENABLE_RELAYER) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    };
    enable_relayer && get_actor() == Actor::Committee
}

pub fn is_enable_update_spv_contract() -> bool {
    match std::env::var(ENV_ENABLE_UPDATE_SPV_CONTRACT) {
        Ok(value) => value.to_lowercase() == "true",
        Err(_) => false,
    }
}

pub fn is_enable_babe_setup_state_cleanup() -> bool {
    match std::env::var(ENV_ENABLE_BABE_SETUP_STATE_CLEANUP) {
        Ok(value) => value.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

pub fn get_btc_block_confirms(network: Network) -> u32 {
    std::env::var(ENV_BTC_BLOCK_CONFIRMS)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(util::get_btc_block_confirms(network))
}

pub fn get_node_goat_private_key() -> anyhow::Result<String> {
    std::env::var(ENV_GOAT_PRIVATE_KEY).map_err(|_| anyhow::anyhow!("Goat private key is missing"))
}

pub fn get_node_goat_address() -> Option<EvmAddress> {
    if let Ok(private_key_hex) = get_node_goat_private_key() {
        let singer =
            PrivateKeySigner::from_str(&private_key_hex).expect("fail to decode goat private key");
        Some(singer.address())
    } else {
        let mut addr_op = None;
        if let Ok(addr_str) = std::env::var(ENV_GOAT_ADDRESS)
            && let Ok(addr) = EvmAddress::from_str(&addr_str)
        {
            addr_op = Some(addr);
        }

        addr_op
    }
}

pub async fn check_node_info() {
    if [Actor::Committee.to_string()].contains(&get_actor().to_string())
        && std::env::var(ENV_GOAT_PRIVATE_KEY).is_err()
    {
        panic!("Relayer and Committee must set goat secret key");
    }
    let node_info = get_local_node_info();
    if [Actor::Operator.to_string(), Actor::Verifier.to_string()].contains(&node_info.actor)
        && node_info.goat_addr.is_empty()
    {
        panic!("Operator and Verifier must set goat address or goat secret key");
    }
    if Actor::Committee.to_string() == node_info.actor
        || Actor::Operator.to_string() == node_info.actor
    {
        let rpc_url = get_goat_url_from_env();
        let gateway_address = get_goat_gateway_contract_from_env();
        let provider = ProviderBuilder::new().connect_http(rpc_url);
        let committee_management_address =
            get_committee_management_contract(&provider, gateway_address)
                .await
                .expect("fail to get committee manager address");
        let peer_id = PeerId::from_str(&node_info.peer_id).expect("fail to decode");

        if node_info.actor == Actor::Committee.to_string() {
            match is_validate_committee(
                &provider,
                committee_management_address,
                &peer_id.to_bytes(),
            )
            .await
            {
                Ok(is_legal) => {
                    if is_legal {
                        info!("Committee is legal!");
                    } else {
                        panic!("Committee is illegal as not finish register! ")
                    }
                }
                Err(err) => {
                    panic!("Committee validate failed, err:{err:?}")
                }
            }
        }
    }
}
pub fn get_local_node_info() -> NodeInfo {
    let actor = get_actor();
    let peer_key = get_peer_id();
    let pubkey_str = get_node_pubkey().expect("fail to get pubkey").to_string();
    let goat_address = if let Ok(private_key_hex) = std::env::var(ENV_GOAT_PRIVATE_KEY) {
        let singer =
            PrivateKeySigner::from_str(&private_key_hex).expect("fail to decode goat private key");
        Some(singer.address().to_string())
    } else {
        let mut addr_op = None;
        if let Ok(addr_str) = std::env::var(ENV_GOAT_ADDRESS)
            && let Ok(addr) = Address::from_str(&addr_str)
        {
            addr_op = Some(addr.to_string());
        }

        addr_op
    };
    let socket_addr = std::env::var(ENV_EXTERNAL_SOCKET_ADDR).unwrap_or("".to_string());
    NodeInfo {
        peer_id: peer_key,
        actor: actor.to_string(),
        goat_addr: goat_address.unwrap_or("".to_string()),
        btc_pub_key: pubkey_str,
        socket_addr,
        node_name: get_node_name(),
        service_fee_rate: get_operator_node_service_fee_rate(),
        available_peg_btc: "0".to_string(),
    }
}
pub fn get_committee_member_num() -> usize {
    COMMITTEE_MEMBER_NUMBER
}

#[derive(Clone, Copy, Display, EnumString)]
pub enum GraphBtcTxName {
    #[strum(serialize = "cur-pre-kickoff.hex")]
    CurPreKickoff,
    #[strum(serialize = "next-pre-kickoff.hex")]
    NextPreKickoff,
    #[strum(serialize = "force-skip-kickoff.hex")]
    ForceSkipKickoff,
    #[strum(serialize = "quick-challenge.hex")]
    QuickChallenge,
    #[strum(serialize = "challenge-incomplete-kickoff.hex")]
    ChallengeIncompleteKickoff,
    #[strum(serialize = "pegin.hex")]
    Pegin,
    #[strum(serialize = "kickoff.hex")]
    Kickoff,
    #[strum(serialize = "take1.hex")]
    Take1,
    #[strum(serialize = "challenge.hex")]
    Challenge,
    #[strum(serialize = "watchtower-challenge-init.hex")]
    WatchtowerChallengeInit,
    #[strum(serialize = "operator-assert.hex")]
    OperatorAssert,
    #[strum(serialize = "verifier-assert.hex")]
    VerifierAssert,
    #[strum(serialize = "disprove.hex")]
    Disprove,
    #[strum(serialize = "take2.hex")]
    Take2,
}
pub fn get_btc_url_from_env() -> Option<String> {
    std::env::var(ENV_BTC_CHAIN_URL).ok()
}

pub fn get_sequencer_set_monitor_start_cosmos_block_from_env() -> Option<u64> {
    std::env::var(ENV_SEQUENCER_SET_MONITOR_START_COSMOS_BLOCK)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
}

pub fn get_cosmos_rpc_url_from_env() -> String {
    std::env::var(ENV_COSMOS_RPC_URL).unwrap_or(DEFAULT_COSMOS_RPC_URL.to_string())
}

pub fn get_goat_url_from_env() -> Url {
    std::env::var(ENV_GOAT_CHAIN_URL)
        .ok()
        .and_then(|url_str| url_str.parse::<Url>().ok())
        .unwrap_or_else(|| panic!("Fail to get url from env"))
}

pub fn get_goat_address_from_env(var_name: &str) -> Option<EvmAddress> {
    let address_str = std::env::var(var_name).ok()?;
    address_str.parse::<EvmAddress>().ok()
}

pub fn get_goat_gateway_contract_from_env() -> EvmAddress {
    get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .unwrap_or_else(|| panic!("Failed to get goat address from env"))
}

pub fn get_goat_gateway_event_filter_from_from_env() -> i64 {
    let event_filter_from_str =
        std::env::var(ENV_GOAT_GATEWAY_EVENT_FILTER_FROM).unwrap_or("8454507".to_string());
    event_filter_from_str
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("Failed to parse {event_filter_from_str} to i64"))
}
pub fn get_goat_swap_event_filter_from_from_env() -> i64 {
    let event_filter_from_str =
        std::env::var(ENV_GOAT_SWAP_EVENT_FILTER_FROM).unwrap_or("8454507".to_string());
    event_filter_from_str
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("Failed to parse {event_filter_from_str} to i64"))
}

pub fn get_goat_gateway_event_filter_gap_from_env() -> i64 {
    let event_filter_gap_str =
        std::env::var(ENV_GOAT_GATEWAY_EVENT_FILTER_GAP).unwrap_or("1000".to_string());
    event_filter_gap_str
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("Failed to parse {event_filter_gap_str} to address"))
}
pub fn get_goat_swap_event_filter_gap_from_env() -> i64 {
    let event_filter_gap_str =
        std::env::var(ENV_GOAT_SWAP_EVENT_FILTER_GAP).unwrap_or("1000".to_string());
    event_filter_gap_str
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("Failed to parse {event_filter_gap_str} to address"))
}

pub fn get_goat_gateway_the_graph_urls_from_env() -> String {
    std::env::var(ENV_GOAT_GATEWAY_EVENT_THE_GRAPH_URL)
        .unwrap_or("https://graph.goat.network/subgraphs/name/bitvm_gateway_dev".to_string())
}

pub fn get_goat_swap_the_graph_urls_from_env() -> String {
    std::env::var(ENV_GOAT_SWAP_EVENT_THE_GRAPH_URL)
        .unwrap_or("https://graph.goat.network/subgraphs/name/bitvm_escrow_manager_dev".to_string())
}

pub async fn goat_config_from_env() -> GoatInitConfig {
    let rpc_url = get_goat_url_from_env();
    let private_key = std::env::var(ENV_GOAT_PRIVATE_KEY).ok();
    let gateway_address = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS);
    let (
        chain_id,
        committee_management_address,
        stake_management_address,
        btc_spv_address,
        peg_btc_address,
    ) = {
        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
        let chain_id = provider
            .get_chain_id()
            .await
            .unwrap_or_else(|_| panic!("cannot get chain_id from {rpc_url}"))
            as u32;

        let (
            committee_management_address,
            stake_management_address,
            btc_spv_address,
            peg_btc_address,
        ) = if let Some(gateway_address) = gateway_address {
            let (committee_management_address, stake_management_address, btc_spv_address, peg_btc_address) =
                    get_gateway_relay_contracts(&provider, gateway_address).await.expect(
                        "fail to get committee, stake management, btc spv, peg btc contract online addresses",
                    );
            (
                Some(committee_management_address),
                Some(stake_management_address),
                Some(btc_spv_address),
                Some(peg_btc_address),
            )
        } else {
            (None, None, None, None)
        };
        (
            chain_id,
            committee_management_address,
            stake_management_address,
            btc_spv_address,
            peg_btc_address,
        )
    };

    GoatInitConfig {
        rpc_url,
        chain_id,
        private_key,
        gateway_address,
        sequencer_set_publisher_address: get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS,
        ),
        committee_management_address,
        stake_management_address,
        multi_sig_verifier_address: get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
        ),
        btc_spv_address,
        peg_btc_address,
    }
}

const DEFAULT_PROTO_NAME_BASE: &str = "bitvm";
pub fn get_proto_base() -> String {
    match std::env::var("PROTO_NAME") {
        Ok(proto_name) => {
            if proto_name.trim().is_empty() {
                DEFAULT_PROTO_NAME_BASE.to_string()
            } else {
                proto_name
            }
        }
        _ => DEFAULT_PROTO_NAME_BASE.to_owned(),
    }
}

pub fn get_rpc_support_actors() -> Vec<Actor> {
    vec![Actor::Committee]
}

pub fn get_proof_server_url() -> Option<String> {
    std::env::var(ENV_PROOF_SEVER_URL).ok()
}

pub fn get_node_name() -> String {
    std::env::var(ENV_NODE_NAME).unwrap_or(DEFAULT_NODE_NAME.to_owned())
}

pub fn get_operator_node_service_fee_rate() -> f64 {
    if let Ok(service_fee) = std::env::var(ENV_OPERATOR_NODE_SERVICE_FEE_RATE)
        && let Ok(fee) = service_fee.parse::<f64>()
    {
        fee
    } else {
        DEFAULT_OPERATOR_NODE_SERVICE_FEE_RATE
    }
}

pub fn get_proof_build_rpc_host() -> Option<String> {
    std::env::var(ENV_PROOF_BUILD_URL).ok()
}

pub fn get_watchtower_proof_wait_secs() -> usize {
    std::env::var(ENV_WATCHTOWER_PROOF_WAIT_SECS)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_WATCHTOWER_PROOF_WAIT_SECS)
}

pub fn get_operator_proof_wait_secs() -> usize {
    std::env::var(ENV_OPERATOR_PROOF_WAIT_SECS)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_OPERATOR_PROOF_WAIT_SECS)
}

pub fn get_min_required_verifier() -> anyhow::Result<usize> {
    match std::env::var(ENV_MIN_REQUIRED_VERIFIER) {
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_MIN_REQUIRED_VERIFIER),
        Err(error) => Err(anyhow::anyhow!("failed to read {ENV_MIN_REQUIRED_VERIFIER}: {error}")),
        Ok(value) => value.parse::<usize>().ok().filter(|value| *value > 0).ok_or_else(|| {
            anyhow::anyhow!("{ENV_MIN_REQUIRED_VERIFIER} must be a positive integer, got {value:?}")
        }),
    }
}

pub fn get_verifier_candidate_backup_count() -> usize {
    std::env::var(ENV_VERIFIER_CANDIDATE_BACKUP_COUNT)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_VERIFIER_CANDIDATE_BACKUP_COUNT)
}

pub fn get_verifier_candidate_collection_window_secs() -> i64 {
    std::env::var(ENV_VERIFIER_CANDIDATE_COLLECTION_WINDOW_SECS)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|value| value.clamp(1, 300))
        .unwrap_or(DEFAULT_VERIFIER_CANDIDATE_COLLECTION_WINDOW_SECS)
}

pub fn get_p2p_graph_setup_retry_interval_secs() -> i64 {
    std::env::var(ENV_P2P_GRAPH_SETUP_RETRY_INTERVAL_SECS)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|value| value.clamp(1, 300))
        .unwrap_or(DEFAULT_P2P_GRAPH_SETUP_RETRY_INTERVAL_SECS)
}

pub fn get_p2p_graph_setup_retry_window_secs() -> i64 {
    std::env::var(ENV_P2P_GRAPH_SETUP_RETRY_WINDOW_SECS)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|value| value.clamp(10, 3600))
        .unwrap_or(DEFAULT_P2P_GRAPH_SETUP_RETRY_WINDOW_SECS)
}

pub fn get_soldering_proof_payload_store_path() -> anyhow::Result<String> {
    let value = std::env::var(ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH)
        .map_err(|_| anyhow::anyhow!("{ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH} needs to be set"))?;
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH} cannot be empty");
    }
    Ok(value.to_string())
}

pub fn validate_soldering_proof_payload_store_config(actor: &Actor) -> anyhow::Result<()> {
    if matches!(actor, Actor::Verifier | Actor::Operator | Actor::All) {
        get_soldering_proof_payload_store_path()
            .map(|_| ())
            .map_err(|err| anyhow::anyhow!("{err}; required for actor {actor}"))
    } else {
        Ok(())
    }
}

pub fn get_operator_vk_hash() -> anyhow::Result<[u8; 32]> {
    let value = std::env::var(ENV_OPERATOR_VK_HASH)
        .map_err(|_| anyhow::anyhow!("{ENV_OPERATOR_VK_HASH} needs to be set"))?;
    hex_parse::<32>(&value).map_err(|err| anyhow::anyhow!("invalid {ENV_OPERATOR_VK_HASH}: {err}"))
}

pub fn get_operator_zkm_version() -> anyhow::Result<String> {
    std::env::var(ENV_OPERATOR_ZKM_VERSION)
        .map_err(|_| anyhow::anyhow!("{ENV_OPERATOR_ZKM_VERSION} needs to be set"))
}

pub struct BabeGcAssetPaths {
    pub fgc_gates: PathBuf,
    pub fgc_out_indices: PathBuf,
    pub sgc_gates: PathBuf,
    pub sgc_out_indices: PathBuf,
    pub fgc_compact_gates: PathBuf,
    pub fgc_compact_out_indices: PathBuf,
    pub sgc_compact_gates: PathBuf,
    pub sgc_compact_out_indices: PathBuf,
}

pub fn get_babe_gc_asset_paths() -> anyhow::Result<BabeGcAssetPaths> {
    fn read_path(name: &str) -> anyhow::Result<PathBuf> {
        let path =
            PathBuf::from(std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is missing"))?);
        if !path.is_file() {
            anyhow::bail!("{name} does not point to a readable file: {}", path.display());
        }
        Ok(path)
    }
    Ok(BabeGcAssetPaths {
        fgc_gates: read_path(ENV_FGC_GATES_PATH)?,
        fgc_out_indices: read_path(ENV_FGC_OUT_INDICES_PATH)?,
        sgc_gates: read_path(ENV_SGC_GATES_PATH)?,
        sgc_out_indices: read_path(ENV_SGC_OUT_INDICES_PATH)?,
        fgc_compact_gates: read_path(ENV_FGC_COMPACT_GATES_PATH)?,
        fgc_compact_out_indices: read_path(ENV_FGC_COMPACT_OUT_INDICES_PATH)?,
        sgc_compact_gates: read_path(ENV_SGC_COMPACT_GATES_PATH)?,
        sgc_compact_out_indices: read_path(ENV_SGC_COMPACT_OUT_INDICES_PATH)?,
    })
}

pub fn get_instance_maintenance_batch_size() -> u32 {
    std::env::var(ENV_INSTANCE_MAINTENANCE_BATCH_SIZE)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|size| size.clamp(1, 5000))
        .unwrap_or(DEFAULT_INSTANCE_MAINTENANCE_BATCH_SIZE)
}

pub fn get_maintenance_run_timeout_secs() -> u64 {
    std::env::var(ENV_MAINTENANCE_RUN_TIMEOUT_SECS)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|timeout| timeout.clamp(1, 300))
        .unwrap_or(DEFAULT_MAINTENANCE_RUN_TIMEOUT_SECS)
}

pub fn get_p2p_inbox_batch_size() -> i64 {
    std::env::var(ENV_P2P_INBOX_BATCH_SIZE)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|size| size.clamp(1, 128))
        .unwrap_or(DEFAULT_P2P_INBOX_BATCH_SIZE)
}

pub fn get_p2p_outbox_batch_size() -> i64 {
    std::env::var(ENV_P2P_OUTBOX_BATCH_SIZE)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|size| size.clamp(1, 128))
        .unwrap_or(DEFAULT_P2P_OUTBOX_BATCH_SIZE)
}

pub fn is_enable_committee_instance_key_delete() -> bool {
    // TODO: enable this feature when ready
    tracing::warn!(
        "Committee key delete not activated, ignore ENV_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE"
    );
    false
    // std::env::var(ENV_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE)
    //     .ok()
    //     .map(|value| value.eq_ignore_ascii_case("true"))
    //     .unwrap_or(DEFAULT_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE)
}

pub fn get_committee_instance_key_delete_timelock_blocks() -> i64 {
    std::env::var(ENV_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map(|v| v.clamp(1, 200_000))
        .unwrap_or(DEFAULT_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS)
}

pub fn should_always_challenge() -> bool {
    match std::env::var(ENV_ALWAYS_CHALLENGE) {
        Ok(val) => val.to_lowercase() == "true",
        Err(_) => false,
    }
}

pub fn get_genesis_sequencer_commit_id() -> [u8; 32] {
    use bitcoin::hashes::Hash;
    let hexed = std::env::var(ENV_GENESIS_SEQUENCER_COMMIT_TXID).unwrap();
    let txid = bitcoin::Txid::from_str(&hexed).expect("Invalid genesis sequencer commit txid");
    txid.to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn soldering_proof_payload_store_config_required_for_soldering_actors() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH) };

        assert!(validate_soldering_proof_payload_store_config(&Actor::Verifier).is_err());
        assert!(validate_soldering_proof_payload_store_config(&Actor::Operator).is_err());
        assert!(validate_soldering_proof_payload_store_config(&Actor::All).is_err());
        assert!(validate_soldering_proof_payload_store_config(&Actor::Committee).is_ok());
        assert!(validate_soldering_proof_payload_store_config(&Actor::Watchtower).is_ok());
        assert!(validate_soldering_proof_payload_store_config(&Actor::Publisher).is_ok());

        unsafe { std::env::set_var(ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH, "/tmp/store") };
        assert!(validate_soldering_proof_payload_store_config(&Actor::Verifier).is_ok());
        assert!(validate_soldering_proof_payload_store_config(&Actor::Operator).is_ok());

        unsafe { std::env::set_var(ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH, " ") };
        assert!(validate_soldering_proof_payload_store_config(&Actor::Verifier).is_err());

        unsafe { std::env::remove_var(ENV_SOLDERING_PROOF_PAYLOAD_STORE_PATH) };
    }
}
