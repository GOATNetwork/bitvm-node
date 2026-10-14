mod btc;
mod committee_keys;
mod endorse;
pub mod evm_swap_utils;
mod goat_chain;
mod graph_chain_state;
mod graph_store;
mod graph_tx;
mod graph_validate;
mod instance_store;
mod node_info;
mod proof_client;
mod rounds;
mod setup_state;

pub use btc::*;
pub use committee_keys::*;
pub use endorse::*;
pub use goat_chain::*;
pub(crate) use graph_chain_state::*;
pub use graph_store::*;
pub use graph_tx::*;
pub use graph_validate::*;
pub use instance_store::*;
pub use node_info::*;
pub use proof_client::*;
pub use rounds::*;
pub use setup_state::*;

use alloy::primitives::Address as EvmAddress;
use anyhow::Result;
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use rand::Rng;
use secp256k1::Secp256k1;
use store::BridgeOutGlobalStats;
use store::localdb::StorageProcessor;

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(0..255)).collect()
}

pub fn get_rand_btc_address_p2wpkh(network: Network) -> String {
    let secp = Secp256k1::new();
    Address::p2wpkh(
        &CompressedPublicKey::try_from(PrivateKey::generate(network).public_key(&secp))
            .expect("Could not compress public key"),
        network,
    )
    .to_string()
}

pub fn get_rand_goat_address() -> String {
    EvmAddress::from_slice(&generate_random_bytes(20)).to_string()
}

pub fn strip_hex_prefix_owned(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") { s[2..].to_string() } else { s.to_string() }
}

pub fn generate_local_key() -> libp2p::identity::Keypair {
    libp2p::identity::Keypair::generate_ed25519()
}

pub fn temp_sqlite_db_path() -> String {
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    format!("sqlite:{}", tmp_db.path().as_os_str().to_str().unwrap())
}

// contract calls

pub(crate) const BRIDGE_OUT_GLOBAL_STATS_ID: i64 = 1;

pub(crate) async fn get_bridge_out_global_stats<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> Result<BridgeOutGlobalStats> {
    match storage_processor.find_bridge_out_global_stats_by_id(BRIDGE_OUT_GLOBAL_STATS_ID).await? {
        Some(global_stats) => Ok(global_stats),
        None => Ok(BridgeOutGlobalStats {
            id: BRIDGE_OUT_GLOBAL_STATS_ID,
            initial_txn: 0,
            initial_amount: "0".to_string(),
            claim_txn: 0,
            claim_amount: "0".to_string(),
            refund_txn: 0,
            refund_amount: "0".to_string(),
            created_at: 0,
            updated_at: 0,
        }),
    }
}
