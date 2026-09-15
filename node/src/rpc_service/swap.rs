use super::utils::{deserialize_u256, serialize_u256};
use crate::rpc_service::bitvm::{StatusExtra, StatusUserAction};
use crate::rpc_service::current_time_secs;
use alloy::primitives::U256;
use client::btc_chain::BTCClient;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use store::{SerializableTxid, SwapEscrow, SwapEscrowStatus};

const SWAP_CLAIM_BTC_TARGET_CONFIRMATIONS: u32 = 6;
const SWAP_TIMEOUT_ERROR: &str = "The operation timed out. Please try again.";

#[derive(Debug, Deserialize)]
pub struct SwapListRequest {
    pub from_addr: Option<String>, // offerer goat address
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct SwapEscrowDisplay {
    pub escrow_hash: String,
    pub network: String,
    pub status: String,
    pub from_addr: String,    // offerer goat address
    pub to_addr: String,      // btc payout address
    pub claimer_addr: String, // goat address entitled to claim
    pub token: String,
    #[serde(serialize_with = "serialize_u256", deserialize_with = "deserialize_u256")]
    pub amount: U256,
    pub refund_deadline: i64,
    pub init_tx_hash: String,
    pub init_tx_height: i64,
    pub claim_tx_hash: String,
    pub claim_btc_txid: Option<SerializableTxid>,
    pub refund_tx_hash: String,
    pub status_updated_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<SwapEscrow> for SwapEscrowDisplay {
    fn from(escrow: SwapEscrow) -> Self {
        Self {
            escrow_hash: escrow.escrow_hash,
            network: escrow.network,
            status: escrow.status,
            from_addr: escrow.offerer_addr,
            to_addr: escrow.btc_addr,
            claimer_addr: escrow.claimer_addr,
            token: escrow.token,
            amount: U256::from_str(&escrow.amount).unwrap_or_default(),
            refund_deadline: escrow.refund_deadline,
            init_tx_hash: escrow.init_tx_hash,
            init_tx_height: escrow.init_tx_height,
            claim_tx_hash: escrow.claim_tx_hash,
            claim_btc_txid: escrow.claim_btc_txid,
            refund_tx_hash: escrow.refund_tx_hash,
            status_updated_at: escrow.status_updated_at,
            created_at: escrow.created_at,
            updated_at: escrow.updated_at,
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct SwapEscrowExtended {
    pub swap: SwapEscrowDisplay,
    /// Hex abi-encoded EscrowData captured from the Initialize tx, if seen.
    pub escrow_data: Option<String>,
    pub waiting_time_in_secs: i64,
    pub confirmations: u32,
    pub target_confirmations: u32,
    pub status_extra: StatusExtra,
}

impl SwapEscrowExtended {
    pub async fn convert_from_swap_escrow(
        btc_client: &BTCClient,
        btc_current_height: u32,
        mut escrow: SwapEscrow,
    ) -> Self {
        let (confirmations, target_confirmations) =
            get_claim_btc_confirm_progress(btc_client, btc_current_height, &escrow.claim_btc_txid)
                .await;
        Self {
            waiting_time_in_secs: get_swap_waiting_time(&escrow.status, escrow.refund_deadline),
            confirmations,
            target_confirmations,
            status_extra: get_swap_status_extra(&escrow.status),
            escrow_data: escrow.escrow_data.take(),
            swap: escrow.into(),
        }
    }
}

/// Seconds until the refund deadline while the escrow is still initializing.
fn get_swap_waiting_time(status: &str, refund_deadline: i64) -> i64 {
    match SwapEscrowStatus::from_str(status) {
        Ok(SwapEscrowStatus::Initialize) => (refund_deadline - current_time_secs()).max(0),
        _ => 0,
    }
}

fn get_swap_status_extra(status: &str) -> StatusExtra {
    let mut status_extra = StatusExtra::default();
    if matches!(SwapEscrowStatus::from_str(status), Ok(SwapEscrowStatus::Timeout)) {
        status_extra.is_failed = true;
        status_extra.error = Some(SWAP_TIMEOUT_ERROR.to_string());
        status_extra.user_action = StatusUserAction::Refund;
    }
    status_extra
}

async fn get_claim_btc_confirm_progress(
    btc_client: &BTCClient,
    current_height: u32,
    claim_btc_txid: &Option<SerializableTxid>,
) -> (u32, u32) {
    if let Some(txid) = claim_btc_txid
        && let Ok(tx_status) = btc_client.get_tx_status(&txid.0).await
        && let Some(height) = tx_status.block_height
    {
        (current_height + 1 - height, SWAP_CLAIM_BTC_TARGET_CONFIRMATIONS)
    } else {
        (0, SWAP_CLAIM_BTC_TARGET_CONFIRMATIONS)
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct SwapListResponse {
    pub swaps: Vec<SwapEscrowExtended>,
    pub total: i64,
}

#[derive(Deserialize, Serialize)]
pub struct SwapGetResponse {
    pub swap: Option<SwapEscrowExtended>,
}
