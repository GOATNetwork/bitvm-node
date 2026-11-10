//! Bridge-out (swap) events: escrow initialisations, claims and refunds.

use crate::env::get_network;
use crate::scheduled_tasks::get_timestamp_from_contract_data;
use crate::utils::evm_swap_utils::IEscrowManager::EscrowData;
use crate::utils::evm_swap_utils::{
    ClaimData, extract_claim_data_from_tx, extract_escrow_data_from_tx,
};
use crate::utils::{get_bridge_out_global_stats, strip_hex_prefix_owned};
use alloy::primitives::{Address as EvmAddress, U256};
use alloy::sol_types::SolValue;
use bitcoin::Address;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    SwapClaimEvent, SwapEventEntity, SwapInitializeEvent, SwapRefundEvent,
};
use std::ops::AddAssign;
use std::str::FromStr;
use store::localdb::{StorageProcessor, SwapEscrowUpdate};
use store::{SwapEscrow, SwapEscrowStatus, normalize_escrow_hash};
use tracing::{info, warn};

/// The swap events of a block range. The init and claim transactions are
/// traced while fetching, so applying them only writes.
#[derive(Default)]
pub struct SwapRange {
    entities: Vec<SwapEventEntity>,
    inits: Vec<(SwapInitializeEvent, Option<EscrowData>)>,
    claims: Vec<(SwapClaimEvent, Option<ClaimData>)>,
    refunds: Vec<SwapRefundEvent>,
}

fn escrow_hash_bytes(escrow_hash: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(strip_hex_prefix_owned(escrow_hash))?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("escrow_hash length is {}, expected 32", v.len()))
}

/// Query the range and trace its init and claim transactions; no database
/// access. Anyone can create an escrow, so the number of traces is not ours to
/// bound, and none of them may run inside the write transaction.
pub async fn fetch_bridge_out_events(
    goat_client: &GOATClient,
    client: &GraphQueryClient,
    contract_addr: &EvmAddress,
    graph_url: &str,
    event_entities: &[SwapEventEntity],
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<SwapRange> {
    let query_res = client.get_events(graph_url, event_entities, from_height, to_height).await?;
    let mut range = SwapRange { entities: event_entities.to_vec(), ..Default::default() };
    for entity in event_entities {
        let Some(value_vec) = query_res[entity.to_string()].as_array() else {
            continue;
        };
        let values = serde_json::Value::Array(value_vec.clone());
        match entity {
            SwapEventEntity::Initializes => {
                for event in serde_json::from_value::<Vec<SwapInitializeEvent>>(values)? {
                    let escrow_data = extract_escrow_data_from_tx(
                        goat_client,
                        &event.transaction_hash,
                        contract_addr,
                        &escrow_hash_bytes(&event.escrow_hash)?,
                    )
                    .await?;
                    range.inits.push((event, escrow_data));
                }
            }
            SwapEventEntity::Claims => {
                for event in serde_json::from_value::<Vec<SwapClaimEvent>>(values)? {
                    let claim_data = extract_claim_data_from_tx(
                        goat_client,
                        &event.transaction_hash,
                        contract_addr,
                        &escrow_hash_bytes(&event.escrow_hash)?,
                    )
                    .await?;
                    range.claims.push((event, claim_data));
                }
            }
            SwapEventEntity::Refunds => {
                range.refunds = serde_json::from_value(values)?;
            }
        }
    }
    Ok(range)
}

/// Write a fetched range, entity by entity in the configured order: a claim
/// needs the escrow its init created.
pub async fn apply_bridge_out_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    range: SwapRange,
    gateway_peg_btc_address: EvmAddress,
) -> anyhow::Result<()> {
    let SwapRange { entities, inits, claims, refunds } = range;
    let (mut inits, mut claims, mut refunds) = (Some(inits), Some(claims), Some(refunds));
    for entity in entities {
        match entity {
            SwapEventEntity::Initializes => {
                if let Some(inits) = inits.take() {
                    handle_swap_init_events(storage_processor, &gateway_peg_btc_address, inits)
                        .await?;
                }
            }
            SwapEventEntity::Claims => {
                if let Some(claims) = claims.take() {
                    handle_swap_claim_events(storage_processor, &gateway_peg_btc_address, claims)
                        .await?;
                }
            }
            SwapEventEntity::Refunds => {
                if let Some(refunds) = refunds.take() {
                    handle_swap_refund_events(storage_processor, &gateway_peg_btc_address, refunds)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

async fn handle_swap_init_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    gateway_peg_btc_address: &EvmAddress,
    init_events: Vec<(SwapInitializeEvent, Option<EscrowData>)>,
) -> anyhow::Result<()> {
    for (event, escrow_data) in init_events {
        let Some(escrow_data) = escrow_data else {
            warn!("failed to parse escrow_data for event:{event:?}");
            continue;
        };
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let create_time = event.block_timestamp.parse::<i64>()?;
        let event_height = event.block_number.parse::<i64>()?;
        let escrow = SwapEscrow {
            escrow_hash: escrow_hash.clone(),
            network: get_network().to_string(),
            status: SwapEscrowStatus::Initialize.to_string(),
            offerer_addr: escrow_data.offerer.to_string(),
            claimer_addr: escrow_data.claimer.to_string(),
            token: escrow_data.token.to_string(),
            amount: escrow_data.amount.to_string(),
            refund_deadline: get_timestamp_from_contract_data(&escrow_data.refundData.0),
            escrow_data: Some(hex::encode(escrow_data.abi_encode())),
            init_tx_hash: event.transaction_hash.clone(),
            init_tx_height: event_height,
            status_updated_at: create_time,
            created_at: create_time,
            ..Default::default()
        };
        // Swap records are derived exclusively from the on-chain Initialize
        // event; duplicate event scans must not overwrite the first record.
        let initialized = storage_processor.insert_swap_escrow_if_absent(&escrow).await?;
        if initialized && escrow_data.token == *gateway_peg_btc_address {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut initial_amount =
                U256::from_str(&bridge_out_global_stats.initial_amount).unwrap_or_default();
            initial_amount.add_assign(&escrow_data.amount);
            bridge_out_global_stats.initial_amount = initial_amount.to_string();
            bridge_out_global_stats.initial_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap initialize stats included: tx_hash={}, escrow_hash={}, token={}, amount={}",
                event.transaction_hash, escrow_hash, escrow_data.token, escrow_data.amount,
            );
        } else if initialized {
            info!(
                "swap initialize stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}, token={}, expect_token={}",
                event.transaction_hash, escrow_hash, escrow_data.token, gateway_peg_btc_address,
            );
        } else {
            info!(
                "swap initialize ignored for resolved or previously initialized escrow {escrow_hash}"
            );
        }
    }
    Ok(())
}

async fn handle_swap_claim_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    gateway_peg_btc_address: &EvmAddress,
    claim_events: Vec<(SwapClaimEvent, Option<ClaimData>)>,
) -> anyhow::Result<()> {
    for (event, claim_data) in claim_events {
        let Some(claim_data) = claim_data else {
            warn!("failed to parse claim_data for event:{event:?}");
            continue;
        };
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let Some(escrow) = storage_processor.find_swap_escrow(&escrow_hash).await? else {
            warn!(
                "swap claim ignored for unknown escrow {escrow_hash}, tx_hash={}",
                event.transaction_hash
            );
            continue;
        };
        let btc_addr = Address::from_script(
            bitcoin::Script::from_bytes(&claim_data.output_script),
            get_network(),
        )
        .map(|address| address.to_string())
        .unwrap_or_else(|error| {
            warn!(
                escrow_hash = %escrow_hash,
                tx_hash = %event.transaction_hash,
                output_script = %hex::encode(&claim_data.output_script),
                %error,
                "swap claim output script is not a Bitcoin address; storing an empty display address"
            );
            String::new()
        });
        // The claim event is authoritative: it also overrides a locally
        // derived Timeout.
        let transitioned = storage_processor
            .update_swap_escrow(
                &SwapEscrowUpdate::new(escrow_hash.clone())
                    .with_status(SwapEscrowStatus::Claim.to_string())
                    .with_claim_tx_hash(event.transaction_hash.clone())
                    .with_claim_btc_txid(claim_data.txid.into())
                    .with_btc_addr(btc_addr)
                    .with_only_if_status_in(vec![
                        SwapEscrowStatus::Initialize.to_string(),
                        SwapEscrowStatus::Timeout.to_string(),
                    ]),
            )
            .await?;
        if !transitioned {
            info!(
                "swap claim ignored for resolved escrow {escrow_hash} with status {}",
                escrow.status
            );
            continue;
        }
        if escrow.token == gateway_peg_btc_address.to_string() {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut claim_amount =
                U256::from_str(&bridge_out_global_stats.claim_amount).unwrap_or_default();
            claim_amount.add_assign(&U256::from_str(&escrow.amount).unwrap_or_default());
            bridge_out_global_stats.claim_amount = claim_amount.to_string();
            bridge_out_global_stats.claim_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap claim stats included: tx_hash={}, escrow_hash={}, amount={}",
                event.transaction_hash, escrow_hash, escrow.amount,
            );
        } else {
            info!(
                "swap claim stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}",
                event.transaction_hash, escrow_hash,
            );
        }
    }
    Ok(())
}

async fn handle_swap_refund_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    gateway_peg_btc_address: &EvmAddress,
    refund_events: Vec<SwapRefundEvent>,
) -> anyhow::Result<()> {
    for event in refund_events {
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let Some(escrow) = storage_processor.find_swap_escrow(&escrow_hash).await? else {
            warn!(
                "swap refund ignored for unknown escrow {escrow_hash}, tx_hash={}",
                event.transaction_hash
            );
            continue;
        };
        // The refund event is authoritative: it also overrides a locally
        // derived Timeout.
        let transitioned = storage_processor
            .update_swap_escrow(
                &SwapEscrowUpdate::new(escrow_hash.clone())
                    .with_status(SwapEscrowStatus::Refund.to_string())
                    .with_refund_tx_hash(event.transaction_hash.clone())
                    .with_only_if_status_in(vec![
                        SwapEscrowStatus::Initialize.to_string(),
                        SwapEscrowStatus::Timeout.to_string(),
                    ]),
            )
            .await?;
        if !transitioned {
            info!(
                "swap refund ignored for resolved escrow {escrow_hash} with status {}",
                escrow.status
            );
            continue;
        }
        if escrow.token == gateway_peg_btc_address.to_string() {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut refund_amount =
                U256::from_str(&bridge_out_global_stats.refund_amount).unwrap_or_default();
            refund_amount.add_assign(&U256::from_str(&escrow.amount).unwrap_or_default());
            bridge_out_global_stats.refund_amount = refund_amount.to_string();
            bridge_out_global_stats.refund_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap refund stats included: tx_hash={}, escrow_hash={}, amount={}",
                event.transaction_hash, escrow_hash, escrow.amount,
            );
        } else {
            info!(
                "swap refund stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}",
                event.transaction_hash, escrow_hash,
            );
        }
    }
    Ok(())
}
