//! Reads from the Goat gateway: committees, peg-in requests, instances, graph
//! status and the posted graph data.

use crate::env::*;
use crate::error::SpecialError;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, PublicKey, Txid, XOnlyPublicKey};
use bitvm_lib::types::{BitvmGcGraph, BitvmGcInstanceParameters, UserInfo};
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::transactions::base::Input;
use libp2p::PeerId;
use std::str::FromStr;
use std::time::Instant;
use store::localdb::LocalDB;

use bitvm_lib::transactions::base::BaseTransaction;
use client::goat_chain::{GraphData, PeginStatus};
use store::GraphStatus;
use uuid::Uuid;

use super::btc::outpoint_available;

pub fn build_graph_data(graph: &BitvmGcGraph) -> Result<GraphData> {
    // operator pubkey: first byte is prefix, next 32 bytes are key
    let op_pk_bytes = graph.parameters.operator_pubkey.to_bytes();
    let operator_pubkey_prefix = op_pk_bytes[0];
    let operator_pubkey: [u8; 32] =
        op_pk_bytes[1..33].try_into().map_err(|_| anyhow!("invalid operator pubkey length"))?;

    // compute txids for all required transactions
    let pegin_txid = graph.pegin.finalize().compute_txid().to_byte_array();
    let kickoff_txid = graph.kickoff.finalize().compute_txid().to_byte_array();
    let take1_txid = graph.take1.finalize().compute_txid().to_byte_array();
    let take2_txid = graph.take2.finalize().compute_txid().to_byte_array();
    let watchtower_challenge_init_txid =
        graph.watchtower_challenge_init.finalize().compute_txid().to_byte_array();
    let prover_assert_txid = graph.operator_assert.finalize().compute_txid().to_byte_array();
    let disprove_txids: Vec<[u8; 32]> =
        graph.disproves.iter().map(|tx| tx.finalize().compute_txid().to_byte_array()).collect();
    let watchtower_challenge_timeout_txids: Vec<[u8; 32]> = graph
        .watchtower_challenge_timeouts
        .iter()
        .map(|tx| tx.finalize().compute_txid().to_byte_array())
        .collect();
    let operator_challenge_nack_txids: Vec<[u8; 32]> = graph
        .operator_challenge_nacks
        .iter()
        .map(|tx| tx.finalize().compute_txid().to_byte_array())
        .collect();
    let operator_commit_timeout_txid =
        graph.operator_commit_timeout.finalize().compute_txid().to_byte_array();

    Ok(GraphData {
        operator_pubkey_prefix,
        operator_pubkey,
        pegin_txid,
        kickoff_txid,
        take1_txid,
        take2_txid,
        watchtower_challenge_init_txid,
        prover_assert_txid,
        disprove_txids,
        watchtower_challenge_timeout_txids,
        operator_challenge_nack_txids,
        operator_commit_timeout_txid,
    })
}

pub async fn validate_committee(
    goat_client: &GOATClient,
    peer_id: &PeerId,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<()> {
    // return SpecialError::InvalidCommittee if not valid
    let registry = crate::p2p_admission::peer_registry();
    // A peer the registry has fresh word is unregistered gets no chain reads.
    if registry.is_known_unregistered(peer_id, Instant::now()) {
        bail!(SpecialError::InvalidCommittee("author is not a registered peer".to_string()));
    }
    // A peer the registry holds as committee whose binding on Goat does not
    // match yet (a re-registered peer id, or a lagging Goat node) is asked
    // again later instead of being refused for good; the job's deadline
    // bounds the retries. Anyone else is refused.
    let refused = |detail: &str| -> anyhow::Error {
        if registry.is_committee(peer_id, Instant::now()) {
            anyhow!("committee binding of {peer_id} on Goat does not match yet: {detail}")
        } else {
            anyhow!(SpecialError::InvalidCommittee(detail.to_string()))
        }
    };
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    for (i, pk) in pegin_data.committee_pubkeys.iter().enumerate() {
        let pk = PublicKey::from_slice(pk)?;
        if &pk == committee_pubkey {
            let addr = pegin_data.committee_addresses[i];
            let stored_peer_id = goat_client.committee_mana_get_committee_peer_id(&addr).await?;
            if stored_peer_id.to_vec() != peer_id.to_bytes() {
                return Err(refused("committee pubkey & peer id mismatch"));
            }
            return Ok(());
        }
    }
    Err(refused("committee pubkey not found in instance's committee pubkeys"))
}

pub async fn validate_committee_with_evm_address(
    goat_client: &GOATClient,
    peer_id: &PeerId,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
    committee_evm_address: &EvmAddress,
) -> Result<()> {
    // return SpecialError::InvalidCommittee if not valid
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    for i in 0..pegin_data.committee_pubkeys.len() {
        let pk = PublicKey::from_slice(&pegin_data.committee_pubkeys[i])?;
        let addr = &pegin_data.committee_addresses[i];
        if addr == committee_evm_address {
            if &pk != committee_pubkey {
                bail!(SpecialError::InvalidCommittee(
                    "committee evm address & pubkey mismatch".to_string()
                ));
            }
            let stored_peer_id = goat_client.committee_mana_get_committee_peer_id(addr).await?;
            if stored_peer_id.to_vec() != peer_id.to_bytes() {
                bail!(SpecialError::InvalidCommittee(
                    "committee evm address & peer id mismatch".to_string()
                ));
            }
            return Ok(());
        }
    }
    bail!(SpecialError::InvalidCommittee(
        "committee evm address not found in instance's committee addresses".to_string()
    ))
}

pub async fn read_pegin_request(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<(UserInfo, Amount, Vec<EvmAddress>)> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    if pegin_data.status != PeginStatus::Pending {
        bail!(SpecialError::InvalidPeginRequest(format!(
            "pegin request is {} on Goat: expired or already processed",
            pegin_data.status
        )));
    }
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_change_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_change_addr network: {e}"))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_refund_addr network: {e}"))
        })?;
    let user_xonly_pubkey =
        XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey).map_err(|e| {
            SpecialError::InvalidPeginRequest(format!("invalid user_xonly_pubkey: {e}"))
        })?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();
    // TODO: we need to run our own bitcoin node in case of downtime or ddos attack.
    for input in &inputs {
        if !outpoint_available(btc_client, &input.outpoint.txid, input.outpoint.vout.into()).await?
        {
            bail!(SpecialError::InvalidPeginRequest(format!(
                "input {}:{} is not available",
                input.outpoint.txid, input.outpoint.vout
            )));
        }
    }
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    Ok((user_info, Amount::from_sat(pegin_data.pegin_amount_sats), pegin_data.committee_addresses))
}

pub async fn read_instance_info_from_goat(
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<BitvmGcInstanceParameters> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let network = get_network();
    let user_change_address = Address::from_str(&pegin_data.user_change_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_change_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_change_addr network: {e}"))
        })?;
    let user_refund_address = Address::from_str(&pegin_data.user_refund_addr)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_refund_addr: {e}")))?
        .require_network(network)
        .map_err(|e| {
            SpecialError::InvalidPeginData(format!("invalid user_refund_addr network: {e}"))
        })?;
    let user_xonly_pubkey = XOnlyPublicKey::from_slice(&pegin_data.user_xonly_pubkey)
        .map_err(|e| SpecialError::InvalidPeginData(format!("invalid user_xonly_pubkey: {e}")))?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();
    let user_info = UserInfo {
        depositor_evm_address: pegin_data.depositor_address,
        txn_fees: pegin_data.txn_fees,
        inputs,
        user_change_address,
        user_refund_address,
        user_xonly_pubkey,
    };
    let committee_pubkeys = match goat_client.gateway_get_committee_pubkeys(&instance_id).await {
        Ok(pks) => pks,
        Err(e) if crate::error::is_contract_revert(&e) => {
            bail!(SpecialError::InvalidPeginData(format!("fail to get committee pubkeys: {e:#}")))
        }
        Err(e) => bail!(e),
    };
    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    Ok(BitvmGcInstanceParameters {
        network,
        instance_id,
        user_info,
        pegin_amount: Amount::from_sat(pegin_data.pegin_amount_sats),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

pub async fn get_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<GraphStatus>> {
    let mut storage_process = local_db.acquire().await?;
    let graph_op = storage_process.find_graph(&graph_id).await?;
    if graph_op.is_none() {
        return Ok(None);
    };
    let graph = graph_op.unwrap();
    if graph.instance_id.ne(&instance_id) {
        bail!(
            "grap with graph_id:{graph_id} has instance_id:{} not match exp instance:{instance_id}",
            graph.instance_id,
        );
    }
    Ok(Some(
        GraphStatus::from_str(&graph.status)
            .map_err(|_| anyhow!("unknown graph status: {}", graph.status))?,
    ))
}
