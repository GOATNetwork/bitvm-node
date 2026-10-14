//! Endorsement signatures over graphs, graph parameters and peg-ins.

use crate::env::*;
use alloy::primitives::{Address as EvmAddress, Signature as EvmSignature};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Result, anyhow};
use bitcoin::key::Keypair;
use bitcoin::{PublicKey, Txid, XOnlyPublicKey};
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use client::goat_chain::GOATClient;
use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Message as SecpMessage, SECP256K1};
use std::str::FromStr;

use uuid::Uuid;

use super::goat_chain::build_graph_data;

pub async fn get_graph_digest(goat_client: &GOATClient, graph: &BitvmGcGraph) -> Result<[u8; 32]> {
    let instance_id = graph.parameters.instance_parameters.instance_id;
    let graph_id = graph.parameters.graph_id;
    let graph_data = build_graph_data(graph)?;
    goat_client.gateway_get_post_graph_digest(&instance_id, &graph_id, graph_data).await
}

pub async fn endorse_graph(goat_client: &GOATClient, graph: &BitvmGcGraph) -> Result<EvmSignature> {
    let signer = PrivateKeySigner::from_str(&get_node_goat_private_key()?)?;
    let graph_digest = get_graph_digest(goat_client, graph).await?;
    let sig = signer.sign_hash(&graph_digest.into()).await?;
    Ok(sig)
}

pub async fn endorse_graph_params(graph: &BitvmGcGraph) -> Result<EvmSignature> {
    let signer = PrivateKeySigner::from_str(&get_node_goat_private_key()?)?;
    let params_hash = graph.parameters.canonical_graph_params_hash()?;
    let sig = signer.sign_hash(&params_hash.into()).await?;
    Ok(sig)
}

pub async fn endorse_pegin(
    goat_client: &GOATClient,
    instance_id: Uuid,
    pegin_txid: &Txid,
) -> Result<EvmSignature> {
    let signer = PrivateKeySigner::from_str(&get_node_goat_private_key()?)?;
    let pegin_digest = goat_client.gateway_get_post_pegin_digest(&instance_id, pegin_txid).await?;
    let sig = signer.sign_hash(&pegin_digest.into()).await?;
    Ok(sig)
}

pub async fn verify_pegin_endorsement(
    goat_client: &GOATClient,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
    pegin_txid: &Txid,
    signature: &[u8],
) -> Result<bool> {
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let expected_evm_address = pegin_data
        .committee_pubkeys
        .iter()
        .zip(pegin_data.committee_addresses.iter())
        .find_map(|(pubkey, evm_address)| {
            PublicKey::from_slice(pubkey)
                .ok()
                .filter(|on_chain_pubkey| on_chain_pubkey == committee_pubkey)
                .map(|_| *evm_address)
        })
        .ok_or_else(|| anyhow!("committee pubkey {committee_pubkey} not found on-chain"))?;
    let pegin_digest = goat_client.gateway_get_post_pegin_digest(&instance_id, pegin_txid).await?;
    let sig = EvmSignature::try_from(signature)?;
    sig.recover_address_from_prehash(&pegin_digest.into())
        .map(|addr| addr == expected_evm_address)
        .map_err(|e| e.into())
}

pub async fn verify_graph_endorsement(
    goat_client: &GOATClient,
    evm_address: &EvmAddress,
    graph: &BitvmGcGraph,
    signature: &[u8],
) -> Result<bool> {
    let graph_digest = get_graph_digest(goat_client, graph).await?;
    verify_graph_endorsement_digest(evm_address, &graph_digest, signature)
}

/// Whether `signature` over the graph digest recovers to `evm_address`.
pub fn verify_graph_endorsement_digest(
    evm_address: &EvmAddress,
    graph_digest: &[u8; 32],
    signature: &[u8],
) -> Result<bool> {
    let sig = EvmSignature::try_from(signature)?;
    sig.recover_address_from_prehash(&(*graph_digest).into())
        .map(|addr| &addr == evm_address)
        .map_err(|e| e.into())
}

pub fn verify_graph_params_endorsement(
    evm_address: &EvmAddress,
    graph: &BitvmGcGraph,
    signature: &[u8],
) -> Result<bool> {
    let params_hash = graph.parameters.canonical_graph_params_hash()?;
    let sig = EvmSignature::try_from(signature)?;
    sig.recover_address_from_prehash(&params_hash.into())
        .map(|addr| &addr == evm_address)
        .map_err(|e| e.into())
}

pub fn sign_verifier_graph_params(
    verifier_keypair: Keypair,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<SchnorrSignature> {
    let params_hash = graph.canonical_graph_params_hash()?;
    Ok(SECP256K1.sign_schnorr(&SecpMessage::from_digest(params_hash), &verifier_keypair))
}

pub fn verify_verifier_graph_params_endorsement(
    verifier_pubkey: &PublicKey,
    graph: &SimplifiedBitvmGcGraph,
    signature: &SchnorrSignature,
) -> Result<bool> {
    let params_hash = graph.canonical_graph_params_hash()?;
    Ok(SECP256K1
        .verify_schnorr(
            signature,
            &SecpMessage::from_digest(params_hash),
            &XOnlyPublicKey::from(*verifier_pubkey),
        )
        .is_ok())
}
