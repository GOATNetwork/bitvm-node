//! Committee round material: nonces, partial signatures and endorsements per
//! graph and per instance.

use crate::error::SpecialError;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Result, anyhow, bail};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::committee::*;
use indexmap::IndexMap;
use musig2::{PartialSignature, PubNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use store::localdb::LocalDB;

use uuid::Uuid;

use super::graph_store::{find_pegin_graph_process_data, upsert_pegin_graph_process_data};
use super::graph_validate::min_required_operator;
use super::instance_store::{find_pegin_instance_process_data, upsert_pegin_instance_process_data};

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct InstanceProcessDataItem {
    pub pub_nonce: Option<PubNonce>,
    pub agg_nonce_consensus_hash: Option<[u8; 32]>,
    pub agg_nonce_consensus_signature: Option<SchnorrSignature>,
    pub partial_sign: Option<PartialSignature>,
    pub endorse_signature: Vec<u8>,
}

pub type InstanceProcessDataMap = IndexMap<PublicKey, InstanceProcessDataItem>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct GraphProcessDataItem {
    pub committee_pub_nonce: Option<CommitteePubNonces>,
    pub agg_nonce_consensus_hash: Option<[u8; 32]>,
    pub agg_nonce_consensus_signature: Option<SchnorrSignature>,
    pub partial_sigs: Option<CommitteePartialSignatures>,
    pub committee_evm_address: Option<EvmAddress>,
    pub endorse_signature: Vec<u8>,
    pub params_endorse_signature: Vec<u8>,
    pub verifier_index: Option<usize>,
    pub verifier_peer_id: Option<String>,
    pub verifier_params_signature: Option<SchnorrSignature>,
}

pub type GraphProcessDataMap = IndexMap<PublicKey, GraphProcessDataItem>;

pub fn order_committee_values<T: Clone>(
    committee_pubkeys: &[PublicKey],
    values: Vec<(PublicKey, T)>,
    label: &str,
) -> Result<Vec<T>> {
    for (idx, (pubkey, _)) in values.iter().enumerate() {
        if !committee_pubkeys.contains(pubkey) {
            bail!("{label} contains non-committee pubkey {pubkey}");
        }
        if values.iter().skip(idx + 1).any(|(other, _)| other == pubkey) {
            bail!("{label} contains duplicate pubkey {pubkey}");
        }
    }

    committee_pubkeys
        .iter()
        .map(|committee_pubkey| {
            values
                .iter()
                .find(|(pubkey, _)| pubkey == committee_pubkey)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| anyhow!("{label} missing pubkey {committee_pubkey}"))
        })
        .collect()
}

pub async fn store_committee_pub_nonces_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonces: CommitteePubNonces,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    if let Some(existing_pub_nonces) =
        process_data.get(&committee_pubkey).and_then(|v| v.committee_pub_nonce.as_ref())
        && existing_pub_nonces != &pub_nonces
    {
        bail!(SpecialError::InvalidGraph(format!(
            "committee pub nonces changed for graph {graph_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.committee_pub_nonce = Some(pub_nonces.clone()))
        .or_insert_with(|| GraphProcessDataItem {
            committee_pub_nonce: Some(pub_nonces),
            ..Default::default()
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn get_committee_pub_nonces_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, CommitteePubNonces)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.committee_pub_nonce.as_ref().map(|nonce| (*k, nonce.clone())))
        .collect::<Vec<(PublicKey, CommitteePubNonces)>>())
}

pub async fn store_committee_agg_nonce_consensus_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    consensus_hash: [u8; 32],
    signature: SchnorrSignature,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    if let Some((existing_hash, existing_signature)) = process_data
        .get(&committee_pubkey)
        .and_then(|item| item.agg_nonce_consensus_hash.zip(item.agg_nonce_consensus_signature))
        && (existing_hash != consensus_hash || existing_signature != signature)
    {
        tracing::error!(
            event = "committee_agg_nonce_consensus_conflict",
            %instance_id,
            %graph_id,
            %committee_pubkey,
            existing_consensus_hash = %hex::encode(existing_hash),
            existing_signature = %existing_signature,
            conflicting_consensus_hash = %hex::encode(consensus_hash),
            conflicting_signature = %signature,
            "detected conflicting committee agg nonce consensus signatures"
        );
        bail!(SpecialError::InvalidGraph(format!(
            "committee agg nonce consensus changed for graph {graph_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|item| {
            item.agg_nonce_consensus_hash = Some(consensus_hash);
            item.agg_nonce_consensus_signature = Some(signature);
        })
        .or_insert_with(|| GraphProcessDataItem {
            agg_nonce_consensus_hash: Some(consensus_hash),
            agg_nonce_consensus_signature: Some(signature),
            ..Default::default()
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn get_committee_agg_nonce_consensus_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, [u8; 32], SchnorrSignature)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(pubkey, item)| {
            item.agg_nonce_consensus_hash
                .zip(item.agg_nonce_consensus_signature)
                .map(|(consensus_hash, signature)| (*pubkey, consensus_hash, signature))
        })
        .collect())
}

pub async fn store_committee_partial_sigs_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: CommitteePartialSignatures,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    if let Some(existing_partial_sigs) =
        process_data.get(&committee_pubkey).and_then(|v| v.partial_sigs.as_ref())
        && existing_partial_sigs != &partial_sigs
    {
        bail!(SpecialError::InvalidGraph(format!(
            "committee partial signatures changed for graph {graph_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.partial_sigs = Some(partial_sigs.clone()))
        .or_insert_with(|| GraphProcessDataItem {
            partial_sigs: Some(partial_sigs),
            ..Default::default()
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn get_committee_partial_sigs_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, CommitteePartialSignatures)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.partial_sigs.as_ref().map(|nonce| (*k, nonce.clone())))
        .collect::<Vec<(PublicKey, CommitteePartialSignatures)>>())
}

pub async fn get_committee_partial_sigs_for_graph_member(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<CommitteePartialSignatures>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.partial_sigs.clone()))
}

pub async fn store_committee_endorsement_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    committee_pubkey: PublicKey,
    committee_evm_address: EvmAddress,
    endorse_signature: Vec<u8>,
    params_endorse_signature: Vec<u8>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| {
            v.endorse_signature = endorse_signature.clone();
            v.params_endorse_signature = params_endorse_signature.clone();
            v.committee_evm_address = Some(committee_evm_address);
        })
        .or_insert_with(|| GraphProcessDataItem {
            committee_evm_address: Some(committee_evm_address),
            endorse_signature,
            params_endorse_signature,
            ..Default::default()
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn store_committee_endorsements_for_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
    params_endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;

    for (committee_pubkey, committee_evm_address, endorse_signature) in endorse_sigs {
        process_data
            .entry(committee_pubkey)
            .and_modify(|v| {
                v.endorse_signature = endorse_signature.clone();
                v.committee_evm_address = Some(committee_evm_address);
            })
            .or_insert_with(|| GraphProcessDataItem {
                committee_evm_address: Some(committee_evm_address),
                endorse_signature,
                ..Default::default()
            });
    }
    for (committee_pubkey, committee_evm_address, params_endorse_signature) in params_endorse_sigs {
        process_data
            .entry(committee_pubkey)
            .and_modify(|v| {
                v.params_endorse_signature = params_endorse_signature.clone();
                v.committee_evm_address = Some(committee_evm_address);
            })
            .or_insert_with(|| GraphProcessDataItem {
                committee_evm_address: Some(committee_evm_address),
                params_endorse_signature,
                ..Default::default()
            });
    }
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn get_committee_endorsements_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, EvmAddress, Vec<u8>)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            if !v.endorse_signature.is_empty() {
                v.committee_evm_address
                    .as_ref()
                    .map(|evm_addr| (*k, *evm_addr, v.endorse_signature.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<(PublicKey, EvmAddress, Vec<u8>)>>())
}

pub async fn get_committee_params_endorsements_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, EvmAddress, Vec<u8>)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            if !v.params_endorse_signature.is_empty() {
                v.committee_evm_address
                    .as_ref()
                    .map(|evm_addr| (*k, *evm_addr, v.params_endorse_signature.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<(PublicKey, EvmAddress, Vec<u8>)>>())
}

pub async fn store_verifier_graph_params_endorsement(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: PublicKey,
    verifier_index: usize,
    verifier_peer_id: &str,
    signature: SchnorrSignature,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (is_endorsed, mut process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    for (key, item) in &process_data {
        if let Some(peer) = &item.verifier_peer_id
            && ((*key == verifier_pubkey && peer != verifier_peer_id)
                || (*key != verifier_pubkey
                    && (peer == verifier_peer_id
                        || XOnlyPublicKey::from(*key) == XOnlyPublicKey::from(verifier_pubkey))))
        {
            bail!(SpecialError::InvalidGraph("conflicting verifier peer/key binding".into()));
        }
    }
    if let Some(existing_index) = process_data.get(&verifier_pubkey).and_then(|v| v.verifier_index)
        && existing_index != verifier_index
    {
        bail!(SpecialError::InvalidGraph(format!(
            "verifier params endorsement index changed for graph {graph_id} and verifier {verifier_pubkey}"
        )));
    }
    if let Some(existing_signature) =
        process_data.get(&verifier_pubkey).and_then(|v| v.verifier_params_signature.as_ref())
        && existing_signature != &signature
    {
        bail!(SpecialError::InvalidGraph(format!(
            "verifier params endorsement signature changed for graph {graph_id} and verifier {verifier_pubkey}"
        )));
    }
    process_data
        .entry(verifier_pubkey)
        .and_modify(|v| {
            v.verifier_index = Some(verifier_index);
            v.verifier_peer_id = Some(verifier_peer_id.to_owned());
            v.verifier_params_signature = Some(signature);
        })
        .or_insert_with(|| GraphProcessDataItem {
            verifier_index: Some(verifier_index),
            verifier_peer_id: Some(verifier_peer_id.to_owned()),
            verifier_params_signature: Some(signature),
            ..Default::default()
        });
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        is_endorsed,
        &process_data,
    )
    .await?;
    Ok(())
}

pub async fn get_verifier_graph_params_endorsements_for_graph(
    local_db: &LocalDB,
    _instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<(PublicKey, usize, String, SchnorrSignature)>> {
    let mut storage_processor = local_db.acquire().await?;
    let (_is_endorsed, process_data) =
        find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            v.verifier_index
                .zip(v.verifier_params_signature.as_ref())
                .zip(v.verifier_peer_id.as_ref())
                .map(|((index, signature), peer)| (*k, index, peer.clone(), *signature))
        })
        .collect())
}

pub async fn mark_graph_as_endorsed(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let (_, process_data) = find_pegin_graph_process_data(&mut storage_processor, graph_id).await?;
    upsert_pegin_graph_process_data(
        &mut storage_processor,
        graph_id,
        instance_id,
        true,
        &process_data,
    )
    .await
}

pub async fn get_endorsed_graph_count(local_db: &LocalDB, instance_id: Uuid) -> Result<usize> {
    let mut storage_processor = local_db.acquire().await?;
    Ok(storage_processor.get_pegin_graph_endorsed_len_by_instance_id(&instance_id, true).await?
        as usize)
}

pub async fn has_required_presigned_graphs(local_db: &LocalDB, instance_id: Uuid) -> Result<bool> {
    Ok(get_endorsed_graph_count(local_db, instance_id).await? >= min_required_operator())
}

pub async fn store_committee_pub_nonce_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    pub_nonce: PubNonce,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_pub_nonce) =
        process_data.get(&committee_pubkey).and_then(|v| v.pub_nonce.as_ref())
        && existing_pub_nonce != &pub_nonce
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee pub nonce changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.pub_nonce = Some(pub_nonce.clone()))
        .or_insert_with(|| InstanceProcessDataItem {
            pub_nonce: Some(pub_nonce),
            ..Default::default()
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}

pub async fn get_committee_pub_nonce_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<PubNonce>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.pub_nonce.clone()))
}

pub async fn get_committee_pub_nonces_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, PubNonce)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.pub_nonce.as_ref().map(|pub_nonce| (*k, pub_nonce.clone())))
        .collect())
}

pub async fn store_committee_agg_nonce_consensus_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    consensus_hash: [u8; 32],
    signature: SchnorrSignature,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some((existing_hash, existing_signature)) = process_data
        .get(&committee_pubkey)
        .and_then(|item| item.agg_nonce_consensus_hash.zip(item.agg_nonce_consensus_signature))
        && (existing_hash != consensus_hash || existing_signature != signature)
    {
        tracing::error!(
            event = "committee_pegin_confirm_nonce_consensus_conflict",
            %instance_id,
            %committee_pubkey,
            existing_consensus_hash = %hex::encode(existing_hash),
            existing_signature = %existing_signature,
            conflicting_consensus_hash = %hex::encode(consensus_hash),
            conflicting_signature = %signature,
            "detected conflicting committee PeginConfirm nonce consensus signatures"
        );
        bail!(SpecialError::InvalidPeginData(format!(
            "committee PeginConfirm nonce consensus changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|item| {
            item.agg_nonce_consensus_hash = Some(consensus_hash);
            item.agg_nonce_consensus_signature = Some(signature);
        })
        .or_insert_with(|| InstanceProcessDataItem {
            agg_nonce_consensus_hash: Some(consensus_hash),
            agg_nonce_consensus_signature: Some(signature),
            ..Default::default()
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}

pub async fn get_committee_agg_nonce_consensus_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, [u8; 32], SchnorrSignature)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(pubkey, item)| {
            item.agg_nonce_consensus_hash
                .zip(item.agg_nonce_consensus_signature)
                .map(|(consensus_hash, signature)| (*pubkey, consensus_hash, signature))
        })
        .collect())
}

pub async fn store_committee_partial_sig_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    partial_sigs: PartialSignature,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_partial_sig) =
        process_data.get(&committee_pubkey).and_then(|v| v.partial_sign.as_ref())
        && existing_partial_sig != &partial_sigs
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee partial signature changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.partial_sign = Some(partial_sigs))
        .or_insert_with(|| InstanceProcessDataItem {
            partial_sign: Some(partial_sigs),
            ..Default::default()
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}

pub async fn get_committee_partial_sigs_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, PartialSignature)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| v.partial_sign.as_ref().map(|partial_sign| (*k, *partial_sign)))
        .collect())
}

pub async fn get_committee_partial_sig_for_instance(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: &PublicKey,
) -> Result<Option<PartialSignature>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data.get(committee_pubkey).and_then(|v| v.partial_sign))
}

pub async fn store_committee_endorse_sig_for_pegin(
    local_db: &LocalDB,
    instance_id: Uuid,
    committee_pubkey: PublicKey,
    endorse_sig: Vec<u8>,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let mut process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    if let Some(existing_endorse_sig) =
        process_data.get(&committee_pubkey).map(|v| v.endorse_signature.as_slice())
        && !existing_endorse_sig.is_empty()
        && existing_endorse_sig != endorse_sig.as_slice()
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "committee endorse signature changed for instance {instance_id} and committee {committee_pubkey}"
        )));
    }
    process_data
        .entry(committee_pubkey)
        .and_modify(|v| v.endorse_signature = endorse_sig.clone())
        .or_insert_with(|| InstanceProcessDataItem {
            endorse_signature: endorse_sig,
            ..Default::default()
        });
    upsert_pegin_instance_process_data(&mut storage_processor, instance_id, &process_data).await?;
    Ok(())
}

pub async fn get_committee_endorse_sigs_for_pegin(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Vec<(PublicKey, Vec<u8>)>> {
    let mut storage_processor = local_db.acquire().await?;
    let process_data =
        find_pegin_instance_process_data(&mut storage_processor, instance_id).await?;
    Ok(process_data
        .iter()
        .filter_map(|(k, v)| {
            if !v.endorse_signature.is_empty() {
                Some((*k, v.endorse_signature.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<(PublicKey, Vec<u8>)>>())
}
