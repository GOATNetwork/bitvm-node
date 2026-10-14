//! Instance parameters and process data.

use crate::env::*;
use crate::error::SpecialError;
use crate::rpc_service::current_time_secs;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result, bail};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, OutPoint, PublicKey, Txid, XOnlyPublicKey};
use bitvm_lib::types::{BitvmGcInstanceParameters, UserInfo};
use client::Utxo as ClientUtxo;
use client::btc_chain::BTCClient;
use goat::contexts::base::generate_n_of_n_public_key;
use goat::transactions::base::Input;
use indexmap::IndexMap;
use std::str::FromStr;
use store::localdb::{LocalDB, StorageProcessor};

use crate::env;

use store::{
    ByteArray32, Instance, InstanceBridgeInStatus, PeginInstanceProcessData, UInt64Array3,
};
use tracing::warn;
use uuid::Uuid;

use super::rounds::InstanceProcessDataMap;

pub struct GenerateInstanceParams {
    pub instance_id: Uuid,
    pub user_info: UserInfo,
    pub pegin_amount: Amount,
    pub pegin_request_tx_hash: String,
    pub pegin_request_height: i64,
    pub pegin_timestamp: i64,
}

pub async fn generate_instance(
    btc_client: &BTCClient,
    params: GenerateInstanceParams,
) -> Result<Instance> {
    let from_addr = if !params.user_info.inputs.is_empty()
        && let Some(tx) = btc_client.get_tx(&params.user_info.inputs[0].outpoint.txid).await?
    {
        let tx_scripts =
            tx.output[params.user_info.inputs[0].outpoint.vout as usize].script_pubkey.clone();
        Address::from_script(&tx_scripts, env::get_network())
            .map(|addr| addr.to_string())
            .unwrap_or_default()
    } else {
        warn!(
            "failed to decode instance {} from_address from pegin_request as input_utxos is empty or decode address failed",
            params.instance_id
        );
        "".to_string()
    };
    let input_utxos = params
        .user_info
        .inputs
        .iter()
        .map(|input| ClientUtxo {
            txid: input.outpoint.txid.to_byte_array(),
            vout: input.outpoint.vout,
            amount_sats: input.amount.to_sat(),
        })
        .collect::<Vec<_>>();
    let current_time = current_time_secs();

    Ok(Instance {
        instance_id: params.instance_id,
        network: get_network().to_string(),
        from_addr,
        to_addr: EvmAddress::from(&params.user_info.depositor_evm_address).to_string(),
        amount: params.pegin_amount.to_sat() as i64,
        fees: UInt64Array3(params.user_info.txn_fees),
        input_utxos: serde_json::to_string(&input_utxos)?,
        status: InstanceBridgeInStatus::UserInited.to_string(),
        goat_tx_hash: params.pegin_request_tx_hash,
        goat_tx_height: params.pegin_request_height,
        user_xonly_pubkey: ByteArray32(params.user_info.user_xonly_pubkey.clone().serialize()),
        user_change_addr: params.user_info.user_change_address.clone().to_string(),
        user_refund_addr: params.user_info.user_refund_address.clone().to_string(),
        btc_txid: None,
        pegin_confirm_txid: None,
        pegin_cancel_txid: None,
        committees_answers: IndexMap::new(),
        pegin_data_tx_hash: "".to_string(),
        btc_height: 0,
        parameters: None,
        post_pegin_txhash: None,
        key_deleted: false,
        status_updated_at: params.pegin_timestamp,
        created_at: current_time,
        updated_at: current_time,
    })
}

pub async fn store_instance_parameters(
    local_db: &LocalDB,
    instance_params: &BitvmGcInstanceParameters,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let incoming_parameters_hash = instance_params.parameters_hash()?;
    if let Some(existing_parameters) =
        storage_processor.get_instance_parameters_by_id(&instance_params.instance_id).await?
    {
        let existing_instance_params: BitvmGcInstanceParameters =
            serde_json::from_str(&existing_parameters)?;
        let existing_parameters_hash = existing_instance_params.parameters_hash()?;
        if existing_parameters_hash != incoming_parameters_hash {
            bail!(SpecialError::InvalidPeginData(format!(
                "instance parameters changed for instance_id {}: existing={}, incoming={}",
                instance_params.instance_id,
                hex::encode(existing_parameters_hash),
                hex::encode(incoming_parameters_hash)
            )));
        }
    }
    storage_processor
        .update_instance_parameters(
            &instance_params.instance_id,
            &serde_json::to_string(&instance_params)?,
        )
        .await?;
    Ok(())
}

pub async fn get_instance_parameters(
    local_db: &LocalDB,
    instance_id: Uuid,
) -> Result<Option<BitvmGcInstanceParameters>> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(instance) = storage_processor.find_instance(&instance_id).await? else {
        return Ok(None);
    };

    if let Some(parameters) = instance.parameters {
        return Ok(Some(serde_json::from_str(&parameters)?));
    }

    Ok(Some(
        gen_instance_parameters_local(&instance).with_context(|| {
            format!("failed to reconstruct parameters for instance {instance_id}")
        })?,
    ))
}

pub async fn upsert_pegin_instance_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    process_data_map: &InstanceProcessDataMap,
) -> Result<()> {
    let current_time = current_time_secs();
    storage_processor
        .upsert_pegin_instance_process_data(&PeginInstanceProcessData {
            instance_id,
            process_data: serde_json::to_string(process_data_map)?,
            updated_at: current_time,
            created_at: current_time,
        })
        .await?;
    Ok(())
}

pub async fn find_pegin_instance_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
) -> Result<InstanceProcessDataMap> {
    if let Ok(Some(data)) = storage_processor.find_pegin_instance_process_data(&instance_id).await
        && let Ok(process_data) = serde_json::from_str(data.process_data.as_str())
    {
        Ok(process_data)
    } else {
        Ok(IndexMap::new())
    }
}

pub fn gen_instance_parameters_local(
    instance: &Instance,
) -> anyhow::Result<BitvmGcInstanceParameters> {
    let network = Network::from_str(&instance.network)?;
    let committee_pubkeys: Vec<PublicKey> = instance
        .committees_answers
        .iter()
        .map(|(committee, pubkey)| {
            PublicKey::from_slice(pubkey).with_context(|| {
                format!(
                    "invalid committee public key for committee {committee} in instance {}",
                    instance.instance_id
                )
            })
        })
        .collect::<anyhow::Result<_>>()?;
    if committee_pubkeys.is_empty() {
        bail!(
            "instance {} has no committee answers to derive parameters from",
            instance.instance_id
        );
    }

    let committee_agg_pubkey = generate_n_of_n_public_key(&committee_pubkeys).0;
    let utxos: Vec<client::Utxo> = serde_json::from_str(&instance.input_utxos)?;
    Ok(BitvmGcInstanceParameters {
        network,
        instance_id: instance.instance_id,
        user_info: gen_user_info(
            network,
            &instance.to_addr,
            &instance.user_change_addr.clone(),
            &instance.user_refund_addr.clone(),
            utxos,
            instance.fees.0,
            &instance.user_xonly_pubkey.0,
        )?,
        pegin_amount: Amount::from_sat(instance.amount as u64),
        committee_pubkeys,
        committee_agg_pubkey,
    })
}

fn gen_user_info(
    network: Network,
    depositor_evm_address: &str,
    user_change_addr: &str,
    user_refund_addr: &str,
    utxos: Vec<client::Utxo>,
    txn_fees: [u64; 3],
    user_xonly_pubkey: &[u8; 32],
) -> anyhow::Result<UserInfo> {
    let user_change_address: Address<NetworkUnchecked> = Address::from_str(user_change_addr)?;
    let user_refund_addr: Address<NetworkUnchecked> = Address::from_str(user_refund_addr)?;
    let inputs = utxos
        .into_iter()
        .map(|utxo| Input {
            outpoint: OutPoint { txid: Txid::from_slice(&utxo.txid).unwrap(), vout: utxo.vout },
            amount: Amount::from_sat(utxo.amount_sats),
        })
        .collect();
    Ok(UserInfo {
        depositor_evm_address: EvmAddress::from_str(depositor_evm_address)?.into_array(),
        txn_fees,
        inputs,
        user_xonly_pubkey: XOnlyPublicKey::from_slice(user_xonly_pubkey)?,
        user_change_address: user_change_address.require_network(network)?,
        user_refund_address: user_refund_addr.require_network(network)?,
    })
}
