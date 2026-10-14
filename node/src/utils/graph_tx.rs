//! Building and sending the graph transactions: pre-kickoff, kickoff, skip and
//! challenges.

use crate::env::*;
use crate::error::SpecialError;
use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::{Address, Amount, EcdsaSighashType, OutPoint, TxOut, Txid};
use bitvm_lib::keys::{OperatorMasterKey, VerifierMasterKey, WatchtowerMasterKey};
use bitvm_lib::operator::*;
use bitvm_lib::timelocks::default_timelock_config;
use bitvm_lib::types::{
    BitvmGcCircuitData, BitvmGcGraph, BitvmGcGraphParameters, BitvmGcInstanceParameters,
    PrekickoffParameters,
};
use bitvm_lib::verifier::*;
use bitvm_lib::watchtower::*;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::{
    base::TaprootConnector,
    kickoff_connectors::{ForceSkipConnector, KickoffConnector, PrekickoffConnector},
};
use goat::scripts::generate_opreturn_script;
use goat::transactions::base::Input;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::PrekickoffTransaction;
use store::localdb::LocalDB;

use uuid::Uuid;

use super::btc::{
    broadcast_package, broadcast_tx, build_cpfp_txns, build_sign_and_broadcast_tx, fund_address,
    get_fee_rate, get_proper_utxo_set, node_p2wsh_address, node_sign, tx_visible,
};
use super::graph_validate::{
    challenge_amount, min_prekickoff_input_amount, min_required_verifier, prekickoff_fee_amount,
    prekickoff_replenishment_amount, validate_watchtower_registry_selection,
};

pub async fn verifier_force_skip_kickoff(client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_master_keypair = verifier_master_key.master_keypair();
    let verifier_receive_address =
        node_p2wsh_address(get_network(), &verifier_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (force_skip_kickoff_tx, anchor_added) =
        build_force_skip_kickoff_tx(graph, verifier_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = force_skip_kickoff_tx.output.len() as u64 - 1;
        let force_skip_kickoff_tx_total_input_amount =
            graph.force_skip_kickoff.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        let child_tx = build_cpfp_txns(
            client,
            &force_skip_kickoff_tx,
            anchor_vout,
            force_skip_kickoff_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => {
                broadcast_package(client, &[force_skip_kickoff_tx.clone(), tx], true).await?
            }
            None => broadcast_tx(client, &force_skip_kickoff_tx).await?,
        }
    } else {
        broadcast_tx(client, &force_skip_kickoff_tx).await?;
    }
    Ok(force_skip_kickoff_tx.compute_txid())
}

pub async fn verifier_quick_challenge(client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_master_keypair = verifier_master_key.master_keypair();
    let verifier_receive_address =
        node_p2wsh_address(get_network(), &verifier_master_keypair.public_key().into());
    let fee_rate = get_fee_rate(client).await?;
    let (quick_challenge_tx, anchor_added) =
        build_quick_challenge_tx(graph, verifier_receive_address, fee_rate)?;
    if anchor_added {
        let anchor_vout = quick_challenge_tx.output.len() as u64 - 1;
        let quick_challenge_tx_total_input_amount =
            graph.quick_challenge.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        let child_tx = build_cpfp_txns(
            client,
            &quick_challenge_tx,
            anchor_vout,
            quick_challenge_tx_total_input_amount,
        )
        .await?;
        match child_tx {
            Some(tx) => broadcast_package(client, &[quick_challenge_tx.clone(), tx], true).await?,
            None => broadcast_tx(client, &quick_challenge_tx).await?,
        }
    } else {
        broadcast_tx(client, &quick_challenge_tx).await?;
    }
    Ok(quick_challenge_tx.compute_txid())
}

pub async fn build_genesis_prekickoff_tx(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> Result<PrekickoffTransaction> {
    let watchtower_num = goat_client.committee_mana_get_watchtowers().await?.len();
    let verifier_num = min_required_verifier();
    let network = get_network();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let node_keypair = operator_master_key.master_keypair();
    let operator_taproot_public_key = node_keypair.x_only_public_key().0;
    let cur_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let next_kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let init_amount = prekickoff_replenishment_amount();
    let cur_prekickoff_connector_input = genesis_funding_input(
        btc_client,
        node_keypair,
        cur_prekickoff_connector.generate_taproot_address(),
        init_amount,
    )
    .await?;
    let fee_amount = prekickoff_fee_amount(0);
    PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        vec![],
        vec![],
        fee_amount.to_sat(),
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))
}

/// Reuse a matching unspent output, or fund the genesis address.
async fn genesis_funding_input(
    btc_client: &BTCClient,
    node_keypair: Keypair,
    address: Address,
    amount: Amount,
) -> Result<Input> {
    let existing = btc_client
        .get_address_utxo(address.clone())
        .await?
        .into_iter()
        .filter(|utxo| utxo.value == amount)
        .min_by_key(|utxo| (utxo.txid, utxo.vout));
    let outpoint = match existing {
        Some(utxo) => OutPoint { txid: utxo.txid, vout: utxo.vout },
        None => fund_address(btc_client, node_keypair, address, amount).await?,
    };
    Ok(Input { outpoint, amount })
}

pub async fn build_prekickoff_params(
    btc_client: &BTCClient,
    graph_nonce: u64,
    cur_prekickoff_txn: PrekickoffTransaction,
) -> Result<PrekickoffParameters> {
    let prekickoff_remaining_amount = cur_prekickoff_txn
        .prekickoff_connector_input()
        .map_err(|e| anyhow!("failed to get pre-kickoff connector input: {e}"))?
        .amount;
    let (replenish_fee_inputs, replenish_fee_prev_outs, fee_amount) = if prekickoff_remaining_amount
        >= min_prekickoff_input_amount()
    {
        // no need to replenish funds
        (vec![], vec![], prekickoff_fee_amount(0))
    } else {
        let network = get_network();
        let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
        let master_keypair = operator_master_key.master_keypair();
        let nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce);
        let nonce_address = node_p2wsh_address(network, &nonce_keypair.public_key().into());
        let replenishment_amount = prekickoff_replenishment_amount();
        let mut replenish_fee_inputs: Vec<Input> = btc_client
            .get_address_utxo(nonce_address.clone())
            .await?
            .into_iter()
            .map(|u| Input { outpoint: OutPoint { txid: u.txid, vout: u.vout }, amount: u.value })
            .collect();
        let current_balance: Amount = replenish_fee_inputs.iter().map(|i| i.amount).sum();
        if current_balance < replenishment_amount {
            let shortfall = replenishment_amount - current_balance;
            let extra_input = Input {
                outpoint: fund_address(
                    btc_client,
                    master_keypair,
                    nonce_address.clone(),
                    shortfall,
                )
                .await?,
                amount: shortfall,
            };
            replenish_fee_inputs.push(extra_input);
        };
        let replenish_fee_prev_outs: Vec<TxOut> = replenish_fee_inputs
            .iter()
            .map(|i| TxOut { value: i.amount, script_pubkey: nonce_address.script_pubkey() })
            .collect();
        let fee_amount = prekickoff_fee_amount(replenish_fee_inputs.len());
        (replenish_fee_inputs, replenish_fee_prev_outs, fee_amount)
    };
    Ok(PrekickoffParameters {
        cur_prekickoff_txn,
        replenish_fee_inputs,
        replenish_fee_prev_outs,
        fee_amount: fee_amount.to_sat(),
    })
}

pub async fn build_graph_params(
    _local_db: &LocalDB,
    goat_client: &GOATClient,
    instance_parameters: BitvmGcInstanceParameters,
    prekickoff_parameters: PrekickoffParameters,
    bitvm_gc_circuit_datas: Vec<BitvmGcCircuitData>,
    graph_nonce: u64,
    graph_id: Uuid,
) -> Result<BitvmGcGraphParameters> {
    let network = instance_parameters.network;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_pubkey = operator_master_keypair.public_key().into();
    let operator_receive_address =
        node_p2wsh_address(instance_parameters.network, &operator_pubkey);
    let (_, operator_assert_wots_pubkey) =
        operator_master_key.assert_wots_keypair_for_graph(graph_id);
    let (_, operator_commit_pubin_wots_pubkey) =
        operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id);
    let watchtower_pubkeys = goat_client.committee_mana_get_watchtowers().await?;
    let watchtower_ack_hashlocks = (0..watchtower_pubkeys.len())
        .map(|index| {
            bitcoin::hashes::hash160::Hash::hash(
                &operator_master_key.preimage_for_graph(graph_id, index),
            )
            .to_byte_array()
        })
        .collect();
    validate_watchtower_registry_selection(&watchtower_pubkeys, &watchtower_pubkeys)?;
    Ok(BitvmGcGraphParameters {
        instance_parameters,
        prekickoff_parameters,
        timelock_config: default_timelock_config(network),
        graph_id,
        graph_nonce,
        challenge_amount: challenge_amount(),
        operator_pubkey,
        operator_assert_wots_pubkey,
        operator_commit_pubin_wots_pubkey,
        operator_receive_address,
        watchtower_pubkeys,
        watchtower_ack_hashlocks,
        pubin_disprove_constant: [0u8; 32],
        gc_data: bitvm_gc_circuit_datas,
    })
}

pub async fn operator_skip_graph(btc_client: &BTCClient, graph: &mut BitvmGcGraph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_master_keypair = operator_master_key.master_keypair();
    let operator_receive_address =
        node_p2wsh_address(get_network(), &operator_master_keypair.public_key().into());
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce - 1);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let prekickoff_tx_total_input_amount =
        graph.cur_prekickoff.input_amounts.clone().into_iter().sum();
    let child_tx =
        build_cpfp_txns(btc_client, &prekickoff_tx, anchor_vout, prekickoff_tx_total_input_amount)
            .await?;
    let prekickoff_txid = prekickoff_tx.compute_txid();
    match operator_sign_skip_kickoff(
        operator_graph_keypair,
        graph,
        operator_receive_address,
        get_fee_rate(btc_client).await?,
    )? {
        Some(skip_kickoff_tx) => {
            let skip_kickoff_txid = skip_kickoff_tx.compute_txid();
            if !tx_visible(btc_client, &prekickoff_txid).await? {
                broadcast_package(btc_client, &[prekickoff_tx, skip_kickoff_tx], true).await?;
                if let Some(child_tx) = child_tx {
                    broadcast_tx(btc_client, &child_tx).await?;
                }
            } else if !tx_visible(btc_client, &skip_kickoff_txid).await? {
                if let Some(child_tx) = child_tx {
                    broadcast_package(btc_client, &[skip_kickoff_tx, child_tx], true).await?;
                } else {
                    broadcast_tx(btc_client, &skip_kickoff_tx).await?;
                }
            }
        }
        None => match child_tx {
            Some(tx) => {
                if !tx_visible(btc_client, &prekickoff_txid).await? {
                    broadcast_package(btc_client, &[prekickoff_tx, tx], true).await?;
                }
            }
            None => {
                if !tx_visible(btc_client, &prekickoff_txid).await? {
                    broadcast_tx(btc_client, &prekickoff_tx).await?;
                }
            }
        },
    };
    Ok(())
}

pub async fn operator_kickoff(btc_client: &BTCClient, graph: &mut BitvmGcGraph) -> Result<()> {
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let mut prekickoff_tx = operator_sign_prekickoff_input_0(operator_graph_keypair, graph)?;
    if prekickoff_tx.input.len() != 1 {
        let operator_nonce_keypair = operator_master_key.keypair_for_nonce(graph_nonce - 1);
        for i in 1..prekickoff_tx.input.len() {
            let input_value = graph.cur_prekickoff.input_amounts[i];
            node_sign(
                &mut prekickoff_tx,
                i,
                input_value,
                bitcoin::EcdsaSighashType::All,
                &operator_nonce_keypair,
            )?;
        }
    }
    let prekickoff_txid = prekickoff_tx.compute_txid();
    let anchor_vout = prekickoff_tx.output.len() as u64 - 1;
    let prekickoff_tx_total_input_amount =
        graph.cur_prekickoff.input_amounts.clone().into_iter().sum();
    let prekickoff_child_tx =
        build_cpfp_txns(btc_client, &prekickoff_tx, anchor_vout, prekickoff_tx_total_input_amount)
            .await?;

    let kickoff_tx = operator_sign_kickoff(operator_graph_keypair, graph)?;
    let kickoff_txid = kickoff_tx.compute_txid();
    let anchor_vout = kickoff_tx.output.len() as u64 - 1;
    let kickoff_tx_total_input_amount = graph.kickoff.prev_outs().iter().map(|o| o.value).sum();
    let kickoff_child_tx =
        build_cpfp_txns(btc_client, &kickoff_tx, anchor_vout, kickoff_tx_total_input_amount)
            .await?;

    // If a tx is already on-chain, skip rebroadcasting and move to the next one.
    let mut kickoff_child_broadcasted = false;
    if !tx_visible(btc_client, &prekickoff_txid).await? {
        // Parent not on-chain yet: broadcast parent and kickoff together as a package.
        broadcast_package(btc_client, &[prekickoff_tx, kickoff_tx], true).await?;
    } else if !tx_visible(btc_client, &kickoff_txid).await? {
        // Parent is on-chain, but kickoff isn't: try kickoff (and its CPFP child if present).
        if let Some(child) = kickoff_child_tx.as_ref() {
            broadcast_package(btc_client, &[kickoff_tx, child.clone()], true).await?;
            kickoff_child_broadcasted = true;
        } else {
            broadcast_tx(btc_client, &kickoff_tx).await?;
        }
    }

    // Ensure both transactions are seen on-chain and then handle CPFP children.
    if !tx_visible(btc_client, &prekickoff_txid).await? {
        bail!("prekickoff tx not on chain after broadcasting");
    }
    if let Some(prekickoff_child_tx) = prekickoff_child_tx
        && let Err(e) = broadcast_tx(btc_client, &prekickoff_child_tx).await
    {
        tracing::warn!("failed to broadcast prekickoff child tx: {e}");
    }
    if !tx_visible(btc_client, &kickoff_txid).await? {
        bail!("kickoff tx not on chain after broadcasting");
    }
    if !kickoff_child_broadcasted
        && let Some(kickoff_child_tx) = kickoff_child_tx
        && let Err(e) = broadcast_tx(btc_client, &kickoff_child_tx).await
    {
        tracing::warn!("failed to broadcast kickoff child tx: {e}");
    }
    Ok(())
}

pub async fn send_challenge_tx(btc_client: &BTCClient, graph: &BitvmGcGraph) -> Result<Txid> {
    let (mut challenge_tx, _) = export_challenge_tx(graph)?;
    let challenge_keypair = VerifierMasterKey::new(get_bitvm_key()?).master_keypair();
    let verifier_evm_address = get_node_goat_address()
        .ok_or_else(|| anyhow::anyhow!("failed to get node goat address".to_string()))?;
    challenge_tx.output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: generate_opreturn_script(verifier_evm_address.to_vec()),
    });
    let connector_a_input = graph
        .kickoff
        .connector_a_input()
        .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?;
    build_sign_and_broadcast_tx(
        btc_client,
        challenge_keypair,
        challenge_tx.input,
        connector_a_input.amount,
        challenge_tx.output,
    )
    .await
}

pub async fn send_watchtower_challenge_tx(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    watchtower_index: usize,
    commitment_data: Vec<u8>,
) -> Result<Txid> {
    let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let fee_rate = get_fee_rate(btc_client).await?;
    let watchtower_challenge_tx_base_vbytes =
        estimate_watchtower_challenge_vbytes(commitment_data.len());
    let node_address = node_p2wsh_address(get_network(), &watchtower_keypair.public_key().into());
    match get_proper_utxo_set(
        btc_client,
        watchtower_challenge_tx_base_vbytes as u64,
        node_address.clone(),
        Amount::ZERO,
        fee_rate,
    )
    .await?
    {
        Some((inputs, fee_amount, _)) => {
            let mut watchtower_challenge_tx = build_watchtower_challenge_tx(
                graph,
                &watchtower_keypair,
                watchtower_index,
                &commitment_data,
                inputs.clone(),
                &node_address,
                fee_amount,
            )
            .unwrap();
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut watchtower_challenge_tx,
                    i + 1,
                    input.amount,
                    EcdsaSighashType::All,
                    &watchtower_keypair,
                )?;
            }
            broadcast_tx(btc_client, &watchtower_challenge_tx).await?;
            Ok(watchtower_challenge_tx.compute_txid())
        }
        None => {
            let current_balance = btc_client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance}"
            )));
        }
    }
}
