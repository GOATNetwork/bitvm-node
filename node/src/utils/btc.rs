//! Bitcoin transactions: fees, broadcasts, CPFP, UTXO selection, outpoint and
//! confirmation checks.

use crate::env::*;
use crate::error::SpecialError;
use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitvm::treepp::*;
use bitvm_lib::operator::*;
use bitvm_lib::timelocks::connector_f_timelock_blocks;
use client::btc_chain::BTCClient;
use esplora_client::Utxo;
use goat::constants::TimelockConfig;
use goat::scripts::{generate_opreturn_script, p2a_output};
use goat::transactions::base::Input;
use goat::transactions::signing::populate_p2wsh_witness;
use std::time::Instant;

pub async fn is_take1_timelock_expired(
    client: &BTCClient,
    kickoff_height: u32,
    timelock_config: &TimelockConfig,
) -> Result<bool> {
    let lock_blocks = take1_timelock_with_config(get_network(), timelock_config);
    let current_height = client.get_height().await?;
    Ok(current_height >= kickoff_height + lock_blocks)
}

pub async fn is_take2_timelock_expired(
    client: &BTCClient,
    operator_assert_height: u32,
    watchtower_challenge_init_height: u32,
    timelock_config: &TimelockConfig,
) -> Result<bool> {
    let network = get_network();
    let connector_d_lock_blocks = take2_timelock_with_config(network, timelock_config);
    let connector_f_lock_blocks = connector_f_timelock_blocks(network, timelock_config);
    let current_height = client.get_height().await?;
    Ok(current_height >= operator_assert_height + connector_d_lock_blocks
        && current_height >= watchtower_challenge_init_height + connector_f_lock_blocks)
}

pub async fn get_fee_rate(client: &BTCClient) -> Result<f64> {
    match client.network() {
        //TODO mempool api /fee-estimates failed, fix it latter
        Network::Testnet | Network::Testnet4 | Network::Regtest => Ok(5.0),
        _ => {
            let res = client.get_fee_estimates().await?;
            Ok(*res.get(&DEFAULT_CONFIRMATION_TARGET).ok_or(anyhow!(
                "fee for {DEFAULT_CONFIRMATION_TARGET} confirmation target not found"
            ))?)
        }
    }
}

/// Broadcasts a raw transaction to the Bitcoin network using the mempool API.
///
/// Requirements:
/// - The mempool API URL must be configured.
/// - The transaction should already be fully signed.
pub async fn broadcast_tx(client: &BTCClient, tx: &Transaction) -> Result<()> {
    let txid = tx.compute_txid();
    let started_at = Instant::now();
    match client.broadcast(tx).await {
        Ok(()) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_btc_tx_broadcast(true);
            }
            tracing::info!(
                event = "btc_tx_broadcast",
                outcome = "broadcasted",
                txid = %txid,
                input_count = tx.input.len(),
                output_count = tx.output.len(),
                elapsed_ms = started_at.elapsed().as_millis() as u64,
                "bitcoin transaction broadcast accepted by client"
            );
            Ok(())
        }
        Err(err) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_btc_tx_broadcast(false);
            }
            tracing::warn!(
                event = "btc_tx_broadcast",
                outcome = "failed",
                txid = %txid,
                input_count = tx.input.len(),
                output_count = tx.output.len(),
                elapsed_ms = started_at.elapsed().as_millis() as u64,
                error = %err,
                "bitcoin transaction broadcast failed"
            );
            Err(err)
        }
    }
}

pub async fn broadcast_package(
    client: &BTCClient,
    txns: &[Transaction],
    fallback_on_failure: bool,
) -> Result<()> {
    let txids: Vec<Txid> = txns.iter().map(Transaction::compute_txid).collect();
    let started_at = Instant::now();
    match client.broadcast_package(txns).await {
        Ok(_) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_btc_tx_broadcast(true);
            }
            tracing::info!(
                event = "btc_tx_package_broadcast",
                outcome = "broadcasted",
                transaction_count = txids.len(),
                txids = ?txids,
                elapsed_ms = started_at.elapsed().as_millis() as u64,
                "bitcoin transaction package broadcast accepted by client"
            );
        }
        Err(e) => {
            if fallback_on_failure {
                tracing::warn!(
                    event = "btc_tx_package_broadcast",
                    outcome = "fallback_to_individual_broadcast",
                    transaction_count = txids.len(),
                    txids = ?txids,
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    error = %e,
                    "bitcoin transaction package broadcast failed; falling back to individual broadcasts"
                );
                for tx in txns {
                    broadcast_tx(client, tx).await?;
                }
            } else {
                if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                    metrics_state.record_btc_tx_broadcast(false);
                }
                // Surface the original error when fallback is disabled
                return Err(e);
            }
        }
    }
    Ok(())
}

pub async fn fund_address(
    client: &BTCClient,
    node_keypair: Keypair,
    address: Address,
    amount: Amount,
) -> Result<OutPoint> {
    let txins = Vec::new();
    let txouts = vec![TxOut { script_pubkey: address.script_pubkey(), value: amount }];
    let txid =
        build_sign_and_broadcast_tx(client, node_keypair, txins, Amount::ZERO, txouts).await?;
    Ok(OutPoint { txid, vout: 0 })
}

pub async fn build_sign_and_broadcast_tx(
    client: &BTCClient,
    node_keypair: Keypair,
    txins: Vec<TxIn>,
    total_input_amount: Amount,
    txouts: Vec<TxOut>,
) -> Result<Txid> {
    let txouts = if txouts.is_empty() {
        // bitcoin network does not allow a transaction without outputs
        vec![TxOut { value: Amount::ZERO, script_pubkey: generate_opreturn_script(vec![]) }]
    } else {
        txouts
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };
    let fixed_inputs_num = tx.input.len();
    let total_output_amount: Amount = tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_fee_rate(client).await?;
    let node_address = node_p2wsh_address(get_network(), &node_keypair.public_key().into());
    let shortfall =
        Amount::from_sat(total_output_amount.to_sat().saturating_sub(total_input_amount.to_sat()));
    match get_proper_utxo_set(
        client,
        tx.weight().to_vbytes_ceil(),
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            for input in &inputs {
                tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            }
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut tx,
                    i + fixed_inputs_num,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_keypair,
                )?;
            }
            broadcast_tx(client, &tx).await?;
            Ok(tx.compute_txid())
        }
        None => {
            let current_balance = client
                .get_address_utxo(node_address)
                .await?
                .iter()
                .map(|u| u.value)
                .sum::<Amount>();
            bail!(SpecialError::InsufficientBalance(format!(
                "Not enough balance to complete the transaction, current_balance: {current_balance} < shortfall: {shortfall}"
            )));
        }
    }
}

pub async fn build_cpfp_txns(
    btc_client: &BTCClient,
    parent_tx: &Transaction,
    anchor_vout: u64,
    parent_tx_total_input_amount: Amount,
) -> Result<Option<Transaction>> {
    let network = get_network();
    if network == Network::Regtest || network == Network::Testnet || network == Network::Testnet4 {
        // skip cpfp in test network for testing convenience
        return Ok(None);
    }
    let node_master_keypair = get_bitvm_key()?;
    let node_address = node_p2wsh_address(network, &node_master_keypair.public_key().into());
    let total_output_amount: Amount = parent_tx.output.iter().map(|o| o.value).sum();
    let fee_rate = get_fee_rate(btc_client).await?;
    let fee_amount =
        Amount::from_sat((parent_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if total_output_amount + fee_amount <= parent_tx_total_input_amount {
        return Ok(None);
    };
    let shortfall = total_output_amount + fee_amount - parent_tx_total_input_amount;
    match get_proper_utxo_set(
        btc_client,
        ANCHOR_CHILD_BASE_VBYTES,
        node_address.clone(),
        shortfall,
        fee_rate,
    )
    .await?
    {
        Some((inputs, _, change_amount)) => {
            let mut child_tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            if change_amount > Amount::from_sat(DUST_AMOUNT) {
                child_tx.output.push(TxOut {
                    script_pubkey: node_address.script_pubkey(),
                    value: change_amount,
                });
            } else {
                // add an op_return output to avoid no-output transaction
                child_tx.output.push(TxOut {
                    script_pubkey: generate_opreturn_script(vec![]),
                    value: Amount::ZERO,
                });
            }
            for input in &inputs {
                child_tx.input.push(TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                });
            }
            child_tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: parent_tx.compute_txid(),
                    vout: anchor_vout as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            });
            for (i, input) in inputs.iter().enumerate() {
                node_sign(
                    &mut child_tx,
                    i,
                    input.amount,
                    EcdsaSighashType::All,
                    &node_master_keypair,
                )?;
            }
            Ok(Some(child_tx))
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
            )))
        }
    }
}

pub async fn broadcast_tx_with_cpfp(
    btc_client: &BTCClient,
    parent_tx: Transaction,
    parent_tx_total_input_amount: Amount,
) -> Result<()> {
    let anchor_output = p2a_output();
    let anchor_vout = parent_tx
        .output
        .iter()
        .position(|output| output == &anchor_output)
        .ok_or_else(|| anyhow!("cannot CPFP transaction without a P2A anchor output"))?;
    if let Some(duplicate_vout) = parent_tx
        .output
        .iter()
        .enumerate()
        .skip(anchor_vout + 1)
        .find_map(|(vout, output)| if output == &anchor_output { Some(vout) } else { None })
    {
        bail!("transaction has multiple P2A anchor outputs at {anchor_vout} and {duplicate_vout}");
    };
    let child_tx =
        build_cpfp_txns(btc_client, &parent_tx, anchor_vout as u64, parent_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(btc_client, &[parent_tx, tx], true).await?,
        None => broadcast_tx(btc_client, &parent_tx).await?,
    };
    Ok(())
}

/// Returns:
/// - `Ok(None)` if given address does not have enough btc,
/// - `Ok(Some((utxos, fee_amount, change_amount)))`
pub async fn get_proper_utxo_set(
    client: &BTCClient,
    base_vbytes: u64,
    address: Address,
    target_amount: Amount,
    fee_rate: f64,
) -> Result<Option<(Vec<Input>, Amount, Amount)>> {
    fn estimate_tx_vbytes(base_vbytes: u64, extra_inputs: usize, extra_outputs: usize) -> u64 {
        // p2wsh inputs/outputs
        base_vbytes
            + (extra_inputs as u64 * CHECKSIG_P2WSH_INPUT_VBYTES_ESTIMATE)
            + (extra_outputs as u64 * P2WSH_OUTPUT_VBYTES)
    }
    fn to_input(utxos: Vec<Utxo>) -> Vec<Input> {
        utxos
            .into_iter()
            .map(|utxo| Input {
                outpoint: OutPoint { txid: utxo.txid, vout: utxo.vout },
                amount: utxo.value,
            })
            .collect()
    }
    tracing::debug!("get utxos from: {address}");

    let utxos = client.get_address_utxo(address).await?;
    let mut sorted_utxos = utxos;
    sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total_value = Amount::ZERO;

    for utxo in sorted_utxos.into_iter().take(MAX_CUSTOM_INPUTS) {
        selected.push(utxo.clone());
        total_value += utxo.value;

        let num_inputs = selected.len();
        let num_outputs = 1; // change
        let tx_vbytes = estimate_tx_vbytes(base_vbytes, num_inputs, num_outputs);
        let fee = Amount::from_sat((tx_vbytes as f64 * fee_rate).ceil() as u64);

        if total_value >= target_amount + fee {
            let change = total_value - target_amount - fee;
            return Ok(Some((to_input(selected), fee, change)));
        }
    }

    Ok(None)
}

pub fn node_p2wsh_script(pubkey: &PublicKey) -> ScriptBuf {
    script! {
        { *pubkey }
        OP_CHECKSIG
    }
    .compile()
}

pub fn node_p2wsh_address(network: Network, pubkey: &PublicKey) -> Address {
    Address::p2wsh(&node_p2wsh_script(pubkey), network)
}

pub fn node_sign(
    tx: &mut Transaction,
    input_index: usize,
    input_value: Amount,
    sighash_type: EcdsaSighashType,
    node_keypair: &Keypair,
) -> Result<()> {
    let node_pubkey = node_keypair.public_key();
    populate_p2wsh_witness(
        tx,
        input_index,
        sighash_type,
        &node_p2wsh_script(&node_pubkey.into()),
        input_value,
        &vec![node_keypair],
    );
    Ok(())
}

/// Whether the backend knows the transaction: confirmed, or still in its mempool.
pub async fn tx_visible(client: &BTCClient, txid: &Txid) -> Result<bool> {
    match client.get_tx(txid).await? {
        Some(_) => Ok(true),
        _ => Ok(false),
    }
}

pub async fn tx_confirmed(client: &BTCClient, txid: &Txid) -> Result<bool> {
    Ok(client.get_tx_status(txid).await?.confirmed)
}

/// The confirmed spender of an outpoint. A spend that is only in the mempool can be replaced,
/// so nothing irreversible is decided on it.
pub async fn outpoint_spent_confirmed(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<Txid>> {
    match outpoint_spent_txid(client, txid, vout).await? {
        Some(spent_txid) if client.get_tx_status(&spent_txid).await?.confirmed => {
            Ok(Some(spent_txid))
        }
        _ => Ok(None),
    }
}

pub async fn outpoint_available(client: &BTCClient, txid: &Txid, vout: u64) -> Result<bool> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(!status.spent),
        _ => Ok(false),
    }
}

pub async fn outpoint_spent_txid(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<Txid>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => Ok(status.txid),
        _ => Ok(None),
    }
}

pub async fn outpoint_spent_txin(
    client: &BTCClient,
    txid: &Txid,
    vout: u64,
) -> Result<Option<(Txid, u64, TxIn)>> {
    match client.get_output_status(txid, vout).await? {
        Some(status) => {
            if let Some(spent_txid) = status.txid
                && let Some(vin) = status.vin
                && let Some(spent_tx) = client.get_tx(&spent_txid).await?
            {
                Ok(spent_tx.input.get(vin as usize).cloned().map(|txin| (spent_txid, vin, txin)))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// Returns:
/// - `Ok(true)` tx confirmed,
/// - `Ok(false)` tx not confirmed, exceeds the maximum waiting time
pub async fn wait_tx_confirmation(
    btc_client: &BTCClient,
    txid: &Txid,
    interval: u64,
    max_wait_secs: u64,
) -> Result<bool> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let start_time = Instant::now();
    loop {
        if start_time.elapsed().as_secs() > max_wait_secs {
            // println!("Timeout: Transaction not confirmed after {} seconds", max_wait_secs);
            return Ok(false);
        };
        // FIXME: should not use esplora directly
        match btc_client.get_tx_status(txid).await {
            Ok(status) => {
                if let Some(_height) = status.block_height {
                    // println!("Transaction confirmed in block {}", height);
                    return Ok(true);
                } else {
                    // println!("Transaction unconfirmed, polling again...");
                }
            }
            Err(e) => {
                bail!("Failed to fetch transaction status: {e}");
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

pub async fn check_bridge_in_uxto_available_or_self_spent(
    btc_client: &BTCClient,
    target_txid: Option<String>,
    utxos: &[client::Utxo],
) -> Result<bool> {
    for utxo in utxos {
        if let Ok(txid) = Txid::from_slice(&utxo.txid)
            && let Ok(Some(status)) = btc_client.get_output_status(&txid, utxo.vout as u64).await
            && status.spent
        {
            if let Some(target_txid) = target_txid
                && let Some(txid) = status.txid
                && txid.to_string() == target_txid
            {
                return Ok(true);
            }
            return Ok(false);
        }
    }
    Ok(true)
}
