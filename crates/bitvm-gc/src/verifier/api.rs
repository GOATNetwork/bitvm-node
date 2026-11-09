use crate::{
    babe_adapter::TxAssertWitness,
    timelocks::{default_timelock_config, disprove_timelock_blocks},
    types::BitvmGcGraph,
};
use anyhow::{Result, bail};
use ark_bn254::{G1Affine, G2Affine};
use ark_serialize::CanonicalSerialize;
use bitcoin::{
    Address, Amount, Network, ScriptBuf, Transaction, TxIn, TxOut, Witness, script::read_scriptint,
};
use bitvm::chunk::api::type_conversion_utils::RawWitness;
use goat::{
    assert_scripts::{INPUT_WIRE_NUM, Label, PROVER_SIG_LEN},
    connectors::{base::TaprootConnector, connector_d::CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX},
    constants::TimelockConfig,
    scripts::{generate_opreturn_script, p2a_output},
    transactions::{
        assert::{pubin_disprove, validate_pubin},
        base::{DUST_AMOUNT, output_topology},
        pre_signed::PreSignedTransaction,
        watchtower_challenge::extract_operator_preimage_from_ack_txin,
    },
    wots::{WOTS96_BASE, Wots, Wots96},
};

/// challenge has a pre-signed SinglePlusAnyoneCanPay input and output
/// get incomplete tx here, add inputs with enough amount, then broadcast it to start challnege progress
pub fn export_challenge_tx(graph: &BitvmGcGraph) -> Result<(Transaction, Amount)> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    Ok((graph.challenge.tx().clone(), graph.challenge.challenge_amount))
}

/// return true if anchor output is added
/// return false if change output is added or no output is added
fn add_change_or_anchor_output(
    tx: &mut Transaction,
    total_input_amount: Amount,
    change_address: Address,
    fee_rate: f64,
) -> Result<bool> {
    let dust_amount = Amount::from_sat(DUST_AMOUNT);
    let output_amount = tx.output.iter().map(|o| o.value).sum();
    tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: change_address.script_pubkey() });
    let min_relay_fee = 1.0;
    let min_fee_amount =
        Amount::from_sat((tx.weight().to_vbytes_ceil() as f64 * min_relay_fee).ceil() as u64);
    let fee_amount =
        Amount::from_sat((tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if min_fee_amount + dust_amount + output_amount > total_input_amount {
        bail!("insufficient input amount to cover min relay fee");
    }
    if fee_amount + output_amount + dust_amount < total_input_amount {
        // add change output
        let change_amount = total_input_amount - fee_amount - output_amount;
        tx.output.last_mut().unwrap().value = change_amount;
        Ok(false)
    } else if fee_amount + output_amount > total_input_amount {
        // add anchor output
        tx.output.pop();
        tx.output.push(p2a_output());
        Ok(true)
    } else {
        // not add any output since remaining is just enough to cover fee
        tx.output.pop();
        Ok(false)
    }
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_force_skip_kickoff_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    // Input 1 spends the force-skip connector, which only the committee signs.
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    let mut tx = graph.force_skip_kickoff.tx().clone();
    let total_input_amount = graph.force_skip_kickoff.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_quick_challenge_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    // Input 1 spends the force-skip connector, which only the committee signs.
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    let mut tx = graph.quick_challenge.tx().clone();
    let total_input_amount = graph.quick_challenge.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_challenge_incomplete_kickoff_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    let mut tx = graph.challenge_incomplete_kickoff.tx().clone();
    let total_input_amount =
        graph.challenge_incomplete_kickoff.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

fn split_operator_assert_wots_and_extra_data(
    mut operator_assertion: RawWitness,
) -> Result<(RawWitness, Vec<u8>, Vec<u8>)> {
    let expected_len = PROVER_SIG_LEN + 2;
    if operator_assertion.len() != expected_len {
        bail!(
            "operator assert witness has {} stack items; expected {expected_len}",
            operator_assertion.len()
        );
    }
    let pi3 = operator_assertion
        .pop()
        .ok_or_else(|| anyhow::anyhow!("operator assert witness is empty"))?;
    let pi2 = operator_assertion
        .pop()
        .ok_or_else(|| anyhow::anyhow!("operator assert witness is missing pi2"))?;
    Ok((operator_assertion, pi2, pi3))
}

fn operator_assert_wots_signature(operator_assertion: &RawWitness) -> Result<Vec<[u8; 21]>> {
    if operator_assertion.len() != PROVER_SIG_LEN {
        bail!(
            "operator assert WOTS witness has {} stack items; expected {PROVER_SIG_LEN}",
            operator_assertion.len()
        );
    }

    let mut wots_sig = Vec::with_capacity(Wots96::TOTAL_DIGIT_LEN as usize);
    for i in (0..operator_assertion.len()).step_by(2) {
        let digit_signature = &operator_assertion[i];
        let digit_value_bytes = &operator_assertion[i + 1];
        if digit_signature.len() != 20 {
            bail!(
                "operator assert WOTS digit signature has {} bytes; expected 20",
                digit_signature.len()
            );
        }
        if digit_value_bytes.len() > 2 {
            bail!(
                "operator assert WOTS digit value has {} bytes; expected at most 2",
                digit_value_bytes.len()
            );
        }
        let digit_value = read_scriptint(digit_value_bytes)
            .map_err(|e| anyhow::anyhow!("invalid operator assert WOTS digit value: {e}"))?;
        if !(0..WOTS96_BASE as i64).contains(&digit_value) {
            bail!("operator assert WOTS digit value {digit_value} is out of range");
        }

        let mut item = [0u8; 21];
        item[..20].copy_from_slice(digit_signature);
        item[20] = digit_value as u8;
        wots_sig.push(item);
    }
    Ok(wots_sig)
}

fn validate_operator_assert_extra_data(pi2: &[u8], pi3: &[u8]) -> Result<()> {
    let pi2_len = G2Affine::default().compressed_size();
    let pi3_len = G1Affine::default().compressed_size();
    if pi2.len() != pi2_len {
        bail!("operator assert pi2 has {} bytes; expected {pi2_len}", pi2.len());
    }
    if pi3.len() != pi3_len {
        bail!("operator assert pi3 has {} bytes; expected {pi3_len}", pi3.len());
    }
    Ok(())
}

/// `txin` as a script-path spend of `leaf_script`, with any BIP341 annex
/// dropped so the goat extractors see exactly `[data.., script, control block]`.
fn script_path_txin(txin: &TxIn, leaf_script: &ScriptBuf) -> Result<TxIn> {
    let mut witness = txin.witness.to_vec();
    if txin.witness.taproot_annex().is_some() {
        witness.pop();
    }
    if witness.len() < 2 || witness[witness.len() - 2] != leaf_script.as_bytes() {
        bail!("input does not spend the expected leaf script");
    }
    Ok(TxIn { witness: Witness::from_slice(&witness), ..txin.clone() })
}

fn operator_assert_raw_witness(
    graph: &BitvmGcGraph,
    operator_assert_txin: &TxIn,
) -> Result<RawWitness> {
    let connector_c = graph.connector_c();
    let txin =
        script_path_txin(operator_assert_txin, &connector_c.generate_taproot_leaf_script(1))?;
    connector_c
        .extract_leaf_1_raw_witness(&txin)
        .map_err(|e| anyhow::anyhow!("failed to extract operator assertion: {e}"))
}

fn operator_commit_pubin_raw_witness(
    graph: &BitvmGcGraph,
    commit_pubin_txin: &TxIn,
) -> Result<RawWitness> {
    let connector_e = graph.connector_e();
    let txin = script_path_txin(commit_pubin_txin, &connector_e.generate_taproot_leaf_script(0))?;
    connector_e
        .extract_leaf_0_raw_witness(&txin)
        .map_err(|e| anyhow::anyhow!("failed to extract operator commit pubin witness: {e}"))
}

pub fn extract_operator_assert_witness(
    graph: &BitvmGcGraph,
    operator_assert_txin: &TxIn,
) -> Result<TxAssertWitness> {
    let operator_assertion = operator_assert_raw_witness(graph, operator_assert_txin)?;
    let (operator_assertion, pi2, pi3) =
        split_operator_assert_wots_and_extra_data(operator_assertion)?;

    let wots_sig = operator_assert_wots_signature(&operator_assertion)?;
    validate_operator_assert_extra_data(&pi2, &pi3)?;
    let assert_witness = TxAssertWitness { wots_sig, pi2, pi3 };
    if assert_witness.recover_pi2_pi3().is_none() {
        bail!("operator assert extra-data cannot recover pi2 and pi3");
    }
    Ok(assert_witness)
}

pub fn extract_operator_assert_witness_for_challenge(
    graph: &BitvmGcGraph,
    operator_assert_txin: &TxIn,
) -> Result<TxAssertWitness> {
    let operator_assertion = operator_assert_raw_witness(graph, operator_assert_txin)?;
    let (operator_assertion, pi2, pi3) =
        split_operator_assert_wots_and_extra_data(operator_assertion)?;
    let wots_sig = operator_assert_wots_signature(&operator_assertion)?;
    let (pi2, pi3) = if validate_operator_assert_extra_data(&pi2, &pi3).is_ok() {
        (pi2, pi3)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(TxAssertWitness { wots_sig, pi2, pi3 })
}

pub fn build_verifier_assert_tx(
    graph: &BitvmGcGraph,
    operator_assert_txin: TxIn,
    verifier_index: usize,
    labels: [Label; INPUT_WIRE_NUM],
) -> Result<Transaction> {
    if verifier_index >= graph.verifier_asserts.len() {
        bail!("invalid verifier index {verifier_index}")
    };

    let operator_assertion = operator_assert_raw_witness(graph, &operator_assert_txin)?;
    let (operator_assertion, _pi2, _pi3) =
        split_operator_assert_wots_and_extra_data(operator_assertion)?;

    let verifier_connector = graph.verifier_connector(verifier_index)?;
    let mut verifier_assert = graph.verifier_asserts[verifier_index].clone();
    verifier_assert
        .verifier_publish_labels(&verifier_connector, labels, &operator_assertion)
        .map_err(|e| anyhow::anyhow!("failed to build verifier assert: {e}"))?;
    Ok(verifier_assert.tx().clone())
}

pub fn build_disprove_tx(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    verifier_receive_address: Option<[u8; 20]>,
) -> Result<Transaction> {
    if verifier_index >= graph.disproves.len() {
        bail!("invalid verifier index {verifier_index}")
    };
    if !graph.committee_pre_signed {
        bail!("missing pre-signatures from committee")
    };
    let mut disprove_tx = graph.disproves[verifier_index].tx().clone();
    if let Some(verifier_receive_address) = verifier_receive_address {
        disprove_tx.output.insert(
            0,
            TxOut {
                value: Amount::ZERO,
                script_pubkey: generate_opreturn_script(verifier_receive_address.to_vec()),
            },
        );
    }
    Ok(disprove_tx)
}

pub fn validate_pubin_disprove(
    graph: &BitvmGcGraph,
    operator_commit_pubin_txin: &TxIn,
    operator_assert_txin: &TxIn,
    operator_ack_txins: &[TxIn],
) -> Result<Option<(RawWitness, ScriptBuf)>> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let mut ack_preimages = vec![vec![]; watchtower_num];
    for txin in operator_ack_txins {
        let vout = txin.previous_output.vout as usize;
        if vout % 2 != 1 {
            bail!("invalid ack txin in operator_ack_txins, unexpected vout: {vout}");
        }
        let watchtower_index = vout / 2;
        if watchtower_index >= watchtower_num
            || vout != output_topology::watchtower_challenge_init::ack_connector(watchtower_index)
        {
            bail!("invalid ack txin in operator_ack_txins, unexpected vout: {vout}");
        }
        let preimage = extract_operator_preimage_from_ack_txin(txin)
            .map_err(|e| anyhow::anyhow!("failed to extract preimage from ack txin: {e}"))?;
        ack_preimages[watchtower_index] = preimage;
    }

    let operator_commit_pubin_witness =
        operator_commit_pubin_raw_witness(graph, operator_commit_pubin_txin)?;
    let operator_assert_witness = operator_assert_raw_witness(graph, operator_assert_txin)?;
    let (operator_assert_witness, _pi2, _pi3) =
        split_operator_assert_wots_and_extra_data(operator_assert_witness)?;
    let connector_d = graph.connector_d();
    let input_lock_script =
        connector_d.generate_taproot_leaf_script(CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX);

    Ok(validate_pubin(
        operator_commit_pubin_witness,
        operator_assert_witness,
        ack_preimages,
        input_lock_script,
    ))
}

pub fn build_pubin_disprove_txin(
    graph: &BitvmGcGraph,
    input_script_witness: RawWitness,
) -> Result<TxIn> {
    let connector_d = graph.connector_d();
    let connector_d_input = graph
        .operator_assert
        .connector_d_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-d input: {e}"))?;
    pubin_disprove(&connector_d, &connector_d_input, input_script_witness)
        .map_err(|e| anyhow::anyhow!("failed to build pubin-disprove txin: {e}"))
}

pub fn disprove_timelock(network: Network) -> u32 {
    disprove_timelock_with_config(network, &default_timelock_config(network))
}

pub fn disprove_timelock_with_config(network: Network, timelock_config: &TimelockConfig) -> u32 {
    disprove_timelock_blocks(network, timelock_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        OutPoint, TxOut, XOnlyPublicKey,
        secp256k1::{Keypair, SECP256K1, SecretKey},
    };
    use goat::{
        connectors::{
            base::TaprootConnector,
            connector_d::{CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX, ConnectorD},
        },
        scripts::{generate_opreturn_script, p2a_output},
        transactions::base::{Input, pubin_disprove_input_amount},
    };

    #[test]
    fn script_path_txin_drops_annex_and_checks_leaf_script() {
        let leaf_script = ScriptBuf::from_bytes(vec![0x51]);
        let data = vec![vec![1u8; 20], vec![2u8]];
        let txin_with = |extra: &[Vec<u8>]| {
            let mut items = data.clone();
            items.extend_from_slice(extra);
            TxIn { witness: Witness::from_slice(&items), ..Default::default() }
        };
        let expected = txin_with(&[leaf_script.to_bytes(), vec![0xc0; 33]]);

        assert_eq!(script_path_txin(&expected, &leaf_script).unwrap(), expected);
        let annexed = txin_with(&[leaf_script.to_bytes(), vec![0xc0; 33], vec![0x50, 0xaa]]);
        assert_eq!(script_path_txin(&annexed, &leaf_script).unwrap(), expected);

        let other_leaf = txin_with(&[vec![0x52], vec![0xc0; 33]]);
        assert!(script_path_txin(&other_leaf, &leaf_script).is_err());
        let too_short =
            TxIn { witness: Witness::from_slice(&[vec![0xc0; 33]]), ..Default::default() };
        assert!(script_path_txin(&too_short, &leaf_script).is_err());
    }

    #[test]
    fn honest_commit_pubin_witness_extracts_with_or_without_annex() {
        use goat::{
            connectors::connector_e::ConnectorE,
            transactions::watchtower_challenge::operator_commit_pubin,
        };

        let committee_secret = SecretKey::from_slice(&[2; 32]).expect("valid committee secret");
        let committee_keypair = Keypair::from_secret_key(SECP256K1, &committee_secret);
        let committee_key =
            XOnlyPublicKey::from(bitcoin::PublicKey::from(committee_keypair.public_key()));
        let wots_secret = Wots96::generate_secret_key();
        let wots_public_key = Wots96::generate_public_key(&wots_secret);
        let connector_e = ConnectorE::new(
            Network::Testnet4,
            &committee_key,
            &wots_public_key,
            &default_timelock_config(Network::Testnet4),
        );
        let input = Input { outpoint: OutPoint::null(), amount: Amount::from_sat(1_000) };
        let mut txin = operator_commit_pubin(&connector_e, &[0x11; 96], &wots_secret, input)
            .expect("honest commit-pubin");
        let leaf_script = connector_e.generate_taproot_leaf_script(0);

        let plain = script_path_txin(&txin, &leaf_script).expect("honest witness");
        assert_eq!(connector_e.extract_leaf_0_raw_witness(&plain).unwrap().len(), PROVER_SIG_LEN);

        txin.witness.push([0x50]);
        assert!(connector_e.extract_leaf_0_raw_witness(&txin).is_err());
        assert_eq!(script_path_txin(&txin, &leaf_script).unwrap(), plain);
    }

    #[test]
    fn pubin_disprove_with_witness_is_standard_sized() {
        let operator_secret = SecretKey::from_slice(&[1; 32]).expect("valid operator secret");
        let committee_secret = SecretKey::from_slice(&[2; 32]).expect("valid committee secret");
        let operator_keypair = Keypair::from_secret_key(SECP256K1, &operator_secret);
        let committee_keypair = Keypair::from_secret_key(SECP256K1, &committee_secret);
        let operator_key =
            XOnlyPublicKey::from(bitcoin::PublicKey::from(operator_keypair.public_key()));
        let committee_key =
            XOnlyPublicKey::from(bitcoin::PublicKey::from(committee_keypair.public_key()));

        let guest_secret = Wots96::generate_secret_key();
        let guest_public_key = Wots96::generate_public_key(&guest_secret);
        let assert_secret = Wots96::generate_secret_key();
        let assert_public_key = Wots96::generate_public_key(&assert_secret);
        let expected_constant = [0x22; 32];
        let mut guest_pubin = [0u8; 96];
        guest_pubin[..32].fill(0x11);
        guest_pubin[32..64].fill(0x23);
        guest_pubin[64..].fill(0xff);
        let operator_assert_pubin = [0u8; 96];

        let connector_d = ConnectorD::new(
            Network::Testnet4,
            &operator_key,
            &committee_key,
            &guest_public_key,
            &assert_public_key,
            &expected_constant,
            &[],
            &default_timelock_config(Network::Testnet4),
        );
        let assert_witness =
            Wots96::sign_to_raw_witness(&assert_secret, &operator_assert_pubin).to_vec();
        let guest_witness = Wots96::sign_to_raw_witness(&guest_secret, &guest_pubin).to_vec();
        assert!(
            validate_pubin(
                guest_witness.clone(),
                assert_witness.clone(),
                vec![],
                connector_d.generate_taproot_leaf_script(CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX),
            )
            .is_some(),
            "locally constructed pubin-disprove witness must satisfy Connector-D",
        );
        let mut witness = assert_witness;
        witness.extend(guest_witness);
        let input = pubin_disprove(
            &connector_d,
            &Input {
                outpoint: OutPoint::null(),
                amount: Amount::from_sat(pubin_disprove_input_amount()),
            },
            witness,
        )
        .expect("build pubin-disprove input");
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![
                p2a_output(),
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: generate_opreturn_script(b"pubin-disprove".to_vec()),
                },
            ],
        };

        let base_size = tx.base_size();
        let witness_size = tx.input[0].witness.size();
        let total_size = tx.total_size();
        println!(
            "pubin-disprove tx sizes: base_size={base_size}, witness_size={witness_size}, total_size={total_size}"
        );
        assert_eq!(
            total_size,
            base_size + witness_size + 2,
            "pubin-disprove total size must include the SegWit marker/flag and script witness: total={total_size}, base={base_size}, witness={witness_size}",
        );
        assert!(
            tx.weight() <= Transaction::MAX_STANDARD_WEIGHT,
            "pubin-disprove exceeds Bitcoin Core's standard transaction limit: weight={}, total_size={total_size}",
            tx.weight().to_wu(),
        );
    }
}
