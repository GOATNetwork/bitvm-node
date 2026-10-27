pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Header, LightBlock, ValidatorSet},
};

use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut,
    key::Keypair,
    secp256k1::{Message as EcdsaMessage, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature, TapLeafHash},
};

/// Generate Taproot script-path's Schnorr signature
#[allow(dead_code)]
fn generate_taproot_leaf_schnorr_signature(
    tx: &mut Transaction,
    prev_outs: &[TxOut],
    input_index: usize,
    sighash_type: TapSighashType,
    script: &Script,
    keypair: &Keypair,
) -> TaprootSignature {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let secp = Secp256k1::new();

    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prev_outs),
            leaf_hash,
            sighash_type,
        )
        .expect("Failed to construct sighash");

    let msg = EcdsaMessage::from(sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);

    TaprootSignature { signature: sig, sighash_type }
}

/// Verifies the Taproot script-path witness and Schnorr signature for one transaction input.
pub fn verify_taproot_leaf_schnorr_signature(
    script: &ScriptBuf,
    spending_tx: &Transaction,
    input_index: usize,
    prev_out: &TxOut,
    pubkey: &XOnlyPublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = spending_tx.input.get(input_index).ok_or("Invalid input index")?;
    let sig = input.witness.iter().next().ok_or("Missing Taproot signature").and_then(|bytes| {
        TaprootSignature::from_slice(bytes).map_err(|_| "Invalid Taproot signature")
    })?;
    if sig.sighash_type != TapSighashType::AllPlusAnyoneCanPay {
        return Err("Invalid sig type".into());
    }
    let secp = Secp256k1::verification_only();
    let witness_len = input.witness.len();
    if witness_len < 3 {
        return Err("Invalid Taproot script-path witness".into());
    }
    let witness_script =
        input.witness.iter().nth(witness_len - 2).ok_or("Missing Taproot witness script")?;
    if witness_script != script.as_bytes() {
        return Err("Taproot witness script mismatch".into());
    }
    let control_block = ControlBlock::decode(
        input.witness.iter().nth(witness_len - 1).ok_or("Missing Taproot control block")?,
    )?;
    let script_pubkey = prev_out.script_pubkey.as_bytes();
    if script_pubkey.len() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
        return Err("Prevout is not P2TR".into());
    }
    let output_key = XOnlyPublicKey::from_slice(&script_pubkey[2..])?;
    if !control_block.verify_taproot_commitment(&secp, output_key, script) {
        return Err("Taproot control block does not commit to the witness script".into());
    }

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = match SighashCache::new(spending_tx).taproot_script_spend_signature_hash(
        input_index,
        &Prevouts::One(input_index, prev_out.clone()),
        leaf_hash,
        TapSighashType::AllPlusAnyoneCanPay,
    ) {
        Ok(sighash) => sighash,
        _ => return Err("Invalid sig hash".into()),
    };
    let msg = EcdsaMessage::from(sighash);

    Ok(secp.verify_schnorr(&sig.signature, &msg, pubkey)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        blockdata::script::Builder,
        consensus::encode::serialize,
        key::Keypair,
        secp256k1::{Secp256k1, XOnlyPublicKey},
        sighash::TapSighashType,
        taproot::{LeafVersion, TaprootBuilder},
    };
    use bitcoin::{ScriptBuf, hashes::Hash};
    use rand::rngs::OsRng;

    #[test]
    fn test_taproot_script_path_end_to_end_with_verification() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut OsRng);
        let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

        // 2. Create Tapscript: <pubkey> OP_CHECKSIG
        let script = Builder::new()
            .push_x_only_key(&internal_xonly)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script();

        // 3. Construct Taproot (script path)
        let builder = TaprootBuilder::new().add_leaf(0, script.clone()).expect("taproot builder");
        let taproot_info = builder.finalize(&secp, internal_xonly).expect("finalize taproot");
        let output_key = taproot_info.output_key();

        // 4. Construct prevout (UTXO)
        let prev_txid = Txid::from_byte_array([1u8; 32]); // fake txid
        let prev_vout = 0;
        let prev_value = Amount::from_sat(50_000);

        let prev_out = TxOut {
            value: prev_value,
            script_pubkey: bitcoin::Address::p2tr_tweaked(output_key, bitcoin::Network::Testnet)
                .script_pubkey(),
        };

        // 5. Create the spending txn
        let mut spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: prev_vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_op_return([0x6a]),
            }],
        };

        // 6. Generate Schnorr signature
        let sig = generate_taproot_leaf_schnorr_signature(
            &mut spending_tx,
            std::slice::from_ref(&prev_out),
            0,
            TapSighashType::AllPlusAnyoneCanPay,
            &script,
            &keypair,
        );

        // 7. Construct control block + witness
        let control_block = taproot_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block");

        spending_tx.input[0].witness = Witness::from(vec![
            sig.to_vec(),
            script.clone().into_bytes(),
            control_block.serialize(),
        ]);

        // 8. Verify the signature and Taproot script commitment.
        verify_taproot_leaf_schnorr_signature(&script, &spending_tx, 0, &prev_out, &internal_xonly)
            .unwrap();
        let mut wrong_prevout = prev_out.clone();
        wrong_prevout.script_pubkey = ScriptBuf::new();
        assert!(
            verify_taproot_leaf_schnorr_signature(
                &script,
                &spending_tx,
                0,
                &wrong_prevout,
                &internal_xonly,
            )
            .is_err()
        );
        let mut missing_signature = spending_tx.clone();
        missing_signature.input[0].witness = Witness::new();
        assert!(
            verify_taproot_leaf_schnorr_signature(
                &script,
                &missing_signature,
                0,
                &prev_out,
                &internal_xonly,
            )
            .is_err()
        );

        println!("Final spending tx hex = {}", hex::encode(serialize(&spending_tx)));
    }
}
