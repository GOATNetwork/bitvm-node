pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Header, LightBlock, ValidatorSet},
};

use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut,
    key::Keypair,
    secp256k1::{Message as EcdsaMessage, Secp256k1, XOnlyPublicKey},
    sighash::{Annex, Prevouts, SighashCache, TapSighashType},
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
    prev_outs: &[TxOut],
    pubkey: &XOnlyPublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if prev_outs.len() != spending_tx.input.len() {
        return Err("Prevout count does not match input count".into());
    }
    let input = spending_tx.input.get(input_index).ok_or("Invalid input index")?;
    let prev_out = prev_outs.get(input_index).ok_or("Missing input prevout")?;
    let mut stack = input.witness.iter().collect::<Vec<_>>();
    let annex = if stack.len() >= 2 && stack.last().is_some_and(|item| item.first() == Some(&0x50))
    {
        Some(Annex::new(stack.pop().unwrap())?)
    } else {
        None
    };
    // The supported script is <watchtower key> OP_CHECKSIG, with one stack argument.
    if stack.len() != 3 {
        return Err("Invalid Taproot script-path witness".into());
    }
    let signature_bytes = stack[0];
    // BIP341 encodes SIGHASH_DEFAULT only as a 64-byte signature.
    if signature_bytes.len() == 65 && signature_bytes[64] == 0 {
        return Err("Explicit SIGHASH_DEFAULT byte is invalid".into());
    }
    let sig = TaprootSignature::from_slice(signature_bytes)?;
    if stack[1] != script.as_bytes() {
        return Err("Taproot witness script mismatch".into());
    }
    let control_block = ControlBlock::decode(stack[2])?;
    if control_block.leaf_version != LeafVersion::TapScript {
        return Err("Unsupported Taproot leaf version".into());
    }
    let secp = Secp256k1::verification_only();
    let script_pubkey = prev_out.script_pubkey.as_bytes();
    if script_pubkey.len() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
        return Err("Prevout is not P2TR".into());
    }
    let output_key = XOnlyPublicKey::from_slice(&script_pubkey[2..])?;
    if !control_block.verify_taproot_commitment(&secp, output_key, script) {
        return Err("Taproot control block does not commit to the witness script".into());
    }

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = SighashCache::new(spending_tx).taproot_signature_hash(
        input_index,
        &Prevouts::All(prev_outs),
        annex,
        Some((leaf_hash, u32::MAX)),
        sig.sighash_type,
    )?;
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

    fn signed_challenge(
        input_index: usize,
        sighash_type: TapSighashType,
        annex: Option<&[u8]>,
    ) -> (Transaction, Vec<TxOut>, ScriptBuf, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[7; 32]).unwrap();
        let (key, _) = keypair.x_only_public_key();
        let script = Builder::new()
            .push_x_only_key(&key)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let tree = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, key)
            .unwrap();
        let prev_outs = vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: bitcoin::Address::p2tr_tweaked(
                    tree.output_key(),
                    bitcoin::Network::Regtest
                )
                .script_pubkey(),
            };
            3
        ];
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..3)
                .map(|index| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([index as u8 + 1; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                })
                .collect(),
            output: vec![
                TxOut { value: Amount::from_sat(40_000), script_pubkey: ScriptBuf::new() };
                3
            ],
        };
        let hash = SighashCache::new(&tx)
            .taproot_signature_hash(
                input_index,
                &Prevouts::All(&prev_outs),
                annex.map(|bytes| Annex::new(bytes).unwrap()),
                Some((TapLeafHash::from_script(&script, LeafVersion::TapScript), u32::MAX)),
                sighash_type,
            )
            .unwrap();
        let signature = TaprootSignature {
            signature: secp.sign_schnorr_no_aux_rand(&EcdsaMessage::from(hash), &keypair),
            sighash_type,
        };
        let mut witness = vec![
            signature.to_vec(),
            script.to_bytes(),
            tree.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap().serialize(),
        ];
        if let Some(annex) = annex {
            witness.push(annex.to_vec());
        }
        tx.input[input_index].witness = Witness::from(witness);
        (tx, prev_outs, script, key)
    }

    #[test]
    fn verifies_all_sighash_types_at_each_input_with_or_without_annex() {
        for sighash_type in [
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            for index in 0..3 {
                for annex in [None, Some(&[0x50, 1, 2][..])] {
                    let (tx, prevouts, script, key) = signed_challenge(index, sighash_type, annex);
                    verify_taproot_leaf_schnorr_signature(&script, &tx, index, &prevouts, &key)
                        .unwrap_or_else(|error| {
                            panic!("{sighash_type:?}, input {index}, annex {annex:?}: {error}")
                        });
                }
            }
        }
    }

    #[test]
    fn anyonecanpay_challenge_survives_an_inserted_fee_input() {
        let (mut tx, mut prevouts, script, key) =
            signed_challenge(0, TapSighashType::AllPlusAnyoneCanPay, None);
        tx.input.insert(
            0,
            TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([99; 32]), vout: 1 },
                ..Default::default()
            },
        );
        prevouts
            .insert(0, TxOut { value: Amount::from_sat(10_000), script_pubkey: ScriptBuf::new() });
        verify_taproot_leaf_schnorr_signature(&script, &tx, 1, &prevouts, &key).unwrap();
    }

    #[test]
    fn rejects_tampered_sighash_evidence_and_witness() {
        let (tx, prevouts, script, key) =
            signed_challenge(1, TapSighashType::Default, Some(&[0x50, 1]));
        let verify = |tx: &Transaction, prevouts: &[TxOut]| {
            verify_taproot_leaf_schnorr_signature(&script, tx, 1, prevouts, &key).is_err()
        };
        let mut wrong_prevouts = prevouts.clone();
        wrong_prevouts[0].value += Amount::from_sat(1);
        assert!(verify(&tx, &wrong_prevouts));
        assert!(verify(&tx, &prevouts[..2]));
        // Tamper independently with signature, script, control block and annex.
        for element in 0..4 {
            let mut tampered = tx.clone();
            let mut witness = tx.input[1].witness.to_vec();
            witness[element][0] ^= 1;
            tampered.input[1].witness = Witness::from(witness);
            assert!(verify(&tampered, &prevouts), "witness element {element}");
        }
        let mut explicit_default = tx.clone();
        let mut witness = tx.input[1].witness.to_vec();
        witness[0].push(0);
        explicit_default.input[1].witness = Witness::from(witness);
        assert!(verify(&explicit_default, &prevouts));
        assert!(verify_taproot_leaf_schnorr_signature(&script, &tx, 3, &prevouts, &key).is_err());
    }

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
        verify_taproot_leaf_schnorr_signature(
            &script,
            &spending_tx,
            0,
            std::slice::from_ref(&prev_out),
            &internal_xonly,
        )
        .unwrap();
        let mut wrong_prevout = prev_out.clone();
        wrong_prevout.script_pubkey = ScriptBuf::new();
        assert!(
            verify_taproot_leaf_schnorr_signature(
                &script,
                &spending_tx,
                0,
                std::slice::from_ref(&wrong_prevout),
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
                std::slice::from_ref(&prev_out),
                &internal_xonly,
            )
            .is_err()
        );

        println!("Final spending tx hex = {}", hex::encode(serialize(&spending_tx)));
    }
}
