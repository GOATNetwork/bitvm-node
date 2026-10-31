use std::{collections::HashSet, error::Error};

use bitcoin::blockdata::{opcodes::all::*, script::Builder};
use bitcoin::{Amount, CompressedPublicKey, Network, ScriptBuf, Transaction, TxOut, Witness};

use bitcoin::secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature as EcdsaSignature,
};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

/// Validates a Publisher key set before it is committed into a P2WSH multisig script.
pub fn validate_publisher_set(public_keys: &[PublicKey], threshold: usize) -> Result<(), String> {
    let total = public_keys.len();
    println!("Multi sig: {threshold} of {total}");

    if public_keys.is_empty() || total > 20 || threshold == 0 || threshold > total {
        return Err(format!(
            "Invalid Publisher set: public key count {total}, threshold {threshold}; expected 1 to 20 public keys and a threshold between 1 and the public key count",
        ));
    }

    let mut unique_keys = HashSet::with_capacity(total);
    for public_key in public_keys {
        if !unique_keys.insert(public_key.serialize()) {
            return Err(format!("Duplicate Publisher public key: {public_key}"));
        }
    }

    Ok(())
}

pub fn create_sequencer_update_script(public_keys: &[PublicKey], threshold: usize) -> ScriptBuf {
    validate_publisher_set(public_keys, threshold)
        .unwrap_or_else(|error| panic!("Invalid Publisher set: {error}"));

    let mut redeem_script = Builder::new().push_int(threshold as i64);
    for pk in public_keys {
        redeem_script = redeem_script.push_slice(pk.serialize());
    }
    redeem_script.push_int(public_keys.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script()
}

pub fn sign_partial(
    tx: &mut Transaction,
    seckey: &SecretKey,
    redeem_script: &ScriptBuf,
    amount: Amount,
    sig_hash_type: EcdsaSighashType,
) -> Result<(Vec<u8>, bitcoin::secp256k1::Message), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache.p2wsh_signature_hash(0, redeem_script, amount, sig_hash_type)?;
    let msg = Message::from_digest_slice(&sighash[..])?;
    let mut sig = secp.sign_ecdsa(&msg, seckey).serialize_der().to_vec();
    sig.push(sig_hash_type as u8);
    Ok((sig, msg))
}

pub fn sign_raw(
    tx: &mut Transaction,
    seckey: &SecretKey,
    redeem_script: &ScriptBuf,
    amount: Amount,
    sig_hash_type: EcdsaSighashType,
) -> Result<([u8; 64], bitcoin::secp256k1::Message), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx);
    let sighash = cache.p2wsh_signature_hash(0, redeem_script, amount, sig_hash_type)?;
    let msg = Message::from_digest_slice(&sighash[..])?;
    let sig = secp.sign_ecdsa(&msg, seckey).serialize_compact();
    Ok((sig, msg))
}

pub fn finalize(
    tx: &mut Transaction,
    sigs: Vec<Vec<u8>>,
    redeem_script: &ScriptBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtns = vec![vec![]];
    for sig in &sigs {
        wtns.push(sig.clone());
    }
    wtns.push(redeem_script.to_bytes()); // the redeem script itself
    tx.input[0].witness = Witness::from(wtns);
    Ok(())
}

/// Verify P2WSH multisig witness (CHECKMULTISIG behavior).
/// - `tx` is the spending transaction
/// - `input_index` is the input to verify
/// - `prevout` is the TxOut being spent (needed for amount + script_pubkey)
/// - `redeem_script` is the script that must equal the last witness element
/// - `pubkeys` is the n pubkeys in the redeem script in script order
/// - `threshold` is m (required signatures)
pub fn verify_p2wsh_multisig_witness(
    tx: &Transaction,
    input_index: usize,
    prevout: &TxOut,
    redeem_script: &ScriptBuf,
    pubkeys: &[PublicKey],
    threshold: usize,
) -> Result<bool, Box<dyn Error>> {
    // Basic checks
    let secp = Secp256k1::verification_only();
    let txin = &tx.input[input_index];
    let witness: &Witness = &txin.witness;
    let expected_script_pubkey = ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());

    if prevout.script_pubkey != expected_script_pubkey {
        return Err("prevout script_pubkey does not match redeem_script".into());
    }

    // Expect witness: [<empty>, sig1, sig2, ..., redeem_script_bytes]
    if witness.len() < 2 {
        return Err("witness too short".into());
    }

    // Last stack item must equal redeem_script
    let last: &[u8] = &witness[witness.len() - 1];
    if last != redeem_script.as_bytes() {
        return Err("redeem_script mismatch with witness last element".into());
    }

    // Extract signatures (skip first dummy element, skip last redeem_script)
    let raw_sigs: Vec<&[u8]> = witness
        .iter()
        .skip(1)
        .take(witness.len() - 2) // exclude last (redeem_script)
        .collect();

    if raw_sigs.is_empty() {
        return Ok(false); // no signatures provided
    }

    // Parse each signature: DER (r,s) + 1-byte sighash flag.
    // We'll keep a vec of (sig, sighash_flag) for verification.
    let mut parsed_sigs: Vec<(EcdsaSignature, EcdsaSighashType)> =
        Vec::with_capacity(raw_sigs.len());
    for (i, raw) in raw_sigs.iter().enumerate() {
        if raw.is_empty() {
            return Err(format!("signature[{i}] too short").into());
        }
        let flag = raw[raw.len() - 1];
        let sighash_ty = EcdsaSighashType::from_consensus(flag as u32);
        let der = &raw[..raw.len() - 1];
        let sig = EcdsaSignature::from_der(der)
            .map_err(|e| format!("invalid DER signature at index {i}: {e:?}"))?;
        parsed_sigs.push((sig, sighash_ty));
    }

    // We'll need to compute sighash per signature (it depends on sighash flag).
    // Use a SighashCache on the tx. For P2WSH we call p2wsh_signature_hash.
    let mut cache = SighashCache::new(tx);

    // Now implement CHECKMULTISIG matching:
    // iterate pubkeys in order, and try to match the *current* signature.
    let mut sig_idx = 0usize;
    let mut matched = 0usize;

    for pk in pubkeys.iter() {
        if sig_idx >= parsed_sigs.len() {
            break; // no more signatures to match
        }

        // For the current signature, compute the sighash according to its flag.
        let (ref sig, sighash_ty) = parsed_sigs[sig_idx];

        // Compute the p2wsh sighash for this signature (signature's own sighash type)
        let sighash =
            cache.p2wsh_signature_hash(input_index, redeem_script, prevout.value, sighash_ty)?;

        let msg = Message::from_digest_slice(&sighash[..])
            .map_err(|e| format!("bad message from sighash: {e:?}"))?;

        // Try verify current signature against this pubkey
        match secp.verify_ecdsa(&msg, sig, pk) {
            Ok(_) => {
                // matched: consume this signature and advance
                matched += 1;
                sig_idx += 1;
                if matched >= threshold {
                    break;
                }
            }
            Err(_) => {
                // no match: try next pubkey (do NOT advance sig_idx)
                continue;
            }
        }
    }

    Ok(matched >= threshold)
}

pub fn create_dummy_publisher_keys(total: usize, network: Network) -> Vec<(SecretKey, PublicKey)> {
    let secp = Secp256k1::new();

    let mut keys = Vec::new();

    for i in 0..total {
        let sk = SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        keys.push((sk, pk));
    }
    println!("Publisher private key:");
    keys.iter().for_each(|(sk, _)| {
        let k = bitcoin::PrivateKey { compressed: true, network: network.into(), inner: *sk };
        println!("{:?}\n", k.to_wif())
    });
    println!("Publisher public key:");
    keys.iter().for_each(|(_, pk)| println!("{}\n", CompressedPublicKey(*pk)));
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Address, EcdsaSighashType, Network, OutPoint, Sequence, TxIn, absolute::LockTime,
        hashes::Hash, transaction::Version,
    };

    #[test]
    fn test_verify_p2wsh_multisig_witness() {
        // === Step 1: generate key pairs ===
        let keys = create_dummy_publisher_keys(3, bitcoin::Network::Regtest);
        let pubkeys: Vec<PublicKey> = keys.iter().map(|(_, pk)| *pk).collect();

        let threshold = 2;

        // === Step 2: create redeem_script ===
        let redeem_script = create_sequencer_update_script(&pubkeys, threshold);

        // === Step 3: create prevout (P2WSH output) ===
        let script_pubkey = ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());
        let prev_value = Amount::from_sat(100_000);
        let prevout = TxOut { value: prev_value, script_pubkey };

        // Fake OutPoint
        let prev_outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([0u8; 32]), vout: 0 };

        // === Step 4: construct spending tx ===
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: {
                    let btc_pk0 = bitcoin::PublicKey::from(pubkeys[0]);
                    Address::p2pkh(btc_pk0, Network::Testnet).script_pubkey()
                },
            }],
        };

        // === Step 5: sign by 2 private keys ===
        let (sig1, _) =
            sign_partial(&mut tx, &keys[0].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();

        let (sig2, _) =
            sign_partial(&mut tx, &keys[1].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();

        // === Step 6: finalize witness ===
        finalize(&mut tx, vec![sig1, sig2], &redeem_script).unwrap();

        // === Step 7: verify ===
        let ok =
            verify_p2wsh_multisig_witness(&tx, 0, &prevout, &redeem_script, &pubkeys, threshold)
                .unwrap();

        assert!(ok, "2-of-3 multisig witness should verify");
    }

    #[test]
    fn test_verify_p2wsh_multisig_witness_rejects_prevout_script_mismatch() {
        let keys = create_dummy_publisher_keys(3, bitcoin::Network::Regtest);
        let pubkeys: Vec<PublicKey> = keys.iter().map(|(_, pk)| *pk).collect();
        let threshold = 2;
        let redeem_script = create_sequencer_update_script(&pubkeys, threshold);
        let prev_value = Amount::from_sat(100_000);
        let prevout = TxOut {
            value: prev_value,
            script_pubkey: ScriptBuf::new_p2wsh(&ScriptBuf::new().wscript_hash()),
        };
        let prev_outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([0u8; 32]), vout: 0 };

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: {
                    let btc_pk0 = bitcoin::PublicKey::from(pubkeys[0]);
                    Address::p2pkh(btc_pk0, Network::Testnet).script_pubkey()
                },
            }],
        };

        let (sig1, _) =
            sign_partial(&mut tx, &keys[0].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();
        let (sig2, _) =
            sign_partial(&mut tx, &keys[1].0, &redeem_script, prev_value, EcdsaSighashType::All)
                .unwrap();
        finalize(&mut tx, vec![sig1, sig2], &redeem_script).unwrap();

        assert!(
            verify_p2wsh_multisig_witness(&tx, 0, &prevout, &redeem_script, &pubkeys, threshold,)
                .is_err()
        );
    }
}
