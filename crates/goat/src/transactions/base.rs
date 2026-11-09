use super::pre_signed_musig2::{verify_public_nonce, PreSignedMusig2Transaction};
use crate::error::Error;
use bitcoin::policy::{DEFAULT_MIN_RELAY_TX_FEE, DUST_RELAY_TX_FEE};
use bitcoin::{consensus, Amount, OutPoint, PublicKey, Script, Transaction, Txid, XOnlyPublicKey};
use core::cmp;
use itertools::Itertools;
use musig2::{secp256k1::schnorr::Signature, PubNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DUST_AMOUNT: u64 = (43 + 67) * DUST_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_RATE: u64 = (DEFAULT_MIN_RELAY_TX_FEE / 1000) as u64;
pub const DUST_RELAY_FEE_RATE: u64 = (DUST_RELAY_TX_FEE / 1000) as u64;

pub const fn max(a: u64, b: u64) -> u64 {
    [a, b][(a < b) as usize]
}

// TBD: accurately calculate the relay fee
pub const RELAY_FEE_BUFFER_MULTIPLIER: f32 = 1.2;
pub const ACCELERATE_FEE_MULTIPLIER: u64 = 2;
pub const MIN_RELAY_FEE_KICKOFF: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_TAKE_1: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_TAKE_2: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_VERIFIER_ASSERT: u64 = relay_fee(60000);
pub const MIN_RELAY_FEE_WRONGLY_CHALLENGED: u64 = relay_fee(1500);
pub const MIN_RELAY_FEE_DISPROVE: u64 = relay_fee(800);
pub const MIN_RELAY_FEE_PUBIN_DISPROVE: u64 = relay_fee(800);
pub const MIN_RELAY_FEE_WATCHTOWER_CHALLENGE_TIMEOUT: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_OPERATOR_CHALLENGE_ACK: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_OPERATOR_CHALLENGE_NACK: u64 = relay_fee(800);
pub const MIN_RELAY_FEE_OPERATOR_COMMIT_PUBIN: u64 = relay_fee(500);
pub const MIN_RELAY_FEE_OPERATOR_COMMIT_TIMEOUT: u64 = relay_fee(800);
pub const P2A_AMOUNT: u64 = 240;
pub const fn min_relay_fee_watchtower_challenge_init(watchtower_num: usize) -> u64 {
    relay_fee(watchtower_num * 200 + 400)
}
pub const fn min_relay_fee_operator_assert(num_verifier: usize) -> u64 {
    relay_fee(num_verifier * 100 + 15000)
}
pub const fn wrongly_challenged_input_amount() -> u64 {
    MIN_RELAY_FEE_WRONGLY_CHALLENGED + P2A_AMOUNT
}
pub const fn verifier_assert_prover_output_amount() -> u64 {
    max(DUST_AMOUNT, wrongly_challenged_input_amount())
}
pub const fn verifier_assert_input_amount() -> u64 {
    MIN_RELAY_FEE_VERIFIER_ASSERT + verifier_assert_prover_output_amount() + P2A_AMOUNT
}
pub const fn disprove_input_amount() -> u64 {
    MIN_RELAY_FEE_DISPROVE + P2A_AMOUNT
}
pub const fn pubin_disprove_input_amount() -> u64 {
    MIN_RELAY_FEE_PUBIN_DISPROVE + P2A_AMOUNT
}
pub const fn watchtower_challenge_timeout_input_amount() -> u64 {
    MIN_RELAY_FEE_WATCHTOWER_CHALLENGE_TIMEOUT + P2A_AMOUNT
}
pub const fn operator_challenge_nack_input_amount() -> u64 {
    MIN_RELAY_FEE_OPERATOR_CHALLENGE_NACK + P2A_AMOUNT
}
pub const fn operator_commit_timeout_input_amount() -> u64 {
    MIN_RELAY_FEE_OPERATOR_COMMIT_TIMEOUT + P2A_AMOUNT
}
pub const fn watchtower_challenge_connector_output_amount() -> u64 {
    max(
        DUST_AMOUNT,
        watchtower_challenge_timeout_input_amount().saturating_sub(ack_connector_output_amount()),
    )
}
pub const fn ack_connector_output_amount() -> u64 {
    DUST_AMOUNT
}
pub const fn connector_e_output_amount() -> u64 {
    DUST_AMOUNT
}
pub const fn connector_f_output_amount() -> u64 {
    max(
        DUST_AMOUNT,
        max(
            operator_challenge_nack_input_amount().saturating_sub(ack_connector_output_amount()),
            operator_commit_timeout_input_amount().saturating_sub(connector_e_output_amount()),
        ),
    )
}
pub const fn connector_d_assert_output_amount() -> u64 {
    let disprove_connector_d_amount =
        if disprove_input_amount() > verifier_assert_prover_output_amount() {
            disprove_input_amount() - verifier_assert_prover_output_amount()
        } else {
            0
        };

    max(
        max(DUST_AMOUNT, disprove_connector_d_amount),
        pubin_disprove_input_amount(),
    )
}
pub const fn operator_assert_input_amount(num_verifier: usize) -> u64 {
    min_relay_fee_operator_assert(num_verifier)
        + num_verifier as u64 * verifier_assert_input_amount()
        + connector_d_assert_output_amount()
        + P2A_AMOUNT
}
pub const fn max_assert_cost(num_verifier: usize) -> u64 {
    operator_assert_input_amount(num_verifier)
}
pub const fn max_watchtower_challenge_cost(num_watchtowers: usize) -> u64 {
    min_relay_fee_watchtower_challenge_init(num_watchtowers)
        + num_watchtowers as u64
            * (watchtower_challenge_connector_output_amount() + ack_connector_output_amount())
        + connector_e_output_amount()
        + connector_f_output_amount()
        + P2A_AMOUNT
}
pub const fn max_pegout_cost(num_watchtowers: usize, num_verifier: usize) -> u64 {
    max_assert_cost(num_verifier)
        + max_watchtower_challenge_cost(num_watchtowers)
        + MIN_RELAY_FEE_KICKOFF
        + DUST_AMOUNT * 2
        + P2A_AMOUNT
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Input {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    pub outpoint: OutPoint,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    pub amount: Amount,
}

pub struct InputWithScript<'a> {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub script: &'a Script,
}

pub fn tx_output_input(transaction: &Transaction, vout: usize) -> Result<Input, Error> {
    let output = transaction
        .output
        .get(vout)
        .ok_or(Error::Other("transaction output index out of bounds"))?;
    let vout = vout
        .try_into()
        .map_err(|_| Error::Other("transaction output index exceeds u32"))?;

    Ok(Input {
        outpoint: OutPoint {
            txid: transaction.compute_txid(),
            vout,
        },
        amount: output.value,
    })
}

pub mod output_topology {
    pub mod kickoff {
        pub const CONNECTOR_A: usize = 0;
        pub const CONNECTOR_B: usize = 1;
        pub const CONNECTOR_C: usize = 2;
        pub const GUARDIAN_CONNECTOR: usize = 3;
        pub const ANCHOR: usize = 4;
        pub const OUTPUT_NUM: usize = ANCHOR + 1;

        pub const fn connector_a() -> usize {
            CONNECTOR_A
        }

        pub const fn connector_b() -> usize {
            CONNECTOR_B
        }

        pub const fn connector_c() -> usize {
            CONNECTOR_C
        }

        pub const fn guardian_connector() -> usize {
            GUARDIAN_CONNECTOR
        }

        pub const fn anchor() -> usize {
            ANCHOR
        }
    }

    pub mod prekickoff {
        pub const FORCE_SKIP_CONNECTOR: usize = 0;
        pub const KICKOFF_CONNECTOR: usize = 1;
        pub const PREKICKOFF_CONNECTOR: usize = 2;
        pub const ANCHOR: usize = 3;
        pub const OUTPUT_NUM: usize = ANCHOR + 1;

        pub const fn force_skip_connector() -> usize {
            FORCE_SKIP_CONNECTOR
        }

        pub const fn kickoff_connector() -> usize {
            KICKOFF_CONNECTOR
        }

        pub const fn prekickoff_connector() -> usize {
            PREKICKOFF_CONNECTOR
        }

        pub const fn anchor() -> usize {
            ANCHOR
        }
    }

    pub mod pegin_deposit {
        pub const CONNECTOR_Z: usize = 0;
        pub const CHANGE: usize = 1;

        pub const fn connector_z() -> usize {
            CONNECTOR_Z
        }

        pub const fn change() -> usize {
            CHANGE
        }

        pub const fn output_num(has_change: bool) -> usize {
            if has_change {
                CHANGE + 1
            } else {
                CONNECTOR_Z + 1
            }
        }
    }

    pub mod pegin_refund {
        pub const REFUND: usize = 0;
        pub const OUTPUT_NUM: usize = REFUND + 1;

        pub const fn refund() -> usize {
            REFUND
        }
    }

    pub mod pegin_confirm {
        pub const CONNECTOR_0: usize = 0;
        pub const OP_RETURN: usize = 1;
        pub const OUTPUT_NUM: usize = OP_RETURN + 1;

        pub const fn connector_0() -> usize {
            CONNECTOR_0
        }

        pub const fn op_return() -> usize {
            OP_RETURN
        }
    }

    pub mod watchtower_challenge_init {
        pub const WATCHTOWER_CONNECTOR_PAIR_START: usize = 0;

        pub const fn watchtower_connector(index: usize) -> usize {
            WATCHTOWER_CONNECTOR_PAIR_START + index * 2
        }

        pub const fn ack_connector(index: usize) -> usize {
            WATCHTOWER_CONNECTOR_PAIR_START + index * 2 + 1
        }

        pub const fn connector_e(watchtower_num: usize) -> usize {
            WATCHTOWER_CONNECTOR_PAIR_START + watchtower_num * 2
        }

        pub const fn connector_f(watchtower_num: usize) -> usize {
            connector_e(watchtower_num) + 1
        }

        pub const fn anchor(watchtower_num: usize) -> usize {
            connector_f(watchtower_num) + 1
        }

        pub const fn output_num(watchtower_num: usize) -> usize {
            anchor(watchtower_num) + 1
        }

        pub const fn watchtower_num(output_num: usize) -> usize {
            if output_num < 3 {
                0
            } else {
                (output_num - 3) / 2
            }
        }
    }

    pub mod operator_assert {
        pub const VERIFIER_CONNECTOR_START: usize = 0;

        pub const fn verifier_connector(index: usize) -> usize {
            VERIFIER_CONNECTOR_START + index
        }

        pub const fn connector_d(verifier_num: usize) -> usize {
            VERIFIER_CONNECTOR_START + verifier_num
        }

        pub const fn anchor(verifier_num: usize) -> usize {
            connector_d(verifier_num) + 1
        }

        pub const fn output_num(verifier_num: usize) -> usize {
            anchor(verifier_num) + 1
        }

        pub const fn verifier_num(output_num: usize) -> usize {
            if output_num < 2 {
                0
            } else {
                output_num - 2
            }
        }
    }

    pub mod verifier_assert {
        pub const PROVER_CONNECTOR: usize = 0;
        pub const ANCHOR: usize = 1;
        pub const OUTPUT_NUM: usize = ANCHOR + 1;

        pub const fn prover_connector() -> usize {
            PROVER_CONNECTOR
        }

        pub const fn anchor() -> usize {
            ANCHOR
        }
    }
}

pub trait BaseTransaction {
    fn name(&self) -> &'static str;
    // fn initialize(&mut self, context: &dyn BaseContext);

    // TODO: Use musig2 to aggregate signatures
    // fn pre_sign(&mut self, context: &dyn BaseContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self) -> Transaction;
}

pub const fn relay_fee(vsize: usize) -> u64 {
    (vsize as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE
}

pub fn merge_transactions(
    destination_transaction: &mut Transaction,
    source_transaction: &Transaction,
) {
    for i in destination_transaction.input.len()..source_transaction.input.len() {
        destination_transaction
            .input
            .push(source_transaction.input[i].clone());
    }

    for i in 0..cmp::min(
        destination_transaction.input.len(),
        source_transaction.input.len(),
    ) {
        // TODO: takes longer witness data but should combine both
        // TODO: merge signatures after Musig2 feature is ready
        if destination_transaction.input[i].witness.len()
            < source_transaction.input[i].witness.len()
        {
            destination_transaction.input[i].witness = source_transaction.input[i].witness.clone();
        }
    }

    for i in destination_transaction.output.len()..source_transaction.output.len() {
        destination_transaction
            .output
            .push(source_transaction.output[i].clone());
    }
}

// assumes source_transaction is the latest
pub fn merge_musig2_nonces_and_signatures(
    destination_transaction: &mut dyn PreSignedMusig2Transaction,
    source_transaction: &dyn PreSignedMusig2Transaction,
) {
    let nonces = destination_transaction.musig2_nonces_mut();
    merge_hash_maps(nonces, source_transaction.musig2_nonces().clone());

    let nonce_signatures = destination_transaction.musig2_nonce_signatures_mut();
    merge_hash_maps(
        nonce_signatures,
        source_transaction.musig2_nonce_signatures().clone(),
    );

    let signatures = destination_transaction.musig2_signatures_mut();
    merge_hash_maps(signatures, source_transaction.musig2_signatures().clone());
}

// merge the nonce/signature hashmaps. We can't just do a.extend(b) since that would just overwrite the inner
// hashmap rather than merging it
fn merge_hash_maps<T: Clone>(
    a: &mut HashMap<usize, HashMap<PublicKey, T>>,
    b: HashMap<usize, HashMap<PublicKey, T>>,
) {
    let all_keys = a
        .keys()
        .chain(b.keys())
        .unique()
        .cloned()
        .collect::<Vec<_>>();
    for key in all_keys {
        let q = a.entry(key).or_default();
        let w = b.get(&key).cloned().unwrap_or(HashMap::new());
        q.extend(w.clone());
    }
}

pub fn validate_transaction(
    transaction: &Transaction,
    comparison_transaction: &Transaction,
) -> bool {
    for i in 0..comparison_transaction.input.len() {
        if transaction.input[i].previous_output != comparison_transaction.input[i].previous_output
            || transaction.input[i].script_sig != comparison_transaction.input[i].script_sig
            || transaction.input[i].sequence != comparison_transaction.input[i].sequence
        {
            println!(
                "Input mismatch on transaction: {} input index: {}",
                transaction.compute_txid(),
                i
            );
            return false;
        }
    }

    for i in 0..comparison_transaction.output.len() {
        if transaction.output[i].value != comparison_transaction.output[i].value
            || transaction.output[i].script_pubkey != comparison_transaction.output[i].script_pubkey
        {
            println!(
                "Output mismatch on transaction: {} output index: {}",
                transaction.compute_txid(),
                i
            );
            return false;
        }
    }

    true
}

fn verify_public_nonces(
    all_nonces: &HashMap<usize, HashMap<PublicKey, PubNonce>>,
    all_sigs: &HashMap<usize, HashMap<PublicKey, Signature>>,
    txid: Txid,
) -> bool {
    let mut ret_val = true;

    for (i, nonces) in all_nonces {
        for (pubkey, nonce) in nonces {
            if !verify_public_nonce(&all_sigs[i][pubkey], nonce, &XOnlyPublicKey::from(*pubkey)) {
                eprintln!(
                    "Failed to verify public nonce for pubkey {pubkey} on tx:input {txid}:{i}."
                );
                ret_val = false;
            }
        }
    }

    ret_val
}

pub fn verify_public_nonces_for_tx(tx: &impl PreSignedMusig2Transaction) -> bool {
    verify_public_nonces(
        tx.musig2_nonces(),
        tx.musig2_nonce_signatures(),
        tx.tx().compute_txid(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::{
        key::{
            constants::{SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE},
            Keypair,
        },
        PublicKey, Txid,
    };
    use musig2::{secp256k1::schnorr::Signature, PubNonce};

    use crate::{
        contexts::base::generate_keys_from_secret,
        transactions::{pre_signed_musig2::get_nonce_message, signing_musig2::generate_nonce},
    };

    use super::verify_public_nonces;

    const DUMMY_TXID: &str = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";

    type TestNonces = HashMap<usize, HashMap<PublicKey, PubNonce>>;
    type TestNonceSignatures = HashMap<usize, HashMap<PublicKey, Signature>>;

    fn get_test_nonces() -> (TestNonces, TestNonceSignatures) {
        const SIGNERS: usize = 3;
        const INPUTS: usize = 4;

        // Generate keys
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut pubkeys: Vec<PublicKey> = Vec::new();
        for signer in 0..SIGNERS {
            let (keypair, pubkey) = generate_keys_from_secret(
                bitcoin::Network::Bitcoin,
                &hex::encode([(signer + 1) as u8; SECRET_KEY_SIZE]),
            );
            keypairs.push(keypair);
            pubkeys.push(pubkey);
        }

        // Generate and sign nonces
        let mut all_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>> = HashMap::new();
        let mut all_sigs: HashMap<usize, HashMap<PublicKey, Signature>> = HashMap::new();
        for input in 0..INPUTS {
            let mut nonces: HashMap<PublicKey, PubNonce> = HashMap::new();
            let mut sigs: HashMap<PublicKey, Signature> = HashMap::new();
            for signer in 0..SIGNERS {
                let secret_nonce = generate_nonce();

                nonces.insert(pubkeys[signer], secret_nonce.public_nonce());

                let nonce_signature =
                    keypairs[signer].sign_schnorr(get_nonce_message(&secret_nonce.public_nonce()));
                sigs.insert(pubkeys[signer], nonce_signature);
            }
            all_nonces.insert(input, nonces);
            all_sigs.insert(input, sigs);
        }
        (all_nonces, all_sigs)
    }

    #[test]
    fn test_verify_public_nonces_all_valid_signatures() {
        let (all_nonces, all_sigs) = get_test_nonces();

        assert!(
            verify_public_nonces(&all_nonces, &all_sigs, DUMMY_TXID.parse::<Txid>().unwrap()),
            "verify_public_nonces() did not return true on success"
        );
    }

    #[test]
    fn test_verify_public_nonces_invalid_signature() {
        let (all_nonces, mut all_sigs) = get_test_nonces();

        let input_index = all_sigs.len() / 2;
        let pubkey = *all_sigs[&input_index].keys().next().unwrap();
        let mut bad_sig = all_sigs[&input_index][&pubkey].serialize();
        bad_sig[SCHNORR_SIGNATURE_SIZE - 1] += 1;
        all_sigs
            .get_mut(&input_index)
            .unwrap()
            .insert(pubkey, Signature::from_slice(&bad_sig).unwrap());

        assert!(
            !verify_public_nonces(&all_nonces, &all_sigs, DUMMY_TXID.parse::<Txid>().unwrap()),
            "verify_public_nonces() did not return false on invalid signature"
        );
    }
}
