use crate::wots::{Wots, Wots96};
use bitvm::{signatures::WinternitzSecret, treepp::*};
use serde::{Deserialize, Serialize};

pub const INPUT_WIRE_NUM: usize = 768;
pub const PROVER_SIG_LEN: usize = 2 * Wots96::TOTAL_DIGIT_LEN as usize;
pub type OperatorAssertSecretKey = WinternitzSecret;
pub type OperatorAssertPublicKey = <Wots96 as Wots>::PublicKey;
pub type OperatorCommitPubinSecretKey = WinternitzSecret;
pub type OperatorCommitPubinPublicKey = <Wots96 as Wots>::PublicKey;
pub const OPERATOR_ASSERT_PI1_X_INDEX: usize = 0;
pub const OPERATOR_ASSERT_PI1_Y_INDEX: usize = 1;
pub const OPERATOR_ASSERT_X_D_INDEX: usize = 2;

pub type Label = Vec<u8>;
pub type LabelHash = [u8; 20];
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WireHash {
    pub true_label_hash: LabelHash,
    pub false_label_hash: LabelHash,
}

pub fn label_hash(label: &Label) -> LabelHash {
    use bitcoin::hashes::{hash160, Hash};
    hash160::Hash::hash(label).to_byte_array()
}

fn label_hash_script() -> Script {
    script! {
        OP_HASH160
    }
}

pub fn wrongly_challenged_hashlocks_script(hashlocks: &[LabelHash]) -> Script {
    assert!(
        !hashlocks.is_empty(),
        "wrongly challenged script requires at least one hashlock"
    );
    script! {
        { label_hash_script() }
        { 0 }
        for hashlock in hashlocks.iter() {
            OP_OVER
            { hashlock.to_vec() }
            OP_EQUAL
            OP_BOOLOR
        }
        OP_NIP
    }
}

pub fn verify_prover_assert_script_768_wire(
    prover_wots_pubkey: &<Wots96 as Wots>::PublicKey,
) -> Script {
    script! {
        OP_2DROP
        { Wots96::checksig_verify_and_clear_stack(prover_wots_pubkey) }
        OP_TRUE
    }
}

pub fn verify_prover_pubin_script(prover_wots_pubkey: &<Wots96 as Wots>::PublicKey) -> Script {
    script! {
        { Wots96::checksig_verify_and_clear_stack(prover_wots_pubkey) }
        OP_TRUE
    }
}

pub fn verify_verifier_assert_script_768_wire(
    prover_wots_pubkey: &<Wots96 as Wots>::PublicKey,
    label_hashes: &[WireHash; 768],
) -> Script {
    script! {
        for byte_hashes in label_hashes.chunks(8).rev() {
            { 0 }
            for (bit_index, wire_hash) in byte_hashes.iter().enumerate().rev() {
                OP_SWAP
                OP_DUP
                { label_hash_script() }
                { wire_hash.true_label_hash.to_vec() }
                OP_EQUAL
                OP_IF
                    OP_DROP
                    { 1 << bit_index }
                    OP_ADD
                OP_ELSE
                    { label_hash_script() }
                    { wire_hash.false_label_hash.to_vec() }
                    OP_EQUALVERIFY
                OP_ENDIF
            }
            OP_TOALTSTACK
        }
        { Wots96::checksig_verify(prover_wots_pubkey) }
        for _ in 0..Wots96::MSG_BYTE_LEN {
            OP_FROMALTSTACK
            OP_EQUALVERIFY
        }
        OP_TRUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvm::execute_script;
    use rand::RngCore;

    #[test]
    fn test_wrongly_challenged_script_accepts_any_hashlock_preimage() {
        let labels = [
            b"first preimage".to_vec(),
            b"second preimage".to_vec(),
            b"third preimage".to_vec(),
        ];
        let hashlocks: Vec<LabelHash> = labels.iter().map(label_hash).collect();

        for label in labels {
            let s = script! {
                { label.clone() }
                { wrongly_challenged_hashlocks_script(&hashlocks) }
            };
            let result = execute_script(s);
            assert!(result.success);
            assert_eq!(result.final_stack.len(), 1);
        }
    }

    #[test]
    fn test_wrongly_challenged_script_rejects_unknown_preimage() {
        let labels = [
            b"first preimage".to_vec(),
            b"second preimage".to_vec(),
            b"third preimage".to_vec(),
        ];
        let hashlocks: Vec<LabelHash> = labels.iter().map(label_hash).collect();

        let s = script! {
            { b"unknown preimage".to_vec() }
            { wrongly_challenged_hashlocks_script(&hashlocks) }
        };
        let result = execute_script(s);
        assert!(!result.success);
    }

    #[test]
    fn test_verify_verifier_assert_script_768_wire() {
        let secret = Wots96::generate_secret_key();
        let public_key = Wots96::generate_public_key(&secret);

        let true_labels: Vec<Vec<u8>> = (0..768)
            .map(|i| {
                let mut label = vec![0x54; 20];
                label[0] = (i & 0xff) as u8;
                label[1] = (i >> 8) as u8;
                label
            })
            .collect();
        let false_labels: Vec<Vec<u8>> = (0..768)
            .map(|i| {
                let mut label = vec![0x46; 20];
                label[0] = (i & 0xff) as u8;
                label[1] = (i >> 8) as u8;
                label
            })
            .collect();

        let mut msg: [u8; 96] = [0; 96];
        rand::thread_rng().fill_bytes(&mut msg);

        let mut bits = [false; 768];
        for i in 0..768 {
            bits[i] = (msg[i / 8] >> (i % 8)) & 1 == 1;
        }

        let label_hashes = std::array::from_fn(|i| WireHash {
            true_label_hash: label_hash(&true_labels[i]),
            false_label_hash: label_hash(&false_labels[i]),
        });
        let selected_labels: Vec<Vec<u8>> = (0..768)
            .map(|i| {
                if bits[i] {
                    true_labels[i].clone()
                } else {
                    false_labels[i].clone()
                }
            })
            .collect();

        let s = script! {
            { Wots96::sign_to_raw_witness(&secret, &msg) }
            for wire_index in 0..768 {
                { selected_labels[wire_index].clone() }
            }
            { verify_verifier_assert_script_768_wire(&public_key, &label_hashes) }
        };
        println!("verifier assert full script size: {}", s.len());
        let result = execute_script(s);
        println!(
            "verifier assert max stack item size: {:?}",
            result.stats.max_nb_stack_items
        );
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
    }
}
