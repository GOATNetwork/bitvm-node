use crate::{
    assert_scripts::{
        LabelHash, OPERATOR_ASSERT_X_D_INDEX, OperatorAssertPublicKey, OperatorCommitPubinPublicKey,
    },
    wots::{Wots, Wots96},
};
use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};

pub const GUEST_PUBIN_NUM: usize = 3;
pub const GUEST_PUBIN_BLOCKHASH_INDEX: usize = 0;
pub const GUEST_PUBIN_CONSTANT_INDEX: usize = 1;
pub const GUEST_PUBIN_INCLUDED_MAP_INDEX: usize = 2;

pub fn verify_guest_pubin_commitment(
    guest_pubin_wots_pubkey: &OperatorCommitPubinPublicKey,
    operator_assert_wots_pubkey: &OperatorAssertPublicKey,
    constant_value: &[u8; 32],
    hashes: &Vec<LabelHash>,
) -> Script {
    let wots96_msg_stack_items_num = Wots96::MSG_BYTE_LEN as usize;
    let wots96_sig_stack_items_num = Wots96::TOTAL_DIGIT_LEN as usize * 2;

    script! {
        { Wots96::checksig_verify(guest_pubin_wots_pubkey) }

        { 1 } OP_TOALTSTACK

        { verify_hashlock_pubin_segment_dup(GUEST_PUBIN_INCLUDED_MAP_INDEX, hashes) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK

        { verify_constant_pubin_segment_dup(GUEST_PUBIN_CONSTANT_INDEX, constant_value) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK

        // Consume the operator assertion WOTS witness before computing the guest
        // pubin commitment. Leaving its 196 raw witness items on the stack while
        // SHA256 runs pushes the combined stack over Bitcoin's 1000-item limit.
        { roll_n(wots96_msg_stack_items_num, wots96_sig_stack_items_num) }
        { Wots96::checksig_verify(operator_assert_wots_pubkey) }

        // Keep only x_d from the 96-byte operator assertion message. The other
        // 64 bytes are pi1.x and pi1.y and are not needed by PubinDisprove.
        { lift_and_reverse_bytes(OPERATOR_ASSERT_X_D_INDEX * 32, 32) }
        { roll_n(32, OPERATOR_ASSERT_X_D_INDEX * 32) }
        for _ in 0..(OPERATOR_ASSERT_X_D_INDEX * 32) {
            OP_DROP
        }

        // Move the 96-byte guest pubin above x_d and compute its commitment.
        // BLAKE3 requires the main stack to contain only its compact message,
        // so keep x_d on the alt stack until the digest is available.
        { roll_n(32, wots96_msg_stack_items_num) }
        for _ in 0..32 {
            { wots96_msg_stack_items_num } OP_ROLL OP_TOALTSTACK
        }
        { generate_guest_pubin_commitment(GUEST_PUBIN_NUM as u32) }
        for _ in 0..32 {
            OP_FROMALTSTACK
        }
        // Restore x_d below the 64-nibble digest, preserving the old comparison
        // stack layout: x_d | guest pubin commitment (top).
        { roll_n(32, 64) }
        { zip_nibbles_bytes32() }

        { 1 }
        for i in (0..32).rev() {
            OP_SWAP { i + 2 } OP_ROLL OP_NUMEQUAL OP_BOOLAND
        }

        // Pubin-Disprove succeeds when the guest pubin commitment differs from
        // x_d in OperatorAssertTransaction, i.e. Prover-Assert in the protocol
        // graph. The operator/prover assert pubin layout is:
        // pi1.x LE-32 | pi1.y LE-32 | x_d LE-32, and x_d is the
        // guest-pubin commitment encoded as a Groth16 public input. The
        // generated commitment is also left in LE field-byte order here.
        OP_FROMALTSTACK
        OP_BOOLAND
        OP_NOT
    }
}

pub fn verify_constant_pubin_segment_dup(
    segment_index: usize,
    constant_value: &[u8; 32],
) -> Script {
    script! {
        { copy_guest_pubin_segment_to_top(segment_index) }
        { verify_constant_pubin_script_inner(constant_value) }
    }
}

pub fn verify_constant_pubin_script_inner(constant_value: &[u8; 32]) -> Script {
    script! {
        { 1 }
        for byte in constant_value.to_vec() {
            OP_SWAP
            { byte }
            OP_NUMEQUAL
            OP_BOOLAND
        }
    }
}

pub fn verify_hashlock_pubin_segment_dup(segment_index: usize, hashes: &Vec<LabelHash>) -> Script {
    let preimage_roll_depths = hashlock_preimage_roll_depths(hashes.len());
    script! {
        for depth in preimage_roll_depths {
            { depth } OP_ROLL OP_TOALTSTACK
        }
        { copy_guest_pubin_segment_to_top(segment_index) }
        { verify_hashlock_pubin_script_inner(hashes) }
    }
}

fn hashlock_preimage_roll_depths(hash_count: usize) -> Vec<usize> {
    let mut consume_order = Vec::with_capacity(hash_count);
    for chunk_start in (0..hash_count).step_by(8) {
        let chunk_end = (chunk_start + 8).min(hash_count);
        for index in (chunk_start..chunk_end).rev() {
            consume_order.push(index);
        }
    }

    let mut remaining: Vec<usize> = (0..hash_count).collect();
    consume_order
        .into_iter()
        .rev()
        .map(|target| {
            let position = remaining
                .iter()
                .position(|index| *index == target)
                .expect("target preimage index must exist");
            let depth = Wots96::MSG_BYTE_LEN as usize + remaining.len() - 1 - position;
            remaining.remove(position);
            depth
        })
        .collect()
}

fn verify_hashlock_pubin_script_inner(hashes: &Vec<LabelHash>) -> Script {
    fn chunk_count(len: usize, chunk_size: usize) -> usize {
        len.div_ceil(chunk_size)
    }

    script! {
        { 1 }
        for chunk in hashes.chunks(8) {
            OP_SWAP
            for i in (1..8).rev() {
                if i >= chunk.len() {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                    OP_ELSE
                        OP_DROP
                    OP_ENDIF
                } else {
                    { 1 << i } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB OP_FROMALTSTACK OP_DROP
                    OP_ELSE
                        OP_DROP
                        OP_SWAP
                        OP_FROMALTSTACK
                        OP_HASH160
                        { chunk[i].to_vec() }
                        OP_EQUAL
                        OP_NOT
                        OP_BOOLAND
                        OP_SWAP
                    OP_ENDIF
                }
            }
            OP_IF
                OP_FROMALTSTACK OP_DROP
            OP_ELSE
                OP_FROMALTSTACK
                OP_HASH160
                { chunk[0].to_vec() }
                OP_EQUAL
                OP_NOT
                OP_BOOLAND
            OP_ENDIF
        }
        for _ in 0..(32 - chunk_count(hashes.len(), 8)) {
            OP_NIP
        }
    }
}

fn copy_guest_pubin_segment_to_top(segment_index: usize) -> Script {
    script! {
        for i in 0..32 {
            { segment_index * 32 + i } OP_PICK
            OP_TOALTSTACK
        }
        for _ in 0..32 {
            OP_FROMALTSTACK
        }
    }
}

fn generate_guest_pubin_blake3_input() -> Script {
    script! {
        // Build the four U256s in reverse final-stack order on the alt stack.
        // The witness has byte 0 at the top. Roll block0.part1 out first, then
        // consume block0.part0 and block1.part0 from the top of the main stack.
        // Restoring the four U256s leaves the BLAKE3 format required by the
        // helper: block1.p0 | block1.p1 | block0.p0 | block0.p1 (top).

        // block 0, part 1.
        for word_index in 0..8 {
            for _ in 0..4 {
                { 32 + 4 * word_index + 3 } OP_ROLL
            }
        }
        { bytes32_to_u4() }
        for _ in 0..64 {
            OP_TOALTSTACK
        }

        // block 0, part 0.
        for word_index in 0..8 {
            for _ in 0..4 {
                { 4 * word_index + 3 } OP_ROLL
            }
        }
        { bytes32_to_u4() }
        for _ in 0..64 {
            OP_TOALTSTACK
        }

        // block 1, part 1: zero padding in compact nibble form.
        for _ in 0..32 {
            OP_0 OP_0
        }
        for _ in 0..64 {
            OP_TOALTSTACK
        }

        // block 1, part 0.
        for word_index in 0..8 {
            for _ in 0..4 {
                { 4 * word_index + 3 } OP_ROLL
            }
        }
        { bytes32_to_u4() }
        for _ in 0..64 {
            OP_TOALTSTACK
        }

        for _ in 0..4 * 64 {
            OP_FROMALTSTACK
        }
    }
}

pub fn generate_guest_pubin_commitment(guest_pubin_num: u32) -> Script {
    assert_eq!(guest_pubin_num, GUEST_PUBIN_NUM as u32);

    script! {
        { generate_guest_pubin_blake3_input() }
        { blake3_compute_script_with_limb(GUEST_PUBIN_NUM * 32, 4) }
        { reverse_bytes_u4(32) }
        OP_SWAP { mod2_u4() } OP_SWAP
    }
}

fn roll(d: usize) -> Script {
    match d {
        0 => script! {},
        1 => script! { OP_SWAP },
        2 => script! { OP_ROT },
        _ => script! { { d } OP_ROLL },
    }
}

fn roll_n(depth: usize, num_items: usize) -> Script {
    script! {
        for _ in 0..num_items {
            { roll(depth + num_items - 1) }
        }
    }
}

fn lift_and_reverse_bytes(depth: usize, num_bytes: usize) -> Script {
    script! {
        for i in 0..num_bytes {
            { roll(depth + i) }
        }
    }
}

fn bytes32_to_u4() -> Script {
    script! {
        { U256::transform_limbsize(8, 4) }
    }
}

fn lift_and_reverse_bytes_u4(depth: usize, num_bytes: usize) -> Script {
    script! {
        for i in 0..num_bytes {
            { roll(depth + 2 * i + 1) }
            { roll(depth + 2 * i + 1) }
        }
    }
}

fn reverse_bytes_u4(num_bytes: usize) -> Script {
    lift_and_reverse_bytes_u4(0, num_bytes)
}

fn mod2_u4() -> Script {
    script! {
        OP_DUP
        OP_8
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_8
            OP_SUB
        OP_ENDIF

        OP_DUP
        OP_4
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_4
            OP_SUB
        OP_ENDIF

        OP_DUP
        OP_3
        OP_EQUAL

        OP_SWAP
        OP_1
        OP_EQUAL
        OP_BOOLOR
    }
}

fn zip_nibbles_bytes32() -> Script {
    script! {
        { U256::transform_limbsize(4, 8) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assert_scripts::{OPERATOR_ASSERT_X_D_INDEX, label_hash},
        wots::Wots96,
    };
    use bitvm::{FmtStack, execute_script};

    fn guest_pubin(blockhash: &[u8; 32], constant: &[u8; 32], included_map: &[u8; 32]) -> [u8; 96] {
        let mut msg = [0u8; 96];
        msg[0..32].copy_from_slice(blockhash);
        msg[32..64].copy_from_slice(constant);
        msg[64..96].copy_from_slice(included_map);
        msg
    }

    fn operator_assert_pubin(pi1_x: &[u8; 32], pi1_y: &[u8; 32], x_d: &[u8; 32]) -> [u8; 96] {
        let mut msg = [0u8; 96];
        msg[0..32].copy_from_slice(pi1_x);
        msg[32..64].copy_from_slice(pi1_y);
        let x_d_start = OPERATOR_ASSERT_X_D_INDEX * 32;
        msg[x_d_start..x_d_start + 32].copy_from_slice(x_d);
        msg
    }

    fn compute_guest_commitment(guest: &[u8; 96]) -> [u8; 32] {
        let s = script! {
            for byte in guest.iter().rev() {
                { *byte }
            }
            { generate_guest_pubin_commitment(GUEST_PUBIN_NUM as u32) }
            { zip_nibbles_bytes32() }
        };
        let result = execute_script(s);
        assert_eq!(result.error, None, "{result}");
        assert!(result.final_stack.len() >= 32, "{result}");
        let commitment_start = result.final_stack.len() - 32;
        parse_bytes_from_stack(commitment_start, &result.final_stack)
    }

    #[test]
    fn test_guest_pubin_blake3_input_matches_static_builder() {
        let guest: [u8; 96] = std::array::from_fn(|index| index as u8);
        let secret = Wots96::generate_secret_key();
        let public_key = Wots96::generate_public_key(&secret);
        let dynamic = execute_script(script! {
            { Wots96::sign_to_raw_witness(&secret, &guest) }
            { Wots96::checksig_verify(&public_key) }
            { generate_guest_pubin_blake3_input() }
        });
        let static_input = execute_script(script! {
            { bitvm::hash::blake3::blake3_push_message_script_with_limb(&guest, 4) }
        });

        assert_eq!(dynamic.error, None, "{dynamic}");
        assert_eq!(static_input.error, None, "{static_input}");
        assert_eq!(dynamic.final_stack.len(), static_input.final_stack.len());
        for index in 0..dynamic.final_stack.len() {
            assert_eq!(
                dynamic.final_stack.get(index),
                static_input.final_stack.get(index),
                "different packed BLAKE3 element at stack index {index}"
            );
        }
    }

    #[test]
    fn test_generate_guest_pubin_commitment_matches_reference_vector() {
        let blockhash: [u8; 32] =
            hex::decode("5a690bba0ba076d621f77665398f4b1ddbfc2349bbb3e8880307625ac5cfa900")
                .unwrap()
                .try_into()
                .unwrap();
        let constant: [u8; 32] =
            hex::decode("2df7bde0605973f5809a1338094cb47a309bc38363dd35ce178c088cd3cda79f")
                .unwrap()
                .try_into()
                .unwrap();
        let included_map: [u8; 32] =
            hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap();
        let guest = guest_pubin(&blockhash, &constant, &included_map);
        let mut expected = *blake3::hash(&guest).as_bytes();
        // Preserve the existing field-element high-bit reduction.
        expected[0] &= 0x1f;

        let mut actual_be = compute_guest_commitment(&guest);
        actual_be.reverse();

        assert_eq!(actual_be, expected);
    }

    fn parse_bytes_from_stack(start_index_from_bottom: usize, stack: &FmtStack) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = stack_value_from_bottom(stack, start_index_from_bottom + i);
        }
        bytes
    }

    fn stack_value_from_bottom(stack: &FmtStack, index_from_bottom: usize) -> u8 {
        let element = stack.get(index_from_bottom);
        if element.is_empty() { 0 } else { element[0] }
    }

    fn run_pubin_disprove(
        guest_msg: &[u8; 96],
        operator_assert_msg: &[u8; 96],
        constant: &[u8; 32],
        hashes: &Vec<LabelHash>,
        preimages: &Vec<Vec<u8>>,
    ) -> bool {
        let guest_secret = Wots96::generate_secret_key();
        let guest_public_key = Wots96::generate_public_key(&guest_secret);
        let operator_assert_secret = Wots96::generate_secret_key();
        let operator_assert_public_key = Wots96::generate_public_key(&operator_assert_secret);

        let s = script! {
            { Wots96::sign_to_raw_witness(&operator_assert_secret, operator_assert_msg) }
            { preimages.clone() }
            { Wots96::sign_to_raw_witness(&guest_secret, guest_msg) }
            { verify_guest_pubin_commitment(
                &guest_public_key,
                &operator_assert_public_key,
                constant,
                hashes,
            ) }
        };
        let result = execute_script(s);
        assert!(
            result.stats.max_nb_stack_items <= 1000,
            "PubinDisprove exceeded Bitcoin's stack limit: {}",
            result.stats.max_nb_stack_items
        );
        assert_eq!(result.error, None, "{result}");
        result.success
    }

    #[test]
    fn test_pubin_disprove_fails_when_pubin_is_valid() {
        let blockhash = [0x11; 32];
        let constant = [0x22; 32];
        let mut included_map = [0u8; 32];
        included_map[0] = 0b0000_0011;
        let guest_msg = guest_pubin(&blockhash, &constant, &included_map);
        let x_d = compute_guest_commitment(&guest_msg);
        let operator_assert_msg = operator_assert_pubin(&[0x33; 32], &[0x44; 32], &x_d);
        let preimages = vec![
            b"included-watchtower".to_vec(),
            b"missing-watchtower".to_vec(),
        ];
        let hashes = vec![label_hash(&preimages[0]), label_hash(&preimages[1])];

        assert!(!run_pubin_disprove(
            &guest_msg,
            &operator_assert_msg,
            &constant,
            &hashes,
            &preimages,
        ));
    }

    #[test]
    fn test_pubin_disprove_succeeds_on_constant_mismatch() {
        let blockhash = [0x11; 32];
        let constant = [0x22; 32];
        let wrong_constant = [0x23; 32];
        let included_map = [0xff; 32];
        let guest_msg = guest_pubin(&blockhash, &wrong_constant, &included_map);
        let x_d = compute_guest_commitment(&guest_msg);
        let operator_assert_msg = operator_assert_pubin(&[0x33; 32], &[0x44; 32], &x_d);
        let preimages = vec![b"included-watchtower".to_vec(), b"also-included".to_vec()];
        let nil_preimages = vec![vec![], vec![]];
        let hashes = vec![label_hash(&preimages[0]), label_hash(&preimages[1])];

        assert!(run_pubin_disprove(
            &guest_msg,
            &operator_assert_msg,
            &constant,
            &hashes,
            &nil_preimages,
        ));
    }

    #[test]
    fn test_pubin_disprove_succeeds_on_hashlock_mismatch() {
        let blockhash = [0x11; 32];
        let constant = [0x22; 32];
        let included_map = [0u8; 32];
        let guest_msg = guest_pubin(&blockhash, &constant, &included_map);
        let x_d = compute_guest_commitment(&guest_msg);
        let operator_assert_msg = operator_assert_pubin(&[0x33; 32], &[0x44; 32], &x_d);
        let preimages = vec![b"watchtower-0".to_vec(), b"watchtower-1".to_vec()];
        let hashes = vec![label_hash(&preimages[0]), label_hash(&preimages[1])];

        assert!(run_pubin_disprove(
            &guest_msg,
            &operator_assert_msg,
            &constant,
            &hashes,
            &preimages,
        ));
    }

    #[test]
    fn test_pubin_disprove_succeeds_on_second_hashlock_byte_mismatch() {
        let blockhash = [0x11; 32];
        let constant = [0x22; 32];
        let mut included_map = [0xff; 32];
        included_map[1] = 0b0000_0001;
        let guest_msg = guest_pubin(&blockhash, &constant, &included_map);
        let x_d = compute_guest_commitment(&guest_msg);
        let operator_assert_msg = operator_assert_pubin(&[0x33; 32], &[0x44; 32], &x_d);
        let preimages = (0..10)
            .map(|index| format!("watchtower-{index}").into_bytes())
            .collect::<Vec<_>>();
        let hashes = preimages.iter().map(label_hash).collect::<Vec<_>>();

        assert!(run_pubin_disprove(
            &guest_msg,
            &operator_assert_msg,
            &constant,
            &hashes,
            &preimages,
        ));
    }

    #[test]
    fn test_pubin_disprove_succeeds_on_x_d_mismatch() {
        let blockhash = [0x11; 32];
        let constant = [0x22; 32];
        let included_map = [0xff; 32];
        let guest_msg = guest_pubin(&blockhash, &constant, &included_map);
        let mut wrong_x_d = compute_guest_commitment(&guest_msg);
        wrong_x_d[0] ^= 0x01;
        let operator_assert_msg = operator_assert_pubin(&[0x33; 32], &[0x44; 32], &wrong_x_d);
        let preimages = vec![b"included-watchtower".to_vec(), b"also-included".to_vec()];
        let hashes = vec![label_hash(&preimages[0]), label_hash(&preimages[1])];

        assert!(run_pubin_disprove(
            &guest_msg,
            &operator_assert_msg,
            &constant,
            &hashes,
            &preimages,
        ));
    }
}
