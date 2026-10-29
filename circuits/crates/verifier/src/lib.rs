use sha2::{Digest, Sha256};
use zkm_verifier::{Groth16Verifier, IMM_GROTH16_VK_BYTES, decode_zkm_vkey_hash};

pub type ProgramId = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramType {
    Header = 1,
    State = 2,
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The partial STARK verifying key bundled for `zkm_version`, or an error for an unknown version.
fn bundled_part_stark_vk(zkm_version: &str) -> Result<&'static [u8], String> {
    Groth16Verifier::try_get_part_stark_vk(zkm_version)
        .ok_or_else(|| format!("no partial STARK verifying key is bundled for Ziren {zkm_version}"))
}

fn program_id_with_part_vk(zkm_vk_hash: &str, part_stark_vk: &[u8]) -> Result<ProgramId, String> {
    let vk_hash = decode_zkm_vkey_hash(zkm_vk_hash).map_err(|e| format!("{e:?}"))?;
    let part_vk_hash: [u8; 32] = Sha256::digest(part_stark_vk).into();
    Ok(tagged_hash(b"bitvm/program-id/v1", &[&vk_hash, &part_vk_hash]))
}

pub fn program_id(zkm_vk_hash: &[u8], zkm_version: &str) -> Result<ProgramId, String> {
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    program_id_with_part_vk(&zkm_vk_hash, bundled_part_stark_vk(zkm_version)?)
}

pub fn initial_history(program_type: ProgramType) -> [u8; 32] {
    tagged_hash(b"bitvm/vk-history-seed/v1", &[&[program_type as u8]])
}

pub fn next_history(
    program_type: ProgramType,
    previous_history: [u8; 32],
    previous_program_id: ProgramId,
    current_program_id: ProgramId,
) -> [u8; 32] {
    if previous_program_id == current_program_id {
        previous_history
    } else {
        tagged_hash(
            b"bitvm/vk-history-step/v1",
            &[&[program_type as u8], &previous_history, &previous_program_id],
        )
    }
}

pub fn finalize_history(
    program_type: ProgramType,
    history: [u8; 32],
    current_program_id: ProgramId,
) -> [u8; 32] {
    tagged_hash(
        b"bitvm/vk-history-final/v1",
        &[&[program_type as u8], &history, &current_program_id],
    )
}

pub fn program_history_root(header_history: [u8; 32], state_history: [u8; 32]) -> [u8; 32] {
    tagged_hash(b"bitvm/program-history/v1", &[&header_history, &state_history])
}

/// Extends a circuit checkpoint with the authenticated predecessor output at an upgrade.
pub fn proof_checkpoint(
    program_type: ProgramType,
    previous_checkpoint: [u8; 32],
    previous_program_id: ProgramId,
    current_program_id: ProgramId,
    previous_public_values: &[u8],
) -> [u8; 32] {
    let public_values_hash: [u8; 32] = Sha256::digest(previous_public_values).into();
    tagged_hash(
        b"bitvm/proof-upgrade/v1",
        &[
            &[program_type as u8],
            &previous_checkpoint,
            &previous_program_id,
            &current_program_id,
            &public_values_hash,
        ],
    )
}

/// Combines the Header and State upgrade checkpoints committed by the Publisher.
pub fn proof_checkpoint_root(header_checkpoint: [u8; 32], state_checkpoint: [u8; 32]) -> [u8; 32] {
    tagged_hash(b"bitvm/proof-checkpoint-root/v1", &[&header_checkpoint, &state_checkpoint])
}

pub fn verify_groth16_proof(
    proof: &[u8],
    zkm_public_values: &[u8],
    zkm_vk_hash: &[u8],
    zkm_version: &str,
) -> Result<ProgramId, String> {
    let groth16_vk = *IMM_GROTH16_VK_BYTES;
    let zkm_vk_hash = String::from_utf8(zkm_vk_hash.to_vec()).map_err(|e| e.to_string())?;
    let part_stark_vk = bundled_part_stark_vk(zkm_version)?;

    Groth16Verifier::verify_by_imm_groth16_vk(
        proof,
        zkm_public_values,
        &zkm_vk_hash,
        groth16_vk,
        part_stark_vk,
    )
    .map_err(|err| format!("Verify Groth16 proof, err: {err:?}"))?;

    program_id_with_part_vk(&zkm_vk_hash, part_stark_vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the Groth16 statement to Ziren `3cf393cd` (circuit version v2.0.0). The Ziren dependency
    /// has no tag or rev, so a `cargo update` could otherwise move the wrap vk or the recursion vk
    /// root without a reviewable diff. Update these only together with a deliberate Ziren upgrade.
    #[test]
    fn ziren_wrap_vk_and_vk_root_are_pinned() {
        let imm_vk_hash: [u8; 32] = Sha256::digest(*IMM_GROTH16_VK_BYTES).into();
        assert_eq!(
            imm_vk_hash,
            [
                0x3b, 0x80, 0xd6, 0x3c, 0xa6, 0x6a, 0x02, 0x8a, 0x72, 0xd9, 0x57, 0xd9, 0x99, 0x69,
                0xab, 0xa6, 0xdb, 0x7d, 0xc1, 0xe9, 0x7d, 0xf2, 0x7f, 0x78, 0x74, 0xfa, 0x98, 0x76,
                0x42, 0x5e, 0x77, 0x12,
            ]
        );
        assert_eq!(
            *zkm_verifier::VK_ROOT_BYTES,
            [
                0x00, 0xfa, 0x3d, 0x18, 0xd9, 0x6c, 0xec, 0x7a, 0xc6, 0xaf, 0x03, 0x79, 0xcc, 0xfd,
                0x0a, 0xb1, 0xb5, 0x39, 0x23, 0xca, 0x41, 0x7e, 0xaa, 0x94, 0xfb, 0x7c, 0x8c, 0xe1,
                0xc9, 0x4c, 0x5d, 0x6e,
            ]
        );
    }

    #[test]
    fn unknown_ziren_version_is_an_error() {
        assert!(program_id(b"0x00", "v0.0.0-unknown").is_err());
        assert!(verify_groth16_proof(&[], &[], b"0x00", "v0.0.0-unknown").is_err());
    }

    #[test]
    fn program_history_root_binds_header_then_state() {
        assert_eq!(
            program_history_root([1; 32], [2; 32]),
            [
                0x50, 0x25, 0x7c, 0x01, 0xae, 0x8d, 0x1e, 0x79, 0x07, 0x4f, 0x76, 0xf6, 0x21, 0xfd,
                0x4f, 0x0c, 0x63, 0x24, 0xc0, 0x71, 0xd2, 0x79, 0x92, 0xce, 0xc7, 0xc9, 0x31, 0x4d,
                0x7c, 0xf1, 0xe3, 0xe7,
            ]
        );
    }

    #[test]
    fn proof_checkpoint_binds_predecessor_and_upgrade_ids() {
        let checkpoint =
            proof_checkpoint(ProgramType::Header, [1; 32], [2; 32], [3; 32], b"public values");
        assert_ne!(
            checkpoint,
            proof_checkpoint(ProgramType::Header, [1; 32], [2; 32], [4; 32], b"public values",)
        );
        assert_ne!(
            checkpoint,
            proof_checkpoint(
                ProgramType::Header,
                [1; 32],
                [2; 32],
                [3; 32],
                b"other public values",
            )
        );
    }
}
