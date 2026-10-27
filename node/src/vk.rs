use anyhow::Result;
use zkm_verifier::{IMM_GROTH16_VK_BYTES, load_ark_groth16_verifying_key_from_bytes};

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;

pub async fn get_vk() -> Result<VerifyingKey> {
    Ok(load_ark_groth16_verifying_key_from_bytes(&IMM_GROTH16_VK_BYTES)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_vk() {
        let vk = get_vk().await.unwrap();
        let imm_v =
            load_ark_groth16_verifying_key_from_bytes(&zkm_verifier::IMM_GROTH16_VK_BYTES).unwrap();

        assert_eq!(vk, imm_v);
        // Ziren V2 wraps with [vkey_hash, committed_values_digest, vk_root]; BABE splits them by slot.
        assert_eq!(vk.gamma_abc_g1.len(), bitvm_lib::babe_adapter::NUM_PUBLIC_INPUTS + 1);
    }
}
