//! Modified from https://github.com/BitVM/BitVM/tree/main/header-chain
mod header_chain;
pub use header_chain::*;
pub mod merkle_tree;
pub mod mmr;
pub mod transaction;
pub mod utils;

pub use merkle_tree::*;
pub use mmr::*;
pub use transaction::*;

pub mod spv;
pub use spv::SPV;

/// The main entry point of the header chain circuit.
pub fn header_chain_circuit(input: HeaderChainCircuitInput) -> BlockHeaderCircuitOutput {
    // println!("Detected network: {:?}", NETWORK_TYPE);
    // println!("NETWORK_CONSTANTS: {:?}", NETWORK_CONSTANTS);
    let self_program_id = input.self_program_id;
    let (mut chain_state, program_history_hash, upgrade_checkpoint_hash) = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock => {
            let first =
                input.block_headers.first().expect("genesis header batch must be non-empty");
            // Use the real Bitcoin genesis block as the first header in the header chain.
            let expected = CircuitBlockHeader::from(
                bitcoin::blockdata::constants::genesis_block(NETWORK).header,
            );
            assert_eq!(
                first, &expected,
                "header chain must start at the configured Bitcoin genesis"
            );

            (ChainState::new(), verifier::initial_history(verifier::ProgramType::Header), [0u8; 32])
        }
        HeaderChainPrevProofType::PrevProof => {
            println!("verify header chain of prev proof");
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let output = decode_header_chain_circuit_output(&input.zkm_public_values);
            assert_eq!(output.self_program_id, previous_program_id);

            let history = verifier::next_history(
                verifier::ProgramType::Header,
                output.program_history_hash,
                previous_program_id,
                self_program_id,
            );
            let checkpoint = if previous_program_id == self_program_id {
                output.upgrade_checkpoint_hash
            } else {
                verifier::proof_checkpoint(
                    verifier::ProgramType::Header,
                    output.upgrade_checkpoint_hash,
                    previous_program_id,
                    self_program_id,
                    &input.zkm_public_values,
                )
            };
            (output.chain_state, history, checkpoint)
        }
    };

    chain_state.apply_blocks(input.block_headers);
    BlockHeaderCircuitOutput {
        chain_state,
        self_program_id,
        program_history_hash,
        upgrade_checkpoint_hash,
    }
}

#[cfg(test)]
mod circuit_output_tests {
    use super::*;

    #[test]
    fn classifies_only_current_output() {
        let mut current = bincode::serialize(&BlockHeaderCircuitOutput {
            chain_state: ChainState::new(),
            self_program_id: [1u8; 32],
            program_history_hash: [2u8; 32],
            upgrade_checkpoint_hash: [3u8; 32],
        })
        .unwrap();
        assert_eq!(
            classify_header_chain_output(&current).unwrap(),
            HeaderChainPrevProofType::PrevProof
        );
        current.push(0);
        assert!(classify_header_chain_output(&current).is_err());
        assert!(classify_header_chain_output(b"unknown").is_err());
    }
}
