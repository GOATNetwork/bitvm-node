mod cbft;
mod state_chain;

pub use cbft::*;
pub use state_chain::*;

pub fn state_chain_circuit(input: StateChainCircuitInput) -> StateChainCircuitOutput {
    let self_program_id = input.self_program_id;
    let (mut chain_state, program_history_hash, upgrade_checkpoint_hash) = match input.prev_proof {
        StateChainPrevProofType::GenesisBlock => {
            assert!(!input.blocks.is_empty(), "state chain genesis batch must be non-empty");
            let block_hash: [u8; 32] = input.blocks[0].evm_block.current_block.hash_slow().into();
            let block_height = input.blocks[0].evm_block.current_block.header.number;
            let cosmos_block = input.blocks[0].cosmos_block.clone();
            (
                StateChainState::new(block_height, block_hash, cosmos_block),
                verifier::initial_history(verifier::ProgramType::State),
                [0u8; 32],
            )
        }

        StateChainPrevProofType::PrevProof => {
            println!("verify state chain of prev proof");
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let state_chain_output = decode_state_chain_circuit_output(&input.zkm_public_values);
            assert_eq!(state_chain_output.self_program_id, previous_program_id);
            let history = verifier::next_history(
                verifier::ProgramType::State,
                state_chain_output.program_history_hash,
                previous_program_id,
                self_program_id,
            );
            let checkpoint = if previous_program_id == self_program_id {
                state_chain_output.upgrade_checkpoint_hash
            } else {
                verifier::proof_checkpoint(
                    verifier::ProgramType::State,
                    state_chain_output.upgrade_checkpoint_hash,
                    previous_program_id,
                    self_program_id,
                    &input.zkm_public_values,
                )
            };
            (state_chain_output.chain_state, history, checkpoint)
        }
    };

    chain_state.apply_blocks(input.blocks);
    StateChainCircuitOutput {
        chain_state,
        self_program_id,
        program_history_hash,
        upgrade_checkpoint_hash,
    }
}

#[cfg(test)]
mod circuit_output_tests {
    use super::*;

    fn chain_state() -> StateChainState {
        StateChainState::new(1, [1u8; 32], Vec::new())
    }

    #[test]
    fn classifies_only_current_output() {
        let mut current = bincode::serialize(&StateChainCircuitOutput {
            chain_state: chain_state(),
            self_program_id: [1u8; 32],
            program_history_hash: [2u8; 32],
            upgrade_checkpoint_hash: [3u8; 32],
        })
        .unwrap();
        assert_eq!(
            classify_state_chain_output(&current).unwrap(),
            StateChainPrevProofType::PrevProof
        );
        current.push(0);
        assert!(classify_state_chain_output(&current).is_err());
        assert!(classify_state_chain_output(b"unknown").is_err());
    }
}
