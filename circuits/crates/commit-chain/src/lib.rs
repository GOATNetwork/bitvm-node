mod publisher;
pub use publisher::*;
mod commit_chain;
pub use commit_chain::*;

pub fn commit_chain_circuit(input: CommitChainCircuitInput) -> CommitChainCircuitOutput {
    let self_program_id = input.self_program_id;
    assert!(!input.commits.is_empty(), "commit batch must be non-empty");
    let mut chain_state = match input.prev_proof {
        CommitChainPrevProofType::GenesisBlock => {
            CommitChainState::new(input.commits[0].genesis_txid)
        }
        CommitChainPrevProofType::PrevProof => {
            println!("verify commit chain of prev proof");
            let previous_program_id = verifier::verify_groth16_proof(
                &input.zkm_proof,
                &input.zkm_public_values,
                &input.zkm_vk_hash,
                &input.zkm_version,
            )
            .unwrap();

            let output = decode_commit_chain_circuit_output(&input.zkm_public_values);
            assert_eq!(output.self_program_id, previous_program_id);
            assert_eq!(
                previous_program_id, self_program_id,
                "commit predecessor ProgramId must match current ProgramId"
            );
            output.chain_state
        }
    };

    chain_state.apply_commit(input.commits);
    CommitChainCircuitOutput { chain_state, self_program_id }
}

#[cfg(test)]
mod circuit_output_tests {
    use super::*;

    fn chain_state() -> CommitChainState {
        CommitChainState::new([1u8; 32])
    }

    #[test]
    fn classifies_only_current_outputs() {
        let current = bincode::serialize(&CommitChainCircuitOutput {
            chain_state: chain_state(),
            self_program_id: [1u8; 32],
        })
        .unwrap();
        assert_eq!(
            classify_commit_chain_output(&current).unwrap(),
            CommitChainPrevProofType::PrevProof
        );
        assert!(classify_commit_chain_output(b"unknown").is_err());
    }
}
