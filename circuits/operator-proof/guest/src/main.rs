#![no_main]
zkm_zkvm::entrypoint!(main);
use alloy_primitives::U256;
use bitcoin::Transaction;
use bitcoin_light_client_circuit::IndexedWatchtowerChallenge;
use commit_chain::CommitChainCircuitInput;
use header_chain::{HeaderChainCircuitInput, MMRInclusionProof, SPV};
use state_chain::StateChainCircuitInput;

pub fn main() {
    // calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
    let included_watchtowers: U256 = zkm_zkvm::io::read::<U256>();
    let graph_id: [u8; 16] = zkm_zkvm::io::read::<[u8; 16]>();
    let operator_genesis_sequencer_commit_txid: [u8; 32] = zkm_zkvm::io::read();
    let gateway_address: [u8; 20] = zkm_zkvm::io::read();
    let withdrawal_proof: MMRInclusionProof = zkm_zkvm::io::read();

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    let watchtower_challenge_init_txid: [u8; 32] = zkm_zkvm::io::read();
    let watchtower_challenge_init_txn: Option<Transaction> = zkm_zkvm::io::read();
    let graph_watchtower_xonly_public_keys: Vec<[u8; 32]> = zkm_zkvm::io::read();
    let watchtower_challenges: Vec<IndexedWatchtowerChallenge> = zkm_zkvm::io::read();

    let operator_header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read();
    let operator_commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let operator_state_chain: StateChainCircuitInput = zkm_zkvm::io::read();
    let spv_ss_commit: SPV = zkm_zkvm::io::read();
    let operator_committed_blockhash: [u8; 32] = zkm_zkvm::io::read();

    let (btc_best_block_hash, constant, included_watchtowers) =
        bitcoin_light_client_circuit::propose_longest_chain(
            included_watchtowers,
            graph_id,
            operator_genesis_sequencer_commit_txid,
            gateway_address,
            withdrawal_proof,
            watchtower_challenge_init_txid,
            watchtower_challenge_init_txn,
            watchtower_challenges,
            &graph_watchtower_xonly_public_keys,
            operator_header_chain,
            operator_commit_chain,
            operator_state_chain,
            spv_ss_commit,
            operator_committed_blockhash,
        );

    zkm_zkvm::io::commit(&btc_best_block_hash);
    zkm_zkvm::io::commit(&constant);
    zkm_zkvm::io::commit(&included_watchtowers);
}
