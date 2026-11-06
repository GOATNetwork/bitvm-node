#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use commit_chain::CommitChainCircuitInput;
use header_chain::{HeaderChainCircuitInput, SPV};
use state_chain::StateChainCircuitInput;

pub fn main() {
    let genesis_sequencer_commit_txid = zkm_zkvm::io::read::<[u8; 32]>();
    let header_chain: HeaderChainCircuitInput = zkm_zkvm::io::read(); // private inputs
    let commit_chain: CommitChainCircuitInput = zkm_zkvm::io::read();
    let state_chain: StateChainCircuitInput = zkm_zkvm::io::read();
    let spv: SPV = zkm_zkvm::io::read();

    let (total_work, btc_best_block_height) = bitcoin_light_client_circuit::watch_longest_chain(
        genesis_sequencer_commit_txid,
        header_chain,
        commit_chain,
        state_chain,
        spv,
    );
    zkm_zkvm::io::commit(&total_work);
    zkm_zkvm::io::commit(&btc_best_block_height);
    zkm_zkvm::io::commit(&genesis_sequencer_commit_txid);
}
