use crate::cbft::check_el_block_from_payload;
use alloy_consensus::Header;
use alloy_primitives::utils::keccak256;
use alloy_primitives::{Address, B256, U256};
use bincode::Options as BincodeOptions;
use guest_executor::executor::EthClientExecutor;
use guest_executor::io::EthClientExecutorInput;
use header_chain::MMRGuest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tendermint_light_client_verifier::types::LightBlock;

// Contract address, base slot and key, the expected value of the slot is hardcoded to 1.
pub type WithdrawalSlot = (Address, [u8; 32], Vec<[u8; 16]>);

/// Base storage slot of `Gateway.withdrawDataMap`, the only slot a withdrawal may
/// be read from. `forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout`.
pub const WITHDRAW_DATA_BASE_SLOT: [u8; 32] = {
    let mut slot = [0u8; 32];
    slot[31] = 16;
    slot
};

/// Leaf of the withdrawal accumulator: the Gateway that processed the withdrawal
/// and the graph it was processed for. The slot is fixed by [`WITHDRAW_DATA_BASE_SLOT`].
pub fn withdrawal_leaf(gateway: &[u8; 20], graph_id: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitvm/withdrawal-leaf/v1");
    hasher.update(gateway);
    hasher.update(graph_id);
    hasher.finalize().into()
}

/// One withdrawal in accumulator order, as the host replays it to build inclusion proofs.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct WithdrawalRecord {
    pub block_number: u64,
    pub gateway: [u8; 20],
    pub graph_id: [u8; 16],
}

impl WithdrawalRecord {
    pub fn leaf(&self) -> [u8; 32] {
        withdrawal_leaf(&self.gateway, &self.graph_id)
    }
}

/// The withdrawals of `block` in the order the circuit appends them.
pub fn block_withdrawal_records(block: &CircuitStateBlock) -> Vec<WithdrawalRecord> {
    let block_number = block.evm_block.current_block.number;
    block
        .withdrawals
        .iter()
        .flat_map(|(gateway, _, graph_ids)| {
            graph_ids.iter().map(move |graph_id| WithdrawalRecord {
                block_number,
                gateway: gateway.into_array(),
                graph_id: *graph_id,
            })
        })
        .collect()
}

/// The input proof of the commit chain circuit.
/// The proof can be either None (implying the beginning) or a Succinct proof.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum StateChainPrevProofType {
    GenesisBlock,
    PrevProof,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CircuitStateBlock {
    pub cosmos_txns: Vec<Vec<u8>>,
    // Cosmos light block
    pub cosmos_block: Vec<u8>,
    pub evm_block: EthClientExecutorInput,
    // (gateway contracts, withdraw_data_base_slot, [graph_ids])
    pub withdrawals: Vec<WithdrawalSlot>,
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainState {
    pub evm_block_height: u64,
    pub genesis_evm_block_hash: [u8; 32],
    pub latest_evm_block_hash: [u8; 32],
    pub latest_cosmos_block: Vec<u8>,
    /// Every withdrawal processed since genesis, one [`withdrawal_leaf`] each.
    pub withdrawals: MMRGuest,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitOutput {
    pub chain_state: StateChainState,
    pub self_program_id: verifier::ProgramId,
    pub program_history_hash: [u8; 32],
    pub upgrade_checkpoint_hash: [u8; 32],
}

pub fn classify_state_chain_output(
    public_values: &[u8],
) -> Result<StateChainPrevProofType, String> {
    if deserialize_state_chain_output(public_values).is_ok() {
        return Ok(StateChainPrevProofType::PrevProof);
    }
    Err("unknown state-chain public output format".to_string())
}

fn deserialize_state_chain_output(
    public_values: &[u8],
) -> Result<StateChainCircuitOutput, Box<bincode::ErrorKind>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(public_values)
}

/// Decode current state-chain public values.
pub fn decode_state_chain_circuit_output(public_values: &[u8]) -> StateChainCircuitOutput {
    deserialize_state_chain_output(public_values)
        .expect("failed to decode current state chain circuit output")
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct StateChainCircuitInput {
    pub zkm_proof: Vec<u8>,
    pub zkm_public_values: Vec<u8>,
    pub zkm_vk_hash: Vec<u8>,
    pub zkm_version: String,
    pub self_program_id: verifier::ProgramId,
    pub prev_proof: StateChainPrevProofType,
    pub blocks: Vec<CircuitStateBlock>,
}

impl StateChainState {
    pub fn new(
        evm_block_height: u64,
        genesis_evm_block_hash: [u8; 32],
        latest_cosmos_block: Vec<u8>,
    ) -> Self {
        StateChainState {
            evm_block_height,
            latest_evm_block_hash: genesis_evm_block_hash,
            genesis_evm_block_hash,
            latest_cosmos_block,
            withdrawals: MMRGuest::new(),
        }
    }

    pub fn apply_blocks(&mut self, blocks: Vec<CircuitStateBlock>) {
        for block in blocks {
            // check evm state transition
            let evm_header =
                execute_el_block_and_check_withdraw_tx(&block.withdrawals, block.evm_block.clone());
            assert_eq!(evm_header.number, block.evm_block.current_block.number);
            assert_eq!(evm_header.number, self.evm_block_height);
            let current_block_hash: [u8; 32] = evm_header.hash_slow().into();
            // check the evm block is committed in the consensus txns
            // TODO: we carry the data hash in the state chain block for optimization
            let cosmos_block: LightBlock = serde_json::from_slice(&block.cosmos_block)
                .expect("failed to deserialize cosmos block");
            if current_block_hash != self.genesis_evm_block_hash {
                // Link this block to the one we last applied. Both ends of the
                // chain are committed on Bitcoin - the genesis hash through the
                // commit-chain digest, the final block through the signed cosmos
                // header whose payload names it - so an unforgeable parent chain
                // between them authenticates every intermediate block.
                assert_eq!(
                    evm_header.parent_hash.0, self.latest_evm_block_hash,
                    "evm block does not extend the current chain tip"
                );
                let data_hash: [u8; 32] = cosmos_block
                    .signed_header
                    .header
                    .data_hash
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap();
                check_el_block_from_payload(
                    block.evm_block.current_block.number,
                    &current_block_hash,
                    &self.latest_evm_block_hash,
                    &block.cosmos_txns,
                    &data_hash,
                );
                for record in block_withdrawal_records(&block) {
                    self.withdrawals.append(record.leaf());
                }
            }
            self.evm_block_height += 1;
            self.latest_evm_block_hash = current_block_hash;
            self.latest_cosmos_block = block.cosmos_block;
        }
    }
}

// https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/src/Gateway.sol#L192
// Get base slot:  forge inspect src/GatewayDebug.sol:GatewayDebug storage-layout
pub fn execute_el_block_and_check_withdraw_tx(
    withdrawals: &[WithdrawalSlot],
    input: EthClientExecutorInput,
) -> Header {
    // verify the state transition and withdraw status
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );

    let mut storage_info = vec![];
    withdrawals.iter().for_each(|withdrawal| {
        assert_eq!(withdrawal.1, WITHDRAW_DATA_BASE_SLOT, "withdrawal is not in withdrawDataMap");
        for graph_id in &withdrawal.2 {
            let mut data = [0u8; 32 * 2];
            data[0..16].copy_from_slice(graph_id);
            data[32..].copy_from_slice(&withdrawal.1);
            let slot_id = B256::from(keccak256(data));
            // FIXME: hardcode the value to 1 for now
            storage_info.push((withdrawal.0, slot_id.into(), U256::ONE));
        }
    });

    let (header, _) = executor.execute(input, storage_info).expect("failed to execute client");
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_statechain_apply_blocks() {
        let blocks: Vec<CircuitStateBlock> =
            serde_json::from_slice(include_bytes!("../../../data/state-chain/10346758-10.blocks"))
                .unwrap();
        let block_hash: [u8; 32] = blocks[0].evm_block.current_block.hash_slow().into();
        let block_height = blocks[0].evm_block.current_block.header.number;
        let cosmos_block = blocks[0].cosmos_block.clone();
        let mut chain_state = StateChainState::new(block_height, block_hash, cosmos_block);

        chain_state.apply_blocks(blocks);

        let blocks2: Vec<CircuitStateBlock> =
            serde_json::from_slice(include_bytes!("../../../data/state-chain/10346768-10.blocks"))
                .unwrap();
        chain_state.apply_blocks(blocks2);
    }

    #[test]
    fn withdrawals_accumulate_in_block_order_and_prove_their_gateway() {
        let blocks: Vec<CircuitStateBlock> =
            serde_json::from_slice(include_bytes!("../../../data/state-chain/10346758-10.blocks"))
                .unwrap();
        let block_hash: [u8; 32] = blocks[0].evm_block.current_block.hash_slow().into();
        let block_height = blocks[0].evm_block.current_block.header.number;
        let mut chain_state =
            StateChainState::new(block_height, block_hash, blocks[0].cosmos_block.clone());
        assert_eq!(chain_state.withdrawals.size, 0);

        // The fixture has no withdrawals; a block-level unit check covers the leaf order.
        let gateway = Address::repeat_byte(0x11);
        let other_gateway = Address::repeat_byte(0x22);
        let mut block = blocks[1].clone();
        block.withdrawals = vec![
            (gateway, WITHDRAW_DATA_BASE_SLOT, vec![[1; 16], [2; 16]]),
            (other_gateway, WITHDRAW_DATA_BASE_SLOT, vec![[1; 16]]),
        ];
        let records = block_withdrawal_records(&block);
        assert_eq!(
            records,
            vec![
                WithdrawalRecord {
                    block_number: block.evm_block.current_block.number,
                    gateway: gateway.into_array(),
                    graph_id: [1; 16]
                },
                WithdrawalRecord {
                    block_number: block.evm_block.current_block.number,
                    gateway: gateway.into_array(),
                    graph_id: [2; 16]
                },
                WithdrawalRecord {
                    block_number: block.evm_block.current_block.number,
                    gateway: other_gateway.into_array(),
                    graph_id: [1; 16]
                },
            ]
        );
        let mut host = header_chain::MMRHost::new();
        for record in &records {
            chain_state.withdrawals.append(record.leaf());
            host.append(record.leaf());
        }
        assert_eq!(chain_state.withdrawals.size, 3);
        let (leaf, proof) = host.generate_proof(1);
        assert_eq!(leaf, withdrawal_leaf(&gateway.into_array(), &[2; 16]));
        assert!(chain_state.withdrawals.verify_proof(leaf, &proof));
        // The same graph id under another Gateway is a different leaf.
        assert!(
            !chain_state
                .withdrawals
                .verify_proof(withdrawal_leaf(&other_gateway.into_array(), &[2; 16]), &proof)
        );
        assert_ne!(
            withdrawal_leaf(&gateway.into_array(), &[1; 16]),
            withdrawal_leaf(&other_gateway.into_array(), &[1; 16])
        );
    }

    #[test]
    fn withdrawals_outside_withdraw_data_map_are_rejected() {
        let blocks: Vec<CircuitStateBlock> =
            serde_json::from_slice(include_bytes!("../../../data/state-chain/10346758-10.blocks"))
                .unwrap();
        let mut block = blocks[1].clone();
        block.withdrawals = vec![(Address::repeat_byte(0x11), [0; 32], vec![[1; 16]])];
        let result = std::panic::catch_unwind(|| {
            execute_el_block_and_check_withdraw_tx(&block.withdrawals, block.evm_block.clone())
        });
        assert!(result.is_err());
    }
}
