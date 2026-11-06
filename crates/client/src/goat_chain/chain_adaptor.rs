use crate::btc_chain::MerkleProofExtend;
use crate::goat_chain::goat_adaptor::{GoatAdaptor, GoatInitConfig};
use crate::goat_chain::mock_goat_adaptor::MockAdaptor;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::{
    TransactionReceipt,
    trace::geth::{GethDebugTracingOptions, GethTrace},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use uuid::Uuid;

#[async_trait]
pub trait ChainAdaptor: Send + Sync {
    fn get_default_signer_address(&self) -> Address;
    async fn get_finalized_block_number(&self) -> anyhow::Result<i64>;
    async fn get_latest_block_number(&self) -> anyhow::Result<i64>;
    async fn native_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256>;
    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>>;
    async fn debug_trace_tx(
        &self,
        tx_hash: &str,
        trace_options: Option<GethDebugTracingOptions>,
    ) -> anyhow::Result<GethTrace>;
    #[allow(clippy::too_many_arguments)]
    async fn swap_initialize(
        &self,
        contract_address: Address,
        escrow: SwapEscrowData,
        signature: Bytes,
        timeout: U256,
        extra_data: Bytes,
        value_wei: U256,
        max_wait_secs: u64,
    ) -> anyhow::Result<SwapInitializeResult>;
    async fn extract_initialize_escrow_hash_from_tx(
        &self,
        tx_hash: &str,
        contract_address: Address,
    ) -> anyhow::Result<Option<String>>;

    async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64>;
    async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64>;
    async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64>;
    async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64>;
    async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64>;
    async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<U256>;
    async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64>;
    async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64>;
    async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64>;
    async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]>;
    async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]>;
    async fn gateway_get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData>;
    async fn gateway_get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData>;
    async fn gateway_get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData>;
    async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64>;
    async fn peg_btc_allowance(&self, owner: &[u8; 20], spender: &[u8; 20])
    -> anyhow::Result<U256>;
    async fn peg_btc_approve(&self, spender: &[u8; 20], amount: U256) -> anyhow::Result<String>;

    #[allow(clippy::too_many_arguments)]
    async fn gateway_post_pegin_request(
        &self,
        instance_id: &[u8; 16],
        pegin_amount_sats: u64,
        tx_fees: &[u64; 3],
        receiver_addr: &[u8; 20],
        user_inputs: &[Utxo],
        user_xonly_pubkey: &[u8; 32],
        user_change_addr: &str,
        user_refund_addr: &str,
    ) -> anyhow::Result<String>;

    async fn gateway_answer_pegin_request(
        &self,
        instance_id: &[u8; 16],
        committee_pubkey: &[u8],
    ) -> anyhow::Result<String>;
    async fn gateway_post_pegin_data(
        &self,
        instance_id: &[u8; 16],
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String>;

    async fn gateway_post_graph_data(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        operator_data: &GraphData,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String>;

    async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>>;
    async fn gateway_get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>>;
    async fn gateway_init_withdraw(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
    ) -> anyhow::Result<String>;
    async fn gateway_cancel_withdraw(
        &self,
        graph_id: &[u8; 16],
        nonce: U256,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String>;
    async fn gateway_process_withdraw(
        &self,
        graph_id: &[u8; 16],
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;
    async fn gateway_finish_withdraw_happy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;
    async fn gateway_finish_withdraw_unhappy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;

    #[allow(clippy::too_many_arguments)]
    async fn gateway_finish_withdraw_disproved(
        &self,
        graph_id: &[u8; 16],
        disprove_type: DisproveTxType,
        tx_index: u64,
        raw_challenge_start_tx: &BitcoinTx,
        challenge_start_proof: &BitcoinTxProof,
        raw_challenge_finshish_tx: &BitcoinTx,
        challenge_finish_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String>;

    async fn gateway_get_committee_pubkeys(
        &self,
        instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<Vec<u8>>>;

    async fn gateway_get_post_graph_digest(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        graph_data: GraphData,
    ) -> anyhow::Result<[u8; 32]>;

    async fn gateway_get_post_pegin_digest(
        &self,
        instance_id: &[u8; 16],
        pegin_txid: &[u8; 32],
    ) -> anyhow::Result<[u8; 32]>;

    async fn gateway_get_graph_ids_by_instance_id(
        &self,
        instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<[u8; 16]>>;

    async fn btc_spv_blockhash(&self, height: u64) -> anyhow::Result<[u8; 32]>;
    async fn btc_spv_latest_height(&self) -> anyhow::Result<u64>;
    async fn btc_spv_post_block_hash(
        &self,
        height: u64,
        header_hash: &[u8; 32],
    ) -> anyhow::Result<String>;

    async fn btc_spv_post_block_hash_batch(
        &self,
        heights: &[u64],
        header_hashes: &[[u8; 32]],
    ) -> anyhow::Result<String>;

    async fn ss_update_sequencer_set(
        &self,
        goat_height: U256,
        witness: SequencerSetUpdateWitness,
    ) -> anyhow::Result<String>;

    async fn ss_get_sequencer_set_update_witness(
        &self,
        goat_height: U256,
    ) -> anyhow::Result<Vec<SequencerSetUpdateWitness>>;

    async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]>;
    async fn stake_mana_pubkey_to_address(&self, pubkey: &[u8; 32]) -> anyhow::Result<[u8; 20]>;
    async fn stake_mana_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256>;
    async fn stake_mana_lock_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256>;
    async fn stake_mana_slash_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String>;
    async fn stake_mana_lock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String>;
    async fn stake_mana_unlock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String>;
    async fn committee_mana_is_committee_member(&self, member: &[u8; 20]) -> anyhow::Result<bool>;

    async fn committee_mana_committee_size(&self) -> anyhow::Result<u64>;
    async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64>;
    async fn committee_mana_verify_signatures(
        &self,
        msg_hash: &[u8; 32],
        signs: &[Vec<u8>],
    ) -> anyhow::Result<bool>;

    async fn committee_mana_get_committee_peer_id(
        &self,
        member: &[u8; 20],
    ) -> anyhow::Result<Vec<u8>>;

    async fn committee_mana_is_validate_peer_id(&self, peer_id: &[u8]) -> anyhow::Result<bool>;

    async fn committee_mana_get_watchtowers(&self) -> anyhow::Result<Vec<[u8; 32]>>;
    async fn committee_mana_get_verifiers(&self) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn committee_mana_is_verifier(&self, peer_id: &[u8]) -> anyhow::Result<bool>;
    async fn committee_mana_add_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: U256,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String>;
    async fn committee_mana_remove_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: U256,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String>;

    async fn peg_btc_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256>;
    async fn peg_btc_decimals(&self) -> anyhow::Result<u8>;
}

#[derive(Clone, Debug)]
pub struct SwapEscrowData {
    pub offerer: Address,
    pub claimer: Address,
    pub amount: U256,
    pub token: Address,
    pub flags: U256,
    pub claim_handler: Address,
    pub claim_data: [u8; 32],
    pub refund_handler: Address,
    pub refund_data: [u8; 32],
    pub security_deposit: U256,
    pub claimer_bounty: U256,
    pub deposit_token: Address,
    pub success_action_commitment: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SwapInitializeResult {
    pub tx_hash: String,
    pub escrow_hash: String,
}
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum GoatNetwork {
    Main,
    Test,
    /// Locally hosted network.
    Local,
}

#[derive(Copy, Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Display, EnumString)]
pub enum DisproveTxType {
    Disprove,
    QuickChallenge,
    ChallengeIncompleteKickoff,
    PubinDisprove,
    OperatorChallengeNack,
    OperatorCommitTimeout,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Display)]
pub enum PeginStatus {
    None,
    Pending,
    Withdrawable,
    Processing,
    Locked,
    Claimed,
    Discarded,
}
impl From<u8> for PeginStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeginStatus::None,
            1 => PeginStatus::Processing,
            2 => PeginStatus::Withdrawable,
            3 => PeginStatus::Locked,
            4 => PeginStatus::Claimed,
            _ => PeginStatus::None,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Display)]
pub enum WithdrawStatus {
    None,
    Processing,
    Initialized,
    Canceled,
    Complete,
    Disproved,
}
impl From<u8> for WithdrawStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => WithdrawStatus::None,
            1 => WithdrawStatus::Processing,
            2 => WithdrawStatus::Initialized,
            3 => WithdrawStatus::Canceled,
            4 => WithdrawStatus::Complete,
            5 => WithdrawStatus::Disproved,
            _ => WithdrawStatus::None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount_sats: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeginData {
    pub status: PeginStatus,
    pub instance_id: [u8; 16],
    pub depositor_address: [u8; 20],
    pub pegin_amount_sats: u64,
    pub txn_fees: [u64; 3],
    pub user_inputs: Vec<Utxo>,
    pub user_xonly_pubkey: [u8; 32],
    pub user_change_addr: String,
    pub user_refund_addr: String,
    pub pegin_txid: [u8; 32],
    pub created_at: u64,
    pub committee_addresses: Vec<Address>,
    pub committee_pubkeys: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawData {
    pub pegin_txid: [u8; 32],
    pub operator_address: [u8; 20],
    pub status: WithdrawStatus,
    pub instance_id: [u8; 16],
    pub lock_amount: U256,
    pub btc_block_height_withdraw: U256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphData {
    pub operator_pubkey_prefix: u8,
    pub operator_pubkey: [u8; 32],
    pub pegin_txid: [u8; 32],
    pub kickoff_txid: [u8; 32],
    pub take1_txid: [u8; 32],
    pub take2_txid: [u8; 32],
    pub watchtower_challenge_init_txid: [u8; 32],
    pub prover_assert_txid: [u8; 32],
    pub disprove_txids: Vec<[u8; 32]>,
    pub watchtower_challenge_timeout_txids: Vec<[u8; 32]>,
    pub operator_challenge_nack_txids: Vec<[u8; 32]>,
    pub operator_commit_timeout_txid: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BitcoinTx {
    pub version: u32,
    pub input_vector: Vec<u8>,
    pub output_vector: Vec<u8>,
    pub lock_time: u32,
}

#[derive(Clone, Debug)]
pub struct BitcoinTxProof {
    pub raw_header: Vec<u8>,
    pub height: u64,
    pub proof: Vec<[u8; 32]>,
    pub index: u64,
}

impl From<MerkleProofExtend> for BitcoinTxProof {
    fn from(data: MerkleProofExtend) -> Self {
        Self {
            raw_header: data.raw_header,
            height: data.height,
            proof: data.merkle,
            index: data.index,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SequencerSetUpdateWitness {
    pub sig_hash: [u8; 32],
    pub btc_pub_key: Vec<u8>,
    pub btc_sig: Vec<u8>,
}

pub fn get_chain_adaptor(
    network: GoatNetwork,
    goat_config: GoatInitConfig,
) -> Box<dyn ChainAdaptor> {
    match network {
        //GoatAdaptor
        GoatNetwork::Main => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Test => Box::new(GoatAdaptor::new(goat_config)),
        GoatNetwork::Local => Box::new(MockAdaptor::new()),
    }
}
