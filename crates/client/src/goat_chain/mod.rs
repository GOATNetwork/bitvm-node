// Gateway rate multiplier constant
const GATEWAY_RATE_MULTIPLIER: u64 = 10000;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::{
    TransactionReceipt,
    trace::geth::{GethDebugTracingOptions, GethTrace},
};
use anyhow::bail;
use bitcoin::hashes::Hash;
use bitcoin::{PublicKey, Transaction, Txid, XOnlyPublicKey};
use uuid::Uuid;
pub mod utils;
use crate::btc_chain::{BTCClient, MerkleProofExtend};
pub use chain_adaptor::{
    BitcoinTx, BitcoinTxProof, GoatNetwork, GraphData, PeginData, PeginStatus,
    SequencerSetUpdateWitness, SwapEscrowData, SwapInitializeResult, WithdrawData, WithdrawStatus,
    get_chain_adaptor,
};
pub use goat_adaptor::GoatInitConfig;
mod chain_adaptor;
mod evmchain;
mod goat_adaptor;
mod mock_goat_adaptor;
use crate::goat_chain::evmchain::EvmChain;
use crate::goat_chain::mock_goat_adaptor::MockAdaptor;
pub use chain_adaptor::{DisproveTxType, Utxo};

pub struct GOATClient {
    chain_service: EvmChain,
}
impl GOATClient {
    pub fn new(goat_init_config: GoatInitConfig, goat_network: GoatNetwork) -> Self {
        GOATClient {
            chain_service: EvmChain::new(get_chain_adaptor(goat_network, goat_init_config)),
        }
    }

    pub fn new_mock_client() -> (Self, MockAdaptor) {
        let mock_adaptor = MockAdaptor::new();
        (GOATClient { chain_service: EvmChain::new(Box::new(mock_adaptor.clone())) }, mock_adaptor)
    }

    pub fn get_default_signer_address(&self) -> Address {
        self.chain_service.get_default_signer_address()
    }

    pub async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]> {
        self.chain_service.gateway_get_committee_management().await
    }

    pub async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]> {
        self.chain_service.gateway_get_stake_management().await
    }
    pub async fn gateway_get_pegin_data(&self, instance_id: &Uuid) -> anyhow::Result<PeginData> {
        self.chain_service.gateway_get_pegin_data(instance_id).await
    }

    pub async fn gateway_get_graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
        self.chain_service.gateway_get_graph_data(graph_id).await
    }

    pub async fn gateway_get_withdraw_data(&self, graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        self.chain_service.gateway_get_withdraw_data(graph_id).await
    }

    pub async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.chain_service.gateway_get_initialized_ids().await
    }

    pub async fn get_tx_receipt(
        &self,
        tx_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.chain_service.get_tx_receipt(tx_hash).await
    }

    pub async fn debug_trace_tx(
        &self,
        tx_hash: &str,
        trace_options: Option<GethDebugTracingOptions>,
    ) -> anyhow::Result<GethTrace> {
        self.chain_service.debug_trace_tx(tx_hash, trace_options).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn swap_initialize(
        &self,
        contract_address: Address,
        escrow: SwapEscrowData,
        signature: Bytes,
        timeout: U256,
        extra_data: Bytes,
        value_wei: U256,
        max_wait_secs: u64,
    ) -> anyhow::Result<SwapInitializeResult> {
        self.chain_service
            .swap_initialize(
                contract_address,
                escrow,
                signature,
                timeout,
                extra_data,
                value_wei,
                max_wait_secs,
            )
            .await
    }

    pub async fn extract_initialize_escrow_hash_from_tx(
        &self,
        tx_hash: &str,
        contract_address: Address,
    ) -> anyhow::Result<Option<String>> {
        self.chain_service.extract_initialize_escrow_hash_from_tx(tx_hash, contract_address).await
    }

    pub async fn is_committee_member(&self) -> anyhow::Result<bool> {
        let addr = self.get_default_signer_address();
        self.committee_mana_is_committee_member(&addr).await
    }

    // Add all EvmChain methods to GOATClient
    pub async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        self.chain_service.get_finalized_block_number().await
    }

    pub async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        self.chain_service.get_latest_block_number().await
    }

    pub async fn native_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256> {
        self.chain_service.native_balance(address).await
    }

    pub async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_response_window_blocks().await
    }

    pub async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_challenge_amount_sats().await
    }

    pub async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_pegin_fee_sats().await
    }

    pub async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_pegin_fee_rate().await
    }

    pub async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_operator_reward_sats().await
    }

    pub async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_operator_reward_rate().await
    }

    pub async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<U256> {
        self.chain_service.gateway_get_min_stake_amount().await
    }

    pub async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_challenger_reward().await
    }

    pub async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_disprover_reward().await
    }

    pub async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64> {
        self.chain_service.gateway_get_min_slash_amount().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn gateway_post_pegin_request(
        &self,
        instance_id: &Uuid,
        pegin_amount_sats: u64,
        tx_fees: &[u64; 3],
        receiver_addr: &[u8; 20],
        user_inputs: &[Utxo],
        user_xonly_pubkey: &[u8; 32],
        user_change_addr: &str,
        user_refund_addr: &str,
    ) -> anyhow::Result<String> {
        let pegin_data = self.gateway_get_pegin_data(instance_id).await?;
        if pegin_data.status != PeginStatus::None {
            tracing::warn!("instance_id:{instance_id} instanceId already used",);
            bail!("instance_id:{instance_id} instanceId already used",);
        }
        self.chain_service
            .gateway_post_pegin_request(
                instance_id,
                pegin_amount_sats,
                tx_fees,
                receiver_addr,
                user_inputs,
                user_xonly_pubkey,
                user_change_addr,
                user_refund_addr,
            )
            .await
    }

    pub async fn gateway_answer_pegin_request(
        &self,
        instance_id: &Uuid,
        committee_pubkey: &PublicKey,
    ) -> anyhow::Result<String> {
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let pegin_data = self.gateway_get_pegin_data(instance_id).await?;
        if pegin_data.status != PeginStatus::Pending {
            tracing::warn!(
                "instance_id:{instance_id} pegin_data.status is {}, not PeginStatus::Pending",
                pegin_data.status,
            );
            bail!(
                "instance_id:{instance_id} pegin_data.status is {}, not PeginStatus::Pending",
                pegin_data.status,
            );
        }
        let next_block = self.get_latest_block_number().await? + 1;
        let window_blocks = self.gateway_get_response_window_blocks().await?;
        if pegin_data.created_at + window_blocks < next_block as u64 {
            tracing::warn!(
                "instance_id:{instance_id} response window expired. created_at:{}, window_blocks: {window_blocks}, next_block: {next_block}",
                pegin_data.created_at,
            );
            bail!(
                "instance_id:{instance_id} response window expired. created_at:{}, window_blocks: {window_blocks}, next_block: {next_block}",
                pegin_data.created_at,
            );
        }

        self.chain_service
            .gateway_answer_pegin_request(instance_id, &committee_pubkey.to_bytes())
            .await
    }

    pub async fn gateway_get_instanceids_by_pubkey(
        &self,
        operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        self.chain_service.gateway_get_instanceids_by_pubkey(operator_pubkey).await
    }

    pub async fn gateway_init_withdraw(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<String> {
        self.chain_service.gateway_init_withdraw(instance_id, graph_id).await
    }

    pub async fn gateway_cancel_withdraw(
        &self,
        graph_id: &Uuid,
        nonce: U256,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        self.chain_service.gateway_cancel_withdraw(graph_id, nonce, committee_signs).await
    }

    pub async fn gateway_process_withdraw(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let operator_data = self.gateway_get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.kickoff_txid)?;
        let tx_proof_data = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "withdraw",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Initialized),
            )
            .await?;
        let raw_kickoff_tx = tx_reconstruct(tx);
        self.chain_service
            .gateway_process_withdraw(graph_id, &raw_kickoff_tx, &tx_proof_data.into())
            .await
    }
    pub async fn gateway_finish_withdraw_happy_path(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let operator_data = self.gateway_get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.take1_txid)?;
        let tx_proof_data = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "take1",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Processing),
            )
            .await?;
        let raw_take1_tx = tx_reconstruct(tx);
        self.chain_service
            .gateway_finish_withdraw_happy_path(graph_id, &raw_take1_tx, &tx_proof_data.into())
            .await
    }

    pub async fn gateway_finish_withdraw_unhappy_path(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        tx: &bitcoin::Transaction,
    ) -> anyhow::Result<String> {
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let operator_data = self.gateway_get_graph_data(graph_id).await?;
        let tx_id_on_line = Txid::from_slice(&operator_data.take2_txid)?;
        let tx_proof_data = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "take2",
                graph_id,
                &tx.compute_txid(),
                &tx_id_on_line,
                Some(WithdrawStatus::Processing),
            )
            .await?;
        let raw_take2_tx = tx_reconstruct(tx);
        self.chain_service
            .gateway_finish_withdraw_unhappy_path(graph_id, &raw_take2_tx, &tx_proof_data.into())
            .await
    }

    pub async fn gateway_finish_withdraw_disproved(
        &self,
        btc_client: &BTCClient,
        graph_id: &Uuid,
        disprove_type: DisproveTxType,
        tx_index: u64,
        challenge_start_tx: Option<&Transaction>,
        challenge_finish_tx: &Transaction,
    ) -> anyhow::Result<String> {
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let (raw_challenge_start_tx, challenge_start_proof) = match challenge_start_tx {
            Some(challenge_start_tx) => {
                let tx_proof_data = self
                    .check_withdraw_actions_and_get_proof(
                        btc_client,
                        "challenge_start",
                        graph_id,
                        &challenge_start_tx.compute_txid(),
                        &challenge_start_tx.compute_txid(),
                        None,
                    )
                    .await?;
                let raw_challenge_start_tx = tx_reconstruct(challenge_start_tx);
                let challenge_start_proof: BitcoinTxProof = tx_proof_data.into();
                (raw_challenge_start_tx, challenge_start_proof)
            }
            None => {
                // if no challengeStartTx happens, set rawChallengeStartTx.inputVector to empty
                if !matches!(
                    disprove_type,
                    DisproveTxType::QuickChallenge
                        | DisproveTxType::ChallengeIncompleteKickoff
                        | DisproveTxType::PubinDisprove
                        | DisproveTxType::OperatorChallengeNack
                        | DisproveTxType::OperatorCommitTimeout
                ) {
                    bail!("challenge_start_tx is required for disprove type {disprove_type:?}");
                }
                let raw_challenge_start_tx = BitcoinTx {
                    version: 0,
                    lock_time: 0,
                    input_vector: vec![],
                    output_vector: vec![],
                };
                let challenge_start_proof =
                    BitcoinTxProof { raw_header: vec![], height: 0, proof: vec![], index: 0 };
                (raw_challenge_start_tx, challenge_start_proof)
            }
        };
        let tx_proof_data = self
            .check_withdraw_actions_and_get_proof(
                btc_client,
                "challenge_finish",
                graph_id,
                &challenge_finish_tx.compute_txid(),
                &challenge_finish_tx.compute_txid(),
                None,
            )
            .await?;
        let raw_challenge_finish_tx = tx_reconstruct(challenge_finish_tx);
        let challenge_finish_proof: BitcoinTxProof = tx_proof_data.into();
        self.chain_service
            .gateway_finish_withdraw_disproved(
                graph_id,
                disprove_type,
                tx_index,
                &raw_challenge_start_tx,
                &challenge_start_proof,
                &raw_challenge_finish_tx,
                &challenge_finish_proof,
            )
            .await
    }

    pub async fn gateway_post_pegin_data(
        &self,
        btc_client: &BTCClient,
        instance_id: &Uuid,
        tx: &bitcoin::Transaction,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let tx_id = tx.compute_txid();
        tracing::info!("post_pegin_data instance_id:{instance_id}, pegin_tx:{}", tx_id.to_string());
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        let pegin_data = self.gateway_get_pegin_data(instance_id).await?;
        if pegin_data.status != PeginStatus::Pending {
            tracing::warn!("instance_id:{instance_id} not a pending pegin request",);
            bail!("instance_id:{instance_id} not a pending pegin request",);
        }

        if tx.output[0].value.to_sat() != pegin_data.pegin_amount_sats {
            tracing::warn!("instance_id:{instance_id} pegin amount mismatch",);
            bail!("instance_id:{instance_id} pegin amount mismatch",);
        }

        let tx_proof_data = btc_client.get_merkle_proof_extend(&tx_id).await?;

        let block_hash_online = self.btc_spv_blockhash(tx_proof_data.height).await?;
        if block_hash_online != tx_proof_data.block_hash {
            tracing::warn!(
                "instance_id:{instance_id}  block_hash mismatch, from chain:{}, in contract:{}",
                hex::encode(tx_proof_data.block_hash),
                hex::encode(block_hash_online)
            );
            // The SPV contract is written only by the relayer, which posts
            // confirmed blocks; never overwrite it from this node's esplora view.
            bail!(
                "instance_id:{instance_id}  block_hash mismatch, from chain:{}, in contract:{}",
                hex::encode(tx_proof_data.block_hash),
                hex::encode(block_hash_online)
            );
        }
        let pegin_amount_sats = tx.output[0].value.to_sat();
        let min_pegin_fee_sats = self.gateway_get_min_pegin_fee_sats().await?;
        let pegin_fee_rate = self.gateway_get_pegin_fee_rate().await?;
        let pegin_fee_sats =
            min_pegin_fee_sats + pegin_amount_sats * pegin_fee_rate / GATEWAY_RATE_MULTIPLIER;
        if pegin_fee_sats >= pegin_amount_sats {
            tracing::warn!(
                "instance_id:{instance_id} pegin amount:{pegin_amount_sats} cannot cover fee:{pegin_fee_sats}"
            );
            bail!(
                "instance_id:{instance_id} pegin amount:{pegin_amount_sats} cannot cover fee:{pegin_fee_sats}"
            );
        }

        let raw_pegin_tx = tx_reconstruct(tx);
        self.chain_service
            .gateway_post_pegin_data(
                instance_id,
                &raw_pegin_tx,
                &tx_proof_data.into(),
                committee_signs,
            )
            .await
    }

    pub async fn gateway_post_graph_data(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        graph_data: &GraphData,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        tracing::info!("post_operate_data instance_id:{}, graph_id:{}", instance_id, graph_id);
        if !self.is_committee_member().await? {
            bail!("only committee member can call");
        }
        // check operator register
        let operator_stake_addr =
            self.stake_mana_pubkey_to_address(&graph_data.operator_pubkey).await?;
        if operator_stake_addr == [0_u8; 20] {
            tracing::warn!("instance_id:{instance_id} graph_id {graph_id} operator not registered",);
            bail!("instance_id:{instance_id} graph_id {graph_id} operator not registered");
        }
        let min_stake_amount = self.gateway_get_min_stake_amount().await?;
        let locked_stake = self.stake_mana_lock_stake_of(&operator_stake_addr).await?;
        if locked_stake < min_stake_amount {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} insufficient operator stake,\
                 as locked_stake: {locked_stake}, min_stake_amount:{min_stake_amount}",
            );
            bail!(
                "instance_id:{instance_id} graph_id {graph_id} insufficient operator stake, \
                as locked_stake: {locked_stake}, min_stake_amount:{min_stake_amount}"
            );
        }

        // TODO committeeSigs

        let graph_data_online = self.gateway_get_graph_data(graph_id).await?;
        if graph_data_online.pegin_txid != [0_u8; 32] {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} graph data already posted",
            );
            bail!("instance_id:{instance_id} graph_id {graph_id} graph data already posted");
        }

        let pegin_data = self.gateway_get_pegin_data(instance_id).await?;
        if pegin_data.pegin_txid != graph_data.pegin_txid {
            tracing::warn!(
                "instance_id:{instance_id} graph_id {graph_id} graph data pegin txid mismatch, exp:{},  act:{}",
                hex::encode(pegin_data.pegin_txid),
                hex::encode(graph_data.pegin_txid),
            );
            bail!(
                "instance_id:{instance_id} graph_id {graph_id} graph data pegin txid mismatch, exp:{},  act:{}",
                hex::encode(pegin_data.pegin_txid),
                hex::encode(graph_data.pegin_txid),
            );
        }

        self.chain_service
            .gateway_post_graph_data(instance_id, graph_id, graph_data, committee_signs)
            .await
    }
    pub async fn check_withdraw_actions_and_get_proof(
        &self,
        btc_client: &BTCClient,
        tag: &str,
        graph_id: &Uuid,
        tx_act: &Txid,
        tx_id_on_line: &Txid,
        required_status: Option<WithdrawStatus>,
    ) -> anyhow::Result<MerkleProofExtend> {
        // check tx id match
        if tx_id_on_line.ne(tx_act) {
            tracing::warn!(
                "graph:{} at {} mismatch, exp:{},  act:{}",
                tag,
                graph_id,
                tx_id_on_line.to_string(),
                tx_act.to_string()
            );
            bail!("graph:{tag} at {graph_id} txid mismatch, exp:{tx_id_on_line},  act:{tx_act}",);
        }

        // check withdraw status
        if let Some(status) = required_status {
            let withdraw_data = self.gateway_get_withdraw_data(graph_id).await?;
            if withdraw_data.status == WithdrawStatus::Disproved {
                tracing::warn!("graph:{tag} at {graph_id} stage already disproved");
                bail!("graph:{tag} at {graph_id} stagealready disproved");
            } else if withdraw_data.status != status {
                tracing::warn!(
                    "graph:{tag} at {graph_id} stage not match, exp: {status}, act: {}",
                    withdraw_data.status
                );
                bail!(
                    "graph:{} at {} stage not match, exp: {status}, act: {}",
                    tag,
                    graph_id,
                    withdraw_data.status
                );
            }
        }
        // check hash in btc chain and spv contract
        let tx_proof_data = btc_client.get_merkle_proof_extend(tx_act).await?;

        let block_hash_online = self.btc_spv_blockhash(tx_proof_data.height).await?;
        if block_hash_online != tx_proof_data.block_hash {
            tracing::warn!(
                "graph:{tag} at {graph_id} block_hash mismatch, from chain:{},  in contract:{}",
                hex::encode(tx_proof_data.block_hash),
                hex::encode(block_hash_online)
            );

            // The SPV contract is written only by the relayer, which posts
            // confirmed blocks; never overwrite it from this node's esplora view.
            bail!(
                "graph:{tag} at {graph_id} block_hash mismatch, from chain:{},  in contract:{}",
                hex::encode(tx_proof_data.block_hash),
                hex::encode(block_hash_online)
            );
        }
        Ok(tx_proof_data)
    }
    pub async fn gateway_get_committee_pubkeys(
        &self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<PublicKey>> {
        let pubkeys = self.chain_service.gateway_get_committee_pubkeys(instance_id).await?;
        Ok(pubkeys.iter().filter_map(|v| PublicKey::from_slice(v).ok()).collect::<Vec<PublicKey>>())
    }

    pub async fn gateway_get_post_graph_digest(
        &self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        graph_data: GraphData,
    ) -> anyhow::Result<[u8; 32]> {
        self.chain_service.gateway_get_post_graph_digest(instance_id, graph_id, graph_data).await
    }

    pub async fn gateway_get_post_pegin_digest(
        &self,
        instance_id: &Uuid,
        pegin_txid: &Txid,
    ) -> anyhow::Result<[u8; 32]> {
        self.chain_service.gateway_get_post_pegin_digest(instance_id, pegin_txid).await
    }
    pub async fn btc_spv_blockhash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        self.chain_service.btc_spv_blockhash(height).await
    }

    pub async fn btc_spv_latest_height(&self) -> anyhow::Result<u64> {
        self.chain_service.btc_spv_latest_height().await
    }

    pub async fn btc_spv_post_block_hash(
        &self,
        height: u64,
        header_hash: &[u8; 32],
    ) -> anyhow::Result<String> {
        self.chain_service.btc_spv_post_block_hash(height, header_hash).await
    }

    pub async fn btc_spv_post_block_hash_batch(
        &self,
        heights: &[u64],
        header_hashes: &[[u8; 32]],
    ) -> anyhow::Result<String> {
        self.chain_service.btc_spv_post_block_hash_batch(heights, header_hashes).await
    }
    pub async fn gateway_get_graph_ids_by_instance_id(
        &self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<Uuid>> {
        self.chain_service.gateway_get_graph_ids_by_instance_id(instance_id).await
    }

    pub async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]> {
        self.chain_service.stake_mana_stake_token_address().await
    }
    pub async fn stake_mana_pubkey_to_address(
        &self,
        pubkey: &[u8; 32],
    ) -> anyhow::Result<[u8; 20]> {
        self.chain_service.stake_mana_pubkey_to_address(pubkey).await
    }
    pub async fn stake_mana_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256> {
        self.chain_service.stake_mana_stake_of(operator).await
    }
    pub async fn stake_mana_lock_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256> {
        self.chain_service.stake_mana_lock_stake_of(operator).await
    }
    pub async fn stake_mana_slash_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.chain_service.stake_mana_slash_stake(operator, amount).await
    }

    pub async fn stake_mana_lock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.chain_service.stake_mana_lock_stake(operator, amount).await
    }
    pub async fn stake_mana_unlock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        self.chain_service.stake_mana_unlock_stake(operator, amount).await
    }
    pub async fn committee_mana_is_committee_member(
        &self,
        member: &[u8; 20],
    ) -> anyhow::Result<bool> {
        self.chain_service.committee_mana_is_committee_member(member).await
    }

    pub async fn committee_mana_committee_size(&self) -> anyhow::Result<u64> {
        self.chain_service.committee_mana_committee_size().await
    }
    pub async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64> {
        self.chain_service.committee_mana_quorum_size().await
    }
    pub async fn committee_mana_verify_signatures(
        &self,
        msg_hash: &[u8; 32],
        signs: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        self.chain_service.committee_mana_verify_signatures(msg_hash, signs).await
    }

    pub async fn committee_mana_get_committee_peer_id(
        &self,
        member: &[u8; 20],
    ) -> anyhow::Result<Vec<u8>> {
        self.chain_service.committee_mana_get_committee_peer_id(member).await
    }

    pub async fn committee_mana_is_validate_peer_id(&self, peer_id: &[u8]) -> anyhow::Result<bool> {
        self.chain_service.committee_mana_is_validate_peer_id(peer_id).await
    }

    pub async fn committee_mana_get_watchtowers(&self) -> anyhow::Result<Vec<XOnlyPublicKey>> {
        let watchtowers = self.chain_service.committee_mana_get_watchtowers().await?;
        Ok(watchtowers
            .iter()
            .filter_map(|v| XOnlyPublicKey::from_slice(v).ok())
            .collect::<Vec<XOnlyPublicKey>>())
    }

    pub async fn committee_mana_get_verifiers(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        self.chain_service.committee_mana_get_verifiers().await
    }

    pub async fn committee_mana_is_verifier(&self, peer_id: &[u8]) -> anyhow::Result<bool> {
        self.chain_service.committee_mana_is_verifier(peer_id).await
    }

    pub async fn committee_mana_add_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: u64,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        self.chain_service.committee_mana_add_watchtower(watchtower, nonce, auth_signs).await
    }

    pub async fn committee_mana_remove_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: u64,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        self.chain_service.committee_mana_remove_watchtower(watchtower, nonce, auth_signs).await
    }

    pub async fn peg_btc_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256> {
        self.chain_service.peg_btc_balance(address).await
    }

    pub async fn peg_btc_decimals(&self) -> anyhow::Result<u8> {
        self.chain_service.peg_btc_decimals().await
    }

    pub async fn peg_btc_allowance(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
    ) -> anyhow::Result<U256> {
        self.chain_service.peg_btc_allowance(owner, spender).await
    }

    pub async fn peg_btc_approve(
        &self,
        spender: &[u8; 20],
        amount: U256,
    ) -> anyhow::Result<String> {
        self.chain_service.peg_btc_approve(spender, amount).await
    }

    pub async fn ss_update_sequencer_set(
        &self,
        goat_height: u64,
        witness: SequencerSetUpdateWitness,
    ) -> anyhow::Result<String> {
        let goat_height = U256::from(goat_height);
        self.chain_service.ss_update_sequencer_set(goat_height, witness).await
    }

    pub async fn ss_get_sequencer_set_update_witness(
        &self,
        goat_height: u64,
    ) -> anyhow::Result<Vec<SequencerSetUpdateWitness>> {
        let goat_height = U256::from(goat_height);
        self.chain_service.ss_get_sequencer_set_update_witness(goat_height).await
    }
}

pub fn tx_reconstruct(tx: &bitcoin::Transaction) -> BitcoinTx {
    BitcoinTx {
        version: tx.version.0 as u32,
        lock_time: tx.lock_time.to_consensus_u32(),
        input_vector: bitcoin::consensus::serialize(&tx.input),
        output_vector: bitcoin::consensus::serialize(&tx.output),
    }
}

// remove me later
#[cfg(test)]
mod tests {
    use crate::goat_chain::GOATClient;
    use crate::goat_chain::mock_goat_adaptor::GatewayContractConfig;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mack_goat_client() -> anyhow::Result<()> {
        let (mock_client, mock_adaptor) = GOATClient::new_mock_client();
        let min_challenge_amount_sats = 20000000;
        mock_adaptor.set_gateway_contract_config(GatewayContractConfig {
            min_challenge_amount_sats,
            min_pegin_fee_sats: 0,
            pegin_fee_rate: 0,
            min_operator_reward_sats: 0,
            operator_reward_rate: 0,
            min_stake_amount: 0,
            min_challenger_reward: 0,
            min_disprover_reward: 0,
            min_slash_amount: 0,
        });
        let min_challenge_amount_sats_act =
            mock_client.gateway_get_min_challenge_amount_sats().await?;
        assert_eq!(min_challenge_amount_sats, min_challenge_amount_sats_act);
        Ok(())
    }
}
