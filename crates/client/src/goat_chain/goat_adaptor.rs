use crate::goat_chain::chain_adaptor::{
    BitcoinTx, BitcoinTxProof, ChainAdaptor, DisproveTxType, GraphData, PeginData, PeginStatus,
    SequencerSetUpdateWitness, SwapEscrowData, SwapInitializeResult, Utxo, WithdrawData,
    WithdrawStatus,
};
use crate::goat_chain::goat_adaptor::IBitcoinSPV::IBitcoinSPVInstance;
use crate::goat_chain::goat_adaptor::ICommitteeManagement::ICommitteeManagementInstance;
use crate::goat_chain::goat_adaptor::IGateway::IGatewayInstance;
use crate::goat_chain::goat_adaptor::IPegBtc::IPegBtcInstance;
use crate::goat_chain::goat_adaptor::ISequencerSetPublisher::ISequencerSetPublisherInstance;
use crate::goat_chain::goat_adaptor::IStakeManagement::IStakeManagementInstance;
use crate::timeout_config::get_goat_rpc_timeout_secs;
use alloy::eips::BlockNumberOrTag;
use alloy::providers::Identity;
use alloy::providers::ext::DebugApi;
use alloy::providers::fillers::{FillProvider, JoinFill, RecommendedFillers};
use alloy::rpc::types::TransactionReceipt;
use alloy::rpc::types::trace::geth::{CallConfig, GethDebugTracingOptions, GethTrace};
use alloy::transports::http::reqwest::Client as AlloyReqwestClient;
use alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet, eip2718::Encodable2718},
    primitives::{Address, B256, Bytes, ChainId, FixedBytes, TxHash, U256, keccak256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionRequest,
    signers::{Signer, local::PrivateKeySigner},
    sol,
    sol_types::SolValue,
    transports::http::reqwest::Url,
};
use anyhow::{bail, format_err};
use async_trait::async_trait;
use std::str::FromStr;
use std::time::Duration;
use tokio::time;
use uuid::Uuid;

const EIP1559_PRIORITY_FEE_WEI: u128 = 5_000_000;
const EIP1559_MAX_BASE_FEE_WEI: u128 = 2_000_000_000;
const EIP1559_BASE_FEE_MULTIPLIER_NUM: u128 = 125;
const EIP1559_BASE_FEE_MULTIPLIER_DEN: u128 = 100;

fn build_goat_rpc_client() -> AlloyReqwestClient {
    let timeout = Duration::from_secs(get_goat_rpc_timeout_secs());
    match AlloyReqwestClient::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                "failed to build GOAT RPC reqwest client with timeout: {err}, fallback to default client"
            );
            AlloyReqwestClient::new()
        }
    }
}

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface IGateway {
        enum DisproveTxType {
            Disprove,
            QuickChallenge,
            ChallengeIncompleteKickoff,
            PubinDisprove,
            OperatorChallengeNack,
            OperatorCommitTimeout
        }
        enum PeginStatus {
            None,
            Pending,
            Withdrawable,
            Processing,
            Locked,
            Claimed,
            Discarded
        }
        enum WithdrawStatus {
            None,
            Processing,
            Initialized,
            Canceled,
            Complete,
            Disproved
        }

        struct Utxo {
             bytes32 txid;
             uint32 vout;
             uint64 amountSats;
        }

        struct PeginData {
             PeginStatus status;
             bytes16 instanceId;
             address depositorAddress;
             uint64 peginAmountSats;
             uint64[3] txnFees;
             Utxo[] userInputs;
             bytes32 userXonlyPubkey;
             string userChangeAddress;
             string userRefundAddress;
             bytes32 peginTxid;
             uint256 createdAt;
             address[] committeeAddresses;
             bytes[] committeePubkeys;
        }
        struct WithdrawData {
            WithdrawStatus status;
            bytes32 peginTxid;
            address operatorAddress;
            bytes16 instanceId;
            uint256 lockAmount;
            uint256 btcBlockHeightAtWithdraw;
        }

        struct GraphData {
            bytes1 operatorPubkeyPrefix;
            bytes32 operatorPubkey;
            bytes32 peginTxid;
            bytes32 kickoffTxid;
            bytes32 take1Txid;
            bytes32 take2Txid;
            bytes32 watchtowerChallengeInitTxid;
            bytes32 proverAssertTxid;
            bytes32[] verifierAssertTxids;
            bytes32[] watchtowerChallengeTimeoutTxids;
            bytes32[] operatorChallengeNackTxids;
            bytes32 operatorCommitTimeoutTxid;
        }

        struct BitcoinTx {
            bytes4 version;
            bytes inputVector;
            bytes outputVector;
            bytes4 locktime;
        }

        struct BitcoinTxProof {
            bytes rawHeader;
            uint256 height;
            bytes32[] proof;
            uint256 index;
        }

        // uint64 constant rateMultiplier = 10000;

        uint64 public minChallengeAmountSats;
        uint64 public minPeginFeeSats;
        uint64 public peginFeeRate;
        uint64 public minOperatorRewardSats;
        uint64 public operatorRewardRate;
        uint256 public minStakeAmount;
        uint256 public minChallengerReward;
        uint256 public minDisproverReward;
        uint256 public minSlashAmount;

        address public  pegBTC;
        address public  bitcoinSPV;
        address public  committeeManagement;
        address public  stakeManagement;

        uint256 public responseWindowBlocks;
        bytes16[] public instanceIds;
        mapping(bytes16 graphId => GraphData) public graphDataMap;
        mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;
        mapping(bytes16 instanceId => bytes16[] graphIds)
        public instanceIdToGraphIds;

        function postPeginRequest(bytes16 instanceId, uint64 peginAmountSats, uint64[3] calldata txnFees, address receiverAddress, Utxo[] calldata userInputs, bytes32 userXonlyPubkey, string calldata userChangeAddress, string calldata userRefundAddress) external payable;
        function answerPeginRequest(bytes16 instanceId, bytes committeeXonlyPubkey) onlyCommittee() external;
        function postPeginData(bytes16 instanceId, BitcoinTx calldata rawPeginTx, BitcoinTxProof calldata peginProof, bytes[] calldata committeeSigs) external;
        function getPeginData(bytes16 instanceId) external view returns (PeginData memory);
        function postGraphData(bytes16 instanceId, bytes16 graphId, GraphData calldata graphData, bytes[] calldata committeeSigs) public;
        function getGraphData(bytes16 graphId) external view returns (GraphData memory);
        function initWithdraw(bytes16 instanceId, bytes16 graphId) external;
        function committeeCancelWithdraw(bytes16 graphId, uint256 nonce, bytes[] calldata committeeSigs) external;
        function proceedWithdraw(bytes16 graphId, BitcoinTx calldata rawKickoffTx, BitcoinTxProof calldata kickoffProof) external;
        function finishWithdrawHappyPath(bytes16 graphId, BitcoinTx calldata rawTake1Tx, BitcoinTxProof calldata take1Proof) external;
        function finishWithdrawUnhappyPath(bytes16 graphId, BitcoinTx calldata rawTake2Tx, BitcoinTxProof calldata take2Proof) external;
        function finishWithdrawDisproved(bytes16 graphId, DisproveTxType disproveTxType, uint256 txnIndex, BitcoinTx calldata rawChallengeStartTx, BitcoinTxProof calldata challengeStartTxProof, BitcoinTx calldata rawChallengeFinishTx, BitcoinTxProof calldata challengeFinishTxProof ) external;
        function getCommitteePubkeys(bytes16 instanceId) public view returns (bytes[] memory committeePubkeys);
        function getCommitteeAddresses(bytes16 instanceId) public view returns (address[] memory committeeAddresses);
        function getCommitteePubkeysUnsafe(bytes16 instanceId) public view returns (bytes[] memory committeePubkeys);
        function getGraphIdsByInstanceId(bytes16 instanceId) external view returns (bytes16[] memory);
        function getCancelWithdrawDigestNonced(bytes16 graphId, uint256 nonce) public view returns (bytes32);
        function getUnlockStakeDigestNonced(address operator, uint256 amount, uint256 nonce) public view returns (bytes32);
        function unlockOperatorStake(address operator, uint256 amount, uint256 nonce, bytes[] calldata committeeSigs) external;

    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISwapEscrowManager {
        event Initialize(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address claimHandler, address refundHandler);

        struct EscrowData {
            address offerer;
            address claimer;
            uint256 amount;
            address token;
            uint256 flags;
            address claimHandler;
            bytes32 claimData;
            address refundHandler;
            bytes32 refundData;
            uint256 securityDeposit;
            uint256 claimerBounty;
            address depositToken;
            bytes32 successActionCommitment;
        }

        function initialize(EscrowData calldata escrow, bytes calldata signature, uint256 timeout, bytes memory _extraData) external payable;
    }
);

const INITIALIZE_EVENT_SIGNATURE: &str = "Initialize(address,address,bytes32,address,address)";

fn initialize_event_topic0() -> B256 {
    keccak256(INITIALIZE_EVENT_SIGNATURE.as_bytes())
}

fn extract_escrow_hash_from_initialize_topics(topics: &[B256]) -> Option<String> {
    if topics.len() < 4 {
        return None;
    }
    Some(format!("0x{}", hex::encode(topics[3].0)))
}

fn extract_initialize_escrow_hash_from_receipt(
    receipt: &TransactionReceipt,
    swap_contract_address: &Address,
) -> Option<String> {
    let topic0 = initialize_event_topic0();
    receipt.logs().iter().find_map(|log| {
        if log.address() != *swap_contract_address {
            return None;
        }
        if log.topic0() != Some(&topic0) {
            return None;
        }
        extract_escrow_hash_from_initialize_topics(log.topics())
    })
}

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IBitcoinSPV {
        function blockHash(uint256 height) external view returns (bytes32);
        function latestHeight() external view returns (uint256);
        function postBlockHash(uint256 height, bytes32 headerHash) external;
        function postBlockHashBatch(uint256[] calldata heights, bytes32[] calldata headerHashes) external;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IPegBtc{
         function decimals() external view returns (uint8);
         function balanceOf(address account) external view returns (uint256);
         function allowance(address owner, address spender) external view returns (uint256);
         function approve(address spender, uint256 amount) external returns (bool);
         function mint(address to, uint256 amount) external;
         function burn(uint256 amount) external;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISequencerSetPublisher {

        struct SequencerSetUpdateWitness {
            bytes32 sigHash;
            bytes btcPubkey;
            bytes btcSig;
        }

        function updateSequencerSet(
            uint256 goatHeight,
            SequencerSetUpdateWitness calldata witness
        ) external;

        function getSequencerSetUpdateWitnesses(
            uint256 goatHeight
        ) external view override returns (SequencerSetUpdateWitness[] memory);

        mapping(uint256 height => SequencerSetUpdateWitness) public sequencerSetUpdateWitnesses;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IStakeManagement {
        function stakeTokenAddress() external view returns (address);
        function pubkeyToAddress(bytes32 pubkey) external view returns (address); // XOnlyPubkey
        function stakeOf(address operator) external view returns (uint256);
        function lockedStakeOf(address operator) external view returns (uint256);
        function slashStake(address operator, uint256 amount) external;
        function lockStake(address operator, uint256 amount) external;
        function unlockStake(address operator, uint256 amount) external;
        function stake(uint256 amount) external;
        function unstake(uint256 amount) external;
        function registerPubkey(bytes32 pubkey) external;
    }
);

sol!(
    #[derive(Debug)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ICommitteeManagement {
        function isCommitteeMember(address member) external view returns (bool);
        function committeeSize() external view returns (uint256);
        function quorumSize() external view returns (uint256);
        function verifySignatures(bytes32 msgHash, bytes[] memory signatures) external view returns (bool);
        function registerPeerId(bytes calldata peerId) external;
        function getCommitteePeerId(address member) external view returns (bytes);
        function isValidPeerId(bytes calldata peerId) external view returns (bool);
        function getWatchtowers() external view returns (bytes32[] memory);
        function getVerifiers() external view returns (bytes[] memory);
        function isVerifier(bytes calldata peerId) external view returns (bool);
        function addWatchtower(bytes32 watchtower, uint256 nonce, bytes[] memory authSignatures) external;
        function removeWatchtower(bytes32 watchtower, uint256 nonce, bytes[] memory authSignatures) external;
        function getNoncedDigest(bytes32 msgHash, uint256 nonce) external view returns (bytes32);
        function getAddWatchtowerDigestNonced(bytes32 watchtower, uint256 nonce) external view returns (bytes32);
        function getRemoveWatchtowerDigestNonced(bytes32 watchtower, uint256 nonce) external view returns (bytes32);
        function isAuthorizedCaller(address caller) external view returns (bool);
        function addAuthorizedCaller(address caller, uint256 nonce, bytes[] memory authSignatures) external;
        function removeAuthorizedCaller(address caller, uint256 nonce, bytes[] memory authSignatures) external;
        function getAddAuthorizedCallerDigestNonced(address caller, uint256 nonce) external view returns (bytes32);
        function getRemoveAuthorizedCallerDigestNonced(address caller, uint256 nonce) external view returns (bytes32);
        function executeNoncedSignatures(bytes32 msgHash, uint256 nonce, bytes[] memory signatures) external;
    }
);

#[derive(Clone, Debug)]
pub struct GoatInitConfig {
    pub rpc_url: Url,
    pub private_key: Option<String>,
    pub chain_id: u32,
    pub gateway_address: Option<Address>,
    pub sequencer_set_publisher_address: Option<Address>,
    pub committee_management_address: Option<Address>,
    pub stake_management_address: Option<Address>,
    pub multi_sig_verifier_address: Option<Address>,
    pub btc_spv_address: Option<Address>,
    pub peg_btc_address: Option<Address>,
}

impl GoatInitConfig {
    pub async fn new(rpc_url: Url) -> anyhow::Result<GoatInitConfig> {
        let provider =
            ProviderBuilder::new().connect_reqwest(build_goat_rpc_client(), rpc_url.clone());
        Ok(GoatInitConfig {
            private_key: None,
            chain_id: provider.get_chain_id().await? as u32,
            rpc_url,
            gateway_address: None,
            sequencer_set_publisher_address: None,
            committee_management_address: None,
            stake_management_address: None,
            multi_sig_verifier_address: None,
            btc_spv_address: None,
            peg_btc_address: None,
        })
    }

    pub fn with_private_key(mut self, private_key: Option<String>) -> GoatInitConfig {
        self.private_key = private_key;
        self
    }

    pub fn with_gateway_address(mut self, gateway_address: Option<Address>) -> GoatInitConfig {
        self.gateway_address = gateway_address;
        self
    }

    pub fn with_sequencer_set_publisher_address(
        mut self,
        sequencer_set_publisher_address: Option<Address>,
    ) -> GoatInitConfig {
        self.sequencer_set_publisher_address = sequencer_set_publisher_address;
        self
    }

    pub fn with_committee_management_address(
        mut self,
        committee_management_address: Option<Address>,
    ) -> GoatInitConfig {
        self.committee_management_address = committee_management_address;
        self
    }

    pub fn with_stake_management_address(
        mut self,
        stake_management_address: Option<Address>,
    ) -> GoatInitConfig {
        self.stake_management_address = stake_management_address;
        self
    }

    pub fn with_multi_sig_verifier_address(
        mut self,
        multi_sig_verifier_address: Option<Address>,
    ) -> GoatInitConfig {
        self.multi_sig_verifier_address = multi_sig_verifier_address;
        self
    }

    pub fn with_btc_spv_address(mut self, btc_spv_address: Option<Address>) -> GoatInitConfig {
        self.btc_spv_address = btc_spv_address;
        self
    }

    pub fn with_peg_btc_address(mut self, peg_btc_address: Option<Address>) -> GoatInitConfig {
        self.peg_btc_address = peg_btc_address;
        self
    }
}
type GatewayInstance = IGatewayInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;

type BitcoinSPVInstance = IBitcoinSPVInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;

type PegBtcInstance = IPegBtcInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;
type SequencerSetPublisherInstance = ISequencerSetPublisherInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;
type CommitteeManagementInstance = ICommitteeManagementInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;

type StakeManagementInstance = IStakeManagementInstance<
    FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
>;

pub struct GoatAdaptor {
    chain_id: ChainId,
    signer: EthereumWallet,
    provider: FillProvider<
        JoinFill<Identity, <Ethereum as RecommendedFillers>::RecommendedFillers>,
        RootProvider,
    >,
    gateway: Option<GatewayInstance>,
    btc_spv: Option<BitcoinSPVInstance>,
    peg_btc: Option<PegBtcInstance>,
    sequencer_set_publisher: Option<SequencerSetPublisherInstance>,
    committee_management: Option<CommitteeManagementInstance>,
    stake_management: Option<StakeManagementInstance>,
}

impl GoatAdaptor {
    #[allow(unused)]
    fn get_price_amend(&self, price: u128) -> u128 {
        price
    }

    fn get_gateway(&self) -> anyhow::Result<&GatewayInstance> {
        self.gateway.as_ref().ok_or_else(|| anyhow::anyhow!("Gateway not initialized"))
    }

    fn get_btc_spv(&self) -> anyhow::Result<&BitcoinSPVInstance> {
        self.btc_spv.as_ref().ok_or_else(|| anyhow::anyhow!("Gateway.bitcoinSPV not initialized"))
    }

    fn get_peg_btc(&self) -> anyhow::Result<&PegBtcInstance> {
        self.peg_btc.as_ref().ok_or_else(|| anyhow::anyhow!("Gateway.pegBtc not initialized"))
    }

    fn get_sequencer_set_publisher(&self) -> anyhow::Result<&SequencerSetPublisherInstance> {
        self.sequencer_set_publisher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SequencerSetPublisher not initialized"))
    }

    fn get_committee_management(&self) -> anyhow::Result<&CommitteeManagementInstance> {
        self.committee_management
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CommitteeManagement not initialized"))
    }

    fn get_stake_management(&self) -> anyhow::Result<&StakeManagementInstance> {
        self.stake_management
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("StakeManagement not initialized"))
    }

    fn convert_swap_escrow_data(escrow: SwapEscrowData) -> ISwapEscrowManager::EscrowData {
        ISwapEscrowManager::EscrowData {
            offerer: escrow.offerer,
            claimer: escrow.claimer,
            amount: escrow.amount,
            token: escrow.token,
            flags: escrow.flags,
            claimHandler: escrow.claim_handler,
            claimData: FixedBytes::<32>::from(escrow.claim_data),
            refundHandler: escrow.refund_handler,
            refundData: FixedBytes::<32>::from(escrow.refund_data),
            securityDeposit: escrow.security_deposit,
            claimerBounty: escrow.claimer_bounty,
            depositToken: escrow.deposit_token,
            successActionCommitment: FixedBytes::<32>::from(escrow.success_action_commitment),
        }
    }

    async fn handle_transaction_request(
        &self,
        tx_request: TransactionRequest,
    ) -> anyhow::Result<TxHash> {
        let (tx_hash, _) = self.handle_transaction_request_with_wait(tx_request, 10).await?;
        Ok(tx_hash)
    }

    async fn handle_transaction_request_eip1559(
        &self,
        tx_request: TransactionRequest,
    ) -> anyhow::Result<TxHash> {
        let (tx_hash, _) =
            self.handle_transaction_request_with_wait_eip1559(tx_request, 10).await?;
        Ok(tx_hash)
    }

    async fn get_eip1559_fee_params(&self) -> anyhow::Result<(u128, u128)> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| format_err!("latest block not found"))?;
        let base_fee = u128::from(
            block
                .header
                .base_fee_per_gas
                .ok_or_else(|| format_err!("latest block missing base_fee_per_gas"))?,
        );
        let mut adjusted_base_fee = base_fee.saturating_mul(EIP1559_BASE_FEE_MULTIPLIER_NUM)
            / EIP1559_BASE_FEE_MULTIPLIER_DEN;
        if adjusted_base_fee > EIP1559_MAX_BASE_FEE_WEI {
            adjusted_base_fee = EIP1559_MAX_BASE_FEE_WEI;
        }
        let max_fee = adjusted_base_fee
            .checked_add(EIP1559_PRIORITY_FEE_WEI)
            .ok_or_else(|| format_err!("max_fee_per_gas overflow"))?;
        Ok((max_fee, EIP1559_PRIORITY_FEE_WEI))
    }

    async fn handle_transaction_request_with_wait(
        &self,
        mut tx_request: TransactionRequest,
        max_wait_secs: u64,
    ) -> anyhow::Result<(TxHash, TransactionReceipt)> {
        // update  gas price nonce gas_limit
        tx_request.gas_price = Some(self.provider.clone().get_gas_price().await?);
        tracing::info!("gas price: {}", tx_request.gas_price.unwrap());
        tx_request.nonce =
            Some(self.provider.clone().get_transaction_count(tx_request.from.unwrap()).await?);
        tracing::info!("tx: {:?}", tx_request);
        tx_request.gas = Some(self.provider.clone().estimate_gas(tx_request.clone()).await?);
        tracing::info!("estimated gas: {:?}", tx_request.gas);

        // change into unsigned tx
        let unsigned_tx =
            tx_request.build_typed_tx().map_err(|v| format_err!("{v:?} fail to build typed tx"))?;
        // signed tx
        let signed_tx = <EthereumWallet as NetworkWallet<Ethereum>>::sign_transaction(
            &self.signer,
            unsigned_tx,
        )
        .await?;
        // send tx
        let pending_tx =
            self.provider.send_raw_transaction(signed_tx.encoded_2718().as_slice()).await?;
        let tx_hash = pending_tx.tx_hash();
        tracing::info!("finish send tx_hash: {}", tx_hash.to_string());

        let poll_interval_secs = 2_u64;
        let max_attempts = (max_wait_secs / poll_interval_secs).max(1);
        for i in 0..max_attempts {
            if i > 0 {
                time::sleep(Duration::from_secs(poll_interval_secs)).await;
            }
            match self.provider.get_transaction_receipt(*tx_hash).await {
                Err(_) => {
                    tracing::info!(
                        "Get transaction:{} receipt failed at {} times, will try later",
                        tx_hash.to_string(),
                        i
                    );
                    continue;
                }
                Ok(receipt) => {
                    if receipt.is_none() {
                        tracing::info!(
                            "Get transaction:{} receipt is none at {} times, will try later",
                            tx_hash.to_string(),
                            i
                        );
                        continue;
                    }
                    let receipt = receipt.expect("checked is_some");
                    if !receipt.status() {
                        bail!("tx_hash:{tx_hash} execute failed on chain");
                    }
                    return Ok((*tx_hash, receipt));
                }
            };
        }
        bail!("tx_hash:{tx_hash} receipt not found within {max_wait_secs} seconds")
    }

    async fn handle_transaction_request_with_wait_eip1559(
        &self,
        mut tx_request: TransactionRequest,
        max_wait_secs: u64,
    ) -> anyhow::Result<(TxHash, TransactionReceipt)> {
        let (max_fee_per_gas, max_priority_fee_per_gas) = self.get_eip1559_fee_params().await?;
        tx_request.gas_price = None;
        tx_request.max_fee_per_gas = Some(max_fee_per_gas);
        tx_request.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        tracing::info!(
            "eip1559 fee max_fee_per_gas: {}, max_priority_fee_per_gas: {}",
            max_fee_per_gas,
            max_priority_fee_per_gas
        );
        tx_request.nonce =
            Some(self.provider.clone().get_transaction_count(tx_request.from.unwrap()).await?);
        tracing::info!("tx(type2): {:?}", tx_request);
        tx_request.gas = Some(self.provider.clone().estimate_gas(tx_request.clone()).await?);
        tracing::info!("estimated gas(type2): {:?}", tx_request.gas);

        let unsigned_tx =
            tx_request.build_typed_tx().map_err(|v| format_err!("{v:?} fail to build typed tx"))?;
        let signed_tx = <EthereumWallet as NetworkWallet<Ethereum>>::sign_transaction(
            &self.signer,
            unsigned_tx,
        )
        .await?;
        let pending_tx =
            self.provider.send_raw_transaction(signed_tx.encoded_2718().as_slice()).await?;
        let tx_hash = pending_tx.tx_hash();
        tracing::info!("finish send tx_hash(type2): {}", tx_hash.to_string());

        let poll_interval_secs = 2_u64;
        let max_attempts = (max_wait_secs / poll_interval_secs).max(1);
        for i in 0..max_attempts {
            if i > 0 {
                time::sleep(Duration::from_secs(poll_interval_secs)).await;
            }
            match self.provider.get_transaction_receipt(*tx_hash).await {
                Err(_) => {
                    tracing::info!(
                        "Get transaction(type2):{} receipt failed at {} times, will try later",
                        tx_hash.to_string(),
                        i
                    );
                    continue;
                }
                Ok(receipt) => {
                    if receipt.is_none() {
                        tracing::info!(
                            "Get transaction(type2):{} receipt is none at {} times, will try later",
                            tx_hash.to_string(),
                            i
                        );
                        continue;
                    }
                    let receipt = receipt.expect("checked is_some");
                    if !receipt.status() {
                        bail!("tx_hash:{tx_hash} execute failed on chain");
                    }
                    return Ok((*tx_hash, receipt));
                }
            };
        }
        bail!("tx_hash:{tx_hash} receipt not found within {max_wait_secs} seconds")
    }
}

impl From<&BitcoinTx> for IGateway::BitcoinTx {
    fn from(value: &BitcoinTx) -> Self {
        Self {
            version: FixedBytes::<4>::from_slice(&value.version.to_le_bytes()),
            inputVector: Bytes::copy_from_slice(&value.input_vector),
            outputVector: Bytes::copy_from_slice(&value.output_vector),
            locktime: FixedBytes::<4>::from(value.lock_time),
        }
    }
}

impl From<&BitcoinTxProof> for IGateway::BitcoinTxProof {
    fn from(value: &BitcoinTxProof) -> Self {
        let proof: Vec<FixedBytes<32>> =
            value.proof.iter().map(|v| FixedBytes::<32>::from_slice(v)).collect();
        Self {
            rawHeader: Bytes::copy_from_slice(&value.raw_header),
            height: U256::from(value.height),
            proof,
            index: U256::from(value.index),
        }
    }
}

impl From<IGateway::PeginStatus> for PeginStatus {
    fn from(value: IGateway::PeginStatus) -> Self {
        match value {
            IGateway::PeginStatus::None => PeginStatus::None,
            IGateway::PeginStatus::Pending => PeginStatus::Pending,
            IGateway::PeginStatus::Withdrawable => PeginStatus::Withdrawable,
            IGateway::PeginStatus::Processing => PeginStatus::Processing,
            IGateway::PeginStatus::Locked => PeginStatus::Locked,
            IGateway::PeginStatus::Claimed => PeginStatus::Claimed,
            IGateway::PeginStatus::Discarded => PeginStatus::Discarded,
            _ => PeginStatus::None,
        }
    }
}

impl From<IGateway::WithdrawStatus> for WithdrawStatus {
    fn from(value: IGateway::WithdrawStatus) -> Self {
        match value {
            IGateway::WithdrawStatus::None => WithdrawStatus::None,
            IGateway::WithdrawStatus::Processing => WithdrawStatus::Processing,
            IGateway::WithdrawStatus::Initialized => WithdrawStatus::Initialized,
            IGateway::WithdrawStatus::Canceled => WithdrawStatus::Canceled,
            IGateway::WithdrawStatus::Complete => WithdrawStatus::Complete,
            IGateway::WithdrawStatus::Disproved => WithdrawStatus::Disproved,
            _ => WithdrawStatus::None,
        }
    }
}

impl From<DisproveTxType> for IGateway::DisproveTxType {
    fn from(value: DisproveTxType) -> Self {
        match value {
            DisproveTxType::Disprove => IGateway::DisproveTxType::Disprove,
            DisproveTxType::QuickChallenge => IGateway::DisproveTxType::QuickChallenge,
            DisproveTxType::ChallengeIncompleteKickoff => {
                IGateway::DisproveTxType::ChallengeIncompleteKickoff
            }
            DisproveTxType::PubinDisprove => IGateway::DisproveTxType::PubinDisprove,
            DisproveTxType::OperatorChallengeNack => {
                IGateway::DisproveTxType::OperatorChallengeNack
            }
            DisproveTxType::OperatorCommitTimeout => {
                IGateway::DisproveTxType::OperatorCommitTimeout
            }
        }
    }
}

impl From<&IGateway::Utxo> for Utxo {
    fn from(value: &IGateway::Utxo) -> Self {
        Self { txid: value.txid.0, vout: value.vout, amount_sats: value.amountSats }
    }
}

impl From<&Utxo> for IGateway::Utxo {
    fn from(value: &Utxo) -> Self {
        Self {
            txid: FixedBytes::from_slice(&value.txid),
            vout: value.vout,
            amountSats: value.amount_sats,
        }
    }
}

impl From<IGateway::PeginData> for PeginData {
    fn from(value: IGateway::PeginData) -> Self {
        Self {
            status: value.status.into(),
            instance_id: value.instanceId.0,
            depositor_address: value.depositorAddress.into_array(),
            pegin_amount_sats: value.peginAmountSats,

            txn_fees: value.txnFees,
            user_inputs: value.userInputs.iter().map(|v| v.into()).collect(),
            user_xonly_pubkey: value.userXonlyPubkey.0,
            user_change_addr: value.userChangeAddress,
            user_refund_addr: value.userRefundAddress,
            pegin_txid: value.peginTxid.0,
            created_at: value.createdAt.try_into().expect("failed to convert created"),
            committee_addresses: value.committeeAddresses.to_vec(),
            committee_pubkeys: value
                .committeePubkeys
                .into_iter()
                .map(|pubkey| pubkey.to_vec())
                .collect(),
        }
    }
}
// The committee signs these digests with its GOAT hot key, so they are
// computed here as `Gateway.getPostPeginDigest` / `getPostGraphDigest` do,
// never taken from the RPC.
const POST_PEGIN_TYPE: &str =
    "POST_PEGIN_DATA(address contract,bytes16 instanceId,bytes32 peginTxid)";
const POST_GRAPH_TYPE: &str =
    "POST_GRAPH_DATA(address contract,bytes16 instanceId,bytes16 graphId,bytes32 graphDataHash)";

pub fn post_pegin_digest(
    gateway: Address,
    instance_id: &[u8; 16],
    pegin_txid: &[u8; 32],
) -> [u8; 32] {
    let encoded = (
        keccak256(POST_PEGIN_TYPE),
        gateway,
        FixedBytes::<16>::from(*instance_id),
        FixedBytes::<32>::from(*pegin_txid),
    )
        .abi_encode();
    keccak256(encoded).0
}

pub fn post_graph_digest(
    gateway: Address,
    instance_id: &[u8; 16],
    graph_id: &[u8; 16],
    graph_data: GraphData,
) -> [u8; 32] {
    let graph_data_hash = keccak256(IGateway::GraphData::from(graph_data).abi_encode());
    let encoded = (
        keccak256(POST_GRAPH_TYPE),
        gateway,
        FixedBytes::<16>::from(*instance_id),
        FixedBytes::<16>::from(*graph_id),
        graph_data_hash,
    )
        .abi_encode();
    keccak256(encoded).0
}

impl From<GraphData> for IGateway::GraphData {
    fn from(value: GraphData) -> Self {
        Self {
            operatorPubkeyPrefix: FixedBytes::from(value.operator_pubkey_prefix),
            operatorPubkey: FixedBytes::from_slice(&value.operator_pubkey),
            peginTxid: FixedBytes::from_slice(&value.pegin_txid),
            kickoffTxid: FixedBytes::from_slice(&value.kickoff_txid),
            take1Txid: FixedBytes::from_slice(&value.take1_txid),
            take2Txid: FixedBytes::from_slice(&value.take2_txid),
            watchtowerChallengeInitTxid: FixedBytes::from_slice(
                &value.watchtower_challenge_init_txid,
            ),
            proverAssertTxid: FixedBytes::from_slice(&value.prover_assert_txid),
            verifierAssertTxids: value
                .verifier_assert_txids
                .into_iter()
                .map(|txid| FixedBytes::from_slice(&txid))
                .collect::<Vec<_>>(),
            watchtowerChallengeTimeoutTxids: value
                .watchtower_challenge_timeout_txids
                .into_iter()
                .map(|txid| FixedBytes::from_slice(&txid))
                .collect::<Vec<_>>(),
            operatorChallengeNackTxids: value
                .operator_challenge_nack_txids
                .into_iter()
                .map(|txid| FixedBytes::from_slice(&txid))
                .collect::<Vec<_>>(),
            operatorCommitTimeoutTxid: FixedBytes::from_slice(&value.operator_commit_timeout_txid),
        }
    }
}
impl From<IGateway::GraphData> for GraphData {
    fn from(value: IGateway::GraphData) -> Self {
        GraphData {
            // stake_amount_sats: value.stakeAmountSats,
            operator_pubkey_prefix: value.operatorPubkeyPrefix.0[0],
            operator_pubkey: value.operatorPubkey.0,
            pegin_txid: value.peginTxid.0,
            kickoff_txid: value.kickoffTxid.0,
            take1_txid: value.take1Txid.0,
            take2_txid: value.take2Txid.0,
            watchtower_challenge_init_txid: value.watchtowerChallengeInitTxid.0,
            prover_assert_txid: value.proverAssertTxid.0,
            verifier_assert_txids: value
                .verifierAssertTxids
                .into_iter()
                .map(|txid| txid.into())
                .collect(),
            watchtower_challenge_timeout_txids: value
                .watchtowerChallengeTimeoutTxids
                .into_iter()
                .map(|txid| txid.into())
                .collect(),
            operator_challenge_nack_txids: value
                .operatorChallengeNackTxids
                .into_iter()
                .map(|txid| txid.into())
                .collect(),
            operator_commit_timeout_txid: value.operatorCommitTimeoutTxid.0,
        }
    }
}
impl From<IGateway::WithdrawData> for WithdrawData {
    fn from(value: IGateway::WithdrawData) -> Self {
        Self {
            pegin_txid: value.peginTxid.0,
            operator_address: value.operatorAddress.0.map(|v| v),
            status: value.status.into(),
            instance_id: value.instanceId.0,
            lock_amount: value.lockAmount,
            btc_block_height_withdraw: value.btcBlockHeightAtWithdraw,
        }
    }
}

impl From<SequencerSetUpdateWitness> for ISequencerSetPublisher::SequencerSetUpdateWitness {
    fn from(value: SequencerSetUpdateWitness) -> Self {
        Self {
            sigHash: FixedBytes::from_slice(&value.sig_hash),
            btcPubkey: Bytes::copy_from_slice(&value.btc_pub_key),
            btcSig: Bytes::copy_from_slice(&value.btc_sig),
        }
    }
}

impl From<ISequencerSetPublisher::SequencerSetUpdateWitness> for SequencerSetUpdateWitness {
    fn from(value: ISequencerSetPublisher::SequencerSetUpdateWitness) -> Self {
        Self {
            sig_hash: *value.sigHash,
            btc_pub_key: value.btcPubkey.to_vec(),
            btc_sig: value.btcSig.to_vec(),
        }
    }
}

#[async_trait]
impl ChainAdaptor for GoatAdaptor {
    fn get_default_signer_address(&self) -> Address {
        <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&self.signer)
    }

    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        if let Some(block) = self.provider.get_block_by_number(BlockNumberOrTag::Finalized).await? {
            Ok(block.header.number as i64)
        } else {
            bail!("fail to get finalize block");
        }
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<i64> {
        if let Some(block) = self.provider.get_block_by_number(BlockNumberOrTag::Latest).await? {
            Ok(block.header.number as i64)
        } else {
            bail!("fail to get latest block");
        }
    }

    async fn native_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256> {
        Ok(self.provider.get_balance(Address::from_slice(address)).await?)
    }

    async fn get_tx_receipt(&self, tx_hash: &str) -> anyhow::Result<Option<TransactionReceipt>> {
        Ok(self.provider.get_transaction_receipt(TxHash::from_str(tx_hash)?).await?)
    }

    async fn debug_trace_tx(
        &self,
        tx_hash: &str,
        trace_options: Option<GethDebugTracingOptions>,
    ) -> anyhow::Result<GethTrace> {
        let opts = trace_options
            .unwrap_or_else(|| GethDebugTracingOptions::call_tracer(CallConfig::default()));
        Ok(self.provider.debug_trace_transaction(TxHash::from_str(tx_hash)?, opts).await?)
    }

    async fn swap_initialize(
        &self,
        contract_address: Address,
        escrow: SwapEscrowData,
        signature: Bytes,
        timeout: U256,
        extra_data: Bytes,
        value_wei: U256,
        max_wait_secs: u64,
    ) -> anyhow::Result<SwapInitializeResult> {
        let contract = ISwapEscrowManager::new(contract_address, self.provider.clone());
        let escrow = GoatAdaptor::convert_swap_escrow_data(escrow);
        let tx_request: TransactionRequest = contract
            .initialize(escrow, signature, timeout, extra_data)
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .value(value_wei)
            .into_transaction_request();
        let (tx_hash, receipt) =
            self.handle_transaction_request_with_wait_eip1559(tx_request, max_wait_secs).await?;
        let escrow_hash = extract_initialize_escrow_hash_from_receipt(&receipt, &contract_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Initialize event with escrowHash not found in tx {tx_hash} logs for contract {contract_address}"
                )
            })?;
        Ok(SwapInitializeResult { tx_hash: tx_hash.to_string(), escrow_hash })
    }

    async fn extract_initialize_escrow_hash_from_tx(
        &self,
        tx_hash: &str,
        contract_address: Address,
    ) -> anyhow::Result<Option<String>> {
        let receipt = self.provider.get_transaction_receipt(TxHash::from_str(tx_hash)?).await?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        if !receipt.status() {
            bail!("tx {tx_hash} failed on-chain (status = 0)");
        }
        Ok(extract_initialize_escrow_hash_from_receipt(&receipt, &contract_address))
    }

    async fn gateway_get_min_challenge_amount_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minChallengeAmountSats().call().await?)
    }

    async fn gateway_get_min_pegin_fee_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minPeginFeeSats().call().await?)
    }

    async fn gateway_get_pegin_fee_rate(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.peginFeeRate().call().await?)
    }

    async fn gateway_get_min_operator_reward_sats(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minOperatorRewardSats().call().await?)
    }

    async fn gateway_get_operator_reward_rate(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.operatorRewardRate().call().await?)
    }

    async fn gateway_get_min_stake_amount(&self) -> anyhow::Result<U256> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minStakeAmount().call().await?)
    }

    async fn gateway_get_min_challenger_reward(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minChallengerReward().call().await?.try_into()?)
    }

    async fn gateway_get_min_disprover_reward(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minDisproverReward().call().await?.try_into()?)
    }

    async fn gateway_get_min_slash_amount(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.minSlashAmount().call().await?.try_into()?)
    }

    async fn gateway_get_committee_management(&self) -> anyhow::Result<[u8; 20]> {
        let gateway = self.get_gateway()?;
        Ok(gateway.committeeManagement().call().await?.into_array())
    }

    async fn gateway_get_stake_management(&self) -> anyhow::Result<[u8; 20]> {
        let gateway = self.get_gateway()?;
        Ok(gateway.stakeManagement().call().await?.into_array())
    }

    async fn gateway_get_pegin_data(&self, instance_id: &[u8; 16]) -> anyhow::Result<PeginData> {
        let gateway = self.get_gateway()?;
        Ok(gateway.getPeginData(FixedBytes::<16>::from_slice(instance_id)).call().await?.into())
    }

    async fn gateway_get_withdraw_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<WithdrawData> {
        let gateway = self.get_gateway()?;
        let res = gateway.withdrawDataMap(FixedBytes::<16>::from_slice(graph_id)).call().await?;
        Ok(WithdrawData {
            status: res._0.into(),
            pegin_txid: res._1.0,
            operator_address: res._2.0.0,
            instance_id: res._3.0,
            lock_amount: res._4,
            btc_block_height_withdraw: res._5,
        })
    }

    async fn gateway_get_graph_data(&self, graph_id: &[u8; 16]) -> anyhow::Result<GraphData> {
        let gateway = self.get_gateway()?;
        Ok(gateway.getGraphData(FixedBytes::<16>::from_slice(graph_id)).call().await?.into())
    }

    async fn gateway_get_response_window_blocks(&self) -> anyhow::Result<u64> {
        let gateway = self.get_gateway()?;
        Ok(gateway.responseWindowBlocks().call().await?.try_into()?)
    }

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
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let user_inputs: Vec<IGateway::Utxo> = user_inputs.iter().map(|u| u.into()).collect();
        let tx_request = gateway
            .postPeginRequest(
                FixedBytes::from_slice(instance_id),
                pegin_amount_sats,
                *tx_fees,
                Address::from_slice(receiver_addr),
                user_inputs,
                FixedBytes::from_slice(user_xonly_pubkey),
                user_change_addr.to_string(),
                user_refund_addr.to_string(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_answer_pegin_request(
        &self,
        instance_id: &[u8; 16],
        committee_pubkey: &[u8],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .answerPeginRequest(
                FixedBytes::from_slice(instance_id),
                Bytes::copy_from_slice(committee_pubkey),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_post_pegin_data(
        &self,
        instance_id: &[u8; 16],
        raw_pgin_tx: &BitcoinTx,
        pegin_proof: &BitcoinTxProof,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let signs: Vec<Bytes> = committee_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request: TransactionRequest = gateway
            .postPeginData(
                FixedBytes::<16>::from_slice(instance_id),
                raw_pgin_tx.into(),
                pegin_proof.into(),
                signs,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_post_graph_data(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        operator_data: &GraphData,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let signs: Vec<Bytes> = committee_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request = gateway
            .postGraphData(
                FixedBytes::from_slice(instance_id),
                FixedBytes::from_slice(graph_id),
                (*operator_data).clone().into(),
                signs,
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();

        let res = self.handle_transaction_request(tx_request).await?;
        Ok(res.to_string())
    }

    async fn gateway_get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        bail!("Gateway.getInitializedInstanceIds is not available in the gc contract interface")
    }

    async fn gateway_get_instanceids_by_pubkey(
        &self,
        _operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        bail!("Gateway.getInstanceIdsByPubKey is not available in the gc contract interface")
    }

    async fn gateway_init_withdraw(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .initWithdraw(FixedBytes::from_slice(instance_id), FixedBytes::from_slice(graph_id))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_cancel_withdraw(
        &self,
        graph_id: &[u8; 16],
        nonce: U256,
        committee_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let signs: Vec<Bytes> = committee_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request = gateway
            .committeeCancelWithdraw(FixedBytes::from_slice(graph_id), nonce, signs)
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_process_withdraw(
        &self,
        graph_id: &[u8; 16],
        raw_kickoff_tx: &BitcoinTx,
        kickoff_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .proceedWithdraw(
                FixedBytes::from_slice(graph_id),
                raw_kickoff_tx.into(),
                kickoff_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_finish_withdraw_happy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take1_tx: &BitcoinTx,
        take1_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .finishWithdrawHappyPath(
                FixedBytes::from_slice(graph_id),
                raw_take1_tx.into(),
                take1_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_finish_withdraw_unhappy_path(
        &self,
        graph_id: &[u8; 16],
        raw_take2_tx: &BitcoinTx,
        take2_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .finishWithdrawUnhappyPath(
                FixedBytes::from_slice(graph_id),
                raw_take2_tx.into(),
                take2_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    async fn gateway_finish_withdraw_disproved(
        &self,
        graph_id: &[u8; 16],
        disprove_tx_type: DisproveTxType,
        tx_index: u64,
        raw_challenge_start_tx: &BitcoinTx,
        challenge_start_proof: &BitcoinTxProof,
        raw_challenge_finshish_tx: &BitcoinTx,
        challenge_finish_proof: &BitcoinTxProof,
    ) -> anyhow::Result<String> {
        let gateway = self.get_gateway()?;
        let tx_request = gateway
            .finishWithdrawDisproved(
                FixedBytes::from_slice(graph_id),
                disprove_tx_type.into(),
                U256::from(tx_index),
                raw_challenge_start_tx.into(),
                challenge_start_proof.into(),
                raw_challenge_finshish_tx.into(),
                challenge_finish_proof.into(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn gateway_get_committee_pubkeys(
        &self,
        instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let gateway = self.get_gateway()?;
        Ok(gateway
            .getCommitteePubkeys(FixedBytes::from_slice(instance_id))
            .call()
            .await?
            .iter()
            .map(|pk| pk.to_vec())
            .collect())
    }

    async fn gateway_get_post_graph_digest(
        &self,
        instance_id: &[u8; 16],
        graph_id: &[u8; 16],
        graph_data: GraphData,
    ) -> anyhow::Result<[u8; 32]> {
        Ok(post_graph_digest(*self.get_gateway()?.address(), instance_id, graph_id, graph_data))
    }

    async fn gateway_get_post_pegin_digest(
        &self,
        instance_id: &[u8; 16],
        pegin_txid: &[u8; 32],
    ) -> anyhow::Result<[u8; 32]> {
        Ok(post_pegin_digest(*self.get_gateway()?.address(), instance_id, pegin_txid))
    }

    async fn gateway_get_graph_ids_by_instance_id(
        &self,
        instance_id: &[u8; 16],
    ) -> anyhow::Result<Vec<[u8; 16]>> {
        let gateway = self.get_gateway()?;
        Ok(gateway
            .getGraphIdsByInstanceId(FixedBytes::from_slice(instance_id))
            .call()
            .await?
            .iter()
            .map(|v| v.0)
            .collect())
    }

    async fn btc_spv_blockhash(&self, height: u64) -> anyhow::Result<[u8; 32]> {
        let btc_spv = self.get_btc_spv()?;
        Ok(btc_spv.blockHash(U256::from(height)).call().await?.0)
    }

    async fn btc_spv_latest_height(&self) -> anyhow::Result<u64> {
        let btc_spv = self.get_btc_spv()?;
        Ok(btc_spv
            .latestHeight()
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("latestConfirmedHeight error :{e:?}"))?)
    }
    async fn btc_spv_post_block_hash(
        &self,
        height: u64,
        header_hash: &[u8; 32],
    ) -> anyhow::Result<String> {
        let btc_spv = self.get_btc_spv()?;
        let tx_request = btc_spv
            .postBlockHash(U256::from(height), FixedBytes::from_slice(header_hash))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn btc_spv_post_block_hash_batch(
        &self,
        heights: &[u64],
        header_hashes: &[[u8; 32]],
    ) -> anyhow::Result<String> {
        let btc_spv = self.get_btc_spv()?;

        let tx_request = btc_spv
            .postBlockHashBatch(
                heights.iter().map(|height| U256::from(*height)).collect::<Vec<U256>>(),
                header_hashes.iter().map(|v| FixedBytes::from_slice(v)).collect::<Vec<_>>(),
            )
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }
    async fn stake_mana_stake_token_address(&self) -> anyhow::Result<[u8; 20]> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management.stakeTokenAddress().call().await?.into_array())
    }

    async fn stake_mana_pubkey_to_address(&self, pubkey: &[u8; 32]) -> anyhow::Result<[u8; 20]> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management
            .pubkeyToAddress(FixedBytes::from_slice(pubkey))
            .call()
            .await?
            .into_array())
    }

    // Stake amounts carry 18 decimals and exceed u64 above ~18.45 tokens.
    async fn stake_mana_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management.stakeOf(Address::from_slice(operator)).call().await?)
    }

    async fn stake_mana_lock_stake_of(&self, operator: &[u8; 20]) -> anyhow::Result<U256> {
        let stake_management = self.get_stake_management()?;
        Ok(stake_management.lockedStakeOf(Address::from_slice(operator)).call().await?)
    }

    async fn stake_mana_slash_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .slashStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn stake_mana_lock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .lockStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn stake_mana_unlock_stake(
        &self,
        operator: &[u8; 20],
        amount: u64,
    ) -> anyhow::Result<String> {
        let stake_management = self.get_stake_management()?;
        let tx_request = stake_management
            .unlockStake(Address::from_slice(operator), U256::from(amount))
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn committee_mana_is_committee_member(&self, member: &[u8; 20]) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management.isCommitteeMember(Address::from_slice(member)).call().await?)
    }

    async fn committee_mana_committee_size(&self) -> anyhow::Result<u64> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .committeeSize()
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn committee_mana_quorum_size(&self) -> anyhow::Result<u64> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .quorumSize()
            .call()
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("StakeOf error :{e:?}"))?)
    }

    async fn committee_mana_verify_signatures(
        &self,
        msg_hash: &[u8; 32],
        signs: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        let signatures: Vec<Bytes> = signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        Ok(committee_management
            .verifySignatures(FixedBytes::from_slice(msg_hash), signatures)
            .call()
            .await?)
    }

    async fn committee_mana_get_committee_peer_id(
        &self,
        member: &[u8; 20],
    ) -> anyhow::Result<Vec<u8>> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .getCommitteePeerId(Address::from_slice(member))
            .call()
            .await?
            .0
            .to_vec())
    }

    async fn committee_mana_is_validate_peer_id(&self, peer_id: &[u8]) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management.isValidPeerId(Bytes::copy_from_slice(peer_id)).call().await?)
    }

    async fn committee_mana_get_watchtowers(&self) -> anyhow::Result<Vec<[u8; 32]>> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .getWatchtowers()
            .call()
            .await?
            .into_iter()
            .map(|w| w.0)
            .collect::<Vec<[u8; 32]>>())
    }

    async fn committee_mana_get_verifiers(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management
            .getVerifiers()
            .call()
            .await?
            .into_iter()
            .map(|v| v.to_vec())
            .collect::<Vec<Vec<u8>>>())
    }

    async fn committee_mana_is_verifier(&self, peer_id: &[u8]) -> anyhow::Result<bool> {
        let committee_management = self.get_committee_management()?;
        Ok(committee_management.isVerifier(Bytes::copy_from_slice(peer_id)).call().await?)
    }

    async fn committee_mana_add_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: U256,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let committee_management = self.get_committee_management()?;
        let auth_signs: Vec<Bytes> = auth_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request = committee_management
            .addWatchtower(FixedBytes::from_slice(watchtower), nonce, auth_signs)
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn committee_mana_remove_watchtower(
        &self,
        watchtower: &[u8; 32],
        nonce: U256,
        auth_signs: &[Vec<u8>],
    ) -> anyhow::Result<String> {
        let committee_management = self.get_committee_management()?;
        let auth_signs: Vec<Bytes> = auth_signs.iter().map(|v| Bytes::copy_from_slice(v)).collect();
        let tx_request = committee_management
            .removeWatchtower(FixedBytes::from_slice(watchtower), nonce, auth_signs)
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn peg_btc_balance(&self, address: &[u8; 20]) -> anyhow::Result<U256> {
        let peg_btc = self.get_peg_btc()?;
        Ok(peg_btc.balanceOf(Address::from_slice(address)).call().await?)
    }

    async fn peg_btc_decimals(&self) -> anyhow::Result<u8> {
        let peg_btc = self.get_peg_btc()?;
        Ok(peg_btc.decimals().call().await?)
    }

    async fn peg_btc_allowance(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
    ) -> anyhow::Result<U256> {
        let peg_btc = self.get_peg_btc()?;
        Ok(peg_btc
            .allowance(Address::from_slice(owner), Address::from_slice(spender))
            .call()
            .await?)
    }

    async fn peg_btc_approve(&self, spender: &[u8; 20], amount: U256) -> anyhow::Result<String> {
        let peg_btc = self.get_peg_btc()?;
        let tx_request = peg_btc
            .approve(Address::from_slice(spender), amount)
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request_eip1559(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn ss_update_sequencer_set(
        &self,
        goat_height: U256,
        witness: SequencerSetUpdateWitness,
    ) -> anyhow::Result<String> {
        let sequencer_set_publisher = self.get_sequencer_set_publisher()?;
        let tx_request = sequencer_set_publisher
            .updateSequencerSet(goat_height, witness.into())
            .from(self.get_default_signer_address())
            .chain_id(self.chain_id)
            .into_transaction_request();
        let tx_hash = self.handle_transaction_request(tx_request).await?;
        Ok(tx_hash.to_string())
    }

    async fn ss_get_sequencer_set_update_witness(
        &self,
        goat_height: U256,
    ) -> anyhow::Result<Vec<SequencerSetUpdateWitness>> {
        let sequencer_set_publisher = self.get_sequencer_set_publisher()?;
        let resp =
            sequencer_set_publisher.getSequencerSetUpdateWitnesses(goat_height).call().await?;
        Ok(resp.iter().map(|x| x.clone().into()).collect())
    }
}

impl GoatAdaptor {
    pub fn new(config: GoatInitConfig) -> Self {
        Self::from_config(config)
    }

    fn from_config(config: GoatInitConfig) -> Self {
        let chain_id = ChainId::from(config.chain_id);
        let signer = if let Some(private_key) = config.private_key {
            PrivateKeySigner::from_str(private_key.as_str())
                .expect("create signer")
                .with_chain_id(Some(chain_id))
        } else {
            PrivateKeySigner::random()
        };
        let provider =
            ProviderBuilder::new().connect_reqwest(build_goat_rpc_client(), config.rpc_url);
        Self {
            chain_id,
            signer: EthereumWallet::new(signer),
            provider: provider.clone(),
            gateway: config.gateway_address.map(|addr| IGateway::new(addr, provider.clone())),
            sequencer_set_publisher: config
                .sequencer_set_publisher_address
                .map(|addr| ISequencerSetPublisher::new(addr, provider.clone())),
            committee_management: config
                .committee_management_address
                .map(|addr| ICommitteeManagement::new(addr, provider.clone())),
            stake_management: config
                .stake_management_address
                .map(|addr| IStakeManagement::new(addr, provider.clone())),
            btc_spv: config.btc_spv_address.map(|addr| IBitcoinSPV::new(addr, provider.clone())),
            peg_btc: config.peg_btc_address.map(|addr| IPegBtc::new(addr, provider.clone())),
        }
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    // Values from the Gateway contract (localnet/contracts) deployed by forge.
    const GATEWAY: &str = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f";
    const INSTANCE_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn word(value: u8) -> [u8; 32] {
        let mut word = [0; 32];
        word[31] = value;
        word
    }

    #[test]
    fn digests_match_the_gateway_contract() {
        let gateway = Address::from_str(GATEWAY).unwrap();
        assert_eq!(
            hex::encode(post_pegin_digest(gateway, &INSTANCE_ID, &word(0x11))),
            "0e3c99f1aa81d655c37ed28331afa3ea8e8969151c975f7eb98a5776ce34a40f"
        );
        let mut graph_id = INSTANCE_ID;
        graph_id.reverse();
        let graph_data = GraphData {
            operator_pubkey_prefix: 0x03,
            operator_pubkey: word(1),
            pegin_txid: word(2),
            kickoff_txid: word(3),
            take1_txid: word(4),
            take2_txid: word(5),
            watchtower_challenge_init_txid: word(6),
            prover_assert_txid: word(7),
            verifier_assert_txids: vec![word(0xd1), word(0xd2)],
            watchtower_challenge_timeout_txids: vec![word(0xe1)],
            operator_challenge_nack_txids: vec![],
            operator_commit_timeout_txid: word(9),
        };
        assert_eq!(
            hex::encode(post_graph_digest(gateway, &INSTANCE_ID, &graph_id, graph_data)),
            "e9115e8303ab1480367c771bff96b27cd8753f6e80bcbc515b750494d3aca0e0"
        );
    }
}
