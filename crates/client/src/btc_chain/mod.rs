use crate::btc_chain::bitcoin_adaptor::get_btc_chain_adapter;
use crate::btc_chain::bitcoin_chain::BitcoinChain;
use crate::btc_chain::mock_bitcoin_adaptor::MockBitcoinAdaptor;
use bitcoin::{Address as BtcAddress, Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{MerkleProof, OutputStatus, Tx, TxStatus, Utxo};
use std::collections::HashMap;
use std::str::FromStr;

pub mod bitcoin_adaptor;
pub mod bitcoin_chain;
mod esplora_bitcoin_adaptor;
pub use esplora_bitcoin_adaptor::BtcRpcTimeoutError;
mod mock_bitcoin_adaptor;

#[derive(Debug)]
pub struct BTCClient {
    chain_service: BitcoinChain,
}

pub struct MerkleProofExtend {
    pub txid: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub raw_header: Vec<u8>,
    pub root: [u8; 32],
    pub index: u64,
    pub merkle: Vec<[u8; 32]>,
}

impl BTCClient {
    pub fn new(network: Network, esplora_url: Option<&str>) -> Self {
        BTCClient { chain_service: BitcoinChain::new(get_btc_chain_adapter(network, esplora_url)) }
    }

    pub fn from_str(network: &str, esplora_url: Option<&str>) -> Self {
        BTCClient {
            chain_service: BitcoinChain::new(get_btc_chain_adapter(
                Network::from_str(network).unwrap_or(Network::Testnet4),
                esplora_url,
            )),
        }
    }
    pub fn new_mock_client() -> (Self, MockBitcoinAdaptor) {
        let mock_adaptor = MockBitcoinAdaptor::new(Network::Testnet4);
        let chain_service = BitcoinChain::new(Box::new(mock_adaptor.clone()));
        (BTCClient { chain_service }, mock_adaptor)
    }

    pub fn network(&self) -> Network {
        self.chain_service.network()
    }

    pub async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus> {
        self.chain_service.get_tx_status(txid).await
    }

    pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.chain_service.get_tx(txid).await
    }

    pub async fn get_tx_info(&self, tx_id: &Txid) -> anyhow::Result<Option<Tx>> {
        self.chain_service.get_tx_info(tx_id).await
    }

    pub async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.chain_service.get_address_utxo(address).await
    }

    pub async fn get_height(&self) -> anyhow::Result<u32> {
        self.chain_service.get_height().await
    }

    pub async fn get_fee_estimates(&self) -> anyhow::Result<HashMap<u16, f64>> {
        self.chain_service.get_fee_estimates().await
    }
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<OutputStatus>> {
        self.chain_service.get_output_status(txid, vout).await
    }

    pub async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<BlockHash> {
        self.chain_service.get_block_hash(block_height).await
    }

    pub async fn get_block_by_hash(&self, block_hash: &BlockHash) -> anyhow::Result<Option<Block>> {
        self.chain_service.get_block_by_hash(block_hash).await
    }

    pub async fn get_block_by_height(&self, block_height: u32) -> anyhow::Result<Block> {
        self.chain_service.get_block_by_height(block_height).await
    }

    pub async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        self.chain_service.get_merkle_proof(tx_id).await
    }

    pub async fn get_merkle_proof_extend(&self, tx_id: &Txid) -> anyhow::Result<MerkleProofExtend> {
        self.chain_service.get_merkle_proof_extend(tx_id).await
    }

    pub async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.chain_service.broadcast(tx).await
    }

    pub async fn broadcast_package(&self, txns: &[Transaction]) -> anyhow::Result<()> {
        self.chain_service.broadcast_package(txns).await
    }
}

#[cfg(test)]
mod tests {
    use crate::btc_chain::BTCClient;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mack_btc_client() -> anyhow::Result<()> {
        let (mock_client, mock_adaptor) = BTCClient::new_mock_client();
        let height_in = 1234_u32;
        mock_adaptor.set_height(height_in);
        let height_out = mock_client.get_height().await?;
        assert_eq!(height_out, height_in);
        Ok(())
    }
}
