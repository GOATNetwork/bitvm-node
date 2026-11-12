use crate::btc_chain::bitcoin_adaptor::BitcoinAdaptor;
use crate::timeout_config::get_btc_request_timeout_secs;
use bitcoin::block::Header;
use bitcoin::{Address as BtcAddress, Block, Network, Transaction, Txid};
use esplora_client::{AsyncClient, Builder, MerkleProof, Tx, Utxo};
use std::fmt;
use std::future::Future;
use std::time::Duration;
use tracing::warn;

const MAIN_URL: &str = "https://mempool.space/api";
const TESTNET4_URL: &str = "https://mempool.space/testnet4/api";
const SIGNET_URL: &str = "https://mempool.space/signet/api";
const TESTNET3_URL: &str = "https://mempool.space/testnet/api";

/// Retries esplora-client makes for 429 and 5xx answers. Its backoff starts at 256 ms
/// and doubles, so three retries wait about 1.8 s in all and fit in the request
/// timeout; its default of six waits about 16 s, longer than the default timeout.
const ESPLORA_MAX_RETRIES: usize = 3;

#[derive(Debug)]
pub struct BtcRpcTimeoutError {
    pub request_name: &'static str,
    pub timeout_secs: u64,
}

impl fmt::Display for BtcRpcTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "esplora request timeout: {}, timeout_secs={}",
            self.request_name, self.timeout_secs
        )
    }
}

impl std::error::Error for BtcRpcTimeoutError {}

pub fn get_esplora_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => MAIN_URL,
        Network::Testnet4 => TESTNET4_URL,
        Network::Signet => SIGNET_URL,
        // testnet3; regtest has no public explorer and needs an explicit URL
        _ => TESTNET3_URL,
    }
}

pub struct EsploraBitcoinAdaptor {
    esplora: AsyncClient,
    network: Network,
    request_timeout: Duration,
}

impl EsploraBitcoinAdaptor {
    pub fn new(network: Network, esplora_url: Option<&str>) -> Self {
        let timeout_secs = get_btc_request_timeout_secs();
        EsploraBitcoinAdaptor {
            esplora: Builder::new(esplora_url.unwrap_or(get_esplora_url(network)))
                .timeout(timeout_secs)
                .max_retries(ESPLORA_MAX_RETRIES)
                .build_async()
                .expect("Could not build esplora client"),
            network,
            request_timeout: Duration::from_secs(timeout_secs),
        }
    }

    async fn with_timeout<T, F>(&self, request_name: &'static str, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = Result<T, esplora_client::Error>>,
    {
        match tokio::time::timeout(self.request_timeout, future).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => {
                warn!(
                    request_name,
                    timeout_secs = self.request_timeout.as_secs(),
                    "esplora request timeout"
                );
                Err(BtcRpcTimeoutError {
                    request_name,
                    timeout_secs: self.request_timeout.as_secs(),
                }
                .into())
            }
        }
    }
}

#[async_trait::async_trait]
impl BitcoinAdaptor for EsploraBitcoinAdaptor {
    fn network(&self) -> Network {
        self.network
    }

    async fn get_tx_status(&self, txid: &Txid) -> anyhow::Result<esplora_client::TxStatus> {
        self.with_timeout("get_tx_status", self.esplora.get_tx_status(txid)).await
    }

    async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
        self.with_timeout("get_tx", self.esplora.get_tx(txid)).await
    }

    async fn get_tx_info(&self, txid: &Txid) -> anyhow::Result<Option<Tx>> {
        self.with_timeout("get_tx_info", self.esplora.get_tx_info(txid)).await
    }

    async fn get_address_utxo(&self, address: BtcAddress) -> anyhow::Result<Vec<Utxo>> {
        self.with_timeout("get_address_utxo", self.esplora.get_address_utxo(address)).await
    }

    async fn get_height(&self) -> anyhow::Result<u32> {
        self.with_timeout("get_height", self.esplora.get_height()).await
    }

    async fn get_fee_estimates(&self) -> anyhow::Result<std::collections::HashMap<u16, f64>> {
        self.with_timeout("get_fee_estimates", self.esplora.get_fee_estimates()).await
    }

    async fn broadcast(&self, tx: &Transaction) -> anyhow::Result<()> {
        self.with_timeout("broadcast", self.esplora.broadcast(tx)).await
    }

    async fn broadcast_package(&self, txns: &[Transaction]) -> anyhow::Result<()> {
        self.with_timeout("broadcast_package", self.esplora.broadcast_package(txns)).await
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u64,
    ) -> anyhow::Result<Option<esplora_client::OutputStatus>> {
        self.with_timeout("get_output_status", self.esplora.get_output_status(txid, vout)).await
    }

    async fn get_block_hash(&self, block_height: u32) -> anyhow::Result<bitcoin::BlockHash> {
        self.with_timeout("get_block_hash", self.esplora.get_block_hash(block_height)).await
    }

    async fn get_block_by_hash(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> anyhow::Result<Option<Block>> {
        self.with_timeout("get_block_by_hash", self.esplora.get_block_by_hash(block_hash)).await
    }

    async fn get_merkle_proof(&self, tx_id: &Txid) -> anyhow::Result<Option<MerkleProof>> {
        self.with_timeout("get_merkle_proof", self.esplora.get_merkle_proof(tx_id)).await
    }

    async fn get_header_by_hash(&self, block_hash: &bitcoin::BlockHash) -> anyhow::Result<Header> {
        self.with_timeout("get_header_by_hash", self.esplora.get_header_by_hash(block_hash)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_explorer_matches_the_network() {
        assert_eq!(get_esplora_url(Network::Bitcoin), MAIN_URL);
        assert_eq!(get_esplora_url(Network::Testnet4), TESTNET4_URL);
        assert_eq!(get_esplora_url(Network::Signet), SIGNET_URL);
        assert_eq!(get_esplora_url(Network::Testnet), TESTNET3_URL);
    }
}
