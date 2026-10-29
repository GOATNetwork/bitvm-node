#![feature(trim_prefix_suffix)]
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_provider::Provider;
use alloy_provider::{
    RootProvider,
    network::{Ethereum, Network},
};
use anyhow::Context;
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{
    HttpClient, fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block,
    get_cosmos_block_height_at,
};
use futures_util::{StreamExt, TryStreamExt, stream};
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use proof_builder::ProofRequest;
use proof_builder::{LongRunning, ProofBuilder};
use reth_chainspec::ChainSpec;
use state_chain::*;
use std::{collections::BTreeSet, sync::Arc};
use url::Url;
use zkm_sdk::{
    HashableKey, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofKind, ZKMProofWithPublicValues,
    ZKMStdin, include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
pub const STATE_CHAIN: &[u8] = include_elf!("state-chain-guest");

use std::fs;

use clap::Parser;

/// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub print_program_id: bool,

    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[clap(long, env, short, default_value = "https://rpc.testnet3.goat.network")]
    pub execution_layer_rpc: String,

    #[clap(long, env, default_value = "goattest")]
    pub goat_network: String,

    #[clap(long, env, default_value = "https://rpc.testnet3.goat.network/goat-rpc")]
    pub cosmos_rpc_url: String,

    #[arg(long, default_value = "blocks.bin")]
    pub blocks: String,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "input.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output.bin")]
    pub output_proof: String,

    #[clap(long, env, default_value_t = 10)]
    pub batch_size: u64,

    #[clap(long, env, default_value_t = 0)]
    pub start: u64,

    /// Maximum number of GOAT blocks fetched concurrently.
    #[clap(long, env, default_value_t = default_fetch_concurrency())]
    #[serde(default = "default_fetch_concurrency")]
    pub fetch_concurrency: usize,

    // Print-only mode skips runtime inputs but keeps them required otherwise.
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub l2_contract_addresses: String,
}

fn default_fetch_concurrency() -> usize {
    16
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            self.batch_size
        );
        next_args.blocks = format!("{}.blocks", next_args.input_proof);
        next_args
    }
}

type RpcReceipt = <Ethereum as Network>::ReceiptResponse;
type RpcBlock = <Ethereum as Network>::BlockResponse;
type Withdrawal = (Address, [u8; 32], Vec<[u8; 16]>);

#[derive(Debug, PartialEq, Eq)]
struct BlockWithdrawals {
    block_hash: B256,
    withdrawals: Vec<Withdrawal>,
}

fn input_not_ready(message: impl std::fmt::Display) -> anyhow::Error {
    let message = message.to_string();
    tracing::warn!(error = %message, "withdrawal inputs not ready; retrying the entire batch");
    anyhow::Error::new(proof_builder::ProofError::InputNotReady(3)).context(message)
}

fn parse_gateway_addresses(value: &str) -> anyhow::Result<Vec<Address>> {
    let mut seen = BTreeSet::new();
    value
        .split(',')
        .map(|part| {
            let address: Address = part.trim().parse().context("invalid Gateway address")?;
            anyhow::ensure!(address != Address::ZERO, "Gateway address must not be zero");
            anyhow::ensure!(seen.insert(address), "duplicate Gateway address {address}");
            Ok(address)
        })
        .collect()
}

/// Decode ProceedWithdraw(bytes16 indexed instanceId, bytes16 indexed graphId, bytes32 kickoffTxid).
/// <https://github.com/GOATNetwork/bitvm-L2-contracts/blob/ad14d956ac670414553f08548345627cc7a88e1b/src/interfaces/IGateway.sol#L154>
fn decode_proceed_withdraw(topics: &[B256], data: &[u8]) -> anyhow::Result<[u8; 16]> {
    if topics.len() != 3
        || data.len() != 32
        || topics.first() != Some(&keccak256(b"ProceedWithdraw(bytes16,bytes16,bytes32)"))
        || topics[1].as_slice()[16..].iter().any(|byte| *byte != 0)
        || topics[2].as_slice()[16..].iter().any(|byte| *byte != 0)
    {
        return Err(input_not_ready("malformed ProceedWithdraw event"));
    }
    Ok(topics[2].as_slice()[..16].try_into().unwrap())
}

fn collect_receipt_withdrawals(
    receipt: &RpcReceipt,
    gateways: &[Address],
    block_number: u64,
    block_hash: B256,
    txid: B256,
    tx_index: u64,
    withdrawals: &mut Vec<Withdrawal>,
) -> anyhow::Result<()> {
    if receipt.block_number != Some(block_number)
        || receipt.block_hash != Some(block_hash)
        || receipt.transaction_hash != txid
        || receipt.transaction_index != Some(tx_index)
    {
        return Err(input_not_ready("receipt does not match its block/transaction"));
    }
    if !receipt.status() {
        return Ok(());
    }
    for log in receipt.inner.logs() {
        if !gateways.contains(&log.address())
            || log.topics().first() != Some(&keccak256(b"ProceedWithdraw(bytes16,bytes16,bytes32)"))
        {
            continue;
        }
        if log.removed
            || log.block_hash != Some(block_hash)
            || log.block_number != Some(block_number)
            || log.transaction_hash != Some(txid)
            || log.transaction_index != Some(tx_index)
        {
            return Err(input_not_ready("withdrawal log does not match its receipt"));
        }
        let graph_id = decode_proceed_withdraw(log.topics(), &log.data().data)?;
        if let Some((_, _, graph_ids)) =
            withdrawals.iter_mut().find(|(address, _, _)| *address == log.address())
        {
            if !graph_ids.contains(&graph_id) {
                graph_ids.push(graph_id);
            }
        } else {
            withdrawals.push((log.address(), U256::from(16).to_be_bytes(), vec![graph_id]));
        }
    }
    Ok(())
}

async fn fetch_withdrawal_events(
    provider: &RootProvider<Ethereum>,
    l2_contract_addresses: &[Address],
    height: u64,
) -> anyhow::Result<BlockWithdrawals> {
    // EthGetBlock normalizes a missing transaction list into empty hashes.
    // Read the typed RPC response directly so missing data remains distinguishable.
    let block = provider
        .client()
        .request::<_, Option<RpcBlock>>("eth_getBlockByNumber", (format!("0x{height:x}"), false))
        .await
        .map_err(|error| input_not_ready(format!("get block {height}: {error}")))?
        .ok_or_else(|| input_not_ready(format!("block {height} is missing")))?;
    if block.header.number != height {
        return Err(input_not_ready(format!("wrong block number returned for {height}")));
    }
    if block.transactions.is_uncle() {
        return Err(input_not_ready(format!("block {height} has no transaction list")));
    }
    let block_hash = block.header.hash;
    let mut withdrawals = Vec::new();
    for (index, txid) in block.transactions.hashes().enumerate() {
        let receipt = provider
            .get_transaction_receipt(txid)
            .await
            .map_err(|error| input_not_ready(format!("get receipt {txid}: {error}")))?
            .ok_or_else(|| input_not_ready(format!("receipt {txid} is missing")))?;
        collect_receipt_withdrawals(
            &receipt,
            l2_contract_addresses,
            height,
            block_hash,
            txid,
            index as u64,
            &mut withdrawals,
        )?;
    }
    Ok(BlockWithdrawals { block_hash, withdrawals })
}

fn check_execution_block(
    expected_height: u64,
    expected_hash: B256,
    actual_height: u64,
    actual_hash: B256,
) -> anyhow::Result<()> {
    if expected_height != actual_height || expected_hash != actual_hash {
        return Err(input_not_ready(
            "withdrawal receipts and EVM execution refer to different blocks",
        ));
    }
    Ok(())
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(
    provider: &RootProvider<Ethereum>,
    execution_layer_block_number: u64,
    genesis: &Genesis,
) -> anyhow::Result<EthClientExecutorInput> {
    //let rpc_db = RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;
    let host_executor = EthHostExecutor::eth(chain_spec, custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            execution_layer_block_number,
            provider,
            provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await?;
    Ok(client_input)
}

/// Fetch execution and consensus inputs for GOAT block `i` and match them to its receipts.
async fn fetch_state_block(
    provider: &RootProvider<Ethereum>,
    cosmos: &HttpClient,
    genesis: &Genesis,
    withdrawal_block: BlockWithdrawals,
    i: u64,
    retry_after: u64,
) -> anyhow::Result<CircuitStateBlock> {
    let evm_block = fetch_exection_layer_block(provider, i, genesis).await.map_err(|e| {
        tracing::error!("fetch_exection_layer_block: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;

    check_execution_block(
        i,
        withdrawal_block.block_hash,
        evm_block.current_block.header.number,
        evm_block.current_block.header.hash_slow(),
    )?;
    let parent_beacon_block_root = evm_block
        .current_block
        .header
        .parent_beacon_block_root
        .ok_or_else(|| input_not_ready(format!("block {i} has no parent beacon block root")))?;
    let parent_cosmos_block_height = get_cosmos_block_height_at(cosmos, *parent_beacon_block_root)
        .await
        .map_err(|error| input_not_ready(format!("get parent cosmos block for {i}: {error}")))?;

    let (_, cl_block_number) =
        fetch_cbft_validator_info(cosmos, i, parent_cosmos_block_height, 1000).await.map_err(
            |e| {
                tracing::error!("fetch_cbft_validator_info: {e:?}");
                proof_builder::ProofError::InputNotReady(retry_after)
            },
        )?;
    let cosmos_txns = fetch_cbft_tx_data(cosmos, cl_block_number).await.map_err(|e| {
        tracing::error!("fetch_cbft_tx_data: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;
    let cosmos_block = fetch_cosmos_block(cosmos, cl_block_number).await.map_err(|e| {
        tracing::error!("fetch_cosmos_block: {e:?}");
        proof_builder::ProofError::InputNotReady(retry_after)
    })?;

    tracing::info!("block: {i}, cl_block_number: {cl_block_number}, txns: {}", cosmos_txns.len());

    let withdrawals = withdrawal_block.withdrawals;
    let cosmos_block = serde_json::to_vec(&cosmos_block)?;
    tracing::info!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
    Ok(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals })
}

/// Fetches GOAT blocks `start..start + batch_size`, `concurrency` blocks at a time, in block order.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_state_chain(
    l2_contract_addresses: &str,
    start: u64,
    batch_size: u64,
    execution_layer_rpc: &str,
    blocks_file: &str,
    genesis: &str,
    cosmos_rpc_url: &str,
    concurrency: usize,
) -> anyhow::Result<Vec<CircuitStateBlock>> {
    let l2_contract_addresses = parse_gateway_addresses(l2_contract_addresses)?;
    anyhow::ensure!(start > 0, "Don't get genesis block from the consensus layer");
    anyhow::ensure!(batch_size > 0, "batch_size must be positive");
    let end = start.checked_add(batch_size).context("state-chain block range overflows")?;
    let genesis = if genesis == "goattest" { Genesis::GoatTestnet } else { Genesis::GOAT };
    // One client per layer for the whole batch, so blocks reuse their connections.
    let provider = RootProvider::<Ethereum>::new_http(Url::parse(execution_layer_rpc)?);
    let cosmos = HttpClient::new(cosmos_rpc_url)
        .map_err(|e| anyhow::anyhow!("Invalid cosmos rpc url {cosmos_rpc_url}: {e:?}"))?;
    let concurrency = concurrency.max(1);
    let fetch_start = std::time::Instant::now();

    // Validate the batch's receipts before starting execution witness requests.
    let withdrawals: Vec<BlockWithdrawals> = stream::iter(start..end)
        .map(|height| fetch_withdrawal_events(&provider, &l2_contract_addresses, height))
        .buffered(concurrency)
        .try_collect()
        .await?;
    let blocks: Vec<CircuitStateBlock> = stream::iter((start..end).zip(withdrawals))
        .map(|(i, withdrawal_block)| {
            // GOAT's block time is 3 seconds.
            let retry_after = (end - i).saturating_mul(3);
            fetch_state_block(&provider, &cosmos, &genesis, withdrawal_block, i, retry_after)
        })
        .buffered(concurrency)
        .try_collect()
        .await?;
    tracing::info!(
        "fetched blocks {start}..{end}, {concurrency} at a time, in {:?}",
        fetch_start.elapsed()
    );
    let block_bytes = serde_json::to_vec(&blocks)?;
    std::fs::write(blocks_file, block_bytes)?;
    Ok(blocks)
}

pub struct StateChainProofBuilder {
    client: Arc<ProverClient>,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl StateChainProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_client(Arc::new(ProverClient::new()))
    }

    /// Sets the program up on a prover client that other builders may share.
    pub fn with_client(client: Arc<ProverClient>) -> Self {
        let (proving_key, verifying_key) = client.setup(STATE_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for StateChainProofBuilder {
    fn client(&self) -> &zkm_sdk::ProverClient {
        &self.client
    }

    fn pk(&self) -> &zkm_sdk::ZKMProvingKey {
        &self.proving_key
    }

    fn vk(&self) -> &zkm_sdk::ZKMVerifyingKey {
        &self.verifying_key
    }

    fn name() -> String {
        "state-chain".to_string()
    }

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::StateChainProofRequest { init_input, input_proof, blocks, .. } = ctx
        else {
            anyhow::bail!("Invalid state chain inputs");
        };

        let prev_receipt = if *init_input {
            None
        } else {
            let public_inputs = fs::read(format!("{}.public_inputs.bin", input_proof))
                .context("Read public input")?;
            Some(public_inputs)
        };

        let self_program_id = self.program_id()?;
        let (prev_proof, zkm_proof, zkm_public_values, zkm_vk_hash, zkm_version) =
            match prev_receipt.clone() {
                Some(public_inputs) => {
                    let proof_bytes =
                        fs::read(input_proof).context("Failed to read input proof file")?;
                    let zkm_vk_hash =
                        fs::read(format!("{}.vk_hash.bin", input_proof)).context("Read vk_hash")?;
                    let version_path = format!("{input_proof}.zkm_version.bin");
                    let zkm_version = fs::read(&version_path)
                        .with_context(|| {
                            format!("failed to read zkm_version file '{version_path}'")
                        })
                        .and_then(|raw_zkm_version| {
                            String::from_utf8(raw_zkm_version).with_context(|| {
                                format!("invalid UTF-8 in zkm_version file '{version_path}'")
                            })
                        })?;
                    let prev_proof =
                        classify_state_chain_output(&public_inputs).map_err(anyhow::Error::msg)?;
                    (prev_proof, proof_bytes, public_inputs, zkm_vk_hash.to_vec(), zkm_version)
                }
                None => (
                    StateChainPrevProofType::GenesisBlock,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    ZKM_CIRCUIT_VERSION.into(),
                ),
            };

        let input: StateChainCircuitInput = StateChainCircuitInput {
            prev_proof,
            zkm_proof,
            zkm_public_values,
            zkm_vk_hash,
            zkm_version,
            self_program_id,
            blocks: blocks.clone(),
        };
        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&input);
                let elf_id = if ELF_ID.get().is_none() {
                    ELF_ID
                        .set(hex::encode(Sha256::digest(&self.proving_key.elf)))
                        .map_err(anyhow::Error::msg)?;
                    None
                } else {
                    Some(ELF_ID.get().unwrap().clone())
                };
                tracing::info!("elf id: {:?}", elf_id);

                proof_builder::prove_timed(
                    &self.client,
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )
            },
        )?;
        tracing::info!("State chain proof cycles: {}", cycles);

        self.client
            .verify(&proof, &self.verifying_key)
            .context("Failed to verify generated state chain proof")?;

        let input = bincode::serialize(&input)?;
        Ok((input, proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::StateChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("Invalid state chain inputs");
        };
        let proof_bytes = proof.bytes()?;
        let proof_size = proof_bytes.len();
        let public_values = proof.public_values.to_vec();
        let public_value_hex = hex::encode(&public_values);
        let vk_hash = self.verifying_key.bytes32();
        proof_builder::artifacts::publish_artifacts(
            output_proof,
            &proof_bytes,
            &[
                (".public_inputs.bin", public_values.as_slice()),
                (".vk_hash.bin", vk_hash.as_bytes()),
                (".zkm_version.bin", proof.zkm_version.as_bytes()),
            ],
        )?;

        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }
    fn gateway(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }
    fn log(graph: u8, address: Address, txid: B256, index: u64) -> Value {
        json!({
            "address": address,
            "topics": [keccak256(b"ProceedWithdraw(bytes16,bytes16,bytes32)"),
                format!("0x{}{}", "22".repeat(16), "00".repeat(16)),
                format!("0x{}{}", hex::encode([graph; 16]), "00".repeat(16))],
            "data": format!("0x{}", "00".repeat(32)),
            "blockHash": hash(10), "blockNumber": "0xa", "transactionHash": txid,
            "transactionIndex": format!("0x{index:x}"), "logIndex": "0x0", "removed": false
        })
    }
    fn receipt(txid: B256, index: u64, success: bool, logs: Vec<Value>) -> Value {
        json!({
            "type": "0x0", "status": if success {"0x1"} else {"0x0"},
            "cumulativeGasUsed": "0x1", "gasUsed": "0x1", "effectiveGasPrice": "0x1",
            "logsBloom": format!("0x{}", "00".repeat(256)), "logs": logs,
            "transactionHash": txid, "transactionIndex": format!("0x{index:x}"),
            "blockHash": hash(10), "blockNumber": "0xa", "from": gateway(9),
            "to": gateway(8), "contractAddress": null
        })
    }
    fn block(height: u64, transactions: Vec<B256>) -> Value {
        json!({
            "hash": hash(height as u8), "number": format!("0x{height:x}"),
            "parentHash": hash(0), "sha3Uncles": hash(0), "miner": gateway(0),
            "stateRoot": hash(0), "transactionsRoot": hash(0), "receiptsRoot": hash(0),
            "logsBloom": format!("0x{}", "00".repeat(256)), "difficulty": "0x0",
            "gasLimit": "0xffffff", "gasUsed": "0x1", "timestamp": "0x1",
            "extraData": "0x", "mixHash": hash(0), "nonce": "0x0000000000000000",
            "transactions": transactions, "uncles": [], "size": "0x1"
        })
    }
    fn assert_retry(error: &anyhow::Error) {
        assert!(
            matches!(
                error.downcast_ref::<proof_builder::ProofError>(),
                Some(proof_builder::ProofError::InputNotReady(3))
            ),
            "{error:#}"
        );
    }

    /// Serve real JSON-RPC requests, asserting the extractor never fetches calldata.
    async fn rpc(steps: Vec<(&'static str, Value)>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (method, response) in steps {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (body_offset, content_length) = loop {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while bytes.len() < body_offset + content_length {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let request: Value =
                    serde_json::from_slice(&bytes[body_offset..body_offset + content_length])
                        .unwrap();
                assert_eq!(request["method"], method);
                let mut reply = json!({"jsonrpc": "2.0", "id": request["id"]});
                reply.as_object_mut().unwrap().extend(response.as_object().unwrap().clone());
                let body = serde_json::to_vec(&reply).unwrap();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (url, server)
    }
    async fn finish(server: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn extracts_successful_logs_from_internal_calls_and_merges_all_gateways() {
        let tx1 = hash(1);
        let tx2 = hash(2);
        let tx3 = hash(3);
        let (url, server) = rpc(vec![
            ("eth_getBlockByNumber", json!({"result": block(10, vec![tx1, tx2, tx3])})),
            ("eth_getTransactionReceipt", json!({"result": receipt(tx1, 0, true, vec![log(1, gateway(1), tx1, 0), log(9, gateway(3), tx1, 0)])})),
            ("eth_getTransactionReceipt", json!({"result": receipt(tx2, 1, true, vec![log(2, gateway(1), tx2, 1), log(1, gateway(1), tx2, 1), log(3, gateway(2), tx2, 1)])})),
            ("eth_getTransactionReceipt", json!({"result": receipt(tx3, 2, false, vec![log(99, gateway(1), tx3, 2)])})),
        ]).await;
        let provider = RootProvider::<Ethereum>::new_http(Url::parse(&url).unwrap());
        let batch =
            fetch_withdrawal_events(&provider, &[gateway(1), gateway(2)], 10).await.unwrap();
        assert_eq!(batch.block_hash, hash(10));
        assert_eq!(
            batch.withdrawals,
            vec![
                (gateway(1), U256::from(16).to_be_bytes(), vec![[1; 16], [2; 16]]),
                (gateway(2), U256::from(16).to_be_bytes(), vec![[3; 16]]),
            ]
        );
        finish(server).await;
    }

    #[tokio::test]
    async fn missing_or_failed_receipts_never_return_a_partial_batch() {
        for response in [
            json!({"result": null}),
            json!({"error": {"code": -32000, "message": "backend unavailable"}}),
        ] {
            let (url, server) = rpc(vec![
                ("eth_getBlockByNumber", json!({"result": block(10, vec![hash(1), hash(2)])})),
                ("eth_getTransactionReceipt", json!({"result": receipt(hash(1), 0, true, vec![log(1, gateway(1), hash(1), 0)])})),
                ("eth_getTransactionReceipt", response),
            ]).await;
            let provider = RootProvider::<Ethereum>::new_http(Url::parse(&url).unwrap());
            assert_retry(&fetch_withdrawal_events(&provider, &[gateway(1)], 10).await.unwrap_err());
            finish(server).await;
        }
    }

    #[tokio::test]
    async fn missing_or_failed_blocks_retry_without_overwriting_existing_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocks.json");
        std::fs::write(&file, b"previous complete batch").unwrap();
        for response in [
            json!({"result": null}),
            json!({"error": {"code": -32000, "message": "backend unavailable"}}),
        ] {
            let (url, server) = rpc(vec![
                ("eth_getBlockByNumber", json!({"result": block(10, vec![])})),
                ("eth_getBlockByNumber", response),
            ])
            .await;
            let error = fetch_state_chain(
                &gateway(1).to_string(),
                10,
                2,
                &url,
                file.to_str().unwrap(),
                "goattest",
                "http://127.0.0.1:1",
                1,
            )
            .await
            .unwrap_err();
            assert_retry(&error);
            assert_eq!(std::fs::read(&file).unwrap(), b"previous complete batch");
            finish(server).await;
        }
    }

    #[tokio::test]
    async fn omitted_transaction_list_is_not_treated_as_an_empty_block() {
        let mut value = block(10, vec![hash(1)]);
        value.as_object_mut().unwrap().remove("transactions");
        let (url, server) = rpc(vec![("eth_getBlockByNumber", json!({"result": value}))]).await;
        let provider = RootProvider::<Ethereum>::new_http(Url::parse(&url).unwrap());
        assert_retry(&fetch_withdrawal_events(&provider, &[gateway(1)], 10).await.unwrap_err());
        finish(server).await;
    }

    #[test]
    fn event_decoder_checks_topic_count_and_fixed_bytes_padding() {
        let value = log(1, gateway(1), hash(1), 0);
        let topics: Vec<B256> = serde_json::from_value(value["topics"].clone()).unwrap();
        assert_eq!(decode_proceed_withdraw(&topics, &[0; 32]).unwrap(), [1; 16]);
        for length in 0..3 {
            assert_retry(&decode_proceed_withdraw(&topics[..length], &[0; 32]).unwrap_err());
        }
        let mut padded = topics.clone();
        let mut bytes = padded[2].0;
        bytes[31] = 1;
        padded[2] = B256::from(bytes);
        assert_retry(&decode_proceed_withdraw(&padded, &[0; 32]).unwrap_err());
        assert_retry(&decode_proceed_withdraw(&topics, &[0; 31]).unwrap_err());
    }

    #[test]
    fn mismatched_receipts_and_removed_or_malformed_logs_retry() {
        let original = receipt(hash(1), 0, true, vec![log(1, gateway(1), hash(1), 0)]);
        for (field, wrong) in [
            ("blockHash", json!(hash(99))),
            ("blockNumber", json!("0xb")),
            ("transactionHash", json!(hash(99))),
            ("transactionIndex", json!("0x1")),
        ] {
            let mut value = original.clone();
            value[field] = wrong;
            let decoded: RpcReceipt = serde_json::from_value(value).unwrap();
            assert_retry(
                &collect_receipt_withdrawals(
                    &decoded,
                    &[gateway(1)],
                    10,
                    hash(10),
                    hash(1),
                    0,
                    &mut vec![],
                )
                .unwrap_err(),
            );
        }
        for (field, wrong) in [
            ("removed", json!(true)),
            ("blockHash", json!(hash(99))),
            ("blockNumber", json!("0xb")),
            ("transactionHash", json!(hash(99))),
            ("transactionIndex", json!("0x1")),
            ("data", json!("0x")),
            ("topics", json!([keccak256(b"ProceedWithdraw(bytes16,bytes16,bytes32)")])),
        ] {
            let mut value = original.clone();
            value["logs"][0][field] = wrong;
            let decoded: RpcReceipt = serde_json::from_value(value).unwrap();
            assert_retry(
                &collect_receipt_withdrawals(
                    &decoded,
                    &[gateway(1)],
                    10,
                    hash(10),
                    hash(1),
                    0,
                    &mut vec![],
                )
                .unwrap_err(),
            );
        }
    }

    #[test]
    fn execution_block_must_match_receipts_and_configuration_is_validated() {
        check_execution_block(10, hash(10), 10, hash(10)).unwrap();
        assert_retry(&check_execution_block(10, hash(10), 11, hash(10)).unwrap_err());
        assert_retry(&check_execution_block(10, hash(10), 10, hash(11)).unwrap_err());
        assert_eq!(
            parse_gateway_addresses(&format!(" {}, {} ", gateway(1), gateway(2))).unwrap(),
            vec![gateway(1), gateway(2)]
        );
        for invalid in [
            "".into(),
            "invalid".into(),
            Address::ZERO.to_string(),
            format!("{},{}", gateway(1), gateway(1)),
            format!("{},", gateway(1)),
        ] {
            assert!(parse_gateway_addresses(&invalid).is_err(), "{invalid}");
        }
    }

    /// A block as JSON, minus what changes between fetches of the same block: the cosmos node
    /// that served the light block (behind a load balancer), and the order of the bytecodes,
    /// which come from a hash map and which the guest looks up by hash.
    fn comparable(block: &CircuitStateBlock) -> Value {
        let mut light_block: Value = serde_json::from_slice(&block.cosmos_block).unwrap();
        light_block.as_object_mut().unwrap().remove("provider");
        let mut evm_block = serde_json::to_value(&block.evm_block).unwrap();
        evm_block["bytecodes"].as_array_mut().unwrap().sort_by_key(|code| code.to_string());
        serde_json::json!({
            "cosmos_txns": block.cosmos_txns,
            "light_block": light_block,
            "evm_block": evm_block,
            "withdrawals": block.withdrawals,
        })
    }

    /// The JSON paths at which two values differ.
    fn differing_paths(a: &Value, b: &Value, path: String) -> Vec<String> {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
                keys.into_iter()
                    .flat_map(|k| {
                        let missing = Value::Null;
                        let (x, y) = (x.get(k).unwrap_or(&missing), y.get(k).unwrap_or(&missing));
                        differing_paths(x, y, format!("{path}.{k}"))
                    })
                    .collect()
            }
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => (0..x.len())
                .flat_map(|i| differing_paths(&x[i], &y[i], format!("{path}[{i}]")))
                .collect(),
            _ if a != b => vec![path],
            _ => vec![],
        }
    }

    #[tokio::test]
    #[ignore = "requires public GOAT testnet3 RPC"]
    async fn concurrent_fetch_matches_sequential() {
        let execution_layer_rpc = std::env::var("EXECUTION_LAYER_RPC")
            .unwrap_or("https://rpc-legacy.testnet3.goat.network".to_string());
        let cosmos_rpc_url = std::env::var("COSMOS_RPC_URL")
            .unwrap_or("https://rpc.testnet3.goat.network/goat-rpc".to_string());
        let (start, batch_size) = (17781200, 6);
        let blocks_file = std::env::temp_dir().join("state-chain-fetch-test.blocks");
        let fetch = |concurrency| {
            fetch_state_chain(
                "0x0c7821F1C72181a2C710Eaa91d81120d7e009e41,0x60a5b099eE011018DD064F9eBD50d381C37b5e8b",
                start,
                batch_size,
                &execution_layer_rpc,
                blocks_file.to_str().unwrap(),
                "goattest",
                &cosmos_rpc_url,
                concurrency,
            )
        };

        let sequential = fetch(1).await.unwrap();
        let concurrent = fetch(4).await.unwrap();

        let numbers: Vec<u64> =
            concurrent.iter().map(|b| b.evm_block.current_block.header.number).collect();
        assert_eq!(numbers, (start..start + batch_size).collect::<Vec<_>>());
        for (number, (s, c)) in numbers.iter().zip(sequential.iter().zip(&concurrent)) {
            let paths = differing_paths(&comparable(s), &comparable(c), String::new());
            assert!(paths.is_empty(), "block {number} differs at {}", paths.join(", "));
        }
    }
}
