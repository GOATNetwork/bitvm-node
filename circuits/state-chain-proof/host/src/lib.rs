#![feature(trim_prefix_suffix)]
use alloy_consensus::transaction::Transaction;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_provider::{RootProvider, network::Ethereum};
use anyhow::Context;
use bitcoin_light_client_circuit::EthClientExecutorInput;
use cbft_rpc::{
    fetch_cbft_tx_data, fetch_cbft_validator_info, fetch_cosmos_block, get_cosmos_block_height_at,
};
use host_executor::EthHostExecutor;
use primitives::genesis::Genesis;
use proof_builder::ProofRequest;
use proof_builder::{LongRunning, ProofBuilder};
use reth_chainspec::ChainSpec;
use state_chain::*;
use std::sync::Arc;
use url::Url;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofKind, ZKMProofWithPublicValues,
    ZKMStdin, include_elf,
};

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use util::hex_parse;
static ELF_ID: OnceLock<String> = OnceLock::new();

/// A program that aggregates the proofs of the simple program.
const STATE_CHAIN: &[u8] = include_elf!("guest");

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

    // Print-only mode skips runtime inputs but keeps them required otherwise.
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub l2_contract_addresses: String,

    // https://explorer.testnet3.goat.network/address/0x9F0A61ce47678F43A326dB9F8964C56a924cd3D0?tab=read_write_contract
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub proceed_withdraw_method_ids: String,
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

async fn fetch_withdrawal_events(
    execution_layer_rpc: &str,
    l2_contract_addresses: &[Address],
    proceed_withdraw_method_ids: &[[u8; 4]],
    start: u64,
    batch_size: u64,
) -> anyhow::Result<Vec<(u64, [u8; 16], Address)>> {
    let rpc_url = Url::parse(execution_layer_rpc)?;
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);
    let mut withdrawals = vec![];
    for i in start..start + batch_size {
        let block = match provider.get_block(i.into()).await {
            Ok(Some(x)) => x,
            Ok(None) => {
                tracing::error!("get block {i} returns none");
                continue;
            }
            Err(e) => {
                tracing::error!("get block {i} error, {e}");
                continue;
            }
        };
        for txid in block.transactions.hashes() {
            let txn = match provider.get_transaction_by_hash(txid).await {
                Ok(Some(x)) => x,
                Ok(None) => {
                    tracing::error!("get transaction by hash {txid} returns none");
                    continue;
                }
                Err(e) => {
                    tracing::error!("get transaction by hash {txid} error, {e}");
                    continue;
                }
            };
            let to = txn.to();
            let input = txn.input();
            l2_contract_addresses.iter().zip(proceed_withdraw_method_ids.iter()).for_each(
                |(l2_contract_address, proceed_withdraw_method_id)| {
                    if to == Some(*l2_contract_address)
                        && &input[0..4] == proceed_withdraw_method_id
                    {
                        let graph_id: [u8; 16] = input[4..16 + 4].try_into().unwrap();
                        withdrawals.push((i, graph_id, *l2_contract_address));
                        println!("block: {i}, graph_id: {:?}", hex::encode(graph_id));
                    }
                },
            );
        }
    }
    Ok(withdrawals)
}

// https://github.com/ProjectZKM/reth-processor/blob/stateless/crates/executor/host/tests/integration.rs#L69
async fn fetch_exection_layer_block(
    execution_layer_rpc: &str,
    execution_layer_block_number: u64,
    genesis: &Genesis,
) -> anyhow::Result<EthClientExecutorInput> {
    // Setup the provider.
    let rpc_url = Url::parse(execution_layer_rpc)?;
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);
    //let rpc_db = RpcDb::new(provider.clone(), provider.clone(), execution_layer_block_number - 1);
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());
    let custom_beneficiary = None;
    let host_executor = EthHostExecutor::eth(chain_spec, custom_beneficiary);
    // Execute the host.
    let client_input = host_executor
        .execute(
            execution_layer_block_number,
            &provider,
            &provider,
            genesis.clone(),
            custom_beneficiary,
            false,
        )
        .await?;
    Ok(client_input)
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_state_chain(
    l2_contract_addresses: &str,
    proceed_withdraw_method_ids: &str,
    start: u64,
    batch_size: u64,
    execution_layer_rpc: &str,
    blocks_file: &str,
    genesis: &str,
    cosmos_rpc_url: &str,
) -> anyhow::Result<Vec<CircuitStateBlock>> {
    let l2_contract_addresses: Vec<Address> = l2_contract_addresses
        .split(',')
        .map(|s| {
            let addr = s.trim().trim_start_matches("0x");
            let bytes: [u8; 20] = hex::decode(addr).unwrap().try_into().unwrap();
            Address::from(bytes)
        })
        .collect();
    let proceed_withdraw_method_ids: Vec<[u8; 4]> =
        proceed_withdraw_method_ids.split(',').map(|s| hex_parse::<4>(s).unwrap()).collect();

    let genesis = if genesis == "goattest" { Genesis::GoatTestnet } else { Genesis::GOAT };
    assert!(start > 0, "Don't get genesis block from the consensus layer.");
    let mut blocks: Vec<_> = Vec::new();
    let base_slot: [u8; 32] = U256::from(16).to_be_bytes();
    // fetch graph_block_numbers and graph_ids between in goat block(start, start + batch_size)
    let withdrawal_events = fetch_withdrawal_events(
        execution_layer_rpc,
        &l2_contract_addresses,
        &proceed_withdraw_method_ids,
        start,
        batch_size,
    )
    .await?;

    for i in start..(start + batch_size) {
        let evm_block =
            fetch_exection_layer_block(execution_layer_rpc, i, &genesis).await.map_err(|e| {
                tracing::error!("fetch_exection_layer_block: {e:?}");
                proof_builder::ProofError::InputNotReady((batch_size + start - i) * 3)
            })?;

        let parent_beacon_block_root =
            evm_block.current_block.header.parent_beacon_block_root.unwrap();

        let parent_cosmos_block_height =
            get_cosmos_block_height_at(cosmos_rpc_url, *parent_beacon_block_root)
                .await
                .unwrap_or_default();

        let (_, cl_block_number) =
            fetch_cbft_validator_info(cosmos_rpc_url, i, parent_cosmos_block_height, 1000)
                .await
                .map_err(|e| {
                    tracing::error!("fetch_cbft_validator_info: {e:?}");
                    // GOAT's block time is 3 seconds
                    proof_builder::ProofError::InputNotReady((batch_size + start - i) * 3)
                })?;
        let cosmos_txns =
            fetch_cbft_tx_data(cosmos_rpc_url, cl_block_number).await.map_err(|e| {
                tracing::error!("fetch_cbft_tx_data: {e:?}");
                proof_builder::ProofError::InputNotReady((batch_size + start - i) * 3)
            })?;
        let cosmos_block =
            fetch_cosmos_block(cosmos_rpc_url, cl_block_number).await.map_err(|e| {
                tracing::error!("fetch_cosmos_block: {e:?}");
                proof_builder::ProofError::InputNotReady((batch_size + start - i) * 3)
            })?;

        tracing::info!(
            "block: {i}, cl_block_number: {cl_block_number}, txns: {}",
            cosmos_txns.len()
        );

        // for block i, find the contract call with graph_id in its input
        let mut withdrawals: Vec<(Address, [u8; 32], Vec<[u8; 16]>)> = Vec::new();
        withdrawal_events.iter().enumerate().filter(|&(_, &val)| val.0 == i).for_each(|(i, _)| {
            let graph_id = withdrawal_events[i].1;
            let l2_contract_address = withdrawal_events[i].2;
            let graph_ids = withdrawals
                .iter()
                .find(|(addr, _, _)| *addr == l2_contract_address)
                .map(|(_, _, graph_ids)| graph_ids.clone())
                .unwrap_or(vec![graph_id]);
            withdrawals.push((l2_contract_address, base_slot, graph_ids));
        });

        // merge the graph ids of a same contract into one

        let cosmos_block = serde_json::to_vec(&cosmos_block)?;
        tracing::info!("[push] block: {}, withdrawals: {:?}", i, withdrawals);
        blocks.push(CircuitStateBlock { cosmos_txns, cosmos_block, evm_block, withdrawals });
    }
    let block_bytes = serde_json::to_vec(&blocks)?;
    std::fs::write(blocks_file, block_bytes)?;
    Ok(blocks)
}

pub struct StateChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl StateChainProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let client = ProverClient::new();
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

                let proving_start = tokio::time::Instant::now();
                let (proof, cycles) = self.client.prove_with_cycles(
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )?;
                let proving_duration = proving_start.elapsed().as_secs_f32() * 1000.0;
                Ok((proof, cycles, proving_duration))
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
        std::fs::write(output_proof, &proof_bytes)?;
        let public_value_hex = hex::encode(proof.public_values.to_vec());
        let proof_size = proof_bytes.len();
        let zkm_version = proof.zkm_version.clone();
        std::fs::write(
            format!("{}.public_inputs.bin", output_proof),
            proof.public_values.to_vec(),
        )?;
        std::fs::write(format!("{}.vk_hash.bin", output_proof), self.verifying_key.bytes32())?;
        std::fs::write(format!("{}.zkm_version.bin", output_proof), zkm_version)?;

        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}
