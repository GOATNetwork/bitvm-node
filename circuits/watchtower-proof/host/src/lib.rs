#![feature(trim_prefix_suffix)]
//! Generate watchtower proof
use anyhow::Context;
use borsh::BorshDeserialize;
use commit_chain::{CommitChainCircuitInput, CommitChainPrevProofType};
use header_chain::{CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use zkm_sdk::{
    HashableKey, ProverClient, ZKMProofKind, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};

use bitcoin::{Block, Network, Transaction, Txid, hashes::Hash};
use bitcoin_light_client_circuit::build_spv;
use sha2::{Digest, Sha256};
use state_chain::{StateChainCircuitInput, StateChainPrevProofType};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
static ELF_ID: OnceLock<String> = OnceLock::new();

use proof_builder::{LongRunning, ProofBuilder, ProofRequest};

use clap::Parser;
use std::fs;

// The arguments for the cli.
#[derive(Debug, Clone, Parser, serde::Deserialize, serde::Serialize)]
pub struct Args {
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub print_program_id: bool,

    #[arg(long, default_value_t = true)]
    pub enable: bool,

    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
    pub esplora_url: String,

    #[arg(long, env, default_value_t = Network::Regtest)]
    pub bitcoin_network: Network,

    // Print-only mode skips runtime inputs but keeps them required otherwise.
    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub genesis_sequencer_commit_txid: String,

    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub latest_sequencer_commit_txid: String,

    #[clap(
        long,
        env,
        short = 'H',
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub header_chain_input_proof: String,

    #[clap(
        long,
        env,
        short,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub commit_chain_input_proof: String,

    #[clap(
        long,
        env,
        short,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub state_chain_input_proof: String,

    #[clap(
        long,
        env,
        required = false,
        required_unless_present = "print_program_id",
        default_value_if("print_program_id", "true", Some(""))
    )]
    pub output: String,
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        self.clone()
    }
}

pub async fn fetch_target_block(
    esplora_url: &str,
    latest_sequencer_commit_txid: &str,
    bitcoin_network: Network,
) -> anyhow::Result<(u32, Block, Transaction)> {
    let btc_client = client::btc_chain::BTCClient::new(bitcoin_network, Some(esplora_url));
    let latest_sequencer_commit_txid = Txid::from_str(latest_sequencer_commit_txid)
        .context("invalid latest sequencer commitment txid")?;
    let tx_info = btc_client
        .get_tx_info(&latest_sequencer_commit_txid)
        .await
        .with_context(|| {
            format!("failed to fetch transaction info for {latest_sequencer_commit_txid}")
        })?
        .with_context(|| format!("transaction {latest_sequencer_commit_txid} not found"))?;
    anyhow::ensure!(
        tx_info.status.confirmed,
        "transaction {latest_sequencer_commit_txid} is not confirmed"
    );
    let block_pos =
        tx_info.status.block_height.context("confirmed transaction is missing its block height")?;
    let block_hash =
        tx_info.status.block_hash.context("confirmed transaction is missing its block hash")?;
    tracing::info!("block height: {block_pos}");
    let target_block = btc_client
        .get_block_by_hash(&block_hash)
        .await
        .with_context(|| format!("failed to fetch block {block_hash}"))?
        .with_context(|| format!("block {block_hash} not found"))?;
    let latest_sequencer_commit_tx = tx_info.to_tx();

    Ok((block_pos, target_block, latest_sequencer_commit_tx))
}

/// A program that aggregates the proofs of the simple program.
pub const WATCHTOWER: &[u8] = include_elf!("watchtower-guest");
pub struct WatchtowerProofBuilder {
    client: Arc<ProverClient>,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
}

impl WatchtowerProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_client(Arc::new(ProverClient::new()))
    }

    /// Sets the program up on a prover client that other builders may share.
    pub fn with_client(client: Arc<ProverClient>) -> Self {
        let (proving_key, verifying_key) = client.setup(WATCHTOWER);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for WatchtowerProofBuilder {
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
        "watchtower-chain".to_string()
    }

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::WatchtowerProofRequest {
            header_chain_input_proof,
            commit_chain_input_proof,
            state_chain_input_proof,
            genesis_sequencer_commit_txid,
            target_block,
            block_pos,
            latest_sequencer_commit_tx,
            ..
        } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        // --- header chain --- //
        let header_chain_input = {
            let zkm_public_values =
                fs::read(format!("{}.public_inputs.bin", header_chain_input_proof)).unwrap();
            let zkm_proof = fs::read(header_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_vk_hash =
                fs::read(format!("{}.vk_hash.bin", header_chain_input_proof)).unwrap();
            let version_path = format!("{header_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;
            let self_program_id =
                verifier::program_id(&zkm_vk_hash, &zkm_version).map_err(anyhow::Error::msg)?;

            HeaderChainCircuitInput {
                prev_proof: HeaderChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
                self_program_id,
                block_headers: vec![],
            }
        };

        // --- commit chain --- //
        let commit_chain_input = {
            let zkm_public_values =
                fs::read(format!("{}.public_inputs.bin", commit_chain_input_proof)).unwrap();
            let zkm_proof = fs::read(commit_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_vk_hash =
                fs::read(format!("{}.vk_hash.bin", commit_chain_input_proof)).unwrap();
            let version_path = format!("{commit_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;
            let self_program_id =
                verifier::program_id(&zkm_vk_hash, &zkm_version).map_err(anyhow::Error::msg)?;
            CommitChainCircuitInput {
                prev_proof: CommitChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
                self_program_id,
                commits: vec![],
            }
        };

        // --- state chain --- //
        let state_chain_input = {
            let zkm_proof = fs::read(state_chain_input_proof)
                .context("Failed to read input proof file")
                .unwrap();
            let zkm_public_values =
                fs::read(format!("{}.public_inputs.bin", state_chain_input_proof)).unwrap();
            let zkm_vk_hash = fs::read(format!("{}.vk_hash.bin", state_chain_input_proof)).unwrap();
            let version_path = format!("{state_chain_input_proof}.zkm_version.bin");
            let zkm_version = fs::read(&version_path)
                .with_context(|| format!("failed to read zkm_version file '{version_path}'"))
                .and_then(|raw_zkm_version| {
                    String::from_utf8(raw_zkm_version).with_context(|| {
                        format!("invalid UTF-8 in zkm_version file '{version_path}'")
                    })
                })?;
            let self_program_id =
                verifier::program_id(&zkm_vk_hash, &zkm_version).map_err(anyhow::Error::msg)?;
            StateChainCircuitInput {
                prev_proof: StateChainPrevProofType::GenesisBlock, // unused
                zkm_proof,
                zkm_public_values,
                zkm_vk_hash,
                zkm_version,
                self_program_id,
                blocks: vec![],
            }
        };
        // --- spv --- //
        let genesis_sequencer_commit_txid = Txid::from_str(genesis_sequencer_commit_txid)?;
        let bitcoin_block_headers = {
            let headers: Vec<u8> = std::fs::read(format!("{header_chain_input_proof}.blocks"))?;
            headers
                .chunks(80)
                .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
                .collect::<Vec<CircuitBlockHeader>>()
        };
        tracing::info!("block headers: {:?}", bitcoin_block_headers.len());
        let found = bitcoin_block_headers
            .iter()
            .position(|h| h.compute_block_hash() == *target_block.block_hash().as_byte_array());
        tracing::info!("block found: {:?}", found);
        if found.is_none() {
            anyhow::bail!(
                "Latest sequencer set commitment tx is not included in header chain blocks"
            );
        }

        tracing::info!("construct spv");
        let spv = build_spv(
            latest_sequencer_commit_tx,
            *block_pos,
            target_block.clone(),
            &bitcoin_block_headers,
        );

        // Generate the proofs.
        let (proof, cycles, proving_time) = tracing::info_span!("generate proof").in_scope(
            || -> anyhow::Result<(ZKMProofWithPublicValues, u64, f32)> {
                let mut stdin = ZKMStdin::new();
                stdin.write(&genesis_sequencer_commit_txid.to_byte_array());
                stdin.write(&header_chain_input);
                stdin.write(&commit_chain_input);
                stdin.write(&state_chain_input);
                stdin.write(&spv);
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

        self.client
            .verify(&proof, &self.verifying_key)
            .context("Failed to verify generated watchtower proof")?;

        Ok((vec![], proof, cycles, proving_time))
    }

    fn save_proof(
        &self,
        ctx: &ProofRequest,
        _input: &[u8],
        _cycles: u64,
        proof: ZKMProofWithPublicValues,
    ) -> anyhow::Result<(String, usize)> {
        let ProofRequest::WatchtowerProofRequest { output, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        let proof_bytes = proof.bytes()?;
        let proof_size = proof_bytes.len();
        let public_values = proof.public_values.to_vec();
        let public_value_hex = hex::encode(&public_values);
        let vk_hash = self.verifying_key.bytes32();
        proof_builder::artifacts::publish_artifacts(
            output,
            &proof_bytes,
            &[
                (".public_inputs.bin", public_values.as_slice()),
                (".vk_hash.bin", vk_hash.as_bytes()),
                (".zkm_version.bin", proof.zkm_version.as_bytes()),
            ],
        )?;
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires public testnet4 Esplora"]
    async fn fetch_target_block_from_testnet4() -> anyhow::Result<()> {
        let (block_num, block, tx) = fetch_target_block(
            "https://mempool.space/testnet4/api",
            "c2d816940391da550af23c7924f8d9ecd276cdf6a22a164fc44443f5eba6d4b5",
            Network::Testnet4,
        )
        .await?;
        // println!("fetch_target_block result: {block_num:#?}, {block:#?}, {tx:#?}");

        assert_eq!(block_num, 146920);
        assert_eq!(
            block.block_hash(),
            bitcoin::BlockHash::from_str(
                "00000000000000024f1da869c78a77e4b88043ca8ed57f76fb79d180578897a8"
            )?
        );
        assert_eq!(
            tx.compute_txid().to_string(),
            "c2d816940391da550af23c7924f8d9ecd276cdf6a22a164fc44443f5eba6d4b5"
        );
        Ok(())
    }
}
