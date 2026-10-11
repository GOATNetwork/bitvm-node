use bitcoin::Network;
use borsh::{BorshDeserialize, BorshSerialize};
use client::btc_chain::BTCClient;
use header_chain::{
    CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
    classify_header_chain_output,
};
use proof_builder::{LongRunning, ProofBuilder, ProofRequest};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek},
};
use util::get_btc_block_confirms;
use zkm_sdk::ZKMProofKind;
use zkm_sdk::{
    HashableKey, Prover, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofWithPublicValues, ZKMStdin,
    include_elf,
};
static ELF_ID: OnceLock<String> = OnceLock::new();
use anyhow::Context;
use clap::Parser;
use std::sync::OnceLock;

/// The arguments for the cli.
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

    #[clap(long, env, default_value_t = 4)]
    pub batch_size: usize,

    #[clap(long, env, default_value_t = 0)]
    pub start: usize,

    #[clap(long, env, default_value_t = false)]
    pub init_input: bool,

    #[clap(long, env, default_value = "block_headers.bin")]
    pub block_headers: String,

    #[clap(long, env, default_value = "input_proof.bin")]
    pub input_proof: String,

    #[clap(long, env, default_value = "output_proof.bin")]
    pub output_proof: String,

    #[clap(long, default_value_t = false)]
    pub force_fetch: bool,
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
        next_args
    }
}

pub async fn fetch_header_chain(
    esplora_url: &str,
    start: usize,
    batch_size: usize,
    block_header_file: &str,
    force_fetch: bool,
    network: Network,
) -> anyhow::Result<Vec<CircuitBlockHeader>> {
    let btc_client = BTCClient::new(network, Some(esplora_url));

    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(block_header_file)
        .with_context(|| format!("Open {block_header_file} error"))?;

    let mut headers: Vec<u8> = Vec::new();
    writer.read_to_end(&mut headers)?;

    let mut block_headers: Vec<_> = headers
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    if force_fetch {
        block_headers.truncate(start);
    }
    assert!(block_headers.len() == start, "Invalid starting block number");

    writer.seek(std::io::SeekFrom::Start((block_headers.len() * 80) as u64))?;

    let confirmations = get_btc_block_confirms(btc_client.network());

    let mut i = start;
    let mut retries = 9;
    while i < start + batch_size {
        tracing::info!("get block by height: {i}");
        let tip_height = btc_client.get_height().await?;
        if i as u32 + confirmations > tip_height {
            tracing::info!("current tip height: {tip_height}, wait for new block");
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            continue;
        }
        match btc_client.get_block_by_height(i as u32).await {
            Ok(block) => {
                tracing::info!("block_id {i}: {}", block.block_hash().to_string());
                let header: header_chain::CircuitBlockHeader = block.header.into();
                block_headers.push(header.clone());
                header.serialize(&mut writer)?;
                retries = 3;
                i += 1;
            }
            Err(e) => {
                tracing::error!("get block by height {i} error, {e:?}");
                retries -= 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(10000 - retries * 1000))
                    .await;
                if retries == 0 {
                    anyhow::bail!("get block error");
                }
            }
        };
    }
    writer.set_len((block_headers.len() * 80) as u64)?;
    let backup_file = format!(
        "{}/{}-{}.bin.blocks",
        std::path::Path::new(block_header_file).parent().unwrap().to_str().unwrap(),
        start,
        batch_size,
    );
    std::fs::copy(block_header_file, backup_file).context("copy error")?;
    Ok(block_headers)
}

/// A program that aggregates the proofs of the simple program.
pub const HEADER_CHAIN: &[u8] = include_elf!("guest");
pub struct HeaderChainProofBuilder {
    client: ProverClient,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
    // database handle
}

impl HeaderChainProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let client = ProverClient::new();
        let (proving_key, verifying_key) = client.setup(HEADER_CHAIN);
        Self { client, proving_key, verifying_key }
    }
}

impl ProofBuilder for HeaderChainProofBuilder {
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
        "header-chain".to_string()
    }

    #[tracing::instrument(level = "info", skip(self, ctx))]
    fn build_proof(
        &self,
        ctx: &ProofRequest,
    ) -> anyhow::Result<(Vec<u8>, ZKMProofWithPublicValues, u64, f32)> {
        let ProofRequest::HeaderChainProofRequest {
            init_input,
            input_proof,
            start,
            batch_size,
            total_block_headers,
            ..
        } = ctx
        else {
            anyhow::bail!("Invalid proof request type");
        };

        let mut _start = 0;
        // Set the previous proof type based on input_proof argument
        let prev_receipt = if *init_input {
            None
        } else {
            let public_inputs = fs::read(format!("{}.public_inputs.bin", input_proof))
                .with_context(|| {
                    format!("Failed to read public inputs from {}.public_inputs.bin", input_proof)
                })?;
            Some(public_inputs)
        };

        let self_program_id = self.program_id()?;
        let (prev_proof, zkm_proof, zkm_public_values, zkm_vk_hash, zkm_version) =
            match prev_receipt.clone() {
                Some(public_inputs) => {
                    let proof_bytes =
                        fs::read(input_proof).context("Failed to read input proof file").unwrap();
                    let zkm_vk_hash = fs::read(format!("{}.vk_hash.bin", input_proof)).unwrap();
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
                        classify_header_chain_output(&public_inputs).map_err(anyhow::Error::msg)?;
                    (prev_proof, proof_bytes, public_inputs, zkm_vk_hash.to_vec(), zkm_version)
                }
                None => (
                    HeaderChainPrevProofType::GenesisBlock,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    ZKM_CIRCUIT_VERSION.into(),
                ),
            };

        tracing::info!(
            "header-chain length: {}, start: {}, batch_size: {}",
            total_block_headers.len(),
            start,
            batch_size
        );

        let block_headers = total_block_headers[*start..*start + *batch_size].to_vec();
        let input: HeaderChainCircuitInput = HeaderChainCircuitInput {
            prev_proof,
            zkm_proof,
            zkm_public_values,
            zkm_vk_hash,
            zkm_version,
            self_program_id,
            block_headers,
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

        tracing::info!("Header chain proof cycles: {}", cycles);

        self.client
            .verify(&proof, &self.verifying_key)
            .context("Failed to verify generated header chain proof")?;

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
        let ProofRequest::HeaderChainProofRequest { output_proof, .. } = ctx else {
            anyhow::bail!("invalid context");
        };
        //fs::write(&output_proof, bincode::serialize(&proof)?)?;
        //let public_value_hex = hex::encode(proof.public_values.as_slice());
        //let proof_size = proof.bytes().len();
        //fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        //fs::write(&format!("{}.in", output_proof), input)?;

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
