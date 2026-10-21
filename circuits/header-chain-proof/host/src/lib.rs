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
    HashableKey, ProverClient, ZKM_CIRCUIT_VERSION, ZKMProofWithPublicValues, ZKMStdin, include_elf,
};
static ELF_ID: OnceLock<String> = OnceLock::new();
use anyhow::Context;
use clap::Parser;
use std::sync::{Arc, OnceLock};

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

    /// Prefer cached headers for the first batch built from Genesis.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub prefer_local_headers_on_init: bool,
}

impl Args {
    pub fn is_genesis_batch(&self) -> bool {
        self.init_input && self.start == 0
    }
}

impl LongRunning for Args {
    fn rotate(&self) -> Self {
        let mut next_args = self.clone();
        next_args.input_proof = self.output_proof.clone();
        next_args.init_input = false;
        next_args.start = self.start + self.batch_size;
        if self.is_genesis_batch() {
            next_args.batch_size = 1;
        }
        next_args.output_proof = format!(
            "{}/{}-{}.bin",
            std::path::Path::new(&self.output_proof).parent().unwrap().to_str().unwrap(),
            next_args.start,
            next_args.batch_size
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
    prefer_local_headers_on_init: bool,
) -> anyhow::Result<Vec<CircuitBlockHeader>> {
    let btc_client = BTCClient::new(network, Some(esplora_url));
    fetch_header_chain_with_client(
        &btc_client,
        start,
        batch_size,
        block_header_file,
        force_fetch,
        prefer_local_headers_on_init,
    )
    .await
}

async fn fetch_header_chain_with_client(
    btc_client: &BTCClient,
    start: usize,
    batch_size: usize,
    block_header_file: &str,
    force_fetch: bool,
    prefer_local_headers_on_init: bool,
) -> anyhow::Result<Vec<CircuitBlockHeader>> {
    let prefer_local = prefer_local_headers_on_init && start == 0;
    let end = start.checked_add(batch_size).context("Header batch range overflow")?;
    anyhow::ensure!(batch_size > 0, "Header batch size must be positive");

    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(block_header_file)
        .with_context(|| format!("Open {block_header_file} error"))?;

    let mut headers: Vec<u8> = Vec::new();
    if prefer_local || force_fetch {
        let cached_headers = if prefer_local { batch_size } else { start };
        let bytes = cached_headers.checked_mul(80).context("Header cache range overflow")?;
        (&mut writer).take(bytes as u64).read_to_end(&mut headers)?;
    } else {
        writer.read_to_end(&mut headers)?;
    }
    if !prefer_local {
        anyhow::ensure!(headers.len().is_multiple_of(80), "Invalid block header file length");
    }

    let mut block_headers: Vec<_> = headers
        .chunks_exact(80)
        .map(CircuitBlockHeader::try_from_slice)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Read block headers from {block_header_file}"))?;

    if prefer_local {
        tracing::info!(
            cached_headers = block_headers.len(),
            batch_size,
            "Loaded local headers for the Genesis batch"
        );
        if block_headers.len() == batch_size {
            return Ok(block_headers);
        }
    } else {
        if force_fetch {
            block_headers.truncate(start);
        }
        assert_eq!(block_headers.len(), start, "Invalid starting block number");
    }

    writer.seek(std::io::SeekFrom::Start((block_headers.len() * 80) as u64))?;

    let confirmations = get_btc_block_confirms(btc_client.network());

    let mut i = block_headers.len();
    let mut retries = 9;
    while i < end {
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
    // The proof's `.blocks` sidecar is published with the proof (see `save_proof`).
    Ok(block_headers)
}

/// The `.blocks` sidecar of a header-chain proof: every header up to the proof's last
/// block, 80 bytes each. Operator and watchtower proofs read it to build SPV proofs.
pub fn proof_block_headers(headers: &[CircuitBlockHeader]) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(headers.len() * 80);
    for header in headers {
        header.serialize(&mut bytes)?;
    }
    anyhow::ensure!(bytes.len() == headers.len() * 80, "block headers must be 80 bytes each");
    Ok(bytes)
}

/// A program that aggregates the proofs of the simple program.
pub const HEADER_CHAIN: &[u8] = include_elf!("header-chain-guest");
pub struct HeaderChainProofBuilder {
    client: Arc<ProverClient>,
    proving_key: zkm_sdk::ZKMProvingKey,
    verifying_key: zkm_sdk::ZKMVerifyingKey,
    // database handle
}

impl HeaderChainProofBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_client(Arc::new(ProverClient::new()))
    }

    /// Sets the program up on a prover client that other builders may share.
    pub fn with_client(client: Arc<ProverClient>) -> Self {
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

                proof_builder::prove_timed(
                    &self.client,
                    &self.proving_key,
                    &stdin,
                    ZKMProofKind::Groth16,
                    elf_id,
                )
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
        let ProofRequest::HeaderChainProofRequest {
            output_proof,
            start,
            batch_size,
            total_block_headers,
            ..
        } = ctx
        else {
            anyhow::bail!("invalid context");
        };
        let proven_headers = total_block_headers
            .get(..start + batch_size)
            .context("block headers do not cover the proven batch")?;
        let blocks = proof_block_headers(proven_headers)?;
        //fs::write(&output_proof, bincode::serialize(&proof)?)?;
        //let public_value_hex = hex::encode(proof.public_values.as_slice());
        //let proof_size = proof.bytes().len();
        //fs::write(&format!("{}.vk", output_proof), bincode::serialize(&self.verifying_key)?)?;
        //fs::write(&format!("{}.in", output_proof), input)?;

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
                (".blocks", blocks.as_slice()),
            ],
            &format!("{} {}", Self::name(), output_proof),
        )?;

        tracing::info!("Generate proof successfully, proof: {:?}", proof);
        Ok((public_value_hex, proof_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_blocks() -> Vec<bitcoin::Block> {
        let genesis = bitcoin::constants::genesis_block(Network::Testnet4);
        let mut second = genesis.clone();
        second.header.prev_blockhash = genesis.block_hash();
        second.header.nonce += 1;
        let mut third = second.clone();
        third.header.prev_blockhash = second.block_hash();
        third.header.nonce += 1;
        vec![genesis, second, third]
    }

    #[tokio::test]
    async fn genesis_batch_uses_local_headers_without_rpc_and_preserves_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.bin");
        let header: CircuitBlockHeader = test_blocks()[0].header.into();
        let headers = vec![header; 10001];
        let bytes = proof_block_headers(&headers).unwrap();
        fs::write(&path, &bytes).unwrap();
        let (client, _) = BTCClient::new_mock_client();

        // The mock tip is 0, so any RPC fetch would wait for confirmations.
        for force_fetch in [false, true] {
            let fetched = tokio::time::timeout(
                Duration::from_secs(2),
                fetch_header_chain_with_client(
                    &client,
                    0,
                    10000,
                    path.to_str().unwrap(),
                    force_fetch,
                    true,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(fetched, headers[..10000]);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn genesis_batch_fetches_only_missing_headers() {
        let blocks = test_blocks();
        let headers: Vec<CircuitBlockHeader> = blocks.iter().map(|b| b.header.into()).collect();
        let bytes = proof_block_headers(&headers).unwrap();

        for cached_bytes in [None, Some(0), Some(80), Some(160 + 17)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("headers.bin");
            if let Some(len) = cached_bytes {
                fs::write(&path, &bytes[..len]).unwrap();
            }
            let (client, mock) = BTCClient::new_mock_client();
            mock.set_height(100);
            let cached_headers = cached_bytes.unwrap_or(0) / 80;
            for (height, block) in blocks.iter().enumerate().skip(cached_headers) {
                mock.set_block_hash(height as u32, block.block_hash());
                mock.set_block(block.block_hash(), block.clone());
            }

            // Cached heights are absent from the mock and must never be fetched again.
            let fetched = tokio::time::timeout(
                Duration::from_secs(2),
                fetch_header_chain_with_client(&client, 0, 3, path.to_str().unwrap(), true, true),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(fetched, headers);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn disabled_preference_and_later_batches_still_fetch_from_rpc() {
        let blocks = test_blocks();
        for (start, prefer_local) in [(0, false), (1, true)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("headers.bin");
            let mut cached: Vec<CircuitBlockHeader> =
                blocks.iter().map(|b| b.header.into()).collect();
            cached[start].nonce += 100;
            let mut bytes = proof_block_headers(&cached).unwrap();
            bytes.extend_from_slice(&[0; 17]);
            fs::write(&path, bytes).unwrap();
            let (client, mock) = BTCClient::new_mock_client();
            mock.set_height(100);
            let block = &blocks[start];
            mock.set_block_hash(start as u32, block.block_hash());
            mock.set_block(block.block_hash(), block.clone());

            let fetched = fetch_header_chain_with_client(
                &client,
                start,
                1,
                path.to_str().unwrap(),
                true,
                prefer_local,
            )
            .await
            .unwrap();
            let expected: Vec<CircuitBlockHeader> =
                blocks[..=start].iter().map(|b| b.header.into()).collect();
            assert_eq!(fetched, expected);
            assert_eq!(fs::read(&path).unwrap(), proof_block_headers(&expected).unwrap());
        }
    }

    #[test]
    fn genesis_batch_rotates_to_single_block_batches() {
        let mut args = Args::try_parse_from([
            "header-chain-proof",
            "--init-input",
            "--start",
            "0",
            "--batch-size",
            "10000",
            "--bitcoin-network",
            "regtest",
            "--output-proof",
            "/tmp/proofs/0-10000.bin",
            "--prefer-local-headers-on-init",
        ])
        .unwrap();
        assert!(args.prefer_local_headers_on_init && args.is_genesis_batch());

        let next = args.rotate();
        assert_eq!((next.start, next.batch_size), (10000, 1));
        assert!(!next.is_genesis_batch());
        assert_eq!(next.input_proof, args.output_proof);
        assert_eq!(next.output_proof, "/tmp/proofs/10000-1.bin");
        let after_next = next.rotate();
        assert_eq!((after_next.start, after_next.batch_size), (10001, 1));
        assert_eq!(after_next.output_proof, "/tmp/proofs/10001-1.bin");

        args.init_input = false;
        assert!(!args.is_genesis_batch());
        args.init_input = true;
        args.start = 1;
        assert!(!args.is_genesis_batch());
    }

    #[test]
    fn proof_block_headers_matches_the_operator_reader() {
        let genesis: CircuitBlockHeader =
            bitcoin::constants::genesis_block(Network::Bitcoin).header.into();
        let regtest: CircuitBlockHeader =
            bitcoin::constants::genesis_block(Network::Regtest).header.into();
        let headers = vec![genesis.clone(), regtest, genesis];
        let bytes = proof_block_headers(&headers).unwrap();
        assert_eq!(bytes.len(), 3 * 80);
        // Operator and watchtower proofs parse the sidecar 80 bytes at a time.
        let parsed: Vec<_> = bytes
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect();
        assert_eq!(parsed, headers);
        assert_eq!(proof_block_headers(&[]).unwrap(), Vec::<u8>::new());
    }
}
