//! Create and sign a sequencer set publish transaction.
//!   * Publish sequencer set commitment to Bitcoin
//!
//! Launch the local bitcoin regtest node with:
//! ```sh
//! cd ../scripts
//! docker-compose -f docker-compose.yml up -d
//! ```
use bitcoin::CompressedPublicKey;
use bitcoin::{
    Address, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, absolute::LockTime, hashes::Hash, key::Keypair, transaction::Version,
};
use bitvm_noded::env::{
    ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
    ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS, get_goat_address_from_env, get_network,
};
use bitvm_noded::utils::wait_tx_confirmation;
use bitvm_noded::utils::{broadcast_tx, get_fee_rate};
use bitvm_noded::utils::{node_p2wsh_address, node_sign};
use clap::{Parser, Subcommand};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::goat_chain::GoatInitConfig;
use client::goat_chain::SequencerSetUpdateWitness;
use dotenv::dotenv;
use hex::FromHex;
use tracing_subscriber::EnvFilter;

use cbft_rpc::fetch_validators;
const RELAYER_FEE: u64 = 500; // satoshis, just to make sure the tx gets mined in time. This is not the actual fee amount.

use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin_light_client_circuit::{
    /*create_dummy_publisher_keys,*/ create_fee_tx, create_sequencer_update_partial_tx,
    estimate_tx_vbytes,
};
use commit_chain::{
    AuthorizedProgramIds, CommitInfo, commit_chain_commitment_digest,
    create_sequencer_update_script, finalize, sign_raw,
};
use header_chain::{
    HeaderChainPrevProofType, classify_header_chain_output, decode_header_chain_circuit_output,
};
use state_chain::{
    StateChainPrevProofType, classify_state_chain_output, decode_state_chain_circuit_output,
};
use tendermint::validator::Info;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::str::FromStr;
use util::hex_parse;
const FEE_RATE_FACTOR: f64 = 5.0;

pub fn decode_btc_public_keys(pubkey: &str) -> Result<secp256k1::PublicKey, String> {
    secp256k1::PublicKey::from_str(pubkey.trim())
        .map_err(|e| format!("Invalid bitcoin public key: {pubkey}, err: {e:?}"))
}

pub fn decode_eth_address(addr: &str) -> Result<[u8; 20], hex::FromHexError> {
    // Strip 0x if it exists
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    // Decode into Vec<u8>
    let bytes = Vec::from_hex(addr)?;

    // Ensure it's 20 bytes
    let arr: [u8; 20] = bytes.try_into().expect("Ethereum address must be 20 bytes");
    Ok(arr)
}

#[derive(Parser, Debug)]
#[command(name = "sequencer-set-publisher", version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Local bitcoin testnet
    #[arg(long, env, default_value = "http://127.0.0.1:3002")]
    esplora_url: String,

    #[arg(long, env, default_value = "https://rpc.testnet3.goat.network")]
    goat_rpc_url: String,

    #[clap(long, env, default_value = "https://rpc.testnet3.goat.network/goat-rpc")]
    cosmos_rpc_url: String,

    #[arg(long, env, env = "GOAT_EVM_PRVKEY")]
    goat_evm_prvkey: Option<String>,

    #[arg(long, env = "OUTPUT_FILE", default_value = "output.data")]
    output_file: String,

    #[arg(long, env = "DB_PATH", default_value = "sqlite:/tmp/bitvm-node.db")]
    db_path: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
struct OutputData {
    funding_input: Option<OutPoint>,
    fee_tx: Option<OutPoint>,
    update_connector: Option<OutPoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramIdManifest {
    network: bitcoin::Network,
    zkm_version: String,
    authorized_program_ids: ManifestProgramIds,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestProgramIds {
    header: String,
    state: String,
    commit: String,
    watchtower: String,
}

impl ManifestProgramIds {
    /// Decodes the four 0x-prefixed or plain hex ProgramIds from the release manifest.
    fn decode(self) -> anyhow::Result<AuthorizedProgramIds> {
        Ok(AuthorizedProgramIds {
            header: hex_parse::<32>(&self.header).map_err(anyhow::Error::msg)?,
            state: hex_parse::<32>(&self.state).map_err(anyhow::Error::msg)?,
            commit: hex_parse::<32>(&self.commit).map_err(anyhow::Error::msg)?,
            watchtower: hex_parse::<32>(&self.watchtower).map_err(anyhow::Error::msg)?,
        })
    }
}

#[cfg(test)]
mod program_id_manifest_tests {
    use super::*;

    #[test]
    fn decodes_four_program_ids_and_rejects_removed_operator() {
        let id = format!("0x{}", "01".repeat(32));
        let value = serde_json::json!({
            "header": id,
            "state": id,
            "commit": id,
            "watchtower": id,
        });
        assert_eq!(
            serde_json::from_value::<ManifestProgramIds>(value.clone())
                .unwrap()
                .decode()
                .unwrap()
                .watchtower,
            [1u8; 32]
        );
        let mut invalid = value.as_object().unwrap().clone();
        invalid.insert("operator".to_string(), serde_json::Value::String(id));
        assert!(
            serde_json::from_value::<ManifestProgramIds>(serde_json::Value::Object(invalid))
                .is_err()
        );
    }
}

/// Loads and validates the ProgramIds authorized for the target Bitcoin network.
fn load_program_id_manifest(
    path: &str,
    expected_network: bitcoin::Network,
) -> anyhow::Result<AuthorizedProgramIds> {
    let manifest: ProgramIdManifest = serde_json::from_slice(&std::fs::read(path)?)?;
    anyhow::ensure!(
        manifest.network == expected_network,
        "ProgramId manifest network does not match Bitcoin client"
    );
    zkm_verifier::Groth16Verifier::get_part_stark_vk(&manifest.zkm_version);
    let authorized_program_ids = manifest.authorized_program_ids.decode()?;
    authorized_program_ids.validate().map_err(anyhow::Error::msg)?;
    Ok(authorized_program_ids)
}
impl OutputData {
    fn merge(&mut self, other: OutputData) {
        if other.fee_tx.is_some() {
            self.fee_tx = other.fee_tx;
        }
        if other.funding_input.is_some() {
            self.funding_input = other.funding_input;
        }
        if other.update_connector.is_some() {
            self.update_connector = other.update_connector;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn save_commit_info(
    output_file: &str,
    btc_public_keys: &[secp256k1::PublicKey],
    next_btc_public_keys: &[secp256k1::PublicKey],
    sequencers: Vec<Info>,
    init_genesis: bool,
    commit_info_file: &str,
    genesis_evm_block_hash: [u8; 32],
    program_history_root: [u8; 32],
    proof_checkpoint_root: [u8; 32],
    authorized_program_ids: AuthorizedProgramIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(output_file)?;
    let output: OutputData = serde_json::from_reader(file).unwrap();

    let txid = &output.update_connector.unwrap().txid.to_string();
    let genesis_txid = if !init_genesis {
        std::fs::read_to_string(format!("{output_file}.genesis")).unwrap()
    } else {
        std::fs::write(format!("{output_file}.genesis"), txid).unwrap();
        txid.clone()
    };
    let commit_info = CommitInfo {
        txid: txid.clone(),
        threshold: (btc_public_keys.len() * 2).div_ceil(3) as u16,
        publisher_public_keys: btc_public_keys.iter().map(|pubkey| pubkey.to_string()).collect(),
        next_threshold: Some((next_btc_public_keys.len() * 2).div_ceil(3) as u16),
        next_publisher_public_keys: Some(
            next_btc_public_keys.iter().map(|pubkey| pubkey.to_string()).collect(),
        ),
        genesis_txid,
        sequencers: sequencers.iter().cloned().map(|v| v.into()).collect(),
        genesis_evm_block_hash,
        program_history_root,
        proof_checkpoint_root,
        authorized_program_ids,
    };

    let commit_info = serde_json::to_string(&commit_info).unwrap();
    Ok(std::fs::write(commit_info_file, commit_info)?)
}

fn save_output(input: OutputData, output_file: &str) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(output_file)
        .unwrap();

    let mut buf = vec![];
    let old_output = file.read_to_end(&mut buf).unwrap();
    drop(file);
    let output = {
        if old_output > 0 {
            let mut output: OutputData = serde_json::from_slice(&buf).unwrap();
            output.merge(input);
            output
        } else {
            input
        }
    };
    std::fs::write(output_file, serde_json::to_string_pretty(&output).unwrap()).unwrap();
}

/// Query sequencer set hash from local DB.
/// Find the first record at or before `goat_block_number`.
/// That is, the sequencer set hash at that goat block.
async fn get_sequencer_set_hash_from_db(
    db_path: &str,
    goat_block_number: u64,
) -> Result<([u8; 32], u64), Box<dyn std::error::Error>> {
    let local_db = store::create_local_db(db_path).await;
    let mut storage = local_db.acquire().await?;
    let record = storage
        .find_first_sequencer_set_hash_change_by_goat_block_at_or_before(i64::try_from(
            goat_block_number,
        )?)
        .await?;
    let record =
        record.ok_or("No validators_hash record found in db. Start the monitor task first")?;

    let sequencer_set_hash = <[u8; 32]>::from_hex(record.validators_hash.trim_start_matches("0x"))?;
    let cosmos_block_number = u64::try_from(record.cosmos_block_height)?;

    Ok((sequencer_set_hash, cosmos_block_number))
}

#[derive(Subcommand, Debug)]
enum Commands {
    DeriveProgramHistoryRoot {
        #[arg(long)]
        header_chain_input_proof: String,
        #[arg(long)]
        state_chain_input_proof: String,
        #[arg(long, env = "PROGRAM_ID_MANIFEST")]
        program_id_manifest: String,
    },
    Pubkey {
        #[arg(long, short, value_delimiter = ',')]
        btc_key_wifs: Vec<String>,
    },
    Fund {
        #[arg(long, env = "FUND_BTC_KEY_WIF")]
        fund_btc_key_wif: Option<String>,
        #[arg(long, env = "BTC_PUBLIC_KEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        btc_public_keys: Vec<secp256k1::PublicKey>,
    },
    SignSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, env = "NEXT_PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        next_publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, env = "GOAT_GENESIS_BLOCK_HASH", value_parser = hex_parse::<32>)]
        goat_genesis_block_hash: [u8; 32],
        #[arg(long, env = "PROGRAM_HISTORY_ROOT", value_parser = hex_parse::<32>)]
        program_history_root: [u8; 32],
        #[arg(long, env = "PROOF_CHECKPOINT_ROOT", value_parser = hex_parse::<32>)]
        proof_checkpoint_root: [u8; 32],
        #[arg(long, env = "PROGRAM_ID_MANIFEST")]
        program_id_manifest: String,
    },
    PushSeq {
        #[arg(long, env = "OWNER_BTC_KEY_WIF")]
        owner_btc_key_wif: Option<String>,
        #[arg(long)]
        goat_block_number: u64,
        #[arg(long, env = "PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, env = "NEXT_PUBLISHER_BTC_PUBKEYS", value_delimiter = ',', value_parser = decode_btc_public_keys)]
        next_publisher_btc_pubkeys: Vec<secp256k1::PublicKey>,
        #[arg(long, default_value_t = false)]
        init_genesis: bool,
        #[arg(long, env = "GOAT_GENESIS_BLOCK_HASH", value_parser = hex_parse::<32>)]
        goat_genesis_block_hash: [u8; 32],
        #[arg(long, env = "PROGRAM_HISTORY_ROOT", value_parser = hex_parse::<32>)]
        program_history_root: [u8; 32],
        #[arg(long, env = "PROOF_CHECKPOINT_ROOT", value_parser = hex_parse::<32>)]
        proof_checkpoint_root: [u8; 32],
        #[arg(long, env = "PROGRAM_ID_MANIFEST")]
        program_id_manifest: String,
        #[arg(long)]
        commit_info: String,
    },
    Payfee {
        #[arg(long, env = "FUND_BTC_KEY_WIF")]
        fund_btc_key_wif: String,
        #[arg(long, env = "OWNER_BTC_PUBLIC_KEY")]
        owner_btc_public_key: String,
        #[arg(long)]
        funding_input_txid: Option<String>,
        #[arg(long)]
        funding_input_vout: Option<u32>,
        #[arg(long, env = "GOAT_EVM_ADDRESS", value_parser = decode_eth_address)]
        goat_evm_address: [u8; 20],
        #[arg(long)]
        total: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let dummy_publisher_keys: Vec<_> = create_dummy_publisher_keys(5);
    //println!("dummy keys: {:?}", dummy_publisher_keys);
    dotenv().ok();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let args = Args::parse();
    if let Commands::DeriveProgramHistoryRoot {
        header_chain_input_proof,
        state_chain_input_proof,
        program_id_manifest,
    } = &args.command
    {
        let authorized_program_ids = load_program_id_manifest(program_id_manifest, get_network())?;
        let (program_history_root, proof_checkpoint_root) = derive_authorization_roots(
            header_chain_input_proof,
            state_chain_input_proof,
            authorized_program_ids.header,
            authorized_program_ids.state,
        )?;
        println!("program_history_root=0x{}", hex::encode(program_history_root));
        println!("proof_checkpoint_root=0x{}", hex::encode(proof_checkpoint_root));
        return Ok(());
    }
    let (btc_client, goat_client) = init_clients(&args).await?;

    let output_file = &args.output_file;
    let cached_data = std::fs::read(output_file);
    let cached_output: OutputData = match cached_data {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            eprintln!("Failed to parse output file (possibly schema change), using default: {e:?}");
            OutputData::default()
        }),
        _ => OutputData::default(),
    };

    match args.command {
        Commands::DeriveProgramHistoryRoot { .. } => unreachable!(),
        Commands::Pubkey { btc_key_wifs } => {
            // calculate compressed public key
            btc_key_wifs.iter().for_each(|btc_key_wif| {
                let secp = secp256k1::Secp256k1::new();
                let private_key = PrivateKey::from_wif(btc_key_wif).expect("Invalid BTC WIF Key");
                println!("Public Key: {}", private_key.public_key(&secp));
            });
            Ok(())
        }
        Commands::Fund { fund_btc_key_wif, btc_public_keys } => {
            action_fund_publishers(
                &btc_client,
                fund_btc_key_wif,
                btc_public_keys,
                &args.output_file,
            )
            .await
        }
        Commands::Payfee {
            fund_btc_key_wif,
            owner_btc_public_key,
            funding_input_txid,
            funding_input_vout,
            goat_evm_address,
            total,
        } => {
            let funding_input = match (funding_input_txid, funding_input_vout) {
                (Some(txid), Some(vout)) => {
                    Some(OutPoint::new(Txid::from_str(&txid).unwrap(), vout))
                }
                _ => None,
            };
            action_push_fee_tx(
                &btc_client,
                &fund_btc_key_wif,
                &owner_btc_public_key,
                total,
                funding_input,
                goat_evm_address,
                output_file,
            )
            .await
        }
        Commands::SignSeq {
            owner_btc_key_wif,
            goat_block_number,
            publisher_btc_pubkeys,
            next_publisher_btc_pubkeys,
            goat_genesis_block_hash,
            program_history_root,
            proof_checkpoint_root,
            program_id_manifest,
        } => {
            let authorized_program_ids =
                load_program_id_manifest(&program_id_manifest, btc_client.network())?;
            let (sequencer_set_hash, cosmos_block_number) =
                get_sequencer_set_hash_from_db(&args.db_path, goat_block_number).await?;
            println!(
                "resolved cl block number: {cosmos_block_number}, resolved el block number: {goat_block_number}"
            );

            let fee_tx = cached_output.fee_tx.unwrap();
            let update_connector = cached_output.update_connector;

            action_sign_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                publisher_btc_pubkeys,
                next_publisher_btc_pubkeys,
                fee_tx,
                update_connector,
                sequencer_set_hash,
                goat_genesis_block_hash,
                program_history_root,
                proof_checkpoint_root,
                authorized_program_ids,
                goat_block_number,
            )
            .await
        }
        Commands::PushSeq {
            owner_btc_key_wif,
            goat_block_number,
            publisher_btc_pubkeys,
            next_publisher_btc_pubkeys,
            init_genesis,
            goat_genesis_block_hash,
            program_history_root,
            proof_checkpoint_root,
            program_id_manifest,
            commit_info,
        } => {
            let authorized_program_ids =
                load_program_id_manifest(&program_id_manifest, btc_client.network())?;
            println!("goat genesis block hash: {:#?}", hex::encode(goat_genesis_block_hash));
            let (sequencer_set_hash, cosmos_block_number) =
                get_sequencer_set_hash_from_db(&args.db_path, goat_block_number).await?;

            let sequencers = fetch_validators(&args.cosmos_rpc_url, cosmos_block_number).await?;
            let fee_tx = cached_output.fee_tx;
            let update_connector = cached_output.update_connector;

            action_push_sequencer_set_update(
                &btc_client,
                &goat_client,
                owner_btc_key_wif,
                publisher_btc_pubkeys.clone(),
                next_publisher_btc_pubkeys.clone(),
                fee_tx,
                update_connector,
                goat_block_number,
                sequencer_set_hash,
                goat_genesis_block_hash,
                program_history_root,
                proof_checkpoint_root,
                authorized_program_ids,
                output_file,
            )
            .await?;
            save_commit_info(
                &args.output_file,
                &publisher_btc_pubkeys,
                &next_publisher_btc_pubkeys,
                sequencers,
                init_genesis,
                &commit_info,
                goat_genesis_block_hash,
                program_history_root,
                proof_checkpoint_root,
                authorized_program_ids,
            )
            .await?;
            Ok(())
        }
    }
}

fn load_verified_proof(path: &str) -> anyhow::Result<(Vec<u8>, verifier::ProgramId)> {
    let proof = std::fs::read(path)?;
    let public_values = std::fs::read(format!("{path}.public_inputs.bin"))?;
    let vk_hash = std::fs::read(format!("{path}.vk_hash.bin"))?;
    let version = String::from_utf8(std::fs::read(format!("{path}.zkm_version.bin"))?)?;
    let program_id = verifier::verify_groth16_proof(&proof, &public_values, &vk_hash, &version)
        .map_err(anyhow::Error::msg)?;
    Ok((public_values, program_id))
}

fn next_header_history_root(
    path: &str,
    next_program_id: verifier::ProgramId,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let (public_values, previous_program_id) = load_verified_proof(path)?;
    let (history, checkpoint) =
        match classify_header_chain_output(&public_values).map_err(anyhow::Error::msg)? {
            HeaderChainPrevProofType::PrevProof => {
                let output = decode_header_chain_circuit_output(&public_values);
                anyhow::ensure!(
                    output.self_program_id == previous_program_id,
                    "header ProgramId mismatch"
                );
                (
                    verifier::next_history(
                        verifier::ProgramType::Header,
                        output.program_history_hash,
                        previous_program_id,
                        next_program_id,
                    ),
                    if previous_program_id == next_program_id {
                        output.upgrade_checkpoint_hash
                    } else {
                        verifier::proof_checkpoint(
                            verifier::ProgramType::Header,
                            output.upgrade_checkpoint_hash,
                            previous_program_id,
                            next_program_id,
                            &public_values,
                        )
                    },
                )
            }
            HeaderChainPrevProofType::GenesisBlock => unreachable!(),
        };
    Ok((
        verifier::finalize_history(verifier::ProgramType::Header, history, next_program_id),
        checkpoint,
    ))
}

fn next_state_history_root(
    path: &str,
    next_program_id: verifier::ProgramId,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let (public_values, previous_program_id) = load_verified_proof(path)?;
    let (history, checkpoint) =
        match classify_state_chain_output(&public_values).map_err(anyhow::Error::msg)? {
            StateChainPrevProofType::PrevProof => {
                let output = decode_state_chain_circuit_output(&public_values);
                anyhow::ensure!(
                    output.self_program_id == previous_program_id,
                    "state ProgramId mismatch"
                );
                (
                    verifier::next_history(
                        verifier::ProgramType::State,
                        output.program_history_hash,
                        previous_program_id,
                        next_program_id,
                    ),
                    if previous_program_id == next_program_id {
                        output.upgrade_checkpoint_hash
                    } else {
                        verifier::proof_checkpoint(
                            verifier::ProgramType::State,
                            output.upgrade_checkpoint_hash,
                            previous_program_id,
                            next_program_id,
                            &public_values,
                        )
                    },
                )
            }
            StateChainPrevProofType::GenesisBlock => unreachable!(),
        };
    Ok((
        verifier::finalize_history(verifier::ProgramType::State, history, next_program_id),
        checkpoint,
    ))
}

/// Verifies the predecessor proofs and derives the root expected from their next recursive steps.
fn derive_authorization_roots(
    header_path: &str,
    state_path: &str,
    next_header_program_id: verifier::ProgramId,
    next_state_program_id: verifier::ProgramId,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let (header_history, header_checkpoint) =
        next_header_history_root(header_path, next_header_program_id)?;
    let (state_history, state_checkpoint) =
        next_state_history_root(state_path, next_state_program_id)?;
    Ok((
        verifier::program_history_root(header_history, state_history),
        verifier::proof_checkpoint_root(header_checkpoint, state_checkpoint),
    ))
}

async fn push_fee_tx(
    fee_tx: &mut Transaction,
    input_value: Amount,
    private_key: &PrivateKey,
    btc_client: &BTCClient,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    // sign the fee tx
    node_sign(
        fee_tx,
        0,
        input_value,
        EcdsaSighashType::All,
        &Keypair::from_secret_key(&secp, &private_key.inner),
    )?;
    println!("Fee txid: {:#?}", fee_tx.compute_txid());
    broadcast_tx(btc_client, fee_tx).await?;
    wait_tx_confirmation(btc_client, &fee_tx.compute_txid(), 3, 10000).await?;
    println!("Fee tx confirmed");
    Ok(fee_tx.compute_txid())
}

#[allow(clippy::too_many_arguments)]
async fn push_sequencer_set_publish_tx(
    owner_p2wpkh: &Address,
    owner_private_key: &PrivateKey,
    update_connector_value: Option<Amount>,
    replenish_fee_connector_value: Option<Amount>,
    btc_client: &BTCClient,
    sequencer_set_publish_tx: &mut Transaction,
    redeem_script: &ScriptBuf,
    publisher_sigs: Vec<Vec<u8>>,
) -> Result<Txid, Box<dyn std::error::Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    let mut input_index = 0;
    if update_connector_value.is_some() {
        println!("Standard spending flow for sequencer set publish tx");
        input_index += 1;
        finalize(sequencer_set_publish_tx, publisher_sigs, redeem_script)?;
    }

    // Sign the replenish fee input (P2WPKH)
    let signer_pkh = owner_p2wpkh
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code =
        ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(signer_pkh.as_bytes())?);

    let mut cache = SighashCache::new(&mut *sequencer_set_publish_tx);
    let sighash = cache
        .p2wsh_signature_hash(
            input_index,
            &script_code,
            replenish_fee_connector_value.unwrap(),
            sig_hash_type,
        )
        .unwrap();
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();

    let sig = secp.sign_ecdsa(&msg, &owner_private_key.inner);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(sig_hash_type as u8);

    println!("Publisher {}'s signature: {}", owner_p2wpkh, hex::encode(&sig_bytes));
    sequencer_set_publish_tx.input[input_index].witness =
        Witness::from(vec![sig_bytes, owner_private_key.public_key(&secp).to_bytes()]);

    println!("Sequencer set publish txid: {:#?}", sequencer_set_publish_tx.compute_txid());
    println!("Sequencer set publish: {sequencer_set_publish_tx:#?}");
    println!(
        "Sequencer set publish hex: {}",
        hex::encode(bitcoin::consensus::encode::serialize(sequencer_set_publish_tx))
    );
    broadcast_tx(btc_client, sequencer_set_publish_tx).await?;
    wait_tx_confirmation(btc_client, &sequencer_set_publish_tx.compute_txid(), 3, 10000).await?;
    println!("Sequencer set publish tx confirmed");
    Ok(sequencer_set_publish_tx.compute_txid())
}

async fn init_clients(args: &Args) -> Result<(BTCClient, GOATClient), anyhow::Error> {
    let network = get_network();
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));
    let config = GoatInitConfig::new(args.goat_rpc_url.parse::<Url>()?)
        .await?
        .with_sequencer_set_publisher_address(get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS,
        ))
        .with_multi_sig_verifier_address(get_goat_address_from_env(
            ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS,
        ))
        .with_private_key(args.goat_evm_prvkey.clone());
    let goat_client = GOATClient::new(config, client::goat_chain::GoatNetwork::Test);
    Ok((btc_client, goat_client))
}

#[tracing::instrument(skip(goat_client))]
async fn update_sequencer_set_on_goat(
    goat_client: &GOATClient,
    goat_block_number: u64,
    sig_hash: [u8; 32],
    btc_pub_key: [u8; 33],
    btc_sig: [u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    let sequencer_set = SequencerSetUpdateWitness {
        sig_hash,
        btc_pub_key: btc_pub_key.to_vec(),
        btc_sig: btc_sig.to_vec(),
    };
    let txid = goat_client.ss_update_sequencer_set(goat_block_number, sequencer_set).await?;
    println!("Txid: {txid}");
    Ok(())
}

/// Collect the threshold signatures for the update connector in redeem-script order.
///
/// Witnesses are permissionlessly appended on Goat, so every field must be treated as
/// untrusted. Invalid, stale, duplicate, or unauthorized witnesses are ignored rather
/// than allowing one entry to abort publishing for the whole height.
fn collect_ordered_publisher_signatures(
    witnesses: &[SequencerSetUpdateWitness],
    btc_public_keys: &[secp256k1::PublicKey],
    expected_sighash: [u8; 32],
    threshold: usize,
    goat_block_number: u64,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest_slice(&expected_sighash)
        .expect("a Bitcoin sighash is always exactly 32 bytes");
    let mut signatures_by_member = vec![None; btc_public_keys.len()];

    for (witness_index, witness) in witnesses.iter().enumerate() {
        let public_key = match secp256k1::PublicKey::from_slice(&witness.btc_pub_key) {
            Ok(public_key) => public_key,
            Err(error) => {
                tracing::warn!(
                    goat_block_number,
                    witness_index,
                    error = %error,
                    "Skipping sequencer set witness with an invalid Bitcoin public key"
                );
                continue;
            }
        };

        let Some(member_index) = btc_public_keys.iter().position(|key| key == &public_key) else {
            tracing::warn!(
                goat_block_number,
                witness_index,
                public_key = %public_key,
                "Skipping sequencer set witness from an unauthorized Bitcoin public key"
            );
            continue;
        };

        if witness.sig_hash != expected_sighash {
            tracing::warn!(
                goat_block_number,
                witness_index,
                public_key = %public_key,
                "Skipping sequencer set witness for a different transaction sighash"
            );
            continue;
        }

        let signature = match secp256k1::ecdsa::Signature::from_compact(&witness.btc_sig) {
            Ok(signature) => signature,
            Err(error) => {
                tracing::warn!(
                    goat_block_number,
                    witness_index,
                    public_key = %public_key,
                    error = %error,
                    "Skipping sequencer set witness with an invalid compact signature"
                );
                continue;
            }
        };

        if let Err(error) = secp.verify_ecdsa(&message, &signature, &public_key) {
            tracing::warn!(
                goat_block_number,
                witness_index,
                public_key = %public_key,
                error = %error,
                "Skipping sequencer set witness with a signature that does not match the transaction"
            );
            continue;
        }

        if signatures_by_member[member_index].is_some() {
            tracing::warn!(
                goat_block_number,
                witness_index,
                public_key = %public_key,
                "Skipping duplicate sequencer set witness"
            );
            continue;
        }

        let mut signature_bytes = signature.serialize_der().to_vec();
        signature_bytes.push(EcdsaSighashType::AllPlusAnyoneCanPay as u8);
        signatures_by_member[member_index] = Some(signature_bytes);
    }

    let mut signatures: Vec<_> = signatures_by_member.into_iter().flatten().collect();
    anyhow::ensure!(
        signatures.len() >= threshold,
        "only {} valid publisher signatures for Goat height {goat_block_number}; need {threshold}",
        signatures.len()
    );
    signatures.truncate(threshold);
    Ok(signatures)
}

/// Submit sequencer set commitment
#[allow(clippy::too_many_arguments)]
async fn action_push_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    next_btc_public_keys: Vec<secp256k1::PublicKey>,
    fee_tx_outpoint: Option<OutPoint>,
    update_connector_outpoint: Option<OutPoint>,
    goat_block_number: u64,
    sequencer_set_hash: [u8; 32],
    goat_genesis_block_hash: [u8; 32],
    program_history_root: [u8; 32],
    proof_checkpoint_root: [u8; 32],
    authorized_program_ids: AuthorizedProgramIds,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let witnesses = goat_client.ss_get_sequencer_set_update_witness(goat_block_number).await?;
    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);

    let total = next_btc_public_keys.len();
    let next_threshold = (2 * total).div_ceil(3);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, btc_client.network());

    // update the sequencer set publish tx with multisig signatures
    let (update_connector, update_connector_value) = match &update_connector_outpoint {
        Some(update_connector) => {
            let tmp_tx = btc_client.get_tx(&update_connector.txid).await?.unwrap();
            (Some(*update_connector), Some(tmp_tx.output[update_connector.vout as usize].value))
        }
        None => (None, None),
    };

    let (replenish_fee_connector, replenish_fee_connector_value) = match &fee_tx_outpoint {
        Some(fee_tx_outpoint) => match btc_client.get_tx(&fee_tx_outpoint.txid).await? {
            Some(fee_tx) => {
                (Some(*fee_tx_outpoint), Some(fee_tx.output[fee_tx_outpoint.vout as usize].value))
            }
            None => {
                panic!("Fee tx {} not found, treating as genesis commit tx", fee_tx_outpoint.txid)
            }
        },
        None => {
            let fee_rate = get_fee_rate(btc_client).await? * FEE_RATE_FACTOR;
            let replenish_fee = fee_rate
                * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73)
                    as f64
                + RELAYER_FEE as f64;
            let replenish_fee = Amount::from_sat(replenish_fee.ceil() as u64);
            println!("replenish fee: {replenish_fee:?}");
            (None, Some(replenish_fee))
        }
    };

    // Skip construction of the genesis tx
    let commitment = commit_chain_commitment_digest(
        sequencer_set_hash,
        goat_genesis_block_hash,
        program_history_root,
        proof_checkpoint_root,
        authorized_program_ids,
    );
    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        commitment,
        &update_connector,
        &replenish_fee_connector,
        next_update_connector_address.clone(),
        Amount::from_sat(RELAYER_FEE),
    )?;

    let publisher_sigs = if let Some(update_connector_value) = update_connector_value {
        let sighash = SighashCache::new(&mut sequencer_set_publish_tx).p2wsh_signature_hash(
            0,
            &redeem_script,
            update_connector_value,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        )?;
        collect_ordered_publisher_signatures(
            &witnesses,
            &btc_public_keys,
            sighash.to_byte_array(),
            threshold,
            goat_block_number,
        )?
    } else {
        Vec::new()
    };

    let secp = secp256k1::Secp256k1::new();
    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let owner_p2wpkh = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(&secp, &owner_private_key)?,
        btc_client.network(),
    );

    let txid = push_sequencer_set_publish_tx(
        &owner_p2wpkh,
        &owner_private_key,
        update_connector_value,
        replenish_fee_connector_value,
        btc_client,
        &mut sequencer_set_publish_tx,
        &redeem_script,
        publisher_sigs,
    )
    .await?;

    let output =
        OutputData { update_connector: Some(OutPoint::new(txid, 0)), ..Default::default() };
    save_output(output, output_file);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn action_sign_sequencer_set_update(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    owner_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    next_btc_public_keys: Vec<secp256k1::PublicKey>,
    fee_tx_outpoint: OutPoint,
    update_connector: Option<OutPoint>,
    sequencer_set_hash: [u8; 32],
    goat_genesis_block_hash: [u8; 32],
    program_history_root: [u8; 32],
    proof_checkpoint_root: [u8; 32],
    authorized_program_ids: AuthorizedProgramIds,
    goat_block_number: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let total = btc_public_keys.len();
    let threshold = (2 * total).div_ceil(3);
    let next_total = next_btc_public_keys.len();
    let next_threshold = (2 * next_total).div_ceil(3);

    let redeem_script = create_sequencer_update_script(&btc_public_keys, threshold);
    let next_redeem_script = create_sequencer_update_script(&next_btc_public_keys, next_threshold);
    let next_update_connector_address = Address::p2wsh(&next_redeem_script, btc_client.network());

    let fee_rate = get_fee_rate(btc_client).await? * FEE_RATE_FACTOR;
    let replenish_fee = fee_rate
        * estimate_tx_vbytes(&[(threshold as u32, total as u32)], &[("p2wsh", 3)], 73) as f64
        + RELAYER_FEE as f64;
    let replenish_fee = Amount::from_sat(replenish_fee.ceil() as u64);
    let commitment = commit_chain_commitment_digest(
        sequencer_set_hash,
        goat_genesis_block_hash,
        program_history_root,
        proof_checkpoint_root,
        authorized_program_ids,
    );

    let mut sequencer_set_publish_tx = create_sequencer_update_partial_tx(
        commitment,
        &update_connector,
        &Some(fee_tx_outpoint),
        next_update_connector_address.clone(),
        Amount::from_sat(RELAYER_FEE),
    )?;

    let owner_private_key = PrivateKey::from_wif(owner_btc_key_wif.as_ref().unwrap())?;
    let (update_connector_value, _replenish_fee_connector_value) = match &update_connector {
        None => (None, Some(replenish_fee)),
        Some(update_connector) => {
            // digest the previous commit tx's output utxo
            let (_update_connector, update_connector_value) = {
                let tmp_tx = btc_client.get_tx(&update_connector.txid).await?.unwrap();
                (Some(*update_connector), tmp_tx.output[update_connector.vout as usize].value)
            };
            let fee_tx =
                btc_client.get_tx(&fee_tx_outpoint.txid).await?.expect("fee tx doesn't exist");
            (Some(update_connector_value), Some(fee_tx.output[fee_tx_outpoint.vout as usize].value))
        }
    };

    println!("update_connector_value: {update_connector_value:?}");
    println!("replenish_fee_connector_value: {_replenish_fee_connector_value:?}");
    let sig_hash_type = EcdsaSighashType::AllPlusAnyoneCanPay;
    // if this is not the genesis commit tx
    if let Some(update_connector_value_) = update_connector_value {
        println!("Standard spending flow for sequencer set publish tx");
        let (sig, msg) = sign_raw(
            &mut sequencer_set_publish_tx,
            &owner_private_key.inner,
            &redeem_script,
            update_connector_value_,
            sig_hash_type,
        )?;

        let secp = secp256k1::Secp256k1::new();
        update_sequencer_set_on_goat(
            goat_client,
            goat_block_number,
            msg[..].try_into().unwrap(),
            owner_private_key.public_key(&secp).to_bytes().try_into().unwrap(),
            sig,
        )
        .await?;
    }
    Ok(())
}

/// Push fee tx
#[allow(clippy::too_many_arguments)]
async fn action_push_fee_tx(
    btc_client: &BTCClient,
    fund_btc_key_wif: &str,
    owner_btc_public_key: &str,
    total: u32,
    funding_input: Option<OutPoint>,
    goat_evm_address: [u8; 20],
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fee_rate = get_fee_rate(btc_client).await? * FEE_RATE_FACTOR;
    let threshold = (2 * total).div_ceil(3);
    let secp = secp256k1::Secp256k1::new();
    let replenish_fee = fee_rate
        * estimate_tx_vbytes(&[(threshold, total)], &[("p2wsh", 3)], 73) as f64
        + RELAYER_FEE as f64;
    let replenish_fee = Amount::from_sat(replenish_fee.ceil() as u64);

    let feepayer_private_key = PrivateKey::from_wif(fund_btc_key_wif)?;

    let owner_pubkey = CompressedPublicKey::from_str(owner_btc_public_key)?;
    let funder_address = node_p2wsh_address(
        btc_client.network(),
        &PublicKey::from_private_key(&secp, &feepayer_private_key),
    );
    let owner_p2wpkh = Address::p2wpkh(&owner_pubkey, btc_client.network());

    let (first_input_utxo, first_input_value) = if let Some(funding_input) = funding_input {
        let tmp_tx = btc_client.get_tx(&funding_input.txid).await?.unwrap();
        (funding_input, tmp_tx.output[funding_input.vout as usize].value)
    } else {
        // use the first UTXO from regtest address
        let utxos = btc_client.get_address_utxo(funder_address.clone()).await?;
        let utxo = utxos.into_iter().find(|u| u.value > replenish_fee).expect("No UTXO found");
        (OutPoint::new(utxo.txid, utxo.vout), utxo.value)
    };
    println!("fee UTXOs: {first_input_utxo:#?}, value: {first_input_value}");

    let mut fee_tx = create_fee_tx(
        &goat_evm_address,
        &first_input_utxo,
        first_input_value,
        replenish_fee,
        owner_p2wpkh,
        funder_address,
        Amount::from_sat(RELAYER_FEE),
    )?;
    let txid =
        push_fee_tx(&mut fee_tx, first_input_value, &feepayer_private_key, btc_client).await?;

    let output = OutputData { fee_tx: Some(OutPoint::new(txid, 0)), ..Default::default() };
    save_output(output, output_file);
    Ok(())
}

/// fund publisher, debug only
async fn action_fund_publishers(
    btc_client: &BTCClient,
    fund_btc_key_wif: Option<String>,
    btc_public_keys: Vec<secp256k1::PublicKey>,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // read public key and threshold from smart contract, which is consistency with btc_public_keys
    //let publisher_keys: Vec<_> = create_dummy_publisher_keys(total);
    let funder_private_key = PrivateKey::from_wif(&fund_btc_key_wif.unwrap())?;
    let txn = fund_publishers(&funder_private_key, btc_public_keys, btc_client).await?;

    let output =
        OutputData { funding_input: Some(OutPoint::new(txn.0, txn.1)), ..Default::default() };
    save_output(output, output_file);
    Ok(())
}

async fn fund_publishers(
    fund_private_key: &PrivateKey,
    publishers: Vec<secp256k1::PublicKey>,
    btc_client: &BTCClient,
) -> Result<(Txid, u32), Box<dyn std::error::Error>> {
    println!("network: {:?}", btc_client.network());
    let secp = Secp256k1::new();
    let from_address = node_p2wsh_address(
        btc_client.network(),
        &PublicKey::from_private_key(&secp, fund_private_key),
    );
    println!("Funding publishers from address: {from_address}");
    let utxos = btc_client.get_address_utxo(from_address.clone()).await?;
    println!("utxo: {utxos:?}");
    assert!(!utxos.is_empty(), "No UTXO found to fund publishers");
    let mut total_value = 0;
    for utxo in &utxos {
        total_value += utxo.value.to_sat();
    }

    println!("Funding publishers from {from_address} with total UTXO value: {total_value}");

    let fee = Amount::from_sat(4000);
    let to_value = 20000; // each publisher get 20000 sat 

    let mut txins = Vec::new();
    for utxo in &utxos {
        txins.push(TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
    }

    let mut txouts = Vec::new();
    let mut current_tx_vout = 0;
    for (i, pk) in publishers.iter().enumerate() {
        let address = Address::p2wpkh(&CompressedPublicKey(*pk), btc_client.network());
        txouts.push(TxOut {
            value: Amount::from_sat(to_value),
            script_pubkey: address.script_pubkey(),
        });
        if PublicKey::from_private_key(&secp, fund_private_key) == (*pk).into() {
            current_tx_vout = i;
        }
    }

    let change_value = total_value - to_value * publishers.len() as u64 - fee.to_sat();
    if change_value > 546 {
        txouts.push(TxOut {
            value: Amount::from_sat(change_value),
            script_pubkey: from_address.script_pubkey(),
        });
    }

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: txins,
        output: txouts,
    };

    for (i, utxo) in utxos.iter().enumerate().take(tx.input.len()) {
        node_sign(
            &mut tx,
            i,
            utxo.value,
            EcdsaSighashType::All,
            &Keypair::from_secret_key(&secp, &fund_private_key.inner),
        )?;
    }

    println!("Funding txid: {:#?}", tx.compute_txid());
    broadcast_tx(btc_client, &tx).await?;
    assert!(
        wait_tx_confirmation(btc_client, &tx.compute_txid(), 3, 10000).await?,
        "Funding tx not confirmed"
    );
    Ok((tx.compute_txid(), current_tx_vout as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    const SIGHASH: [u8; 32] = [42; 32];

    fn secret_key(value: u8) -> SecretKey {
        SecretKey::from_slice(&[value; 32]).expect("valid test secret key")
    }

    fn public_key(secret_key: &SecretKey) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), secret_key)
    }

    fn signed_witness(secret_key: &SecretKey, sighash: [u8; 32]) -> SequencerSetUpdateWitness {
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(
            &Message::from_digest_slice(&sighash).expect("test sighash is 32 bytes"),
            secret_key,
        );
        SequencerSetUpdateWitness {
            sig_hash: sighash,
            btc_pub_key: public_key(secret_key).serialize().to_vec(),
            btc_sig: signature.serialize_compact().to_vec(),
        }
    }

    fn expected_signature(secret_key: &SecretKey) -> Vec<u8> {
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(
            &Message::from_digest_slice(&SIGHASH).expect("test sighash is 32 bytes"),
            secret_key,
        );
        let mut encoded = signature.serialize_der().to_vec();
        encoded.push(EcdsaSighashType::AllPlusAnyoneCanPay as u8);
        encoded
    }

    #[test]
    fn publisher_witnesses_are_filtered_deduplicated_and_reordered() {
        let first = secret_key(1);
        let second = secret_key(2);
        let third = secret_key(3);
        let stranger = secret_key(4);
        let publishers = vec![public_key(&first), public_key(&second), public_key(&third)];

        let mut malformed_key = signed_witness(&first, SIGHASH);
        malformed_key.btc_pub_key[0] = 0x01;
        let mut malformed_signature = signed_witness(&second, SIGHASH);
        malformed_signature.btc_sig.clear();

        let witnesses = vec![
            malformed_key,
            signed_witness(&stranger, SIGHASH),
            malformed_signature,
            signed_witness(&third, SIGHASH),
            signed_witness(&first, SIGHASH),
            signed_witness(&first, SIGHASH),
        ];

        let signatures =
            collect_ordered_publisher_signatures(&witnesses, &publishers, SIGHASH, 2, 123)
                .expect("two valid publisher signatures");

        assert_eq!(signatures, vec![expected_signature(&first), expected_signature(&third)]);
    }

    #[test]
    fn publisher_witnesses_keep_exactly_threshold_signatures_in_script_order() {
        let first = secret_key(1);
        let second = secret_key(2);
        let third = secret_key(3);
        let publishers = vec![public_key(&first), public_key(&second), public_key(&third)];
        let witnesses = vec![
            signed_witness(&third, SIGHASH),
            signed_witness(&second, SIGHASH),
            signed_witness(&first, SIGHASH),
        ];

        let signatures =
            collect_ordered_publisher_signatures(&witnesses, &publishers, SIGHASH, 2, 123)
                .expect("three valid signatures meet the threshold of two");

        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures, vec![expected_signature(&first), expected_signature(&second)]);
    }

    #[test]
    fn publisher_witnesses_require_a_valid_threshold() {
        let first = secret_key(1);
        let second = secret_key(2);
        let third = secret_key(3);
        let publishers = vec![public_key(&first), public_key(&second), public_key(&third)];

        let witnesses = vec![signed_witness(&first, SIGHASH), signed_witness(&second, [7; 32])];

        let error = collect_ordered_publisher_signatures(&witnesses, &publishers, SIGHASH, 2, 123)
            .expect_err("one valid signature is below threshold");
        assert!(error.to_string().contains("only 1 valid publisher signatures"));
    }
}
