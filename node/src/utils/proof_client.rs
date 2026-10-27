//! The proof builder client: watchtower commitments and challenge data, operator
//! proofs and the statements they are checked against.

use crate::env::*;
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::{BlockHash, Txid, XOnlyPublicKey};
use bitcoin_light_client_circuit::{
    VK_HASH_SIZE, build_watchtower_commitment, decode_operator_public_outputs,
};
use bitvm_lib::babe_adapter::{
    DYNAMIC_SLOTS, NUM_PUBLIC_INPUTS, STATIC_SLOTS, StaticInputs, ziren_static_inputs,
};

use bitvm_lib::types::BitvmGcGraph;
use client::btc_chain::BTCClient;
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use p3_bn254_fr::Bn254Fr;
use p3_field::{PrimeCharacteristicRing, PrimeField};
use reqwest::Url;
use serde::Serialize;
use store::localdb::LocalDB;

use crate::env;
use crate::rpc_service::routes::v1::{
    NODES_OPERATOR_BASE, NODES_WATCHTOWER_BASE, PROOFS_WATCHTOWER_PROOF_TIMEOUT,
};

use bitcoin_light_client_circuit::hash_operator_constant;
use client::http_client::async_client::HttpAsyncClient;
use proof_builder::api_auth::{ProofBuilderAuthRole, sign_proof_builder_request};
use proof_builder::{
    OperatorProofRequest, OperatorProofResponse, ProofData, WatchtowerProofRequest,
    WatchtowerProofResponse, WatchtowerProofTimeoutUpdateRequest,
    WatchtowerProofTimeoutUpdateResponse,
};
use store::SerializableTxid;
use tracing::{info, warn};
use uuid::Uuid;
use zkm_pcs::PartStarkVerifyingKey;
use zkm_recursion_core::stark::KoalaBearPoseidon2Outer;
use zkm_sdk::ZKMProofWithPublicValues;
use zkm_verifier::{
    Groth16Verifier, IMM_GROTH16_VK_BYTES, VK_ROOT_BYTES, convert_ark_imm_wrap_vk,
    decode_zkm_vkey_hash,
};

use super::btc::outpoint_spent_txid;

pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;

pub type Groth16Proof = ark_groth16::Proof<ark_bn254::Bn254>;

pub type PublicInputs = Vec<ark_bn254::Fr>;

#[derive(Clone)]
pub struct ValidatedOperatorProof {
    pub proof: Groth16Proof,
    pub public_inputs: PublicInputs,
    pub verifying_key: VerifyingKey,
    pub public_values: Vec<u8>,
    pub vk_hash: String,
    pub zkm_version: String,
}

#[derive(Clone)]
pub struct OperatorStatement {
    pub static_input: StaticInputs,
    pub vk_hash: [u8; 32],
    pub zkm_version: String,
    pub constant: [u8; 32],
}

fn gen_watchtower_commitment(graph_id: Uuid, proof_data: ProofData) -> Result<Vec<u8>> {
    let graph_id = graph_id.as_bytes();
    let proof =
        proof_data.proof.as_slice().try_into().map_err(|_| anyhow!("invalid proof length"))?;
    let public_inputs = proof_data
        .public_inputs
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid public inputs length"))?;
    if proof_data.vk.len() != VK_HASH_SIZE {
        bail!("invalid vk_hash length");
    }
    if proof_data.zkm_version.is_empty() {
        bail!("missing zkm_version");
    }

    Ok(build_watchtower_commitment(
        graph_id,
        proof,
        &public_inputs,
        &proof_data.vk,
        &proof_data.zkm_version,
    ))
}

// proof network
/// Builds fresh Proof Builder authentication headers for one outbound request attempt.
fn proof_builder_auth_headers<B: Serialize>(
    keypair: &Keypair,
    role: ProofBuilderAuthRole,
    path: &str,
    body: &B,
) -> Result<Vec<(String, String)>> {
    Ok(sign_proof_builder_request(keypair, role, "POST", path, body)?.to_header_pairs())
}

/// Returns:
/// - `Ok(Some(WatchtowerCommitment), _)` if watchtower proof is available
/// - `Ok(None, wait_secs)` if watchtower proof is not yet available, with suggested wait time
pub async fn get_watchtower_commitment(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    http_client: &HttpAsyncClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(Option<Vec<u8>>, usize)> {
    let mut storage_processor = local_db.acquire().await?;
    if let Some(graph) = storage_processor.find_graph(&graph_id).await?
        && let Some(challenge_init_txid) = graph.watchtower_challenge_init_txid
    {
        // check if challenge_txid is confirmed
        let tx_status = btc_client.get_tx_status(&challenge_init_txid.0).await?;
        if !tx_status.confirmed {
            warn!("graph {graph_id} challenge tx is not confirmed");
            return Ok((None, get_watchtower_proof_wait_secs()));
        }

        let base_url = Url::parse(
            &get_proof_build_rpc_host()
                .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
        )?;
        let url = base_url.join(NODES_WATCHTOWER_BASE)?;

        let payload = WatchtowerProofRequest {
            instance_id: instance_id.to_string(),
            graph_id: graph_id.to_string(),
            gateway_address: Some(env::get_goat_gateway_contract_from_env().to_string()),
            public_key: env::get_node_pubkey()?.to_string(),
            challenge_init_txid: challenge_init_txid.0.to_string(),
            execution_layer_block_number: graph.proceed_withdraw_height, // NOTE: this number may be zero
        };
        let auth_keypair = get_bitvm_key()?;
        let response = http_client
            .post_response_json_with_dynamic_headers::<WatchtowerProofResponse, _, _>(
                url.as_str(),
                &payload,
                || {
                    proof_builder_auth_headers(
                        &auth_keypair,
                        ProofBuilderAuthRole::Watchtower,
                        NODES_WATCHTOWER_BASE,
                        &payload,
                    )
                },
            )
            .await
            .inspect(|_| crate::metrics_service::record_backend_ok("proof"))
            .inspect_err(|error| {
                crate::metrics_service::record_backend_failure("proof", "watchtower_proofs", error)
            })?;
        match response.proof_data {
            Some(proof_data) => {
                let watchtower_commitment = gen_watchtower_commitment(graph_id, proof_data)?;
                Ok((Some(watchtower_commitment), 0))
            }
            None => Ok((None, get_watchtower_proof_wait_secs())),
        }
    } else {
        warn!("graph:{graph_id} not found or related txn is none",);
        bail!("No graph in db");
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct WatchtowerChallengeInfo {
    pub challenge_txids: Vec<Option<String>>,
    pub included_watchtowers: Vec<bool>,
    pub resolved_branch_txids: Vec<Txid>,
}

#[tracing::instrument(name = "get_watchtower_challenge_info", skip(btc_client))]
pub async fn get_watchtower_challenge_info(
    btc_client: &BTCClient,
    watchtower_challenge_init_txid: &SerializableTxid,
    watchtower_timeout_txids: &[Txid],
    num_watchtowers: usize,
) -> Result<WatchtowerChallengeInfo> {
    let mut challenge_txids = Vec::with_capacity(num_watchtowers);
    let mut included_watchtowers = Vec::with_capacity(num_watchtowers);
    let mut resolved_branch_txids = Vec::with_capacity(num_watchtowers);
    for index in 0..num_watchtowers {
        let challenge_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(index) as u64;
        let spent_txid =
            outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid.0, challenge_vout)
                .await?;
        match spent_txid {
            Some(txid) => {
                let status = btc_client.get_tx_status(&txid).await?;
                if !status.confirmed {
                    bail!("watchtower branch tx {txid} at index {index} is not confirmed yet");
                }
                resolved_branch_txids.push(txid);

                let is_timeout = watchtower_timeout_txids
                    .get(index)
                    .is_some_and(|timeout_txid| txid == *timeout_txid);
                if is_timeout {
                    challenge_txids.push(None);
                    included_watchtowers.push(false);
                } else {
                    challenge_txids.push(Some(txid.to_string()));
                    included_watchtowers.push(true);
                }
            }
            None => {
                challenge_txids.push(None);
                included_watchtowers.push(false);
            }
        }
    }
    Ok(WatchtowerChallengeInfo { challenge_txids, included_watchtowers, resolved_branch_txids })
}

/// Returns `(btc_best_block_hash, included_watchtowers_bitmap)` using every finalized
/// challenge-branch resolution for the block hash while only challenges set bitmap bits.
///
/// The selected hash is signed into the operator's pubin and cannot be replaced after a
/// reorganization. Require every branch that determines the bitmap to be at least as deeply
/// buried as the header/SPV finality window before returning it.
pub async fn compute_operator_pubin_blockhash_and_bitmap(
    btc_client: &BTCClient,
    resolved_branch_txids: &[Txid],
    included_watchtowers_bits: &[bool],
) -> Result<([u8; 32], [u8; 32])> {
    let tip_height = btc_client.get_height().await?;
    let required_burial_depth = get_btc_block_confirms(btc_client.network());
    let btc_best_block_hash = {
        let mut largest: Option<(u32, BlockHash)> = None;
        for txid in resolved_branch_txids {
            let status = btc_client.get_tx_status(txid).await?;
            let (height, hash) = match (status.confirmed, status.block_height, status.block_hash) {
                (true, Some(height), Some(hash)) => (height, hash),
                _ => bail!("watchtower branch resolution tx {txid} is not confirmed yet"),
            };
            // `BTC_BLOCK_CONFIRMS` is the number of blocks that must follow a block before
            // the SPV/header pipeline consumes it. Match the proof-builder's strict boundary:
            // the anchor must have more than this many blocks after it.
            let burial_depth = tip_height.saturating_sub(height);
            if burial_depth <= required_burial_depth {
                bail!(
                    "watchtower branch resolution tx {txid} is not final enough for operator pubin: height={height}, tip={tip_height}, burial_depth={burial_depth}, required_burial_depth>{required_burial_depth}"
                );
            }
            if largest.is_none_or(|(h, _)| height > h) {
                largest = Some((height, hash));
            }
        }
        largest
            .map(|(_, hash)| hash.to_byte_array())
            .ok_or_else(|| anyhow!("no confirmed watchtower branch resolution tx available"))?
    };

    let mut included_watchtowers = [0u8; 32];
    for (i, &included) in included_watchtowers_bits.iter().enumerate() {
        if included && i < 256 {
            included_watchtowers[i / 8] |= 1 << (i % 8);
        }
    }

    Ok((btc_best_block_hash, included_watchtowers))
}

async fn get_operator_committed_blockhash(
    btc_client: &BTCClient,
    resolved_branch_txids: &[Txid],
    included_watchtowers_bits: &[bool],
    graph_id: Uuid,
) -> Result<Option<String>> {
    match compute_operator_pubin_blockhash_and_bitmap(
        btc_client,
        resolved_branch_txids,
        included_watchtowers_bits,
    )
    .await
    {
        Ok((btc_best_block_hash, _)) => {
            Ok(Some(BlockHash::from_byte_array(btc_best_block_hash).to_string()))
        }
        Err(e) => {
            warn!("operator proof inputs are not ready for graph {graph_id}: {e}");
            Ok(None)
        }
    }
}

/// Assembles the 96-byte guest pubin:
pub fn build_operator_guest_pubin(
    btc_best_block_hash: &[u8; 32],
    pubin_disprove_constant: &[u8; 32],
    included_watchtowers: &[u8; 32],
) -> [u8; 96] {
    let mut pubin = [0u8; 96];
    pubin[0..32].copy_from_slice(btc_best_block_hash);
    pubin[32..64].copy_from_slice(pubin_disprove_constant);
    pubin[64..96].copy_from_slice(included_watchtowers);
    pubin
}

fn load_part_stark_vk_for_zkm_version(zkm_version: &str) -> Result<Vec<u8>> {
    let part_stark_vk = Groth16Verifier::try_get_part_stark_vk(zkm_version).ok_or_else(|| {
        anyhow!("no partial STARK verifying key is bundled for Ziren {zkm_version}")
    })?;
    Ok(Vec::from(part_stark_vk))
}

fn convert_operator_proof_to_ark(
    proof: &ZKMProofWithPublicValues,
    vk_hash: &str,
) -> Result<zkm_verifier::ArkProof> {
    let part_stark_vk = load_part_stark_vk_for_zkm_version(&proof.zkm_version)?;
    convert_ark_imm_wrap_vk(proof, vk_hash, &IMM_GROTH16_VK_BYTES, &part_stark_vk)
        .map_err(|err| anyhow!("failed to convert operator proof to ark format: {err}"))
}

fn check_operator_public_input_count(public_inputs: &[ark_bn254::Fr]) -> Result<()> {
    if public_inputs.len() != NUM_PUBLIC_INPUTS {
        bail!(
            "operator proof has {} public inputs; expected {NUM_PUBLIC_INPUTS}",
            public_inputs.len()
        );
    }
    Ok(())
}

fn operator_static_inputs(public_inputs: &[ark_bn254::Fr]) -> Result<StaticInputs> {
    check_operator_public_input_count(public_inputs)?;
    Ok(STATIC_SLOTS.map(|slot| public_inputs[slot]))
}

pub fn operator_assert_dynamic_input(public_inputs: &[ark_bn254::Fr]) -> Result<ark_bn254::Fr> {
    check_operator_public_input_count(public_inputs)?;
    Ok(public_inputs[DYNAMIC_SLOTS[0]])
}

fn combined_operator_vk_hash(operator_vk_hash: &str, zkm_version: &str) -> Result<[u8; 32]> {
    if !operator_vk_hash.starts_with("0x") {
        bail!("configured operator vk hash must use 0x-prefixed Ziren encoding");
    }
    let raw_vk_hash = decode_zkm_vkey_hash(operator_vk_hash)
        .map_err(|e| anyhow!("invalid configured operator vk hash: {e:?}"))?;
    let part_vk: PartStarkVerifyingKey<KoalaBearPoseidon2Outer> =
        bincode::deserialize(&load_part_stark_vk_for_zkm_version(zkm_version)?)
            .context("deserialize operator partial STARK verifying key")?;
    let base = Bn254Fr::from_u32(256);
    let mut field_hash = Bn254Fr::ZERO;
    for byte in raw_vk_hash {
        field_hash = field_hash * base + Bn254Fr::from_u32(byte as u32);
    }
    let combined = zkm_recursion_core::hash_vkey_with_part_vk(&part_vk, field_hash);
    let bytes = combined.as_canonical_biguint().to_bytes_be();
    if bytes.len() > 32 {
        bail!("combined operator verifying key hash exceeds BN254 field encoding");
    }
    let mut encoded = [0u8; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(encoded)
}

fn operator_identity() -> Result<([u8; 32], String, StaticInputs)> {
    let vk_hash = get_operator_vk_hash()?;
    let zkm_version = get_operator_zkm_version()?;
    let combined_hash =
        combined_operator_vk_hash(&format!("0x{}", hex::encode(vk_hash)), &zkm_version)?;
    let static_input = ziren_static_inputs(&combined_hash, &VK_ROOT_BYTES);
    Ok((vk_hash, zkm_version, static_input))
}

pub fn derive_operator_static_input() -> Result<StaticInputs> {
    Ok(operator_identity()?.2)
}

/// Derives the Operator proof identity and graph constant for one challenge-init transaction.
pub fn derive_operator_statement(
    graph_id: Uuid,
    challenge_init_txid: [u8; 32],
    watchtower_pubkeys: &[XOnlyPublicKey],
) -> Result<OperatorStatement> {
    let (vk_hash, zkm_version, static_input) = operator_identity()?;
    let key_bytes = watchtower_pubkeys.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
    let constant = hash_operator_constant(
        *graph_id.as_bytes(),
        get_genesis_sequencer_commit_id(),
        challenge_init_txid,
        &key_bytes,
    );
    Ok(OperatorStatement { static_input, vk_hash, zkm_version, constant })
}

/// Returns:
/// - `Ok(Some(OperatorProof), _)` if operator proof is available and valid
/// - `Ok(None, wait_secs)` if operator proof is not yet available
pub async fn get_operator_proof(
    local_db: &LocalDB,
    http_client: &HttpAsyncClient,
    bitvm_graph: &BitvmGcGraph,
    btc_client: &BTCClient,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<(Option<ValidatedOperatorProof>, usize)> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(graph) = storage_processor.find_graph(&graph_id).await? else {
        warn!("graph:{graph_id} not found");
        bail!("No graph in db");
    };
    drop(storage_processor);

    if graph.proceed_withdraw_height <= 0 {
        warn!("graph {graph_id} proceed_withdraw_height <= 0, waiting to been updated");
        return Ok((None, get_operator_proof_wait_secs()));
    }

    let watchtower_challenge_init_txid = graph
        .watchtower_challenge_init_txid
        .ok_or_else(|| anyhow::anyhow!("watchtower_challenge_init_txid is none"))?;
    let num_challenger = bitvm_graph.parameters.watchtower_pubkeys.len();
    let watchtower_timeout_txids: Vec<Txid> =
        bitvm_graph.watchtower_challenge_timeouts.iter().map(|tx| tx.tx().compute_txid()).collect();
    let WatchtowerChallengeInfo {
        challenge_txids: watchtower_challenge_txids,
        included_watchtowers,
        resolved_branch_txids,
    } = match get_watchtower_challenge_info(
        btc_client,
        &watchtower_challenge_init_txid,
        &watchtower_timeout_txids,
        num_challenger,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            warn!("Failed to get watchtower challenge info: {e}");
            return Ok((None, get_operator_proof_wait_secs()));
        }
    };
    let Some(operator_committed_blockhash) = get_operator_committed_blockhash(
        btc_client,
        &resolved_branch_txids,
        &included_watchtowers,
        graph_id,
    )
    .await?
    else {
        return Ok((None, get_operator_proof_wait_secs()));
    };

    let base_url = Url::parse(
        &get_proof_build_rpc_host()
            .ok_or_else(|| anyhow::anyhow!("failed to get proof_build_rpc_host"))?,
    )?;
    let operator_url = base_url.join(NODES_OPERATOR_BASE)?;
    let payload = OperatorProofRequest {
        instance_id: instance_id.to_string(),
        graph_id: graph_id.to_string(),
        gateway_address: Some(env::get_goat_gateway_contract_from_env().to_string()),
        operator_committed_blockhash,
        execution_layer_block_number: graph.proceed_withdraw_height,
        watchtower_challenge_txids,
        included_watchtowers,
        watchtower_challenge_init_txid: watchtower_challenge_init_txid.0.to_string(),
        watchtower_challenge_pubkeys: bitvm_graph
            .parameters
            .watchtower_pubkeys
            .iter()
            .map(|pk| pk.public_key(secp256k1::Parity::Even).to_string())
            .collect(),
    };
    let auth_keypair = get_bitvm_key()?;
    let operator_response = http_client
        .post_response_json_with_dynamic_headers::<OperatorProofResponse, _, _>(
            operator_url.as_str(),
            &payload,
            || {
                proof_builder_auth_headers(
                    &auth_keypair,
                    ProofBuilderAuthRole::Operator,
                    NODES_OPERATOR_BASE,
                    &payload,
                )
            },
        )
        .await
        .inspect(|_| crate::metrics_service::record_backend_ok("proof"))
        .inspect_err(|error| {
            crate::metrics_service::record_backend_failure("proof", "operator_proofs", error)
        })?;

    let Some(proof_data) = operator_response.proof_data else {
        if let Some(error) = operator_response.error {
            info!("operator proof is not ready for graph_id:{graph_id}: {error}");
        }
        return Ok((None, get_operator_proof_wait_secs()));
    };

    let statement = derive_operator_statement(
        graph_id,
        bitvm_graph.watchtower_challenge_init.tx().compute_txid().to_byte_array(),
        &bitvm_graph.parameters.watchtower_pubkeys,
    )?;
    if statement.constant != bitvm_graph.parameters.pubin_disprove_constant {
        bail!("graph operator constant does not match its watchtower list");
    }

    let proof: ZKMProofWithPublicValues = bincode::deserialize(proof_data.proof.as_slice())
        .map_err(|err| anyhow!("failed to deserialize operator proof: {err}"))?;

    let operator_vk_hash_raw = decode_zkm_vkey_hash(&proof_data.vk)
        .map_err(|e| anyhow!("invalid operator proof vk hash: {e:?}"))?;
    if operator_vk_hash_raw != statement.vk_hash {
        bail!("operator proof vk hash does not match configured operator identity");
    }
    if proof.zkm_version != statement.zkm_version || proof_data.zkm_version != statement.zkm_version
    {
        bail!("operator proof Ziren version does not match configured operator identity");
    }

    let outputs = decode_operator_public_outputs(&proof.public_values.to_vec())
        .map_err(|e| anyhow!("invalid operator public outputs: {e}"))?;
    if outputs.constant != statement.constant {
        bail!("operator proof constant does not match graph setup");
    }

    let ark_proof = convert_operator_proof_to_ark(&proof, &proof_data.vk)?;
    if operator_static_inputs(&ark_proof.public_inputs)? != statement.static_input {
        bail!("operator proof static public inputs do not match graph setup statement");
    }

    Ok((
        Some(ValidatedOperatorProof {
            proof: ark_proof.proof,
            public_inputs: ark_proof.public_inputs.into(),
            verifying_key: ark_proof.groth16_vk.into(),
            public_values: proof.public_values.to_vec(),
            vk_hash: proof_data.vk,
            zkm_version: proof.zkm_version,
        }),
        0,
    ))
}

/// Tell the proof builder that this watchtower's proof for the graph is no
/// longer needed: the operator asserted, the watchtower window is over.
/// Returns whether the builder accepted it; without a builder host, `false`.
pub async fn notify_watchtower_proof_timeout(instance_id: Uuid, graph_id: Uuid) -> Result<bool> {
    let Some(host) = get_proof_build_rpc_host() else {
        warn!("notify_watchtower_proof_timeout: proof builder host is not configured");
        return Ok(false);
    };
    let url = Url::parse(&host)?.join(PROOFS_WATCHTOWER_PROOF_TIMEOUT)?;
    let payload = WatchtowerProofTimeoutUpdateRequest {
        instance_id: instance_id.to_string(),
        graph_id: graph_id.to_string(),
        gateway_address: Some(env::get_goat_gateway_contract_from_env().to_string()),
        public_key: get_node_pubkey()?.to_string(),
    };
    let auth_keypair = get_bitvm_key()?;
    // Called once per graph at most; a fresh client is enough.
    let response = HttpAsyncClient::new(None)
        .post_response_json_with_dynamic_headers::<WatchtowerProofTimeoutUpdateResponse, _, _>(
            url.as_str(),
            &payload,
            || {
                proof_builder_auth_headers(
                    &auth_keypair,
                    ProofBuilderAuthRole::Watchtower,
                    PROOFS_WATCHTOWER_PROOF_TIMEOUT,
                    &payload,
                )
            },
        )
        .await?;
    info!("call {}, response:{:?}", PROOFS_WATCHTOWER_PROOF_TIMEOUT, response);
    Ok(response.data.is_some())
}

/// Computes the graph constant committed by the Operator guest and Connector D.
pub fn get_guest_constant_value(
    graph_id: Uuid,
    challenge_init_txid: [u8; 32],
    watchtower_pubkeys: &[XOnlyPublicKey],
) -> Result<[u8; 32]> {
    let key_bytes = watchtower_pubkeys.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
    Ok(hash_operator_constant(
        graph_id.into_bytes(),
        get_genesis_sequencer_commit_id(),
        challenge_init_txid,
        &key_bytes,
    ))
}

#[cfg(test)]
mod commit_pubin_tests {
    use super::*;
    use ark_serialize::CanonicalSerialize;
    use bitcoin::BlockHash;
    use bitcoin::ScriptBuf;
    use client::btc_chain::BTCClient;
    use esplora_client::{Tx, TxStatus, Vin};
    use store::SerializableTxid;

    fn make_txid(byte: u8) -> Txid {
        Txid::from_slice(&[byte; 32]).unwrap()
    }

    fn make_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    fn create_confirmed_tx(
        txid: Txid,
        spends: &[(Txid, u32)],
        height: u32,
        block_hash: BlockHash,
    ) -> Tx {
        Tx {
            txid,
            version: 2,
            locktime: 0,
            vin: spends
                .iter()
                .map(|(prev_txid, vout)| Vin {
                    txid: *prev_txid,
                    vout: *vout,
                    prevout: None,
                    scriptsig: ScriptBuf::default(),
                    witness: vec![],
                    sequence: 1,
                    is_coinbase: false,
                })
                .collect(),
            vout: vec![],
            size: 1,
            weight: 1,
            status: TxStatus {
                confirmed: true,
                block_height: Some(height),
                block_hash: Some(block_hash),
                block_time: Some(1_000_000),
            },
            fee: 0,
        }
    }

    #[test]
    fn assert_ready_extracts_blake3_xd_from_operator_public_values() {
        let mut pubin = [0u8; 96];
        pubin[..32].copy_from_slice(&[0x11; 32]);
        pubin[32..64].copy_from_slice(&[0x22; 32]);
        pubin[64..].copy_from_slice(&[0x33; 32]);
        let outputs = decode_operator_public_outputs(&pubin).unwrap();
        assert_eq!(outputs.btc_best_block_hash, [0x11; 32]);
        assert_eq!(outputs.constant, [0x22; 32]);
        assert_eq!(outputs.included_watchtowers, [0x33; 32]);

        let public_inputs: PublicInputs = zkm_verifier::load_ark_public_inputs_from_bytes(
            &[0u8; 32],
            &zkm_verifier::hash_public_inputs(&pubin),
            &VK_ROOT_BYTES,
        )
        .into();
        let dynamic_input = operator_assert_dynamic_input(&public_inputs).unwrap();
        assert_eq!(
            operator_static_inputs(&public_inputs).unwrap(),
            ziren_static_inputs(&[0u8; 32], &VK_ROOT_BYTES)
        );

        let mut expected_xd = *blake3::hash(&pubin).as_bytes();
        expected_xd[0] &= 0x1f;
        let mut actual_xd = Vec::new();
        dynamic_input.serialize_uncompressed(&mut actual_xd).unwrap();
        // `pi1_xd_to_wots96_msg` serializes the field element most-significant byte first,
        // whereas the public-input digest is defined in little-endian order.
        actual_xd.reverse();
        assert_eq!(actual_xd, expected_xd);
    }

    #[tokio::test]
    async fn test_get_watchtower_challenge_info_partial_inclusion() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();

        let watchtower_init_txid = make_txid(0x00);
        let challenge_txid_wt0 = make_txid(0x01);
        let block_hash = make_block_hash(0xAA);

        let challenge_vout_0 =
            output_topology::watchtower_challenge_init::watchtower_connector(0) as u32;
        let ack_vout_0 = output_topology::watchtower_challenge_init::ack_connector(0) as u32;

        // watchtower 0 spent its challenge connector and ACK connector; watchtower 1 is unresolved.
        mock_adaptor.set_tx(
            challenge_txid_wt0,
            create_confirmed_tx(
                challenge_txid_wt0,
                &[(watchtower_init_txid, challenge_vout_0)],
                100,
                block_hash,
            ),
        );
        let ack_txid_wt0 = make_txid(0x02);
        mock_adaptor.set_tx(
            ack_txid_wt0,
            create_confirmed_tx(
                ack_txid_wt0,
                &[(watchtower_init_txid, ack_vout_0)],
                101,
                block_hash,
            ),
        );

        let info = get_watchtower_challenge_info(
            &btc_client,
            &SerializableTxid::from(watchtower_init_txid),
            &[],
            2, // 2 watchtowers
        )
        .await
        .unwrap();

        assert_eq!(info.challenge_txids, vec![Some(challenge_txid_wt0.to_string()), None]);
        assert_eq!(info.included_watchtowers, vec![true, false]);
        assert_eq!(info.resolved_branch_txids, vec![challenge_txid_wt0]);
    }

    #[tokio::test]
    async fn test_compute_operator_pubin_blockhash_and_bitmap() {
        let (btc_client, mock_adaptor) = BTCClient::new_mock_client();

        let init_txid = make_txid(0x00);
        let challenge_txid_wt0 = make_txid(0x01);
        let timeout_txid_wt1 = make_txid(0x03);
        let challenge_txid_wt2 = make_txid(0x02);
        let block_hash_low = make_block_hash(0x10);
        let block_hash_middle = make_block_hash(0x15);
        let block_hash_high = make_block_hash(0x20);

        let challenge_vout_0 =
            output_topology::watchtower_challenge_init::watchtower_connector(0) as u32;
        let challenge_vout_2 =
            output_topology::watchtower_challenge_init::watchtower_connector(2) as u32;

        // All three branches are finalized; wt2's height 200 block is the anchor.
        let required_burial_depth = get_btc_block_confirms(btc_client.network());
        mock_adaptor.set_height(200 + required_burial_depth + 1);
        mock_adaptor.set_tx(
            challenge_txid_wt0,
            create_confirmed_tx(
                challenge_txid_wt0,
                &[(init_txid, challenge_vout_0)],
                100,
                block_hash_low,
            ),
        );
        mock_adaptor.set_tx(
            timeout_txid_wt1,
            create_confirmed_tx(timeout_txid_wt1, &[(init_txid, 1)], 150, block_hash_middle),
        );
        mock_adaptor.set_tx(
            challenge_txid_wt2,
            create_confirmed_tx(
                challenge_txid_wt2,
                &[(init_txid, challenge_vout_2)],
                200,
                block_hash_high,
            ),
        );

        let resolved_branch_txids = vec![challenge_txid_wt0, timeout_txid_wt1, challenge_txid_wt2];
        let bits = vec![true, false, true];

        let (best_hash, bitmap) =
            compute_operator_pubin_blockhash_and_bitmap(&btc_client, &resolved_branch_txids, &bits)
                .await
                .unwrap();

        // block at height 200 wins
        assert_eq!(best_hash, block_hash_high.to_byte_array());

        // bits 0 and 2 set → byte 0 = 0b0000_0101
        assert_eq!(bitmap[0], 0b0000_0101u8);
        assert_eq!(&bitmap[1..], &[0u8; 31]);
    }
}
