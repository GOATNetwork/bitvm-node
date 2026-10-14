//! Validation of graph parameters, policy and the init and finalized graphs.

use crate::env::*;
use crate::error::SpecialError;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, PublicKey, XOnlyPublicKey};
use bitvm_lib::committee::*;
use bitvm_lib::operator::*;
use bitvm_lib::timelocks::estimated_block_interval_secs;
use bitvm_lib::types::{
    BitvmGcGraph, BitvmGcGraphParameters, BitvmGcInstanceParameters, SimplifiedBitvmGcGraph,
};
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::transactions::pre_signed::PreSignedTransaction;
use libp2p::PeerId;
use secp256k1::schnorr::Signature as SchnorrSignature;
use std::str::FromStr;
use store::localdb::{GraphQuery, LocalDB};

use bitcoin_light_client_circuit::hash_operator_constant;
use bitvm_lib::babe_adapter::BABE_M_CC;
use bitvm_lib::transactions::base::BaseTransaction;

use super::endorse::{
    get_graph_digest, verify_graph_endorsement_digest, verify_graph_params_endorsement,
    verify_verifier_graph_params_endorsement,
};
use super::goat_chain::read_instance_info_from_goat;
use super::graph_store::load_validated_graph_definition;

// other operations
pub fn avg_block_time_secs(network: Network) -> u64 {
    estimated_block_interval_secs(network) as u64
}

pub fn min_required_operator() -> usize {
    // todo!("get min required operator number")
    1
}

pub fn min_required_watchtower() -> usize {
    // todo!("get min required watchtower number")
    1
}

pub fn min_required_verifier() -> usize {
    get_min_required_verifier()
        .unwrap_or_else(|error| panic!("invalid verifier count configuration: {error}"))
}

/// Checks graph Watchtower membership, uniqueness, and supported count.
pub(super) fn validate_watchtower_registry_selection(
    selected: &[XOnlyPublicKey],
    registered: &[XOnlyPublicKey],
) -> Result<()> {
    use std::collections::HashSet;

    if selected.len() < min_required_watchtower() {
        bail!(SpecialError::InvalidGraph(format!(
            "insufficient watchtowers: have {}, required {}",
            selected.len(),
            min_required_watchtower()
        )));
    }
    if selected.len() > 256 {
        bail!(SpecialError::InvalidGraph(format!(
            "too many watchtowers: {}, max 256",
            selected.len()
        )));
    }

    let mut seen = HashSet::new();
    for key in selected {
        if !seen.insert(*key) {
            bail!(SpecialError::InvalidGraph("duplicate watchtower pubkey in graph".to_string()));
        }
        if !registered.contains(key) {
            bail!(SpecialError::InvalidGraph(format!("watchtower {} is not registered", key)));
        }
    }
    Ok(())
}

/// Validates the graph's ordered watchtower selection and its bound Operator constant.
fn validate_watchtower_selection(
    selected: &[XOnlyPublicKey],
    registered: &[XOnlyPublicKey],
    graph_id: [u8; 16],
    genesis_txid: [u8; 32],
    challenge_init_txid: [u8; 32],
    constant: [u8; 32],
) -> Result<()> {
    validate_watchtower_registry_selection(selected, registered)?;
    let key_bytes = selected.iter().map(XOnlyPublicKey::serialize).collect::<Vec<_>>();
    let expected = hash_operator_constant(graph_id, genesis_txid, challenge_init_txid, &key_bytes);
    if constant != expected {
        bail!(SpecialError::InvalidGraph(
            "operator constant mismatch for graph watchtower list".to_string()
        ));
    }
    Ok(())
}

pub async fn validate_graph_instance_parameters(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    parameters: &BitvmGcInstanceParameters,
) -> Result<()> {
    let expected = read_instance_info_from_goat(goat_client, parameters.instance_id)
        .await
        .context("failed to load instance parameters from GoatChain")?;
    if parameters != &expected {
        bail!(SpecialError::InvalidGraph(
            "instance parameters mismatch with GoatChain peg-in data".to_string()
        ));
    }

    for input in &expected.user_info.inputs {
        let funding_tx = btc_client.get_tx(&input.outpoint.txid).await.with_context(|| {
            format!("failed to load peg-in funding transaction {}", input.outpoint.txid)
        })?;
        // The parameters already match GoatChain: a transaction the Bitcoin
        // backend does not know yet is the backend lagging, not a bad graph.
        let Some(funding_tx) = funding_tx else {
            bail!("peg-in funding transaction {} not found on Bitcoin", input.outpoint.txid);
        };
        let funding_output =
            funding_tx.output.get(input.outpoint.vout as usize).ok_or_else(|| {
                SpecialError::InvalidGraph(format!(
                    "peg-in funding outpoint {}:{} does not exist",
                    input.outpoint.txid, input.outpoint.vout
                ))
            })?;
        if funding_output.value != input.amount {
            bail!(SpecialError::InvalidGraph(format!(
                "peg-in funding amount mismatch for {}:{}: graph={}, bitcoin={}",
                input.outpoint.txid,
                input.outpoint.vout,
                input.amount.to_sat(),
                funding_output.value.to_sat()
            )));
        }
    }

    let pegin_deposit_txid = expected
        .build_pegin_tx()
        .map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to reconstruct peg-in deposit: {e}"))
        })?
        .0
        .tx()
        .compute_txid();
    if btc_client
        .get_tx(&pegin_deposit_txid)
        .await
        .with_context(|| format!("failed to load peg-in deposit transaction {pegin_deposit_txid}"))?
        .is_none()
    {
        bail!("peg-in deposit transaction {pegin_deposit_txid} not found on Bitcoin");
    }

    Ok(())
}

fn validate_graph_policy(parameters: &BitvmGcGraphParameters) -> Result<()> {
    let verifier_num = parameters.gc_data.len();
    if verifier_num < min_required_verifier() {
        bail!(SpecialError::InvalidGraph(format!(
            "insufficient verifier GC slots: have {}, required {}",
            verifier_num,
            min_required_verifier()
        )));
    }

    let mut verifier_pubkeys = std::collections::HashSet::new();
    for gc_data in &parameters.gc_data {
        if !verifier_pubkeys.insert(XOnlyPublicKey::from(gc_data.verifier_pubkey)) {
            bail!(SpecialError::InvalidGraph(format!(
                "duplicate verifier pubkey in GC data: {}",
                gc_data.verifier_pubkey
            )));
        }
        if gc_data.final_msg_hashlocks.len() != BABE_M_CC {
            bail!(SpecialError::InvalidGraph(format!(
                "verifier {} has {} final message hashlocks, expected {}",
                gc_data.verifier_pubkey,
                gc_data.final_msg_hashlocks.len(),
                BABE_M_CC
            )));
        }
    }

    let watchtower_num = parameters.watchtower_pubkeys.len();
    if watchtower_num < min_required_watchtower() {
        bail!(SpecialError::InvalidGraph(format!(
            "insufficient watchtower slots: have {}, required {}",
            watchtower_num,
            min_required_watchtower()
        )));
    }
    let mut watchtower_pubkeys = std::collections::HashSet::new();
    for pubkey in &parameters.watchtower_pubkeys {
        if !watchtower_pubkeys.insert(*pubkey) {
            bail!(SpecialError::InvalidGraph(format!(
                "duplicate watchtower pubkey in graph: {pubkey}"
            )));
        }
    }
    let mut watchtower_hashlocks = std::collections::HashSet::new();
    for hashlock in &parameters.watchtower_ack_hashlocks {
        if !watchtower_hashlocks.insert(*hashlock) {
            bail!(SpecialError::InvalidGraph(
                "duplicate watchtower ack hashlock in graph".to_string()
            ));
        }
    }

    Ok(())
}

async fn validate_prekickoff_continuity(
    local_db: &LocalDB,
    full_graph: &BitvmGcGraph,
) -> Result<()> {
    if full_graph.parameters.graph_nonce == 0 {
        return Ok(());
    }

    let mut storage_processor = local_db.acquire().await?;
    let previous_nonce = full_graph.parameters.graph_nonce - 1;
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(full_graph.parameters.operator_pubkey.to_string())
                .with_kickoff_index(previous_nonce as i64)
                .with_limit(1),
        )
        .await?;
    if let Some(previous_graph) = graphs.first() {
        let simplified_graph = load_validated_graph_definition(
            &mut storage_processor,
            previous_graph.instance_id,
            previous_graph.graph_id,
        )
        .await?
        .ok_or_else(|| {
            anyhow!("previous graph raw data is missing for graph nonce {previous_nonce}")
        })?;
        let expected_cur_prekickoff =
            BitvmGcGraph::from_simplified(&simplified_graph)?.next_prekickoff;
        let expected_txid = expected_cur_prekickoff.finalize().compute_txid();
        let actual_txid = full_graph.cur_prekickoff.finalize().compute_txid();
        if actual_txid != expected_txid {
            bail!(SpecialError::InvalidGraph(format!(
                "cur prekickoff continuity mismatch: graph={actual_txid}, expected={expected_txid}"
            )));
        }
        Ok(())
    } else {
        // Not stored yet: the job retries until the definition arrives by
        // gossip or a pull, or the graph retires.
        bail!("previous graph is missing for graph nonce {previous_nonce}");
    }
}

pub async fn validate_init_graph_base(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    if !graph.operator_pre_signed() {
        bail!(SpecialError::InvalidGraph("graph is missing operator pre-signatures".to_string()));
    }
    // Basic structural and on-chain consistency checks for an incoming graph proposal.
    // Return SpecialError::InvalidGraph on any validation failure.
    // 1) Rebuild full graph (ensures signatures present if flags are set and tx graph is coherent)
    let full_graph = BitvmGcGraph::from_simplified(graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;
    validate_graph_policy(&graph.parameters)?;
    validate_prekickoff_continuity(local_db, &full_graph).await?;
    verify_graph_operator_pre_signatures(&full_graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid operator pre-signatures: {e}")))?;

    // 2) Bind all instance and peg-in parameters to GoatChain and Bitcoin.
    validate_graph_instance_parameters(
        btc_client,
        goat_client,
        &graph.parameters.instance_parameters,
    )
    .await?;

    // 3) Challenge amount and assert-commit count must match local constants
    if graph.parameters.challenge_amount != challenge_amount() {
        bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
    }

    // 4) Watchtower config sanity: number of watchtowers should match number of hashlocks and registry size
    let watchtowers_on_chain = goat_client
        .committee_mana_get_watchtowers()
        .await
        .context("load the watchtower registry from GoatChain")?;

    validate_watchtower_selection(
        &graph.parameters.watchtower_pubkeys,
        &watchtowers_on_chain,
        *graph.parameters.graph_id.as_bytes(),
        get_genesis_sequencer_commit_id(),
        full_graph.watchtower_challenge_init.tx().compute_txid().to_byte_array(),
        graph.parameters.pubin_disprove_constant,
    )?;

    // 5) Operator stake sanity: verify operator is registered and has enough locked stake.
    // The query may fail transiently; only the verdict is a rejection.
    match operator_stake_status(goat_client, &graph.parameters.operator_pubkey)
        .await
        .context("query operator stake")?
    {
        OperatorStakeStatus::Staked => {}
        OperatorStakeStatus::NotRegistered => {
            bail!(SpecialError::InvalidGraph("operator not registered".to_string()))
        }
        OperatorStakeStatus::Insufficient { locked, min } => {
            bail!(SpecialError::InvalidGraph(format!(
                "insufficient operator stake: locked={locked}, min={min}"
            )))
        }
    }

    Ok(())
}

/// Operator stake verdict; RPC failures are returned as errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStakeStatus {
    Staked,
    NotRegistered,
    Insufficient { locked: u64, min: u64 },
}

pub async fn operator_stake_status(
    goat_client: &GOATClient,
    operator_pubkey: &PublicKey,
) -> Result<OperatorStakeStatus> {
    let operator_xonly_pubkey = XOnlyPublicKey::from(*operator_pubkey).serialize();
    let operator_addr = goat_client
        .stake_mana_pubkey_to_address(&operator_xonly_pubkey)
        .await
        .context("query operator address")?;
    if operator_addr == [0; 20] {
        return Ok(OperatorStakeStatus::NotRegistered);
    }
    let min_stake_amount =
        goat_client.gateway_get_min_stake_amount().await.context("query minimum operator stake")?;
    let locked_stake = goat_client
        .stake_mana_lock_stake_of(&operator_addr)
        .await
        .context("query operator locked stake")?;
    if locked_stake < min_stake_amount {
        return Ok(OperatorStakeStatus::Insufficient {
            locked: locked_stake,
            min: min_stake_amount,
        });
    }
    Ok(OperatorStakeStatus::Staked)
}

pub async fn validate_verifier_graph_params_endorsements(
    goat_client: &GOATClient,
    graph: &SimplifiedBitvmGcGraph,
    verifier_endorsements: &[(PublicKey, usize, String, SchnorrSignature)],
) -> Result<()> {
    let expected_verifier_num = graph.parameters.gc_data.len();
    if verifier_endorsements.len() != expected_verifier_num {
        bail!(SpecialError::InvalidGraph(format!(
            "verifier params endorsement count {} does not match GC slot count {}",
            verifier_endorsements.len(),
            expected_verifier_num
        )));
    }

    let mut seen_pubkeys = std::collections::HashSet::new();
    let mut seen_indices = std::collections::HashSet::new();
    let mut seen_peers = std::collections::HashSet::new();
    for (verifier_pubkey, verifier_index, verifier_peer_id, signature) in verifier_endorsements {
        let peer =
            PeerId::from_str(verifier_peer_id).context("invalid verifier endorsement peer")?;
        if !seen_peers.insert(peer) {
            bail!(SpecialError::InvalidGraph("duplicate verifier endorsement peer".into()));
        }
        if *verifier_index >= expected_verifier_num {
            bail!(SpecialError::InvalidGraph(format!(
                "verifier params endorsement index {verifier_index} out of range"
            )));
        }
        let slot_pubkey = graph.parameters.gc_data[*verifier_index].verifier_pubkey;
        if slot_pubkey != *verifier_pubkey {
            bail!(SpecialError::InvalidGraph(format!(
                "verifier params endorsement slot mismatch at index {verifier_index}: signature pubkey={}, graph pubkey={slot_pubkey}",
                verifier_pubkey
            )));
        }
        if !seen_pubkeys.insert(XOnlyPublicKey::from(*verifier_pubkey)) {
            bail!(SpecialError::InvalidGraph(format!(
                "duplicate verifier params endorsement pubkey: {verifier_pubkey}"
            )));
        }
        if !seen_indices.insert(*verifier_index) {
            bail!(SpecialError::InvalidGraph(format!(
                "duplicate verifier params endorsement index: {verifier_index}"
            )));
        }
        let ok = verify_verifier_graph_params_endorsement(verifier_pubkey, graph, signature)?;
        if !ok {
            bail!(SpecialError::InvalidGraph(format!(
                "invalid verifier params endorsement signature for {verifier_pubkey}"
            )));
        }
    }

    for (_, _, peer, _) in verifier_endorsements {
        let peer = PeerId::from_str(peer)?;
        if !goat_client
            .committee_mana_is_verifier(&peer.to_bytes())
            .await
            .context("recheck verifier registration before committee setup")?
        {
            bail!(SpecialError::InvalidGraph(
                "endorsement peer is not a registered verifier".into()
            ));
        }
    }
    Ok(())
}

pub async fn validate_init_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &SimplifiedBitvmGcGraph,
    verifier_endorsements: &[(PublicKey, usize, String, SchnorrSignature)],
) -> Result<()> {
    validate_init_graph_base(local_db, btc_client, goat_client, graph).await?;
    validate_verifier_graph_params_endorsements(goat_client, graph, verifier_endorsements).await
}

pub async fn validate_finalized_graph(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &SimplifiedBitvmGcGraph,
    endorse_sigs: &[(PublicKey, EvmAddress, Vec<u8>)],
    params_endorse_sigs: &[(PublicKey, EvmAddress, Vec<u8>)],
) -> Result<()> {
    if !graph.operator_pre_signed() || !graph.committee_pre_signed() {
        bail!(SpecialError::InvalidGraph(
            "finalized graph is missing operator or committee pre-signatures".to_string()
        ));
    }
    // 1) Rebuild full graph to ensure structure is coherent and txns derivable
    let full_graph = BitvmGcGraph::from_simplified(graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid graph structure: {e}")))?;
    validate_graph_policy(&graph.parameters)?;
    verify_graph_operator_pre_signatures(&full_graph)
        .map_err(|e| SpecialError::InvalidGraph(format!("invalid operator pre-signatures: {e}")))?;
    verify_graph_committee_pre_signatures(&full_graph).map_err(|e| {
        SpecialError::InvalidGraph(format!("invalid committee pre-signatures: {e}"))
    })?;

    // 2) Repeat the full instance and peg-in binding for nodes that did not see CreateGraph.
    validate_graph_instance_parameters(
        btc_client,
        goat_client,
        &graph.parameters.instance_parameters,
    )
    .await?;

    let instance_id = graph.parameters.instance_parameters.instance_id;
    if graph.parameters.challenge_amount != challenge_amount() {
        bail!(SpecialError::InvalidGraph("unexpected challenge amount".to_string()));
    }

    let watchtowers_on_chain = goat_client
        .committee_mana_get_watchtowers()
        .await
        .context("load the watchtower registry from GoatChain")?;
    validate_watchtower_selection(
        &graph.parameters.watchtower_pubkeys,
        &watchtowers_on_chain,
        *graph.parameters.graph_id.as_bytes(),
        get_genesis_sequencer_commit_id(),
        full_graph.watchtower_challenge_init.tx().compute_txid().to_byte_array(),
        graph.parameters.pubin_disprove_constant,
    )?;

    // 3) Validate endorsements: unique, from legitimate committee members, and signatures recover to the provided EVM address
    use std::collections::HashSet;
    let mut seen_committee: HashSet<PublicKey> = HashSet::new();
    let mut seen_evm: HashSet<EvmAddress> = HashSet::new();
    let pegin_data = goat_client
        .gateway_get_pegin_data(&instance_id)
        .await
        .context("load the instance's peg-in data from GoatChain")?;
    // One digest per graph; computing it is a GoatChain call and may fail
    // transiently, while a signature that does not recover is a rejection.
    let graph_digest = get_graph_digest(goat_client, &full_graph)
        .await
        .context("load the graph digest from GoatChain")?;
    if pegin_data.committee_pubkeys.len() != pegin_data.committee_addresses.len() {
        bail!(SpecialError::InvalidGraph(
            "on-chain committee pubkey and address counts differ".to_string()
        ));
    }
    if endorse_sigs.len() != pegin_data.committee_pubkeys.len() {
        bail!(SpecialError::InvalidGraph(format!(
            "endorsement count {} does not match instance committee count {}",
            endorse_sigs.len(),
            pegin_data.committee_pubkeys.len()
        )));
    }
    if params_endorse_sigs.len() != pegin_data.committee_pubkeys.len() {
        bail!(SpecialError::InvalidGraph(format!(
            "params endorsement count {} does not match instance committee count {}",
            params_endorse_sigs.len(),
            pegin_data.committee_pubkeys.len()
        )));
    }

    for (pk, evm_addr, sig) in endorse_sigs.iter() {
        // no duplicates
        if !seen_committee.insert(*pk) {
            bail!(SpecialError::InvalidGraph(
                "duplicate committee pubkey in endorsements".to_string()
            ));
        }
        if !seen_evm.insert(*evm_addr) {
            bail!(SpecialError::InvalidGraph("duplicate evm address in endorsements".to_string()));
        }

        // map pubkey -> expected evm address from GoatChain
        let mut found = false;
        for i in 0..pegin_data.committee_pubkeys.len() {
            let on_chain_pk =
                PublicKey::from_slice(&pegin_data.committee_pubkeys[i]).map_err(|e| {
                    SpecialError::InvalidGraph(format!("invalid committee pubkey on-chain: {e}"))
                })?;
            if &on_chain_pk == pk {
                found = true;
                let expected_addr = pegin_data.committee_addresses[i];
                if &expected_addr != evm_addr {
                    bail!(SpecialError::InvalidGraph("committee evm address mismatch".to_string()));
                }
                break;
            }
        }
        if !found {
            bail!(SpecialError::InvalidGraph("endorser not in committee set".to_string()));
        }

        // cryptographically verify the endorsement against the graph digest
        let ok = verify_graph_endorsement_digest(evm_addr, &graph_digest, sig).map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to verify endorsement: {e}"))
        })?;
        if !ok {
            bail!(SpecialError::InvalidGraph("invalid endorsement signature".to_string()));
        }
    }

    let mut seen_committee: HashSet<PublicKey> = HashSet::new();
    let mut seen_evm: HashSet<EvmAddress> = HashSet::new();
    for (pk, evm_addr, sig) in params_endorse_sigs.iter() {
        if !seen_committee.insert(*pk) {
            bail!(SpecialError::InvalidGraph(
                "duplicate committee pubkey in params endorsements".to_string()
            ));
        }
        if !seen_evm.insert(*evm_addr) {
            bail!(SpecialError::InvalidGraph(
                "duplicate evm address in params endorsements".to_string()
            ));
        }

        let mut found = false;
        for i in 0..pegin_data.committee_pubkeys.len() {
            let on_chain_pk =
                PublicKey::from_slice(&pegin_data.committee_pubkeys[i]).map_err(|e| {
                    SpecialError::InvalidGraph(format!("invalid committee pubkey on-chain: {e}"))
                })?;
            if &on_chain_pk == pk {
                found = true;
                let expected_addr = pegin_data.committee_addresses[i];
                if &expected_addr != evm_addr {
                    bail!(SpecialError::InvalidGraph(
                        "committee evm address mismatch in params endorsements".to_string()
                    ));
                }
                break;
            }
        }
        if !found {
            bail!(SpecialError::InvalidGraph("params endorser not in committee set".to_string()));
        }

        let ok = verify_graph_params_endorsement(evm_addr, &full_graph, sig).map_err(|e| {
            SpecialError::InvalidGraph(format!("failed to verify params endorsement: {e}"))
        })?;
        if !ok {
            bail!(SpecialError::InvalidGraph("invalid params endorsement signature".to_string()));
        }
    }

    Ok(())
}

pub fn prekickoff_replenishment_amount() -> Amount {
    Amount::from_sat(500000)
}

pub fn min_prekickoff_input_amount() -> Amount {
    Amount::from_sat(200000)
}

pub fn challenge_amount() -> Amount {
    Amount::from_sat(20000)
}

pub fn prekickoff_fee_amount(replenish_fee_inputs_num: usize) -> Amount {
    let tx_vbytes = PRE_KICKOFF_BASE_VBYTES
        + (replenish_fee_inputs_num as u64 * CHECKSIG_P2WSH_INPUT_VBYTES_ESTIMATE);
    Amount::from_sat(tx_vbytes)
}
