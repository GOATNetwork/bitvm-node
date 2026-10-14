//! Graph setup helpers for candidate selection, verifier indices, message
//! identity checks and signed `InitGraph` messages.

use crate::env::{
    get_peer_id, get_verifier_candidate_backup_count, get_verifier_candidate_collection_window_secs,
};
use crate::messages::{InitGraph, SolderingProofReady, sign_init_graph};
use crate::utils::{
    OperatorBabeSetupState, OperatorVerifierCandidate, min_required_verifier,
    soldering_payload_hash, soldering_payload_hash_hex,
};
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::PublicKey;
use bitcoin::key::Keypair;
use bitvm_lib::babe_adapter::{
    BABE_M_CC, BabeProverState, CACSetupPackage, CompactSolderingProofPayload,
    FinalizedInstanceData, SolderingData, derive_finalized_indices,
};
use bitvm_lib::types::{BitvmGcCircuitData, BitvmGcGraph};
use libp2p::PeerId;
use std::str::FromStr;
use uuid::Uuid;

pub(crate) fn build_signed_init_graph(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_keypair: &Keypair,
) -> Result<InitGraph> {
    let operator_peer_id = PeerId::from_str(&get_peer_id())
        .context("decode local operator peer id for InitGraph")?
        .to_bytes();
    Ok(sign_init_graph(instance_id, graph_id, operator_keypair, operator_peer_id))
}

/// A graph-bearing message has two identity representations: its envelope and
/// the signed graph parameters. Never use one to read/write local state while
/// using the other to reconstruct or scan the graph.
pub(crate) fn message_identity_matches(
    message_kind: &str,
    message_instance_id: Uuid,
    message_graph_id: Uuid,
    message_graph_nonce: u64,
    graph_instance_id: Uuid,
    graph_graph_id: Uuid,
    graph_nonce: u64,
) -> bool {
    if message_instance_id == graph_instance_id
        && message_graph_id == graph_graph_id
        && message_graph_nonce == graph_nonce
    {
        return true;
    }

    tracing::warn!(
        "Ignore {message_kind}: message identity {message_instance_id}:{message_graph_id}:{message_graph_nonce:?} does not match graph parameters {graph_instance_id}:{graph_graph_id}:{graph_nonce}"
    );
    false
}

/// Closes a bounded candidate collection window and assigns provisional slots.
/// Final graph slots are assigned only after valid soldering proofs are collected.
pub(crate) fn freeze_operator_candidates(state: &mut OperatorBabeSetupState) -> Result<()> {
    if state.candidate_verifier_pubkeys.is_some() {
        return Ok(());
    }
    if state.candidates.len() < min_required_verifier() {
        bail!(
            "cannot freeze {} verifier candidates before reaching target {}",
            state.candidates.len(),
            min_required_verifier()
        );
    }
    let mut verifier_peer_ids = std::collections::HashSet::new();
    for candidate in &state.candidates {
        if !verifier_peer_ids.insert(&candidate.verifier_peer_id) {
            bail!("cannot freeze duplicate verifier peer id");
        }
    }
    state.candidates.sort_by_key(|candidate| candidate.verifier_pubkey.to_bytes());
    for (candidate_index, candidate) in state.candidates.iter_mut().enumerate() {
        candidate.candidate_index = Some(candidate_index);
        candidate.selected_circuit_indexes =
            derive_finalized_indices(&candidate.setup_package, BABE_M_CC)?;
    }
    state.candidate_verifier_pubkeys =
        Some(state.candidates.iter().map(|candidate| candidate.verifier_pubkey).collect());
    Ok(())
}

/// Whether the candidate pool may be frozen now: the required number of
/// candidates is present and either the pool is full or the collection
/// window elapsed. Returns the seconds still to wait otherwise.
pub(crate) fn candidate_freeze_readiness(
    state: &OperatorBabeSetupState,
    now: i64,
) -> CandidateReadiness {
    if state.candidate_verifier_pubkeys.is_some() {
        return CandidateReadiness::Frozen;
    }
    let required = min_required_verifier();
    let limit = required.saturating_add(get_verifier_candidate_backup_count());
    if state.candidates.len() < required {
        return CandidateReadiness::Short;
    }
    if state.candidates.len() >= limit {
        return CandidateReadiness::Ready;
    }
    let window = get_verifier_candidate_collection_window_secs();
    let started_at = state.candidate_collection_started_at.unwrap_or(now);
    let elapsed = now - started_at;
    if elapsed >= window {
        CandidateReadiness::Ready
    } else {
        CandidateReadiness::Wait((window - elapsed).max(1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CandidateReadiness {
    Frozen,
    Short,
    Ready,
    Wait(i64),
}

pub(crate) fn seal_selected_verifiers(
    state: &mut OperatorBabeSetupState,
    selected_verifier_pubkeys: Vec<PublicKey>,
) -> Result<()> {
    if let Some(existing) = &state.selected_verifier_pubkeys {
        if existing != &selected_verifier_pubkeys {
            bail!("refuse to replace the sealed verifier selection");
        }
        return Ok(());
    }
    if selected_verifier_pubkeys.len() != min_required_verifier() {
        bail!(
            "selected verifier count {} does not match required {}",
            selected_verifier_pubkeys.len(),
            min_required_verifier()
        );
    }
    if selected_verifier_pubkeys.windows(2).any(|pair| pair[0].to_bytes() >= pair[1].to_bytes()) {
        bail!("selected verifier public keys must be unique and canonically ordered");
    }
    if selected_verifier_pubkeys.iter().any(|selected| {
        !state.candidates.iter().any(|candidate| candidate.verifier_pubkey == *selected)
    }) {
        bail!("sealed verifier selection contains a non-candidate public key");
    }
    state.selected_verifier_pubkeys = Some(selected_verifier_pubkeys);
    Ok(())
}

pub(crate) fn selected_gc_data(state: &OperatorBabeSetupState) -> Result<Vec<BitvmGcCircuitData>> {
    let selected = state
        .selected_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| anyhow!("verifier selection is not sealed"))?;
    selected
        .iter()
        .map(|verifier_pubkey| {
            state
                .candidates
                .iter()
                .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
                .and_then(|candidate| candidate.gc_data.clone())
                .ok_or_else(|| {
                    anyhow!("missing verified GC data for sealed verifier {verifier_pubkey}")
                })
        })
        .collect()
}

pub(crate) fn selected_candidate_for_graph_index(
    state: &OperatorBabeSetupState,
    verifier_index: usize,
) -> Result<&OperatorVerifierCandidate> {
    let verifier_pubkey = state
        .selected_verifier_pubkeys
        .as_ref()
        .and_then(|selected| selected.get(verifier_index))
        .ok_or_else(|| anyhow!("missing sealed verifier slot {verifier_index}"))?;
    state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
        .ok_or_else(|| anyhow!("missing candidate for sealed verifier slot {verifier_index}"))
}

/// Stores verified proof data against its immutable candidate slot.
pub(crate) fn record_candidate_gc_data(
    state: &mut OperatorBabeSetupState,
    verifier_pubkey: PublicKey,
    candidate_index: usize,
    setup_package: &CACSetupPackage,
    gc_data: BitvmGcCircuitData,
    prover_state: &BabeProverState,
    soldering_proof_ready: SolderingProofReady,
) -> Result<()> {
    if gc_data.verifier_pubkey != verifier_pubkey {
        bail!("GC slot owner does not match soldering proof verifier");
    }
    let candidate = state
        .candidates
        .iter_mut()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.candidate_index != Some(candidate_index) {
        bail!("candidate index does not match soldering proof slot");
    }
    if candidate.setup_package != *setup_package {
        bail!("soldering proof setup package does not match selected verifier candidate");
    }
    if prover_state.package != *setup_package {
        bail!("BABE prover state setup package does not match selected verifier candidate");
    }
    if candidate.selected_circuit_indexes != prover_state.soldering.finalized_indices {
        bail!("BABE prover state finalized indices do not match selected verifier cut");
    }
    if soldering_proof_ready.candidate_index != candidate_index {
        bail!("soldering proof reference candidate index does not match selected verifier");
    }
    if prover_state.finalized.len() != BABE_M_CC || prover_state.h_msgs.len() != BABE_M_CC {
        bail!("BABE prover state must contain exactly {BABE_M_CC} finalized instances and hashes");
    }
    if prover_state.h_msgs != gc_data.final_msg_hashlocks {
        bail!("BABE prover state hashes do not match GC slot hashes");
    }
    if let Some(existing) = &candidate.gc_data
        && existing != &gc_data
    {
        bail!("conflicting GC data received for verifier candidate");
    }
    if let Some(existing) = &candidate.soldering_proof_ready
        && existing != &soldering_proof_ready
    {
        bail!("conflicting soldering proof reference received for verifier candidate");
    }
    if candidate.gc_data.is_none() {
        candidate.gc_data = Some(gc_data);
    }
    if candidate.soldering_proof_ready.is_none() {
        candidate.soldering_proof_ready = Some(soldering_proof_ready);
    }
    Ok(())
}

pub(crate) fn build_babe_prover_state(
    setup_package: &CACSetupPackage,
    finalized: Vec<FinalizedInstanceData>,
    soldering: SolderingData,
) -> Result<BabeProverState> {
    let h_msgs = finalized
        .iter()
        .map(|finalized| {
            setup_package
                .commits
                .get(finalized.index)
                .map(|commit| commit.h_msg)
                .ok_or_else(|| anyhow!("finalized BABE instance index is out of range"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BabeProverState { package: setup_package.clone(), finalized, soldering, h_msgs })
}

pub(crate) fn validate_verifier_slot(graph: &BitvmGcGraph, verifier_index: usize) -> Result<()> {
    let gc_data_len = graph.parameters.gc_data.len();
    let verifier_asserts_len = graph.verifier_asserts.len();
    let disproves_len = graph.disproves.len();
    if gc_data_len == 0 {
        bail!("graph has no verifier GC slots");
    }
    if gc_data_len != verifier_asserts_len || gc_data_len != disproves_len {
        bail!(
            "graph verifier branch lengths differ: gc_data={gc_data_len}, verifier_asserts={verifier_asserts_len}, disproves={disproves_len}"
        );
    }
    if verifier_index >= gc_data_len {
        bail!("verifier index {verifier_index} out of range for {gc_data_len} slots");
    }
    Ok(())
}

pub(crate) fn find_verifier_index_by_pubkey(
    gc_data: &[BitvmGcCircuitData],
    verifier_pubkey: &PublicKey,
) -> Result<Option<usize>> {
    let matches = gc_data
        .iter()
        .enumerate()
        .filter_map(|(index, data)| (data.verifier_pubkey == *verifier_pubkey).then_some(index))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => bail!("graph contains duplicate slots for verifier {verifier_pubkey}"),
    }
}

/// Candidates still owed CutCircuits, excluding delivered proofs and closed selections.
pub(crate) fn cut_circuits_owed(
    state: &OperatorBabeSetupState,
    now: i64,
) -> Vec<OperatorVerifierCandidate> {
    if state.candidate_verifier_pubkeys.is_none() || state.selected_verifier_pubkeys.is_some() {
        return Vec::new();
    }
    let delivered = state.candidates.iter().filter(|candidate| candidate.gc_data.is_some()).count();
    let window_over = state.proof_collection_started_at.is_some_and(|started_at| {
        now - started_at >= get_verifier_candidate_collection_window_secs()
    });
    if window_over && delivered >= min_required_verifier() {
        return Vec::new();
    }
    state
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.gc_data.is_none() && candidate.soldering_proof_ready.is_none()
        })
        .cloned()
        .collect()
}

pub(crate) fn decode_soldering_proof_payload(
    soldering_proof_ready: &SolderingProofReady,
    payload: &[u8],
) -> Result<CompactSolderingProofPayload> {
    let SolderingProofReady { instance_id, graph_id, candidate_index, payload_hash, total_len } =
        soldering_proof_ready;
    if payload.len() != *total_len {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            candidate_index,
            actual_len = payload.len(),
            total_len,
            payload_hash = %soldering_payload_hash_hex(payload_hash),
            "SolderingProof payload length mismatch"
        );
        bail!(
            "SolderingProof payload length {} does not match total_len {total_len}",
            payload.len()
        );
    }
    let actual_hash = soldering_payload_hash(payload);
    if actual_hash != *payload_hash {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            candidate_index,
            expected_hash = %soldering_payload_hash_hex(payload_hash),
            actual_hash = %soldering_payload_hash_hex(&actual_hash),
            "SolderingProof payload hash mismatch"
        );
        bail!("SolderingProof payload hash mismatch");
    }
    bincode::deserialize(payload).context("deserialize compact soldering proof payload")
}
