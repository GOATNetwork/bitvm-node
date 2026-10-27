//! Graph setup, validation, signing and publishing jobs.
//!
//! Jobs validate messages, query chain state and persist protocol material.
//! They return a [`GraphPlan`] for outgoing messages and follow-up work;
//! temporary failures are retried.

use super::common::{PlannedMessage, delivery_id};
use super::graph::{
    ALL_JOBS, GRAPH_KIND, GraphPlan, GraphStateUpdate, JOB_BUILD_GRAPH, JOB_COMMITTEE_ENDORSE,
    JOB_COMMITTEE_INGEST_GRAPH, JOB_COMMITTEE_NONCES, JOB_COMMITTEE_PRESIGN, JOB_COMMITTEE_VOTE,
    JOB_FETCH_GRAPH, JOB_FINALIZE_GRAPH, JOB_FREEZE_CANDIDATES, JOB_INGEST_ENDORSEMENT,
    JOB_INGEST_FINALIZED, JOB_INGEST_GEN_CIRCUITS, JOB_INGEST_NONCES, JOB_INGEST_PRESIGN,
    JOB_INGEST_SOLDERING_PROOF, JOB_INGEST_VERIFIER_ENDORSEMENT, JOB_INGEST_VOTE,
    JOB_OPERATOR_INIT, JOB_POST_GRAPH_DATA, JOB_SEAL_PROOFS, JOB_VERIFIER_SETUP,
    JOB_VERIFIER_SOLDER, JOB_VERIFIER_VALIDATE_GRAPH, OperatorStart, PHASE_COLLECT, PHASE_DELIVER,
    PHASE_ENDORSE, PHASE_SETUP, PHASE_SIGNING, graph_pulled_event, graph_ref, outbox_id, retired,
    slot_ref,
};
use super::graph_fetch::{GraphLookup, fetch_and_store_graph};
use super::graph_pegout::PEGOUT_JOBS;
use super::graph_pegout_jobs::run_pegout_step;
use super::graph_setup::{
    CandidateReadiness, build_babe_prover_state, build_signed_init_graph,
    candidate_freeze_readiness, cut_circuits_owed, decode_soldering_proof_payload,
    find_verifier_index_by_pubkey, freeze_operator_candidates, message_identity_matches,
    record_candidate_gc_data, seal_selected_verifiers, selected_candidate_for_graph_index,
    selected_gc_data, validate_verifier_slot,
};
use super::jobs::{
    JobDeps, Plan, aggregate_uuid, author_peer, committee_pubkeys, decode_inbound,
    ensure_committee_sender, gate_closed, instance_status, local_member, local_operator,
    plan_outcome, signing_nonce_id,
};
use crate::clock::current_time_secs;
use crate::engine_bridge::submit_event;
use crate::env::{
    get_babe_gc_asset_paths, get_bitvm_key, get_node_goat_address, get_peer_id,
    get_soldering_proof_payload_store_path, get_verifier_candidate_collection_window_secs,
};
use crate::error::{FailureClass, SpecialError, classify_failure};
use crate::messages::{
    AggNonceConsensus, CommitteePresign, CreateGraph, CutCircuits, EndorseGraph, GOATMessage,
    GOATMessageContent, GenCircuits, GraphFinalize, NonceGeneration,
    VerifierGraphParamsEndorsement, verify_init_graph_signature,
};
use crate::soldering_payload_store::{
    read_soldering_proof_store_payload, soldering_proof_payload_store_path,
};
use crate::utils::{
    OperatorBabeSetupState, OperatorStakeStatus, VerifierBabeSetupState,
    build_genesis_prekickoff_tx, build_graph_params, build_prekickoff_params,
    derive_operator_static_input, endorse_graph, endorse_graph_params,
    get_committee_agg_nonce_consensus_for_graph, get_committee_endorsements_for_graph,
    get_committee_params_endorsements_for_graph, get_committee_partial_sigs_for_graph,
    get_committee_partial_sigs_for_graph_member, get_committee_pub_nonces_for_graph,
    get_current_prekickoff_tx, get_graph, get_guest_constant_value, get_instance_parameters,
    get_verifier_graph_params_endorsements_for_graph, load_babe_setup_state,
    mark_graph_as_endorsed, min_required_verifier, operator_stake_status, order_committee_values,
    pending_graph_belongs_to_operator, refresh_graph, save_babe_setup_state,
    save_soldering_proof_payload, sign_verifier_graph_params,
    store_committee_agg_nonce_consensus_for_graph, store_committee_endorsement_for_graph,
    store_committee_endorsements_for_graph, store_committee_partial_sigs_for_graph,
    store_committee_pub_nonces_for_graph, store_finalized_graph_if_needed,
    store_operator_presigned_graph, store_verifier_graph_params_endorsement,
    update_babe_setup_state, validate_committee_with_evm_address, validate_finalized_graph,
    validate_init_graph, validate_init_graph_base, validate_verifier_graph_params_endorsements,
    verify_graph_endorsement, verify_graph_params_endorsement,
    verify_verifier_graph_params_endorsement,
};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::{
    BABE_M_CC, BABE_N_CC, build_real_setup_package, expand_compact_soldering_proof_payload,
    extract_gc_circuit_data, open_real_setup_and_solder, verify_real_setup,
};
use bitvm_lib::committee::{
    committee_nonce_consensus_hash, committee_pre_sign, nonces_aggregation,
    push_committee_pre_signatures, signature_aggregation, verify_graph_committee_partial_sigs,
    verify_nonce_signatures,
};
use bitvm_lib::keys::{CommitteeMasterKey, VerifierMasterKey};
use bitvm_lib::operator::{
    generate_bitvm_graph, operator_pre_sign, verify_graph_operator_pre_signatures,
};
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use client::goat_chain::PeginStatus;
use engine::{EngineBuilder, JobContext, JobOutcome, JobRunner};
use goat::transactions::pre_signed::PreSignedTransaction;
use libp2p::PeerId;
use secp256k1::{Message as SecpMessage, SECP256K1};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use store::{GraphStatus, SigningAuthorization};
use tracing::{info, warn};
use uuid::Uuid;

pub fn register_graph_jobs(builder: EngineBuilder, deps: Arc<JobDeps>) -> EngineBuilder {
    let runner: Arc<dyn JobRunner> = Arc::new(GraphJobRunner { deps });
    let mut builder = builder;
    for action in ALL_JOBS.iter().chain(PEGOUT_JOBS) {
        builder = builder.job_runner(GRAPH_KIND, *action, runner.clone());
    }
    builder
}

pub(super) type Step = super::jobs::Step<GraphPlan>;

struct GraphJobRunner {
    deps: Arc<JobDeps>,
}

#[async_trait]
impl JobRunner for GraphJobRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let graph_id = match aggregate_uuid(&ctx, "a graph") {
            Ok(graph_id) => graph_id,
            Err(outcome) => return outcome,
        };
        let params = ctx.job.params.clone().unwrap_or_default();
        let action = ctx.job.action.clone();
        let attempts = ctx.job.attempts;
        let pegout = PEGOUT_JOBS.contains(&action.as_str());
        match run_step(&self.deps, &action, graph_id, &params, attempts).await {
            Ok(step) => step.into_outcome(),
            Err(error) => match classify_failure(&error) {
                FailureClass::Permanent(reason) if pegout => {
                    // A Goat revert on a peg-out call: retrying cannot help.
                    warn!(event = "graph_job", graph_id = %graph_id, action = %action, reason = %reason, "peg-out action rejected");
                    self.deps.metrics_state.record_instance_alert("pegout_action_rejected");
                    plan_outcome(&GraphPlan::noted(format!("rejected: {reason}")))
                }
                FailureClass::Permanent(reason) => {
                    warn!(event = "graph_job", graph_id = %graph_id, action = %action, reason = %reason, "message rejected");
                    self.deps.metrics_state.record_graph_validation(false);
                    plan_outcome(&GraphPlan::noted(format!("rejected: {reason}")))
                }
                FailureClass::Transient => {
                    JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
                }
                // A setup step failing for no recognised reason is given up on
                // after a while: its session and slot are released and the
                // failure is reported. Peg-out steps guard funds and keep
                // retrying, with an alert every so often.
                FailureClass::Unknown if !pegout && attempts >= UNKNOWN_FAILURE_RETRIES => {
                    warn!(event = "graph_job", graph_id = %graph_id, action = %action, attempts, error = %format!("{error:#}"), "setup step keeps failing for an unknown reason; giving up");
                    self.deps.metrics_state.record_instance_alert("graph_job_gave_up");
                    JobOutcome::Failed(format!("gave up after {attempts} attempts: {error:#}"))
                }
                FailureClass::Unknown => {
                    if attempts >= UNKNOWN_FAILURE_RETRIES
                        && attempts % UNKNOWN_FAILURE_RETRIES == 0
                    {
                        warn!(event = "graph_job", graph_id = %graph_id, action = %action, attempts, error = %format!("{error:#}"), "peg-out step keeps failing for an unknown reason");
                        self.deps.metrics_state.record_instance_alert("pegout_job_stuck");
                    }
                    JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
                }
            },
        }
    }
}

/// Attempts a step failing for an unrecognised reason gets before a setup
/// step is failed and a peg-out step raises an alert (then every so many).
const UNKNOWN_FAILURE_RETRIES: i64 = 20;

async fn run_step(
    deps: &JobDeps,
    action: &str,
    graph_id: Uuid,
    params: &[u8],
    attempts: i64,
) -> Result<Step> {
    match action {
        JOB_OPERATOR_INIT => operator_init_graph(deps, graph_id, params).await,
        JOB_VERIFIER_SETUP => verifier_setup(deps, graph_id, params).await,
        JOB_INGEST_GEN_CIRCUITS => ingest_gen_circuits(deps, graph_id, params).await,
        JOB_FREEZE_CANDIDATES => freeze_candidates(deps, graph_id, params).await,
        JOB_VERIFIER_SOLDER => verifier_solder(deps, graph_id, params).await,
        JOB_INGEST_SOLDERING_PROOF => ingest_soldering_proof(deps, graph_id, params).await,
        JOB_SEAL_PROOFS => seal_proofs(deps, graph_id, params).await,
        JOB_BUILD_GRAPH => build_graph(deps, graph_id, params).await,
        JOB_VERIFIER_VALIDATE_GRAPH => verifier_validate_graph(deps, graph_id, params).await,
        JOB_COMMITTEE_INGEST_GRAPH => committee_ingest_graph(deps, graph_id, params).await,
        JOB_INGEST_VERIFIER_ENDORSEMENT => {
            ingest_verifier_endorsement(deps, graph_id, params).await
        }
        JOB_COMMITTEE_NONCES => committee_nonces(deps, graph_id, params).await,
        JOB_INGEST_NONCES => ingest_nonces(deps, graph_id, params).await,
        JOB_COMMITTEE_VOTE => committee_vote(deps, graph_id, params).await,
        JOB_INGEST_VOTE => ingest_vote(deps, graph_id, params).await,
        JOB_COMMITTEE_PRESIGN => committee_presign(deps, graph_id, params).await,
        JOB_INGEST_PRESIGN => ingest_presign(deps, graph_id, params).await,
        JOB_COMMITTEE_ENDORSE => committee_endorse(deps, graph_id, params).await,
        JOB_INGEST_ENDORSEMENT => ingest_endorsement(deps, graph_id, params).await,
        JOB_FINALIZE_GRAPH => finalize_graph(deps, graph_id, params).await,
        JOB_INGEST_FINALIZED => ingest_finalized(deps, graph_id, params).await,
        JOB_POST_GRAPH_DATA => post_graph_data(deps, graph_id, params).await,
        JOB_FETCH_GRAPH => fetch_graph(deps, graph_id, params, attempts).await,
        pegout if PEGOUT_JOBS.contains(&pegout) => {
            run_pegout_step(deps, pegout, graph_id, params, attempts).await
        }
        other => bail!("unknown graph job {other}"),
    }
}

// ------------------------------------------------------------------ helpers

/// Serialize an outbound message and plan it, computing the ack set for the
/// given recipients.
async fn planned(
    graph_id: Uuid,
    phase_ref: &str,
    actor: Actor,
    content: GOATMessageContent,
    ack_peers: &[String],
    qualifier: Option<&str>,
) -> Result<PlannedMessage> {
    let kind = content.event_type();
    let payload = GOATMessage::new(actor.clone(), content).serialize_message().await?;
    let ack_set = if ack_peers.is_empty() {
        None
    } else {
        let sender = get_peer_id();
        Some(
            ack_peers
                .iter()
                .filter(|peer| **peer != sender)
                .map(|peer| (peer.clone(), delivery_id(&sender, peer, &payload)))
                .collect(),
        )
    };
    Ok(PlannedMessage {
        outbox_id: outbox_id(graph_id, kind, qualifier),
        phase_ref: phase_ref.to_string(),
        kind: kind.to_string(),
        actor: actor.to_string(),
        payload,
        ack_set,
    })
}

/// Committee peers from the registry, for the ack sets of the operator's
/// heavy messages.
fn committee_ack_peers() -> Vec<String> {
    crate::p2p_admission::peer_registry()
        .committee_peer_ids(std::time::Instant::now())
        .into_iter()
        .map(|peer| peer.to_string())
        .collect()
}

/// Counts of committee endorsements, parameter endorsements, nonces and partials.
struct Collections {
    endorsements: usize,
    params_endorsements: usize,
    pub_nonces: usize,
    partial_sigs: usize,
}

async fn collections(deps: &JobDeps, instance_id: Uuid, graph_id: Uuid) -> Result<Collections> {
    Ok(Collections {
        endorsements: get_committee_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
            .await?
            .len(),
        params_endorsements: get_committee_params_endorsements_for_graph(
            &deps.local_db,
            instance_id,
            graph_id,
        )
        .await?
        .len(),
        pub_nonces: get_committee_pub_nonces_for_graph(&deps.local_db, instance_id, graph_id)
            .await?
            .len(),
        partial_sigs: get_committee_partial_sigs_for_graph(&deps.local_db, instance_id, graph_id)
            .await?
            .len(),
    })
}

async fn four_sets_complete(deps: &JobDeps, instance_id: Uuid, graph_id: Uuid) -> Result<bool> {
    let committee = committee_pubkeys(deps, instance_id).await?.len();
    let collected = collections(deps, instance_id, graph_id).await?;
    Ok(collected.endorsements == committee
        && collected.params_endorsements == committee
        && collected.pub_nonces == committee
        && collected.partial_sigs == committee)
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(SpecialError::InvalidGraph(message.into()).into())
}

// ----------------------------------------------------------------- operator

async fn operator_init_graph(_deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let start: OperatorStart = bincode::deserialize(params).context("decode operator_start")?;
    let (master, operator_pubkey) = local_operator()?;
    let init = build_signed_init_graph(start.instance_id, graph_id, &master.master_keypair())?;
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SETUP,
            Actor::Verifier,
            GOATMessageContent::InitGraph(init),
            &[],
            None,
        )
        .await?,
    );
    plan.state = GraphStateUpdate {
        instance_id: Some(start.instance_id),
        operator_pubkey: Some(operator_pubkey.to_string()),
        ..Default::default()
    };
    Step::done(plan)
}

async fn ingest_gen_circuits(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::GenCircuits(GenCircuits {
        instance_id,
        graph_id: message_graph_id,
        verifier_pubkey,
        setup_package,
    }) = message.content
    else {
        return invalid("not a GenCircuits message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("GenCircuits identity mismatch");
    }
    let (_, local_operator_pubkey) = local_operator()?;
    if !pending_graph_belongs_to_operator(
        &deps.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        return Step::ignore("no local pending graph session");
    }
    if setup_package.commits.len() != BABE_N_CC {
        return invalid(format!(
            "invalid GenCircuits setup package commitment count: expected {BABE_N_CC}, got {}",
            setup_package.commits.len()
        ));
    }
    let verifier_peer = author_peer(&inbound)?;
    let verifier_peer_id = verifier_peer.to_bytes();
    if !crate::p2p_admission::peer_registry().is_verifier(&verifier_peer)
        && !deps.goat_client.committee_mana_is_verifier(&verifier_peer_id).await.with_context(
            || format!("validate GenCircuits sender {verifier_peer} against the verifier registry"),
        )?
    {
        return Step::ignore(format!("sender {verifier_peer} is not a registered verifier"));
    }

    let mut state =
        load_babe_setup_state(&deps.local_db, instance_id, graph_id)?.unwrap_or_default();
    let operator_state = state.operator.get_or_insert_with(|| OperatorBabeSetupState {
        candidate_verifier_pubkeys: None,
        candidates: vec![],
        candidate_collection_started_at: None,
        proof_collection_started_at: None,
        selected_verifier_pubkeys: None,
        asserted_operator_proof: None,
    });
    let was_frozen = operator_state.candidate_verifier_pubkeys.is_some();
    if let Some(existing) = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_peer_id == verifier_peer_id)
    {
        if existing.verifier_pubkey != verifier_pubkey {
            return Step::ignore(format!(
                "verifier peer {verifier_peer} already submitted a different public key"
            ));
        }
        if existing.setup_package != setup_package {
            return invalid(format!(
                "conflicting GenCircuits setup package for verifier {verifier_pubkey}"
            ));
        }
    } else if operator_state.candidates.iter().any(|candidate| {
        XOnlyPublicKey::from(candidate.verifier_pubkey) == XOnlyPublicKey::from(verifier_pubkey)
    }) {
        return Step::ignore(format!(
            "verifier public key {verifier_pubkey} is already bound to another peer"
        ));
    } else if was_frozen {
        return Step::ignore("verifier membership is frozen");
    } else {
        if operator_state.candidates.len()
            >= min_required_verifier()
                .saturating_add(crate::env::get_verifier_candidate_backup_count())
        {
            return Step::ignore("candidate collection reached its configured limit");
        }
        operator_state.candidates.push(crate::utils::OperatorVerifierCandidate {
            verifier_peer_id,
            verifier_pubkey,
            setup_package,
            candidate_index: None,
            selected_circuit_indexes: vec![],
            gc_data: None,
            soldering_proof_ready: None,
        });
        operator_state.candidate_collection_started_at.get_or_insert_with(current_time_secs);
    }
    let candidate_count = operator_state.candidates.len();
    let readiness = candidate_freeze_readiness(operator_state, current_time_secs());
    let mut plan = GraphPlan::default();
    match readiness {
        CandidateReadiness::Frozen | CandidateReadiness::Ready => {
            freeze_operator_candidates(operator_state)?;
            plan_cut_circuits(graph_id, instance_id, operator_state, &mut plan).await?;
        }
        CandidateReadiness::Wait(secs) => {
            plan.then(
                JOB_FREEZE_CANDIDATES,
                bincode::serialize(&FreezeParams {
                    candidate_count,
                    due_at: current_time_secs() + secs,
                })?,
                Some(secs),
            );
            plan.note = Some(format!("collecting verifier candidates: {candidate_count} received"));
        }
        CandidateReadiness::Short => {
            plan.note = Some(format!(
                "collecting verifier candidates: {candidate_count}/{} received",
                min_required_verifier()
            ));
        }
    }
    save_babe_setup_state(&deps.local_db, instance_id, graph_id, &state)?;
    plan.state.instance_id = Some(instance_id);
    Step::done(plan)
}

/// Params of a delayed job: distinct per schedule, since a job id is derived
/// from its params and an existing id is not enqueued again.
#[derive(Serialize, Deserialize)]
struct FreezeParams {
    candidate_count: usize,
    due_at: i64,
}

async fn freeze_candidates(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let _: FreezeParams = bincode::deserialize(params).context("decode freeze params")?;
    let Some(instance_id) = pending_session(deps, graph_id).await? else {
        return Step::ignore("no pending graph session");
    };
    let mut state =
        load_babe_setup_state(&deps.local_db, instance_id, graph_id)?.unwrap_or_default();
    let Some(operator_state) = state.operator.as_mut() else {
        return Step::ignore("no operator setup state");
    };
    let mut plan = GraphPlan::default();
    match candidate_freeze_readiness(operator_state, current_time_secs()) {
        CandidateReadiness::Frozen | CandidateReadiness::Ready => {
            freeze_operator_candidates(operator_state)?;
            plan_cut_circuits(graph_id, instance_id, operator_state, &mut plan).await?;
            save_babe_setup_state(&deps.local_db, instance_id, graph_id, &state)?;
        }
        CandidateReadiness::Wait(secs) => {
            plan.then(
                JOB_FREEZE_CANDIDATES,
                bincode::serialize(&FreezeParams {
                    candidate_count: operator_state.candidates.len(),
                    due_at: current_time_secs() + secs,
                })?,
                Some(secs),
            );
        }
        CandidateReadiness::Short => {
            plan.note = Some("not enough verifier candidates yet".to_string());
        }
    }
    Step::done(plan)
}

/// The operator's pending session for a graph: `(instance_id, operator_pubkey)`.
/// The instance of the graph's pending setup session, if any.
async fn pending_session(deps: &JobDeps, graph_id: Uuid) -> Result<Option<Uuid>> {
    Ok(deps
        .local_db
        .acquire()
        .await?
        .find_pending_graph_init_by_graph_id(&graph_id)
        .await?
        .map(|pending| pending.instance_id))
}

/// CutCircuits for every frozen candidate still owed one, closing InitGraph.
async fn plan_cut_circuits(
    graph_id: Uuid,
    instance_id: Uuid,
    operator_state: &OperatorBabeSetupState,
    plan: &mut GraphPlan,
) -> Result<()> {
    for candidate in cut_circuits_owed(operator_state, current_time_secs()) {
        let verifier_peer = PeerId::from_bytes(&candidate.verifier_peer_id)
            .context("decode candidate verifier peer id")?
            .to_string();
        let content = GOATMessageContent::CutCircuits(CutCircuits {
            instance_id,
            graph_id,
            verifier_pubkey: candidate.verifier_pubkey,
            candidate_index: candidate.candidate_index.context("frozen candidate has no slot")?,
            selected_circuit_indexes: candidate.selected_circuit_indexes.clone(),
        });
        let qualifier = candidate.verifier_pubkey.to_string();
        plan.send(
            planned(
                graph_id,
                PHASE_SETUP,
                Actor::Verifier,
                content,
                &[verifier_peer],
                Some(&qualifier),
            )
            .await?,
        );
    }
    plan.close_rows.push(outbox_id(graph_id, "InitGraph", None));
    Ok(())
}

async fn ingest_soldering_proof(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::SolderingProofReady(soldering_proof_ready) = message.content else {
        return invalid("not a SolderingProofReady message");
    };
    let instance_id = soldering_proof_ready.instance_id;
    let candidate_index = soldering_proof_ready.candidate_index;
    if soldering_proof_ready.graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("SolderingProofReady identity mismatch");
    }
    if soldering_proof_ready.total_len == 0 {
        return invalid("SolderingProofReady total_len must be greater than zero");
    }
    let (_, local_operator_pubkey) = local_operator()?;
    if !pending_graph_belongs_to_operator(
        &deps.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        return Step::ignore("no local pending graph session");
    }
    let mut state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing BABE setup state for pending graph {graph_id}"))?;
    let operator_state = state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for pending graph {graph_id}"))?;
    let Some(frozen) = operator_state.candidate_verifier_pubkeys.clone() else {
        return Step::retry("operator verifier membership is not frozen", 30);
    };
    let verifier_pubkey = *frozen.get(candidate_index).ok_or_else(|| {
        anyhow!("SolderingProofReady candidate index {candidate_index} out of range")
    })?;
    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.candidate_index != Some(candidate_index) {
        return invalid(
            "selected verifier candidate index does not match SolderingProofReady slot",
        );
    }
    if operator_state
        .selected_verifier_pubkeys
        .as_ref()
        .is_some_and(|selected| !selected.contains(&verifier_pubkey))
    {
        return Step::ignore(
            "late SolderingProofReady from a verifier outside the sealed selection",
        );
    }
    let verifier_peer_id = author_peer(&inbound)?.to_bytes();
    if candidate.verifier_peer_id != verifier_peer_id {
        return Step::ignore(format!(
            "sender {} does not own verifier candidate {candidate_index}",
            inbound.author
        ));
    }
    if candidate.gc_data.is_some() {
        // Already verified; only the collection window decides what is next.
        return proof_collection_step(deps, graph_id, instance_id, &mut state).await;
    }

    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = match read_soldering_proof_store_payload(&payload_path).await {
        Ok(payload) => payload,
        Err(error) => {
            return Step::retry(format!("read soldering proof payload from store: {error}"), 30);
        }
    };
    let payload = decode_soldering_proof_payload(&soldering_proof_ready, &payload)?;
    let setup_package = candidate.setup_package.clone();
    let claimed_finalized_indices = candidate.selected_circuit_indexes.clone();
    let (opened, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand compact soldering proof payload")?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE validation")?;
    let static_input = derive_operator_static_input()?;
    let soldering_builder = Arc::clone(
        deps.soldering_builder
            .as_ref()
            .context("BABE soldering builder is not initialized for Operator")?,
    );
    #[cfg(feature = "mock-gc")]
    crate::mock_gc::simulate(crate::mock_gc::GcOp::Verify).await;
    let verification = {
        let package = setup_package.clone();
        let opened = opened.clone();
        let finalized = finalized.clone();
        let soldering = soldering.clone();
        tokio::task::spawn_blocking(move || {
            verify_real_setup(
                &soldering_builder,
                &package,
                &opened,
                &finalized,
                &soldering,
                &vk,
                &claimed_finalized_indices,
                static_input,
            )
        })
        .await
        .context("real BABE setup verification task failed")?
    };
    if let Err(error) = verification {
        deps.metrics_state.record_pegin_graph_setup(false);
        return invalid(format!("soldering proof verification failed: {error}"));
    }
    if finalized.len() != BABE_M_CC {
        return invalid(format!(
            "each verifier must contribute exactly {BABE_M_CC} finalized BABE instances"
        ));
    }
    let epk = &setup_package.commits[finalized[0].index].epk;
    let prover_state = build_babe_prover_state(&setup_package, finalized, soldering)?;
    let gc_data = extract_gc_circuit_data(verifier_pubkey, epk, &prover_state.h_msgs)?;
    record_candidate_gc_data(
        operator_state,
        verifier_pubkey,
        candidate_index,
        &setup_package,
        gc_data,
        &prover_state,
        soldering_proof_ready.clone(),
    )?;
    deps.metrics_state.record_pegin_graph_setup(true);
    info!(
        event = "operator_graph_creation",
        outcome = "soldering_verified",
        graph_id = %graph_id,
        candidate_index,
        verifier_pubkey = %verifier_pubkey,
        "verified verifier soldering proof"
    );
    operator_state.proof_collection_started_at.get_or_insert_with(current_time_secs);
    proof_collection_step(deps, graph_id, instance_id, &mut state).await
}

/// See [`FreezeParams`].
#[derive(Serialize, Deserialize)]
struct SealParams {
    completed: usize,
    due_at: i64,
}

/// Persist the operator state and decide whether the proofs can be sealed now,
/// later (a delayed `seal_proofs`), or not yet.
async fn proof_collection_step(
    deps: &JobDeps,
    graph_id: Uuid,
    instance_id: Uuid,
    state: &mut crate::utils::BabeSetupState,
) -> Result<Step> {
    let operator_state = state.operator.as_mut().context("operator setup state")?;
    let completed =
        operator_state.candidates.iter().filter(|candidate| candidate.gc_data.is_some()).count();
    let required = min_required_verifier();
    let started_at =
        *operator_state.proof_collection_started_at.get_or_insert_with(current_time_secs);
    save_babe_setup_state(&deps.local_db, instance_id, graph_id, state)?;
    let elapsed = current_time_secs() - started_at;
    let window = get_verifier_candidate_collection_window_secs();
    let mut plan = GraphPlan::default();
    plan.state.instance_id = Some(instance_id);
    if completed < required {
        plan.note = Some(format!("collecting verified soldering proofs: {completed}/{required}"));
    } else if elapsed < window {
        let remaining = (window - elapsed).max(1);
        plan.then(
            JOB_SEAL_PROOFS,
            bincode::serialize(&SealParams { completed, due_at: current_time_secs() + remaining })?,
            Some(remaining),
        );
        plan.note =
            Some(format!("{completed}/{required} proofs verified; sealing in {remaining}s"));
    } else {
        plan.then(JOB_BUILD_GRAPH, Vec::new(), None);
    }
    Step::done(plan)
}

async fn seal_proofs(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let _: SealParams = bincode::deserialize(params).context("decode seal params")?;
    let Some(instance_id) = pending_session(deps, graph_id).await? else {
        return Step::ignore("no pending graph session");
    };
    let mut state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing BABE setup state for pending graph {graph_id}"))?;
    if state.operator.is_none() {
        return Step::ignore("no operator setup state");
    }
    proof_collection_step(deps, graph_id, instance_id, &mut state).await
}

async fn build_graph(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(instance_id) = pending_session(deps, graph_id).await? else {
        return Step::ignore("no pending graph session");
    };
    let (operator_master_key, local_operator_pubkey) = local_operator()?;
    let mut state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing BABE setup state for pending graph {graph_id}"))?;
    let operator_state = state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for pending graph {graph_id}"))?;
    let required_slots = min_required_verifier();
    let selected_verifier_pubkeys = match &operator_state.selected_verifier_pubkeys {
        Some(selected) => selected.clone(),
        None => {
            let mut selected = operator_state
                .candidates
                .iter()
                .filter(|candidate| candidate.gc_data.is_some())
                .map(|candidate| candidate.verifier_pubkey)
                .collect::<Vec<_>>();
            selected.sort_by_key(|candidate| candidate.to_bytes());
            selected.truncate(required_slots);
            selected
        }
    };
    seal_selected_verifiers(operator_state, selected_verifier_pubkeys)?;
    let bitvm_gc_circuit_datas = selected_gc_data(operator_state)?;
    let selected_verifier_count = operator_state
        .selected_verifier_pubkeys
        .as_ref()
        .context("selected verifier set is missing after proof collection")?
        .len();
    let selected_verifier_peer_ids = (0..selected_verifier_count)
        .map(|verifier_index| {
            let candidate = selected_candidate_for_graph_index(operator_state, verifier_index)?;
            PeerId::from_bytes(&candidate.verifier_peer_id)
                .context("decode selected verifier peer id for CreateGraph ACK")
                .map(|peer_id| peer_id.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate_pubkeys = operator_state
        .candidates
        .iter()
        .map(|candidate| candidate.verifier_pubkey)
        .collect::<Vec<_>>();
    save_babe_setup_state(&deps.local_db, instance_id, graph_id, &state)?;

    // Reuse an existing graph for this id and resume CreateGraph delivery.
    let (graph, already_finalized) = match get_graph(&deps.local_db, instance_id, graph_id).await? {
        Some(stored) => {
            let already_finalized = BitvmGcGraph::from_simplified(&stored)?.committee_pre_signed();
            info!(event = "operator_graph_creation", outcome = "resumed", graph_id = %graph_id, already_finalized, "graph was stored by an earlier run");
            (stored, already_finalized)
        }
        None => {
            let instance_params = get_instance_parameters(&deps.local_db, instance_id)
                .await?
                .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
            let (graph_nonce, cur_prekickoff_txn) =
                match get_current_prekickoff_tx(&deps.local_db, &local_operator_pubkey).await? {
                    Some((graph_nonce, prekickoff_tx)) => (graph_nonce, prekickoff_tx),
                    None => (
                        0,
                        build_genesis_prekickoff_tx(&deps.btc_client, &deps.goat_client).await?,
                    ),
                };
            let prekickoff_params =
                build_prekickoff_params(&deps.btc_client, graph_nonce, cur_prekickoff_txn).await?;
            let mut graph_params = build_graph_params(
                &deps.local_db,
                &deps.goat_client,
                instance_params,
                prekickoff_params,
                bitvm_gc_circuit_datas,
                graph_nonce,
                graph_id,
            )
            .await?;
            let challenge_init_txid = generate_bitvm_graph(graph_params.clone())?
                .watchtower_challenge_init
                .tx()
                .compute_txid()
                .to_byte_array();
            graph_params.pubin_disprove_constant = get_guest_constant_value(
                graph_id,
                challenge_init_txid,
                &graph_params.watchtower_pubkeys,
            )?;
            let mut graph = generate_bitvm_graph(graph_params)?;
            anyhow::ensure!(
                graph.watchtower_challenge_init.tx().compute_txid().to_byte_array()
                    == challenge_init_txid,
                "Operator constant unexpectedly changes the watchtower challenge init transaction"
            );
            operator_pre_sign(operator_master_key.master_keypair(), &mut graph)?;
            let graph = graph.to_simplified()?;
            store_operator_presigned_graph(&deps.local_db, &graph).await?;
            info!(event = "operator_graph_creation", outcome = "committed", graph_id = %graph_id, graph_nonce, "stored operator-pre-signed graph definition");
            (graph, false)
        }
    };
    let graph_nonce = graph.parameters.graph_nonce;

    let mut plan = GraphPlan::default();
    if !already_finalized {
        let mut ack_peers = selected_verifier_peer_ids;
        ack_peers.extend(committee_ack_peers());
        plan.send(
            planned(
                graph_id,
                PHASE_COLLECT,
                Actor::All,
                GOATMessageContent::CreateGraph(CreateGraph {
                    instance_id,
                    graph_id,
                    graph_nonce,
                    graph,
                }),
                &ack_peers,
                None,
            )
            .await?,
        );
    }
    plan.close_rows.push(outbox_id(graph_id, "InitGraph", None));
    for pubkey in candidate_pubkeys {
        plan.close_rows.push(outbox_id(graph_id, "CutCircuits", Some(&pubkey.to_string())));
    }
    plan.delete_pending_session = true;
    plan.wake_refs.push(slot_ref(&local_operator_pubkey.to_string(), graph_nonce));
    plan.state = GraphStateUpdate {
        instance_id: Some(instance_id),
        operator_pubkey: Some(local_operator_pubkey.to_string()),
        graph_nonce: Some(graph_nonce),
        finalized: Some(already_finalized),
    };
    Step::done(plan)
}

async fn ingest_nonces(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::NonceGeneration(NonceGeneration {
        instance_id,
        graph_id: message_graph_id,
        committee_pubkey,
        pub_nonces,
        nonce_sigs,
    }) = message.content
    else {
        return invalid("not a NonceGeneration message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("NonceGeneration identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    if deps.actor == Actor::Committee && local_member(deps, instance_id).await?.is_none() {
        return Step::ignore("not in this instance's committee");
    }
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::retry("graph definition not stored yet", 30);
    };
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.parameters.gc_data.len();
    if !verify_nonce_signatures(
        &XOnlyPublicKey::from(committee_pubkey),
        &pub_nonces,
        &nonce_sigs,
        watchtower_num,
        verifier_num,
    )? {
        return invalid(format!("invalid pub_nonces or nonce_sigs from {committee_pubkey}"));
    }
    pub_nonces.validate_length(watchtower_num, verifier_num).map_err(|error| {
        SpecialError::InvalidGraph(format!("invalid pub_nonces length: {error}"))
    })?;
    store_committee_pub_nonces_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        committee_pubkey,
        pub_nonces,
    )
    .await?;
    after_committee_value(deps, instance_id, graph_id, &graph).await
}

/// What follows a stored committee value: the operator finalizes once the four
/// collections are complete; a committee member votes once every nonce is in
/// and pre-signs once every vote agrees.
async fn after_committee_value(
    deps: &JobDeps,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<Step> {
    let mut plan = GraphPlan::default();
    plan.state.instance_id = Some(instance_id);
    plan.state.operator_pubkey = Some(graph.parameters.operator_pubkey.to_string());
    plan.state.graph_nonce = Some(graph.parameters.graph_nonce);
    match deps.actor {
        Actor::Operator => {
            if four_sets_complete(deps, instance_id, graph_id).await? {
                plan.then(JOB_FINALIZE_GRAPH, Vec::new(), None);
            }
        }
        Actor::Committee => {
            let committee = committee_pubkeys(deps, instance_id).await?;
            let pub_nonces =
                get_committee_pub_nonces_for_graph(&deps.local_db, instance_id, graph_id)
                    .await?
                    .len();
            if pub_nonces >= committee.len() {
                plan.then(JOB_COMMITTEE_VOTE, Vec::new(), None);
            }
        }
        _ => {}
    }
    Step::done(plan)
}

async fn ingest_presign(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::CommitteePresign(CommitteePresign {
        instance_id,
        graph_id: message_graph_id,
        committee_pubkey,
        committee_partial_sigs,
        agg_nonces: received_agg_nonces,
    }) = message.content
    else {
        return invalid("not a CommitteePresign message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("CommitteePresign identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    if deps.actor == Actor::Committee && local_member(deps, instance_id).await?.is_none() {
        return Step::ignore("not in this instance's committee");
    }
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::retry("graph definition not stored yet", 30);
    };
    let Some(consensus) = nonce_consensus(deps, instance_id, graph_id, &graph).await? else {
        return Step::retry("waiting for committee public nonces", 30);
    };
    let NonceConsensus { full_graph, committee, pub_nonces, agg_nonces, .. } = consensus;
    let Some(received_pub_nonces) = committee
        .iter()
        .position(|pubkey| *pubkey == committee_pubkey)
        .map(|index| pub_nonces[index].clone())
    else {
        return invalid(format!("missing signer pub nonces for {committee_pubkey}"));
    };
    if agg_nonces != received_agg_nonces {
        return invalid(format!("agg_nonces mismatch from {committee_pubkey}"));
    }
    if let Err(error) = verify_graph_committee_partial_sigs(
        &full_graph,
        &committee,
        &committee_pubkey,
        &received_pub_nonces,
        &agg_nonces,
        &committee_partial_sigs,
    ) {
        return invalid(format!("invalid partial signatures from {committee_pubkey}: {error}"));
    }
    store_committee_partial_sigs_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        committee_pubkey,
        committee_partial_sigs,
    )
    .await?;
    match deps.actor {
        Actor::Committee => {
            let partials =
                get_committee_partial_sigs_for_graph(&deps.local_db, instance_id, graph_id)
                    .await?
                    .len();
            let mut plan = GraphPlan::default();
            plan.state.instance_id = Some(instance_id);
            if partials >= committee.len() {
                plan.then(JOB_COMMITTEE_ENDORSE, Vec::new(), None);
            }
            Step::done(plan)
        }
        _ => after_committee_value(deps, instance_id, graph_id, &graph).await,
    }
}

async fn ingest_endorsement(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::EndorseGraph(EndorseGraph {
        instance_id,
        graph_id: message_graph_id,
        committee_pubkey,
        committee_sig_for_graph,
        committee_sig_for_params,
        committee_evm_address,
    }) = message.content
    else {
        return invalid("not an EndorseGraph message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("EndorseGraph identity mismatch");
    }
    let peer = author_peer(&inbound)?;
    validate_committee_with_evm_address(
        &deps.goat_client,
        &peer,
        instance_id,
        &committee_pubkey,
        &committee_evm_address,
    )
    .await?;
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::ignore("graph not found, maybe belongs to another operator");
    };
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    if let Err(error) = verify_graph_endorsement(
        &deps.goat_client,
        &committee_evm_address,
        &full_graph,
        &committee_sig_for_graph,
    )
    .await
    {
        return invalid(format!("invalid endorsement signature from {committee_pubkey}: {error}"));
    }
    match verify_graph_params_endorsement(
        &committee_evm_address,
        &full_graph,
        &committee_sig_for_params,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return invalid(format!(
                "invalid params endorsement signature from {committee_pubkey}"
            ));
        }
        Err(error) => {
            return invalid(format!(
                "invalid params endorsement signature from {committee_pubkey}: {error}"
            ));
        }
    }
    store_committee_endorsement_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        committee_pubkey,
        committee_evm_address,
        committee_sig_for_graph,
        committee_sig_for_params,
    )
    .await?;
    after_committee_value(deps, instance_id, graph_id, &graph).await
}

async fn finalize_graph(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(row) = deps.local_db.acquire().await?.find_graph(&graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    // Given up at the abandon height while the signatures were still being
    // collected: the slot is left for the Skip, nothing is finalized.
    if retired(GraphStatus::from_str(&row.status).ok()) {
        return Step::ignore(format!("graph is {}", row.status));
    }
    let instance_id = row.instance_id;
    let endorsements =
        get_committee_endorsements_for_graph(&deps.local_db, instance_id, graph_id).await?;
    let params_endorsements =
        get_committee_params_endorsements_for_graph(&deps.local_db, instance_id, graph_id).await?;
    let pub_nonces =
        get_committee_pub_nonces_for_graph(&deps.local_db, instance_id, graph_id).await?;
    let partial_sigs =
        get_committee_partial_sigs_for_graph(&deps.local_db, instance_id, graph_id).await?;
    let committee = committee_pubkeys(deps, instance_id).await?;
    if endorsements.len() != committee.len()
        || params_endorsements.len() != committee.len()
        || pub_nonces.len() != committee.len()
        || partial_sigs.len() != committee.len()
    {
        return Step::ignore(format!(
            "collections incomplete: endorsements {}/{} params {}/{} nonces {}/{} partials {}/{}",
            endorsements.len(),
            committee.len(),
            params_endorsements.len(),
            committee.len(),
            pub_nonces.len(),
            committee.len(),
            partial_sigs.len(),
            committee.len()
        ));
    }
    let stored = get_graph(&deps.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    let mut graph = BitvmGcGraph::from_simplified(&stored)?;
    if graph.parameters.instance_parameters.instance_id != instance_id
        || graph.parameters.graph_id != graph_id
    {
        bail!("refuse to finalize graph {instance_id}:{graph_id} with mismatched graph parameters");
    }
    // Reuse stored committee signatures when retrying graph finalization.
    if !graph.committee_pre_signed() {
        let pub_nonces =
            order_committee_values(&committee, pub_nonces, "graph committee pub nonces")?;
        let agg_nonces = nonces_aggregation(&pub_nonces)?;
        let partial_sigs =
            order_committee_values(&committee, partial_sigs, "graph committee partial sigs")?;
        let committee_sig_for_graph = signature_aggregation(&partial_sigs, &agg_nonces, &graph)?;
        push_committee_pre_signatures(&mut graph, &committee_sig_for_graph)?;
    }
    let simplified_graph = graph.to_simplified()?;
    store_finalized_graph_if_needed(&deps.local_db, &simplified_graph).await?;
    mark_graph_as_endorsed(&deps.local_db, instance_id, graph_id).await?;
    let graph_nonce = graph.parameters.graph_nonce;
    let operator_pubkey = graph.parameters.operator_pubkey.to_string();
    try_refresh_graph(deps, instance_id, graph_id, &graph).await;

    let mut ack_peers = committee_ack_peers();
    ack_peers.extend(selected_verifier_peers(deps, instance_id, graph_id).await?);
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_DELIVER,
            Actor::All,
            GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce,
                endorse_sigs: endorsements,
                params_endorse_sigs: params_endorsements,
                graph: simplified_graph,
            }),
            &ack_peers,
            None,
        )
        .await?,
    );
    plan.notify_instance_endorsed = true;
    plan.wake_refs.push(slot_ref(&operator_pubkey, graph_nonce));
    plan.state = GraphStateUpdate {
        instance_id: Some(instance_id),
        operator_pubkey: Some(operator_pubkey),
        graph_nonce: Some(graph_nonce),
        finalized: Some(true),
    };
    Step::done(plan)
}

/// Selected verifier peers of an operator's graph, from its BABE setup state.
async fn selected_verifier_peers(
    deps: &JobDeps,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Vec<String>> {
    let Some(state) = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .and_then(|state| state.operator)
    else {
        return Ok(Vec::new());
    };
    let Some(selected) = state.selected_verifier_pubkeys.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(selected
        .iter()
        .filter_map(|pubkey| {
            state.candidates.iter().find(|candidate| candidate.verifier_pubkey == *pubkey)
        })
        .filter_map(|candidate| PeerId::from_bytes(&candidate.verifier_peer_id).ok())
        .map(|peer| peer.to_string())
        .collect())
}

/// The instance of a stored graph row, if any.
async fn graph_instance(deps: &JobDeps, graph_id: Uuid) -> Result<Option<Uuid>> {
    Ok(deps.local_db.acquire().await?.find_graph(&graph_id).await?.map(|row| row.instance_id))
}

/// Reconcile the finalized graph against both chains; a failure here is only
/// logged, the finalized definition is already stored. What the chain asks
/// of this node next comes from the graph's chain scans.
async fn try_refresh_graph(
    deps: &JobDeps,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
) {
    if let Err(error) = refresh_graph(
        &deps.local_db,
        &deps.btc_client,
        &deps.goat_client,
        instance_id,
        graph_id,
        graph,
    )
    .await
    {
        warn!(event = "graph_refresh", graph_id = %graph_id, error = %error, "graph refresh failed");
    }
}

// ----------------------------------------------------------------- verifier

async fn verifier_setup(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::InitGraph(init) = message.content else {
        return invalid("not an InitGraph message");
    };
    let instance_id = init.instance_id;
    if init.graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("InitGraph identity mismatch");
    }
    let from_peer = author_peer(&inbound)?;
    if init.operator_peer_id != from_peer.to_bytes() {
        return Step::ignore("signed operator peer id differs from the P2P source");
    }
    if !verify_init_graph_signature(&init) {
        return invalid("invalid operator signature on InitGraph");
    }
    // The instance can fail while this message waits (or while a restart
    // re-claims the job): the operator dropped its session, so the setup
    // would only cost CPU and be ignored.
    if instance_status(deps, instance_id).await?.is_some_and(|status| status.is_failed()) {
        return Step::ignore("instance failed; verifier setup skipped");
    }
    if !matches!(
        operator_stake_status(&deps.goat_client, &init.operator_pubkey)
            .await
            .context("InitGraph operator stake lookup")?,
        OperatorStakeStatus::Staked
    ) {
        return Step::ignore("operator does not meet stake requirements");
    }
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    let saved_verifier_state = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
        .filter(|state| state.verifier_pubkey == verifier_pubkey);
    let verifier_state = if let Some(saved) = saved_verifier_state {
        if saved.operator_pubkey != init.operator_pubkey
            || saved.operator_peer_id != init.operator_peer_id
        {
            return Step::ignore(
                "a different authenticated operator identity owns this verifier setup",
            );
        }
        saved
    } else {
        get_babe_gc_asset_paths()?;
        let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE setup")?;
        let static_input = derive_operator_static_input()?;
        #[cfg(feature = "mock-gc")]
        crate::mock_gc::simulate(crate::mock_gc::GcOp::Setup).await;
        let (setup_package, private_state) = tokio::task::spawn_blocking(move || {
            build_real_setup_package(BABE_N_CC, &vk, static_input)
        })
        .await
        .context("real BABE setup task failed")??;
        info!(event = "verifier_gc_setup", graph_id = %graph_id, "verifier setup done");
        VerifierBabeSetupState {
            verifier_pubkey,
            operator_pubkey: init.operator_pubkey,
            operator_peer_id: init.operator_peer_id.clone(),
            setup_package,
            private_state,
            finalized_indices: vec![],
            soldering_proof_ready: None,
        }
    };
    let setup_package = verifier_state.setup_package.clone();
    update_babe_setup_state(&deps.local_db, instance_id, graph_id, |state| {
        state.verifier = Some(verifier_state);
    })?;
    let operator_peer = from_peer.to_string();
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SETUP,
            Actor::Operator,
            GOATMessageContent::GenCircuits(GenCircuits {
                instance_id,
                graph_id,
                verifier_pubkey,
                setup_package,
            }),
            std::slice::from_ref(&operator_peer),
            None,
        )
        .await?,
    );
    plan.state = GraphStateUpdate {
        instance_id: Some(instance_id),
        operator_pubkey: Some(init.operator_pubkey.to_string()),
        ..Default::default()
    };
    Step::done(plan)
}

async fn verifier_solder(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::CutCircuits(CutCircuits {
        instance_id,
        graph_id: message_graph_id,
        verifier_pubkey,
        candidate_index,
        selected_circuit_indexes,
    }) = message.content
    else {
        return invalid("not a CutCircuits message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("CutCircuits identity mismatch");
    }
    if instance_status(deps, instance_id).await?.is_some_and(|status| status.is_failed()) {
        return Step::ignore("instance failed; verifier soldering skipped");
    }
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if local_verifier_pubkey != verifier_pubkey {
        return Step::ignore("target verifier pubkey does not match the local verifier");
    }
    let Some(mut verifier_state) = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        return Step::ignore("missing BABE verifier setup state");
    };
    if verifier_state.verifier_pubkey != verifier_pubkey {
        return Step::ignore("verifier pubkey does not match the saved BABE setup state");
    }
    if verifier_state.operator_peer_id != author_peer(&inbound)?.to_bytes() {
        return Step::ignore("sender is not the operator that initiated this verifier setup");
    }
    let operator_peer = PeerId::from_bytes(&verifier_state.operator_peer_id)
        .context("decode operator peer id saved from InitGraph")?
        .to_string();
    if selected_circuit_indexes.len() != BABE_M_CC {
        return invalid(format!(
            "invalid CutCircuits selection: expected {BABE_M_CC}, got {}",
            selected_circuit_indexes.len()
        ));
    }
    let soldering_proof_ready = if let Some(ready) = verifier_state.soldering_proof_ready.clone() {
        if ready.candidate_index != candidate_index {
            return invalid(format!(
                "CutCircuits candidate index {candidate_index} conflicts with persisted slot {}",
                ready.candidate_index
            ));
        }
        if verifier_state.finalized_indices != selected_circuit_indexes {
            return invalid("CutCircuits finalized indices conflict with persisted selection");
        }
        ready
    } else {
        get_babe_gc_asset_paths()?;
        let vk =
            crate::vk::get_vk().await.context("load Groth16 verifying key for BABE opening")?;
        let static_input = derive_operator_static_input()?;
        let private_state = verifier_state.private_state.clone();
        let selected_indices = selected_circuit_indexes.clone();
        let package_for_opening = verifier_state.setup_package.clone();
        let soldering_builder = Arc::clone(
            deps.soldering_builder
                .as_ref()
                .context("BABE soldering builder is not initialized for Verifier")?,
        );
        #[cfg(feature = "mock-gc")]
        crate::mock_gc::simulate(crate::mock_gc::GcOp::Solder).await;
        let (opened, finalized, soldering) = tokio::task::spawn_blocking(move || {
            open_real_setup_and_solder(
                &soldering_builder,
                &private_state,
                &package_for_opening,
                &selected_indices,
                &vk,
                static_input,
            )
        })
        .await
        .context("real BABE opening task failed")??;
        let ready = save_soldering_proof_payload(
            instance_id,
            graph_id,
            candidate_index,
            &opened,
            &finalized,
            &soldering,
        )
        .await?;
        verifier_state.finalized_indices = selected_circuit_indexes;
        verifier_state.soldering_proof_ready = Some(ready.clone());
        update_babe_setup_state(&deps.local_db, instance_id, graph_id, |state| {
            state.verifier = Some(verifier_state);
        })?;
        ready
    };
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SETUP,
            Actor::Operator,
            GOATMessageContent::SolderingProofReady(soldering_proof_ready),
            std::slice::from_ref(&operator_peer),
            None,
        )
        .await?,
    );
    plan.state.instance_id = Some(instance_id);
    Step::done(plan)
}

async fn verifier_validate_graph(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::CreateGraph(CreateGraph {
        instance_id,
        graph_id: message_graph_id,
        graph_nonce,
        graph,
    }) = message.content
    else {
        return invalid("not a CreateGraph message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("CreateGraph identity mismatch");
    }
    if !message_identity_matches(
        "CreateGraph",
        instance_id,
        graph_id,
        graph_nonce,
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return invalid("CreateGraph envelope and graph parameters name different graphs");
    }
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &local_verifier_pubkey)?
    else {
        return Step::ignore("local verifier is not in this graph");
    };
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    validate_verifier_slot(&full_graph, verifier_index)?;
    verify_graph_operator_pre_signatures(&full_graph).map_err(|error| {
        SpecialError::InvalidGraph(format!("invalid operator pre-signatures: {error}"))
    })?;
    let Some(verifier_state) = load_babe_setup_state(&deps.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        return Step::ignore("missing local BABE verifier state");
    };
    if verifier_state.verifier_pubkey != local_verifier_pubkey {
        return Step::ignore("local BABE verifier pubkey mismatch");
    }
    let Some(soldering_proof_ready) = verifier_state.soldering_proof_ready.clone() else {
        return Step::ignore("local verifier has no soldering proof");
    };
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        soldering_proof_ready.candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = read_soldering_proof_store_payload(&payload_path)
        .await
        .context("read local soldering proof payload for graph params endorsement")?;
    let payload = decode_soldering_proof_payload(&soldering_proof_ready, &payload)?;
    let (_opened, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand local soldering proof payload for graph params endorsement")?;
    if finalized.len() != BABE_M_CC {
        bail!("local verifier finalized BABE instance count mismatch");
    }
    let epk = &verifier_state.setup_package.commits[finalized[0].index].epk;
    let prover_state =
        build_babe_prover_state(&verifier_state.setup_package, finalized, soldering)?;
    let expected_gc_data =
        extract_gc_circuit_data(local_verifier_pubkey, epk, &prover_state.h_msgs)?;
    if graph.parameters.gc_data[verifier_index] != expected_gc_data {
        return invalid(
            "graph GC data for the local verifier does not match the local soldering proof",
        );
    }
    let canonical_graph_params_hash = graph.canonical_graph_params_hash()?;
    let signature = sign_verifier_graph_params(verifier_master_key.master_keypair(), &graph)?;
    deps.metrics_state.record_graph_validation(true);
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_ENDORSE,
            Actor::Committee,
            GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
                instance_id,
                graph_id,
                verifier_pubkey: local_verifier_pubkey,
                verifier_index,
                canonical_graph_params_hash,
                signature,
            }),
            &[],
            None,
        )
        .await?,
    );
    plan.close_rows.push(outbox_id(graph_id, "GenCircuits", None));
    plan.close_rows.push(outbox_id(graph_id, "SolderingProofReady", None));
    plan.state = GraphStateUpdate {
        instance_id: Some(instance_id),
        operator_pubkey: Some(graph.parameters.operator_pubkey.to_string()),
        graph_nonce: Some(graph_nonce),
        ..Default::default()
    };
    Step::done(plan)
}

// ---------------------------------------------------------------- committee

async fn committee_ingest_graph(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::CreateGraph(CreateGraph {
        instance_id,
        graph_id: message_graph_id,
        graph_nonce,
        graph,
    }) = message.content
    else {
        return invalid("not a CreateGraph message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("CreateGraph identity mismatch");
    }
    if !message_identity_matches(
        "CreateGraph",
        instance_id,
        graph_id,
        graph_nonce,
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return invalid("CreateGraph envelope and graph parameters name different graphs");
    }
    if local_member(deps, instance_id).await?.is_none() {
        return Step::ignore("not in this instance's committee");
    }
    // Structure, policy, prekickoff continuity, instance parameters against
    // both chains, watchtower set and operator stake; verifier endorsements
    // may arrive later.
    let validation =
        validate_init_graph_base(&deps.local_db, &deps.btc_client, &deps.goat_client, &graph).await;
    deps.metrics_state.record_graph_validation(validation.is_ok());
    validation?;
    store_operator_presigned_graph(&deps.local_db, &graph).await?;
    let verifier_count = graph.parameters.gc_data.len();
    let endorsements =
        get_verifier_graph_params_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
            .await?;
    let mut plan = GraphPlan {
        state: GraphStateUpdate {
            instance_id: Some(instance_id),
            operator_pubkey: Some(graph.parameters.operator_pubkey.to_string()),
            graph_nonce: Some(graph_nonce),
            ..Default::default()
        },
        ..Default::default()
    };
    plan.wake_refs.push(slot_ref(&graph.parameters.operator_pubkey.to_string(), graph_nonce));
    if endorsements.len() >= verifier_count {
        plan.then(JOB_COMMITTEE_NONCES, Vec::new(), None);
    }
    Step::done(plan)
}

async fn ingest_verifier_endorsement(
    deps: &JobDeps,
    graph_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
        instance_id,
        graph_id: message_graph_id,
        verifier_pubkey,
        verifier_index,
        canonical_graph_params_hash,
        signature,
    }) = message.content
    else {
        return invalid("not a VerifierGraphParamsEndorsement message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("VerifierGraphParamsEndorsement identity mismatch");
    }
    if local_member(deps, instance_id).await?.is_none() {
        return Step::ignore("not in this instance's committee");
    }
    let verifier_peer = author_peer(&inbound)?;
    if !crate::p2p_admission::peer_registry().is_verifier(&verifier_peer)
        && !deps.goat_client.committee_mana_is_verifier(&verifier_peer.to_bytes()).await?
    {
        return Step::ignore(format!("sender {verifier_peer} is not a registered verifier"));
    }
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::retry("graph definition not stored yet", 30);
    };
    if canonical_graph_params_hash != graph.canonical_graph_params_hash()? {
        return invalid(format!("canonical graph params hash mismatch from {verifier_pubkey}"));
    }
    if verifier_index >= graph.parameters.gc_data.len() {
        return invalid(format!("verifier index {verifier_index} out of range"));
    }
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != verifier_pubkey {
        return invalid(format!("verifier pubkey does not own slot {verifier_index}"));
    }
    if !verify_verifier_graph_params_endorsement(&verifier_pubkey, &graph, &signature)? {
        return invalid(format!("invalid verifier endorsement signature from {verifier_pubkey}"));
    }
    store_verifier_graph_params_endorsement(
        &deps.local_db,
        instance_id,
        graph_id,
        verifier_pubkey,
        verifier_index,
        &verifier_peer.to_string(),
        signature,
    )
    .await?;
    let endorsements =
        get_verifier_graph_params_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
            .await?;
    let mut plan = GraphPlan::default();
    plan.state.instance_id = Some(instance_id);
    if endorsements.len() >= graph.parameters.gc_data.len() {
        plan.then(JOB_COMMITTEE_NONCES, Vec::new(), None);
    }
    Step::done(plan)
}

/// Start the committee's signing round for a validated, fully endorsed graph:
/// the deterministic nonces, stored before they are sent.
async fn committee_nonces(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(instance_id) = graph_instance(deps, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::ignore("graph definition missing");
    };
    let verifier_endorsements =
        get_verifier_graph_params_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
            .await?;
    if verifier_endorsements.len() < graph.parameters.gc_data.len() {
        return Step::ignore(format!(
            "waiting for verifier graph params endorsements ({}/{})",
            verifier_endorsements.len(),
            graph.parameters.gc_data.len()
        ));
    }
    let validation = validate_init_graph(
        &deps.local_db,
        &deps.btc_client,
        &deps.goat_client,
        &graph,
        &verifier_endorsements,
    )
    .await;
    deps.metrics_state.record_graph_validation(validation.is_ok());
    validation?;
    if let Some(reason) = gate_closed(deps, instance_id).await? {
        return Step::ignore(format!("signing gate closed: {reason}"));
    }
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_committee_pubkey: PublicKey = instance_keypair.public_key().into();
    if get_committee_partial_sigs_for_graph_member(
        &deps.local_db,
        instance_id,
        graph_id,
        &local_committee_pubkey,
    )
    .await?
    .is_some()
    {
        return Step::ignore("local committee partial signatures already exist");
    }
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let (pub_nonces, _, nonce_sigs) =
        committee_master_key.nonces_for_graph_job_with_keypair(&full_graph, instance_keypair)?;
    store_committee_pub_nonces_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        local_committee_pubkey,
        pub_nonces.clone(),
    )
    .await?;
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SIGNING,
            Actor::All,
            GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                pub_nonces,
                nonce_sigs,
            }),
            &[],
            None,
        )
        .await?,
    );
    let committee = committee_pubkeys(deps, instance_id).await?;
    let nonces =
        get_committee_pub_nonces_for_graph(&deps.local_db, instance_id, graph_id).await?.len();
    plan.state.instance_id = Some(instance_id);
    if nonces >= committee.len() {
        plan.then(JOB_COMMITTEE_VOTE, Vec::new(), None);
    }
    Step::done(plan)
}

/// The nonce transcript every member must agree on before signing.
struct NonceConsensus {
    full_graph: BitvmGcGraph,
    committee: Vec<PublicKey>,
    /// Every member's public nonces, in committee order.
    pub_nonces: Vec<bitvm_lib::committee::CommitteePubNonces>,
    agg_nonces: bitvm_lib::committee::CommitteeAggNonces,
    consensus_hash: [u8; 32],
}

async fn nonce_consensus(
    deps: &JobDeps,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<Option<NonceConsensus>> {
    let committee = committee_pubkeys(deps, instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_graph(&deps.local_db, instance_id, graph_id).await?;
    if pub_nonces_unchecked.len() < committee.len() {
        return Ok(None);
    }
    let full_graph = BitvmGcGraph::from_simplified(graph)?;
    let verifier_num = full_graph.parameters.gc_data.len();
    let watchtower_num = full_graph.parameters.watchtower_pubkeys.len();
    let mut checked = Vec::with_capacity(pub_nonces_unchecked.len());
    for (pubkey, pub_nonces) in pub_nonces_unchecked {
        pub_nonces.validate_length(watchtower_num, verifier_num).map_err(|error| {
            anyhow!("committee public nonces from {pubkey} have invalid length: {error}")
        })?;
        checked.push((pubkey, pub_nonces));
    }
    let ordered = order_committee_values(&committee, checked, "graph committee pub nonces")?;
    let agg_nonces = nonces_aggregation(&ordered)?;
    let consensus_hash = committee_nonce_consensus_hash(&full_graph, &committee, &ordered)?;
    Ok(Some(NonceConsensus {
        full_graph,
        committee,
        pub_nonces: ordered,
        agg_nonces,
        consensus_hash,
    }))
}

async fn committee_vote(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(instance_id) = graph_instance(deps, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::ignore("graph definition missing");
    };
    let Some(consensus) = nonce_consensus(deps, instance_id, graph_id, &graph).await? else {
        return Step::ignore("waiting for committee public nonces");
    };
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_committee_pubkey: PublicKey = instance_keypair.public_key().into();
    let votes =
        get_committee_agg_nonce_consensus_for_graph(&deps.local_db, instance_id, graph_id).await?;
    let local_vote = votes.iter().find(|(pubkey, _, _)| *pubkey == local_committee_pubkey);
    if let Some((_, stored_hash, _)) = local_vote
        && *stored_hash != consensus.consensus_hash
    {
        return invalid(format!(
            "local committee agg nonce consensus differs for graph {graph_id}"
        ));
    }
    let signature = match local_vote {
        Some((_, _, signature)) => *signature,
        None => {
            if let Some(reason) = gate_closed(deps, instance_id).await? {
                return Step::ignore(format!("signing gate closed: {reason}"));
            }
            let signature = SECP256K1.sign_schnorr(
                &SecpMessage::from_digest(consensus.consensus_hash),
                &instance_keypair,
            );
            store_committee_agg_nonce_consensus_for_graph(
                &deps.local_db,
                instance_id,
                graph_id,
                local_committee_pubkey,
                consensus.consensus_hash,
                signature,
            )
            .await?;
            signature
        }
    };
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SIGNING,
            Actor::Committee,
            GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                consensus_hash: consensus.consensus_hash,
                signature,
            }),
            &[],
            None,
        )
        .await?,
    );
    plan.state.instance_id = Some(instance_id);
    if votes_complete(deps, instance_id, graph_id, &consensus).await? {
        plan.then(JOB_COMMITTEE_PRESIGN, Vec::new(), None);
    }
    Step::done(plan)
}

/// Every member signed the same ordered nonce set (the AggNonceConsensus barrier).
async fn votes_complete(
    deps: &JobDeps,
    instance_id: Uuid,
    graph_id: Uuid,
    consensus: &NonceConsensus,
) -> Result<bool> {
    let votes =
        get_committee_agg_nonce_consensus_for_graph(&deps.local_db, instance_id, graph_id).await?;
    if votes.len() < consensus.committee.len() {
        return Ok(false);
    }
    let ordered = order_committee_values(
        &consensus.committee,
        votes.into_iter().map(|(pubkey, hash, signature)| (pubkey, (hash, signature))).collect(),
        "graph committee agg nonce consensus",
    )?;
    for (committee_pubkey, (received_hash, signature)) in consensus.committee.iter().zip(ordered) {
        if received_hash != consensus.consensus_hash {
            return invalid(format!(
                "committee agg nonce consensus differs for graph {graph_id} and committee {committee_pubkey}"
            ));
        }
        SECP256K1
            .verify_schnorr(
                &signature,
                &SecpMessage::from_digest(consensus.consensus_hash),
                &XOnlyPublicKey::from(*committee_pubkey),
            )
            .map_err(|error| {
                SpecialError::InvalidGraph(format!(
                    "invalid agg nonce consensus signature for graph {graph_id} and committee {committee_pubkey}: {error}"
                ))
            })?;
    }
    Ok(true)
}

async fn ingest_vote(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
        instance_id,
        graph_id: message_graph_id,
        committee_pubkey,
        consensus_hash: received_hash,
        signature,
    }) = message.content
    else {
        return invalid("not an AggNonceConsensus message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("AggNonceConsensus identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    if deps.actor == Actor::Committee && local_member(deps, instance_id).await?.is_none() {
        return Step::ignore("not in this instance's committee");
    }
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::retry("graph definition not stored yet", 30);
    };
    let Some(consensus) = nonce_consensus(deps, instance_id, graph_id, &graph).await? else {
        return Step::retry(
            "waiting for committee public nonces before validating agg nonce consensus",
            30,
        );
    };
    if received_hash != consensus.consensus_hash {
        return invalid(format!("consensus hash mismatch from {committee_pubkey}"));
    }
    if SECP256K1
        .verify_schnorr(
            &signature,
            &SecpMessage::from_digest(consensus.consensus_hash),
            &XOnlyPublicKey::from(committee_pubkey),
        )
        .is_err()
    {
        return invalid(format!("invalid consensus signature from {committee_pubkey}"));
    }
    store_committee_agg_nonce_consensus_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        committee_pubkey,
        received_hash,
        signature,
    )
    .await?;
    let mut plan = GraphPlan::default();
    plan.state.instance_id = Some(instance_id);
    if votes_complete(deps, instance_id, graph_id, &consensus).await? {
        plan.then(JOB_COMMITTEE_PRESIGN, Vec::new(), None);
    }
    Step::done(plan)
}

async fn committee_presign(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(instance_id) = graph_instance(deps, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::ignore("graph definition missing");
    };
    let Some(mut consensus) = nonce_consensus(deps, instance_id, graph_id, &graph).await? else {
        return Step::ignore("waiting for committee public nonces");
    };
    if !votes_complete(deps, instance_id, graph_id, &consensus).await? {
        return Step::ignore("waiting for agg nonce consensus");
    }
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_committee_pubkey: PublicKey = instance_keypair.public_key().into();
    let partial_sigs = match get_committee_partial_sigs_for_graph_member(
        &deps.local_db,
        instance_id,
        graph_id,
        &local_committee_pubkey,
    )
    .await?
    {
        Some(stored) => stored,
        None => {
            // Recheck the persisted bindings at the actual signing boundary.
            let verifier_endorsements = get_verifier_graph_params_endorsements_for_graph(
                &deps.local_db,
                instance_id,
                graph_id,
            )
            .await?;
            validate_verifier_graph_params_endorsements(
                &deps.goat_client,
                &graph,
                &verifier_endorsements,
            )
            .await?;
            if let Some(reason) = gate_closed(deps, instance_id).await? {
                return Step::ignore(format!("signing gate closed: {reason}"));
            }
            let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
            let (pub_nonces, sec_nonces, _) = committee_master_key
                .nonces_for_graph_job_with_keypair(&consensus.full_graph, instance_keypair)?;
            // Authorization before the signature: this nonce, this transcript,
            // once. The nonce consensus hash binds graph, committee and every
            // public nonce, hence the aggregate nonces and the sighashes.
            let transcript = hex::encode(consensus.consensus_hash);
            let nonce = signing_nonce_id("graph-presign", &bincode::serialize(&pub_nonces)?);
            let authorization = deps
                .local_db
                .acquire()
                .await?
                .authorize_signing(
                    "graph",
                    &graph_id.to_string(),
                    &nonce,
                    &transcript,
                    current_time_secs(),
                )
                .await?;
            if let SigningAuthorization::Conflict { existing_digest } = authorization {
                return Err(SpecialError::InvalidGraph(format!(
                    "graph presign nonce already authorized for transcript {existing_digest}, refusing {transcript}"
                ))
                .into());
            }
            let partial_sigs = committee_pre_sign(
                instance_keypair,
                sec_nonces,
                consensus.agg_nonces.clone(),
                &mut consensus.full_graph,
            )?;
            store_committee_partial_sigs_for_graph(
                &deps.local_db,
                instance_id,
                graph_id,
                local_committee_pubkey,
                partial_sigs.clone(),
            )
            .await?;
            partial_sigs
        }
    };
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SIGNING,
            Actor::All,
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                committee_partial_sigs: partial_sigs,
                agg_nonces: consensus.agg_nonces.clone(),
            }),
            &[],
            None,
        )
        .await?,
    );
    plan.state.instance_id = Some(instance_id);
    let partials =
        get_committee_partial_sigs_for_graph(&deps.local_db, instance_id, graph_id).await?.len();
    if partials >= consensus.committee.len() {
        plan.then(JOB_COMMITTEE_ENDORSE, Vec::new(), None);
    }
    Step::done(plan)
}

async fn committee_endorse(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    let Some(instance_id) = graph_instance(deps, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    let Some(graph) = get_graph(&deps.local_db, instance_id, graph_id).await? else {
        return Step::ignore("graph definition missing");
    };
    let committee = committee_pubkeys(deps, instance_id).await?;
    let partials =
        get_committee_partial_sigs_for_graph(&deps.local_db, instance_id, graph_id).await?;
    if partials.len() != committee.len() {
        return Step::ignore("waiting for committee partial signatures");
    }
    if let Some(reason) = gate_closed(deps, instance_id).await? {
        return Step::ignore(format!("signing gate closed: {reason}"));
    }
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    let committee_sig_for_graph = endorse_graph(&deps.goat_client, &full_graph).await?;
    let committee_sig_for_params = endorse_graph_params(&full_graph).await?;
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_committee_pubkey: PublicKey = instance_keypair.public_key().into();
    let committee_evm_address =
        get_node_goat_address().ok_or_else(|| anyhow!("failed to get node goat address"))?;
    let mut plan = GraphPlan::default();
    plan.send(
        planned(
            graph_id,
            PHASE_SIGNING,
            Actor::All,
            GOATMessageContent::EndorseGraph(EndorseGraph {
                instance_id,
                graph_id,
                committee_pubkey: local_committee_pubkey,
                committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
                committee_sig_for_params: committee_sig_for_params.as_bytes().to_vec(),
                committee_evm_address,
            }),
            &[],
            None,
        )
        .await?,
    );
    plan.state.instance_id = Some(instance_id);
    Step::done(plan)
}

// ------------------------------------------------------------------ finalize

async fn ingest_finalized(deps: &JobDeps, graph_id: Uuid, params: &[u8]) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::GraphFinalize(GraphFinalize {
        instance_id,
        graph_id: message_graph_id,
        graph_nonce,
        graph,
        endorse_sigs,
        params_endorse_sigs,
    }) = message.content
    else {
        return invalid("not a GraphFinalize message");
    };
    if message_graph_id != graph_id || instance_id != inbound.instance_id {
        return invalid("GraphFinalize identity mismatch");
    }
    if !message_identity_matches(
        "GraphFinalize",
        instance_id,
        graph_id,
        graph_nonce,
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return invalid("GraphFinalize envelope and graph parameters name different graphs");
    }
    let validation = validate_finalized_graph(
        &deps.btc_client,
        &deps.goat_client,
        &graph,
        &endorse_sigs,
        &params_endorse_sigs,
    )
    .await;
    deps.metrics_state.record_graph_validation(validation.is_ok());
    validation?;
    store_finalized_graph_if_needed(&deps.local_db, &graph).await?;
    store_committee_endorsements_for_graph(
        &deps.local_db,
        instance_id,
        graph_id,
        endorse_sigs,
        params_endorse_sigs,
    )
    .await?;
    mark_graph_as_endorsed(&deps.local_db, instance_id, graph_id).await?;
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    try_refresh_graph(deps, instance_id, graph_id, &full_graph).await;
    let operator_pubkey = graph.parameters.operator_pubkey.to_string();
    let mut plan = GraphPlan {
        notify_instance_endorsed: true,
        wake_refs: vec![slot_ref(&operator_pubkey, graph_nonce)],
        state: GraphStateUpdate {
            instance_id: Some(instance_id),
            operator_pubkey: Some(operator_pubkey),
            graph_nonce: Some(graph_nonce),
            finalized: Some(true),
        },
        ..Default::default()
    };
    if deps.relayer {
        plan.then(JOB_POST_GRAPH_DATA, Vec::new(), None);
    }
    Step::done(plan)
}

/// The relayer's `postGraphData` once the peg-in is withdrawable (Post phase).
async fn post_graph_data(deps: &JobDeps, graph_id: Uuid, _params: &[u8]) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    let Some(instance_id) = graph_instance(deps, graph_id).await? else {
        return Step::ignore("graph not stored locally");
    };
    if instance_status(deps, instance_id).await?.is_some_and(|status| status.is_failed()) {
        return Step::ignore("instance failed; graph not posted");
    }
    let graph_data = deps.goat_client.gateway_get_graph_data(&graph_id).await?;
    if graph_data.operator_pubkey != [0u8; 32] {
        return Step::ignore("graph data already posted");
    }
    let pegin_data = deps.goat_client.gateway_get_pegin_data(&instance_id).await?;
    if pegin_data.status != PeginStatus::Withdrawable {
        let block_time = crate::utils::avg_block_time_secs(deps.btc_client.network()) as i64;
        return Step::retry(
            format!("pegin data is {}; not withdrawable yet", pegin_data.status),
            block_time,
        );
    }
    let committee = committee_pubkeys(deps, instance_id).await?;
    let endorsement_sigs =
        get_committee_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
            .await?
            .into_iter()
            .map(|(_, _, sig)| sig)
            .collect::<Vec<_>>();
    if endorsement_sigs.len() != committee.len() {
        return Step::retry(
            format!(
                "{} of {} committee endorsements for the graph",
                endorsement_sigs.len(),
                committee.len()
            ),
            60,
        );
    }
    let graph = get_graph(&deps.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    let graph = BitvmGcGraph::from_simplified(&graph)?;
    let data = crate::utils::build_graph_data(&graph)?;
    deps.goat_client
        .gateway_post_graph_data(&instance_id, &graph_id, &data, &endorsement_sigs)
        .await?;
    info!(event = "graph_post", graph_id = %graph_id, instance_id = %instance_id, "postGraphData sent");
    Step::done(GraphPlan::default())
}

/// Pull attempts a minute apart before a missing definition is retried
/// slowly. The job id is stable, so a pull that stopped would never start
/// again for the parked messages that asked for it; it ends when they have
/// expired (`PARKED_MESSAGE_TTL_SECS`), or earlier when the graph retires.
const FETCH_GRAPH_FAST_ATTEMPTS: i64 = 5;
const FETCH_GRAPH_SLOW_RETRY_SECS: i64 = 600;
const FETCH_GRAPH_MAX_ATTEMPTS: i64 = FETCH_GRAPH_FAST_ATTEMPTS
    + super::common::PARKED_MESSAGE_TTL_SECS / FETCH_GRAPH_SLOW_RETRY_SECS;

async fn fetch_graph(deps: &JobDeps, graph_id: Uuid, params: &[u8], attempts: i64) -> Result<Step> {
    let lookup: GraphLookup = bincode::deserialize(params).context("decode graph lookup")?;
    let give_up = |reason: String| {
        if attempts + 1 >= FETCH_GRAPH_MAX_ATTEMPTS {
            warn!(event = "graph_fetch", graph_id = %graph_id, ?lookup, attempts, reason, "giving up on the pull");
            Step::ignore(format!("gave up pulling {lookup:?}: {reason}"))
        } else if attempts + 1 >= FETCH_GRAPH_FAST_ATTEMPTS {
            Step::retry(reason, FETCH_GRAPH_SLOW_RETRY_SECS)
        } else {
            Step::retry(reason, 60)
        }
    };
    match fetch_and_store_graph(
        &deps.local_db,
        &deps.btc_client,
        &deps.goat_client,
        &deps.publisher,
        &lookup,
    )
    .await
    {
        Ok(Some(found)) => {
            // The pulled graph's own aggregate decides what follows.
            submit_event(
                &deps.local_db,
                graph_pulled_event(found.graph_id, found.instance_id, found.finalized)?,
            )
            .await?;
            let mut plan = GraphPlan::noted(format!(
                "pulled graph {} (finalized: {})",
                found.graph_id, found.finalized
            ));
            plan.wake_refs.push(slot_ref(&found.operator_pubkey, found.graph_nonce));
            plan.wake_refs.push(graph_ref(found.graph_id).wake_ref());
            if found.graph_id != graph_id {
                plan.wake_refs.push(graph_ref(graph_id).wake_ref());
            }
            Step::done(plan)
        }
        Ok(None) => give_up(format!("no peer served {lookup:?}")),
        Err(error) => give_up(format!("{error:#}")),
    }
}
