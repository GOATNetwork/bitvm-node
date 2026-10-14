//! Jobs for committee answers, instance parameters and the PeginConfirm round.
//!
//! Jobs query external state, persist protocol material and return an
//! [`InstancePlan`] for outgoing messages and follow-up work. Goat posting and
//! committee key deletion use their own result handlers.

use super::graph::{InboundMessage, PlannedMessage, graph_ref};
use super::graph_jobs::signing_nonce_id;
use super::instance::{
    INSTANCE_JOBS, INSTANCE_KIND, InstancePlan, JOB_ANSWER_PEGIN_REQUEST,
    JOB_BROADCAST_PEGIN_CONFIRM, JOB_CONFIRM_INSTANCE, JOB_DELETE_INSTANCE_KEY,
    JOB_INGEST_PEGIN_CONFIRM_NONCE, JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG,
    JOB_INGEST_PEGIN_CONFIRM_VOTE, JOB_PEGIN_CONFIRM_SIGN, JOB_PEGIN_CONFIRM_VOTE,
    JOB_POST_PEGIN_DATA, JOB_START_PEGIN_CONFIRM, KeyDeleteResult, PHASE_CONFIRM, SigningGate,
    StartGraph, confirm_round_over, signing_gate,
};
use crate::action::{
    GOATMessage, GOATMessageContent, PeginConfirmNonce, PeginConfirmNonceConsensus,
    PeginConfirmPartialSig,
};
use crate::env::{
    get_bitvm_key, get_operator_graph_start_cutoff_blocks, is_enable_committee_instance_key_delete,
};
use crate::error::{FailureClass, SpecialError, classify_failure};
use crate::metrics_service::MetricsState;
use crate::rpc_service::current_time_secs;
use crate::utils::{
    CommitteeMembership, avg_block_time_secs, broadcast_tx, committee_instance_keys_envelope_path,
    endorse_pegin, get_committee_agg_nonce_consensus_for_instance,
    get_committee_endorse_sigs_for_pegin, get_committee_partial_sig_for_instance,
    get_committee_partial_sigs_for_instance, get_committee_pub_nonce_for_instance,
    get_committee_pub_nonces_for_instance, get_graph_by_instance_id_and_operator_pubkey,
    get_instance_parameters, has_required_presigned_graphs, is_io_not_found_error,
    local_committee_membership, order_committee_values, read_instance_info_from_goat,
    read_pegin_request, store_committee_agg_nonce_consensus_for_instance,
    store_committee_endorse_sig_for_pegin, store_committee_partial_sig_for_instance,
    store_committee_pub_nonce_for_instance, store_instance_parameters, tx_visible,
    validate_committee, verify_pegin_endorsement,
};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bitcoin::key::Keypair;
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::committee::{
    nonce_aggregation, pegin_confirm_nonce_consensus_hash, verify_pegin_confirm_partial_sig,
};
use bitvm_lib::keys::{CommitteeMasterKey, OperatorMasterKey};
use bitvm_lib::types::BitvmGcInstanceParameters;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, PeginStatus};
use engine::{EngineBuilder, JobContext, JobOutcome, JobRunner};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::PeerId;
use secp256k1::{Message as SecpMessage, SECP256K1};
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{InstanceBridgeInStatus, SigningAuthorization};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct InstanceJobDeps {
    pub actor: Actor,
    pub relayer: bool,
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    pub metrics_state: MetricsState,
}

pub fn register_instance_jobs(builder: EngineBuilder, deps: Arc<InstanceJobDeps>) -> EngineBuilder {
    let runner: Arc<dyn JobRunner> = Arc::new(InstanceJobRunner { deps: deps.clone() });
    let mut builder = builder;
    for action in INSTANCE_JOBS {
        builder = builder.job_runner(INSTANCE_KIND, *action, runner.clone());
    }
    builder
        .job_runner(
            INSTANCE_KIND,
            JOB_POST_PEGIN_DATA,
            Arc::new(PostPeginDataRunner { deps: deps.clone() }),
        )
        .job_runner(INSTANCE_KIND, JOB_DELETE_INSTANCE_KEY, Arc::new(DeleteInstanceKeyRunner))
}

fn job_instance_id(ctx: &JobContext) -> Result<Uuid, JobOutcome> {
    Uuid::parse_str(&ctx.job.aggregate_id).map_err(|error| {
        JobOutcome::Failed(format!(
            "job aggregate id {} is not an instance id: {error}",
            ctx.job.aggregate_id
        ))
    })
}

/// What one step decided.
pub enum Step {
    Plan(Box<InstancePlan>),
    Retry { reason: String, after_secs: Option<i64> },
}

impl Step {
    fn done(plan: InstancePlan) -> Result<Step> {
        Ok(Step::Plan(Box::new(plan)))
    }

    fn ignore(note: impl Into<String>) -> Result<Step> {
        Ok(Step::Plan(Box::new(InstancePlan::noted(note))))
    }

    fn retry(reason: impl Into<String>, after_secs: i64) -> Result<Step> {
        Ok(Step::Retry { reason: reason.into(), after_secs: Some(after_secs) })
    }
}

/// Rejections that need a human: the node's own signing steps, the
/// relayer's broadcast and the reading of a confirmed peg-in on any, the
/// committee's answer only when Goat refused it (a request the user got
/// wrong, or one whose window is over, is noted).
fn fails_on_rejection(action: &str, error: &anyhow::Error) -> bool {
    match action {
        JOB_CONFIRM_INSTANCE
        | JOB_START_PEGIN_CONFIRM
        | JOB_PEGIN_CONFIRM_VOTE
        | JOB_PEGIN_CONFIRM_SIGN
        | JOB_BROADCAST_PEGIN_CONFIRM => true,
        JOB_ANSWER_PEGIN_REQUEST => crate::error::is_contract_revert(error),
        _ => false,
    }
}

struct InstanceJobRunner {
    deps: Arc<InstanceJobDeps>,
}

#[async_trait]
impl JobRunner for InstanceJobRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let instance_id = match job_instance_id(&ctx) {
            Ok(instance_id) => instance_id,
            Err(outcome) => return outcome,
        };
        let params = ctx.job.params.clone().unwrap_or_default();
        let action = ctx.job.action.clone();
        let attempts = ctx.job.attempts;
        match run_step(&self.deps, &action, instance_id, &params).await {
            Ok(Step::Plan(plan)) => match plan.encode() {
                Ok(bytes) => JobOutcome::Done(bytes),
                Err(error) => JobOutcome::Failed(format!("encode plan: {error}")),
            },
            Ok(Step::Retry { reason, after_secs }) => {
                JobOutcome::Transient { error: reason, retry_after_secs: after_secs }
            }
            Err(error) => match classify_failure(&error) {
                FailureClass::Permanent(reason) if fails_on_rejection(&action, &error) => {
                    JobOutcome::Failed(reason)
                }
                FailureClass::Permanent(reason) => {
                    warn!(event = "instance_job", instance_id = %instance_id, action = %action, reason = %reason, "rejected");
                    match InstancePlan::noted(format!("rejected: {reason}")).encode() {
                        Ok(bytes) => JobOutcome::Done(bytes),
                        Err(error) => JobOutcome::Failed(format!("encode plan: {error}")),
                    }
                }
                FailureClass::Transient => {
                    JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
                }
                // Round steps are bounded by the instance's own deadlines, so an
                // unrecognised failure keeps retrying; it is reported every so often.
                FailureClass::Unknown => {
                    if attempts >= UNKNOWN_FAILURE_ALERT_EVERY
                        && attempts % UNKNOWN_FAILURE_ALERT_EVERY == 0
                    {
                        warn!(event = "instance_job", instance_id = %instance_id, action = %action, attempts, error = %format!("{error:#}"), "step keeps failing for an unknown reason");
                        self.deps.metrics_state.record_instance_alert("instance_job_stuck");
                    }
                    JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
                }
            },
        }
    }
}

const UNKNOWN_FAILURE_ALERT_EVERY: i64 = 20;

async fn run_step(
    deps: &InstanceJobDeps,
    action: &str,
    instance_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    match action {
        JOB_ANSWER_PEGIN_REQUEST => answer_pegin_request(deps, instance_id).await,
        JOB_CONFIRM_INSTANCE => confirm_instance(deps, instance_id).await,
        JOB_START_PEGIN_CONFIRM => start_pegin_confirm(deps, instance_id).await,
        JOB_INGEST_PEGIN_CONFIRM_NONCE => {
            ingest_pegin_confirm_nonce(deps, instance_id, params).await
        }
        JOB_PEGIN_CONFIRM_VOTE => pegin_confirm_vote(deps, instance_id).await,
        JOB_INGEST_PEGIN_CONFIRM_VOTE => ingest_pegin_confirm_vote(deps, instance_id, params).await,
        JOB_PEGIN_CONFIRM_SIGN => pegin_confirm_sign(deps, instance_id).await,
        JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG => {
            ingest_pegin_confirm_partial_sig(deps, instance_id, params).await
        }
        JOB_BROADCAST_PEGIN_CONFIRM => broadcast_pegin_confirm(deps, instance_id, params).await,
        other => bail!("unknown instance job {other}"),
    }
}

// ------------------------------------------------------------------ helpers

async fn instance_status(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
) -> Result<Option<InstanceBridgeInStatus>> {
    Ok(deps
        .local_db
        .acquire()
        .await?
        .find_instance(&instance_id)
        .await?
        .and_then(|instance| InstanceBridgeInStatus::from_str(&instance.status).ok()))
}

/// The instance keypair when this node is in the instance's committee on
/// Goat; `None` means the instance is not this node's to sign for. Only the
/// node's own steps ask: a value from a member is stored by whoever the
/// apply let it through to (the members, and a relayer for every round).
async fn local_member(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Option<Keypair>> {
    match local_committee_membership(&deps.goat_client, instance_id).await? {
        CommitteeMembership::Member(keypair) => Ok(Some(keypair)),
        CommitteeMembership::NotMember(reason) => {
            debug!(event = "instance_job", instance_id = %instance_id, reason, "not in this instance's committee");
            Ok(None)
        }
    }
}

async fn committee_pubkeys(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Vec<PublicKey>> {
    deps.goat_client.gateway_get_committee_pubkeys(&instance_id).await
}

/// The T0 gate for the committee's signing steps: `None` when open.
async fn gate_closed(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Option<String>> {
    Ok(match signing_gate(&deps.local_db, &deps.btc_client, instance_id).await? {
        SigningGate::Open => None,
        SigningGate::Closed(reason) => Some(reason),
    })
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(SpecialError::InvalidPeginData(message.into()).into())
}

async fn decode_inbound(params: &[u8]) -> Result<(InboundMessage, GOATMessage)> {
    let inbound = InboundMessage::decode(params).context("decode inbound message")?;
    let message = GOATMessage::deserialize_message(&inbound.message).await?;
    Ok((inbound, message))
}

/// The committee value really comes from the member it names (pubkey and
/// peer id bound on Goat).
async fn ensure_committee_sender(
    deps: &InstanceJobDeps,
    inbound: &InboundMessage,
    committee_pubkey: &PublicKey,
) -> Result<()> {
    let peer = PeerId::from_str(&inbound.author).context("decode author peer id")?;
    validate_committee(&deps.goat_client, &peer, inbound.instance_id, committee_pubkey).await
}

/// A PeginConfirm round message for the committee topic: one outbox row per
/// kind and instance, re-published until the Confirm phase ends.
async fn round_message(instance_id: Uuid, content: GOATMessageContent) -> Result<PlannedMessage> {
    let kind = content.event_type();
    let payload = GOATMessage::new(Actor::Committee, content).serialize_message().await?;
    Ok(PlannedMessage {
        outbox_id: format!("instance:{instance_id}:{kind}"),
        phase_ref: PHASE_CONFIRM.to_string(),
        kind: kind.to_string(),
        actor: Actor::Committee.to_string(),
        payload,
        ack_set: None,
    })
}

fn local_operator_pubkey() -> Result<PublicKey> {
    Ok(OperatorMasterKey::new(get_bitvm_key()?).master_keypair().public_key().into())
}

/// Load the committee instance key, creating the envelope on first use. A deleted key is never
/// regenerated.
async fn load_or_create_committee_instance_keypair(
    local_db: &LocalDB,
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    match committee_master_key.load_instance_keypair(instance_id, &envelope_path) {
        Ok(keypair) => Ok(keypair),
        Err(load_err) => {
            if !is_io_not_found_error(&load_err) {
                return Err(load_err).with_context(|| {
                    format!(
                        "load committee instance keypair failed for {} at {} (refuse auto-overwrite for non-missing envelope)",
                        instance_id,
                        envelope_path.display()
                    )
                });
            }
            if local_db
                .acquire()
                .await?
                .find_instance(&instance_id)
                .await?
                .is_some_and(|instance| instance.key_deleted)
            {
                bail!(
                    "committee instance key for {instance_id} was deleted; refusing to regenerate it"
                );
            }
            info!(
                "committee instance key not found for {} at {}: {}, creating new envelope",
                instance_id,
                envelope_path.display(),
                load_err
            );
            committee_master_key
                .create_instance_keypair_envelope(instance_id, &envelope_path)
                .with_context(|| {
                    format!(
                        "create committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                })?;
            committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(
                || {
                    format!(
                        "reload committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                },
            )
        }
    }
}

// ------------------------------------------------------------------- answer

/// Answer a pending request with this committee node's instance key.
/// Skip requests already answered, no longer pending, or with spent inputs.
async fn answer_pegin_request(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Step> {
    if deps.actor != Actor::Committee {
        return Step::ignore("only committee nodes answer");
    }
    match instance_status(deps, instance_id).await? {
        Some(InstanceBridgeInStatus::UserInited) => {}
        other => return Step::ignore(format!("instance is {other:?}; answer window closed")),
    }
    let (_, _, answered_by) =
        read_pegin_request(&deps.btc_client, &deps.goat_client, instance_id).await?;
    // Gateway.answerPeginRequest accepts a repeat answer (it overwrites the
    // stored pubkey and emits CommitteeResponse again), so every re-run must
    // check what the contract already holds for this signer.
    if answered_by.contains(&deps.goat_client.get_default_signer_address()) {
        return Step::ignore("this committee already answered");
    }
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_or_create_committee_instance_keypair(
        &deps.local_db,
        &committee_master_key,
        instance_id,
    )
    .await?;
    let pubkey_for_instance: PublicKey = instance_keypair.public_key().into();
    deps.goat_client.gateway_answer_pegin_request(&instance_id, &pubkey_for_instance).await?;
    info!(event = "pegin_request", instance_id = %instance_id, outcome = "answered", "answerPeginRequest sent");
    Step::done(InstancePlan::noted("answered"))
}

// ------------------------------------------------------------------ confirm

/// Local operator policy: no new graph for an instance past `Prepare height +
/// OPERATOR_GRAPH_START_CUTOFF_BLOCKS`.
async fn graph_start_blocked(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Option<String>> {
    let instance = deps.local_db.acquire().await?.find_instance(&instance_id).await?;
    let Some(instance) = instance else {
        return Ok(None);
    };
    if let Ok(status) = InstanceBridgeInStatus::from_str(&instance.status)
        && status.is_failed()
    {
        return Ok(Some(format!("instance is {status}")));
    }
    if instance.btc_height > 0 {
        let cutoff = instance.btc_height + get_operator_graph_start_cutoff_blocks();
        let height = i64::from(deps.btc_client.get_height().await?);
        if height > cutoff {
            return Ok(Some(format!("height {height} is past the graph start cutoff {cutoff}")));
        }
    }
    Ok(None)
}

/// Read and store instance parameters after Prepare confirmation.
/// Operators also prepare a setup session and return its start event.
async fn confirm_instance(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Step> {
    match instance_status(deps, instance_id).await? {
        Some(status) if status.is_failed() => {
            return Step::ignore(format!("instance is {status}"));
        }
        Some(_) => {}
        None => return Step::ignore("instance row missing"),
    }
    let instance_params = read_instance_info_from_goat(&deps.goat_client, instance_id).await?;
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_visible(&deps.btc_client, &pegin_deposit_txid).await? {
        // The scan saw the Prepare confirmed; the backend is lagging.
        return Step::retry(
            format!("pegin deposit tx {pegin_deposit_txid} not found on chain yet"),
            30,
        );
    }
    store_instance_parameters(&deps.local_db, &instance_params).await?;
    if deps.actor != Actor::Operator {
        return Step::ignore("instance parameters stored");
    }
    let operator_pubkey = local_operator_pubkey()?;
    let mut plan = InstancePlan::default();
    if let Some(graph) =
        get_graph_by_instance_id_and_operator_pubkey(&deps.local_db, instance_id, &operator_pubkey)
            .await?
    {
        // Built already: its deliveries live in the Graph aggregate's outbox.
        let graph_id = graph.parameters.graph_id;
        plan.wake_refs.push(graph_ref(graph_id).wake_ref());
        plan.note = Some(format!("graph {graph_id} exists"));
        return Step::done(plan);
    }
    let session = deps
        .local_db
        .acquire()
        .await?
        .find_pending_graph_init_by_instance_and_operator_pubkey(
            &instance_id,
            &operator_pubkey.to_string(),
        )
        .await?;
    let graph_id = match session {
        Some(session) => session.graph_id,
        None => {
            if let Some(reason) = graph_start_blocked(deps, instance_id).await? {
                info!(event = "graph_start_cutoff", instance_id = %instance_id, reason = %reason, "not starting a new graph for this instance");
                return Step::ignore(reason);
            }
            Uuid::new_v4()
        }
    };
    plan.start_graph = Some(StartGraph { graph_id, operator_pubkey: operator_pubkey.to_string() });
    Step::done(plan)
}

// ------------------------------------------------------ pegin confirm round

/// The nonce transcript every member must agree on before signing.
struct NonceConsensus {
    parameters: BitvmGcInstanceParameters,
    committee: Vec<PublicKey>,
    agg_nonce: musig2::AggNonce,
    consensus_hash: [u8; 32],
}

async fn nonce_consensus(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
) -> Result<Option<NonceConsensus>> {
    let parameters = get_instance_parameters(&deps.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let committee = committee_pubkeys(deps, instance_id).await?;
    let pub_nonces = get_committee_pub_nonces_for_instance(&deps.local_db, instance_id).await?;
    if pub_nonces.len() < committee.len() {
        return Ok(None);
    }
    let ordered = order_committee_values(&committee, pub_nonces, "pegin committee pub nonces")?;
    let agg_nonce = nonce_aggregation(&ordered);
    let consensus_hash = pegin_confirm_nonce_consensus_hash(&parameters, &committee, &ordered)?;
    Ok(Some(NonceConsensus { parameters, committee, agg_nonce, consensus_hash }))
}

/// Every member signed the same ordered nonce set (the consensus barrier).
async fn votes_complete(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
    consensus: &NonceConsensus,
) -> Result<bool> {
    let votes = get_committee_agg_nonce_consensus_for_instance(&deps.local_db, instance_id).await?;
    if votes.len() < consensus.committee.len() {
        return Ok(false);
    }
    let ordered = order_committee_values(
        &consensus.committee,
        votes.into_iter().map(|(pubkey, hash, signature)| (pubkey, (hash, signature))).collect(),
        "PeginConfirm agg nonce consensus",
    )?;
    for (committee_pubkey, (received_hash, signature)) in consensus.committee.iter().zip(ordered) {
        if received_hash != consensus.consensus_hash {
            return invalid(format!(
                "committee PeginConfirm nonce consensus differs for instance {instance_id} and committee {committee_pubkey}"
            ));
        }
        SECP256K1
            .verify_schnorr(
                &signature,
                &SecpMessage::from_digest(consensus.consensus_hash),
                &XOnlyPublicKey::from(*committee_pubkey),
            )
            .map_err(|error| {
                SpecialError::InvalidPeginData(format!(
                    "invalid PeginConfirm nonce consensus signature for instance {instance_id} and committee {committee_pubkey}: {error}"
                ))
            })?;
    }
    Ok(true)
}

async fn nonces_complete(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<bool> {
    let committee = committee_pubkeys(deps, instance_id).await?.len();
    let nonces = get_committee_pub_nonces_for_instance(&deps.local_db, instance_id).await?.len();
    Ok(committee > 0 && nonces >= committee)
}

async fn partial_sigs_complete(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<bool> {
    let committee = committee_pubkeys(deps, instance_id).await?.len();
    let sigs = get_committee_partial_sigs_for_instance(&deps.local_db, instance_id).await?.len();
    Ok(committee > 0 && sigs >= committee)
}

/// The relayer aggregates and broadcasts once the last partial signature is in.
fn then_broadcast(deps: &InstanceJobDeps, plan: &mut InstancePlan) {
    if deps.relayer {
        plan.then(JOB_BROADCAST_PEGIN_CONFIRM, Vec::new(), None);
    }
}

/// Start or resume PeginConfirm after enough graphs are endorsed.
/// Persist the deterministic nonce before scheduling its delivery.
async fn start_pegin_confirm(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Step> {
    if deps.actor != Actor::Committee {
        return Step::ignore("not a committee node");
    }
    if let Some(status) = instance_status(deps, instance_id).await?
        && confirm_round_over(status)
    {
        return Step::ignore(format!("instance is {status}; round over"));
    }
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    if !has_required_presigned_graphs(&deps.local_db, instance_id).await? {
        return Step::ignore("not enough finalized graphs for the PeginConfirm round");
    }
    let parameters = get_instance_parameters(&deps.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let local_pubkey: PublicKey = instance_keypair.public_key().into();
    let (_, derived_nonce, nonce_sig) =
        committee_master_key.nonce_for_instance_job_with_keypair(&parameters, instance_keypair)?;
    match get_committee_pub_nonce_for_instance(&deps.local_db, instance_id, &local_pubkey).await? {
        Some(stored) => {
            if stored != derived_nonce {
                return invalid(format!(
                    "stored PeginConfirm nonce differs from the deterministic nonce for {instance_id}"
                ));
            }
        }
        None => {
            if let Some(reason) = gate_closed(deps, instance_id).await? {
                return Step::ignore(format!("signing gate closed: {reason}"));
            }
            if get_committee_partial_sig_for_instance(&deps.local_db, instance_id, &local_pubkey)
                .await?
                .is_some()
            {
                return Step::ignore("local PeginConfirm partial signature already exists");
            }
            store_committee_pub_nonce_for_instance(
                &deps.local_db,
                instance_id,
                local_pubkey,
                derived_nonce.clone(),
            )
            .await?;
        }
    }
    let mut plan = InstancePlan::default();
    plan.send(
        round_message(
            instance_id,
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: local_pubkey,
                pub_nonce: derived_nonce,
                nonce_sig,
            }),
        )
        .await?,
    );
    if nonces_complete(deps, instance_id).await? {
        plan.then(JOB_PEGIN_CONFIRM_VOTE, Vec::new(), None);
    }
    Step::done(plan)
}

async fn ingest_pegin_confirm_nonce(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
        instance_id: message_instance_id,
        committee_pubkey,
        pub_nonce,
        nonce_sig,
    }) = message.content
    else {
        return invalid("not a PeginConfirmNonce message");
    };
    if message_instance_id != instance_id || inbound.instance_id != instance_id {
        return invalid("PeginConfirmNonce identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    if !verify_public_nonce(&nonce_sig, &pub_nonce, &XOnlyPublicKey::from(committee_pubkey)) {
        return invalid(format!("invalid pub_nonce or nonce_sig from {committee_pubkey}"));
    }
    store_committee_pub_nonce_for_instance(
        &deps.local_db,
        instance_id,
        committee_pubkey,
        pub_nonce,
    )
    .await?;
    let mut plan = InstancePlan::default();
    if nonces_complete(deps, instance_id).await? {
        plan.then(JOB_PEGIN_CONFIRM_VOTE, Vec::new(), None);
    }
    Step::done(plan)
}

/// Sign the agreed nonce transcript once every nonce is in.
async fn pegin_confirm_vote(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Step> {
    if let Some(status) = instance_status(deps, instance_id).await?
        && confirm_round_over(status)
    {
        return Step::ignore(format!("instance is {status}; round over"));
    }
    let Some(consensus) = nonce_consensus(deps, instance_id).await? else {
        return Step::ignore("waiting for committee public nonces");
    };
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_pubkey: PublicKey = instance_keypair.public_key().into();
    let votes = get_committee_agg_nonce_consensus_for_instance(&deps.local_db, instance_id).await?;
    let local_vote = votes.iter().find(|(pubkey, _, _)| *pubkey == local_pubkey);
    if let Some((_, stored_hash, _)) = local_vote
        && *stored_hash != consensus.consensus_hash
    {
        return invalid(format!("local PeginConfirm nonce consensus differs for {instance_id}"));
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
            store_committee_agg_nonce_consensus_for_instance(
                &deps.local_db,
                instance_id,
                local_pubkey,
                consensus.consensus_hash,
                signature,
            )
            .await?;
            signature
        }
    };
    let mut plan = InstancePlan::default();
    plan.send(
        round_message(
            instance_id,
            GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
                instance_id,
                committee_pubkey: local_pubkey,
                consensus_hash: consensus.consensus_hash,
                signature,
            }),
        )
        .await?,
    );
    if votes_complete(deps, instance_id, &consensus).await? {
        plan.then(JOB_PEGIN_CONFIRM_SIGN, Vec::new(), None);
    }
    Step::done(plan)
}

async fn ingest_pegin_confirm_vote(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
        instance_id: message_instance_id,
        committee_pubkey,
        consensus_hash: received_hash,
        signature,
    }) = message.content
    else {
        return invalid("not a PeginConfirmNonceConsensus message");
    };
    if message_instance_id != instance_id || inbound.instance_id != instance_id {
        return invalid("PeginConfirmNonceConsensus identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    let Some(consensus) = nonce_consensus(deps, instance_id).await? else {
        return Step::retry(
            "waiting for committee public nonces before validating PeginConfirm nonce consensus",
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
    store_committee_agg_nonce_consensus_for_instance(
        &deps.local_db,
        instance_id,
        committee_pubkey,
        received_hash,
        signature,
    )
    .await?;
    let mut plan = InstancePlan::default();
    if votes_complete(deps, instance_id, &consensus).await? {
        plan.then(JOB_PEGIN_CONFIRM_SIGN, Vec::new(), None);
    }
    Step::done(plan)
}

/// The committee's partial signature over the Peg-In-Confirm, with the EVM
/// endorsement the relayer's `postPeginData` needs. Authorization is written
/// before signing: the deterministic nonce signs exactly one transcript.
async fn pegin_confirm_sign(deps: &InstanceJobDeps, instance_id: Uuid) -> Result<Step> {
    if let Some(status) = instance_status(deps, instance_id).await?
        && confirm_round_over(status)
    {
        return Step::ignore(format!("instance is {status}; round over"));
    }
    let Some(consensus) = nonce_consensus(deps, instance_id).await? else {
        return Step::ignore("waiting for committee public nonces");
    };
    if !votes_complete(deps, instance_id, &consensus).await? {
        return Step::ignore("waiting for agg nonce consensus");
    }
    let Some(instance_keypair) = local_member(deps, instance_id).await? else {
        return Step::ignore("not in this instance's committee");
    };
    let local_pubkey: PublicKey = instance_keypair.public_key().into();
    let pegin_txid = consensus.parameters.build_pegin_tx()?.1.tx().compute_txid();
    let (partial_sig, endorse_sig) = match get_committee_partial_sig_for_instance(
        &deps.local_db,
        instance_id,
        &local_pubkey,
    )
    .await?
    {
        Some(stored) => {
            // Reuse the stored partial signature and generate a missing EVM endorsement.
            let stored_endorse_sig =
                get_committee_endorse_sigs_for_pegin(&deps.local_db, instance_id)
                    .await?
                    .into_iter()
                    .find(|(pubkey, _)| *pubkey == local_pubkey)
                    .map(|(_, endorse_sig)| endorse_sig);
            let endorse_sig = match stored_endorse_sig {
                Some(endorse_sig) => endorse_sig,
                None => {
                    let endorse_sig = endorse_pegin(&deps.goat_client, instance_id, &pegin_txid)
                        .await?
                        .as_bytes()
                        .to_vec();
                    store_committee_endorse_sig_for_pegin(
                        &deps.local_db,
                        instance_id,
                        local_pubkey,
                        endorse_sig.clone(),
                    )
                    .await?;
                    endorse_sig
                }
            };
            (stored, endorse_sig)
        }
        None => {
            if let Some(reason) = gate_closed(deps, instance_id).await? {
                return Step::ignore(format!("signing gate closed: {reason}"));
            }
            let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
            let (sec_nonce, pub_nonce, _) = committee_master_key
                .nonce_for_instance_job_with_keypair(&consensus.parameters, instance_keypair)?;
            let nonce_id = signing_nonce_id("pegin-confirm", &pub_nonce.serialize());
            let transcript = hex::encode(consensus.consensus_hash);
            let authorization = deps
                .local_db
                .acquire()
                .await?
                .authorize_signing(
                    "instance",
                    &instance_id.to_string(),
                    &nonce_id,
                    &transcript,
                    current_time_secs(),
                )
                .await?;
            if let SigningAuthorization::Conflict { existing_digest } = authorization {
                return invalid(format!(
                    "PeginConfirm nonce for {instance_id} is already authorized for transcript {existing_digest}; refusing {transcript}"
                ));
            }
            let mut pegin_confirm = consensus.parameters.build_pegin_tx()?.1;
            let committee_context = consensus.parameters.get_committee_context(instance_keypair)?;
            let partial_sig = pegin_confirm
                .sign_input_0_musig2(&committee_context, &sec_nonce, &consensus.agg_nonce)
                .map_err(|error| {
                    anyhow!("Failed to sign PeginConfirm for {instance_id}: {error}")
                })?;
            let endorse_sig = endorse_pegin(&deps.goat_client, instance_id, &pegin_txid)
                .await?
                .as_bytes()
                .to_vec();
            store_committee_partial_sig_for_instance(
                &deps.local_db,
                instance_id,
                local_pubkey,
                partial_sig,
            )
            .await?;
            store_committee_endorse_sig_for_pegin(
                &deps.local_db,
                instance_id,
                local_pubkey,
                endorse_sig.clone(),
            )
            .await?;
            (partial_sig, endorse_sig)
        }
    };
    let mut plan = InstancePlan::default();
    plan.send(
        round_message(
            instance_id,
            GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: local_pubkey,
                partial_sig,
                endorse_sig,
            }),
        )
        .await?,
    );
    if partial_sigs_complete(deps, instance_id).await? {
        then_broadcast(deps, &mut plan);
    }
    Step::done(plan)
}

async fn ingest_pegin_confirm_partial_sig(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    let (inbound, message) = decode_inbound(params).await?;
    let GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
        instance_id: message_instance_id,
        committee_pubkey,
        partial_sig,
        endorse_sig,
    }) = message.content
    else {
        return invalid("not a PeginConfirmPartialSig message");
    };
    if message_instance_id != instance_id || inbound.instance_id != instance_id {
        return invalid("PeginConfirmPartialSig identity mismatch");
    }
    ensure_committee_sender(deps, &inbound, &committee_pubkey).await?;
    let committee = committee_pubkeys(deps, instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_instance(&deps.local_db, instance_id).await?;
    if pub_nonces_unchecked.len() != committee.len() {
        return Step::retry("waiting for committee public nonces", 30);
    }
    let Some(signer_pub_nonce) = pub_nonces_unchecked
        .iter()
        .find(|(pubkey, _)| *pubkey == committee_pubkey)
        .map(|(_, pub_nonce)| pub_nonce.clone())
    else {
        return invalid(format!("missing signer pub nonce for {committee_pubkey}"));
    };
    let Some(consensus) = nonce_consensus(deps, instance_id).await? else {
        bail!("committee public nonces changed while a partial signature was verified");
    };
    if !votes_complete(deps, instance_id, &consensus).await? {
        return Step::retry("waiting for committee PeginConfirm agg nonce consensus", 30);
    }
    if let Err(error) = verify_pegin_confirm_partial_sig(
        &consensus.parameters,
        &committee,
        &committee_pubkey,
        &signer_pub_nonce,
        &consensus.agg_nonce,
        partial_sig,
    ) {
        return invalid(format!("invalid partial signature from {committee_pubkey}: {error}"));
    }
    let pegin_txid = consensus.parameters.build_pegin_tx()?.1.tx().compute_txid();
    match verify_pegin_endorsement(
        &deps.goat_client,
        instance_id,
        &committee_pubkey,
        &pegin_txid,
        &endorse_sig,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return invalid(format!("invalid endorsement signature from {committee_pubkey}"));
        }
        Err(error) => {
            return Step::retry(
                format!("failed to verify committee endorsement signature: {error}"),
                30,
            );
        }
    }
    store_committee_partial_sig_for_instance(
        &deps.local_db,
        instance_id,
        committee_pubkey,
        partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        &deps.local_db,
        instance_id,
        committee_pubkey,
        endorse_sig,
    )
    .await?;
    let mut plan = InstancePlan::default();
    if partial_sigs_complete(deps, instance_id).await? {
        then_broadcast(deps, &mut plan);
    }
    Step::done(plan)
}

/// The relayer broadcasts Peg-In-Confirm only before T0 and while no Peg-In-Cancel is
/// confirmed.
async fn pegin_confirm_broadcast_blocked(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
) -> Result<Option<String>> {
    let instance = deps.local_db.acquire().await?.find_instance(&instance_id).await?;
    let Some(instance) = instance else {
        return Ok(Some("instance not found".to_string()));
    };
    if let Some(reason) = gate_closed(deps, instance_id).await? {
        return Ok(Some(reason));
    }
    if let Some(cancel_txid) = instance.pegin_cancel_txid
        && let Some(cancel_tx) = deps.btc_client.get_tx_info(&cancel_txid.0).await?
        && cancel_tx.status.confirmed
    {
        return Ok(Some(format!("Peg-In-Cancel {} is confirmed", cancel_txid.0)));
    }
    Ok(None)
}

/// Aggregate the committee's partial signatures and broadcast the
/// Peg-In-Confirm. Re-run per block while the transaction is not visible
/// (the apply schedules it from the Bitcoin snapshot, with the snapshot's
/// height as params), so a failed attempt retries only until the next
/// block's job takes over.
async fn broadcast_pegin_confirm(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
    params: &[u8],
) -> Result<Step> {
    if !deps.relayer {
        return Step::ignore("not a relayer");
    }
    // The first attempt (from the signatures) carries no height.
    let scanned_height: Option<i64> = params.try_into().ok().map(i64::from_le_bytes);
    let parameters = get_instance_parameters(&deps.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let mut pegin_confirm = parameters.build_pegin_tx()?.1;
    let pegin_txid = pegin_confirm.tx().compute_txid();
    if deps.btc_client.get_tx(&pegin_txid).await?.is_some() {
        return Step::ignore(format!("Peg-In-Confirm {pegin_txid} is already visible"));
    }
    if let Some(reason) = pegin_confirm_broadcast_blocked(deps, instance_id).await? {
        info!(event = "signing_gate", instance_id = %instance_id, reason = %reason, "not broadcasting Peg-In-Confirm");
        return Step::ignore(reason);
    }
    let committee = committee_pubkeys(deps, instance_id).await?;
    let pub_nonces = get_committee_pub_nonces_for_instance(&deps.local_db, instance_id).await?;
    let partial_sigs = get_committee_partial_sigs_for_instance(&deps.local_db, instance_id).await?;
    if pub_nonces.len() != committee.len() || partial_sigs.len() != committee.len() {
        return Step::ignore(format!(
            "{} of {} nonces and {} of {} partial signatures",
            pub_nonces.len(),
            committee.len(),
            partial_sigs.len(),
            committee.len()
        ));
    }
    let pub_nonces = order_committee_values(&committee, pub_nonces, "pegin committee pub nonces")?;
    let partial_sigs =
        order_committee_values(&committee, partial_sigs, "pegin committee partial sigs")?;
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let context = parameters.get_base_context();
    let full_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
        .map_err(|error| {
            anyhow!("Failed to aggregate PeginConfirm signatures for {instance_id}: {error}")
        })?;
    let connector_z = parameters.connector_z();
    pegin_confirm.push_input_0_signature(&connector_z, full_sig);
    let result = broadcast_tx(&deps.btc_client, pegin_confirm.tx()).await;
    deps.metrics_state.record_pegin_confirm(result.is_ok());
    match result {
        Ok(()) => {
            info!(event = "pegin_confirm_broadcast", instance_id = %instance_id, txid = %pegin_txid, "Peg-In-Confirm broadcast");
            Step::done(InstancePlan::noted(format!("broadcast {pegin_txid}")))
        }
        Err(error) => {
            if let Some(scanned_height) = scanned_height
                && i64::from(deps.btc_client.get_height().await?) > scanned_height
            {
                return Step::ignore(format!(
                    "broadcast Peg-In-Confirm {pegin_txid} failed ({error:#}); the next block's attempt takes over"
                ));
            }
            Step::retry(format!("broadcast Peg-In-Confirm {pegin_txid}: {error:#}"), 60)
        }
    }
}

// ------------------------------------------------------------- post pegin

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostOutcome {
    /// Pegin data is on Goat.
    Done,
    /// A precondition is not met yet; retry after about one block.
    Waiting(String),
    /// The gateway refuses the post for good.
    Rejected(String),
}

/// The gateway reverts these for good; everything else is retried.
fn is_permanent_post_rejection(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}");
    ["not a pending pegin request", "pegin amount mismatch", "only committee member can call"]
        .iter()
        .any(|needle| message.contains(needle))
}

/// Submit pegin data after Confirm is confirmed, all committee endorsements are
/// present and Goat SPV covers it. Graph publishing uses separate Graph jobs.
pub async fn post_pegin_data(
    deps: &InstanceJobDeps,
    instance_id: Uuid,
) -> anyhow::Result<PostOutcome> {
    if !deps.relayer {
        warn!(event = "instance_post", instance_id = %instance_id, outcome = "not_relayer", "post job on a node that is not a relayer");
        return Ok(PostOutcome::Done);
    }
    let goat_client = deps.goat_client.as_ref();
    let btc_client = deps.btc_client.as_ref();
    let committee_pubkeys = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    match pegin_data.status {
        PeginStatus::None => {
            return Ok(PostOutcome::Rejected("not a pending pegin request on Goat".to_string()));
        }
        PeginStatus::Pending => {
            let instance_params = get_instance_parameters(&deps.local_db, instance_id)
                .await?
                .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
            let pegin_confirm = instance_params.build_pegin_tx()?.1;
            let pegin_txid = pegin_confirm.tx().compute_txid();
            let Some(pegin_tx) = btc_client.get_tx(&pegin_txid).await? else {
                return Ok(PostOutcome::Waiting(format!(
                    "Peg-In-Confirm {pegin_txid} is not available from the Bitcoin backend"
                )));
            };
            let endorse_sigs = get_committee_endorse_sigs_for_pegin(&deps.local_db, instance_id)
                .await?
                .into_iter()
                .map(|(_, endorse_sig)| endorse_sig)
                .collect::<Vec<_>>();
            if endorse_sigs.len() != committee_pubkeys.len() {
                return Ok(PostOutcome::Waiting(format!(
                    "{} of {} committee endorsements of the Peg-In-Confirm",
                    endorse_sigs.len(),
                    committee_pubkeys.len()
                )));
            }
            let Some(pegin_height) = btc_client.get_tx_status(&pegin_txid).await?.block_height
            else {
                return Ok(PostOutcome::Waiting(format!(
                    "Peg-In-Confirm {pegin_txid} is not confirmed on Bitcoin"
                )));
            };
            let spv_height = goat_client.btc_spv_latest_height().await?;
            if spv_height < u64::from(pegin_height) {
                return Ok(PostOutcome::Waiting(format!(
                    "Goat SPV at {spv_height}, Peg-In-Confirm block {pegin_height}"
                )));
            }
            let result = goat_client
                .gateway_post_pegin_data(btc_client, &instance_id, &pegin_tx, &endorse_sigs)
                .await;
            deps.metrics_state.record_pegin_post(result.is_ok());
            if let Err(error) = result {
                if is_permanent_post_rejection(&error) {
                    return Ok(PostOutcome::Rejected(format!("{error:#}")));
                }
                return Err(error);
            }
            info!(event = "instance_post", instance_id = %instance_id, outcome = "pegin_posted", "postPeginData sent");
        }
        _ => {
            // Already posted.
        }
    }
    Ok(PostOutcome::Done)
}

struct PostPeginDataRunner {
    deps: Arc<InstanceJobDeps>,
}

#[async_trait]
impl JobRunner for PostPeginDataRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let instance_id = match job_instance_id(&ctx) {
            Ok(instance_id) => instance_id,
            Err(outcome) => return outcome,
        };
        match post_pegin_data(&self.deps, instance_id).await {
            Ok(PostOutcome::Done) => JobOutcome::Done(b"posted".to_vec()),
            Ok(PostOutcome::Waiting(reason)) => JobOutcome::Transient {
                error: reason,
                retry_after_secs: Some(avg_block_time_secs(self.deps.btc_client.network()) as i64),
            },
            Ok(PostOutcome::Rejected(reason)) => JobOutcome::Failed(reason),
            Err(error) => {
                JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
            }
        }
    }
}

// ------------------------------------------------------------- key delete

struct DeleteInstanceKeyRunner;

fn key_delete_done(deleted: bool, detail: impl Into<String>) -> JobOutcome {
    let result = KeyDeleteResult { deleted, detail: detail.into() };
    JobOutcome::Done(serde_json::to_vec(&result).expect("KeyDeleteResult serializes"))
}

#[async_trait]
impl JobRunner for DeleteInstanceKeyRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let instance_id = match job_instance_id(&ctx) {
            Ok(instance_id) => instance_id,
            Err(outcome) => return outcome,
        };
        if !is_enable_committee_instance_key_delete() {
            return key_delete_done(false, "deletion disabled");
        }
        let envelope_path = committee_instance_keys_envelope_path(instance_id);
        if !envelope_path.exists() {
            return key_delete_done(true, "envelope absent");
        }
        let committee_master_key = match get_bitvm_key() {
            Ok(key) => CommitteeMasterKey::new(key),
            Err(error) => {
                return JobOutcome::Transient {
                    error: format!("load committee master key: {error:#}"),
                    retry_after_secs: None,
                };
            }
        };
        match committee_master_key.delete_instance_keypair_envelope(instance_id, &envelope_path) {
            Ok(()) => {
                info!(
                    event = "instance_key_delete",
                    instance_id = %instance_id,
                    path = %envelope_path.display(),
                    "deleted committee instance key envelope"
                );
                key_delete_done(true, envelope_path.display().to_string())
            }
            Err(error) => JobOutcome::Failed(format!(
                "delete envelope {}: {error:#}",
                envelope_path.display()
            )),
        }
    }
}
