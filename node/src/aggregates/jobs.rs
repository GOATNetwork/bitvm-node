//! What the Instance and Graph jobs share: their handles, the step a job
//! returns and the lookups every round makes.

use super::common::InboundMessage;
use super::instance::{SigningGate, signing_gate};
use crate::env::get_bitvm_key;
use crate::messages::GOATMessage;
use crate::metrics_service::MetricsState;
use crate::middleware::publisher::NetworkPublisher;
use crate::utils::{CommitteeMembership, local_committee_membership, validate_committee};
use anyhow::{Context, Result};
use bitcoin::PublicKey;
use bitcoin::key::Keypair;
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use bitvm_lib::keys::OperatorMasterKey;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::http_client::async_client::HttpAsyncClient;
use engine::{JobContext, JobOutcome};
use libp2p::PeerId;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use store::InstanceBridgeInStatus;
use store::localdb::LocalDB;
use tracing::debug;
use uuid::Uuid;

/// The handles a job runs with.
pub struct JobDeps {
    pub actor: Actor,
    pub relayer: bool,
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    /// Proof builder requests of the peg-out jobs.
    pub http_client: Arc<HttpAsyncClient>,
    pub soldering_builder: Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: MetricsState,
    pub publisher: NetworkPublisher,
}

/// What a job decided, encoded as its result for the apply.
pub trait Plan: Serialize {
    /// A plan that only notes why nothing is done.
    fn noted(note: impl Into<String>) -> Self;
}

/// What one step decided.
pub enum Step<P> {
    Plan(Box<P>),
    Retry { reason: String, after_secs: i64 },
}

impl<P: Plan> Step<P> {
    pub fn done(plan: P) -> Result<Self> {
        Ok(Step::Plan(Box::new(plan)))
    }

    pub fn ignore(note: impl Into<String>) -> Result<Self> {
        Self::done(P::noted(note))
    }

    pub fn retry(reason: impl Into<String>, after_secs: i64) -> Result<Self> {
        Ok(Step::Retry { reason: reason.into(), after_secs })
    }

    pub fn into_outcome(self) -> JobOutcome {
        match self {
            Step::Plan(plan) => plan_outcome(&*plan),
            Step::Retry { reason, after_secs } => {
                JobOutcome::Transient { error: reason, retry_after_secs: Some(after_secs) }
            }
        }
    }
}

/// The outcome that hands a plan to the apply.
pub fn plan_outcome(plan: &impl Serialize) -> JobOutcome {
    match bincode::serialize(plan) {
        Ok(bytes) => JobOutcome::Done(bytes),
        Err(error) => JobOutcome::Failed(format!("encode plan: {error}")),
    }
}

/// Consecutive runs a contract revert gets before it counts as a rejection.
/// A load-balanced or lagging Goat node can answer from an older state. Every
/// Goat call reads the chain state first, so a call that another relayer made
/// meanwhile ends the job on the next run.
pub(super) const CONTRACT_REVERT_RUNS: u32 = 5;
const CONTRACT_REVERT_RETRY_SECS: i64 = 60;
const CONTRACT_REVERT_PREFIX: &str = "contract revert ";

/// The retry for a contract revert that has runs left, `None` for any other
/// error or once the runs are used up. The count lives in the job's last
/// error, so any other failure in between starts it again.
pub(super) fn retry_contract_revert(
    error: &anyhow::Error,
    last_error: Option<&str>,
) -> Option<JobOutcome> {
    if !crate::error::is_contract_revert(error) {
        return None;
    }
    let previous = last_error
        .and_then(|last| last.strip_prefix(CONTRACT_REVERT_PREFIX))
        .and_then(|rest| rest.split_once(" of "))
        .and_then(|(run, _)| run.parse::<u32>().ok())
        .unwrap_or(0);
    let run = previous + 1;
    (run < CONTRACT_REVERT_RUNS).then(|| JobOutcome::Transient {
        error: format!("{CONTRACT_REVERT_PREFIX}{run} of {CONTRACT_REVERT_RUNS}: {error:#}"),
        retry_after_secs: Some(CONTRACT_REVERT_RETRY_SECS),
    })
}

/// The aggregate id of a job as a UUID; `what` names the aggregate in the
/// failure ("a graph", "an instance").
pub(super) fn aggregate_uuid(ctx: &JobContext, what: &str) -> Result<Uuid, JobOutcome> {
    Uuid::parse_str(&ctx.job.aggregate_id).map_err(|error| {
        JobOutcome::Failed(format!(
            "job aggregate id {} is not {what} id: {error}",
            ctx.job.aggregate_id
        ))
    })
}

// ------------------------------------------------------------------ lookups

pub(super) async fn decode_inbound(params: &[u8]) -> Result<(InboundMessage, GOATMessage)> {
    let inbound = InboundMessage::decode(params).context("decode inbound message")?;
    let message = GOATMessage::deserialize_message(&inbound.message).await?;
    Ok((inbound, message))
}

pub(super) fn author_peer(inbound: &InboundMessage) -> Result<PeerId> {
    PeerId::from_str(&inbound.author).context("decode author peer id")
}

pub(super) async fn instance_status(
    deps: &JobDeps,
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
pub(super) async fn local_member(deps: &JobDeps, instance_id: Uuid) -> Result<Option<Keypair>> {
    match local_committee_membership(&deps.goat_client, instance_id).await? {
        CommitteeMembership::Member(keypair) => Ok(Some(keypair)),
        CommitteeMembership::NotMember(reason) => {
            debug!(event = "job", instance_id = %instance_id, reason, "not in this instance's committee");
            Ok(None)
        }
    }
}

pub(super) async fn committee_pubkeys(deps: &JobDeps, instance_id: Uuid) -> Result<Vec<PublicKey>> {
    deps.goat_client.gateway_get_committee_pubkeys(&instance_id).await
}

/// The T0 gate for the committee's signing steps: `None` when open.
pub(super) async fn gate_closed(deps: &JobDeps, instance_id: Uuid) -> Result<Option<String>> {
    Ok(match signing_gate(&deps.local_db, &deps.btc_client, instance_id).await? {
        SigningGate::Open => None,
        SigningGate::Closed(reason) => Some(reason),
    })
}

/// The local operator master key and its public key.
pub(super) fn local_operator() -> Result<(OperatorMasterKey, PublicKey)> {
    let master = OperatorMasterKey::new(get_bitvm_key()?);
    let pubkey = master.master_keypair().public_key().into();
    Ok((master, pubkey))
}

pub(super) fn signing_nonce_id(label: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The committee value really comes from the member it names (pubkey and
/// peer id bound on Goat).
pub(super) async fn ensure_committee_sender(
    deps: &JobDeps,
    inbound: &InboundMessage,
    committee_pubkey: &PublicKey,
) -> Result<()> {
    let peer = author_peer(inbound)?;
    validate_committee(&deps.goat_client, &peer, inbound.instance_id, committee_pubkey).await
}

#[cfg(test)]
mod contract_revert_tests {
    use super::*;

    fn revert() -> anyhow::Error {
        // A Goat node's JSON-RPC answer to a reverting eth_call or estimateGas.
        let payload = serde_json::from_value(serde_json::json!({
            "code": 3,
            "message": "execution reverted: PeginNotPending",
        }))
        .unwrap();
        let error: alloy::transports::TransportError =
            alloy::transports::RpcError::ErrorResp(payload);
        anyhow::Error::new(error).context("postGraphData")
    }

    fn retried(outcome: Option<JobOutcome>) -> Option<String> {
        match outcome {
            Some(JobOutcome::Transient { error, retry_after_secs }) => {
                assert_eq!(retry_after_secs, Some(CONTRACT_REVERT_RETRY_SECS));
                Some(error)
            }
            None => None,
            Some(other) => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn a_revert_is_retried_a_few_consecutive_runs_then_left_to_the_rejection_path() {
        let mut last_error: Option<String> = None;
        for run in 1..CONTRACT_REVERT_RUNS {
            let error = retried(retry_contract_revert(&revert(), last_error.as_deref()))
                .unwrap_or_else(|| panic!("run {run} is retried"));
            assert!(error.starts_with(&format!("contract revert {run} of {CONTRACT_REVERT_RUNS}")));
            assert!(error.contains("PeginNotPending"));
            last_error = Some(error);
        }
        assert!(retry_contract_revert(&revert(), last_error.as_deref()).is_none());
    }

    #[test]
    fn another_failure_in_between_starts_the_count_again() {
        let error = retried(retry_contract_revert(&revert(), Some("Goat SPV at 10, block 12")));
        assert!(error.unwrap().starts_with("contract revert 1 of"));
    }

    #[test]
    fn other_errors_are_not_handled() {
        assert!(retry_contract_revert(&anyhow::anyhow!("connection refused"), None).is_none());
    }
}
