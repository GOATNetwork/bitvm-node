//! Job runners of the Instance aggregate (docs/node-protocol.md §10.6): the
//! relayer's Goat post, the committee's PeginConfirm round start and the
//! committee's instance key deletion. All check the external state before
//! acting and are safe to re-run.

use super::graph_setup::permanent_rejection;
use super::instance::{
    INSTANCE_KIND, JOB_DELETE_INSTANCE_KEY, JOB_POST_PEGIN_DATA, JOB_START_PEGIN_CONFIRM,
    KeyDeleteResult,
};
use crate::action::GOATMessage;
use crate::env::{get_bitvm_key, get_peer_id, is_enable_committee_instance_key_delete, is_relayer};
use crate::handle::{HandlerContext, start_pegin_confirm_round};
use crate::metrics_service::MetricsState;
use crate::middleware::publisher::NetworkPublisher;
use crate::utils::{
    avg_block_time_secs, committee_instance_keys_envelope_path,
    get_committee_endorse_sigs_for_pegin, get_instance_parameters,
};
use anyhow::anyhow;
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use bitvm_lib::keys::CommitteeMasterKey;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, PeginStatus};
use client::http_client::async_client::HttpAsyncClient;
use engine::{EngineBuilder, JobContext, JobOutcome, JobRunner};
use goat::transactions::pre_signed::PreSignedTransaction;
use libp2p::PeerId;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use tracing::{info, warn};
use uuid::Uuid;

pub struct InstanceJobDeps {
    pub actor: Actor,
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    pub http_client: Arc<HttpAsyncClient>,
    pub soldering_builder: Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: MetricsState,
    pub publisher: NetworkPublisher,
}

pub fn register_instance_jobs(builder: EngineBuilder, deps: Arc<InstanceJobDeps>) -> EngineBuilder {
    builder
        .job_runner(
            INSTANCE_KIND,
            JOB_POST_PEGIN_DATA,
            Arc::new(PostPeginDataRunner { deps: deps.clone() }),
        )
        .job_runner(
            INSTANCE_KIND,
            JOB_START_PEGIN_CONFIRM,
            Arc::new(StartPeginConfirmRunner { deps }),
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
    if !is_relayer() {
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

// ------------------------------------------------------ pegin confirm round

/// Runs the legacy PeginConfirm round start under a handler context of this
/// node's own: the round's messages go through the signing-round outbox.
struct StartPeginConfirmRunner {
    deps: Arc<InstanceJobDeps>,
}

#[async_trait]
impl JobRunner for StartPeginConfirmRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let instance_id = match job_instance_id(&ctx) {
            Ok(instance_id) => instance_id,
            Err(outcome) => return outcome,
        };
        if self.deps.actor != Actor::Committee {
            return JobOutcome::Done(b"not a committee node".to_vec());
        }
        let from_peer_id = match PeerId::from_str(&get_peer_id()) {
            Ok(peer_id) => peer_id,
            Err(error) => return JobOutcome::Failed(format!("local peer id: {error}")),
        };
        let mut publisher = self.deps.publisher.clone();
        let mut handler = HandlerContext {
            swarm: &mut publisher,
            local_db: &self.deps.local_db,
            btc_client: &self.deps.btc_client,
            goat_client: &self.deps.goat_client,
            http_client: &self.deps.http_client,
            soldering_builder: &self.deps.soldering_builder,
            metrics_state: &self.deps.metrics_state,
            actor: Actor::Committee,
            from_peer_id,
            id: GOATMessage::default_message_id(),
            is_self_peer: true,
        };
        match start_pegin_confirm_round(&mut handler, instance_id).await {
            Ok(()) => JobOutcome::Done(b"started".to_vec()),
            Err(error) => match permanent_rejection(&error) {
                Some(reason) => JobOutcome::Failed(reason),
                None => {
                    JobOutcome::Transient { error: format!("{error:#}"), retry_after_secs: None }
                }
            },
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
