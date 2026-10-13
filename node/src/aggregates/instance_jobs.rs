//! Job runners of the Instance aggregate (docs/node-protocol.md §10.6): the
//! relayer's Goat post and the committee's instance key deletion. Both check
//! the external state before acting and are safe to re-run.

use super::instance::{
    INSTANCE_KIND, JOB_DELETE_INSTANCE_KEY, JOB_POST_PEGIN_DATA, KeyDeleteResult,
};
use crate::env::{get_bitvm_key, is_enable_committee_instance_key_delete, is_relayer};
use crate::metrics_service::MetricsState;
use crate::utils::{
    avg_block_time_secs, build_graph_data, committee_instance_keys_envelope_path,
    get_committee_endorse_sigs_for_pegin, get_committee_endorsements_for_graph, get_graph,
    get_graph_ids_for_instance, get_instance_parameters,
};
use anyhow::anyhow;
use async_trait::async_trait;
use bitvm_lib::keys::CommitteeMasterKey;
use bitvm_lib::types::BitvmGcGraph;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, PeginStatus};
use engine::{EngineBuilder, JobContext, JobOutcome, JobRunner};
use goat::transactions::pre_signed::PreSignedTransaction;
use std::sync::Arc;
use store::localdb::LocalDB;
use tracing::{info, warn};
use uuid::Uuid;

pub struct InstanceJobDeps {
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    pub metrics_state: MetricsState,
}

pub fn register_instance_jobs(builder: EngineBuilder, deps: Arc<InstanceJobDeps>) -> EngineBuilder {
    builder
        .job_runner(INSTANCE_KIND, JOB_POST_PEGIN_DATA, Arc::new(PostPeginDataRunner { deps }))
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
    /// Pegin data and every endorsed graph are on Goat.
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

/// `postPeginData` once the Peg-In-Confirm is confirmed, endorsed by every
/// committee member and covered by the Goat SPV, then `postGraphData` for
/// every endorsed graph not yet on Goat. Moved from the legacy `PostReady`
/// handler; the Graph aggregate takes over graph posting in step 3.
pub async fn post_pegin_and_graph_data(
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

    let mut missing_endorsements = Vec::new();
    for graph_id in get_graph_ids_for_instance(&deps.local_db, instance_id).await? {
        let graph_data = goat_client.gateway_get_graph_data(&graph_id).await?;
        if graph_data.operator_pubkey != [0u8; 32] {
            continue;
        }
        let endorsement_sigs =
            get_committee_endorsements_for_graph(&deps.local_db, instance_id, graph_id)
                .await?
                .into_iter()
                .map(|(_, _, sig)| sig)
                .collect::<Vec<_>>();
        if endorsement_sigs.len() != committee_pubkeys.len() {
            missing_endorsements.push(graph_id);
            continue;
        }
        let graph = get_graph(&deps.local_db, instance_id, graph_id)
            .await?
            .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
        let graph = BitvmGcGraph::from_simplified(&graph)?;
        let graph_data = build_graph_data(&graph)?;
        goat_client
            .gateway_post_graph_data(&instance_id, &graph_id, &graph_data, &endorsement_sigs)
            .await?;
        info!(event = "instance_post", instance_id = %instance_id, graph_id = %graph_id, outcome = "graph_posted", "postGraphData sent");
    }
    if !missing_endorsements.is_empty() {
        return Ok(PostOutcome::Waiting(format!(
            "waiting for committee endorsements of graphs {missing_endorsements:?}"
        )));
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
        match post_pegin_and_graph_data(&self.deps, instance_id).await {
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
