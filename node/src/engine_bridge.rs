//! Adapters between the execution engine (`engine` crate) and the node:
//! gossip transport for the outbox, the ACK forwarder for the return channel,
//! configuration from the environment, aggregate registration, and the
//! process-wide handle producers use to record events.

use crate::action::{GOATMessage, GOATMessageContent, GraphSetupAck, publish_to_role};
use crate::aggregates::graph::{GRAPH_KIND, GraphAggregate};
use crate::aggregates::graph_jobs::register_graph_jobs;
use crate::aggregates::instance::{INSTANCE_KIND, InstanceAggregate};
use crate::aggregates::instance_jobs::register_instance_jobs;
use crate::aggregates::jobs::JobDeps;
use crate::env;
use crate::metrics_service::{MetricsState, node_metrics_state};
use crate::middleware::publisher::{MessagePublisher, NetworkPublisher};
use crate::rpc_service::current_time_secs;
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::http_client::async_client::HttpAsyncClient;
use engine::{
    AckReceiver, Engine, EngineBuilder, EngineConfig, EngineHandle, EngineMetrics, NewEvent,
    SubmitOutcome, Transport,
};
use libp2p::gossipsub::IdentTopic;
use libp2p_metrics::Registry;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use store::localdb::{LocalDB, StorageProcessor};
use tokio_util::sync::CancellationToken;

/// Publishes outbox payloads on their gossip topic through the swarm.
pub struct GossipTransport {
    publisher: NetworkPublisher,
}

impl GossipTransport {
    pub fn new(publisher: NetworkPublisher) -> Self {
        Self { publisher }
    }
}

#[async_trait]
impl Transport for GossipTransport {
    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        crate::action::note_oversized_payload(payload, topic, "outbox");
        let mut publisher = self.publisher.clone();
        let result = publisher.publish_message(IdentTopic::new(topic), payload.to_vec()).await;
        if let Some(metrics) = node_metrics_state() {
            metrics.record_p2p_publish(result.is_ok());
        }
        result.map(|_| ())
    }
}

/// Engine settings from the environment, on top of the crate defaults.
pub fn engine_config_from_env() -> EngineConfig {
    let defaults = EngineConfig::default();
    EngineConfig {
        worker_count: env::get_engine_worker_count(defaults.worker_count),
        cpu_pool_slots: env::get_engine_cpu_pool_slots(defaults.cpu_pool_slots),
        pegout_pool_slots: env::get_engine_pegout_pool_slots(defaults.pegout_pool_slots),
        network_pool_slots: env::get_engine_network_pool_slots(defaults.network_pool_slots),
        apply_timeout: Duration::from_secs(env::get_engine_apply_timeout_secs(
            defaults.apply_timeout.as_secs(),
        )),
        recheck_interval: Duration::from_secs(env::get_engine_recheck_interval_secs(
            defaults.recheck_interval.as_secs(),
        )),
        ..defaults
    }
}

/// SQLite busy timeout for the node's database: every writer waits at least
/// as long as the engine's apply may hold the write lock, so a long apply
/// delays other writers instead of failing them.
pub fn db_busy_timeout() -> Duration {
    engine_config_from_env().apply_timeout.max(store::DEFAULT_BUSY_TIMEOUT)
}

/// Register the engine's metrics; done before the registry is shared.
pub fn register_engine_metrics(registry: &mut Registry) -> EngineMetrics {
    let metrics = EngineMetrics::new();
    metrics.register(registry);
    metrics
}

/// What the aggregates and their jobs need from the node.
pub struct EngineDeps {
    pub actor: Actor,
    pub local_peer: String,
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    pub http_client: Arc<HttpAsyncClient>,
    pub soldering_builder: Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: MetricsState,
}

/// Register Instance and Graph handlers, jobs and the network transport.
pub fn build_engine(
    publisher: NetworkPublisher,
    metrics: EngineMetrics,
    deps: EngineDeps,
) -> (Engine, AckReceiver) {
    let builder = EngineBuilder::new(deps.local_db.clone(), engine_config_from_env())
        .transport(Arc::new(GossipTransport::new(publisher.clone())))
        .metrics(metrics)
        .handler(INSTANCE_KIND, Arc::new(InstanceAggregate::from_env(deps.actor.clone())))
        .handler(
            GRAPH_KIND,
            Arc::new(
                GraphAggregate::new(deps.actor.clone(), env::is_relayer(), deps.local_peer.clone())
                    .with_local_operator(own_operator_pubkey(&deps.actor)),
            ),
        );
    let jobs = Arc::new(JobDeps {
        actor: deps.actor,
        relayer: env::is_relayer(),
        local_db: deps.local_db,
        btc_client: deps.btc_client,
        goat_client: deps.goat_client,
        http_client: deps.http_client,
        soldering_builder: deps.soldering_builder,
        metrics_state: deps.metrics_state,
        publisher,
    });
    let builder = register_instance_jobs(builder, jobs.clone());
    register_graph_jobs(builder, jobs).build()
}

/// The operator key this node withdraws with, as graphs store it.
fn own_operator_pubkey(actor: &Actor) -> Option<String> {
    if *actor != Actor::Operator {
        return None;
    }
    match env::get_node_pubkey() {
        Ok(pubkey) => Some(pubkey.to_string()),
        Err(error) => {
            tracing::warn!(error = %error, "operator key unavailable; peg-out jobs for own graphs are disabled");
            None
        }
    }
}

static ENGINE_HANDLE: OnceLock<EngineHandle> = OnceLock::new();

/// Make the running engine reachable from producers that have no handle of
/// their own (the event watcher, the admission path).
pub fn install_engine_handle(handle: EngineHandle) {
    let _ = ENGINE_HANDLE.set(handle);
}

pub fn engine_handle() -> Option<&'static EngineHandle> {
    ENGINE_HANDLE.get()
}

/// Record an event inside the caller's transaction. The worker picks it up on
/// its poll after the commit, or sooner through [`wake`].
pub async fn record_event_in(
    storage: &mut StorageProcessor<'_>,
    event: NewEvent,
) -> anyhow::Result<()> {
    match engine_handle() {
        Some(engine) => {
            engine.submit_in(storage, event).await?;
        }
        None => {
            storage.insert_engine_inbox_event(&event.into_store(), current_time_secs()).await?;
        }
    }
    Ok(())
}

/// Record an event on its own connection and wake its worker. Without an
/// engine handle (tests) the row is inserted directly and counts as new.
pub async fn submit_event(local_db: &LocalDB, event: NewEvent) -> anyhow::Result<SubmitOutcome> {
    match engine_handle() {
        Some(engine) => engine.submit(event).await,
        None => {
            let mut storage = local_db.acquire().await?;
            storage.insert_engine_inbox_event(&event.into_store(), current_time_secs()).await?;
            Ok(SubmitOutcome::Inserted)
        }
    }
}

/// Turn ACK requests from the engine into `GraphSetupAck` messages. The engine
/// only emits an ACK after the material is durably applied or parked.
pub async fn run_ack_forwarder(
    mut acks: AckReceiver,
    mut publisher: NetworkPublisher,
    cancel: CancellationToken,
) -> anyhow::Result<String> {
    loop {
        let request = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok("engine ack forwarder stopped".to_string()),
            request = acks.recv() => request,
        };
        let Some(request) = request else {
            return Ok("engine ack channel closed".to_string());
        };
        let message = GOATMessage::new(
            Actor::All,
            GOATMessageContent::GraphSetupAck(GraphSetupAck {
                delivery_id: request.delivery_id.clone(),
            }),
        );
        if let Err(error) = publish_to_role(&mut publisher, message).await {
            tracing::debug!(
                event = "engine_ack",
                outcome = "publish_failed",
                peer = %request.peer,
                error = %error,
                "ACK publish failed; the sender will resend and be ACKed again"
            );
        }
    }
}
