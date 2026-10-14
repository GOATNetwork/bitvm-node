//! Engine assembly: builder, handle for producers, and the run loop that owns
//! the workers, publisher, executor, re-check timer and housekeeping.

use crate::ack::{AckReceiver, AckRequest, AckSender};
use crate::aggregate::AggregateHandler;
use crate::clock::{Clock, SystemClock};
use crate::config::EngineConfig;
use crate::event::{AggregateRef, NewEvent};
use crate::jobs::{ExecutorDeps, JobRegistry, JobRunner, run_executor};
use crate::metrics::EngineMetrics;
use crate::outbox::{PublisherDeps, Transport, run_publisher};
use crate::wake::{EngineWake, spawn_on_thread};
use crate::worker::{WorkerDeps, run_worker};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use store::localdb::{LocalDB, StorageProcessor};
use store::{
    EngineAggregate, EngineInboxInsert, EngineInboxState, EngineOutboxAck, EnginePoison,
    EngineStateCount, EngineWaitingEvent,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

struct EngineInner {
    db: LocalDB,
    config: Arc<EngineConfig>,
    clock: Arc<dyn Clock>,
    handlers: Arc<HashMap<String, Arc<dyn AggregateHandler>>>,
    runners: Arc<JobRegistry>,
    transport: Arc<dyn Transport>,
    metrics: EngineMetrics,
    wake: EngineWake,
    ack: AckSender,
}

/// A transport that drops everything; used when no network is attached.
struct NullTransport;

#[async_trait::async_trait]
impl Transport for NullTransport {
    async fn publish(&self, _topic: &str, _payload: &[u8]) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("no transport attached to the engine"))
    }
}

pub struct EngineBuilder {
    db: LocalDB,
    config: EngineConfig,
    clock: Arc<dyn Clock>,
    handlers: HashMap<String, Arc<dyn AggregateHandler>>,
    runners: JobRegistry,
    transport: Option<Arc<dyn Transport>>,
    metrics: Option<EngineMetrics>,
}

impl EngineBuilder {
    pub fn new(db: LocalDB, config: EngineConfig) -> Self {
        Self {
            db,
            config,
            clock: Arc::new(SystemClock),
            handlers: HashMap::new(),
            runners: HashMap::new(),
            transport: None,
            metrics: None,
        }
    }

    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    pub fn handler(mut self, kind: impl Into<String>, handler: Arc<dyn AggregateHandler>) -> Self {
        self.handlers.insert(kind.into(), handler);
        self
    }

    pub fn job_runner(
        mut self,
        kind: impl Into<String>,
        action: impl Into<String>,
        runner: Arc<dyn JobRunner>,
    ) -> Self {
        self.runners.insert((kind.into(), action.into()), runner);
        self
    }

    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn metrics(mut self, metrics: EngineMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Build the engine and the receiving end of the ACK channel.
    pub fn build(self) -> (Engine, AckReceiver) {
        let (ack, ack_rx) = AckSender::channel(self.config.ack_channel_capacity);
        let wake = EngineWake::new(self.config.worker_count);
        let inner = EngineInner {
            db: self.db,
            config: Arc::new(self.config),
            clock: self.clock,
            handlers: Arc::new(self.handlers),
            runners: Arc::new(self.runners),
            transport: self.transport.unwrap_or_else(|| Arc::new(NullTransport)),
            metrics: self.metrics.unwrap_or_default(),
            wake,
            ack,
        };
        (Engine { inner: Arc::new(inner) }, ack_rx)
    }
}

pub struct Engine {
    inner: Arc<EngineInner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    Inserted,
    Duplicate { state: EngineInboxState, ack_sent: bool, rearmed: bool },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub counts: Vec<EngineStateCount>,
    /// Parked events, oldest park first.
    pub waiting: Vec<EngineWaitingEvent>,
    /// Actions held back by a panic, oldest first.
    pub poisoned: Vec<EnginePoison>,
}

/// Producer-side handle: record events, apply ACKs, wake waiters.
#[derive(Clone)]
pub struct EngineHandle {
    inner: Arc<EngineInner>,
}

impl EngineHandle {
    /// Record an event once and wake its shard. A duplicate heavy message whose
    /// material is already applied or parked is ACKed again.
    pub async fn submit(&self, event: NewEvent) -> anyhow::Result<SubmitOutcome> {
        let now = self.inner.clock.now();
        let aggregate = event.aggregate.clone();
        let kind = event.kind.clone();
        let ack = event.ack.clone();
        let inserted = {
            let mut storage = self.inner.db.acquire().await?;
            storage.insert_engine_inbox_event(&event.into_store(), now).await?
        };
        match inserted {
            EngineInboxInsert::Inserted { .. } => {
                self.inner.wake.worker_for(&aggregate);
                Ok(SubmitOutcome::Inserted)
            }
            EngineInboxInsert::Duplicate { state, ack_again, rearmed } => {
                let mut ack_sent = false;
                if ack_again && let Some(ack) = ack {
                    ack_sent = self
                        .inner
                        .ack
                        .try_send(AckRequest { peer: ack.peer, delivery_id: ack.delivery_id });
                    if !ack_sent {
                        self.inner.metrics.record_ack_dropped();
                    }
                }
                if rearmed {
                    self.inner.wake.worker_for(&aggregate);
                }
                self.inner.metrics.record_event(&kind, "duplicate");
                Ok(SubmitOutcome::Duplicate { state, ack_sent, rearmed })
            }
        }
    }

    /// Record an event inside the caller's transaction. Nothing is woken and
    /// no ACK is sent: the caller commits and then calls [`Self::wake_for`],
    /// or relies on the worker poll.
    pub async fn submit_in(
        &self,
        storage: &mut StorageProcessor<'_>,
        event: NewEvent,
    ) -> anyhow::Result<SubmitOutcome> {
        let now = self.inner.clock.now();
        let kind = event.kind.clone();
        match storage.insert_engine_inbox_event(&event.into_store(), now).await? {
            EngineInboxInsert::Inserted { .. } => Ok(SubmitOutcome::Inserted),
            EngineInboxInsert::Duplicate { state, rearmed, .. } => {
                self.inner.metrics.record_event(&kind, "duplicate");
                Ok(SubmitOutcome::Duplicate { state, ack_sent: false, rearmed })
            }
        }
    }

    /// Wake the worker owning `aggregate` (for events recorded with
    /// [`Self::submit_in`] after their transaction committed).
    pub fn wake_for(&self, aggregate: &AggregateRef) {
        self.inner.wake.worker_for(aggregate);
    }

    /// Apply an ACK received from `peer`.
    pub async fn acknowledge(
        &self,
        peer: &str,
        delivery_id: &str,
    ) -> anyhow::Result<EngineOutboxAck> {
        let now = self.inner.clock.now();
        // Read-modify-write of the row's outstanding set: the immediate
        // transaction serializes concurrent ACKs for the same row.
        let mut tx = self.inner.db.start_immediate_transaction().await?;
        let ack = tx.acknowledge_engine_outbox(peer, delivery_id, now).await?;
        tx.commit().await?;
        Ok(ack)
    }

    /// Wake events waiting on any of `refs` (for changes made outside an apply).
    pub async fn notify(&self, refs: &[String]) -> anyhow::Result<u64> {
        let now = self.inner.clock.now();
        let woken = {
            let mut storage = self.inner.db.acquire().await?;
            storage.wake_engine_inbox_waiting(refs, now).await?
        };
        if woken > 0 {
            self.inner.wake.workers_all();
        }
        Ok(woken)
    }

    pub fn wake_all(&self) {
        self.inner.wake.workers_all();
        self.inner.wake.publisher();
        self.inner.wake.executor();
    }

    /// Manual clear of one poisoned action, or of every action of the aggregate.
    /// Returns how many actions were released.
    pub async fn clear_poison(
        &self,
        aggregate: &AggregateRef,
        action: Option<&str>,
    ) -> anyhow::Result<u64> {
        let mut storage = self.inner.db.acquire().await?;
        let cleared =
            storage.clear_engine_aggregate_poison(&aggregate.kind, &aggregate.id, action).await?;
        drop(storage);
        if cleared > 0 {
            self.inner.wake.executor();
            self.inner.wake.worker_for(aggregate);
        }
        Ok(cleared)
    }

    /// Actions of `aggregate` currently poisoned.
    pub async fn poisons(&self, aggregate: &AggregateRef) -> anyhow::Result<Vec<EnginePoison>> {
        let mut storage = self.inner.db.acquire().await?;
        storage.list_engine_poisons(Some((&aggregate.kind, &aggregate.id)), 256).await
    }

    pub async fn aggregate(
        &self,
        aggregate: &AggregateRef,
    ) -> anyhow::Result<Option<EngineAggregate>> {
        let mut storage = self.inner.db.acquire().await?;
        storage.find_engine_aggregate(&aggregate.kind, &aggregate.id).await
    }

    pub async fn snapshot(&self) -> anyhow::Result<EngineSnapshot> {
        let mut storage = self.inner.db.acquire().await?;
        Ok(EngineSnapshot {
            counts: storage.engine_state_counts().await?,
            waiting: storage.list_engine_inbox_waiting(256).await?,
            poisoned: storage.list_engine_poisons(None, 256).await?,
        })
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        self.inner.clock.clone()
    }

    pub fn config(&self) -> Arc<EngineConfig> {
        self.inner.config.clone()
    }
}

impl Engine {
    pub fn handle(&self) -> EngineHandle {
        EngineHandle { inner: self.inner.clone() }
    }

    /// Run until `cancel` fires. Returns an error if a core loop stops early.
    pub async fn run(self, cancel: CancellationToken) -> anyhow::Result<()> {
        let inner = self.inner;
        startup_recovery(&inner).await?;
        let mut tasks = Vec::new();
        let mut names = Vec::new();
        let worker_deps = WorkerDeps {
            db: inner.db.clone(),
            clock: inner.clock.clone(),
            config: inner.config.clone(),
            handlers: inner.handlers.clone(),
            metrics: inner.metrics.clone(),
            ack: inner.ack.clone(),
            wake: inner.wake.clone(),
        };
        for shard in 0..inner.wake.shard_count() {
            tasks.push(spawn_on_thread(
                format!("engine-worker-{shard}"),
                inner.config.thread_stack_bytes,
                run_worker(
                    shard,
                    worker_deps.clone(),
                    inner.wake.worker_notify(shard),
                    cancel.clone(),
                ),
            ));
            names.push(format!("worker-{shard}"));
        }
        tasks.push(tokio::spawn(run_publisher(
            PublisherDeps {
                db: inner.db.clone(),
                clock: inner.clock.clone(),
                config: inner.config.clone(),
                transport: inner.transport.clone(),
                metrics: inner.metrics.clone(),
            },
            inner.wake.publisher_notify(),
            cancel.clone(),
        )));
        names.push("publisher".to_string());
        tasks.push(tokio::spawn(run_executor(
            ExecutorDeps {
                db: inner.db.clone(),
                clock: inner.clock.clone(),
                config: inner.config.clone(),
                registry: inner.runners.clone(),
                metrics: inner.metrics.clone(),
                wake: inner.wake.clone(),
            },
            inner.wake.executor_notify(),
            cancel.clone(),
        )));
        names.push("executor".to_string());
        tasks.push(tokio::spawn(run_recheck(inner.clone(), cancel.clone())));
        names.push("recheck".to_string());
        tasks.push(tokio::spawn(run_housekeeping(inner.clone(), cancel.clone())));
        names.push("housekeeping".to_string());
        info!(
            event = "engine_started",
            workers = inner.wake.shard_count(),
            handlers = inner.handlers.len(),
            runners = inner.runners.len(),
            "execution engine started"
        );

        let mut pending = tasks;
        let stopped_early = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            (result, index, remaining) = futures::future::select_all(pending.drain(..)) => {
                pending = remaining;
                Some((names[index].clone(), result))
            }
        };
        cancel.cancel();
        for task in pending {
            let _ = task.await;
        }
        match stopped_early {
            None => {
                info!(event = "engine_stopped", "execution engine stopped");
                Ok(())
            }
            Some((name, result)) => {
                let detail = match result {
                    Ok(()) => "exited".to_string(),
                    Err(error) => format!("failed: {error}"),
                };
                Err(anyhow::anyhow!("engine loop {name} stopped early: {detail}"))
            }
        }
    }
}

async fn startup_recovery(inner: &EngineInner) -> anyhow::Result<()> {
    let now = inner.clock.now();
    let mut storage = inner.db.acquire().await?;
    let rearmed = storage.rearm_engine_inbox_pending(now).await?;
    let outbox_leases = storage.reset_engine_outbox_leases().await?;
    let job_leases = storage.reset_engine_job_leases().await?;
    info!(
        event = "engine_recovery",
        rearmed_events = rearmed,
        outbox_leases,
        job_leases,
        "engine startup recovery completed"
    );
    Ok(())
}

async fn run_recheck(inner: Arc<EngineInner>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(inner.config.recheck_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {}
        }
        let now = inner.clock.now();
        match inner.db.acquire().await {
            Ok(mut storage) => {
                match storage.rearm_engine_inbox_waiting(now).await {
                    Ok(rearmed) if rearmed > 0 => {
                        inner.wake.workers_all();
                        info!(event = "engine_recheck", rearmed, "re-checking waiting events");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(event = "engine_recheck", error = %error, "re-check failed")
                    }
                }
                match storage.engine_state_counts().await {
                    Ok(counts) => {
                        for count in counts {
                            inner.metrics.set_rows(&count.table, &count.state, count.count);
                        }
                    }
                    Err(error) => {
                        warn!(event = "engine_recheck", error = %error, "row count refresh failed")
                    }
                }
            }
            Err(error) => warn!(event = "engine_recheck", error = %error, "storage unavailable"),
        }
    }
}

async fn run_housekeeping(inner: Arc<EngineInner>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(inner.config.housekeeping_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {}
        }
        let before = inner.clock.now() - inner.config.terminal_retention_secs;
        match inner.db.acquire().await {
            Ok(mut storage) => match storage.purge_engine_terminal_rows(before).await {
                Ok(purged) if purged > 0 => {
                    info!(event = "engine_housekeeping", purged, "purged terminal engine rows")
                }
                Ok(_) => {}
                Err(error) => warn!(event = "engine_housekeeping", error = %error, "purge failed"),
            },
            Err(error) => {
                warn!(event = "engine_housekeeping", error = %error, "storage unavailable")
            }
        }
    }
}
