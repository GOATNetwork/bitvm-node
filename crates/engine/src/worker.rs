//! Aggregate workers: one per shard, single writer for every aggregate in the
//! shard. An apply runs inside one transaction; the outcome decides whether
//! the event is applied, parked, rejected, retried or poisoned.

use crate::ack::{AckRequest, AckSender};
use crate::aggregate::{AggregateHandler, ApplyContext, ApplyError, ApplyOutcome, WaitingFor};
use crate::clock::Clock;
use crate::config::EngineConfig;
use crate::effects::{Effects, JobCancel};
use crate::event::AggregateRef;
use crate::metrics::EngineMetrics;
use crate::wake::{EngineWake, panic_message};
use futures::FutureExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use store::localdb::{LocalDB, StorageProcessor};
use store::{
    EngineAggregate, EngineAggregateUpdate, EngineInboxEvent, EngineJobInsert, EngineJobState,
    NewEngineJob, NewEngineOutboxMessage,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub(crate) struct WorkerDeps {
    pub db: LocalDB,
    pub clock: Arc<dyn Clock>,
    pub config: Arc<EngineConfig>,
    pub handlers: Arc<HashMap<String, Arc<dyn AggregateHandler>>>,
    pub metrics: EngineMetrics,
    pub ack: AckSender,
    pub wake: EngineWake,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessOutcome {
    Applied,
    Waiting,
    Rejected,
    Transient,
    TimedOut,
    Poisoned,
    NoHandler,
}

impl ProcessOutcome {
    const fn label(self) -> &'static str {
        match self {
            ProcessOutcome::Applied => "applied",
            ProcessOutcome::Waiting => "waiting",
            ProcessOutcome::Rejected => "rejected",
            ProcessOutcome::Transient => "transient",
            ProcessOutcome::TimedOut => "timed_out",
            ProcessOutcome::Poisoned => "poisoned",
            ProcessOutcome::NoHandler => "no_handler",
        }
    }
}

pub(crate) async fn run_worker(
    shard: usize,
    deps: WorkerDeps,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let shard_count = deps.wake.shard_count();
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match drain_shard(shard, shard_count, &deps, &cancel).await {
            Ok(_) => {}
            Err(error) => {
                warn!(event = "engine_worker", shard, error = %error, "worker pass failed; backing off");
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(deps.config.worker_poll_interval) => {}
                }
            }
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = notify.notified() => {}
            _ = tokio::time::sleep(deps.config.worker_poll_interval) => {}
        }
    }
}

/// Apply runnable events of `shard` until none is left. Returns how many were
/// processed.
pub(crate) async fn drain_shard(
    shard: usize,
    shard_count: usize,
    deps: &WorkerDeps,
    cancel: &CancellationToken,
) -> anyhow::Result<usize> {
    let mut processed = 0;
    loop {
        if cancel.is_cancelled() {
            return Ok(processed);
        }
        let now = deps.clock.now();
        let next = {
            let mut storage = deps.db.acquire().await?;
            storage.next_runnable_engine_inbox_event(shard_count as i64, shard as i64, now).await?
        };
        let Some(event) = next else { return Ok(processed) };
        process_event(deps, event).await?;
        processed += 1;
    }
}

struct PostCommit {
    acks: Vec<store::EngineAckTarget>,
    woke: bool,
    outbox: bool,
    jobs: bool,
}

impl PostCommit {
    fn dispatch(self, deps: &WorkerDeps) {
        for ack in self.acks {
            if !deps
                .ack
                .try_send(AckRequest { peer: ack.peer.clone(), delivery_id: ack.delivery_id })
            {
                deps.metrics.record_ack_dropped();
                warn!(event = "engine_ack", outcome = "dropped", peer = %ack.peer, "ACK channel full; sender will resend");
            }
        }
        if self.woke {
            deps.wake.workers_all();
        }
        if self.outbox {
            deps.wake.publisher();
        }
        if self.jobs {
            deps.wake.executor();
        }
    }
}

pub(crate) async fn process_event(
    deps: &WorkerDeps,
    event: EngineInboxEvent,
) -> anyhow::Result<ProcessOutcome> {
    let aggregate = AggregateRef::from_event(&event);
    let kind = event.kind.clone();
    let Some(handler) = deps.handlers.get(&aggregate.kind).cloned() else {
        let now = deps.clock.now();
        let mut storage = deps.db.acquire().await?;
        storage
            .mark_engine_inbox_failed(
                &event.event_id,
                &format!("no handler for aggregate kind {}", aggregate.kind),
                now,
            )
            .await?;
        warn!(
            event = "engine_apply",
            outcome = "no_handler",
            event_id = %event.event_id,
            aggregate = %aggregate,
            kind = %kind,
            "no handler registered for this aggregate kind"
        );
        deps.metrics.record_event(&kind, ProcessOutcome::NoHandler.label());
        return Ok(ProcessOutcome::NoHandler);
    };

    let started = Instant::now();
    let now = deps.clock.now();
    // BEGIN IMMEDIATE: SQLite has one writer, so the apply takes the write lock
    // up front instead of failing with a stale snapshot at its first write.
    let mut tx = deps.db.start_immediate_transaction().await?;
    let current = tx.find_engine_aggregate(&aggregate.kind, &aggregate.id).await?;
    let (result, effects) = {
        let mut ctx = ApplyContext {
            now,
            aggregate: aggregate.clone(),
            current: current.clone(),
            storage: &mut tx,
            effects: Effects::default(),
        };
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(
            deps.config.apply_timeout,
            handler.apply(&mut ctx, &event),
        ))
        .catch_unwind()
        .await;
        (result, std::mem::take(&mut ctx.effects))
    };
    deps.metrics.record_apply_duration(&kind, started.elapsed());

    let outcome = match result {
        Ok(Ok(Ok(ApplyOutcome::Applied))) => {
            let post =
                commit_apply(deps, tx, &event, &aggregate, current.as_ref(), effects, None, now)
                    .await?;
            post.dispatch(deps);
            debug!(event = "engine_apply", outcome = "applied", event_id = %event.event_id, aggregate = %aggregate, kind = %kind, "event applied");
            ProcessOutcome::Applied
        }
        Ok(Ok(Ok(ApplyOutcome::Waiting(waiting)))) => {
            let detail = waiting.detail.clone();
            let wake_ref = waiting.wake_ref.clone();
            let post = commit_apply(
                deps,
                tx,
                &event,
                &aggregate,
                current.as_ref(),
                effects,
                Some(waiting),
                now,
            )
            .await?;
            post.dispatch(deps);
            info!(event = "engine_apply", outcome = "waiting", event_id = %event.event_id, aggregate = %aggregate, kind = %kind, wake_ref = %wake_ref, detail = %detail, "event parked on a dependency");
            ProcessOutcome::Waiting
        }
        Ok(Ok(Ok(ApplyOutcome::Rejected(reason)))) => {
            drop(tx);
            let now = deps.clock.now();
            let mut storage = deps.db.acquire().await?;
            storage.mark_engine_inbox_failed(&event.event_id, &reason, now).await?;
            storage.release_engine_poison(&aggregate.kind, &aggregate.id, &kind).await?;
            drop(storage);
            PostCommit {
                acks: event.ack_target().into_iter().collect(),
                woke: false,
                outbox: false,
                jobs: false,
            }
            .dispatch(deps);
            warn!(event = "engine_apply", outcome = "rejected", event_id = %event.event_id, aggregate = %aggregate, kind = %kind, reason = %reason, "event rejected");
            ProcessOutcome::Rejected
        }
        Ok(Ok(Err(ApplyError::Transient(error)))) => {
            drop(tx);
            if is_busy_error(&error) {
                // Lock contention is not a business failure: try again shortly.
                schedule_retry_at(deps, &event, &error.to_string(), deps.clock.now() + 1).await?;
            } else {
                schedule_retry(deps, &event, &error.to_string()).await?;
            }
            warn!(event = "engine_apply", outcome = "transient", event_id = %event.event_id, aggregate = %aggregate, kind = %kind, attempt = event.attempts + 1, error = %error, "event apply failed transiently; will retry");
            ProcessOutcome::Transient
        }
        Ok(Ok(Err(ApplyError::Invariant(error)))) => {
            drop(tx);
            poison(deps, &event, &aggregate, &format!("invariant violated: {error}")).await?;
            ProcessOutcome::Poisoned
        }
        Ok(Err(_elapsed)) => {
            drop(tx);
            let message = format!("apply timed out after {:?}", deps.config.apply_timeout);
            schedule_retry(deps, &event, &message).await?;
            warn!(event = "engine_apply", outcome = "timed_out", event_id = %event.event_id, aggregate = %aggregate, kind = %kind, "event apply timed out; will retry");
            ProcessOutcome::TimedOut
        }
        Err(payload) => {
            drop(tx);
            poison(
                deps,
                &event,
                &aggregate,
                &format!("panic: {}", panic_message(payload.as_ref())),
            )
            .await?;
            ProcessOutcome::Poisoned
        }
    };
    deps.metrics.record_event(&kind, outcome.label());
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
async fn commit_apply(
    deps: &WorkerDeps,
    mut tx: StorageProcessor<'static>,
    event: &EngineInboxEvent,
    aggregate: &AggregateRef,
    current: Option<&EngineAggregate>,
    effects: Effects,
    waiting: Option<WaitingFor>,
    now: i64,
) -> anyhow::Result<PostCommit> {
    for message in &effects.outbox {
        tx.insert_engine_outbox_message(
            &NewEngineOutboxMessage {
                outbox_id: message.outbox_id.clone(),
                aggregate_kind: aggregate.kind.clone(),
                aggregate_id: aggregate.id.clone(),
                phase_ref: message.phase_ref.clone(),
                kind: message.kind.clone(),
                topic: message.topic.clone(),
                payload: message.payload.clone(),
                ack_set: message.ack_set.clone(),
                first_at: now,
            },
            now,
        )
        .await?;
    }
    for (target, reason) in &effects.outbox_closes {
        tx.close_engine_outbox(target, reason, now).await?;
    }
    for job in &effects.jobs {
        let inserted = tx
            .insert_engine_job(
                &NewEngineJob {
                    job_id: job.job_id.clone(),
                    aggregate_kind: aggregate.kind.clone(),
                    aggregate_id: aggregate.id.clone(),
                    phase: job.phase.clone(),
                    action: job.action.clone(),
                    pool: job.pool.as_str().to_string(),
                    params: job.params.clone(),
                    deadline_at: job.deadline_at,
                    first_at: job.run_after.unwrap_or(now).max(now),
                },
                now,
            )
            .await?;
        match inserted {
            EngineJobInsert::Inserted => {}
            EngineJobInsert::Existing(EngineJobState::Pending | EngineJobState::Running) => {
                debug!(event = "engine_jobs", outcome = "already_open", job_id = %job.job_id, action = %job.action, "job is already queued or running");
            }
            EngineJobInsert::Existing(
                state @ (EngineJobState::Done | EngineJobState::Cancelled),
            ) => {
                // Same id means same params: the job ran (or was cancelled)
                // before and the engine will not run it again. Aggregates that
                // derive their jobs from chain state ask for the same job on
                // every scan, so a finished one is routine.
                debug!(event = "engine_jobs", outcome = "reenqueue_ignored", job_id = %job.job_id, action = %job.action, event_id = %event.event_id, state = %state, "job already ran; not run again");
            }
            EngineJobInsert::Existing(state) => {
                // A job that failed or panicked is asked for again: it stays
                // where it is, which is worth a look.
                warn!(event = "engine_jobs", outcome = "reenqueue_ignored", job_id = %job.job_id, action = %job.action, event_id = %event.event_id, state = %state, "job re-enqueued after a terminal failure; not run again");
            }
        }
    }
    for cancel in &effects.job_cancels {
        match cancel {
            JobCancel::Job(job_id) => {
                tx.cancel_engine_job(job_id, now).await?;
            }
            JobCancel::Phase(phase) => {
                tx.cancel_engine_jobs_for_phase(&aggregate.kind, &aggregate.id, phase, now).await?;
            }
            JobCancel::Aggregate { aggregate_kind, aggregate_id } => {
                tx.cancel_engine_jobs_for_aggregate(aggregate_kind, aggregate_id, now).await?;
            }
            JobCancel::AggregatePhase { aggregate_kind, aggregate_id, phase } => {
                tx.cancel_engine_jobs_for_phase(aggregate_kind, aggregate_id, phase, now).await?;
            }
        }
    }
    // The handler ran this kind to a decision: a poison it carried is over.
    tx.release_engine_poison(&aggregate.kind, &aggregate.id, &event.kind).await?;
    let update = EngineAggregateUpdate {
        status: effects.status.clone(),
        phase: effects.phase.clone(),
        state: effects.state.clone(),
        last_event_id: Some(event.event_id.clone()),
    };
    let updated = tx.upsert_engine_aggregate(&aggregate.kind, &aggregate.id, &update, now).await?;
    let changed =
        current.map(|c| c.status != updated.status || c.phase != updated.phase).unwrap_or(true);
    let mut wake_refs = effects.wake_refs.clone();
    if changed {
        wake_refs.push(aggregate.wake_ref());
    }
    let woke = if wake_refs.is_empty() {
        0
    } else {
        tx.wake_engine_inbox_waiting(&wake_refs, now).await?
    };
    let marked = match &waiting {
        None => tx.mark_engine_inbox_applied(&event.event_id, now).await?,
        Some(w) => {
            tx.mark_engine_inbox_waiting(
                &event.event_id,
                &w.wake_ref,
                &w.detail,
                now + deps.config.waiting_recheck_secs(),
                now,
            )
            .await?
        }
    };
    if !marked {
        warn!(event = "engine_apply", outcome = "mark_skipped", event_id = %event.event_id, "inbox row was no longer pending when the apply committed");
    }
    tx.commit().await?;
    let mut acks = effects.acks.clone();
    acks.extend(event.ack_target());
    Ok(PostCommit {
        acks,
        woke: woke > 0,
        outbox: !effects.outbox.is_empty(),
        jobs: !effects.jobs.is_empty(),
    })
}

async fn schedule_retry(
    deps: &WorkerDeps,
    event: &EngineInboxEvent,
    error: &str,
) -> anyhow::Result<()> {
    let now = deps.clock.now();
    let next_at = now + deps.config.inbox_retry_backoff.delay(event.attempts + 1);
    schedule_retry_at(deps, event, error, next_at).await
}

async fn schedule_retry_at(
    deps: &WorkerDeps,
    event: &EngineInboxEvent,
    error: &str,
    next_at: i64,
) -> anyhow::Result<()> {
    let now = deps.clock.now();
    let mut storage = deps.db.acquire().await?;
    storage.mark_engine_inbox_retry(&event.event_id, error, next_at, now).await?;
    Ok(())
}

/// SQLite lock contention surfaces as "database is locked"; it means another
/// writer held the lock past the busy timeout, not that the apply is wrong.
pub(crate) fn is_busy_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("database is locked")
            || message.contains("database is busy")
            || message.contains("sqlite_busy")
    })
}

async fn poison(
    deps: &WorkerDeps,
    event: &EngineInboxEvent,
    aggregate: &AggregateRef,
    reason: &str,
) -> anyhow::Result<()> {
    let now = deps.clock.now();
    let mut tx = deps.db.start_immediate_transaction().await?;
    tx.mark_engine_inbox_poisoned(&event.event_id, reason, now).await?;
    let poison = tx
        .mark_engine_aggregate_poisoned(
            &aggregate.kind,
            &aggregate.id,
            &event.kind,
            reason,
            now,
            &|count| deps.config.poison_backoff.delay(count),
        )
        .await?;
    tx.commit().await?;
    deps.metrics.record_poisoned();
    error!(
        event = "engine_poisoned",
        event_id = %event.event_id,
        aggregate = %aggregate,
        kind = %event.kind,
        poison_count = poison.poison_count,
        blocked_until = poison.blocked_until,
        reason = %reason,
        "event poisoned; later events of this kind wait for the backoff, a clean apply or a manual clear"
    );
    Ok(())
}
