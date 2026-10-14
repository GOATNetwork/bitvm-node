//! Leased jobs with generation fencing. A job is claimed with a lease and a new
//! generation; the holder renews the lease while running and reports with its
//! generation. A holder that lost its lease is fenced at completion, but its
//! external result still reaches the aggregate as a stale `job_result` event.

use crate::clock::Clock;
use crate::config::EngineConfig;
use crate::effects::JobPool;
use crate::event::{AggregateRef, JobResultEvent, JobResultOutcome};
use crate::metrics::EngineMetrics;
use crate::wake::{EngineWake, panic_message, spawn_on_thread};
use async_trait::async_trait;
use futures::FutureExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::LocalDB;
use store::{
    EngineInboxInsert, EngineJob, EngineJobFinish, EngineJobFinishOutcome, EngineJobState,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub struct JobContext {
    pub now: i64,
    pub job: EngineJob,
    /// Cancelled when the lease is lost or the engine shuts down.
    pub cancel: CancellationToken,
}

#[derive(Debug)]
pub enum JobOutcome {
    Done(Vec<u8>),
    /// Retry after `retry_after_secs`, or the configured backoff when `None`.
    Transient {
        error: String,
        retry_after_secs: Option<i64>,
    },
    /// Permanent business failure; recorded and reported to the aggregate.
    Failed(String),
}

#[async_trait]
pub trait JobRunner: Send + Sync {
    async fn run(&self, ctx: JobContext) -> JobOutcome;
}

pub(crate) type JobRegistry = HashMap<(String, String), Arc<dyn JobRunner>>;

#[derive(Clone)]
pub(crate) struct ExecutorDeps {
    pub db: LocalDB,
    pub clock: Arc<dyn Clock>,
    pub config: Arc<EngineConfig>,
    pub registry: Arc<JobRegistry>,
    pub metrics: EngineMetrics,
    pub wake: EngineWake,
}

pub(crate) async fn run_executor(
    deps: ExecutorDeps,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let pools = [
        (JobPool::Cpu, Arc::new(Semaphore::new(deps.config.cpu_pool_slots.max(1)))),
        (JobPool::Pegout, Arc::new(Semaphore::new(deps.config.pegout_pool_slots.max(1)))),
        (JobPool::Network, Arc::new(Semaphore::new(deps.config.network_pool_slots.max(1)))),
    ];
    loop {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(error) = finish_lapsed_cancelled(&deps).await {
            warn!(event = "engine_jobs", outcome = "cancel_sweep_failed", error = %error, "could not finish lapsed cancelled jobs");
        }
        for (pool, semaphore) in &pools {
            if let Err(error) = claim_and_spawn(&deps, *pool, semaphore, &cancel).await {
                warn!(event = "engine_jobs", outcome = "claim_failed", pool = pool.as_str(), error = %error, "job claim failed");
            }
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = notify.notified() => {}
            _ = tokio::time::sleep(deps.config.job_poll_interval) => {}
        }
    }
}

/// A cancelled job whose holder went away (crash, restart) is not run again:
/// it finishes as `Cancelled` here and its result reaches the aggregate.
async fn finish_lapsed_cancelled(deps: &ExecutorDeps) -> anyhow::Result<()> {
    let now = deps.clock.now();
    let mut tx = deps.db.start_immediate_transaction().await?;
    let jobs = tx.finish_lapsed_cancelled_engine_jobs(now).await?;
    if jobs.is_empty() {
        tx.commit().await?;
        return Ok(());
    }
    let mut aggregates = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let aggregate = AggregateRef::new(&job.aggregate_kind, &job.aggregate_id);
        let event = JobResultEvent {
            job_id: job.job_id.clone(),
            phase: job.phase.clone(),
            action: job.action.clone(),
            generation: job.generation,
            stale: false,
            outcome: JobResultOutcome::Cancelled,
        }
        .into_new_event(aggregate.clone())?;
        tx.insert_engine_inbox_event(&event.into_store(), now).await?;
        aggregates.push(aggregate);
    }
    tx.commit().await?;
    for (job, aggregate) in jobs.iter().zip(&aggregates) {
        deps.metrics.record_job_run(&job.action, "cancelled");
        info!(
            event = "engine_jobs",
            outcome = "cancelled",
            job_id = %job.job_id,
            action = %job.action,
            generation = job.generation,
            "cancelled job lost its holder; finished without re-running"
        );
        deps.wake.worker_for(aggregate);
    }
    Ok(())
}

async fn claim_and_spawn(
    deps: &ExecutorDeps,
    pool: JobPool,
    semaphore: &Arc<Semaphore>,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let available = semaphore.available_permits();
        if available == 0 {
            return Ok(());
        }
        let now = deps.clock.now();
        let jobs = {
            let mut storage = deps.db.acquire().await?;
            storage
                .claim_due_engine_jobs(
                    pool.as_str(),
                    now,
                    now + deps.config.job_lease_secs,
                    available as i64,
                )
                .await?
        };
        if jobs.is_empty() {
            return Ok(());
        }
        let claimed = jobs.len();
        for job in jobs {
            let permit = semaphore.clone().acquire_owned().await?;
            spawn_job(deps.clone(), job, pool, permit, cancel.child_token());
        }
        if claimed < available {
            return Ok(());
        }
    }
}

fn spawn_job(
    deps: ExecutorDeps,
    job: EngineJob,
    pool: JobPool,
    permit: OwnedSemaphorePermit,
    cancel: CancellationToken,
) {
    let name = format!("engine-job-{}", &job.job_id[..job.job_id.len().min(12)]);
    let stack = match pool {
        JobPool::Cpu | JobPool::Pegout => deps.config.thread_stack_bytes,
        JobPool::Network => 0,
    };
    spawn_on_thread(name, stack, async move {
        let _permit = permit;
        execute_job(deps, job, cancel).await;
    });
}

async fn execute_job(deps: ExecutorDeps, job: EngineJob, cancel: CancellationToken) {
    let started = Instant::now();
    let now = deps.clock.now();
    let generation = job.generation;
    let key = (job.aggregate_kind.clone(), job.action.clone());
    debug!(
        event = "engine_jobs",
        outcome = "started",
        job_id = %job.job_id,
        action = %job.action,
        generation,
        attempt = job.attempts,
        "job claimed"
    );
    let mut renewal: Option<tokio::task::JoinHandle<()>> = None;
    let finish = if job.deadline_at.is_some_and(|deadline| deadline < now) {
        EngineJobFinish::Failed(format!(
            "deadline {} passed at {now}",
            job.deadline_at.unwrap_or(0)
        ))
    } else {
        match deps.registry.get(&key) {
            None => EngineJobFinish::Failed(format!(
                "no runner registered for {}:{}",
                job.aggregate_kind, job.action
            )),
            Some(runner) => {
                renewal = Some(spawn_lease_renewal(
                    deps.clone(),
                    job.job_id.clone(),
                    generation,
                    cancel.clone(),
                ));
                let ctx = JobContext { now, job: job.clone(), cancel: cancel.clone() };
                let outcome = std::panic::AssertUnwindSafe(runner.run(ctx)).catch_unwind().await;
                match outcome {
                    Ok(JobOutcome::Done(result)) => EngineJobFinish::Done(result),
                    Ok(JobOutcome::Transient { error, retry_after_secs }) => {
                        let delay = retry_after_secs
                            .unwrap_or_else(|| deps.config.job_retry_backoff.delay(job.attempts));
                        EngineJobFinish::Retry { error, next_at: deps.clock.now() + delay }
                    }
                    Ok(JobOutcome::Failed(error)) => EngineJobFinish::Failed(error),
                    Err(payload) => EngineJobFinish::Poisoned(panic_message(payload.as_ref())),
                }
            }
        }
    };
    // Retry completion recording while renewing the lease to avoid rerunning work
    // whose result was not saved. After lease loss, make bounded attempts to record
    // the result for reconciliation.
    let mut attempt: u32 = 0;
    let mut attempts_after_loss: u32 = 0;
    let last_error = loop {
        match record_job_finish(&deps, &job, generation, &finish, started).await {
            Ok(()) => {
                if let Some(renewal) = renewal {
                    renewal.abort();
                }
                return;
            }
            Err(error) => {
                attempt += 1;
                let lease_lost = cancel.is_cancelled();
                if lease_lost {
                    attempts_after_loss += 1;
                }
                warn!(
                    event = "engine_jobs",
                    outcome = "finish_retry",
                    job_id = %job.job_id,
                    generation,
                    attempt,
                    lease_lost,
                    error = %error,
                    "could not record job completion; retrying"
                );
                if attempts_after_loss >= JOB_FINISH_ATTEMPTS_AFTER_LEASE_LOSS {
                    break error;
                }
                let delay = JOB_FINISH_RETRY_BASE.saturating_mul(attempt.min(8));
                tokio::time::sleep(delay).await;
            }
        }
    };
    if let Some(renewal) = renewal {
        renewal.abort();
    }
    error!(
        event = "engine_jobs",
        outcome = "finish_failed",
        job_id = %job.job_id,
        generation,
        attempts = attempt,
        error = %last_error,
        "could not record job completion before the lease was lost; a newer holder re-runs the job"
    );
}

const JOB_FINISH_RETRY_BASE: Duration = Duration::from_millis(250);
const JOB_FINISH_ATTEMPTS_AFTER_LEASE_LOSS: u32 = 2;

fn spawn_lease_renewal(
    deps: ExecutorDeps,
    job_id: String,
    generation: i64,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(deps.config.job_lease_renew_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = deps.clock.now();
            let renewed = match deps.db.acquire().await {
                Ok(mut storage) => {
                    storage
                        .renew_engine_job_lease(
                            &job_id,
                            generation,
                            now + deps.config.job_lease_secs,
                            now,
                        )
                        .await
                }
                Err(error) => Err(error),
            };
            match renewed {
                Ok(true) => {}
                Ok(false) => {
                    // Our own finish may have committed just before this tick.
                    let finished = match deps.db.acquire().await {
                        Ok(mut storage) => storage.find_engine_job(&job_id).await.ok().flatten(),
                        Err(_) => None,
                    }
                    .is_some_and(|row| {
                        row.generation == generation
                            && row.state != EngineJobState::Running.to_string()
                    });
                    if finished {
                        debug!(event = "engine_jobs", outcome = "renewal_done", job_id = %job_id, generation, "job finished; lease renewal stopped");
                        return;
                    }
                    warn!(
                        event = "engine_jobs",
                        outcome = "lease_lost",
                        job_id = %job_id,
                        generation,
                        "job lease was taken over by a newer generation; cancelling this holder"
                    );
                    cancel.cancel();
                    return;
                }
                Err(error) => {
                    warn!(event = "engine_jobs", outcome = "renew_failed", job_id = %job_id, error = %error, "lease renewal failed; retrying");
                }
            }
        }
    })
}

async fn record_job_finish(
    deps: &ExecutorDeps,
    job: &EngineJob,
    generation: i64,
    finish: &EngineJobFinish,
    started: Instant,
) -> anyhow::Result<()> {
    let now = deps.clock.now();
    let aggregate = AggregateRef::new(&job.aggregate_kind, &job.aggregate_id);
    let mut tx = deps.db.start_immediate_transaction().await?;
    let outcome = tx.finish_engine_job(&job.job_id, generation, finish, now).await?;
    let (stale, result_outcome, label) = match (&outcome, finish) {
        (EngineJobFinishOutcome::Applied { state }, finish) => {
            let result_outcome = match (state, finish) {
                (EngineJobState::Done, EngineJobFinish::Done(result)) => {
                    Some(JobResultOutcome::Done(result.clone()))
                }
                (EngineJobState::Cancelled, _) => Some(JobResultOutcome::Cancelled),
                (EngineJobState::Failed, EngineJobFinish::Failed(error)) => {
                    Some(JobResultOutcome::Failed(error.clone()))
                }
                (EngineJobState::Poisoned, EngineJobFinish::Poisoned(error)) => {
                    Some(JobResultOutcome::Poisoned(error.clone()))
                }
                _ => None,
            };
            (false, result_outcome, state.to_string().to_ascii_lowercase())
        }
        (EngineJobFinishOutcome::Stale { .. }, EngineJobFinish::Done(result)) => {
            (true, Some(JobResultOutcome::Done(result.clone())), "stale".to_string())
        }
        (EngineJobFinishOutcome::Stale { .. }, EngineJobFinish::Failed(error)) => {
            (true, Some(JobResultOutcome::Failed(error.clone())), "stale".to_string())
        }
        (EngineJobFinishOutcome::Stale { .. }, EngineJobFinish::Poisoned(error)) => {
            (true, Some(JobResultOutcome::Poisoned(error.clone())), "stale".to_string())
        }
        (EngineJobFinishOutcome::Stale { .. }, EngineJobFinish::Retry { .. }) => {
            (true, None, "stale".to_string())
        }
        (EngineJobFinishOutcome::Missing, _) => (true, None, "missing".to_string()),
    };
    match (&outcome, finish) {
        (EngineJobFinishOutcome::Applied { .. }, EngineJobFinish::Poisoned(reason)) => {
            let poison = tx
                .mark_engine_aggregate_poisoned(
                    &job.aggregate_kind,
                    &job.aggregate_id,
                    &job.action,
                    reason,
                    now,
                    &|count| deps.config.poison_backoff.delay(count),
                )
                .await?;
            deps.metrics.record_poisoned();
            error!(
                event = "engine_poisoned",
                job_id = %job.job_id,
                aggregate = %aggregate,
                action = %job.action,
                poison_count = poison.poison_count,
                blocked_until = poison.blocked_until,
                reason = %reason,
                "job panicked; this action waits for the backoff, a clean run or a manual clear"
            );
        }
        (EngineJobFinishOutcome::Applied { .. }, _) => {
            // The action ran to a result without panicking: its poison is over.
            tx.release_engine_poison(&job.aggregate_kind, &job.aggregate_id, &job.action).await?;
        }
        _ => {}
    }
    let mut wake_worker = false;
    if let Some(result_outcome) = result_outcome {
        let event = JobResultEvent {
            job_id: job.job_id.clone(),
            phase: job.phase.clone(),
            action: job.action.clone(),
            generation,
            stale,
            outcome: result_outcome,
        }
        .into_new_event(aggregate.clone())?;
        let inserted = tx.insert_engine_inbox_event(&event.into_store(), now).await?;
        wake_worker = matches!(inserted, EngineInboxInsert::Inserted { .. });
    }
    tx.commit().await?;
    deps.metrics.record_job_run(&job.action, &label);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &outcome {
        EngineJobFinishOutcome::Applied { state } => info!(
            event = "engine_jobs",
            outcome = %label,
            job_id = %job.job_id,
            action = %job.action,
            generation,
            state = %state,
            elapsed_ms,
            "job finished"
        ),
        EngineJobFinishOutcome::Stale { current_generation, state } => warn!(
            event = "engine_jobs",
            outcome = "stale_completion",
            job_id = %job.job_id,
            action = %job.action,
            generation,
            current_generation,
            state = %state,
            elapsed_ms,
            "late completion fenced; the external result is recorded for reconciliation"
        ),
        EngineJobFinishOutcome::Missing => warn!(
            event = "engine_jobs",
            outcome = "missing",
            job_id = %job.job_id,
            "job row disappeared before completion"
        ),
    }
    if wake_worker {
        deps.wake.worker_for(&aggregate);
    }
    Ok(())
}
