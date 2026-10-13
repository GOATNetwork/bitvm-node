//! Engine tuning knobs. Every duration used for scheduling is a local timer;
//! protocol deadlines are block heights and belong to the aggregates.

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backoff {
    /// Fixed steps in seconds; the last step repeats.
    Steps(Vec<i64>),
    /// `base` doubled per attempt, capped at `cap`, in seconds.
    Doubling { base: i64, cap: i64 },
}

impl Backoff {
    /// Delay in seconds before attempt number `attempt` (1-based) is retried.
    pub fn delay(&self, attempt: i64) -> i64 {
        let attempt = attempt.max(1);
        match self {
            Backoff::Steps(steps) => {
                if steps.is_empty() {
                    return 0;
                }
                let index = usize::try_from(attempt - 1).unwrap_or(usize::MAX).min(steps.len() - 1);
                steps[index]
            }
            Backoff::Doubling { base, cap } => {
                let shift = u32::try_from(attempt - 1).unwrap_or(u32::MAX).min(30);
                base.saturating_mul(1i64 << shift).min(*cap)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Aggregate workers; aggregates are sharded by `shard_key % worker_count`.
    /// SQLite has a single writer and every apply holds the write lock, so more
    /// workers only add lock contention; keep 1 unless applies wait on I/O.
    pub worker_count: usize,
    /// Stack size for worker and CPU job threads; 0 runs them as tokio tasks.
    pub thread_stack_bytes: usize,
    /// Upper bound for one apply; a timed-out apply is retried as transient.
    pub apply_timeout: Duration,
    /// How often a worker polls when nothing woke it.
    pub worker_poll_interval: Duration,
    /// Full re-check of every waiting event, and refresh of row-count metrics.
    pub recheck_interval: Duration,
    /// Retry schedule for transient apply failures.
    pub inbox_retry_backoff: Backoff,
    /// Re-publish schedule for open outbox rows.
    pub outbox_backoff: Backoff,
    pub outbox_batch: i64,
    pub outbox_lease_secs: i64,
    pub outbox_poll_interval: Duration,
    pub job_lease_secs: i64,
    pub job_lease_renew_interval: Duration,
    pub job_retry_backoff: Backoff,
    pub job_poll_interval: Duration,
    /// How long after the n-th poison of an aggregate (since its last manual
    /// clear) a new fact may lift it again. The first poison lifts at once;
    /// a job that panics on every block then waits out growing steps instead
    /// of re-running on every block.
    pub poison_backoff: Backoff,
    /// Concurrent CPU-bound jobs (the `J` slots).
    pub cpu_pool_slots: usize,
    /// Concurrent CPU-bound peg-out jobs; separate slots so a graph build
    /// never holds a challenge or an assert back.
    pub pegout_pool_slots: usize,
    /// Concurrent network-bound jobs.
    pub network_pool_slots: usize,
    /// Bounded ACK return channel; a full channel drops the ACK and relies on resend.
    pub ack_channel_capacity: usize,
    /// Terminal inbox / outbox / job rows are purged after this long.
    pub terminal_retention_secs: i64,
    pub housekeeping_interval: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            worker_count: 1,
            thread_stack_bytes: 32 * 1024 * 1024,
            apply_timeout: Duration::from_secs(120),
            worker_poll_interval: Duration::from_secs(1),
            recheck_interval: Duration::from_secs(60),
            inbox_retry_backoff: Backoff::Steps(vec![10, 30, 60, 120, 300, 600]),
            outbox_backoff: Backoff::Doubling { base: 30, cap: 600 },
            outbox_batch: 16,
            outbox_lease_secs: 60,
            outbox_poll_interval: Duration::from_secs(1),
            job_lease_secs: 300,
            job_lease_renew_interval: Duration::from_secs(60),
            job_retry_backoff: Backoff::Steps(vec![10, 30, 60, 120, 300, 600]),
            job_poll_interval: Duration::from_secs(1),
            poison_backoff: Backoff::Steps(vec![0, 600, 3600, 6 * 3600, 24 * 3600]),
            cpu_pool_slots: 1,
            pegout_pool_slots: 1,
            network_pool_slots: 4,
            ack_channel_capacity: 256,
            terminal_retention_secs: 15 * 24 * 60 * 60,
            housekeeping_interval: Duration::from_secs(60 * 60),
        }
    }
}

impl EngineConfig {
    /// Seconds a waiting event stays parked before the worker re-checks it on
    /// its own (wakeups make it runnable earlier).
    pub fn waiting_recheck_secs(&self) -> i64 {
        self.recheck_interval.as_secs().max(1) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedules() {
        let steps = Backoff::Steps(vec![10, 30, 60]);
        assert_eq!(steps.delay(0), 10);
        assert_eq!(steps.delay(1), 10);
        assert_eq!(steps.delay(3), 60);
        assert_eq!(steps.delay(99), 60);
        let doubling = Backoff::Doubling { base: 30, cap: 600 };
        assert_eq!(doubling.delay(1), 30);
        assert_eq!(doubling.delay(2), 60);
        assert_eq!(doubling.delay(5), 480);
        assert_eq!(doubling.delay(6), 600);
        assert_eq!(doubling.delay(40), 600);
        assert_eq!(Backoff::Steps(vec![]).delay(1), 0);
    }
}
