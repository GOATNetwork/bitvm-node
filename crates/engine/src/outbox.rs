//! The publisher: the only sender. It re-publishes open outbox rows with
//! backoff until an aggregate closes them (ACKs collected, receiver evidence,
//! instance failed, graph unusable).

use crate::clock::Clock;
use crate::config::EngineConfig;
use crate::metrics::EngineMetrics;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use store::localdb::LocalDB;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Wire transport. The engine hands over topic and encoded payload; the
/// transport decides how they reach the network.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub(crate) struct PublisherDeps {
    pub db: LocalDB,
    pub clock: Arc<dyn Clock>,
    pub config: Arc<EngineConfig>,
    pub transport: Arc<dyn Transport>,
    pub metrics: EngineMetrics,
}

pub(crate) async fn run_publisher(
    deps: PublisherDeps,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut failures = PublishFailures::default();
    loop {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(error) = drain_outbox(&deps, &mut failures).await {
            warn!(event = "engine_outbox", outcome = "drain_failed", error = %error, "outbox drain failed");
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = notify.notified() => {}
            _ = tokio::time::sleep(deps.config.outbox_poll_interval) => {}
        }
    }
}

/// Consecutive publish failures per outbox row, so a row the transport keeps
/// refusing backs off instead of retrying at the first step forever. Kept in
/// memory: a restart starts the backoff over.
#[derive(Default)]
pub(crate) struct PublishFailures(HashMap<String, i64>);

/// Rows remembered at most; past it the counts start over, which only
/// shortens some backoffs once.
const PUBLISH_FAILURES_MAX_ROWS: usize = 4_096;

impl PublishFailures {
    fn record(&mut self, outbox_id: &str) -> i64 {
        if self.0.len() >= PUBLISH_FAILURES_MAX_ROWS && !self.0.contains_key(outbox_id) {
            self.0.clear();
        }
        let count = self.0.entry(outbox_id.to_string()).or_default();
        *count += 1;
        *count
    }

    fn clear(&mut self, outbox_id: &str) {
        self.0.remove(outbox_id);
    }
}

/// Publish every due row once. Returns the number of successful publishes.
pub(crate) async fn drain_outbox(
    deps: &PublisherDeps,
    failures: &mut PublishFailures,
) -> anyhow::Result<usize> {
    let mut published = 0;
    loop {
        let now = deps.clock.now();
        let batch = {
            let mut storage = deps.db.acquire().await?;
            storage
                .claim_due_engine_outbox_messages(
                    now,
                    now + deps.config.outbox_lease_secs,
                    deps.config.outbox_batch,
                )
                .await?
        };
        if batch.is_empty() {
            return Ok(published);
        }
        let claimed = batch.len() as i64;
        for row in batch {
            let result = deps.transport.publish(&row.topic, &row.payload).await;
            let now = deps.clock.now();
            let mut storage = deps.db.acquire().await?;
            match result {
                Ok(()) => {
                    failures.clear(&row.outbox_id);
                    let next_at = now + deps.config.outbox_backoff.delay(row.publish_count + 1);
                    storage.record_engine_outbox_publish(&row.outbox_id, next_at, now).await?;
                    deps.metrics.record_publish(true);
                    published += 1;
                    debug!(
                        event = "engine_outbox",
                        outcome = "published",
                        outbox_id = %row.outbox_id,
                        kind = %row.kind,
                        publish_count = row.publish_count + 1,
                        next_at,
                        "outbox row published"
                    );
                }
                Err(error) => {
                    let failed = failures.record(&row.outbox_id);
                    let next_at = now + deps.config.outbox_backoff.delay(failed);
                    storage
                        .record_engine_outbox_publish_failure(
                            &row.outbox_id,
                            &error.to_string(),
                            next_at,
                            now,
                        )
                        .await?;
                    deps.metrics.record_publish(false);
                    warn!(
                        event = "engine_outbox",
                        outcome = "publish_failed",
                        outbox_id = %row.outbox_id,
                        kind = %row.kind,
                        error = %error,
                        failures = failed,
                        next_at,
                        "outbox publish failed; will retry"
                    );
                }
            }
        }
        if claimed < deps.config.outbox_batch {
            return Ok(published);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Backoff;

    #[test]
    fn repeated_publish_failures_back_off_until_a_publish_succeeds() {
        let backoff = Backoff::Doubling { base: 30, cap: 600 };
        let mut failures = PublishFailures::default();
        let delays: Vec<i64> = (0..6).map(|_| backoff.delay(failures.record("row"))).collect();
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 600]);
        assert_eq!(failures.record("other"), 1, "rows count apart");
        failures.clear("row");
        assert_eq!(failures.record("row"), 1, "a publish starts the count over");
    }
}
