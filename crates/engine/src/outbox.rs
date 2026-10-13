//! The publisher: the only sender. It re-publishes open outbox rows with
//! backoff until an aggregate closes them (ACKs collected, receiver evidence,
//! instance failed, graph unusable).

use crate::clock::Clock;
use crate::config::EngineConfig;
use crate::metrics::EngineMetrics;
use async_trait::async_trait;
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
    loop {
        if cancel.is_cancelled() {
            return;
        }
        if let Err(error) = drain_outbox(&deps).await {
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

/// Publish every due row once. Returns the number of successful publishes.
pub(crate) async fn drain_outbox(deps: &PublisherDeps) -> anyhow::Result<usize> {
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
                    let next_at = now + deps.config.outbox_backoff.delay(1);
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
