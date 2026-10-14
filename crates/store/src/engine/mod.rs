//! Storage for engine events, aggregate state, outbox messages and leased jobs.
//!
//! These methods perform database operations. Scheduling, retry and delivery
//! policies are implemented by the execution engine.

use crate::localdb::StorageProcessor;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use std::collections::BTreeMap;
use strum::{Display, EnumString};

/// Lifecycle of an inbox event. `Pending` covers both runnable and waiting
/// rows; a waiting row carries a `waiting_ref`.
#[derive(Clone, Copy, Debug, Display, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineInboxState {
    Pending,
    Applied,
    Failed,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Display, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineOutboxState {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Display, EnumString, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineJobState {
    Pending,
    Running,
    Done,
    Failed,
    Cancelled,
    Poisoned,
}

/// Stable shard key for an aggregate: FNV-1a over `kind:id`, folded to a
/// non-negative i64 so `shard_key % K` works in SQL for any worker count.
pub fn engine_shard_key(aggregate_kind: &str, aggregate_id: &str) -> i64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in aggregate_kind.bytes().chain([b':']).chain(aggregate_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    (hash >> 1) as i64
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineAckTarget {
    pub peer: String,
    pub delivery_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct NewEngineInboxEvent {
    pub event_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub kind: String,
    pub source: String,
    pub author: String,
    /// How admission classified the author of a network event (empty for
    /// local, chain and job events); the storage quota is kept per class.
    pub admission_class: String,
    pub payload: Vec<u8>,
    pub ack: Option<EngineAckTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineInboxInsert {
    Inserted {
        seq: i64,
    },
    /// The event id was already known. `ack_again` is true when the material
    /// is already durably applied or parked, so a heavy message may be ACKed
    /// again; `rearmed` is true when a `Failed` row was put back to `Pending`.
    Duplicate {
        state: EngineInboxState,
        ack_again: bool,
        rearmed: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineInboxEvent {
    pub seq: i64,
    pub event_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub shard_key: i64,
    pub kind: String,
    pub source: String,
    pub author: String,
    pub admission_class: String,
    pub payload: Option<Vec<u8>>,
    pub payload_size: i64,
    pub state: String,
    pub attempts: i64,
    pub next_at: i64,
    pub waiting_ref: Option<String>,
    pub waiting_detail: Option<String>,
    pub ack_peer: Option<String>,
    pub ack_delivery_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub applied_at: Option<i64>,
}

impl EngineInboxEvent {
    pub fn ack_target(&self) -> Option<EngineAckTarget> {
        match (&self.ack_peer, &self.ack_delivery_id) {
            (Some(peer), Some(delivery_id)) => {
                Some(EngineAckTarget { peer: peer.clone(), delivery_id: delivery_id.clone() })
            }
            _ => None,
        }
    }
}

const ENGINE_INBOX_COLUMNS: &str = "seq, event_id, aggregate_kind, aggregate_id, shard_key, kind, \
     source, author, admission_class, payload, payload_size, state, attempts, next_at, \
     waiting_ref, waiting_detail, ack_peer, ack_delivery_id, last_error, created_at, updated_at, \
     applied_at";

fn engine_inbox_event_from_row(row: &SqliteRow) -> Result<EngineInboxEvent, sqlx::Error> {
    Ok(EngineInboxEvent {
        seq: row.try_get("seq")?,
        event_id: row.try_get("event_id")?,
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        shard_key: row.try_get("shard_key")?,
        kind: row.try_get("kind")?,
        source: row.try_get("source")?,
        author: row.try_get("author")?,
        admission_class: row.try_get("admission_class")?,
        payload: row.try_get("payload")?,
        payload_size: row.try_get("payload_size")?,
        state: row.try_get("state")?,
        attempts: row.try_get("attempts")?,
        next_at: row.try_get("next_at")?,
        waiting_ref: row.try_get("waiting_ref")?,
        waiting_detail: row.try_get("waiting_detail")?,
        ack_peer: row.try_get("ack_peer")?,
        ack_delivery_id: row.try_get("ack_delivery_id")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        applied_at: row.try_get("applied_at")?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineAggregate {
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub status: String,
    pub phase: String,
    pub state: Option<String>,
    pub version: i64,
    pub last_event_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

const ENGINE_AGGREGATE_COLUMNS: &str = "aggregate_kind, aggregate_id, status, phase, state, \
     version, last_event_id, created_at, updated_at";

fn engine_aggregate_from_row(row: &SqliteRow) -> Result<EngineAggregate, sqlx::Error> {
    Ok(EngineAggregate {
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        status: row.try_get("status")?,
        phase: row.try_get("phase")?,
        state: row.try_get("state")?,
        version: row.try_get("version")?,
        last_event_id: row.try_get("last_event_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// What an apply changes on the aggregate row. `None` leaves a field alone;
/// `Some(None)` clears an optional field.
#[derive(Clone, Debug, Default)]
pub struct EngineAggregateUpdate {
    pub status: Option<String>,
    pub phase: Option<String>,
    pub state: Option<Option<String>>,
    pub last_event_id: Option<String>,
}

/// An action (job action or event kind) of an aggregate that panicked. It is
/// held back until `blocked_until`; the backoff grows with `poison_count`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginePoison {
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub action: String,
    pub reason: String,
    pub poison_count: i64,
    pub poisoned_at: i64,
    pub blocked_until: i64,
}

/// A parked inbox event: what it waits on and since when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineWaitingEvent {
    pub event_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub kind: String,
    pub waiting_ref: String,
    pub waiting_detail: Option<String>,
    pub next_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineJobInsert {
    Inserted,
    /// A job with this id exists already; it is run again only if it is still open.
    Existing(EngineJobState),
}

impl EngineJobInsert {
    pub fn is_inserted(&self) -> bool {
        matches!(self, EngineJobInsert::Inserted)
    }
}

#[derive(Clone, Debug)]
pub struct NewEngineOutboxMessage {
    pub outbox_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub phase_ref: String,
    pub kind: String,
    pub topic: String,
    pub payload: Vec<u8>,
    /// Outstanding recipients (peer id -> delivery id) for heavy messages.
    pub ack_set: Option<BTreeMap<String, String>>,
    /// First publish time; usually `now`.
    pub first_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineOutboxMessage {
    pub outbox_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub phase_ref: String,
    pub kind: String,
    pub topic: String,
    pub payload: Vec<u8>,
    pub ack_set: Option<BTreeMap<String, String>>,
    pub state: String,
    pub close_reason: Option<String>,
    pub publish_count: i64,
    pub next_at: i64,
    pub lease_until: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub closed_at: Option<i64>,
}

const ENGINE_OUTBOX_COLUMNS: &str = "outbox_id, aggregate_kind, aggregate_id, phase_ref, kind, \
     topic, payload, ack_set, state, close_reason, publish_count, next_at, lease_until, last_error, \
     created_at, updated_at, closed_at";

fn engine_outbox_message_from_row(row: &SqliteRow) -> Result<EngineOutboxMessage, sqlx::Error> {
    let ack_set: Option<String> = row.try_get("ack_set")?;
    let ack_set = match ack_set {
        Some(json) => Some(serde_json::from_str(&json).map_err(|error| {
            sqlx::Error::ColumnDecode { index: "ack_set".to_string(), source: Box::new(error) }
        })?),
        None => None,
    };
    Ok(EngineOutboxMessage {
        outbox_id: row.try_get("outbox_id")?,
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        phase_ref: row.try_get("phase_ref")?,
        kind: row.try_get("kind")?,
        topic: row.try_get("topic")?,
        payload: row.try_get("payload")?,
        ack_set,
        state: row.try_get("state")?,
        close_reason: row.try_get("close_reason")?,
        publish_count: row.try_get("publish_count")?,
        next_at: row.try_get("next_at")?,
        lease_until: row.try_get("lease_until")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        closed_at: row.try_get("closed_at")?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineOutboxCloseTarget {
    Row(String),
    Phase { aggregate_kind: String, aggregate_id: String, phase_ref: String },
    Aggregate { aggregate_kind: String, aggregate_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineOutboxAck {
    /// The peer was removed from the row's ack set; `closed` when it was the last.
    Matched {
        outbox_id: String,
        closed: bool,
    },
    NoMatch,
}

#[derive(Clone, Debug)]
pub struct NewEngineJob {
    pub job_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub phase: String,
    pub action: String,
    pub pool: String,
    pub params: Vec<u8>,
    pub deadline_at: Option<i64>,
    pub first_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineJob {
    pub job_id: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub phase: String,
    pub action: String,
    pub pool: String,
    pub params: Option<Vec<u8>>,
    pub state: String,
    pub generation: i64,
    pub lease_until: i64,
    pub attempts: i64,
    pub next_at: i64,
    pub deadline_at: Option<i64>,
    pub cancel_requested: bool,
    pub result: Option<Vec<u8>>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

const ENGINE_JOB_COLUMNS: &str = "job_id, aggregate_kind, aggregate_id, phase, action, pool, \
     params, state, generation, lease_until, attempts, next_at, deadline_at, cancel_requested, \
     result, last_error, created_at, updated_at, finished_at";

fn engine_job_from_row(row: &SqliteRow) -> Result<EngineJob, sqlx::Error> {
    Ok(EngineJob {
        job_id: row.try_get("job_id")?,
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        phase: row.try_get("phase")?,
        action: row.try_get("action")?,
        pool: row.try_get("pool")?,
        params: row.try_get("params")?,
        state: row.try_get("state")?,
        generation: row.try_get("generation")?,
        lease_until: row.try_get("lease_until")?,
        attempts: row.try_get("attempts")?,
        next_at: row.try_get("next_at")?,
        deadline_at: row.try_get("deadline_at")?,
        cancel_requested: row.try_get::<i64, _>("cancel_requested")? != 0,
        result: row.try_get("result")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

/// How a claimed job ended, as reported by the executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineJobFinish {
    Done(Vec<u8>),
    /// Transient failure: back to `Pending` at `next_at`.
    Retry {
        error: String,
        next_at: i64,
    },
    Failed(String),
    Poisoned(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineJobFinishOutcome {
    Applied {
        state: EngineJobState,
    },
    /// The generation no longer belongs to the caller (lease lost and re-claimed,
    /// or the job was cancelled). Nothing was written.
    Stale {
        current_generation: i64,
        state: String,
    },
    Missing,
}

/// Queued inbox usage for one admission class, with the share attributable to
/// the author being admitted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InboxClassUsage {
    pub admission_class: String,
    pub rows: i64,
    pub bytes: i64,
    pub peer_rows: i64,
    pub peer_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStateCount {
    pub table: String,
    pub state: String,
    pub count: i64,
}

fn ack_set_json(ack_set: &BTreeMap<String, String>) -> anyhow::Result<String> {
    Ok(serde_json::to_string(ack_set)?)
}

impl<'a> StorageProcessor<'a> {
    // ------------------------------------------------------------------ inbox

    /// Record an event once. A duplicate id is never inserted twice: `Failed`
    /// rows are re-armed, everything else is left as is.
    pub async fn insert_engine_inbox_event(
        &mut self,
        event: &NewEngineInboxEvent,
        now: i64,
    ) -> anyhow::Result<EngineInboxInsert> {
        let shard_key = engine_shard_key(&event.aggregate_kind, &event.aggregate_id);
        let (ack_peer, ack_delivery_id) = match &event.ack {
            Some(ack) => (Some(ack.peer.as_str()), Some(ack.delivery_id.as_str())),
            None => (None, None),
        };
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO engine_inbox \
             (event_id, aggregate_kind, aggregate_id, shard_key, kind, source, author, \
              admission_class, payload, payload_size, state, attempts, next_at, ack_peer, \
              ack_delivery_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', 0, ?, ?, ?, ?, ?) \
             RETURNING seq",
        )
        .bind(&event.event_id)
        .bind(&event.aggregate_kind)
        .bind(&event.aggregate_id)
        .bind(shard_key)
        .bind(&event.kind)
        .bind(&event.source)
        .bind(&event.author)
        .bind(&event.admission_class)
        .bind(&event.payload)
        .bind(event.payload.len() as i64)
        .bind(now)
        .bind(ack_peer)
        .bind(ack_delivery_id)
        .bind(now)
        .bind(now)
        .fetch_optional(self.conn())
        .await?;
        if let Some(row) = inserted {
            return Ok(EngineInboxInsert::Inserted { seq: row.try_get("seq")? });
        }
        let existing =
            sqlx::query("SELECT state, waiting_ref FROM engine_inbox WHERE event_id = ?")
                .bind(&event.event_id)
                .fetch_one(self.conn())
                .await?;
        let state: String = existing.try_get("state")?;
        let waiting_ref: Option<String> = existing.try_get("waiting_ref")?;
        let state = state
            .parse::<EngineInboxState>()
            .map_err(|_| anyhow::anyhow!("unknown engine inbox state {state:?}"))?;
        let mut rearmed = false;
        if state == EngineInboxState::Failed {
            rearmed = sqlx::query(
                "UPDATE engine_inbox SET state = 'Pending', next_at = ?, waiting_ref = NULL, \
                 waiting_detail = NULL, last_error = NULL, updated_at = ? \
                 WHERE event_id = ? AND state = 'Failed'",
            )
            .bind(now)
            .bind(now)
            .bind(&event.event_id)
            .execute(self.conn())
            .await?
            .rows_affected()
                > 0;
        }
        let ack_again = match state {
            EngineInboxState::Applied => true,
            EngineInboxState::Pending => waiting_ref.is_some(),
            EngineInboxState::Failed | EngineInboxState::Poisoned => false,
        };
        Ok(EngineInboxInsert::Duplicate { state, ack_again, rearmed })
    }

    pub async fn find_engine_inbox_event(
        &mut self,
        event_id: &str,
    ) -> anyhow::Result<Option<EngineInboxEvent>> {
        let row = sqlx::query(&format!(
            "SELECT {ENGINE_INBOX_COLUMNS} FROM engine_inbox WHERE event_id = ?"
        ))
        .bind(event_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| engine_inbox_event_from_row(&row)).transpose()?)
    }

    /// Oldest runnable event owned by `shard` out of `shard_count`. No lease is
    /// taken: a shard has exactly one worker, and an apply either commits as a
    /// whole or leaves the row untouched.
    pub async fn next_runnable_engine_inbox_event(
        &mut self,
        shard_count: i64,
        shard: i64,
        now: i64,
    ) -> anyhow::Result<Option<EngineInboxEvent>> {
        let row = sqlx::query(&format!(
            "SELECT {ENGINE_INBOX_COLUMNS} FROM engine_inbox e \
             WHERE e.state = 'Pending' AND e.next_at <= ? AND (e.shard_key % ?) = ? \
               AND NOT EXISTS (SELECT 1 FROM engine_aggregate_poison p \
                 WHERE p.aggregate_kind = e.aggregate_kind AND p.aggregate_id = e.aggregate_id \
                   AND p.action = e.kind AND p.blocked_until > ?) \
             ORDER BY e.seq LIMIT 1"
        ))
        .bind(now)
        .bind(shard_count)
        .bind(shard)
        .bind(now)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| engine_inbox_event_from_row(&row)).transpose()?)
    }

    pub async fn mark_engine_inbox_applied(
        &mut self,
        event_id: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET state = 'Applied', payload = NULL, waiting_ref = NULL, \
             waiting_detail = NULL, last_error = NULL, applied_at = ?, updated_at = ? \
             WHERE event_id = ? AND state = 'Pending'",
        )
        .bind(now)
        .bind(now)
        .bind(event_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Park the event until `next_at` (or an earlier wake on `waiting_ref`).
    /// The payload stays so the apply can be repeated.
    pub async fn mark_engine_inbox_waiting(
        &mut self,
        event_id: &str,
        waiting_ref: &str,
        waiting_detail: &str,
        next_at: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET waiting_ref = ?, waiting_detail = ?, next_at = ?, \
             updated_at = ? \
             WHERE event_id = ? AND state = 'Pending'",
        )
        .bind(waiting_ref)
        .bind(waiting_detail)
        .bind(next_at)
        .bind(now)
        .bind(event_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Transient failure: stay `Pending`, retry at `next_at`.
    pub async fn mark_engine_inbox_retry(
        &mut self,
        event_id: &str,
        error: &str,
        next_at: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET attempts = attempts + 1, next_at = ?, last_error = ?, \
             waiting_ref = NULL, waiting_detail = NULL, updated_at = ? \
             WHERE event_id = ? AND state = 'Pending'",
        )
        .bind(next_at)
        .bind(error)
        .bind(now)
        .bind(event_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Permanent business rejection. The payload is kept for inspection and a
    /// duplicate arrival re-arms the row.
    pub async fn mark_engine_inbox_failed(
        &mut self,
        event_id: &str,
        reason: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET state = 'Failed', attempts = attempts + 1, last_error = ?, \
             waiting_ref = NULL, waiting_detail = NULL, updated_at = ? \
             WHERE event_id = ? AND state = 'Pending'",
        )
        .bind(reason)
        .bind(now)
        .bind(event_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn mark_engine_inbox_poisoned(
        &mut self,
        event_id: &str,
        reason: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET state = 'Poisoned', attempts = attempts + 1, last_error = ?, \
             waiting_ref = NULL, waiting_detail = NULL, updated_at = ? \
             WHERE event_id = ? AND state = 'Pending'",
        )
        .bind(reason)
        .bind(now)
        .bind(event_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Make every event waiting on one of `refs` runnable now. Reads first so
    /// an idle call takes no write lock.
    pub async fn wake_engine_inbox_waiting(
        &mut self,
        refs: &[String],
        now: i64,
    ) -> anyhow::Result<u64> {
        let mut woken = 0;
        for waiting_ref in refs {
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM engine_inbox \
                 WHERE state = 'Pending' AND waiting_ref = ? AND next_at > ?",
            )
            .bind(waiting_ref)
            .bind(now)
            .fetch_one(self.conn())
            .await?;
            if pending == 0 {
                continue;
            }
            woken += sqlx::query(
                "UPDATE engine_inbox SET next_at = ?, updated_at = ? \
                 WHERE state = 'Pending' AND waiting_ref = ? AND next_at > ?",
            )
            .bind(now)
            .bind(now)
            .bind(waiting_ref)
            .bind(now)
            .execute(self.conn())
            .await?
            .rows_affected();
        }
        Ok(woken)
    }

    /// Periodic re-check: every waiting event becomes runnable now.
    pub async fn rearm_engine_inbox_waiting(&mut self, now: i64) -> anyhow::Result<u64> {
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM engine_inbox \
             WHERE state = 'Pending' AND waiting_ref IS NOT NULL AND next_at > ?",
        )
        .bind(now)
        .fetch_one(self.conn())
        .await?;
        if pending == 0 {
            return Ok(0);
        }
        Ok(sqlx::query(
            "UPDATE engine_inbox SET next_at = ?, updated_at = ? \
             WHERE state = 'Pending' AND waiting_ref IS NOT NULL AND next_at > ?",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    /// Startup: re-check every pending event regardless of its backoff.
    pub async fn rearm_engine_inbox_pending(&mut self, now: i64) -> anyhow::Result<u64> {
        Ok(sqlx::query(
            "UPDATE engine_inbox SET next_at = ?, updated_at = ? \
             WHERE state = 'Pending' AND next_at > ?",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    pub async fn list_engine_inbox_events_for_aggregate(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<EngineInboxEvent>> {
        let rows = sqlx::query(&format!(
            "SELECT {ENGINE_INBOX_COLUMNS} FROM engine_inbox \
             WHERE aggregate_kind = ? AND aggregate_id = ? ORDER BY seq DESC LIMIT ?"
        ))
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        rows.iter().map(|row| Ok(engine_inbox_event_from_row(row)?)).collect()
    }

    /// Remove terminal inbox rows older than `before` and closed outbox / finished
    /// job rows older than `before`.
    pub async fn purge_engine_terminal_rows(&mut self, before: i64) -> anyhow::Result<u64> {
        let inbox = sqlx::query(
            "DELETE FROM engine_inbox \
             WHERE state IN ('Applied', 'Failed', 'Poisoned') AND updated_at < ?",
        )
        .bind(before)
        .execute(self.conn())
        .await?
        .rows_affected();
        let outbox =
            sqlx::query("DELETE FROM engine_outbox WHERE state = 'Closed' AND updated_at < ?")
                .bind(before)
                .execute(self.conn())
                .await?
                .rows_affected();
        let jobs = sqlx::query(
            "DELETE FROM engine_job \
             WHERE state IN ('Done', 'Failed', 'Cancelled', 'Poisoned') AND updated_at < ?",
        )
        .bind(before)
        .execute(self.conn())
        .await?
        .rows_affected();
        Ok(inbox + outbox + jobs)
    }

    /// Drop the rejected (`Failed`) network events last updated before
    /// `before`: the admission quota should stop charging for them well before
    /// the terminal retention. A sender that wants one back sends it again.
    pub async fn purge_rejected_network_inbox_rows(&mut self, before: i64) -> anyhow::Result<u64> {
        Ok(sqlx::query(
            "DELETE FROM engine_inbox \
             WHERE source = 'network' AND state = 'Failed' AND updated_at < ?",
        )
        .bind(before)
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    // -------------------------------------------------------------- aggregate

    pub async fn find_engine_aggregate(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
    ) -> anyhow::Result<Option<EngineAggregate>> {
        let row = sqlx::query(&format!(
            "SELECT {ENGINE_AGGREGATE_COLUMNS} FROM engine_aggregate \
             WHERE aggregate_kind = ? AND aggregate_id = ?"
        ))
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| engine_aggregate_from_row(&row)).transpose()?)
    }

    /// Create the row if needed and apply `update`; bumps `version`.
    pub async fn upsert_engine_aggregate(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        update: &EngineAggregateUpdate,
        now: i64,
    ) -> anyhow::Result<EngineAggregate> {
        sqlx::query(
            "INSERT OR IGNORE INTO engine_aggregate \
             (aggregate_kind, aggregate_id, status, phase, version, created_at, updated_at) \
             VALUES (?, ?, '', '', 0, ?, ?)",
        )
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        let (set_state, state) = match &update.state {
            Some(state) => (true, state.clone()),
            None => (false, None),
        };
        sqlx::query(
            "UPDATE engine_aggregate SET version = version + 1, updated_at = ?, \
                 status = COALESCE(?, status), phase = COALESCE(?, phase), \
                 state = CASE WHEN ? THEN ? ELSE state END, \
                 last_event_id = COALESCE(?, last_event_id) \
             WHERE aggregate_kind = ? AND aggregate_id = ?",
        )
        .bind(now)
        .bind(&update.status)
        .bind(&update.phase)
        .bind(set_state)
        .bind(state)
        .bind(&update.last_event_id)
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .execute(self.conn())
        .await?;
        self.find_engine_aggregate(aggregate_kind, aggregate_id).await?.ok_or_else(|| {
            anyhow::anyhow!("engine aggregate {aggregate_kind}:{aggregate_id} vanished")
        })
    }

    /// Record a panic of `action` on the aggregate: the action is held back for
    /// `backoff_secs(count)` seconds, where `count` is the number of consecutive
    /// poisons of this action. The row survives until the action runs cleanly
    /// or the aggregate is cleared by hand.
    pub async fn mark_engine_aggregate_poisoned(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        action: &str,
        reason: &str,
        now: i64,
        backoff_secs: &(dyn Fn(i64) -> i64 + Sync),
    ) -> anyhow::Result<EnginePoison> {
        let row = sqlx::query(
            "INSERT INTO engine_aggregate_poison \
             (aggregate_kind, aggregate_id, action, reason, poison_count, poisoned_at, \
              blocked_until, updated_at) \
             VALUES (?, ?, ?, ?, 1, ?, ?, ?) \
             ON CONFLICT(aggregate_kind, aggregate_id, action) DO UPDATE SET \
               reason = excluded.reason, \
               poison_count = engine_aggregate_poison.poison_count + 1, \
               poisoned_at = excluded.poisoned_at, updated_at = excluded.updated_at \
             RETURNING poison_count",
        )
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(action)
        .bind(reason)
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_one(self.conn())
        .await?;
        let poison_count: i64 = row.try_get("poison_count")?;
        let blocked_until = now.saturating_add(backoff_secs(poison_count).max(0));
        sqlx::query(
            "UPDATE engine_aggregate_poison SET blocked_until = ? \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND action = ?",
        )
        .bind(blocked_until)
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(action)
        .execute(self.conn())
        .await?;
        Ok(EnginePoison {
            aggregate_kind: aggregate_kind.to_string(),
            aggregate_id: aggregate_id.to_string(),
            action: action.to_string(),
            reason: reason.to_string(),
            poison_count,
            poisoned_at: now,
            blocked_until,
        })
    }

    /// `action` ran cleanly: it is no longer poisoned and its count starts over.
    pub async fn release_engine_poison(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        action: &str,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "DELETE FROM engine_aggregate_poison \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND action = ?",
        )
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(action)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// A manual clear of one action or of every action of the aggregate.
    pub async fn clear_engine_aggregate_poison(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        action: Option<&str>,
    ) -> anyhow::Result<u64> {
        Ok(sqlx::query(
            "DELETE FROM engine_aggregate_poison \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND (? IS NULL OR action = ?)",
        )
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(action)
        .bind(action)
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    pub async fn list_engine_poisons(
        &mut self,
        aggregate: Option<(&str, &str)>,
        limit: i64,
    ) -> anyhow::Result<Vec<EnginePoison>> {
        let (aggregate_kind, aggregate_id) = match aggregate {
            Some((kind, id)) => (Some(kind), Some(id)),
            None => (None, None),
        };
        let rows = sqlx::query(
            "SELECT aggregate_kind, aggregate_id, action, reason, poison_count, poisoned_at, \
                    blocked_until \
             FROM engine_aggregate_poison \
             WHERE (? IS NULL OR aggregate_kind = ?) AND (? IS NULL OR aggregate_id = ?) \
             ORDER BY poisoned_at, aggregate_kind, aggregate_id, action LIMIT ?",
        )
        .bind(aggregate_kind)
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(aggregate_id)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(EnginePoison {
                    aggregate_kind: row.try_get("aggregate_kind")?,
                    aggregate_id: row.try_get("aggregate_id")?,
                    action: row.try_get("action")?,
                    reason: row.try_get("reason")?,
                    poison_count: row.try_get("poison_count")?,
                    poisoned_at: row.try_get("poisoned_at")?,
                    blocked_until: row.try_get("blocked_until")?,
                })
            })
            .collect()
    }

    /// Parked events, oldest park first.
    pub async fn list_engine_inbox_waiting(
        &mut self,
        limit: i64,
    ) -> anyhow::Result<Vec<EngineWaitingEvent>> {
        let rows = sqlx::query(
            "SELECT event_id, aggregate_kind, aggregate_id, kind, waiting_ref, waiting_detail, \
                    next_at, created_at, updated_at \
             FROM engine_inbox WHERE state = 'Pending' AND waiting_ref IS NOT NULL \
             ORDER BY updated_at, seq LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(EngineWaitingEvent {
                    event_id: row.try_get("event_id")?,
                    aggregate_kind: row.try_get("aggregate_kind")?,
                    aggregate_id: row.try_get("aggregate_id")?,
                    kind: row.try_get("kind")?,
                    waiting_ref: row.try_get("waiting_ref")?,
                    waiting_detail: row.try_get("waiting_detail")?,
                    next_at: row.try_get("next_at")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                })
            })
            .collect()
    }

    // ----------------------------------------------------------------- outbox

    /// Insert once; a known `outbox_id` (open or closed) is left untouched so a
    /// closed row is never reopened.
    pub async fn insert_engine_outbox_message(
        &mut self,
        message: &NewEngineOutboxMessage,
        now: i64,
    ) -> anyhow::Result<bool> {
        let ack_set = match &message.ack_set {
            Some(ack_set) => Some(ack_set_json(ack_set)?),
            None => None,
        };
        Ok(sqlx::query(
            "INSERT OR IGNORE INTO engine_outbox \
             (outbox_id, aggregate_kind, aggregate_id, phase_ref, kind, topic, payload, ack_set, \
              state, publish_count, next_at, lease_until, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', 0, ?, 0, ?, ?)",
        )
        .bind(&message.outbox_id)
        .bind(&message.aggregate_kind)
        .bind(&message.aggregate_id)
        .bind(&message.phase_ref)
        .bind(&message.kind)
        .bind(&message.topic)
        .bind(&message.payload)
        .bind(ack_set)
        .bind(message.first_at)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn find_engine_outbox_message(
        &mut self,
        outbox_id: &str,
    ) -> anyhow::Result<Option<EngineOutboxMessage>> {
        let row = sqlx::query(&format!(
            "SELECT {ENGINE_OUTBOX_COLUMNS} FROM engine_outbox WHERE outbox_id = ?"
        ))
        .bind(outbox_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| engine_outbox_message_from_row(&row)).transpose()?)
    }

    /// Claim up to `limit` open rows that are due and not leased. Candidates
    /// are read first so an idle publisher never takes the write lock.
    pub async fn claim_due_engine_outbox_messages(
        &mut self,
        now: i64,
        lease_until: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EngineOutboxMessage>> {
        let candidates = sqlx::query(
            "SELECT outbox_id FROM engine_outbox \
             WHERE state = 'Open' AND next_at <= ? AND lease_until <= ? \
             ORDER BY next_at, created_at LIMIT ?",
        )
        .bind(now)
        .bind(now)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        let mut claimed = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let outbox_id: String = candidate.try_get("outbox_id")?;
            let row = sqlx::query(&format!(
                "UPDATE engine_outbox SET lease_until = ?, updated_at = ? \
                 WHERE outbox_id = ? AND state = 'Open' AND next_at <= ? AND lease_until <= ? \
                 RETURNING {ENGINE_OUTBOX_COLUMNS}"
            ))
            .bind(lease_until)
            .bind(now)
            .bind(&outbox_id)
            .bind(now)
            .bind(now)
            .fetch_optional(self.conn())
            .await?;
            if let Some(row) = row {
                claimed.push(engine_outbox_message_from_row(&row)?);
            }
        }
        Ok(claimed)
    }

    pub async fn record_engine_outbox_publish(
        &mut self,
        outbox_id: &str,
        next_at: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_outbox SET publish_count = publish_count + 1, next_at = ?, \
             lease_until = 0, last_error = NULL, updated_at = ? \
             WHERE outbox_id = ? AND state = 'Open'",
        )
        .bind(next_at)
        .bind(now)
        .bind(outbox_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn record_engine_outbox_publish_failure(
        &mut self,
        outbox_id: &str,
        error: &str,
        next_at: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_outbox SET next_at = ?, lease_until = 0, last_error = ?, updated_at = ? \
             WHERE outbox_id = ? AND state = 'Open'",
        )
        .bind(next_at)
        .bind(error)
        .bind(now)
        .bind(outbox_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn close_engine_outbox(
        &mut self,
        target: &EngineOutboxCloseTarget,
        reason: &str,
        now: i64,
    ) -> anyhow::Result<u64> {
        // A closed row keeps its identity and ACK bookkeeping, not the payload.
        let set = "SET state = 'Closed', payload = X'', close_reason = ?, closed_at = ?, \
                   lease_until = 0, updated_at = ?";
        let result = match target {
            EngineOutboxCloseTarget::Row(outbox_id) => {
                sqlx::query(&format!(
                    "UPDATE engine_outbox {set} WHERE outbox_id = ? AND state = 'Open'"
                ))
                .bind(reason)
                .bind(now)
                .bind(now)
                .bind(outbox_id)
                .execute(self.conn())
                .await?
            }
            EngineOutboxCloseTarget::Phase { aggregate_kind, aggregate_id, phase_ref } => {
                sqlx::query(&format!(
                    "UPDATE engine_outbox {set} \
                     WHERE aggregate_kind = ? AND aggregate_id = ? AND phase_ref = ? \
                       AND state = 'Open'"
                ))
                .bind(reason)
                .bind(now)
                .bind(now)
                .bind(aggregate_kind)
                .bind(aggregate_id)
                .bind(phase_ref)
                .execute(self.conn())
                .await?
            }
            EngineOutboxCloseTarget::Aggregate { aggregate_kind, aggregate_id } => {
                sqlx::query(&format!(
                    "UPDATE engine_outbox {set} \
                     WHERE aggregate_kind = ? AND aggregate_id = ? AND state = 'Open'"
                ))
                .bind(reason)
                .bind(now)
                .bind(now)
                .bind(aggregate_kind)
                .bind(aggregate_id)
                .execute(self.conn())
                .await?
            }
        };
        Ok(result.rows_affected())
    }

    /// Apply an ACK from `peer` for `delivery_id`. Only a peer listed in the
    /// row's outstanding set with exactly that delivery id counts.
    ///
    /// This is a read-modify-write of `ack_set`: run it inside an immediate
    /// transaction so concurrent ACKs for one row serialize. On a plain
    /// connection two ACKs can each write back the set they read and put an
    /// already confirmed peer back, and the row then never closes.
    pub async fn acknowledge_engine_outbox(
        &mut self,
        peer: &str,
        delivery_id: &str,
        now: i64,
    ) -> anyhow::Result<EngineOutboxAck> {
        let candidates = sqlx::query(&format!(
            "SELECT {ENGINE_OUTBOX_COLUMNS} FROM engine_outbox \
             WHERE state = 'Open' AND ack_set IS NOT NULL AND instr(ack_set, ?) > 0"
        ))
        .bind(delivery_id)
        .fetch_all(self.conn())
        .await?;
        for row in candidates {
            let message = engine_outbox_message_from_row(&row)?;
            let Some(mut ack_set) = message.ack_set else { continue };
            if ack_set.get(peer).map(String::as_str) != Some(delivery_id) {
                continue;
            }
            ack_set.remove(peer);
            let closed = ack_set.is_empty();
            let updated = if closed {
                sqlx::query(
                    "UPDATE engine_outbox SET ack_set = '{}', state = 'Closed', payload = X'', \
                     close_reason = 'acked', closed_at = ?, lease_until = 0, updated_at = ? \
                     WHERE outbox_id = ? AND state = 'Open'",
                )
                .bind(now)
                .bind(now)
                .bind(&message.outbox_id)
                .execute(self.conn())
                .await?
            } else {
                sqlx::query(
                    "UPDATE engine_outbox SET ack_set = ?, updated_at = ? \
                     WHERE outbox_id = ? AND state = 'Open'",
                )
                .bind(ack_set_json(&ack_set)?)
                .bind(now)
                .bind(&message.outbox_id)
                .execute(self.conn())
                .await?
            };
            if updated.rows_affected() > 0 {
                return Ok(EngineOutboxAck::Matched { outbox_id: message.outbox_id, closed });
            }
        }
        Ok(EngineOutboxAck::NoMatch)
    }

    /// Startup: leases held by a previous process are void.
    pub async fn reset_engine_outbox_leases(&mut self) -> anyhow::Result<u64> {
        Ok(sqlx::query(
            "UPDATE engine_outbox SET lease_until = 0 WHERE state = 'Open' AND lease_until > 0",
        )
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    // ------------------------------------------------------------------- jobs

    /// Insert once; a known job id is left as it is, and the caller learns in
    /// which state it was found.
    pub async fn insert_engine_job(
        &mut self,
        job: &NewEngineJob,
        now: i64,
    ) -> anyhow::Result<EngineJobInsert> {
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO engine_job \
             (job_id, aggregate_kind, aggregate_id, phase, action, pool, params, state, \
              generation, lease_until, attempts, next_at, deadline_at, cancel_requested, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', 0, 0, 0, ?, ?, 0, ?, ?)",
        )
        .bind(&job.job_id)
        .bind(&job.aggregate_kind)
        .bind(&job.aggregate_id)
        .bind(&job.phase)
        .bind(&job.action)
        .bind(&job.pool)
        .bind(&job.params)
        .bind(job.first_at)
        .bind(job.deadline_at)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0;
        if inserted {
            return Ok(EngineJobInsert::Inserted);
        }
        let state: String = sqlx::query("SELECT state FROM engine_job WHERE job_id = ?")
            .bind(&job.job_id)
            .fetch_one(self.conn())
            .await?
            .try_get("state")?;
        let state = state
            .parse::<EngineJobState>()
            .map_err(|_| anyhow::anyhow!("unknown engine job state {state:?}"))?;
        Ok(EngineJobInsert::Existing(state))
    }

    pub async fn find_engine_job(&mut self, job_id: &str) -> anyhow::Result<Option<EngineJob>> {
        let row =
            sqlx::query(&format!("SELECT {ENGINE_JOB_COLUMNS} FROM engine_job WHERE job_id = ?"))
                .bind(job_id)
                .fetch_optional(self.conn())
                .await?;
        Ok(row.map(|row| engine_job_from_row(&row)).transpose()?)
    }

    /// Claim up to `limit` due jobs of `pool`: pending rows whose `next_at`
    /// passed, or running rows whose lease lapsed without a cancel request (a
    /// cancelled one is finished by `finish_lapsed_cancelled_engine_jobs`).
    /// Each claim increments the generation so a late completion from the
    /// previous holder is fenced. Jobs whose action is poisoned on their
    /// aggregate are skipped while the poison's backoff runs, and so is every
    /// job of an aggregate that already has a job running under a live lease,
    /// in any pool: the jobs of one aggregate read and write the same rows and
    /// run one at a time (the apply is serialized the same way). Candidates are
    /// read first so an idle executor never takes the write lock.
    pub async fn claim_due_engine_jobs(
        &mut self,
        pool: &str,
        now: i64,
        lease_until: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EngineJob>> {
        let candidates = sqlx::query(
            "SELECT j.job_id FROM engine_job j \
             WHERE j.pool = ? \
               AND ((j.state = 'Pending' AND j.next_at <= ?) \
                 OR (j.state = 'Running' AND j.lease_until <= ? AND j.cancel_requested = 0)) \
               AND NOT EXISTS (SELECT 1 FROM engine_aggregate_poison p \
                 WHERE p.aggregate_kind = j.aggregate_kind AND p.aggregate_id = j.aggregate_id \
                   AND p.action = j.action AND p.blocked_until > ?) \
               AND NOT EXISTS (SELECT 1 FROM engine_job r \
                 WHERE r.aggregate_kind = j.aggregate_kind AND r.aggregate_id = j.aggregate_id \
                   AND r.job_id <> j.job_id AND r.state = 'Running' AND r.lease_until > ?) \
             ORDER BY j.next_at, j.created_at LIMIT ?",
        )
        .bind(pool)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        let mut claimed = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let job_id: String = candidate.try_get("job_id")?;
            let row = sqlx::query(&format!(
                "UPDATE engine_job SET state = 'Running', generation = generation + 1, \
                     lease_until = ?, attempts = attempts + 1, updated_at = ? \
                 WHERE job_id = ? \
                   AND ((state = 'Pending' AND next_at <= ?) \
                     OR (state = 'Running' AND lease_until <= ? AND cancel_requested = 0)) \
                   AND NOT EXISTS (SELECT 1 FROM engine_job r \
                     WHERE r.aggregate_kind = engine_job.aggregate_kind \
                       AND r.aggregate_id = engine_job.aggregate_id \
                       AND r.job_id <> engine_job.job_id \
                       AND r.state = 'Running' AND r.lease_until > ?) \
                 RETURNING {ENGINE_JOB_COLUMNS}"
            ))
            .bind(lease_until)
            .bind(now)
            .bind(&job_id)
            .bind(now)
            .bind(now)
            .bind(now)
            .fetch_optional(self.conn())
            .await?;
            if let Some(row) = row {
                claimed.push(engine_job_from_row(&row)?);
            }
        }
        Ok(claimed)
    }

    /// Running jobs that were asked to cancel and whose lease lapsed (a crash
    /// or restart took their holder away) finish as `Cancelled` instead of being
    /// run again; the rows are returned so their results can be reported.
    pub async fn finish_lapsed_cancelled_engine_jobs(
        &mut self,
        now: i64,
    ) -> anyhow::Result<Vec<EngineJob>> {
        let rows = sqlx::query(&format!(
            "UPDATE engine_job SET state = 'Cancelled', last_error = 'cancelled', \
                 lease_until = 0, finished_at = ?, updated_at = ? \
             WHERE state = 'Running' AND lease_until <= ? AND cancel_requested = 1 \
             RETURNING {ENGINE_JOB_COLUMNS}"
        ))
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_all(self.conn())
        .await?;
        rows.iter().map(|row| Ok(engine_job_from_row(row)?)).collect()
    }

    /// Extend the lease; false when the caller no longer holds the job.
    pub async fn renew_engine_job_lease(
        &mut self,
        job_id: &str,
        generation: i64,
        lease_until: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_job SET lease_until = ?, updated_at = ? \
             WHERE job_id = ? AND generation = ? AND state = 'Running'",
        )
        .bind(lease_until)
        .bind(now)
        .bind(job_id)
        .bind(generation)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Finish a claimed job. Only the current generation may write; a stale
    /// holder gets `Stale` and must not touch the row.
    pub async fn finish_engine_job(
        &mut self,
        job_id: &str,
        generation: i64,
        finish: &EngineJobFinish,
        now: i64,
    ) -> anyhow::Result<EngineJobFinishOutcome> {
        let Some(current) = self.find_engine_job(job_id).await? else {
            return Ok(EngineJobFinishOutcome::Missing);
        };
        if current.generation != generation || current.state != EngineJobState::Running.to_string()
        {
            return Ok(EngineJobFinishOutcome::Stale {
                current_generation: current.generation,
                state: current.state,
            });
        }
        let (state, result, error, next_at): (EngineJobState, Option<&[u8]>, Option<&str>, i64) =
            match finish {
                EngineJobFinish::Done(result) if current.cancel_requested => {
                    (EngineJobState::Cancelled, Some(result.as_slice()), None, 0)
                }
                EngineJobFinish::Done(result) => {
                    (EngineJobState::Done, Some(result.as_slice()), None, 0)
                }
                EngineJobFinish::Retry { .. } if current.cancel_requested => {
                    (EngineJobState::Cancelled, None, Some("cancelled"), 0)
                }
                EngineJobFinish::Retry { error, next_at } => {
                    (EngineJobState::Pending, None, Some(error.as_str()), *next_at)
                }
                EngineJobFinish::Failed(error) => {
                    (EngineJobState::Failed, None, Some(error.as_str()), 0)
                }
                EngineJobFinish::Poisoned(error) => {
                    (EngineJobState::Poisoned, None, Some(error.as_str()), 0)
                }
            };
        let finished_at = match state {
            EngineJobState::Pending | EngineJobState::Running => None,
            _ => Some(now),
        };
        let updated = sqlx::query(
            "UPDATE engine_job SET state = ?, result = ?, last_error = ?, next_at = ?, \
             lease_until = 0, finished_at = ?, updated_at = ? \
             WHERE job_id = ? AND generation = ? AND state = 'Running'",
        )
        .bind(state.to_string())
        .bind(result)
        .bind(error)
        .bind(next_at)
        .bind(finished_at)
        .bind(now)
        .bind(job_id)
        .bind(generation)
        .execute(self.conn())
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(EngineJobFinishOutcome::Stale {
                current_generation: current.generation,
                state: current.state,
            });
        }
        Ok(EngineJobFinishOutcome::Applied { state })
    }

    /// Cancel a job. A pending job is cancelled immediately; a running one is
    /// flagged and finishes as `Cancelled` when its holder reports.
    pub async fn cancel_engine_job(&mut self, job_id: &str, now: i64) -> anyhow::Result<bool> {
        let cancelled = sqlx::query(
            "UPDATE engine_job SET state = 'Cancelled', finished_at = ?, updated_at = ? \
             WHERE job_id = ? AND state = 'Pending'",
        )
        .bind(now)
        .bind(now)
        .bind(job_id)
        .execute(self.conn())
        .await?
        .rows_affected();
        if cancelled > 0 {
            return Ok(true);
        }
        Ok(sqlx::query(
            "UPDATE engine_job SET cancel_requested = 1, updated_at = ? \
             WHERE job_id = ? AND state = 'Running'",
        )
        .bind(now)
        .bind(job_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    /// Cancel every open job of an aggregate (its instance failed or the graph
    /// became unusable).
    pub async fn cancel_engine_jobs_for_aggregate(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        now: i64,
    ) -> anyhow::Result<u64> {
        let pending = sqlx::query(
            "UPDATE engine_job SET state = 'Cancelled', finished_at = ?, updated_at = ? \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND state = 'Pending'",
        )
        .bind(now)
        .bind(now)
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .execute(self.conn())
        .await?
        .rows_affected();
        let running = sqlx::query(
            "UPDATE engine_job SET cancel_requested = 1, updated_at = ? \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND state = 'Running'",
        )
        .bind(now)
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .execute(self.conn())
        .await?
        .rows_affected();
        Ok(pending + running)
    }

    /// Drop a finished job's result and params blobs once the aggregate
    /// consumed the result: a terminal job is never run again, and its params
    /// may hold a whole network message. The row itself stays for
    /// observability until it is purged.
    pub async fn clear_engine_job_result(
        &mut self,
        job_id: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        Ok(sqlx::query(
            "UPDATE engine_job SET result = NULL, params = NULL, updated_at = ? \
             WHERE job_id = ? AND state IN ('Done', 'Failed', 'Cancelled', 'Poisoned')",
        )
        .bind(now)
        .bind(job_id)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0)
    }

    pub async fn cancel_engine_jobs_for_phase(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
        phase: &str,
        now: i64,
    ) -> anyhow::Result<u64> {
        let rows = sqlx::query(
            "SELECT job_id FROM engine_job \
             WHERE aggregate_kind = ? AND aggregate_id = ? AND phase = ? \
               AND state IN ('Pending', 'Running')",
        )
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .bind(phase)
        .fetch_all(self.conn())
        .await?;
        let mut cancelled = 0;
        for row in rows {
            let job_id: String = row.try_get("job_id")?;
            if self.cancel_engine_job(&job_id, now).await? {
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }

    pub async fn list_engine_jobs_for_aggregate(
        &mut self,
        aggregate_kind: &str,
        aggregate_id: &str,
    ) -> anyhow::Result<Vec<EngineJob>> {
        let rows = sqlx::query(&format!(
            "SELECT {ENGINE_JOB_COLUMNS} FROM engine_job \
             WHERE aggregate_kind = ? AND aggregate_id = ? ORDER BY created_at"
        ))
        .bind(aggregate_kind)
        .bind(aggregate_id)
        .fetch_all(self.conn())
        .await?;
        rows.iter().map(|row| Ok(engine_job_from_row(row)?)).collect()
    }

    /// Startup: a job left `Running` by a previous process is claimable at once.
    pub async fn reset_engine_job_leases(&mut self) -> anyhow::Result<u64> {
        Ok(sqlx::query(
            "UPDATE engine_job SET lease_until = 0 WHERE state = 'Running' AND lease_until > 0",
        )
        .execute(self.conn())
        .await?
        .rows_affected())
    }

    // ------------------------------------------------------------------ quota

    /// Queued network events (`Pending`, waiting, `Failed` or `Poisoned`: the
    /// rows that still hold a payload) per admission class.
    pub async fn engine_inbox_class_totals(&mut self) -> anyhow::Result<Vec<InboxClassUsage>> {
        let rows = sqlx::query(
            "SELECT admission_class, COUNT(*) AS total_rows, \
                    COALESCE(SUM(payload_size), 0) AS total_bytes \
             FROM engine_inbox \
             WHERE source = 'network' AND state IN ('Pending', 'Failed', 'Poisoned') \
             GROUP BY admission_class",
        )
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(InboxClassUsage {
                    admission_class: row.try_get("admission_class")?,
                    rows: row.try_get("total_rows")?,
                    bytes: row.try_get("total_bytes")?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// One author's queued network events per class; `rows` and `bytes`
    /// stay zero.
    pub async fn engine_inbox_peer_usage(
        &mut self,
        author: &str,
    ) -> anyhow::Result<Vec<InboxClassUsage>> {
        let rows = sqlx::query(
            "SELECT admission_class, COUNT(*) AS peer_rows, \
                    COALESCE(SUM(payload_size), 0) AS peer_bytes \
             FROM engine_inbox \
             WHERE source = 'network' AND state IN ('Pending', 'Failed', 'Poisoned') AND author = ? \
             GROUP BY admission_class",
        )
        .bind(author)
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(InboxClassUsage {
                    admission_class: row.try_get("admission_class")?,
                    peer_rows: row.try_get("peer_rows")?,
                    peer_bytes: row.try_get("peer_bytes")?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    // ---------------------------------------------------------------- metrics

    pub async fn engine_state_counts(&mut self) -> anyhow::Result<Vec<EngineStateCount>> {
        let rows = sqlx::query(
            "SELECT 'inbox' AS tbl, state, COUNT(*) AS count FROM engine_inbox GROUP BY state \
             UNION ALL \
             SELECT 'inbox_waiting' AS tbl, 'Waiting' AS state, COUNT(*) AS count FROM engine_inbox \
               WHERE state = 'Pending' AND waiting_ref IS NOT NULL \
             UNION ALL \
             SELECT 'outbox' AS tbl, state, COUNT(*) AS count FROM engine_outbox GROUP BY state \
             UNION ALL \
             SELECT 'job' AS tbl, state, COUNT(*) AS count FROM engine_job GROUP BY state \
             UNION ALL \
             SELECT 'aggregate' AS tbl, 'Poisoned' AS state, \
                    COUNT(DISTINCT aggregate_kind || ':' || aggregate_id) AS count \
               FROM engine_aggregate_poison \
             UNION ALL \
             SELECT 'aggregate' AS tbl, 'Waiting' AS state, \
                    COUNT(DISTINCT aggregate_kind || ':' || aggregate_id) AS count \
               FROM engine_inbox WHERE state = 'Pending' AND waiting_ref IS NOT NULL",
        )
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(EngineStateCount {
                    table: row.try_get("tbl")?,
                    state: row.try_get("state")?,
                    count: row.try_get("count")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
