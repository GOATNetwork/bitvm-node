//! Inbox events and aggregate references.

use serde::{Deserialize, Serialize};
use store::{EngineAckTarget, EngineInboxEvent, engine_shard_key};

/// Identity of an aggregate: its kind (`instance`, `graph`, ...) and id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AggregateRef {
    pub kind: String,
    pub id: String,
}

impl AggregateRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self { kind: kind.into(), id: id.into() }
    }

    pub fn from_event(event: &EngineInboxEvent) -> Self {
        Self { kind: event.aggregate_kind.clone(), id: event.aggregate_id.clone() }
    }

    /// The reference other aggregates wait on when this one changes.
    pub fn wake_ref(&self) -> String {
        format!("{}:{}", self.kind, self.id)
    }

    pub fn shard_key(&self) -> i64 {
        engine_shard_key(&self.kind, &self.id)
    }

    pub fn shard(&self, shard_count: usize) -> usize {
        (self.shard_key() % shard_count.max(1) as i64) as usize
    }
}

impl std::fmt::Display for AggregateRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    Network,
    Chain,
    Height,
    Job,
    Local,
}

impl EventSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventSource::Network => "network",
            EventSource::Chain => "chain",
            EventSource::Height => "height",
            EventSource::Job => "job",
            EventSource::Local => "local",
        }
    }
}

/// An event to record in the inbox. `event_id` is the dedup key and must be
/// derived from the content (content id, chain event id, height key, job
/// result id), never from arrival.
#[derive(Clone, Debug)]
pub struct NewEvent {
    pub event_id: String,
    pub aggregate: AggregateRef,
    pub kind: String,
    pub source: EventSource,
    pub author: String,
    pub payload: Vec<u8>,
    /// For heavy messages: who to ACK once the material is durably applied or parked.
    pub ack: Option<EngineAckTarget>,
}

impl NewEvent {
    pub fn new(
        event_id: impl Into<String>,
        aggregate: AggregateRef,
        kind: impl Into<String>,
        source: EventSource,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            aggregate,
            kind: kind.into(),
            source,
            author: String::new(),
            payload,
            ack: None,
        }
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_ack(mut self, peer: impl Into<String>, delivery_id: impl Into<String>) -> Self {
        self.ack = Some(EngineAckTarget { peer: peer.into(), delivery_id: delivery_id.into() });
        self
    }

    /// The store row for this event, for producers that record it inside
    /// their own transaction (see [`crate::EngineHandle::submit_in`]).
    pub fn into_store(self) -> store::NewEngineInboxEvent {
        store::NewEngineInboxEvent {
            event_id: self.event_id,
            aggregate_kind: self.aggregate.kind,
            aggregate_id: self.aggregate.id,
            kind: self.kind,
            source: self.source.as_str().to_string(),
            author: self.author,
            payload: self.payload,
            ack: self.ack,
        }
    }
}

/// Event kind used for job completions.
pub const JOB_RESULT_KIND: &str = "job_result";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobResultOutcome {
    Done(Vec<u8>),
    Failed(String),
    Cancelled,
    Poisoned(String),
}

/// Payload of a `job_result` event. `stale` is true when the completing holder
/// had lost its lease: the job row was not updated, but the external effect may
/// have happened, so the aggregate reconciles it against current state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResultEvent {
    pub job_id: String,
    pub phase: String,
    pub action: String,
    pub generation: i64,
    pub stale: bool,
    pub outcome: JobResultOutcome,
}

impl JobResultEvent {
    pub fn event_id(job_id: &str, generation: i64) -> String {
        format!("job-result:{job_id}:{generation}")
    }

    pub fn decode(payload: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(payload)?)
    }

    pub fn into_new_event(self, aggregate: AggregateRef) -> anyhow::Result<NewEvent> {
        let payload = serde_json::to_vec(&self)?;
        Ok(NewEvent::new(
            Self::event_id(&self.job_id, self.generation),
            aggregate,
            JOB_RESULT_KIND,
            EventSource::Job,
            payload,
        ))
    }
}
