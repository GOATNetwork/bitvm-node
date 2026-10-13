//! The aggregate contract: `apply(state, event) -> Effects` inside one transaction.

use crate::effects::Effects;
use crate::event::AggregateRef;
use async_trait::async_trait;
use store::localdb::StorageProcessor;
use store::{EngineAggregate, EngineInboxEvent};

/// A dependency the apply could not satisfy. The event stays pending with its
/// payload and becomes runnable again when `wake_ref` changes or on the periodic
/// re-check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitingFor {
    pub wake_ref: String,
    pub detail: String,
}

impl WaitingFor {
    pub fn on(aggregate: &AggregateRef, detail: impl Into<String>) -> Self {
        Self { wake_ref: aggregate.wake_ref(), detail: detail.into() }
    }

    pub fn on_ref(wake_ref: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { wake_ref: wake_ref.into(), detail: detail.into() }
    }
}

#[derive(Debug)]
pub enum ApplyOutcome {
    /// Material persisted; the event is done and its payload can go.
    Applied,
    /// A dependency is missing; effects are still committed (for example a
    /// fetch job) and the event is re-applied later.
    Waiting(WaitingFor),
    /// Permanent business rejection. All writes of this apply are rolled back
    /// and the event is recorded as `Failed` with the reason.
    Rejected(String),
}

#[derive(Debug)]
pub enum ApplyError {
    /// Retry later with backoff; nothing of this apply is kept.
    Transient(anyhow::Error),
    /// An invariant is broken: the event is poisoned and the aggregate flagged.
    Invariant(anyhow::Error),
}

impl ApplyError {
    pub fn transient(error: impl Into<anyhow::Error>) -> Self {
        ApplyError::Transient(error.into())
    }

    pub fn invariant(error: impl Into<anyhow::Error>) -> Self {
        ApplyError::Invariant(error.into())
    }
}

/// Unclassified errors (typically storage) are retried rather than poisoned:
/// poison is reserved for panics and explicit invariant violations.
impl From<anyhow::Error> for ApplyError {
    fn from(error: anyhow::Error) -> Self {
        ApplyError::Transient(error)
    }
}

pub struct ApplyContext<'a> {
    pub now: i64,
    pub aggregate: AggregateRef,
    /// Bookkeeping row as it was when the apply started (`None` for a new aggregate).
    pub current: Option<EngineAggregate>,
    /// The apply transaction; business tables are read and written through it.
    pub storage: &'a mut StorageProcessor<'static>,
    pub effects: Effects,
}

impl ApplyContext<'_> {
    pub fn status(&self) -> &str {
        self.current.as_ref().map(|c| c.status.as_str()).unwrap_or("")
    }

    pub fn phase(&self) -> &str {
        self.current.as_ref().map(|c| c.phase.as_str()).unwrap_or("")
    }

    pub fn state(&self) -> Option<&str> {
        self.current.as_ref().and_then(|c| c.state.as_deref())
    }
}

#[async_trait]
pub trait AggregateHandler: Send + Sync {
    async fn apply(
        &self,
        ctx: &mut ApplyContext<'_>,
        event: &EngineInboxEvent,
    ) -> Result<ApplyOutcome, ApplyError>;
}
