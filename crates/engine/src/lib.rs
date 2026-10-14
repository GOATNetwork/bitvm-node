//! Execution engine for persisted events, jobs and P2P messages.
//!
//! Aggregate handlers apply events in a transaction that also records jobs,
//! outbox messages and dependency waits. Job results return as inbox events.
//! The node supplies [`AggregateHandler`]s, [`JobRunner`]s and a [`Transport`].

pub mod ack;
pub mod aggregate;
pub mod clock;
pub mod config;
pub mod effects;
pub mod event;
pub mod jobs;
pub mod metrics;
pub mod outbox;
pub mod runtime;
mod wake;
mod worker;

pub use ack::{AckReceiver, AckRequest, AckSender};
pub use aggregate::{AggregateHandler, ApplyContext, ApplyError, ApplyOutcome, WaitingFor};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{Backoff, EngineConfig};
pub use effects::{Effects, JobCancel, JobPool, JobSpec, OutboxMessage, stable_job_id};
pub use event::{
    AggregateRef, EventSource, JOB_RESULT_KIND, JobResultEvent, JobResultOutcome, NewEvent,
};
pub use jobs::{JobContext, JobOutcome, JobRunner};
pub use metrics::EngineMetrics;
pub use outbox::Transport;
pub use runtime::{Engine, EngineBuilder, EngineHandle, EngineSnapshot, SubmitOutcome};
pub use store::{
    EngineAckTarget as AckTarget, EngineAggregate, EngineInboxEvent, EngineInboxState, EngineJob,
    EngineJobInsert, EngineJobState, EngineOutboxAck, EngineOutboxCloseTarget, EngineOutboxMessage,
    EngineOutboxState, EnginePoison, EngineWaitingEvent,
};
