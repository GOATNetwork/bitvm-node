//! Everything an apply may change besides the aggregate's own business rows.
//! The engine writes these in the same transaction as the apply.

use crate::event::AggregateRef;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use store::EngineOutboxCloseTarget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPool {
    /// CPU-bound setup work (garbled circuits, graph builds).
    Cpu,
    /// CPU-bound peg-out work, on its own slots: a challenge or an assert
    /// answers a timelock and must never queue behind a graph build.
    Pegout,
    Network,
}

impl JobPool {
    pub const fn as_str(self) -> &'static str {
        match self {
            JobPool::Cpu => "cpu",
            JobPool::Pegout => "pegout",
            JobPool::Network => "network",
        }
    }
}

/// Stable job id: `H(aggregate ‖ phase ‖ action ‖ params hash)`.
pub fn stable_job_id(aggregate: &AggregateRef, phase: &str, action: &str, params: &[u8]) -> String {
    let params_hash = Sha256::digest(params);
    let mut hasher = Sha256::new();
    hasher.update(aggregate.kind.as_bytes());
    hasher.update(b":");
    hasher.update(aggregate.id.as_bytes());
    hasher.update(b":");
    hasher.update(phase.as_bytes());
    hasher.update(b":");
    hasher.update(action.as_bytes());
    hasher.update(b":");
    hasher.update(params_hash);
    hex::encode(hasher.finalize())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxMessage {
    pub outbox_id: String,
    pub phase_ref: String,
    pub kind: String,
    pub topic: String,
    pub payload: Vec<u8>,
    /// Heavy message: outstanding recipients (peer id -> delivery id).
    pub ack_set: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    pub job_id: String,
    pub phase: String,
    pub action: String,
    pub pool: JobPool,
    pub params: Vec<u8>,
    /// Unix time after which the job is failed instead of run.
    pub deadline_at: Option<i64>,
    /// Unix time before which the job is not claimed (a local timer, never a
    /// protocol deadline).
    pub run_after: Option<i64>,
}

impl JobSpec {
    /// A job with the stable id derived from its identity.
    pub fn new(
        aggregate: &AggregateRef,
        phase: impl Into<String>,
        action: impl Into<String>,
        pool: JobPool,
        params: Vec<u8>,
    ) -> Self {
        let phase = phase.into();
        let action = action.into();
        let job_id = stable_job_id(aggregate, &phase, &action, &params);
        Self { job_id, phase, action, pool, params, deadline_at: None, run_after: None }
    }

    pub fn with_deadline(mut self, deadline_at: i64) -> Self {
        self.deadline_at = Some(deadline_at);
        self
    }

    pub fn with_run_after(mut self, run_after: i64) -> Self {
        self.run_after = Some(run_after);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobCancel {
    Job(String),
    Phase(String),
    /// Every job of another aggregate (for example the graphs of a failed instance).
    Aggregate {
        aggregate_kind: String,
        aggregate_id: String,
    },
    /// One phase of another aggregate's jobs.
    AggregatePhase {
        aggregate_kind: String,
        aggregate_id: String,
        phase: String,
    },
}

#[derive(Debug, Default)]
pub struct Effects {
    pub status: Option<String>,
    pub phase: Option<String>,
    pub state: Option<Option<String>>,
    pub outbox: Vec<OutboxMessage>,
    pub outbox_closes: Vec<(EngineOutboxCloseTarget, String)>,
    pub jobs: Vec<JobSpec>,
    pub job_cancels: Vec<JobCancel>,
    pub wake_refs: Vec<String>,
    pub acks: Vec<store::EngineAckTarget>,
}

impl Effects {
    pub fn set_status(&mut self, status: impl Into<String>) -> &mut Self {
        self.status = Some(status.into());
        self
    }

    pub fn set_phase(&mut self, phase: impl Into<String>) -> &mut Self {
        self.phase = Some(phase.into());
        self
    }

    /// Replace the opaque aggregate state (`None` clears it).
    pub fn set_state(&mut self, state: Option<String>) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub fn send(&mut self, message: OutboxMessage) -> &mut Self {
        self.outbox.push(message);
        self
    }

    pub fn close_outbox(
        &mut self,
        target: EngineOutboxCloseTarget,
        reason: impl Into<String>,
    ) -> &mut Self {
        self.outbox_closes.push((target, reason.into()));
        self
    }

    pub fn enqueue_job(&mut self, job: JobSpec) -> &mut Self {
        self.jobs.push(job);
        self
    }

    pub fn cancel_job(&mut self, job_id: impl Into<String>) -> &mut Self {
        self.job_cancels.push(JobCancel::Job(job_id.into()));
        self
    }

    pub fn cancel_phase_jobs(&mut self, phase: impl Into<String>) -> &mut Self {
        self.job_cancels.push(JobCancel::Phase(phase.into()));
        self
    }

    pub fn cancel_jobs_for_aggregate(&mut self, aggregate: &AggregateRef) -> &mut Self {
        self.job_cancels.push(JobCancel::Aggregate {
            aggregate_kind: aggregate.kind.clone(),
            aggregate_id: aggregate.id.clone(),
        });
        self
    }

    /// Cancel the jobs of one phase of another aggregate.
    pub fn cancel_phase_jobs_for_aggregate(
        &mut self,
        aggregate: &AggregateRef,
        phase: impl Into<String>,
    ) -> &mut Self {
        self.job_cancels.push(JobCancel::AggregatePhase {
            aggregate_kind: aggregate.kind.clone(),
            aggregate_id: aggregate.id.clone(),
            phase: phase.into(),
        });
        self
    }

    /// Wake events waiting on `wake_ref` (status and phase changes wake the
    /// aggregate's own ref automatically).
    pub fn wake(&mut self, wake_ref: impl Into<String>) -> &mut Self {
        self.wake_refs.push(wake_ref.into());
        self
    }

    pub fn ack(&mut self, peer: impl Into<String>, delivery_id: impl Into<String>) -> &mut Self {
        self.acks
            .push(store::EngineAckTarget { peer: peer.into(), delivery_id: delivery_id.into() });
        self
    }

    pub fn is_empty(&self) -> bool {
        self.status.is_none()
            && self.phase.is_none()
            && self.state.is_none()
            && self.outbox.is_empty()
            && self.outbox_closes.is_empty()
            && self.jobs.is_empty()
            && self.job_cancels.is_empty()
            && self.wake_refs.is_empty()
            && self.acks.is_empty()
    }
}
