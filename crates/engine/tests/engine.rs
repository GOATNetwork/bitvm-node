//! Engine integration tests using file-backed SQLite: transactional apply,
//! deduplication, ACKs, dependency waits, delivery retries and job recovery.

use async_trait::async_trait;
use engine::{
    AckReceiver, AckRequest, AggregateHandler, AggregateRef, ApplyContext, ApplyError,
    ApplyOutcome, Backoff, Clock, Engine, EngineBuilder, EngineConfig, EngineHandle,
    EngineInboxEvent, EngineInboxState, EngineOutboxAck, EngineOutboxCloseTarget, EventSource,
    JOB_RESULT_KIND, JobContext, JobOutcome, JobPool, JobResultEvent, JobResultOutcome, JobRunner,
    JobSpec, ManualClock, NewEvent, OutboxMessage, SubmitOutcome, Transport, WaitingFor,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::localdb::LocalDB;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const KIND: &str = "test";
const WAIT: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ fixtures

#[derive(Default)]
struct Probe {
    concurrent: AtomicUsize,
    max_concurrent: AtomicUsize,
}

struct TestHandler {
    probe: Arc<Probe>,
}

fn payload_str(event: &EngineInboxEvent) -> String {
    String::from_utf8_lossy(event.payload.as_deref().unwrap_or_default()).to_string()
}

#[async_trait]
impl AggregateHandler for TestHandler {
    async fn apply(
        &self,
        ctx: &mut ApplyContext<'_>,
        event: &EngineInboxEvent,
    ) -> Result<ApplyOutcome, ApplyError> {
        let payload = payload_str(event);
        match event.kind.as_str() {
            "set_status" => {
                ctx.effects.set_status(payload);
                Ok(ApplyOutcome::Applied)
            }
            "set_phase" => {
                ctx.effects.set_phase(payload);
                Ok(ApplyOutcome::Applied)
            }
            "wait_on" => {
                // payload: "<kind>:<id>|<required status>"
                let (dep, required) = payload.split_once('|').expect("wait_on payload");
                let (dep_kind, dep_id) = dep.split_once(':').expect("dep ref");
                let dep_row = ctx.storage.find_engine_aggregate(dep_kind, dep_id).await?;
                if dep_row.is_some_and(|row| row.status == required) {
                    ctx.effects.set_status("unblocked");
                    Ok(ApplyOutcome::Applied)
                } else {
                    Ok(ApplyOutcome::Waiting(WaitingFor::on_ref(dep, format!("need {required}"))))
                }
            }
            "transient" => {
                let failures: i64 = payload.parse().expect("transient count");
                if event.attempts < failures {
                    Err(ApplyError::transient(anyhow::anyhow!("flaky attempt {}", event.attempts)))
                } else {
                    ctx.effects.set_status("recovered");
                    Ok(ApplyOutcome::Applied)
                }
            }
            "effects_then_fail" => {
                ctx.effects.set_status("should_not_persist_on_failure");
                ctx.effects.send(OutboxMessage {
                    outbox_id: format!("{}:out", event.event_id),
                    phase_ref: "p".into(),
                    kind: "Msg".into(),
                    topic: "t".into(),
                    payload: b"x".to_vec(),
                    ack_set: None,
                });
                ctx.effects.enqueue_job(JobSpec::new(
                    &ctx.aggregate,
                    "p",
                    "echo",
                    JobPool::Cpu,
                    b"x".to_vec(),
                ));
                if event.attempts < 1 {
                    Err(ApplyError::transient(anyhow::anyhow!("fail once")))
                } else {
                    Ok(ApplyOutcome::Applied)
                }
            }
            "reject" => Ok(ApplyOutcome::Rejected("nope".into())),
            "panic" => panic!("boom in apply"),
            "invariant" => Err(ApplyError::invariant(anyhow::anyhow!("broken"))),
            "slow" => {
                let millis: u64 = payload.parse().expect("slow millis");
                tokio::time::sleep(Duration::from_millis(millis)).await;
                ctx.effects.set_status("slow_done");
                Ok(ApplyOutcome::Applied)
            }
            "send" => {
                // payload: "<outbox_id>|<phase_ref>|<peer:delivery,peer:delivery>" (ack part optional)
                let mut parts = payload.splitn(3, '|');
                let outbox_id = parts.next().unwrap().to_string();
                let phase_ref = parts.next().unwrap().to_string();
                let ack_set = parts.next().filter(|s| !s.is_empty()).map(|acks| {
                    acks.split(',')
                        .map(|pair| {
                            let (peer, delivery) = pair.split_once(':').unwrap();
                            (peer.to_string(), delivery.to_string())
                        })
                        .collect::<BTreeMap<_, _>>()
                });
                ctx.effects.send(OutboxMessage {
                    outbox_id,
                    phase_ref,
                    kind: "Msg".into(),
                    topic: "topic".into(),
                    payload: payload.clone().into_bytes(),
                    ack_set,
                });
                Ok(ApplyOutcome::Applied)
            }
            "close_phase" => {
                ctx.effects.close_outbox(
                    EngineOutboxCloseTarget::Phase {
                        aggregate_kind: ctx.aggregate.kind.clone(),
                        aggregate_id: ctx.aggregate.id.clone(),
                        phase_ref: payload,
                    },
                    "evidence",
                );
                Ok(ApplyOutcome::Applied)
            }
            "job" => {
                // payload: "<action>|<phase>|<params>"
                let mut parts = payload.splitn(3, '|');
                let action = parts.next().unwrap();
                let phase = parts.next().unwrap();
                let params = parts.next().unwrap_or("").as_bytes().to_vec();
                ctx.effects.set_phase(phase);
                ctx.effects.enqueue_job(JobSpec::new(
                    &ctx.aggregate,
                    phase,
                    action,
                    JobPool::Cpu,
                    params,
                ));
                Ok(ApplyOutcome::Applied)
            }
            k if k == JOB_RESULT_KIND => {
                let result = JobResultEvent::decode(event.payload.as_deref().unwrap_or_default())
                    .map_err(ApplyError::invariant)?;
                if result.stale {
                    ctx.effects.set_state(Some("stale_seen".into()));
                    return Ok(ApplyOutcome::Applied);
                }
                if result.phase != ctx.phase() {
                    return Ok(ApplyOutcome::Rejected(format!(
                        "result for phase {} but aggregate is in {}",
                        result.phase,
                        ctx.phase()
                    )));
                }
                let status = match result.outcome {
                    JobResultOutcome::Done(bytes) => {
                        format!("job_done:{}", String::from_utf8_lossy(&bytes))
                    }
                    JobResultOutcome::Failed(error) => format!("job_failed:{error}"),
                    JobResultOutcome::Cancelled => "job_cancelled".to_string(),
                    JobResultOutcome::Poisoned(error) => format!("job_poisoned:{error}"),
                };
                ctx.effects.set_status(status);
                Ok(ApplyOutcome::Applied)
            }
            "serial_probe" => {
                let now = self.probe.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                self.probe.max_concurrent.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.probe.concurrent.fetch_sub(1, Ordering::SeqCst);
                Ok(ApplyOutcome::Applied)
            }
            other => Ok(ApplyOutcome::Rejected(format!("unknown kind {other}"))),
        }
    }
}

struct EchoRunner;

#[async_trait]
impl JobRunner for EchoRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        JobOutcome::Done(ctx.job.params.unwrap_or_default())
    }
}

struct FlakyRunner;

#[async_trait]
impl JobRunner for FlakyRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        if ctx.job.attempts < 3 {
            JobOutcome::Transient {
                error: format!("attempt {}", ctx.job.attempts),
                retry_after_secs: None,
            }
        } else {
            JobOutcome::Done(b"flaky-ok".to_vec())
        }
    }
}

struct BoomRunner;

#[async_trait]
impl JobRunner for BoomRunner {
    async fn run(&self, _ctx: JobContext) -> JobOutcome {
        panic!("boom in job")
    }
}

struct FailRunner;

#[async_trait]
impl JobRunner for FailRunner {
    async fn run(&self, _ctx: JobContext) -> JobOutcome {
        JobOutcome::Failed("permanent".into())
    }
}

/// Waits for the gate before answering with its generation.
struct GatedRunner {
    gate: watch::Receiver<bool>,
}

#[async_trait]
impl JobRunner for GatedRunner {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let mut gate = self.gate.clone();
        while !*gate.borrow() {
            if gate.changed().await.is_err() {
                return JobOutcome::Failed("gate dropped".into());
            }
        }
        JobOutcome::Done(format!("gen{}", ctx.job.generation).into_bytes())
    }
}

#[derive(Default)]
struct RecordingTransport {
    published: Mutex<Vec<(String, Vec<u8>)>>,
    fail: AtomicBool,
}

impl RecordingTransport {
    fn count(&self) -> usize {
        self.published.lock().unwrap().len()
    }

    fn count_for(&self, needle: &str) -> usize {
        self.published
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, payload)| String::from_utf8_lossy(payload).starts_with(needle))
            .count()
    }
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("transport down");
        }
        self.published.lock().unwrap().push((topic.to_string(), payload.to_vec()));
        Ok(())
    }
}

struct TestEngine {
    db: LocalDB,
    _dir: tempfile::TempDir,
    clock: ManualClock,
    transport: Arc<RecordingTransport>,
    probe: Arc<Probe>,
    handle: EngineHandle,
    acks: AckReceiver,
    cancel: CancellationToken,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
    gate: watch::Sender<bool>,
}

fn fast_config() -> EngineConfig {
    EngineConfig {
        worker_count: 2,
        thread_stack_bytes: 0,
        apply_timeout: Duration::from_millis(300),
        worker_poll_interval: Duration::from_millis(30),
        recheck_interval: Duration::from_millis(250),
        inbox_retry_backoff: Backoff::Steps(vec![1]),
        outbox_backoff: Backoff::Doubling { base: 30, cap: 600 },
        outbox_batch: 16,
        outbox_lease_secs: 60,
        outbox_poll_interval: Duration::from_millis(30),
        job_lease_secs: 1,
        job_lease_renew_interval: Duration::from_secs(30),
        job_retry_backoff: Backoff::Steps(vec![1]),
        job_poll_interval: Duration::from_millis(30),
        poison_backoff: Backoff::Steps(vec![0]),
        cpu_pool_slots: 2,
        pegout_pool_slots: 1,
        network_pool_slots: 2,
        ack_channel_capacity: 8,
        terminal_retention_secs: 15 * 24 * 3600,
        housekeeping_interval: Duration::from_secs(3600),
    }
}

async fn test_db(busy_timeout: Duration) -> (LocalDB, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.db");
    let db =
        LocalDB::new_with_busy_timeout(&format!("sqlite:{}", path.display()), false, busy_timeout)
            .await;
    db.migrate().await;
    (db, dir)
}

async fn start_with(config: EngineConfig, prepare: impl AsyncFnOnce(&LocalDB)) -> TestEngine {
    start_with_busy_timeout(config, store::DEFAULT_BUSY_TIMEOUT, prepare).await
}

async fn start_with_busy_timeout(
    config: EngineConfig,
    busy_timeout: Duration,
    prepare: impl AsyncFnOnce(&LocalDB),
) -> TestEngine {
    let (db, dir) = test_db(busy_timeout).await;
    prepare(&db).await;
    let clock = ManualClock::new(1_000_000);
    let transport = Arc::new(RecordingTransport::default());
    let probe = Arc::new(Probe::default());
    let (gate, gate_rx) = watch::channel(false);
    let (engine, acks): (Engine, AckReceiver) = EngineBuilder::new(db.clone(), config)
        .clock(clock.clone())
        .transport(transport.clone())
        .handler(KIND, Arc::new(TestHandler { probe: probe.clone() }))
        .job_runner(KIND, "echo", Arc::new(EchoRunner))
        .job_runner(KIND, "flaky", Arc::new(FlakyRunner))
        .job_runner(KIND, "boom", Arc::new(BoomRunner))
        .job_runner(KIND, "fail", Arc::new(FailRunner))
        .job_runner(KIND, "gated", Arc::new(GatedRunner { gate: gate_rx }))
        .build();
    let handle = engine.handle();
    let cancel = CancellationToken::new();
    let run = tokio::spawn(engine.run(cancel.clone()));
    TestEngine { db, _dir: dir, clock, transport, probe, handle, acks, cancel, run, gate }
}

async fn start() -> TestEngine {
    start_with(fast_config(), async |_| {}).await
}

impl TestEngine {
    async fn stop(self) {
        self.cancel.cancel();
        self.run.await.unwrap().unwrap();
    }

    fn agg(&self, id: &str) -> AggregateRef {
        AggregateRef::new(KIND, id)
    }

    async fn submit(&self, id: &str, event_id: &str, kind: &str, payload: &str) -> SubmitOutcome {
        self.handle
            .submit(NewEvent::new(
                event_id,
                self.agg(id),
                kind,
                EventSource::Local,
                payload.as_bytes().to_vec(),
            ))
            .await
            .unwrap()
    }

    async fn submit_acked(
        &self,
        id: &str,
        event_id: &str,
        kind: &str,
        payload: &str,
        peer: &str,
        delivery: &str,
    ) -> SubmitOutcome {
        self.handle
            .submit(
                NewEvent::new(
                    event_id,
                    self.agg(id),
                    kind,
                    EventSource::Network,
                    payload.as_bytes().to_vec(),
                )
                .with_author(peer)
                .with_ack(peer, delivery),
            )
            .await
            .unwrap()
    }

    async fn inbox(&self, event_id: &str) -> Option<EngineInboxEvent> {
        let mut s = self.db.acquire().await.unwrap();
        s.find_engine_inbox_event(event_id).await.unwrap()
    }

    async fn wait_inbox_state(&self, event_id: &str, state: EngineInboxState) -> EngineInboxEvent {
        wait_for(WAIT, || async {
            self.inbox(event_id).await.filter(|row| row.state == state.to_string())
        })
        .await
    }

    async fn wait_inbox_attempts(&self, event_id: &str, attempts: i64) -> EngineInboxEvent {
        wait_for(WAIT, || async {
            self.inbox(event_id).await.filter(|row| row.attempts >= attempts)
        })
        .await
    }

    async fn wait_status(&self, id: &str, status: &str) -> store::EngineAggregate {
        let agg = self.agg(id);
        wait_for(WAIT, || async {
            self.handle.aggregate(&agg).await.unwrap().filter(|row| row.status == status)
        })
        .await
    }

    async fn wait_job_state(&self, job_id: &str, state: &str) -> store::EngineJob {
        wait_for(WAIT, || async {
            let mut s = self.db.acquire().await.unwrap();
            s.find_engine_job(job_id).await.unwrap().filter(|job| job.state == state)
        })
        .await
    }

    async fn wait_ack(&mut self) -> AckRequest {
        tokio::time::timeout(WAIT, self.acks.recv())
            .await
            .expect("ack in time")
            .expect("ack channel open")
    }

    async fn wait_publishes(&self, needle: &str, count: usize) {
        wait_for(WAIT, || async { (self.transport.count_for(needle) >= count).then_some(()) })
            .await;
    }
}

async fn wait_for<T, F, Fut>(timeout: Duration, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(started.elapsed() < timeout, "condition not met within {timeout:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(250)).await;
}

// --------------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn applies_events_once_and_acks_after_commit() {
    let mut t = start().await;
    assert_eq!(
        t.submit_acked("a", "e1", "set_status", "ready", "peer-1", "d-1").await,
        SubmitOutcome::Inserted
    );
    t.wait_status("a", "ready").await;
    assert_eq!(t.wait_ack().await, AckRequest { peer: "peer-1".into(), delivery_id: "d-1".into() });
    let row = t.wait_inbox_state("e1", EngineInboxState::Applied).await;
    assert!(row.payload.is_none(), "payload cleared once applied");
    assert_eq!(row.attempts, 0);
    // Duplicate of an applied heavy message: ignored, ACKed again.
    assert_eq!(
        t.submit_acked("a", "e1", "set_status", "ready", "peer-1", "d-1").await,
        SubmitOutcome::Duplicate {
            state: EngineInboxState::Applied,
            ack_sent: true,
            rearmed: false
        }
    );
    assert_eq!(t.wait_ack().await.delivery_id, "d-1");
    let agg = t.agg("a");
    let bookkeeping = t.handle.aggregate(&agg).await.unwrap().unwrap();
    assert_eq!(bookkeeping.last_event_id.as_deref(), Some("e1"));
    assert_eq!(bookkeeping.version, 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_apply_rolls_back_effects_and_retries_as_one_transaction() {
    let t = start().await;
    t.submit("a", "e1", "effects_then_fail", "").await;
    let row = t.wait_inbox_attempts("e1", 1).await;
    assert_eq!(row.state, "Pending");
    assert_eq!(row.next_at, t.clock.now() + 1);
    assert!(row.last_error.as_deref().unwrap_or("").contains("fail once"));
    // Nothing from the failed attempt survived.
    {
        let mut s = t.db.acquire().await.unwrap();
        assert!(s.find_engine_outbox_message("e1:out").await.unwrap().is_none());
        assert!(s.list_engine_jobs_for_aggregate(KIND, "a").await.unwrap().is_empty());
        assert!(s.find_engine_aggregate(KIND, "a").await.unwrap().is_none());
    }
    assert_eq!(t.transport.count(), 0);
    // The retry commits everything together.
    t.clock.advance(1);
    t.wait_inbox_state("e1", EngineInboxState::Applied).await;
    t.wait_status("a", "should_not_persist_on_failure").await;
    {
        let mut s = t.db.acquire().await.unwrap();
        assert!(s.find_engine_outbox_message("e1:out").await.unwrap().is_some());
        assert_eq!(s.list_engine_jobs_for_aggregate(KIND, "a").await.unwrap().len(), 1);
    }
    t.wait_publishes("x", 1).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transient_failures_back_off_and_never_poison() {
    let t = start().await;
    t.submit("a", "e1", "transient", "3").await;
    for attempt in 1..=3 {
        let row = t.wait_inbox_attempts("e1", attempt).await;
        assert_eq!(row.state, "Pending", "attempt {attempt}");
        assert!(!t.handle.aggregate(&t.agg("a")).await.unwrap().is_some_and(|a| a.poisoned));
        t.clock.advance(1);
    }
    t.wait_status("a", "recovered").await;
    let row = t.wait_inbox_state("e1", EngineInboxState::Applied).await;
    assert_eq!(row.attempts, 3);
    assert!(t.handle.snapshot().await.unwrap().poisoned.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_timeout_is_a_transient_failure() {
    let t = start().await;
    t.submit("a", "e1", "slow", "2000").await;
    let row = t.wait_inbox_attempts("e1", 1).await;
    assert_eq!(row.state, "Pending");
    assert!(row.last_error.as_deref().unwrap_or("").contains("timed out"));
    assert!(t.handle.snapshot().await.unwrap().poisoned.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_poisons_wait_out_their_backoff() {
    let config = EngineConfig { poison_backoff: Backoff::Steps(vec![0, 3_600]), ..fast_config() };
    let t = start_with(config, async |_| {}).await;
    // The first poison is lifted by the next fact at once.
    t.submit("a", "e1", "panic", "").await;
    t.wait_inbox_state("e1", EngineInboxState::Poisoned).await;
    t.submit("a", "e2", "set_status", "alive").await;
    assert!(!t.wait_status("a", "alive").await.poisoned);
    // The second one stays for an hour, whatever facts arrive meanwhile.
    t.submit("a", "e3", "panic", "").await;
    t.wait_inbox_state("e3", EngineInboxState::Poisoned).await;
    t.submit("a", "e4", "set_status", "still").await;
    let agg = t.wait_status("a", "still").await;
    assert!(agg.poisoned, "the second poison waits out its backoff");
    assert_eq!(agg.poison_count, 2);
    // Once the backoff passed, the next fact lifts it.
    t.clock.advance(3_600);
    t.submit("a", "e5", "set_status", "later").await;
    assert!(!t.wait_status("a", "later").await.poisoned);
    // A manual clear starts the count over.
    t.submit("a", "e6", "panic", "").await;
    t.wait_inbox_state("e6", EngineInboxState::Poisoned).await;
    assert!(t.handle.clear_poison(&t.agg("a")).await.unwrap());
    assert_eq!(t.handle.aggregate(&t.agg("a")).await.unwrap().unwrap().poison_count, 0);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panics_and_invariants_poison_until_a_new_fact_applies() {
    let t = start().await;
    t.submit("a", "e1", "panic", "").await;
    let row = t.wait_inbox_state("e1", EngineInboxState::Poisoned).await;
    assert!(row.last_error.as_deref().unwrap_or("").contains("boom in apply"));
    let agg = wait_for(WAIT, || async {
        t.handle.aggregate(&t.agg("a")).await.unwrap().filter(|a| a.poisoned)
    })
    .await;
    assert_eq!(agg.poison_action.as_deref(), Some("panic"));
    assert_eq!(t.handle.snapshot().await.unwrap().poisoned.len(), 1);
    // Later events for the aggregate still apply, and a successful apply clears the flag.
    t.submit("a", "e2", "set_status", "alive").await;
    let agg = t.wait_status("a", "alive").await;
    assert!(!agg.poisoned);
    // An explicit invariant violation poisons too, and can be cleared by hand.
    t.submit("a", "e3", "invariant", "").await;
    t.wait_inbox_state("e3", EngineInboxState::Poisoned).await;
    assert!(t.handle.clear_poison(&t.agg("a")).await.unwrap());
    assert!(!t.handle.aggregate(&t.agg("a")).await.unwrap().unwrap().poisoned);
    // Poisoned rows are terminal: a duplicate is ignored.
    assert_eq!(
        t.submit("a", "e1", "panic", "").await,
        SubmitOutcome::Duplicate {
            state: EngineInboxState::Poisoned,
            ack_sent: false,
            rearmed: false
        }
    );
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_events_are_failed_acked_and_rearmed_by_a_duplicate() {
    let mut t = start().await;
    t.submit_acked("a", "e1", "reject", "", "peer-1", "d-1").await;
    let row = t.wait_inbox_state("e1", EngineInboxState::Failed).await;
    assert_eq!(row.last_error.as_deref(), Some("nope"));
    assert!(row.payload.is_some(), "rejected payload kept for inspection");
    assert_eq!(t.wait_ack().await.delivery_id, "d-1");
    // A duplicate re-arms the failed row; it is applied again and fails again.
    assert_eq!(
        t.submit_acked("a", "e1", "reject", "", "peer-1", "d-1").await,
        SubmitOutcome::Duplicate {
            state: EngineInboxState::Failed,
            ack_sent: false,
            rearmed: true
        }
    );
    let row = t.wait_inbox_attempts("e1", 2).await;
    assert_eq!(row.state, "Failed");
    assert_eq!(t.wait_ack().await.delivery_id, "d-1");
    // Unknown aggregate kinds have no handler and fail without an ACK.
    t.handle
        .submit(NewEvent::new(
            "e9",
            AggregateRef::new("nobody", "x"),
            "set_status",
            EventSource::Local,
            vec![],
        ))
        .await
        .unwrap();
    let row = t.wait_inbox_state("e9", EngineInboxState::Failed).await;
    assert!(row.last_error.as_deref().unwrap_or("").contains("no handler"));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_events_wake_when_the_dependency_changes() {
    let mut t = start().await;
    t.submit_acked("a", "e1", "wait_on", "test:dep|ready", "peer-1", "d-1").await;
    let row =
        wait_for(WAIT, || async { t.inbox("e1").await.filter(|row| row.waiting_ref.is_some()) })
            .await;
    assert_eq!(row.state, "Pending");
    assert_eq!(row.waiting_ref.as_deref(), Some("test:dep"));
    assert!(row.payload.is_some(), "parked events keep their payload");
    // Parked material is durable, so the heavy message is ACKed already.
    assert_eq!(t.wait_ack().await.delivery_id, "d-1");
    let snapshot = t.handle.snapshot().await.unwrap();
    assert_eq!(snapshot.waiting.len(), 1);
    assert_eq!(snapshot.waiting[0].waiting_detail.as_deref(), Some("need ready"));
    // A duplicate of a parked heavy message is ACKed again.
    assert_eq!(
        t.submit_acked("a", "e1", "wait_on", "test:dep|ready", "peer-1", "d-1").await,
        SubmitOutcome::Duplicate {
            state: EngineInboxState::Pending,
            ack_sent: true,
            rearmed: false
        }
    );
    assert_eq!(t.wait_ack().await.delivery_id, "d-1");
    // The dependency changing status wakes the waiter through the same commit.
    t.submit("dep", "e2", "set_status", "ready").await;
    t.wait_status("a", "unblocked").await;
    let row = t.wait_inbox_state("e1", EngineInboxState::Applied).await;
    assert!(row.waiting_ref.is_none());
    assert!(t.handle.snapshot().await.unwrap().waiting.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_events_are_rechecked_periodically_without_a_wakeup() {
    let t = start().await;
    t.submit("a", "e1", "wait_on", "test:dep|ready").await;
    wait_for(WAIT, || async { t.inbox("e1").await.and_then(|row| row.waiting_ref).map(|_| ()) })
        .await;
    // Change the dependency behind the engine's back: no wakeup is generated.
    {
        let mut s = t.db.acquire().await.unwrap();
        let update =
            store::EngineAggregateUpdate { status: Some("ready".into()), ..Default::default() };
        s.upsert_engine_aggregate(KIND, "dep", &update, t.clock.now()).await.unwrap();
    }
    t.wait_status("a", "unblocked").await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbox_republishes_with_backoff_until_acked_or_closed() {
    let t = start().await;
    t.submit("g", "e1", "send", "heavy|setup|p1:d1,p2:d2").await;
    t.submit("g", "e2", "send", "small|setup|").await;
    t.wait_publishes("heavy", 1).await;
    t.wait_publishes("small", 1).await;
    settle().await;
    assert_eq!(t.transport.count(), 2, "one publish per row until the backoff passes");
    // Backoff: 30 s after the first publish, 60 s after the second.
    t.clock.advance(30);
    t.wait_publishes("heavy", 2).await;
    t.wait_publishes("small", 2).await;
    t.clock.advance(30);
    settle().await;
    assert_eq!(t.transport.count(), 4);
    t.clock.advance(30);
    t.wait_publishes("heavy", 3).await;
    // ACKs close the heavy row only when the whole set answered.
    assert_eq!(
        t.handle.acknowledge("p1", "d1").await.unwrap(),
        EngineOutboxAck::Matched { outbox_id: "heavy".into(), closed: false }
    );
    assert_eq!(t.handle.acknowledge("p2", "wrong").await.unwrap(), EngineOutboxAck::NoMatch);
    assert_eq!(
        t.handle.acknowledge("p2", "d2").await.unwrap(),
        EngineOutboxAck::Matched { outbox_id: "heavy".into(), closed: true }
    );
    let heavy_before = t.transport.count_for("heavy");
    // Receiver evidence closes the small row through an apply.
    t.submit("g", "e3", "close_phase", "setup").await;
    t.wait_inbox_state("e3", EngineInboxState::Applied).await;
    t.clock.advance(600);
    settle().await;
    assert_eq!(t.transport.count_for("heavy"), heavy_before);
    assert_eq!(t.transport.count_for("small"), 3);
    {
        let mut s = t.db.acquire().await.unwrap();
        let small = s.find_engine_outbox_message("small").await.unwrap().unwrap();
        assert_eq!(
            (small.state.as_str(), small.close_reason.as_deref()),
            ("Closed", Some("evidence"))
        );
        let heavy = s.find_engine_outbox_message("heavy").await.unwrap().unwrap();
        assert_eq!(
            (heavy.state.as_str(), heavy.close_reason.as_deref()),
            ("Closed", Some("acked"))
        );
    }
    // Transport failures are recorded and retried.
    t.transport.fail.store(true, Ordering::SeqCst);
    t.submit("g", "e4", "send", "later|other|").await;
    let failed = wait_for(WAIT, || async {
        let mut s = t.db.acquire().await.unwrap();
        s.find_engine_outbox_message("later").await.unwrap().filter(|row| row.last_error.is_some())
    })
    .await;
    assert_eq!(failed.publish_count, 0);
    t.transport.fail.store(false, Ordering::SeqCst);
    t.clock.advance(30);
    t.wait_publishes("later", 1).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_results_come_back_as_events_and_are_validated_against_the_phase() {
    let t = start().await;
    t.submit("a", "e1", "job", "echo|phase1|hello").await;
    let job_id = engine::stable_job_id(&t.agg("a"), "phase1", "echo", b"hello");
    let job = t.wait_job_state(&job_id, "Done").await;
    assert_eq!(job.result.as_deref(), Some(b"hello".as_slice()));
    assert_eq!(job.generation, 1);
    t.wait_status("a", "job_done:hello").await;
    let result_event =
        t.wait_inbox_state(&JobResultEvent::event_id(&job_id, 1), EngineInboxState::Applied).await;
    assert_eq!(result_event.source, "job");
    // Re-creating the same job is a no-op.
    t.submit("a", "e2", "job", "echo|phase1|hello").await;
    t.wait_inbox_state("e2", EngineInboxState::Applied).await;
    settle().await;
    assert_eq!(t.wait_job_state(&job_id, "Done").await.attempts, 1);
    // A result that arrives after the phase moved on is rejected by the aggregate.
    t.submit("a", "e3", "job", "gated|phase2|slow").await;
    let gated_id = engine::stable_job_id(&t.agg("a"), "phase2", "gated", b"slow");
    t.wait_job_state(&gated_id, "Running").await;
    t.submit("a", "e4", "set_phase", "phase3").await;
    t.wait_inbox_state("e4", EngineInboxState::Applied).await;
    t.gate.send(true).unwrap();
    t.wait_job_state(&gated_id, "Done").await;
    let stale_phase =
        t.wait_inbox_state(&JobResultEvent::event_id(&gated_id, 1), EngineInboxState::Failed).await;
    assert!(stale_phase.last_error.as_deref().unwrap_or("").contains("phase2"));
    assert_eq!(t.handle.aggregate(&t.agg("a")).await.unwrap().unwrap().status, "job_done:hello");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_holder_is_fenced_and_its_external_result_is_reconciled() {
    let t = start().await;
    t.submit("a", "e1", "job", "gated|p|x").await;
    let job_id = engine::stable_job_id(&t.agg("a"), "p", "gated", b"x");
    let first = t.wait_job_state(&job_id, "Running").await;
    assert_eq!(first.generation, 1);
    // The lease (1 s) lapses without renewal; the executor claims generation 2
    // while the first holder is still running.
    t.clock.advance(2);
    let second = wait_for(WAIT, || async {
        let mut s = t.db.acquire().await.unwrap();
        s.find_engine_job(&job_id).await.unwrap().filter(|job| job.generation == 2)
    })
    .await;
    assert_eq!((second.state.as_str(), second.attempts), ("Running", 2));
    // Both holders finish; only generation 2 may write the row.
    t.gate.send(true).unwrap();
    let done = t.wait_job_state(&job_id, "Done").await;
    assert_eq!(done.generation, 2);
    assert_eq!(done.result.as_deref(), Some(b"gen2".as_slice()));
    // Both completions reach the aggregate as events: the fresh one advances
    // the status, the stale one is reconciled (recorded in the state).
    let fresh =
        t.wait_inbox_state(&JobResultEvent::event_id(&job_id, 2), EngineInboxState::Applied).await;
    assert_eq!(fresh.source, "job");
    let stale =
        t.wait_inbox_state(&JobResultEvent::event_id(&job_id, 1), EngineInboxState::Applied).await;
    assert_eq!(stale.source, "job");
    let agg = t.wait_status("a", "job_done:gen2").await;
    assert_eq!(agg.state.as_deref(), Some("stale_seen"), "stale result reached the aggregate");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_completion_waits_out_a_long_write_lock_instead_of_rerunning() {
    // A short busy timeout makes every blocked statement fail fast, like a
    // long apply would make them fail against the 5 s default.
    let t = start_with_busy_timeout(fast_config(), Duration::from_millis(300), async |_| {}).await;
    t.submit("a", "e1", "job", "gated|p|x").await;
    let job_id = engine::stable_job_id(&t.agg("a"), "p", "gated", b"x");
    t.wait_job_state(&job_id, "Running").await;
    // Hold the write lock well past the old retry budget while the job finishes.
    let blocker = t.db.start_immediate_transaction().await.unwrap();
    t.gate.send(true).unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(t.wait_job_state(&job_id, "Running").await.generation, 1, "still the first holder");
    drop(blocker);
    let done = t.wait_job_state(&job_id, "Done").await;
    assert_eq!(
        (done.generation, done.attempts),
        (1, 1),
        "recorded by the original holder, not re-run"
    );
    t.wait_status("a", "job_done:gen1").await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_acks_close_the_row_exactly_once() {
    let t = start().await;
    let acks: Vec<String> = (0..8).map(|i| format!("p{i}:d{i}")).collect();
    t.submit("g", "e1", "send", &format!("heavy|setup|{}", acks.join(","))).await;
    t.wait_publishes("heavy", 1).await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        let handle = t.handle.clone();
        tasks.push(tokio::spawn(async move {
            handle.acknowledge(&format!("p{i}"), &format!("d{i}")).await.unwrap()
        }));
    }
    let mut closed = 0;
    for task in tasks {
        match task.await.unwrap() {
            EngineOutboxAck::Matched { outbox_id, closed: was_closed } => {
                assert_eq!(outbox_id, "heavy");
                closed += usize::from(was_closed);
            }
            EngineOutboxAck::NoMatch => panic!("every ACK must match"),
        }
    }
    assert_eq!(closed, 1, "exactly one ACK closes the row");
    let mut s = t.db.acquire().await.unwrap();
    let row = s.find_engine_outbox_message("heavy").await.unwrap().unwrap();
    assert_eq!((row.state.as_str(), row.close_reason.as_deref()), ("Closed", Some("acked")));
    assert!(row.ack_set.unwrap().is_empty());
    drop(s);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_transient_failures_retry_and_panics_poison_the_action() {
    let t = start().await;
    t.submit("a", "e1", "job", "flaky|p|").await;
    let flaky_id = engine::stable_job_id(&t.agg("a"), "p", "flaky", b"");
    for attempt in 1..=2 {
        let job = wait_for(WAIT, || async {
            let mut s = t.db.acquire().await.unwrap();
            s.find_engine_job(&flaky_id)
                .await
                .unwrap()
                .filter(|job| job.attempts == attempt && job.state == "Pending")
        })
        .await;
        assert!(job.last_error.as_deref().unwrap_or("").contains("attempt"));
        t.clock.advance(1);
    }
    let job = t.wait_job_state(&flaky_id, "Done").await;
    assert_eq!(job.attempts, 3);
    t.wait_status("a", "job_done:flaky-ok").await;
    // Permanent failure is reported, not retried.
    t.submit("a", "e2", "job", "fail|p|").await;
    let fail_id = engine::stable_job_id(&t.agg("a"), "p", "fail", b"");
    assert_eq!(t.wait_job_state(&fail_id, "Failed").await.attempts, 1);
    t.wait_status("a", "job_failed:permanent").await;
    // A panic poisons the job and isolates the action on the aggregate.
    t.submit("a", "e3", "job", "boom|p|first").await;
    let boom_id = engine::stable_job_id(&t.agg("a"), "p", "boom", b"first");
    t.wait_job_state(&boom_id, "Poisoned").await;
    let agg = wait_for(WAIT, || async {
        t.handle.aggregate(&t.agg("a")).await.unwrap().filter(|a| a.poisoned)
    })
    .await;
    assert_eq!(agg.poison_action.as_deref(), Some("boom"));
    t.wait_status("a", "job_poisoned:boom in job").await;
    assert!(
        t.handle.aggregate(&t.agg("a")).await.unwrap().unwrap().poisoned,
        "a job result does not lift the poison"
    );
    // A second job for the poisoned action, created without a new event, is
    // held back by the executor while the poison stands.
    let second_id = engine::stable_job_id(&t.agg("a"), "p", "boom", b"second");
    {
        let mut s = t.db.acquire().await.unwrap();
        assert!(
            s.insert_engine_job(
                &store::NewEngineJob {
                    job_id: second_id.clone(),
                    aggregate_kind: KIND.into(),
                    aggregate_id: "a".into(),
                    phase: "p".into(),
                    action: "boom".into(),
                    pool: "cpu".into(),
                    params: b"second".to_vec(),
                    deadline_at: None,
                    first_at: t.clock.now(),
                },
                t.clock.now(),
            )
            .await
            .unwrap()
        );
    }
    t.handle.wake_all();
    settle().await;
    assert_eq!(
        t.wait_job_state(&second_id, "Pending").await.attempts,
        0,
        "same action is held back"
    );
    // A new fact clears the poison: other actions keep running and the held
    // job runs too (and poisons the action again).
    t.submit("a", "e5", "job", "echo|p|still-works").await;
    let echo_id = engine::stable_job_id(&t.agg("a"), "p", "echo", b"still-works");
    t.wait_job_state(&echo_id, "Done").await;
    t.wait_inbox_state(&JobResultEvent::event_id(&echo_id, 1), EngineInboxState::Applied).await;
    t.wait_job_state(&second_id, "Poisoned").await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_of_one_aggregate_apply_strictly_in_order() {
    let t = start().await;
    for index in 0..12 {
        t.submit("serial", &format!("s{index}"), "serial_probe", "").await;
    }
    for index in 0..12 {
        t.wait_inbox_state(&format!("s{index}"), EngineInboxState::Applied).await;
    }
    assert_eq!(t.probe.max_concurrent.load(Ordering::SeqCst), 1);
    // Applied in arrival order.
    let mut s = t.db.acquire().await.unwrap();
    let rows = s.list_engine_inbox_events_for_aggregate(KIND, "serial", 20).await.unwrap();
    let applied: Vec<i64> = rows.iter().map(|row| row.applied_at.unwrap()).collect();
    let mut sorted = applied.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(applied, sorted);
    drop(s);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_recovery_rearms_events_and_reclaims_leases() {
    let job_id = engine::stable_job_id(&AggregateRef::new(KIND, "a"), "p", "echo", b"recover");
    let t = start_with(fast_config(), async |db: &LocalDB| {
        let mut s = db.acquire().await.unwrap();
        // A pending event parked far in the future by a previous process.
        s.insert_engine_inbox_event(
            &store::NewEngineInboxEvent {
                event_id: "old".into(),
                aggregate_kind: KIND.into(),
                aggregate_id: "a".into(),
                kind: "set_status".into(),
                source: "local".into(),
                author: String::new(),
                payload: b"recovered".to_vec(),
                ack: None,
            },
            1,
        )
        .await
        .unwrap();
        s.mark_engine_inbox_retry("old", "busy", i64::MAX / 2, 1).await.unwrap();
        // A job claimed by a dead process, lease far in the future.
        s.insert_engine_job(
            &store::NewEngineJob {
                job_id: job_id.clone(),
                aggregate_kind: KIND.into(),
                aggregate_id: "a".into(),
                phase: "p".into(),
                action: "echo".into(),
                pool: "cpu".into(),
                params: b"recover".to_vec(),
                deadline_at: None,
                first_at: 1,
            },
            1,
        )
        .await
        .unwrap();
        let claimed = s.claim_due_engine_jobs("cpu", 1, i64::MAX / 2, 1).await.unwrap();
        assert_eq!(claimed[0].generation, 1);
        // An outbox row leased by the dead process.
        s.insert_engine_outbox_message(
            &store::NewEngineOutboxMessage {
                outbox_id: "leased".into(),
                aggregate_kind: KIND.into(),
                aggregate_id: "a".into(),
                phase_ref: "p".into(),
                kind: "Msg".into(),
                topic: "t".into(),
                payload: b"leased".to_vec(),
                ack_set: None,
                first_at: 1,
            },
            1,
        )
        .await
        .unwrap();
        assert_eq!(s.claim_due_engine_outbox_messages(1, i64::MAX / 2, 1).await.unwrap().len(), 1);
    })
    .await;
    t.wait_status("a", "recovered").await;
    let job = t.wait_job_state(&job_id, "Done").await;
    assert_eq!(job.generation, 2, "re-claimed with a new generation");
    t.wait_publishes("leased", 1).await;
    t.stop().await;
}
