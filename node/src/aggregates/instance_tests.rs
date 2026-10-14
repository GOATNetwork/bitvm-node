//! Instance lifecycle tests using the engine and SQLite, covering failure
//! states, signing deadlines, the abandon buffer and cleanup effects.

use super::common::{InboundMessage, MembershipProbe, PlannedMessage, content_event_id};
use super::instance::*;
use crate::utils::{mark_graph_as_endorsed, store_committee_partial_sig_for_instance};
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use engine::{
    Backoff, EngineBuilder, EngineConfig, EngineHandle, EngineInboxState, EventSource, JobContext,
    JobOutcome, JobRunner, NewEvent,
};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::localdb::LocalDB;
use store::{
    Graph, GraphStatus, Instance, InstanceBridgeInStatus, NewEngineInboxEvent, NewEngineJob,
    NewEngineOutboxMessage,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DEADLINES: PeginDeadlines =
    PeginDeadlines { t0_blocks: 60, buffer_blocks: 6, key_delete_blocks: 32 };
const PREPARE: i64 = 1_000;
const WAIT: Duration = Duration::from_secs(10);
const LOCAL_PEER: &str = "12D3KooWLocalPeer";
const OTHER_PEER: &str = "12D3KooWOtherPeer";

struct Harness {
    db: LocalDB,
    _dir: tempfile::TempDir,
    handle: EngineHandle,
    cancel: CancellationToken,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
    jobs: Arc<Scripted>,
}

struct StubKeyDelete;

#[async_trait]
impl JobRunner for StubKeyDelete {
    async fn run(&self, _ctx: JobContext) -> JobOutcome {
        let result = KeyDeleteResult { deleted: true, detail: "stub".into() };
        JobOutcome::Done(serde_json::to_vec(&result).unwrap())
    }
}

struct StubPost;

#[async_trait]
impl JobRunner for StubPost {
    async fn run(&self, _ctx: JobContext) -> JobOutcome {
        JobOutcome::Done(b"posted".to_vec())
    }
}

/// Returns the scripted plan for an action and records what it was asked.
#[derive(Default)]
struct Scripted {
    plans: Mutex<HashMap<String, InstancePlan>>,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait]
impl JobRunner for Scripted {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let params = ctx.job.params.clone().unwrap_or_default();
        self.calls.lock().unwrap().push((ctx.job.action.clone(), params));
        let plan = self.plans.lock().unwrap().remove(&ctx.job.action).unwrap_or_default();
        JobOutcome::Done(plan.encode().unwrap())
    }
}

/// Every instance is this node's (the production probe looks for the key
/// envelope on disk).
struct Member;

impl MembershipProbe for Member {
    fn holds_instance_key(&self, _instance_id: Uuid) -> bool {
        true
    }
}

/// A node outside every committee.
struct Outsider;

impl MembershipProbe for Outsider {
    fn holds_instance_key(&self, _instance_id: Uuid) -> bool {
        false
    }
}

/// Every test graph takes its own operator slot (`(operator, nonce)` is unique).
static NEXT_SLOT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

fn fast_config() -> EngineConfig {
    EngineConfig {
        worker_count: 1,
        thread_stack_bytes: 0,
        apply_timeout: Duration::from_secs(5),
        worker_poll_interval: Duration::from_millis(30),
        recheck_interval: Duration::from_millis(250),
        inbox_retry_backoff: Backoff::Steps(vec![1]),
        job_lease_secs: 5,
        job_poll_interval: Duration::from_millis(30),
        outbox_poll_interval: Duration::from_millis(30),
        ..EngineConfig::default()
    }
}

async fn start(actor: Actor, relayer: bool, key_delete_enabled: bool) -> Harness {
    start_with(actor, relayer, key_delete_enabled, Arc::new(Member)).await
}

async fn start_with(
    actor: Actor,
    relayer: bool,
    key_delete_enabled: bool,
    membership: Arc<dyn MembershipProbe>,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("instance.db");
    let db = LocalDB::new_with_busy_timeout(
        &format!("sqlite:{}", path.display()),
        false,
        store::DEFAULT_BUSY_TIMEOUT,
    )
    .await;
    db.migrate().await;
    let jobs = Arc::new(Scripted::default());
    let mut builder = EngineBuilder::new(db.clone(), fast_config())
        .handler(
            INSTANCE_KIND,
            Arc::new(
                InstanceAggregate::new(
                    actor,
                    DEADLINES,
                    relayer,
                    key_delete_enabled,
                    LOCAL_PEER.to_string(),
                )
                .with_membership(membership),
            ),
        )
        .job_runner(INSTANCE_KIND, JOB_DELETE_INSTANCE_KEY, Arc::new(StubKeyDelete))
        .job_runner(INSTANCE_KIND, JOB_POST_PEGIN_DATA, Arc::new(StubPost));
    for action in INSTANCE_JOBS {
        let runner: Arc<dyn JobRunner> = jobs.clone();
        builder = builder.job_runner(INSTANCE_KIND, *action, runner);
    }
    let (engine, _acks) = builder.build();
    let handle = engine.handle();
    let cancel = CancellationToken::new();
    let run = tokio::spawn(engine.run(cancel.clone()));
    Harness { db, _dir: dir, handle, cancel, run, jobs }
}

fn instance_row(status: InstanceBridgeInStatus, prepare_height: i64) -> Instance {
    Instance {
        instance_id: Uuid::new_v4(),
        network: "regtest".to_string(),
        input_utxos: "[]".to_string(),
        status: status.to_string(),
        goat_tx_height: 100,
        btc_height: prepare_height,
        created_at: 1,
        updated_at: 1,
        ..Default::default()
    }
}

impl Harness {
    async fn stop(self) {
        self.cancel.cancel();
        self.run.await.unwrap().unwrap();
    }

    async fn insert(&self, instance: &Instance) -> Uuid {
        let mut storage = self.db.acquire().await.unwrap();
        assert!(storage.insert_instance_if_absent(instance).await.unwrap());
        instance.instance_id
    }

    async fn insert_graph(&self, instance_id: Uuid) -> Uuid {
        let graph = Graph {
            graph_id: Uuid::new_v4(),
            instance_id,
            status: GraphStatus::OperatorPresigned.to_string(),
            definition_hash: "definition".to_string(),
            operator_pubkey: "operator".to_string(),
            kickoff_index: NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ..Default::default()
        };
        let mut storage = self.db.acquire().await.unwrap();
        storage.upsert_graph_definition(&graph).await.unwrap();
        graph.graph_id
    }

    fn script(&self, action: &str, plan: InstancePlan) {
        self.jobs.plans.lock().unwrap().insert(action.to_string(), plan);
    }

    fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.jobs.calls.lock().unwrap().clone()
    }

    /// A PeginConfirm round message event as `inbound_event` builds it; the
    /// apply only reads the envelope.
    fn round_message(&self, kind: &str, author: &str, instance_id: Uuid) -> NewEvent {
        let inbound = InboundMessage {
            author: author.to_string(),
            instance_id,
            graph_nonce: None,
            operator_pubkey: None,
            message: format!("{kind}:{instance_id}:{author}").into_bytes(),
        };
        NewEvent::new(
            content_event_id(author, kind, &instance_id.to_string(), &inbound.message),
            instance_ref(instance_id),
            kind,
            EventSource::Network,
            inbound.encode().unwrap(),
        )
        .with_author(author)
    }

    async fn jobs_of(&self, instance_id: Uuid) -> Vec<store::EngineJob> {
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .list_engine_jobs_for_aggregate(INSTANCE_KIND, &instance_id.to_string())
            .await
            .unwrap()
    }

    async fn wait_job(&self, instance_id: Uuid, action: &str, state: &str) -> store::EngineJob {
        wait_for(|| async {
            self.jobs_of(instance_id)
                .await
                .into_iter()
                .find(|job| job.action == action && job.state == state)
        })
        .await
    }

    async fn outbox(&self, outbox_id: &str) -> Option<store::EngineOutboxMessage> {
        self.db.acquire().await.unwrap().find_engine_outbox_message(outbox_id).await.unwrap()
    }

    async fn wait_outbox(&self, outbox_id: &str, state: &str) -> store::EngineOutboxMessage {
        wait_for(|| async { self.outbox(outbox_id).await.filter(|row| row.state == state) }).await
    }

    async fn insert_open_outbox(&self, instance_id: Uuid) -> String {
        let outbox_id = format!("outbox:{instance_id}");
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .insert_engine_outbox_message(
                &NewEngineOutboxMessage {
                    outbox_id: outbox_id.clone(),
                    aggregate_kind: INSTANCE_KIND.to_string(),
                    aggregate_id: instance_id.to_string(),
                    phase_ref: PHASE_CONFIRM.to_string(),
                    kind: "PeginConfirmNonce".to_string(),
                    topic: "topic".to_string(),
                    payload: b"nonce".to_vec(),
                    ack_set: None,
                    first_at: 1,
                },
                1,
            )
            .await
            .unwrap();
        outbox_id
    }

    async fn submit(&self, event: NewEvent) {
        self.handle.submit(event).await.unwrap();
    }

    async fn submit_id(&self, event: NewEvent) -> String {
        let event_id = event.event_id.clone();
        self.handle.submit(event).await.unwrap();
        event_id
    }

    /// A setup session of the operator's graph that has no row yet, with an
    /// open delivery and a pending job of that graph.
    async fn insert_pending_session(&self, instance_id: Uuid, graph_id: Uuid) -> (String, String) {
        use crate::aggregates::graph::GRAPH_KIND;
        let mut storage = self.db.acquire().await.unwrap();
        storage.upsert_pending_graph_init(&instance_id, "operator", &graph_id).await.unwrap();
        let outbox_id = format!("graph:{graph_id}:InitGraph");
        storage
            .insert_engine_outbox_message(
                &NewEngineOutboxMessage {
                    outbox_id: outbox_id.clone(),
                    aggregate_kind: GRAPH_KIND.to_string(),
                    aggregate_id: graph_id.to_string(),
                    phase_ref: "Setup".to_string(),
                    kind: "InitGraph".to_string(),
                    topic: "topic".to_string(),
                    payload: b"init".to_vec(),
                    ack_set: None,
                    first_at: 1,
                },
                1,
            )
            .await
            .unwrap();
        let job_id = format!("job:{graph_id}");
        let far = crate::rpc_service::current_time_secs() + 3_600;
        storage
            .insert_engine_job(
                &NewEngineJob {
                    job_id: job_id.clone(),
                    aggregate_kind: GRAPH_KIND.to_string(),
                    aggregate_id: graph_id.to_string(),
                    phase: "graph".to_string(),
                    action: "freeze_candidates".to_string(),
                    pool: "Network".to_string(),
                    params: Vec::new(),
                    deadline_at: None,
                    first_at: far,
                },
                1,
            )
            .await
            .unwrap();
        (outbox_id, job_id)
    }

    /// An instance event of a missing instance, parked on `wake_ref` as a
    /// waiting start would be; once woken it re-parks on its own ref.
    async fn insert_parked_event(&self, wake_ref: &str) -> String {
        let event_id = format!("parked:{}", Uuid::new_v4());
        let now = crate::rpc_service::current_time_secs();
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .insert_engine_inbox_event(
                &NewEngineInboxEvent {
                    event_id: event_id.clone(),
                    aggregate_kind: INSTANCE_KIND.to_string(),
                    aggregate_id: Uuid::new_v4().to_string(),
                    kind: EVENT_L2_MINTED.to_string(),
                    source: "local".to_string(),
                    author: String::new(),
                    admission_class: String::new(),
                    payload: Vec::new(),
                    ack: None,
                },
                now,
            )
            .await
            .unwrap();
        assert!(
            storage
                .mark_engine_inbox_waiting(&event_id, wake_ref, "test", now + 3_600, now)
                .await
                .unwrap()
        );
        event_id
    }

    async fn waiting_ref(&self, event_id: &str) -> Option<String> {
        self.db
            .acquire()
            .await
            .unwrap()
            .find_engine_inbox_event(event_id)
            .await
            .unwrap()
            .unwrap()
            .waiting_ref
    }

    async fn snapshot(&self, instance_id: Uuid, snapshot: BtcSnapshot) {
        self.submit(snapshot.event(instance_id).unwrap()).await;
    }

    async fn instance(&self, instance_id: Uuid) -> Instance {
        self.db.acquire().await.unwrap().find_instance(&instance_id).await.unwrap().unwrap()
    }

    async fn wait_status(&self, instance_id: Uuid, status: InstanceBridgeInStatus) -> Instance {
        wait_for(|| async {
            let instance = self.instance(instance_id).await;
            (instance.status == status.to_string()).then_some(instance)
        })
        .await
    }

    async fn wait_key_deleted(&self, instance_id: Uuid) {
        wait_for(|| async { self.instance(instance_id).await.key_deleted.then_some(()) }).await;
    }

    async fn wait_applied(&self, event_id: &str) {
        wait_for(|| async {
            let mut storage = self.db.acquire().await.unwrap();
            storage
                .find_engine_inbox_event(event_id)
                .await
                .unwrap()
                .filter(|row| row.state == EngineInboxState::Applied.to_string())
                .map(|_| ())
        })
        .await;
    }

    async fn graph_status(&self, graph_id: Uuid) -> String {
        self.db.acquire().await.unwrap().find_graph(&graph_id).await.unwrap().unwrap().status
    }

    async fn outbox_state(&self, outbox_id: &str) -> String {
        self.db
            .acquire()
            .await
            .unwrap()
            .find_engine_outbox_message(outbox_id)
            .await
            .unwrap()
            .unwrap()
            .state
    }

    async fn job_actions(&self, instance_id: Uuid) -> Vec<String> {
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .list_engine_jobs_for_aggregate(INSTANCE_KIND, &instance_id.to_string())
            .await
            .unwrap()
            .into_iter()
            .map(|job| job.action)
            .collect()
    }

    async fn engine_status(&self, instance_id: Uuid) -> (String, String) {
        let row = self.handle.aggregate(&instance_ref(instance_id)).await.unwrap().unwrap();
        (row.status, row.phase)
    }
}

async fn wait_for<T, F, Fut>(mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(started.elapsed() < WAIT, "condition not met within {WAIT:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

fn at(height: i64, status: InstanceBridgeInStatus) -> BtcSnapshot {
    BtcSnapshot { height, status_at_scan: status.to_string(), ..Default::default() }
}

fn presign_snapshot(height: i64, confirm: TxFact, cancel: TxFact) -> BtcSnapshot {
    BtcSnapshot {
        confirm: Some(confirm),
        cancel: Some(cancel),
        ..at(height, InstanceBridgeInStatus::Presigned)
    }
}

// ----------------------------------------------------------------- failures

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_discarded_enters_failure_with_every_effect() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, true).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let graph_id = t.insert_graph(id).await;
    let outbox_id = t.insert_open_outbox(id).await;

    let mut snapshot = at(10, CommitteesAnswered);
    snapshot.inputs_available = Some(false);
    t.snapshot(id, snapshot).await;

    t.wait_status(id, UserDiscarded).await;
    assert_eq!(t.graph_status(graph_id).await, GraphStatus::Obsoleted.to_string());
    assert_eq!(t.outbox_state(&outbox_id).await, "Closed");
    t.wait_key_deleted(id).await;
    assert_eq!(t.job_actions(id).await, vec![JOB_DELETE_INSTANCE_KEY.to_string()]);
    assert_eq!(t.engine_status(id).await, (UserDiscarded.to_string(), PHASE_FAILED.to_string()));

    // Failure is terminal: a later Prepare confirmation changes nothing.
    let mut late = at(20, UserDiscarded);
    late.prepare = Some(TxFact::confirmed_at(19));
    t.snapshot(id, late).await;
    settle().await;
    assert_eq!(t.instance(id).await.status, UserDiscarded.to_string());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_enough_committees_answered_when_the_window_closes_below_quorum() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, true).await;
    let id = t.insert(&instance_row(UserInited, 0)).await;
    let mut answers = IndexMap::new();
    answers.insert("0xa".to_string(), vec![1u8; 33]);
    let window = AnswerWindow { goat_height: 200, window_blocks: 50, quorum: 2, answers };
    t.submit(window.event(id).unwrap()).await;
    let instance = t.wait_status(id, NoEnoughCommitteesAnswered).await;
    assert_eq!(instance.committees_answers.len(), 1);
    t.wait_key_deleted(id).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committees_answered_at_quorum_keeps_the_key() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, true).await;
    let id = t.insert(&instance_row(UserInited, 0)).await;
    let mut answers = IndexMap::new();
    answers.insert("0xa".to_string(), vec![1u8; 33]);
    answers.insert("0xb".to_string(), vec![2u8; 33]);
    let window = AnswerWindow { goat_height: 200, window_blocks: 50, quorum: 2, answers };
    t.submit(window.event(id).unwrap()).await;
    let instance = t.wait_status(id, CommitteesAnswered).await;
    assert_eq!(instance.committees_answers.len(), 2);
    assert!(!instance.key_deleted);
    assert!(t.job_actions(id).await.is_empty());
    assert_eq!(t.engine_status(id).await.1, PHASE_AWAIT_PREPARE);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_canceled_from_the_confirm_phase_deletes_the_key() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, true).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let graph_id = t.insert_graph(id).await;
    t.snapshot(id, presign_snapshot(1_070, TxFact::UNKNOWN, TxFact::confirmed_at(1_069))).await;
    t.wait_status(id, UserCanceled).await;
    assert_eq!(t.graph_status(graph_id).await, GraphStatus::Obsoleted.to_string());
    t.wait_key_deleted(id).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_instance_keeps_the_settlement_jobs_of_its_graphs() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, true).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let graph_id = t.insert_graph(id).await;
    let job = |job_id: &str, phase: &str, action: &str| store::NewEngineJob {
        job_id: job_id.to_string(),
        aggregate_kind: "graph".to_string(),
        aggregate_id: graph_id.to_string(),
        phase: phase.to_string(),
        action: action.to_string(),
        pool: "network".to_string(),
        params: Vec::new(),
        deadline_at: None,
        first_at: i64::MAX,
    };
    {
        let mut storage = t.db.acquire().await.unwrap();
        for (job_id, phase, action) in [
            ("setup", crate::aggregates::graph::JOB_PHASE, "committee_presign"),
            ("post", crate::aggregates::graph::PHASE_POST, "post_graph_data"),
            ("challenge", "Settlement", "challenge_kickoff"),
        ] {
            assert!(
                storage
                    .insert_engine_job(&job(job_id, phase, action), 1)
                    .await
                    .unwrap()
                    .is_inserted()
            );
        }
    }
    t.snapshot(id, presign_snapshot(1_070, TxFact::UNKNOWN, TxFact::confirmed_at(1_069))).await;
    t.wait_status(id, UserCanceled).await;
    assert_eq!(t.graph_status(graph_id).await, GraphStatus::Obsoleted.to_string());
    let mut storage = t.db.acquire().await.unwrap();
    for (job_id, state) in [("setup", "Cancelled"), ("post", "Cancelled"), ("challenge", "Pending")]
    {
        assert_eq!(
            storage.find_engine_job(job_id).await.unwrap().unwrap().state,
            state,
            "{job_id}"
        );
    }
    drop(storage);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeout_keeps_the_key_until_cancel_confirms() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, true).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let graph_id = t.insert_graph(id).await;
    let outbox_id = t.insert_open_outbox(id).await;

    // Buffer not over: nothing happens.
    t.snapshot(id, presign_snapshot(1_065, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    settle().await;
    assert_eq!(t.instance(id).await.status, Presigned.to_string());

    // Abandon height, Peg-In-Confirm neither confirmed nor in the mempool.
    t.snapshot(id, presign_snapshot(1_066, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    let instance = t.wait_status(id, Timeout).await;
    assert!(!instance.key_deleted);
    assert_eq!(t.graph_status(graph_id).await, GraphStatus::Obsoleted.to_string());
    assert_eq!(t.outbox_state(&outbox_id).await, "Closed");
    assert!(t.job_actions(id).await.is_empty(), "Timeout must not delete the key");

    // A late Peg-In-Confirm only alerts.
    let mut late = at(1_080, Timeout);
    late.confirm = Some(TxFact::confirmed_at(1_079));
    late.cancel = Some(TxFact::UNKNOWN);
    t.snapshot(id, late).await;
    settle().await;
    assert_eq!(t.instance(id).await.status, Timeout.to_string());

    // Cancel confirmed: UserCanceled and the key goes.
    let mut cancel = at(1_090, Timeout);
    cancel.confirm = Some(TxFact::UNKNOWN);
    cancel.cancel = Some(TxFact::confirmed_at(1_089));
    t.snapshot(id, cancel).await;
    t.wait_status(id, UserCanceled).await;
    t.wait_key_deleted(id).await;
    t.stop().await;
}

// ------------------------------------------------------------------ success

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mempool_visibility_defers_abandon_and_confirmation_completes_the_pegin() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, true).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;

    // Past the abandon height but visible in the mempool: keep waiting.
    t.snapshot(id, presign_snapshot(1_066, TxFact::mempool(), TxFact::UNKNOWN)).await;
    t.snapshot(id, presign_snapshot(1_100, TxFact::mempool(), TxFact::UNKNOWN)).await;
    settle().await;
    assert_eq!(t.instance(id).await.status, Presigned.to_string());

    // Confirmed late: L1 broadcast state, relayer post job, then the mint.
    t.snapshot(id, presign_snapshot(1_101, TxFact::confirmed_at(1_101), TxFact::UNKNOWN)).await;
    t.wait_status(id, RelayerL1Broadcasted).await;
    assert_eq!(t.engine_status(id).await.1, PHASE_POST);
    wait_for(|| async {
        t.job_actions(id).await.contains(&JOB_POST_PEGIN_DATA.to_string()).then_some(())
    })
    .await;

    t.submit(l2_minted_event(id, "0xmint").unwrap()).await;
    let instance = t.wait_status(id, RelayerL2Minted).await;
    assert_eq!(instance.post_pegin_txhash.as_deref(), Some("0xmint"));
    assert_eq!(t.engine_status(id).await.1, PHASE_DONE);

    // Success-side key deletion once the depth is reached.
    let mut deep = at(1_133, RelayerL2Minted);
    deep.confirm = Some(TxFact::confirmed_at(1_101));
    t.snapshot(id, deep).await;
    t.wait_key_deleted(id).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepare_confirmation_records_the_height_and_triggers_confirm_instance() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Operator, false, false).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let mut snapshot = at(500, CommitteesAnswered);
    snapshot.prepare = Some(TxFact::confirmed_at(480));
    t.snapshot(id, snapshot).await;
    let instance = t.wait_status(id, UserBroadcastPeginPrepare).await;
    assert_eq!(instance.btc_height, 480);
    // Every role stores the parameters through the Presign-phase job.
    let job = t.wait_job(id, JOB_CONFIRM_INSTANCE, "Done").await;
    assert_eq!(job.phase, PHASE_PRESIGN);
    assert_eq!(t.engine_status(id).await.1, PHASE_PRESIGN);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirm_plan_opens_the_operator_session_and_starts_the_graph() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Operator, false, false).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let graph_id = Uuid::new_v4();
    let plan = InstancePlan {
        start_graph: Some(StartGraph { graph_id, operator_pubkey: "operator".to_string() }),
        ..Default::default()
    };
    t.script(JOB_CONFIRM_INSTANCE, plan);
    let mut snapshot = at(500, CommitteesAnswered);
    snapshot.prepare = Some(TxFact::confirmed_at(480));
    t.snapshot(id, snapshot).await;
    t.wait_job(id, JOB_CONFIRM_INSTANCE, "Done").await;
    // The session and the Graph aggregate's start event are committed together.
    let start_id =
        crate::aggregates::graph::operator_start_event(id, graph_id, "operator").unwrap().event_id;
    wait_for(|| async {
        let mut storage = t.db.acquire().await.unwrap();
        storage.find_engine_inbox_event(&start_id).await.unwrap().map(|_| ())
    })
    .await;
    let session =
        t.db.acquire()
            .await
            .unwrap()
            .find_pending_graph_init_by_instance_and_operator_pubkey(&id, "operator")
            .await
            .unwrap()
            .expect("setup session opened");
    assert_eq!(session.graph_id, graph_id);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pegin_request_is_answered_by_committee_nodes_until_the_window_closes() {
    use InstanceBridgeInStatus::*;
    let request = PeginRequested { tx_hash: "0xreq".to_string() };

    let t = start(Actor::Operator, false, false).await;
    let id = t.insert(&instance_row(UserInited, 0)).await;
    let event = pegin_request_event(id, &request).unwrap();
    let event_id = event.event_id.clone();
    t.submit(event).await;
    t.wait_applied(&event_id).await;
    assert!(t.job_actions(id).await.is_empty(), "only committee nodes answer");
    t.stop().await;

    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(UserInited, 0)).await;
    t.submit(pegin_request_event(id, &request).unwrap()).await;
    let job = t.wait_job(id, JOB_ANSWER_PEGIN_REQUEST, "Done").await;
    assert_eq!(job.phase, PHASE_ANSWER);
    assert_eq!(t.calls().len(), 1);
    // A request seen again after the Answer phase changes nothing.
    let mut answers = IndexMap::new();
    answers.insert("0xa".to_string(), vec![1u8; 33]);
    let window = AnswerWindow { goat_height: 200, window_blocks: 50, quorum: 1, answers };
    t.submit(window.event(id).unwrap()).await;
    t.wait_status(id, CommitteesAnswered).await;
    let late = PeginRequested { tx_hash: "0xagain".to_string() };
    let event = pegin_request_event(id, &late).unwrap();
    let event_id = event.event_id.clone();
    t.submit(event).await;
    t.wait_applied(&event_id).await;
    assert_eq!(t.calls().len(), 1, "no second answer after the window");
    t.stop().await;
}

// -------------------------------------------------------- pegin confirm round

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_round_message_becomes_an_ingest_job_whose_plan_is_sent_until_the_confirm() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    // Entering Presigned is what starts the round; here the row starts there,
    // so the start job is not enqueued: the member's nonce arrives first.
    let outbox_id = format!("instance:{id}:PeginConfirmNonceConsensus");
    let mut plan = InstancePlan::default();
    plan.send(PlannedMessage {
        outbox_id: outbox_id.clone(),
        phase_ref: PHASE_CONFIRM.to_string(),
        kind: "PeginConfirmNonceConsensus".to_string(),
        actor: Actor::Committee.to_string(),
        payload: b"vote".to_vec(),
        ack_set: None,
    })
    .then(JOB_PEGIN_CONFIRM_VOTE, Vec::new(), None);
    t.script(JOB_INGEST_PEGIN_CONFIRM_NONCE, plan);

    t.submit(t.round_message("PeginConfirmNonce", OTHER_PEER, id)).await;
    let ingest = t.wait_job(id, JOB_INGEST_PEGIN_CONFIRM_NONCE, "Done").await;
    assert_eq!(ingest.phase, PHASE_CONFIRM);
    assert!(ingest.deadline_at.is_some(), "a parked message does not wait forever");
    let row = t.wait_outbox(&outbox_id, "Open").await;
    assert_eq!(row.phase_ref, PHASE_CONFIRM);
    assert_eq!(row.aggregate_id, id.to_string());
    t.wait_job(id, JOB_PEGIN_CONFIRM_VOTE, "Done").await;

    // The same content again is a duplicate: no second ingest.
    let duplicate = t.round_message("PeginConfirmNonce", OTHER_PEER, id);
    t.submit(duplicate).await;
    settle().await;
    assert_eq!(
        t.calls().iter().filter(|(action, _)| action == JOB_INGEST_PEGIN_CONFIRM_NONCE).count(),
        1
    );

    // Peg-In-Confirm confirmed: the Confirm phase's deliveries close.
    t.snapshot(id, presign_snapshot(1_050, TxFact::confirmed_at(1_049), TxFact::UNKNOWN)).await;
    t.wait_status(id, RelayerL1Broadcasted).await;
    t.wait_outbox(&outbox_id, "Closed").await;
    // A late partial signature is still ingested (it carries the endorsement
    // the relayer's post needs); a late nonce is not.
    t.submit(t.round_message("PeginConfirmPartialSig", OTHER_PEER, id)).await;
    t.wait_job(id, JOB_INGEST_PEGIN_CONFIRM_PARTIAL_SIG, "Done").await;
    let late = t.round_message("PeginConfirmNonceConsensus", OTHER_PEER, id);
    let late_id = t.submit_id(late).await;
    t.wait_applied(&late_id).await;
    assert!(!t.job_actions(id).await.contains(&JOB_INGEST_PEGIN_CONFIRM_VOTE.to_string()));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_messages_from_this_node_outsiders_and_closed_rounds_are_ignored() {
    use InstanceBridgeInStatus::*;
    // This node's own message.
    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let own = t.submit_id(t.round_message("PeginConfirmNonce", LOCAL_PEER, id)).await;
    t.wait_applied(&own).await;
    assert!(t.job_actions(id).await.is_empty());
    // A round that is over.
    let done = t.insert(&instance_row(RelayerL2Minted, PREPARE)).await;
    let late = t.submit_id(t.round_message("PeginConfirmPartialSig", OTHER_PEER, done)).await;
    t.wait_applied(&late).await;
    assert!(t.job_actions(done).await.is_empty());
    let failed = t.insert(&instance_row(UserCanceled, PREPARE)).await;
    let late = t.submit_id(t.round_message("PeginConfirmNonce", OTHER_PEER, failed)).await;
    t.wait_applied(&late).await;
    assert!(t.job_actions(failed).await.is_empty());
    t.stop().await;

    // A committee node outside the instance's committee.
    let t = start_with(Actor::Committee, false, false, Arc::new(Outsider)).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let event = t.submit_id(t.round_message("PeginConfirmNonce", OTHER_PEER, id)).await;
    t.wait_applied(&event).await;
    assert!(t.job_actions(id).await.is_empty());
    t.stop().await;

    // A relayer outside the committee still collects the round: it
    // aggregates and broadcasts for committees it does not sign in.
    let t = start_with(Actor::Committee, true, false, Arc::new(Outsider)).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    let event = t.submit_id(t.round_message("PeginConfirmNonce", OTHER_PEER, id)).await;
    t.wait_applied(&event).await;
    t.wait_job(id, JOB_INGEST_PEGIN_CONFIRM_NONCE, "Done").await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn entering_presigned_starts_the_round_and_failure_cancels_it() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, true).await;
    let id = t.insert(&instance_row(UserBroadcastPeginPrepare, PREPARE)).await;
    let graph_id = t.insert_graph(id).await;
    mark_graph_as_endorsed(&t.db, id, graph_id).await.unwrap();
    let mut plan = InstancePlan::default();
    plan.send(PlannedMessage {
        outbox_id: format!("instance:{id}:PeginConfirmNonce"),
        phase_ref: PHASE_CONFIRM.to_string(),
        kind: "PeginConfirmNonce".to_string(),
        actor: Actor::Committee.to_string(),
        payload: b"nonce".to_vec(),
        ack_set: None,
    });
    t.script(JOB_START_PEGIN_CONFIRM, plan);
    t.submit(graph_endorsed_event(id, graph_id).unwrap()).await;
    t.wait_status(id, Presigned).await;
    t.wait_job(id, JOB_START_PEGIN_CONFIRM, "Done").await;
    t.wait_outbox(&format!("instance:{id}:PeginConfirmNonce"), "Open").await;

    // The user cancels: the round's deliveries close and its jobs go.
    let pending = t.submit_id(t.round_message("PeginConfirmNonce", OTHER_PEER, id)).await;
    t.wait_applied(&pending).await;
    t.snapshot(id, presign_snapshot(1_070, TxFact::UNKNOWN, TxFact::confirmed_at(1_069))).await;
    t.wait_status(id, UserCanceled).await;
    t.wait_outbox(&format!("instance:{id}:PeginConfirmNonce"), "Closed").await;
    // The round's ingest job ends Cancelled, or Done when it had already run;
    // its finish may still be waiting for the write lock when the outbox closes.
    wait_for(|| async {
        let jobs = t.jobs_of(id).await;
        let ingest: Vec<_> =
            jobs.iter().filter(|job| job.action == JOB_INGEST_PEGIN_CONFIRM_NONCE).collect();
        (!ingest.is_empty()
            && ingest.iter().all(|job| job.state == "Cancelled" || job.state == "Done"))
        .then_some(())
    })
    .await;
    t.wait_key_deleted(id).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relayer_rebroadcasts_an_invisible_confirm_once_per_block() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, false).await;
    let mut row = instance_row(Presigned, PREPARE);
    row.committees_answers.insert("0xa".to_string(), vec![1u8; 33]);
    let id = t.insert(&row).await;

    // Not every partial signature is stored: nothing to aggregate.
    t.snapshot(id, presign_snapshot(1_010, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    settle().await;
    assert!(t.job_actions(id).await.is_empty());

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(
        &secp,
        &bitcoin::secp256k1::SecretKey::from_slice(&[9; 32]).unwrap(),
    );
    store_committee_partial_sig_for_instance(
        &t.db,
        id,
        bitcoin::PublicKey::new(keypair.public_key()),
        musig2::PartialSignature::one(),
    )
    .await
    .unwrap();
    t.snapshot(id, presign_snapshot(1_011, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    t.wait_job(id, JOB_BROADCAST_PEGIN_CONFIRM, "Done").await;
    // Another block, still invisible: another broadcast; visible: none.
    t.snapshot(id, presign_snapshot(1_012, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    wait_for(|| async {
        (t.calls().iter().filter(|(action, _)| action == JOB_BROADCAST_PEGIN_CONFIRM).count() == 2)
            .then_some(())
    })
    .await;
    t.snapshot(id, presign_snapshot(1_013, TxFact::mempool(), TxFact::UNKNOWN)).await;
    settle().await;
    assert_eq!(
        t.calls().iter().filter(|(action, _)| action == JOB_BROADCAST_PEGIN_CONFIRM).count(),
        2
    );
    // A non-relayer committee node never broadcasts.
    t.stop().await;
    let t = start(Actor::Committee, false, false).await;
    let mut row = instance_row(Presigned, PREPARE);
    row.committees_answers.insert("0xa".to_string(), vec![1u8; 33]);
    let id = t.insert(&row).await;
    store_committee_partial_sig_for_instance(
        &t.db,
        id,
        bitcoin::PublicKey::new(keypair.public_key()),
        musig2::PartialSignature::one(),
    )
    .await
    .unwrap();
    t.snapshot(id, presign_snapshot(1_011, TxFact::UNKNOWN, TxFact::UNKNOWN)).await;
    settle().await;
    assert!(t.job_actions(id).await.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endorsed_graph_reaches_presigned_only_from_the_presign_phase() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(UserBroadcastPeginPrepare, PREPARE)).await;
    let graph_id = t.insert_graph(id).await;

    // Not endorsed yet: the threshold is not met.
    t.submit(graph_endorsed_event(id, graph_id).unwrap()).await;
    settle().await;
    assert_eq!(t.instance(id).await.status, UserBroadcastPeginPrepare.to_string());

    mark_graph_as_endorsed(&t.db, id, graph_id).await.unwrap();
    let other = t.insert_graph(id).await;
    t.submit(graph_endorsed_event(id, other).unwrap()).await;
    t.wait_status(id, Presigned).await;
    assert_eq!(t.engine_status(id).await.1, PHASE_CONFIRM);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endorsement_before_the_presign_phase_waits_for_it() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let graph_id = t.insert_graph(id).await;
    mark_graph_as_endorsed(&t.db, id, graph_id).await.unwrap();
    let event = graph_endorsed_event(id, graph_id).unwrap();
    let event_id = event.event_id.clone();
    t.submit(event).await;
    // Parked on the instance until it reaches the Presign phase.
    let waiting = wait_for(|| async { t.waiting_ref(&event_id).await }).await;
    assert_eq!(waiting, instance_ref(id).wake_ref());
    assert_eq!(t.instance(id).await.status, CommitteesAnswered.to_string());
    // Prepare confirms: the status change wakes the endorsement, which now counts.
    let mut snapshot = at(500, CommitteesAnswered);
    snapshot.prepare = Some(TxFact::confirmed_at(480));
    t.snapshot(id, snapshot).await;
    t.wait_status(id, Presigned).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mint_for_a_failed_instance_leaves_it_failed() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, true, true).await;
    let id = t.insert(&instance_row(UserDiscarded, PREPARE)).await;
    let event = l2_minted_event(id, "0xmint").unwrap();
    let event_id = event.event_id.clone();
    t.submit(event).await;
    t.wait_applied(&event_id).await;
    let instance = t.instance(id).await;
    assert_eq!(instance.status, UserDiscarded.to_string());
    assert_eq!(instance.post_pegin_txhash, None);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_committee_nodes_delete_keys() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Operator, false, true).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let mut snapshot = at(10, CommitteesAnswered);
    snapshot.inputs_available = Some(false);
    t.snapshot(id, snapshot).await;
    let instance = t.wait_status(id, UserDiscarded).await;
    settle().await;
    assert!(!instance.key_deleted);
    assert!(t.job_actions(id).await.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_key_deletion_only_records_the_intent() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, false).await;
    let id = t.insert(&instance_row(Presigned, PREPARE)).await;
    t.snapshot(id, presign_snapshot(1_070, TxFact::UNKNOWN, TxFact::confirmed_at(1_069))).await;
    t.wait_status(id, UserCanceled).await;
    settle().await;
    assert!(!t.instance(id).await.key_deleted);
    assert!(t.job_actions(id).await.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_missing_instance_row_parks_the_event_until_it_exists() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Committee, false, false).await;
    let instance = instance_row(Presigned, PREPARE);
    let id = instance.instance_id;
    let event =
        presign_snapshot(1_070, TxFact::UNKNOWN, TxFact::confirmed_at(1_069)).event(id).unwrap();
    let event_id = event.event_id.clone();
    t.submit(event).await;
    wait_for(|| async {
        let mut storage = t.db.acquire().await.unwrap();
        storage
            .find_engine_inbox_event(&event_id)
            .await
            .unwrap()
            .filter(|row| row.waiting_ref.as_deref() == Some(instance_ref(id).wake_ref().as_str()))
            .map(|_| ())
    })
    .await;
    t.insert(&instance).await;
    t.handle.notify(&[instance_ref(id).wake_ref()]).await.unwrap();
    t.wait_status(id, UserCanceled).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_instance_releases_its_pending_setup_session() {
    use InstanceBridgeInStatus::*;
    let t = start(Actor::Operator, false, false).await;
    let id = t.insert(&instance_row(CommitteesAnswered, 0)).await;
    let graph_id = Uuid::new_v4();
    let (outbox_id, job_id) = t.insert_pending_session(id, graph_id).await;
    // The next start of this operator waits on the slot the session is taking.
    let slot = crate::aggregates::graph::slot_ref("operator", 0);
    let parked = t.insert_parked_event(&slot).await;
    assert_eq!(t.waiting_ref(&parked).await.as_deref(), Some(slot.as_str()));

    let mut snapshot = at(10, CommitteesAnswered);
    snapshot.inputs_available = Some(false);
    t.snapshot(id, snapshot).await;
    t.wait_status(id, UserDiscarded).await;

    // The session is gone with its delivery and job, and the slot is released:
    // the parked event was woken, re-applied, and parked on its own ref.
    assert!(
        t.db.acquire()
            .await
            .unwrap()
            .find_pending_graph_init_by_graph_id(&graph_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(t.outbox_state(&outbox_id).await, "Closed");
    let job = t.db.acquire().await.unwrap().find_engine_job(&job_id).await.unwrap().unwrap();
    assert_eq!(job.state, "Cancelled");
    wait_for(|| async {
        let woken = t.waiting_ref(&parked).await;
        (woken.as_deref() != Some(slot.as_str())).then_some(())
    })
    .await;
    t.stop().await;
}
