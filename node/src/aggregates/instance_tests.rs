//! Instance lifecycle tests using the engine and SQLite, covering failure
//! states, signing deadlines, the abandon buffer and cleanup effects.

use super::instance::*;
use crate::action::{ConfirmInstance, GOATMessageContent, LocalMessageKey, MessageKind};
use crate::utils::{SELF_SENDER, mark_graph_as_endorsed, upsert_message};
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use engine::{
    Backoff, EngineBuilder, EngineConfig, EngineHandle, EngineInboxState, JobContext, JobOutcome,
    JobRunner, NewEvent,
};
use indexmap::IndexMap;
use std::sync::Arc;
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

struct Harness {
    db: LocalDB,
    _dir: tempfile::TempDir,
    handle: EngineHandle,
    cancel: CancellationToken,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
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

struct StubStartPeginConfirm;

#[async_trait]
impl JobRunner for StubStartPeginConfirm {
    async fn run(&self, _ctx: JobContext) -> JobOutcome {
        JobOutcome::Done(b"started".to_vec())
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("instance.db");
    let db = LocalDB::new_with_busy_timeout(
        &format!("sqlite:{}", path.display()),
        false,
        store::DEFAULT_BUSY_TIMEOUT,
    )
    .await;
    db.migrate().await;
    let (engine, _acks) = EngineBuilder::new(db.clone(), fast_config())
        .handler(
            INSTANCE_KIND,
            Arc::new(InstanceAggregate::new(actor, DEADLINES, relayer, key_delete_enabled)),
        )
        .job_runner(INSTANCE_KIND, JOB_DELETE_INSTANCE_KEY, Arc::new(StubKeyDelete))
        .job_runner(INSTANCE_KIND, JOB_POST_PEGIN_DATA, Arc::new(StubPost))
        .job_runner(INSTANCE_KIND, JOB_START_PEGIN_CONFIRM, Arc::new(StubStartPeginConfirm))
        .build();
    let handle = engine.handle();
    let cancel = CancellationToken::new();
    let run = tokio::spawn(engine.run(cancel.clone()));
    Harness { db, _dir: dir, handle, cancel, run }
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

    async fn insert_local_message(&self, instance_id: Uuid) -> String {
        let content = GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id });
        let message_id = LocalMessageKey::from_content(Actor::All, &content).unwrap().message_id();
        let mut storage = self.db.acquire().await.unwrap();
        upsert_message(&mut storage, false, SELF_SENDER.to_string(), Actor::All, content, 0, 0)
            .await
            .unwrap();
        message_id
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

    async fn message_state(&self, message_id: &str) -> String {
        self.db
            .acquire()
            .await
            .unwrap()
            .find_messages_by_id(message_id)
            .await
            .unwrap()
            .unwrap()
            .state
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
    let message_id = t.insert_local_message(id).await;
    let outbox_id = t.insert_open_outbox(id).await;

    let mut snapshot = at(10, CommitteesAnswered);
    snapshot.inputs_available = Some(false);
    t.snapshot(id, snapshot).await;

    t.wait_status(id, UserDiscarded).await;
    assert_eq!(t.graph_status(graph_id).await, GraphStatus::Obsoleted.to_string());
    assert_ne!(t.message_state(&message_id).await, "Pending");
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
    let content = GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id: id });
    let message_id = LocalMessageKey::from_content(Actor::All, &content).unwrap().message_id();
    let message = t.db.acquire().await.unwrap().find_messages_by_id(&message_id).await.unwrap();
    assert_eq!(message.map(|m| m.msg_type), Some(MessageKind::ConfirmInstance.to_string()));
    assert_eq!(t.engine_status(id).await.1, PHASE_PRESIGN);
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
