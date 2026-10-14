//! Graph coordination tests using the engine and SQLite.
//!
//! Scripted jobs exercise routing, slot rules, missing definitions, job plans
//! and delivery closing; they do not perform real graph cryptography.

use super::graph::*;
use super::graph_fetch::GraphLookup;
use super::graph_pegout::*;
use async_trait::async_trait;
use bitvm_lib::actors::Actor;
use engine::{
    Backoff, EngineBuilder, EngineConfig, EngineHandle, EngineInboxState, EventSource, JobContext,
    JobOutcome, JobRunner, NewEvent,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::localdb::LocalDB;
use store::{
    EngineJobState, EngineOutboxState, Graph, GraphStatus, GraphStatusSource, Instance,
    InstanceBridgeInStatus,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(10);
const LOCAL_PEER: &str = "12D3KooWLocalPeer";
const OPERATOR: &str = "02operator";

/// Returns the scripted plan for an action and records what it was asked.
#[derive(Default)]
struct Scripted {
    plans: Mutex<HashMap<String, GraphPlan>>,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    /// Runs of these actions block until the test releases them.
    holds: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Scripted {
    fn hold(&self, action: &str) {
        self.holds.lock().unwrap().insert(action.to_string(), Arc::new(tokio::sync::Notify::new()));
    }

    fn release(&self, action: &str) {
        if let Some(hold) = self.holds.lock().unwrap().remove(action) {
            hold.notify_waiters();
            hold.notify_one();
        }
    }

    fn release_all(&self) {
        let actions: Vec<String> = self.holds.lock().unwrap().keys().cloned().collect();
        for action in actions {
            self.release(&action);
        }
    }
}

#[async_trait]
impl JobRunner for Scripted {
    async fn run(&self, ctx: JobContext) -> JobOutcome {
        let params = ctx.job.params.clone().unwrap_or_default();
        self.calls.lock().unwrap().push((ctx.job.action.clone(), params));
        let hold = self.holds.lock().unwrap().get(&ctx.job.action).cloned();
        if let Some(hold) = hold {
            hold.notified().await;
        }
        let plan = self.plans.lock().unwrap().remove(&ctx.job.action).unwrap_or_default();
        JobOutcome::Done(plan.encode().unwrap())
    }
}

struct Harness {
    db: LocalDB,
    _dir: tempfile::TempDir,
    handle: EngineHandle,
    cancel: CancellationToken,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
    jobs: Arc<Scripted>,
}

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

/// A member whose registry knows no peer.
struct Unacquainted;

impl MembershipProbe for Unacquainted {
    fn holds_instance_key(&self, _instance_id: Uuid) -> bool {
        true
    }

    fn is_registered_peer(&self, _peer: &str) -> bool {
        false
    }
}

async fn start(actor: Actor, relayer: bool) -> Harness {
    start_with(actor, relayer, Arc::new(Member)).await
}

async fn start_with(actor: Actor, relayer: bool, membership: Arc<dyn MembershipProbe>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("graph.db");
    let db = LocalDB::new_with_busy_timeout(
        &format!("sqlite:{}", path.display()),
        false,
        store::DEFAULT_BUSY_TIMEOUT,
    )
    .await;
    db.migrate().await;
    let jobs = Arc::new(Scripted::default());
    let local_operator = (actor == Actor::Operator).then(|| OPERATOR.to_string());
    let mut builder = EngineBuilder::new(db.clone(), fast_config()).handler(
        GRAPH_KIND,
        Arc::new(
            GraphAggregate::new(actor, relayer, LOCAL_PEER.to_string())
                .with_membership(membership)
                .with_local_operator(local_operator),
        ),
    );
    for action in ALL_JOBS.iter().chain(PEGOUT_JOBS) {
        let runner: Arc<dyn JobRunner> = jobs.clone();
        builder = builder.job_runner(GRAPH_KIND, *action, runner);
    }
    let (engine, _acks) = builder.build();
    let handle = engine.handle();
    let cancel = CancellationToken::new();
    let run = tokio::spawn(engine.run(cancel.clone()));
    Harness { db, _dir: dir, handle, cancel, run, jobs }
}

impl Harness {
    async fn stop(self) {
        self.jobs.release_all();
        self.cancel.cancel();
        self.run.await.unwrap().unwrap();
    }

    fn script(&self, action: &str, plan: GraphPlan) {
        self.jobs.plans.lock().unwrap().insert(action.to_string(), plan);
    }

    fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.jobs.calls.lock().unwrap().clone()
    }

    /// The params the runner was handed for the first call of `action`.
    fn job_params(&self, action: &str) -> Vec<u8> {
        self.calls()
            .into_iter()
            .find(|(called, _)| called == action)
            .map(|(_, params)| params)
            .unwrap_or_else(|| panic!("{action} was never run"))
    }

    async fn insert_graph(&self, instance_id: Uuid, nonce: i64, status: GraphStatus) -> Uuid {
        let graph_id = Uuid::new_v4();
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .upsert_graph_definition(&Graph {
                graph_id,
                instance_id,
                status: GraphStatus::OperatorPresigned.to_string(),
                definition_hash: "definition".to_string(),
                operator_pubkey: OPERATOR.to_string(),
                kickoff_index: nonce,
                ..Default::default()
            })
            .await
            .unwrap();
        if status != GraphStatus::OperatorPresigned {
            self.set_status(instance_id, graph_id, status).await;
        }
        graph_id
    }

    async fn insert_session(&self, instance_id: Uuid, graph_id: Uuid) {
        let mut storage = self.db.acquire().await.unwrap();
        storage.upsert_pending_graph_init(&instance_id, OPERATOR, &graph_id).await.unwrap();
    }

    async fn set_instance_status(&self, instance_id: Uuid, status: InstanceBridgeInStatus) {
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .update_instance(
                &store::localdb::InstanceUpdate::new_with_instance_id(instance_id)
                    .with_status(status.to_string()),
            )
            .await
            .unwrap();
    }

    async fn insert_instance(&self, status: InstanceBridgeInStatus) -> Uuid {
        let instance_id = Uuid::new_v4();
        let mut storage = self.db.acquire().await.unwrap();
        assert!(
            storage
                .insert_instance_if_absent(&Instance {
                    instance_id,
                    status: status.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap()
        );
        instance_id
    }

    async fn set_status(&self, instance_id: Uuid, graph_id: Uuid, status: GraphStatus) {
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .transition_graph_status(
                instance_id,
                graph_id,
                status,
                GraphStatusSource::ChainReconcile,
                None,
            )
            .await
            .unwrap();
    }

    /// A network message event as `inbound_event` would build it, without a
    /// real graph: the apply only reads the envelope.
    fn message(
        &self,
        kind: &str,
        author: &str,
        instance_id: Uuid,
        graph_id: Uuid,
        nonce: Option<u64>,
    ) -> NewEvent {
        let inbound = InboundMessage {
            author: author.to_string(),
            instance_id,
            graph_nonce: nonce,
            operator_pubkey: Some(OPERATOR.to_string()),
            message: format!("{kind}:{graph_id}").into_bytes(),
        };
        let mut event = NewEvent::new(
            content_event_id(author, kind, &graph_id.to_string(), &inbound.message),
            graph_ref(graph_id),
            kind,
            EventSource::Network,
            inbound.encode().unwrap(),
        )
        .with_author(author);
        if ack_required(kind) {
            event = event.with_ack(author, delivery_id(author, LOCAL_PEER, &inbound.message));
        }
        event
    }

    async fn submit(&self, event: NewEvent) -> String {
        let event_id = event.event_id.clone();
        self.handle.submit(event).await.unwrap();
        event_id
    }

    /// `None` until the event is recorded (an apply may record it later).
    async fn inbox(&self, event_id: &str) -> Option<store::EngineInboxEvent> {
        self.db.acquire().await.unwrap().find_engine_inbox_event(event_id).await.unwrap()
    }

    async fn wait_inbox(&self, event_id: &str, state: EngineInboxState) -> store::EngineInboxEvent {
        wait_for(|| async {
            self.inbox(event_id).await.filter(|row| row.state == state.to_string())
        })
        .await
    }

    async fn wait_waiting(&self, event_id: &str) -> store::EngineInboxEvent {
        wait_for(|| async { self.inbox(event_id).await.filter(|row| row.waiting_ref.is_some()) })
            .await
    }

    async fn jobs_of(&self, graph_id: Uuid) -> Vec<store::EngineJob> {
        let mut storage = self.db.acquire().await.unwrap();
        storage.list_engine_jobs_for_aggregate(GRAPH_KIND, &graph_id.to_string()).await.unwrap()
    }

    async fn wait_job(
        &self,
        graph_id: Uuid,
        action: &str,
        state: EngineJobState,
    ) -> store::EngineJob {
        wait_for(|| async {
            self.jobs_of(graph_id)
                .await
                .into_iter()
                .find(|job| job.action == action && job.state == state.to_string())
        })
        .await
    }

    /// The job is queued or running: enqueued by an apply, no longer gated.
    async fn wait_job_live(&self, graph_id: Uuid, action: &str) -> store::EngineJob {
        wait_for(|| async {
            self.jobs_of(graph_id).await.into_iter().find(|job| {
                job.action == action
                    && (job.state == EngineJobState::Pending.to_string()
                        || job.state == EngineJobState::Running.to_string())
            })
        })
        .await
    }

    async fn outbox(&self, outbox_id: &str) -> Option<store::EngineOutboxMessage> {
        self.db.acquire().await.unwrap().find_engine_outbox_message(outbox_id).await.unwrap()
    }

    async fn wait_outbox(
        &self,
        outbox_id: &str,
        state: EngineOutboxState,
    ) -> store::EngineOutboxMessage {
        wait_for(|| async {
            self.outbox(outbox_id).await.filter(|row| row.state == state.to_string())
        })
        .await
    }

    async fn aggregate(&self, graph_id: Uuid) -> store::EngineAggregate {
        self.handle.aggregate(&graph_ref(graph_id)).await.unwrap().unwrap()
    }

    async fn wait_phase(&self, graph_id: Uuid, phase: &str) -> store::EngineAggregate {
        wait_for(|| async {
            let row = self.aggregate(graph_id).await;
            (row.phase == phase).then_some(row)
        })
        .await
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

/// The plan a sealed proof collection returns: build the definition.
fn build_plan() -> GraphPlan {
    let mut plan = GraphPlan::noted("proofs sealed");
    plan.then(JOB_BUILD_GRAPH, Vec::new(), None);
    plan
}

fn build_ready_id(graph_id: Uuid) -> String {
    build_ready_event(graph_id).event_id
}

fn planned(graph_id: Uuid, kind: &str, phase: &str, ack: Option<&str>) -> PlannedMessage {
    PlannedMessage {
        outbox_id: outbox_id(graph_id, kind, None),
        phase_ref: phase.to_string(),
        kind: kind.to_string(),
        actor: Actor::All.to_string(),
        payload: kind.as_bytes().to_vec(),
        ack_set: ack.map(|peer| BTreeMap::from([(peer.to_string(), "delivery".to_string())])),
    }
}

// ------------------------------------------------------------------ routing

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_becomes_an_ingest_job_and_its_plan_is_committed() {
    let t = start(Actor::Committee, false).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    let follow_up = GraphPlan {
        messages: vec![planned(graph_id, "NonceGeneration", PHASE_SIGNING, None)],
        next: vec![NextStep::Job {
            action: JOB_COMMITTEE_VOTE.to_string(),
            params: vec![9],
            delay_secs: Some(600),
        }],
        state: GraphStateUpdate {
            instance_id: Some(instance_id),
            graph_nonce: Some(0),
            ..Default::default()
        },
        ..Default::default()
    };
    t.script(JOB_COMMITTEE_INGEST_GRAPH, follow_up);

    // The committee's CreateGraph for slot 0 needs no predecessor.
    let event_id =
        t.submit(t.message("CreateGraph", "peer-op", instance_id, graph_id, Some(0))).await;
    let row = t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    assert_eq!(row.ack_peer.as_deref(), Some("peer-op"), "heavy messages carry their ACK");
    t.wait_job(graph_id, JOB_COMMITTEE_INGEST_GRAPH, EngineJobState::Done).await;
    let calls = t.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, JOB_COMMITTEE_INGEST_GRAPH);
    assert_eq!(InboundMessage::decode(&calls[0].1).unwrap().instance_id, instance_id);

    // The plan: a message in the outbox, the next job delayed, the state kept.
    let sent =
        t.wait_outbox(&outbox_id(graph_id, "NonceGeneration", None), EngineOutboxState::Open).await;
    assert_eq!(sent.phase_ref, PHASE_SIGNING);
    assert_eq!(sent.topic, crate::middleware::get_topic_name("All"));
    let vote = t.wait_job(graph_id, JOB_COMMITTEE_VOTE, EngineJobState::Pending).await;
    assert!(vote.next_at >= vote.created_at + 599, "run_after keeps the delay");
    assert_eq!(vote.params.as_deref(), Some(&[9][..]));
    let row = t.aggregate(graph_id).await;
    let state: GraphState = serde_json::from_str(row.state.as_deref().unwrap()).unwrap();
    assert_eq!(state.instance_id, Some(instance_id));
    // No graph row yet: the phase is still Setup.
    assert_eq!(row.phase, PHASE_SETUP);

    // A copy of the same message is a duplicate, applied once.
    let again = t.submit(t.message("CreateGraph", "peer-op", instance_id, graph_id, Some(0))).await;
    assert_eq!(again, event_id);
    settle().await;
    assert_eq!(t.calls().len(), 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_messages_and_unhandled_roles_are_ignored() {
    let t = start(Actor::Operator, false).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    // From this node: nothing to do.
    let own = t.submit(t.message("GenCircuits", LOCAL_PEER, instance_id, graph_id, None)).await;
    t.wait_inbox(&own, EngineInboxState::Applied).await;
    // An operator never ingests a CreateGraph.
    let foreign =
        t.submit(t.message("CreateGraph", "peer-x", instance_id, graph_id, Some(0))).await;
    t.wait_inbox(&foreign, EngineInboxState::Failed).await;
    // A GenCircuits without a pending session is dropped.
    let stray = t.submit(t.message("GenCircuits", "peer-v", instance_id, graph_id, None)).await;
    t.wait_inbox(&stray, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.calls().is_empty());
    t.stop().await;
}

// ------------------------------------------------------------------- slots

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_definition_for_a_slot_is_refused() {
    let t = start(Actor::Committee, false).await;
    let instance_id = Uuid::new_v4();
    let holder = t.insert_graph(instance_id, 1, GraphStatus::OperatorPresigned).await;
    let newcomer = Uuid::new_v4();
    let event_id =
        t.submit(t.message("CreateGraph", "peer-op", instance_id, newcomer, Some(1))).await;
    let row = t.wait_inbox(&event_id, EngineInboxState::Failed).await;
    assert!(row.last_error.unwrap_or_default().contains(&holder.to_string()));
    settle().await;
    assert!(t.calls().is_empty(), "no job for a refused definition");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_definition_waits_for_its_predecessor_and_pulls_it() {
    let t = start(Actor::Committee, false).await;
    let instance_id = Uuid::new_v4();
    let graph_id = Uuid::new_v4();
    let event_id =
        t.submit(t.message("CreateGraph", "peer-op", instance_id, graph_id, Some(2))).await;
    let row = t.wait_waiting(&event_id).await;
    assert_eq!(row.waiting_ref.as_deref(), Some(slot_ref(OPERATOR, 1).as_str()));
    // The pull is a job with the slot to look up (a finished job has its
    // params cleared, so read what the runner was handed).
    t.wait_job(graph_id, JOB_FETCH_GRAPH, EngineJobState::Done).await;
    let lookup: GraphLookup = bincode::deserialize(&t.job_params(JOB_FETCH_GRAPH)).unwrap();
    assert_eq!(lookup, GraphLookup::Slot { operator_pubkey: OPERATOR.to_string(), graph_nonce: 1 });
    assert!(t.jobs_of(graph_id).await.iter().all(|job| job.action == JOB_FETCH_GRAPH));

    // The predecessor arrives by any path; waking the slot releases the event.
    t.insert_graph(Uuid::new_v4(), 1, GraphStatus::OperatorPresigned).await;
    t.handle.notify(&[slot_ref(OPERATOR, 1)]).await.unwrap();
    t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_COMMITTEE_INGEST_GRAPH, EngineJobState::Done).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_value_from_an_unregistered_author_waits_without_a_pull() {
    let t = start_with(Actor::Committee, false, Arc::new(Unacquainted)).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    let event_id =
        t.submit(t.message("NonceGeneration", "peer-x", instance_id, graph_id, None)).await;
    t.wait_waiting(&event_id).await;
    settle().await;
    assert!(t.jobs_of(graph_id).await.is_empty(), "no GetGraph pull for an unknown author");
    t.stop().await;
}

// ------------------------------------------------------------ round values

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_values_wait_for_the_definition_and_stop_once_the_round_is_over() {
    let t = start(Actor::Committee, false).await;
    let instance_id = Uuid::new_v4();
    let graph_id = Uuid::new_v4();
    // No definition yet: parked on the graph itself, and pulled by id.
    let nonce = t.submit(t.message("NonceGeneration", "peer-c", instance_id, graph_id, None)).await;
    let row = t.wait_waiting(&nonce).await;
    assert_eq!(row.waiting_ref.as_deref(), Some(graph_ref(graph_id).wake_ref().as_str()));
    t.wait_job(graph_id, JOB_FETCH_GRAPH, EngineJobState::Done).await;
    let lookup: GraphLookup = bincode::deserialize(&t.job_params(JOB_FETCH_GRAPH)).unwrap();
    assert_eq!(lookup, GraphLookup::Id { instance_id, graph_id, finalized: false });
    assert!(t.calls().iter().all(|(action, _)| action == JOB_FETCH_GRAPH));

    // The definition is stored (by the ingest job in production): the
    // aggregate's own wake releases the value.
    let mut storage = t.db.acquire().await.unwrap();
    storage
        .upsert_graph_definition(&Graph {
            graph_id,
            instance_id,
            status: GraphStatus::OperatorPresigned.to_string(),
            definition_hash: "definition".to_string(),
            operator_pubkey: OPERATOR.to_string(),
            kickoff_index: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    drop(storage);
    t.handle.notify(&[graph_ref(graph_id).wake_ref()]).await.unwrap();
    t.wait_inbox(&nonce, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_INGEST_NONCES, EngineJobState::Done).await;
    let row = t.wait_phase(graph_id, PHASE_SIGNING).await;
    assert_eq!(row.status, GraphStatus::OperatorPresigned.to_string());

    // Once finalized, late round values are ignored and the round's
    // deliveries are closed.
    t.script(
        JOB_INGEST_PRESIGN,
        GraphPlan {
            messages: vec![planned(graph_id, "CommitteePresign", PHASE_SIGNING, None)],
            ..Default::default()
        },
    );
    let presign =
        t.submit(t.message("CommitteePresign", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&presign, EngineInboxState::Applied).await;
    let sent = outbox_id(graph_id, "CommitteePresign", None);
    t.wait_outbox(&sent, EngineOutboxState::Open).await;
    t.set_status(instance_id, graph_id, GraphStatus::CommitteePresigned).await;
    let late =
        t.submit(t.message("AggNonceConsensus", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&late, EngineInboxState::Applied).await;
    let closed = t.wait_outbox(&sent, EngineOutboxState::Closed).await;
    assert!(closed.close_reason.unwrap_or_default().contains("CommitteePresigned"));
    assert_eq!(
        t.wait_phase(graph_id, PHASE_SIGNED).await.status,
        GraphStatus::CommitteePresigned.to_string()
    );
    assert!(
        !t.calls().iter().any(|(action, _)| action == JOB_INGEST_VOTE),
        "late vote never ingested"
    );
    t.stop().await;
}

// ---------------------------------------------------------- operator start

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_operator_start_runs_the_setup_and_posting_closes_every_delivery() {
    let t = start(Actor::Operator, false).await;
    let instance_id = Uuid::new_v4();
    let graph_id = Uuid::new_v4();
    t.script(
        JOB_OPERATOR_INIT,
        GraphPlan {
            messages: vec![planned(graph_id, "InitGraph", PHASE_SETUP, None)],
            state: GraphStateUpdate { instance_id: Some(instance_id), ..Default::default() },
            ..Default::default()
        },
    );
    let start_id = t.submit(operator_start_event(instance_id, graph_id, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_id, EngineInboxState::Applied).await;
    let init =
        t.wait_outbox(&outbox_id(graph_id, "InitGraph", None), EngineOutboxState::Open).await;
    assert_eq!(init.phase_ref, PHASE_SETUP);
    let calls = t.calls();
    assert_eq!(calls.len(), 1);
    let params: OperatorStart = bincode::deserialize(&calls[0].1).unwrap();
    assert_eq!(params.instance_id, instance_id);

    // The build job delivers CreateGraph with its ack set and closes InitGraph.
    t.script(
        JOB_BUILD_GRAPH,
        GraphPlan {
            messages: vec![planned(graph_id, "CreateGraph", PHASE_COLLECT, Some("peer-v"))],
            close_rows: vec![outbox_id(graph_id, "InitGraph", None)],
            state: GraphStateUpdate { graph_nonce: Some(0), ..Default::default() },
            ..Default::default()
        },
    );
    // Reached through a plan of another job: GenCircuits needs a session.
    let mut storage = t.db.acquire().await.unwrap();
    storage.upsert_pending_graph_init(&instance_id, OPERATOR, &graph_id).await.unwrap();
    drop(storage);
    t.script(
        JOB_INGEST_GEN_CIRCUITS,
        GraphPlan {
            next: vec![NextStep::Job {
                action: JOB_BUILD_GRAPH.to_string(),
                params: vec![],
                delay_secs: None,
            }],
            ..Default::default()
        },
    );
    let circuits = t.submit(t.message("GenCircuits", "peer-v", instance_id, graph_id, None)).await;
    t.wait_inbox(&circuits, EngineInboxState::Applied).await;
    let create =
        t.wait_outbox(&outbox_id(graph_id, "CreateGraph", None), EngineOutboxState::Open).await;
    assert_eq!(create.ack_set.unwrap().get("peer-v").map(String::as_str), Some("delivery"));
    t.wait_outbox(&outbox_id(graph_id, "InitGraph", None), EngineOutboxState::Closed).await;

    // Posted on Goat: the watcher's status write plus the posted event close
    // everything that is left and move the phase on.
    t.insert_graph_with_id(instance_id, graph_id).await;
    t.set_status(instance_id, graph_id, GraphStatus::CommitteePresigned).await;
    t.set_status(instance_id, graph_id, GraphStatus::OperatorDataPushed).await;
    let posted = t.submit(graph_posted_event(graph_id).unwrap()).await;
    t.wait_inbox(&posted, EngineInboxState::Applied).await;
    t.wait_outbox(&outbox_id(graph_id, "CreateGraph", None), EngineOutboxState::Closed).await;
    assert_eq!(
        t.wait_phase(graph_id, PHASE_AWAIT_WITHDRAW).await.status,
        GraphStatus::OperatorDataPushed.to_string()
    );
    t.stop().await;
}

impl Harness {
    async fn insert_graph_with_id(&self, instance_id: Uuid, graph_id: Uuid) {
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .upsert_graph_definition(&Graph {
                graph_id,
                instance_id,
                status: GraphStatus::OperatorPresigned.to_string(),
                definition_hash: "definition".to_string(),
                operator_pubkey: OPERATOR.to_string(),
                kickoff_index: 0,
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

// ----------------------------------------------------------------- retired

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_obsoleted_graph_ignores_messages_and_cancels_its_jobs() {
    let t = start(Actor::Committee, false).await;
    let instance_id = Uuid::new_v4();
    let graph_id = t.insert_graph(instance_id, 0, GraphStatus::OperatorPresigned).await;
    // A pending job of the graph, then the graph is obsoleted.
    t.script(
        JOB_INGEST_NONCES,
        GraphPlan {
            next: vec![NextStep::Job {
                action: JOB_COMMITTEE_VOTE.to_string(),
                params: vec![],
                delay_secs: Some(3_600),
            }],
            ..Default::default()
        },
    );
    let nonce = t.submit(t.message("NonceGeneration", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&nonce, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_COMMITTEE_VOTE, EngineJobState::Pending).await;
    t.set_status(instance_id, graph_id, GraphStatus::Obsoleted).await;
    let late = t.submit(t.message("CommitteePresign", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&late, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_COMMITTEE_VOTE, EngineJobState::Cancelled).await;
    assert_eq!(
        t.wait_phase(graph_id, PHASE_OBSOLETED).await.status,
        GraphStatus::Obsoleted.to_string()
    );
    assert!(!t.calls().iter().any(|(action, _)| action == JOB_INGEST_PRESIGN));
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plan_finished_after_the_graph_retired_is_dropped() {
    let t = start(Actor::Committee, false).await;
    let instance_id = Uuid::new_v4();
    let graph_id = t.insert_graph(instance_id, 0, GraphStatus::OperatorPresigned).await;
    // The ingest is running when the graph is obsoleted (a chain scan, say);
    // its plan would send a message and queue the next step.
    t.jobs.hold(JOB_INGEST_NONCES);
    t.script(
        JOB_INGEST_NONCES,
        GraphPlan {
            messages: vec![planned(graph_id, "NonceGeneration", PHASE_SIGNING, None)],
            next: vec![NextStep::Job {
                action: JOB_COMMITTEE_VOTE.to_string(),
                params: vec![],
                delay_secs: None,
            }],
            wake_refs: vec![slot_ref(OPERATOR, 1)],
            ..Default::default()
        },
    );
    let nonce = t.submit(t.message("NonceGeneration", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&nonce, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_INGEST_NONCES, EngineJobState::Running).await;
    t.set_status(instance_id, graph_id, GraphStatus::Obsoleted).await;
    t.jobs.release(JOB_INGEST_NONCES);
    t.wait_job(graph_id, JOB_INGEST_NONCES, EngineJobState::Done).await;
    t.wait_phase(graph_id, PHASE_OBSOLETED).await;
    settle().await;
    assert!(t.outbox(&outbox_id(graph_id, "NonceGeneration", None)).await.is_none());
    assert!(!t.jobs_of(graph_id).await.iter().any(|job| job.action == JOB_COMMITTEE_VOTE));
    t.stop().await;
}

// ------------------------------------------------------------ predecessor

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_and_its_build_do_not_wait_for_the_previous_slot() {
    let t = start(Actor::Operator, false).await;
    // Slot 0 is built but not finalized and its instance is alive: the next setup starts at
    // once and builds on its definition.
    let previous_instance =
        t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    t.insert_graph(previous_instance, 0, GraphStatus::OperatorPresigned).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    t.insert_session(instance_id, graph_id).await;
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_id = t.submit(operator_start_event(instance_id, graph_id, OPERATOR).unwrap()).await;
    assert!(t.wait_inbox(&start_id, EngineInboxState::Applied).await.waiting_ref.is_none());
    t.wait_job(graph_id, JOB_OPERATOR_INIT, EngineJobState::Done).await;
    t.wait_inbox(&build_ready_id(graph_id), EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_BUILD_GRAPH, EngineJobState::Done).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_instance_settles_its_slot_and_drops_its_own_pending_start() {
    let t = start(Actor::Operator, false).await;
    // The previous slot's graph never got past OperatorPresigned, but its instance failed: the
    // slot is settled.
    let failed_instance = t.insert_instance(InstanceBridgeInStatus::UserCanceled).await;
    t.insert_graph(failed_instance, 3, GraphStatus::OperatorPresigned).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    t.script(JOB_OPERATOR_INIT, GraphPlan::noted("started"));
    let start_id = t.submit(operator_start_event(instance_id, graph_id, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_id, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_OPERATOR_INIT, EngineJobState::Done).await;

    // A start for an instance that failed meanwhile drops its session.
    let doomed_instance = t.insert_instance(InstanceBridgeInStatus::UserDiscarded).await;
    let doomed_graph = Uuid::new_v4();
    let mut storage = t.db.acquire().await.unwrap();
    storage.upsert_pending_graph_init(&doomed_instance, OPERATOR, &doomed_graph).await.unwrap();
    drop(storage);
    let start_id =
        t.submit(operator_start_event(doomed_instance, doomed_graph, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_id, EngineInboxState::Applied).await;
    assert!(
        t.db.acquire()
            .await
            .unwrap()
            .find_pending_graph_init_by_graph_id(&doomed_graph)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(t.calls().len(), 1, "no job for the doomed graph");
    t.stop().await;
}

// ------------------------------------------------------------- membership

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_committee_node_outside_the_committee_ignores_all_but_graph_finalize() {
    let t = start_with(Actor::Committee, false, Arc::new(Outsider)).await;
    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    let create =
        t.submit(t.message("CreateGraph", "peer-op", instance_id, graph_id, Some(0))).await;
    t.wait_inbox(&create, EngineInboxState::Applied).await;
    let nonce = t.submit(t.message("NonceGeneration", "peer-c", instance_id, graph_id, None)).await;
    t.wait_inbox(&nonce, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.calls().is_empty(), "neither ingested nor pulled");
    assert!(t.jobs_of(graph_id).await.is_empty());

    let finalize =
        t.submit(t.message("GraphFinalize", "peer-op", instance_id, graph_id, Some(0))).await;
    t.wait_inbox(&finalize, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_INGEST_FINALIZED, EngineJobState::Done).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_round_value_of_a_failed_instance_is_dropped_instead_of_parked() {
    let t = start(Actor::Committee, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::Timeout).await;
    let graph_id = Uuid::new_v4();
    let nonce = t.submit(t.message("NonceGeneration", "peer-c", instance_id, graph_id, None)).await;
    let row = t.wait_inbox(&nonce, EngineInboxState::Applied).await;
    assert!(row.waiting_ref.is_none());
    settle().await;
    assert!(t.jobs_of(graph_id).await.is_empty(), "nothing is pulled for a failed instance");
    t.stop().await;
}

// -------------------------------------------------------------------- pull

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pulled_finalized_graph_is_posted_by_the_relayer() {
    let t = start(Actor::Committee, true).await;
    let instance_id = Uuid::new_v4();
    let graph_id = t.insert_graph(instance_id, 0, GraphStatus::CommitteePresigned).await;
    let pulled = t.submit(graph_pulled_event(graph_id, instance_id, true).unwrap()).await;
    t.wait_inbox(&pulled, EngineInboxState::Applied).await;
    let post = t.wait_job(graph_id, JOB_POST_GRAPH_DATA, EngineJobState::Done).await;
    assert_eq!(post.phase, PHASE_POST);
    assert_eq!(
        t.wait_phase(graph_id, PHASE_POST).await.status,
        GraphStatus::CommitteePresigned.to_string()
    );

    // A pre-signed copy is not posted, and a non-relayer never posts.
    let other = t.insert_graph(instance_id, 1, GraphStatus::OperatorPresigned).await;
    let pulled = t.submit(graph_pulled_event(other, instance_id, false).unwrap()).await;
    t.wait_inbox(&pulled, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.jobs_of(other).await.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn builds_of_one_operator_run_one_at_a_time() {
    let t = start(Actor::Operator, false).await;
    let instance_a = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let instance_b = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let (graph_a, graph_b) = (Uuid::new_v4(), Uuid::new_v4());
    t.insert_session(instance_a, graph_a).await;
    t.insert_session(instance_b, graph_b).await;
    t.jobs.hold(JOB_BUILD_GRAPH);

    // A starts on an empty chain and builds slot 0.
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_a = t.submit(operator_start_event(instance_a, graph_a, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_a, EngineInboxState::Applied).await;
    t.wait_job(graph_a, JOB_BUILD_GRAPH, EngineJobState::Running).await;
    // B starts meanwhile; only its build waits, on the slot A is taking.
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_b = t.submit(operator_start_event(instance_b, graph_b, OPERATOR).unwrap()).await;
    assert!(t.wait_inbox(&start_b, EngineInboxState::Applied).await.waiting_ref.is_none());
    let ready_b = t.wait_waiting(&build_ready_id(graph_b)).await;
    assert_eq!(ready_b.waiting_ref.as_deref(), Some(slot_ref(OPERATOR, 0).as_str()));
    settle().await;
    assert_eq!(t.called(JOB_BUILD_GRAPH).len(), 1, "one build at a time");

    // A stores slot 0: its row wakes the slot and B builds slot 1.
    t.insert_graph_with_id(instance_a, graph_a).await;
    t.jobs.release(JOB_BUILD_GRAPH);
    t.wait_job(graph_a, JOB_BUILD_GRAPH, EngineJobState::Done).await;
    t.wait_inbox(&build_ready_id(graph_b), EngineInboxState::Applied).await;
    t.wait_job(graph_b, JOB_BUILD_GRAPH, EngineJobState::Done).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_of_a_failed_instance_does_not_hold_the_next_build() {
    let t = start(Actor::Operator, false).await;
    let instance_a = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let instance_b = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let (graph_a, graph_b) = (Uuid::new_v4(), Uuid::new_v4());
    t.insert_session(instance_a, graph_a).await;
    t.insert_session(instance_b, graph_b).await;
    t.jobs.hold(JOB_BUILD_GRAPH);
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_a = t.submit(operator_start_event(instance_a, graph_a, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_a, EngineInboxState::Applied).await;
    t.wait_job(graph_a, JOB_BUILD_GRAPH, EngineJobState::Running).await;

    // A's instance times out while its build runs (the session row is still
    // there, as on a node that applied the failure without this check): B's
    // build does not wait on it.
    t.set_instance_status(instance_a, InstanceBridgeInStatus::Timeout).await;
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_b = t.submit(operator_start_event(instance_b, graph_b, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_b, EngineInboxState::Applied).await;
    let ready_b = t.wait_inbox(&build_ready_id(graph_b), EngineInboxState::Applied).await;
    assert!(ready_b.waiting_ref.is_none());
    t.wait_job_live(graph_b, JOB_BUILD_GRAPH).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_graph_is_given_up_at_the_abandon_height() {
    let t = start(Actor::Operator, false).await;
    // Other operators' graphs carried the instance; this operator's graph
    // never got its committee signatures. Past the abandon height it is
    // retired and its slot left for the Skip.
    let carried = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let unfinished = t.insert_graph(carried, 0, GraphStatus::OperatorPresigned).await;
    let abandoned = SetupAbandoned { instance_id: carried, abandon_height: 166, height: 167 };
    t.submit(setup_abandoned_event(unfinished, &abandoned).unwrap()).await;
    t.wait_status(unfinished, GraphStatus::Obsoleted).await;
    assert!(t.graph_state(unfinished).await.abandoned);

    // A finalized graph, or another operator's, is never given up.
    let finalized = t.insert_graph(carried, 1, GraphStatus::CommitteePresigned).await;
    let foreign =
        t.insert_graph_of(OTHER_OPERATOR, carried, 0, GraphStatus::OperatorPresigned).await;
    for graph_id in [finalized, foreign] {
        let event_id = t.submit(setup_abandoned_event(graph_id, &abandoned).unwrap()).await;
        t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    }
    assert_eq!(t.status(finalized).await, GraphStatus::CommitteePresigned);
    assert_eq!(t.status(foreign).await, GraphStatus::OperatorPresigned);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_unfinished_at_the_abandon_height_is_released() {
    let t = start(Actor::Operator, false).await;
    let instance_a = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let instance_b = t.insert_instance(InstanceBridgeInStatus::Presigned).await;
    let instance_c = t.insert_instance(InstanceBridgeInStatus::Presigned).await;
    let (graph_a, graph_b, graph_c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    for (instance_id, graph_id) in
        [(instance_a, graph_a), (instance_b, graph_b), (instance_c, graph_c)]
    {
        t.insert_session(instance_id, graph_id).await;
    }
    let abandon = |instance_id| SetupAbandoned { instance_id, abandon_height: 166, height: 166 };
    t.jobs.hold(JOB_BUILD_GRAPH);

    // A's build is running and B's build waits behind it when A's instance
    // passes the abandon height: A's session goes and B builds.
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_a = t.submit(operator_start_event(instance_a, graph_a, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_a, EngineInboxState::Applied).await;
    t.wait_job(graph_a, JOB_BUILD_GRAPH, EngineJobState::Running).await;
    t.script(JOB_OPERATOR_INIT, build_plan());
    let start_b = t.submit(operator_start_event(instance_b, graph_b, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_b, EngineInboxState::Applied).await;
    t.wait_waiting(&build_ready_id(graph_b)).await;
    t.submit(setup_abandoned_event(graph_a, &abandon(instance_a)).unwrap()).await;
    t.wait_inbox(&build_ready_id(graph_b), EngineInboxState::Applied).await;
    t.wait_job_live(graph_b, JOB_BUILD_GRAPH).await;
    assert!(t.session(graph_a).await.is_none());
    assert!(t.graph_state(graph_a).await.abandoned);

    // A session abandoned before its start applies is dropped.
    let abandoned = t.submit(setup_abandoned_event(graph_c, &abandon(instance_c)).unwrap()).await;
    t.wait_inbox(&abandoned, EngineInboxState::Applied).await;
    let start_c = t.submit(operator_start_event(instance_c, graph_c, OPERATOR).unwrap()).await;
    t.wait_inbox(&start_c, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.session(graph_c).await.is_none());
    assert_eq!(t.called(JOB_OPERATOR_INIT).len(), 2, "C never starts");
    t.stop().await;
}

// ------------------------------------------------------------------ peg-out

const OTHER_OPERATOR: &str = "02other";

impl Harness {
    async fn insert_graph_of(
        &self,
        operator: &str,
        instance_id: Uuid,
        nonce: i64,
        status: GraphStatus,
    ) -> Uuid {
        let graph_id = Uuid::new_v4();
        let mut storage = self.db.acquire().await.unwrap();
        storage
            .upsert_graph_definition(&Graph {
                graph_id,
                instance_id,
                status: GraphStatus::OperatorPresigned.to_string(),
                definition_hash: "definition".to_string(),
                operator_pubkey: operator.to_string(),
                kickoff_index: nonce,
                ..Default::default()
            })
            .await
            .unwrap();
        drop(storage);
        if status != GraphStatus::OperatorPresigned {
            self.set_status(instance_id, graph_id, status).await;
        }
        graph_id
    }

    async fn status(&self, graph_id: Uuid) -> GraphStatus {
        let row = self.db.acquire().await.unwrap().find_graph(&graph_id).await.unwrap().unwrap();
        row.status.parse().unwrap()
    }

    async fn wait_status(&self, graph_id: Uuid, status: GraphStatus) {
        wait_for(|| async { (self.status(graph_id).await == status).then_some(()) }).await
    }

    async fn graph_state(&self, graph_id: Uuid) -> GraphState {
        serde_json::from_str(self.aggregate(graph_id).await.state.as_deref().unwrap()).unwrap()
    }

    async fn session(&self, graph_id: Uuid) -> Option<store::PendingGraphInit> {
        let mut storage = self.db.acquire().await.unwrap();
        storage.find_pending_graph_init_by_graph_id(&graph_id).await.unwrap()
    }

    fn called(&self, action: &str) -> Vec<Vec<u8>> {
        self.calls()
            .into_iter()
            .filter(|(called, _)| called == action)
            .map(|(_, params)| params)
            .collect()
    }
}

fn scan(
    height: i64,
    status_at_scan: GraphStatus,
    stage: GraphStatus,
    signals: Vec<PegoutSignal>,
    unusable: Option<Unusable>,
) -> ChainScan {
    ChainScan {
        height,
        status_at_scan: status_at_scan.to_string(),
        stage,
        sub_status: None,
        challenge_txid: None,
        unusable,
        signals,
    }
}

fn txid(byte: u8) -> bitcoin::Txid {
    use bitcoin::hashes::Hash;
    bitcoin::Txid::from_byte_array([byte; 32])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdraw_waits_for_the_previous_slot_and_kicks_off_once_it_settles() {
    let t = start(Actor::Operator, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let previous = t.insert_graph(instance_id, 0, GraphStatus::OperatorDataPushed).await;
    let graph_id = t.insert_graph(instance_id, 1, GraphStatus::OperatorDataPushed).await;

    let init = t.submit(withdraw_init_event(graph_id, "0xinit").unwrap()).await;
    let row = t.wait_waiting(&init).await;
    assert_eq!(row.waiting_ref.as_deref(), Some(slot_ref(OPERATOR, 0).as_str()));
    // Meanwhile a job settles the earlier slots from chain facts.
    t.wait_job(graph_id, JOB_SETTLE_PREDECESSORS, EngineJobState::Done).await;
    let params: KickoffParams =
        serde_json::from_slice(&t.job_params(JOB_SETTLE_PREDECESSORS)).unwrap();
    assert_eq!(params.tx_hash, "0xinit");
    t.wait_phase(graph_id, PHASE_KICKOFF).await;
    assert!(t.called(JOB_KICKOFF).is_empty(), "no kickoff over an unsettled slot");

    // The previous slot settles on Goat: mirroring it wakes the withdraw.
    t.set_status(instance_id, previous, GraphStatus::OperatorTake1).await;
    t.submit(goat_status_event(previous, GraphStatus::OperatorTake1, "0xtake1").unwrap()).await;
    t.wait_inbox(&init, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_KICKOFF, EngineJobState::Done).await;
    let params: KickoffParams = serde_json::from_slice(&t.job_params(JOB_KICKOFF)).unwrap();
    assert_eq!(params.tx_hash, "0xinit");
    assert_eq!(t.wait_phase(previous, PHASE_CLOSED).await.status, "OperatorTake1");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_withdraw_never_kicks_off_and_a_new_one_starts_over() {
    let t = start(Actor::Operator, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let previous = t.insert_graph(instance_id, 0, GraphStatus::OperatorKickOff).await;
    let graph_id = t.insert_graph(instance_id, 1, GraphStatus::OperatorDataPushed).await;

    let init = t.submit(withdraw_init_event(graph_id, "0xfirst").unwrap()).await;
    t.wait_waiting(&init).await;
    let cancel = t.submit(withdraw_cancel_event(graph_id, "0xcancel").unwrap()).await;
    t.wait_inbox(&cancel, EngineInboxState::Applied).await;
    t.wait_phase(graph_id, PHASE_AWAIT_WITHDRAW).await;

    // The previous slot settles; the cancelled withdraw stays cancelled.
    t.set_status(instance_id, previous, GraphStatus::OperatorTake1).await;
    t.submit(goat_status_event(previous, GraphStatus::OperatorTake1, "0xtake1").unwrap()).await;
    t.wait_inbox(&init, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.called(JOB_KICKOFF).is_empty());

    // A new InitWithdraw gets jobs of its own.
    let again = t.submit(withdraw_init_event(graph_id, "0xsecond").unwrap()).await;
    t.wait_inbox(&again, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_KICKOFF, EngineJobState::Done).await;
    let params: KickoffParams = serde_json::from_slice(&t.job_params(JOB_KICKOFF)).unwrap();
    assert_eq!(params.tx_hash, "0xsecond");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_withdraw_replaces_the_active_one() {
    let t = start(Actor::Operator, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let previous = t.insert_graph(instance_id, 0, GraphStatus::OperatorKickOff).await;
    let graph_id = t.insert_graph(instance_id, 1, GraphStatus::OperatorDataPushed).await;

    let first = t.submit(withdraw_init_event(graph_id, "0xfirst").unwrap()).await;
    t.wait_waiting(&first).await;
    // Its cancel never reached this node: the next init takes over.
    let second = t.submit(withdraw_init_event(graph_id, "0xsecond").unwrap()).await;
    t.wait_waiting(&second).await;
    let state = t.graph_state(graph_id).await;
    assert_eq!(state.withdraw.as_deref(), Some("0xsecond"));
    assert_eq!(state.retired_withdraws, vec!["0xfirst".to_string()]);

    // The previous slot settles: only the live withdraw kicks off.
    t.set_status(instance_id, previous, GraphStatus::OperatorTake1).await;
    t.submit(goat_status_event(previous, GraphStatus::OperatorTake1, "0xtake1").unwrap()).await;
    t.wait_inbox(&first, EngineInboxState::Applied).await;
    t.wait_inbox(&second, EngineInboxState::Applied).await;
    t.wait_job(graph_id, JOB_KICKOFF, EngineJobState::Done).await;
    settle().await;
    let kickoffs = t.called(JOB_KICKOFF);
    assert_eq!(kickoffs.len(), 1);
    let params: KickoffParams = serde_json::from_slice(&kickoffs[0]).unwrap();
    assert_eq!(params.tx_hash, "0xsecond");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_owning_operator_acts_on_a_withdraw() {
    let t = start(Actor::Operator, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let foreign =
        t.insert_graph_of(OTHER_OPERATOR, instance_id, 0, GraphStatus::OperatorDataPushed).await;
    let init = t.submit(withdraw_init_event(foreign, "0xother").unwrap()).await;
    t.wait_inbox(&init, EngineInboxState::Applied).await;
    // The first slot has no predecessor: the own graph kicks off at once.
    let own = t.insert_graph(instance_id, 0, GraphStatus::OperatorDataPushed).await;
    let init = t.submit(withdraw_init_event(own, "0xown").unwrap()).await;
    t.wait_inbox(&init, EngineInboxState::Applied).await;
    t.wait_job(own, JOB_KICKOFF, EngineJobState::Done).await;
    assert!(t.jobs_of(foreign).await.is_empty());
    t.stop().await;

    let t = start(Actor::Verifier, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let graph_id = t.insert_graph(instance_id, 0, GraphStatus::OperatorDataPushed).await;
    let init = t.submit(withdraw_init_event(graph_id, "0xv").unwrap()).await;
    t.wait_inbox(&init, EngineInboxState::Applied).await;
    settle().await;
    assert!(t.calls().is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_scan_records_the_stage_and_runs_each_roles_job() {
    let signals = vec![PegoutSignal::PreKickoffSent, PegoutSignal::KickoffSent];
    for (actor, relayer, expected) in [
        (Actor::Verifier, false, vec![JOB_CHECK_PREVIOUS_GRAPH, JOB_CHALLENGE_KICKOFF]),
        (Actor::Committee, true, vec![JOB_PROCEED_WITHDRAW]),
        (Actor::Committee, false, vec![]),
        (Actor::Watchtower, false, vec![]),
    ] {
        let t = start(actor.clone(), relayer).await;
        let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
        let graph_id = t.insert_graph(instance_id, 1, GraphStatus::OperatorDataPushed).await;
        let event = scan(
            100,
            GraphStatus::OperatorDataPushed,
            GraphStatus::OperatorKickOff,
            signals.clone(),
            None,
        )
        .event(graph_id)
        .unwrap();
        let event_id = t.submit(event).await;
        t.wait_inbox(&event_id, EngineInboxState::Applied).await;
        t.wait_status(graph_id, GraphStatus::OperatorKickOff).await;
        t.wait_phase(graph_id, PHASE_SETTLEMENT).await;
        for action in &expected {
            t.wait_job(graph_id, action, EngineJobState::Done).await;
        }
        settle().await;
        let mut called: Vec<String> = t.calls().into_iter().map(|(action, _)| action).collect();
        called.sort();
        let mut expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
        expected.sort();
        assert_eq!(called, expected, "{actor} relayer={relayer}");
        if actor == Actor::Verifier {
            let check = PegoutSignal::decode(&t.job_params(JOB_CHECK_PREVIOUS_GRAPH)).unwrap();
            assert_eq!(check, PegoutSignal::PreKickoffSent);
        }
        t.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_graph_keeps_the_relayers_goat_call() {
    let t = start(Actor::Committee, true).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let graph_id = t.insert_graph(instance_id, 0, GraphStatus::OperatorKickOff).await;
    let event = scan(
        200,
        GraphStatus::OperatorKickOff,
        GraphStatus::OperatorTake1,
        vec![PegoutSignal::PreKickoffSent, PegoutSignal::KickoffSent, PegoutSignal::Take1Sent],
        None,
    )
    .event(graph_id)
    .unwrap();
    let event_id = t.submit(event).await;
    t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    t.wait_phase(graph_id, PHASE_CLOSED).await;
    // Closing the graph cancels setup work, not the Goat call it still owes.
    t.wait_job(graph_id, JOB_FINISH_HAPPY, EngineJobState::Done).await;
    t.wait_job(graph_id, JOB_PROCEED_WITHDRAW, EngineJobState::Done).await;
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_prekickoff_obsoletes_the_slot_and_every_later_one() {
    let t = start(Actor::Committee, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::RelayerL2Minted).await;
    let earlier = t.insert_graph(instance_id, 1, GraphStatus::OperatorDataPushed).await;
    let dead = t.insert_graph(instance_id, 2, GraphStatus::CommitteePresigned).await;
    let later = t.insert_graph(instance_id, 3, GraphStatus::OperatorDataPushed).await;
    let foreign =
        t.insert_graph_of(OTHER_OPERATOR, instance_id, 5, GraphStatus::OperatorPresigned).await;
    let unusable = Unusable::PrekickoffInputSpent {
        outpoint: bitcoin::OutPoint { txid: txid(1), vout: 2 },
        spent_by: txid(9),
    };
    let event = scan(
        300,
        GraphStatus::CommitteePresigned,
        GraphStatus::CommitteePresigned,
        Vec::new(),
        Some(unusable),
    )
    .event(dead)
    .unwrap();
    let event_id = t.submit(event).await;
    t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    t.wait_status(dead, GraphStatus::Obsoleted).await;
    // A later slot follows from its own scans, which report the dead slot at
    // every height: posted on Goat, it still stays Obsoleted.
    let mut status_at_scan = GraphStatus::OperatorDataPushed;
    for height in [300, 301] {
        let behind = scan(
            height,
            status_at_scan,
            GraphStatus::OperatorDataPushed,
            Vec::new(),
            Some(Unusable::EarlierSlotDead { slot: 2 }),
        );
        let event_id = t.submit(behind.event(later).unwrap()).await;
        t.wait_inbox(&event_id, EngineInboxState::Applied).await;
        assert_eq!(t.status(later).await, GraphStatus::Obsoleted);
        status_at_scan = GraphStatus::Obsoleted;
    }
    assert_eq!(t.status(earlier).await, GraphStatus::OperatorDataPushed);
    assert_eq!(t.status(foreign).await, GraphStatus::OperatorPresigned);
    assert!(t.graph_state(dead).await.dead);
    assert!(!t.graph_state(later).await.dead, "only the dead slot raises the alert");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_obsoleted_graph_stays_monitored_and_follows_the_chain() {
    let t = start(Actor::Verifier, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::Timeout).await;
    let graph_id = t.insert_graph(instance_id, 1, GraphStatus::Obsoleted).await;
    let taken = Unusable::ConnectorZeroTaken { spent_by: txid(7) };

    // Posted on Goat after all: the projection gives way to the fact.
    let posted = scan(10, GraphStatus::Obsoleted, GraphStatus::OperatorDataPushed, vec![], None);
    t.submit(posted.event(graph_id).unwrap()).await;
    t.wait_status(graph_id, GraphStatus::OperatorDataPushed).await;
    // Another graph took Connector-0: unusable again.
    let gone = scan(
        11,
        GraphStatus::OperatorDataPushed,
        GraphStatus::OperatorDataPushed,
        vec![],
        Some(taken),
    );
    t.submit(gone.event(graph_id).unwrap()).await;
    t.wait_status(graph_id, GraphStatus::Obsoleted).await;
    // Its Pre-Kickoff lands: chain progress overrides the projection, and
    // the verifier checks the previous slot.
    let prekicked = scan(
        12,
        GraphStatus::Obsoleted,
        GraphStatus::PreKickoff,
        vec![PegoutSignal::PreKickoffSent],
        None,
    );
    t.submit(prekicked.event(graph_id).unwrap()).await;
    t.wait_status(graph_id, GraphStatus::PreKickoff).await;
    t.wait_job(graph_id, JOB_CHECK_PREVIOUS_GRAPH, EngineJobState::Done).await;
    // Skipped: closed, out of the monitoring set.
    let skipped = scan(
        13,
        GraphStatus::PreKickoff,
        GraphStatus::Skipped,
        vec![PegoutSignal::PreKickoffSent],
        None,
    );
    t.submit(skipped.event(graph_id).unwrap()).await;
    t.wait_status(graph_id, GraphStatus::Skipped).await;
    t.wait_phase(graph_id, PHASE_CLOSED).await;
    assert_eq!(t.called(JOB_CHECK_PREVIOUS_GRAPH).len(), 1, "a signal runs its job once");
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_stored_after_its_instance_failed_is_obsoleted_by_its_scan() {
    let t = start(Actor::Committee, false).await;
    // A pull stored the definition after the instance had already failed:
    // the instance's own failure never saw it.
    let instance_id = t.insert_instance(InstanceBridgeInStatus::Timeout).await;
    let graph_id = t.insert_graph(instance_id, 2, GraphStatus::OperatorPresigned).await;
    let event =
        scan(40, GraphStatus::OperatorPresigned, GraphStatus::OperatorPresigned, Vec::new(), None)
            .event(graph_id)
            .unwrap();
    t.submit(event).await;
    t.wait_status(graph_id, GraphStatus::Obsoleted).await;
    t.wait_phase(graph_id, PHASE_OBSOLETED).await;
    t.stop().await;
}
