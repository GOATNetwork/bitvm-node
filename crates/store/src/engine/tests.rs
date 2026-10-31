use super::*;
use crate::localdb::{LocalDB, create_local_db};

async fn setup_db() -> LocalDB {
    create_local_db("sqlite::memory:").await
}

fn event(id: &str, aggregate_id: &str) -> NewEngineInboxEvent {
    NewEngineInboxEvent {
        event_id: id.to_string(),
        aggregate_kind: "test".to_string(),
        aggregate_id: aggregate_id.to_string(),
        kind: "ping".to_string(),
        source: "local".to_string(),
        author: String::new(),
        admission_class: String::new(),
        payload: b"payload".to_vec(),
        ack: Some(EngineAckTarget { peer: "peer-a".to_string(), delivery_id: "d1".to_string() }),
    }
}

fn network_event(id: &str, author: &str, class: &str, bytes: usize) -> NewEngineInboxEvent {
    NewEngineInboxEvent {
        event_id: id.to_string(),
        aggregate_kind: "graph".to_string(),
        aggregate_id: "g".to_string(),
        kind: "CreateGraph".to_string(),
        source: "network".to_string(),
        author: author.to_string(),
        admission_class: class.to_string(),
        payload: vec![0; bytes],
        ack: None,
    }
}

/// The quota sees what an author currently makes the node store: rows
/// that still hold a payload, by class, with the author's own share.
#[tokio::test]
async fn inbox_usage_counts_queued_network_rows_per_class_and_author() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    for (id, author, class, bytes) in [
        ("a1", "alice", "Unregistered", 10),
        ("a2", "alice", "Registered", 20),
        ("b1", "bob", "Unregistered", 40),
        ("c1", "carol", "Committee", 80),
    ] {
        s.insert_engine_inbox_event(&network_event(id, author, class, bytes), 1).await.unwrap();
    }
    // A local event and an applied network event hold no payload.
    s.insert_engine_inbox_event(&event("local", "x"), 1).await.unwrap();
    s.insert_engine_inbox_event(&network_event("done", "bob", "Unregistered", 160), 1)
        .await
        .unwrap();
    assert!(s.mark_engine_inbox_applied("done", 2).await.unwrap());
    // Waiting and failed rows keep theirs.
    assert!(s.mark_engine_inbox_waiting("b1", "dep", "x", 100, 2).await.unwrap());
    assert!(s.mark_engine_inbox_failed("c1", "bad", 2).await.unwrap());

    let mut totals = s.engine_inbox_class_totals().await.unwrap();
    totals.sort_by(|a, b| a.admission_class.cmp(&b.admission_class));
    let total = |class: &str| -> (i64, i64) {
        totals
            .iter()
            .find(|usage| usage.admission_class == class)
            .map(|usage| (usage.rows, usage.bytes))
            .unwrap_or((0, 0))
    };
    assert_eq!(total("Unregistered"), (2, 50));
    assert_eq!(total("Registered"), (1, 20));
    assert_eq!(total("Committee"), (1, 80));
    assert!(totals.iter().all(|usage| usage.peer_rows == 0 && usage.peer_bytes == 0));

    let alice = s.engine_inbox_peer_usage("alice").await.unwrap();
    let share = |class: &str| -> (i64, i64) {
        alice
            .iter()
            .find(|usage| usage.admission_class == class)
            .map(|usage| (usage.peer_rows, usage.peer_bytes))
            .unwrap_or((0, 0))
    };
    assert_eq!(share("Unregistered"), (1, 10));
    assert_eq!(share("Registered"), (1, 20));
    assert!(s.engine_inbox_peer_usage("nobody").await.unwrap().is_empty());
}

#[test]
fn shard_key_is_stable_and_non_negative() {
    assert_eq!(engine_shard_key("graph", "abc"), engine_shard_key("graph", "abc"));
    assert_ne!(engine_shard_key("graph", "abc"), engine_shard_key("instance", "abc"));
    assert!(engine_shard_key("graph", "abc") >= 0);
    assert!(engine_shard_key("", "") >= 0);
}

#[tokio::test]
async fn inbox_dedup_rearms_failed_and_acks_applied_or_waiting() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let e = event("e1", "a");
    assert!(matches!(
        s.insert_engine_inbox_event(&e, 10).await.unwrap(),
        EngineInboxInsert::Inserted { .. }
    ));
    // Pending and not yet applied: ignored, no ACK.
    assert_eq!(
        s.insert_engine_inbox_event(&e, 11).await.unwrap(),
        EngineInboxInsert::Duplicate {
            state: EngineInboxState::Pending,
            ack_again: false,
            rearmed: false
        }
    );
    // Waiting: parked with material kept -> ACK again.
    assert!(s.mark_engine_inbox_waiting("e1", "dep:x", "need x", 1_000, 12).await.unwrap());
    assert_eq!(
        s.insert_engine_inbox_event(&e, 13).await.unwrap(),
        EngineInboxInsert::Duplicate {
            state: EngineInboxState::Pending,
            ack_again: true,
            rearmed: false
        }
    );
    let parked = s.find_engine_inbox_event("e1").await.unwrap().unwrap();
    assert_eq!(parked.payload.as_deref(), Some(b"payload".as_slice()));
    assert_eq!(parked.next_at, 1_000);
    // Failed: re-armed as Pending now, no ACK.
    assert!(s.mark_engine_inbox_failed("e1", "bad", 14).await.unwrap());
    assert_eq!(
        s.insert_engine_inbox_event(&e, 15).await.unwrap(),
        EngineInboxInsert::Duplicate {
            state: EngineInboxState::Failed,
            ack_again: false,
            rearmed: true
        }
    );
    let rearmed = s.find_engine_inbox_event("e1").await.unwrap().unwrap();
    assert_eq!(rearmed.state, "Pending");
    assert_eq!(rearmed.next_at, 15);
    assert!(rearmed.last_error.is_none());
    // Applied: payload cleared, ACK again.
    assert!(s.mark_engine_inbox_applied("e1", 16).await.unwrap());
    assert_eq!(
        s.insert_engine_inbox_event(&e, 17).await.unwrap(),
        EngineInboxInsert::Duplicate {
            state: EngineInboxState::Applied,
            ack_again: true,
            rearmed: false
        }
    );
    let applied = s.find_engine_inbox_event("e1").await.unwrap().unwrap();
    assert!(applied.payload.is_none());
    assert_eq!(applied.applied_at, Some(16));
    assert_eq!(applied.ack_target().unwrap().peer, "peer-a");
    // Poisoned rows are terminal and never re-armed.
    s.insert_engine_inbox_event(&event("e2", "a"), 20).await.unwrap();
    assert!(s.mark_engine_inbox_poisoned("e2", "panic", 21).await.unwrap());
    assert_eq!(
        s.insert_engine_inbox_event(&event("e2", "a"), 22).await.unwrap(),
        EngineInboxInsert::Duplicate {
            state: EngineInboxState::Poisoned,
            ack_again: false,
            rearmed: false
        }
    );
}

#[tokio::test]
async fn inbox_runnable_selection_respects_shard_order_and_wakeups() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    s.insert_engine_inbox_event(&event("e1", "agg-1"), 10).await.unwrap();
    s.insert_engine_inbox_event(&event("e2", "agg-1"), 11).await.unwrap();
    s.insert_engine_inbox_event(&event("e3", "agg-2"), 12).await.unwrap();
    let shard = engine_shard_key("test", "agg-1") % 7;
    let other = engine_shard_key("test", "agg-2") % 7;
    // Only this shard's rows, oldest first.
    let next = s.next_runnable_engine_inbox_event(7, shard, 100).await.unwrap().unwrap();
    assert_eq!(next.event_id, "e1");
    assert!(s.mark_engine_inbox_applied("e1", 100).await.unwrap());
    let next = s.next_runnable_engine_inbox_event(7, shard, 100).await.unwrap().unwrap();
    assert_eq!(next.event_id, "e2");
    // A waiting row is not runnable until its ref is woken or the time passes.
    assert!(s.mark_engine_inbox_waiting("e2", "graph:g0", "need g0", 10_000, 100).await.unwrap());
    assert!(
        s.next_runnable_engine_inbox_event(7, shard, 100).await.unwrap().is_none()
            || shard == other
    );
    assert_eq!(s.wake_engine_inbox_waiting(&["graph:other".to_string()], 101).await.unwrap(), 0);
    assert_eq!(s.wake_engine_inbox_waiting(&["graph:g0".to_string()], 101).await.unwrap(), 1);
    let woken = s.find_engine_inbox_event("e2").await.unwrap().unwrap();
    assert_eq!(woken.next_at, 101);
    assert_eq!(woken.waiting_ref.as_deref(), Some("graph:g0"));
    // Periodic re-arm and startup re-arm.
    assert!(s.mark_engine_inbox_waiting("e2", "graph:g0", "need g0", 10_000, 102).await.unwrap());
    assert!(s.mark_engine_inbox_retry("e3", "busy", 5_000, 102).await.unwrap());
    assert_eq!(s.rearm_engine_inbox_waiting(103).await.unwrap(), 1);
    assert_eq!(s.rearm_engine_inbox_pending(104).await.unwrap(), 1);
    let retried = s.find_engine_inbox_event("e3").await.unwrap().unwrap();
    assert_eq!(retried.attempts, 1);
    assert_eq!(retried.next_at, 104);
}

#[tokio::test]
async fn aggregate_upsert_and_poison_per_action() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let update = EngineAggregateUpdate {
        status: Some("Presigned".to_string()),
        phase: Some("Confirm".to_string()),
        state: Some(Some("{\"n\":1}".to_string())),
        last_event_id: Some("e1".to_string()),
    };
    let aggregate = s.upsert_engine_aggregate("instance", "i1", &update, 10).await.unwrap();
    assert_eq!(aggregate.status, "Presigned");
    assert_eq!(aggregate.phase, "Confirm");
    assert_eq!(aggregate.state.as_deref(), Some("{\"n\":1}"));
    assert_eq!(aggregate.last_event_id.as_deref(), Some("e1"));
    assert_eq!(aggregate.version, 1);
    // Untouched fields keep their value; `Some(None)` clears the state.
    let again = EngineAggregateUpdate { phase: Some("Post".to_string()), ..Default::default() };
    let aggregate = s.upsert_engine_aggregate("instance", "i1", &again, 20).await.unwrap();
    assert_eq!((aggregate.status.as_str(), aggregate.phase.as_str()), ("Presigned", "Post"));
    assert_eq!(aggregate.state.as_deref(), Some("{\"n\":1}"));
    assert_eq!(aggregate.version, 2);
    let clear = EngineAggregateUpdate { state: Some(None), ..Default::default() };
    let aggregate = s.upsert_engine_aggregate("instance", "i1", &clear, 30).await.unwrap();
    assert!(aggregate.state.is_none());
    assert_eq!(aggregate.status, "Presigned");
    // Poison is per action: the first poison blocks for backoff(1), the
    // second for backoff(2); a clean run of the action releases it.
    let backoff = |count: i64| if count <= 1 { 0 } else { 600 };
    let first = s
        .mark_engine_aggregate_poisoned("instance", "i1", "sign", "panic", 40, &backoff)
        .await
        .unwrap();
    assert_eq!((first.poison_count, first.blocked_until), (1, 40));
    let second = s
        .mark_engine_aggregate_poisoned("instance", "i1", "sign", "panic again", 41, &backoff)
        .await
        .unwrap();
    assert_eq!((second.poison_count, second.blocked_until), (2, 641));
    assert_eq!(second.reason, "panic again");
    s.mark_engine_aggregate_poisoned("instance", "i1", "vote", "panic", 42, &backoff)
        .await
        .unwrap();
    let listed = s.list_engine_poisons(Some(("instance", "i1")), 10).await.unwrap();
    assert_eq!(
        listed.iter().map(|p| (p.action.as_str(), p.poison_count)).collect::<Vec<_>>(),
        vec![("sign", 2), ("vote", 1)]
    );
    assert!(s.release_engine_poison("instance", "i1", "vote").await.unwrap());
    assert!(!s.release_engine_poison("instance", "i1", "vote").await.unwrap());
    assert_eq!(s.list_engine_poisons(None, 10).await.unwrap().len(), 1);
    // A manual clear removes every action of the aggregate.
    s.mark_engine_aggregate_poisoned("instance", "i2", "x", "panic", 60, &backoff).await.unwrap();
    assert_eq!(s.clear_engine_aggregate_poison("instance", "i1", None).await.unwrap(), 1);
    assert_eq!(s.clear_engine_aggregate_poison("instance", "i1", None).await.unwrap(), 0);
    assert_eq!(s.clear_engine_aggregate_poison("instance", "i2", Some("y")).await.unwrap(), 0);
    assert_eq!(s.clear_engine_aggregate_poison("instance", "i2", Some("x")).await.unwrap(), 1);
}

#[tokio::test]
async fn poisoned_event_kinds_wait_out_their_backoff() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    s.insert_engine_inbox_event(&event("e1", "a"), 10).await.unwrap();
    let backoff = |_: i64| 100;
    s.mark_engine_aggregate_poisoned("test", "a", "ping", "panic", 10, &backoff).await.unwrap();
    // The kind is held back while the backoff runs, other kinds and aggregates are not.
    assert!(s.next_runnable_engine_inbox_event(1, 0, 50).await.unwrap().is_none());
    let mut other = event("e2", "a");
    other.kind = "pong".to_string();
    s.insert_engine_inbox_event(&other, 11).await.unwrap();
    let next = s.next_runnable_engine_inbox_event(1, 0, 50).await.unwrap().unwrap();
    assert_eq!(next.event_id, "e2");
    s.mark_engine_inbox_applied("e2", 51).await.unwrap();
    assert_eq!(
        s.next_runnable_engine_inbox_event(1, 0, 110).await.unwrap().unwrap().event_id,
        "e1"
    );
    // Parking does not count as an attempt.
    assert!(s.mark_engine_inbox_waiting("e1", "x", "y", 200, 111).await.unwrap());
    assert_eq!(s.find_engine_inbox_event("e1").await.unwrap().unwrap().attempts, 0);
    let waiting = s.list_engine_inbox_waiting(10).await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!((waiting[0].event_id.as_str(), waiting[0].waiting_ref.as_str()), ("e1", "x"));
}

fn outbox(id: &str, ack_set: Option<BTreeMap<String, String>>) -> NewEngineOutboxMessage {
    NewEngineOutboxMessage {
        outbox_id: id.to_string(),
        aggregate_kind: "graph".to_string(),
        aggregate_id: "g1".to_string(),
        phase_ref: "setup".to_string(),
        kind: "CreateGraph".to_string(),
        topic: "all".to_string(),
        payload: vec![1, 2, 3],
        ack_set,
        first_at: 10,
    }
}

#[tokio::test]
async fn outbox_claim_publish_ack_and_close() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let acks = BTreeMap::from([
        ("peer-a".to_string(), "deliv-a".to_string()),
        ("peer-b".to_string(), "deliv-b".to_string()),
    ]);
    assert!(s.insert_engine_outbox_message(&outbox("o1", Some(acks)), 10).await.unwrap());
    assert!(!s.insert_engine_outbox_message(&outbox("o1", None), 11).await.unwrap());
    assert!(s.insert_engine_outbox_message(&outbox("o2", None), 10).await.unwrap());
    // Claim: both due, leased until 100.
    let claimed = s.claim_due_engine_outbox_messages(10, 100, 10).await.unwrap();
    assert_eq!(claimed.len(), 2);
    assert!(s.claim_due_engine_outbox_messages(11, 100, 10).await.unwrap().is_empty());
    assert!(s.record_engine_outbox_publish("o1", 40, 12).await.unwrap());
    assert!(s.record_engine_outbox_publish_failure("o2", "no peers", 20, 12).await.unwrap());
    let o1 = s.find_engine_outbox_message("o1").await.unwrap().unwrap();
    assert_eq!((o1.publish_count, o1.next_at, o1.lease_until), (1, 40, 0));
    let o2 = s.find_engine_outbox_message("o2").await.unwrap().unwrap();
    assert_eq!((o2.publish_count, o2.next_at, o2.last_error.as_deref()), (0, 20, Some("no peers")));
    // ACK: wrong peer for a known delivery id does not count.
    assert_eq!(
        s.acknowledge_engine_outbox("peer-b", "deliv-a", 13).await.unwrap(),
        EngineOutboxAck::NoMatch
    );
    assert_eq!(
        s.acknowledge_engine_outbox("peer-a", "deliv-a", 13).await.unwrap(),
        EngineOutboxAck::Matched { outbox_id: "o1".to_string(), closed: false }
    );
    assert_eq!(
        s.acknowledge_engine_outbox("peer-a", "deliv-a", 14).await.unwrap(),
        EngineOutboxAck::NoMatch
    );
    assert_eq!(
        s.acknowledge_engine_outbox("peer-b", "deliv-b", 15).await.unwrap(),
        EngineOutboxAck::Matched { outbox_id: "o1".to_string(), closed: true }
    );
    let o1 = s.find_engine_outbox_message("o1").await.unwrap().unwrap();
    assert_eq!((o1.state.as_str(), o1.close_reason.as_deref()), ("Closed", Some("acked")));
    // Closed rows are not re-opened by a repeated insert, and not re-published.
    assert!(!s.insert_engine_outbox_message(&outbox("o1", None), 16).await.unwrap());
    assert!(!s.record_engine_outbox_publish("o1", 50, 16).await.unwrap());
    // Phase close covers the small message.
    let target = EngineOutboxCloseTarget::Phase {
        aggregate_kind: "graph".to_string(),
        aggregate_id: "g1".to_string(),
        phase_ref: "setup".to_string(),
    };
    assert_eq!(s.close_engine_outbox(&target, "evidence", 17).await.unwrap(), 1);
    // Aggregate close and row close.
    assert!(s.insert_engine_outbox_message(&outbox("o3", None), 18).await.unwrap());
    assert!(s.insert_engine_outbox_message(&outbox("o4", None), 18).await.unwrap());
    assert_eq!(
        s.close_engine_outbox(&EngineOutboxCloseTarget::Row("o3".to_string()), "x", 19)
            .await
            .unwrap(),
        1
    );
    let target = EngineOutboxCloseTarget::Aggregate {
        aggregate_kind: "graph".to_string(),
        aggregate_id: "g1".to_string(),
    };
    assert_eq!(s.close_engine_outbox(&target, "instance_failed", 20).await.unwrap(), 1);
    // Startup lease reset.
    assert!(s.insert_engine_outbox_message(&outbox("o5", None), 21).await.unwrap());
    assert_eq!(s.claim_due_engine_outbox_messages(21, 500, 10).await.unwrap().len(), 1);
    assert_eq!(s.reset_engine_outbox_leases().await.unwrap(), 1);
    assert_eq!(s.claim_due_engine_outbox_messages(22, 500, 10).await.unwrap().len(), 1);
}

fn job(id: &str, action: &str) -> NewEngineJob {
    NewEngineJob {
        job_id: id.to_string(),
        aggregate_kind: "graph".to_string(),
        aggregate_id: "g1".to_string(),
        phase: "kickoff".to_string(),
        action: action.to_string(),
        pool: "cpu".to_string(),
        params: vec![9],
        deadline_at: None,
        first_at: 10,
    }
}

#[tokio::test]
async fn jobs_of_one_aggregate_run_one_at_a_time() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let other = NewEngineJob {
        job_id: "other".to_string(),
        aggregate_id: "g2".to_string(),
        pool: "network".to_string(),
        ..job("other", "ingest")
    };
    let same_pool = job("j2", "ingest");
    let network = NewEngineJob { pool: "network".to_string(), ..job("j3", "fetch") };
    for row in [&job("j1", "sign"), &same_pool, &network, &other] {
        assert!(s.insert_engine_job(row, 10).await.unwrap().is_inserted());
    }
    // The oldest job of g1 is claimed; its siblings wait in every pool,
    // another aggregate's job does not.
    let cpu = s.claim_due_engine_jobs("cpu", 10, 100, 10).await.unwrap();
    assert_eq!(cpu.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j1"]);
    let net = s.claim_due_engine_jobs("network", 11, 100, 10).await.unwrap();
    assert_eq!(net.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["other"]);
    s.finish_engine_job("other", 1, &EngineJobFinish::Done(vec![]), 11).await.unwrap();
    // Done: the next sibling runs.
    s.finish_engine_job("j1", 1, &EngineJobFinish::Done(vec![]), 12).await.unwrap();
    let cpu = s.claim_due_engine_jobs("cpu", 13, 100, 10).await.unwrap();
    assert_eq!(cpu.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j2"]);
    assert!(s.claim_due_engine_jobs("network", 14, 100, 10).await.unwrap().is_empty());
    // A lapsed lease no longer blocks the siblings (the stale holder is fenced).
    let net = s.claim_due_engine_jobs("network", 101, 200, 10).await.unwrap();
    assert_eq!(net.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j3"]);
}

#[tokio::test]
async fn job_lease_generation_fencing_and_cancel() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    assert!(s.insert_engine_job(&job("j1", "broadcast"), 10).await.unwrap().is_inserted());
    assert_eq!(
        s.insert_engine_job(&job("j1", "broadcast"), 11).await.unwrap(),
        EngineJobInsert::Existing(EngineJobState::Pending)
    );
    // First claim: generation 1, leased until 100.
    let first = s.claim_due_engine_jobs("cpu", 10, 100, 10).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(
        (first[0].generation, first[0].attempts, first[0].state.as_str()),
        (1, 1, "Running")
    );
    assert!(s.claim_due_engine_jobs("cpu", 50, 100, 10).await.unwrap().is_empty());
    assert!(s.claim_due_engine_jobs("network", 200, 300, 10).await.unwrap().is_empty());
    // Lease lapses: a second holder claims with generation 2.
    let second = s.claim_due_engine_jobs("cpu", 200, 300, 10).await.unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].generation, 2);
    // The late first holder cannot renew or finish.
    assert!(!s.renew_engine_job_lease("j1", 1, 400, 201).await.unwrap());
    assert!(s.renew_engine_job_lease("j1", 2, 400, 201).await.unwrap());
    assert_eq!(
        s.finish_engine_job("j1", 1, &EngineJobFinish::Done(vec![1]), 202).await.unwrap(),
        EngineJobFinishOutcome::Stale { current_generation: 2, state: "Running".to_string() }
    );
    let job_row = s.find_engine_job("j1").await.unwrap().unwrap();
    assert!(job_row.result.is_none());
    assert_eq!(job_row.state, "Running");
    // The current holder's transient failure re-queues, then it finishes.
    assert_eq!(
        s.finish_engine_job(
            "j1",
            2,
            &EngineJobFinish::Retry { error: "rpc".to_string(), next_at: 500 },
            203
        )
        .await
        .unwrap(),
        EngineJobFinishOutcome::Applied { state: EngineJobState::Pending }
    );
    assert!(s.claim_due_engine_jobs("cpu", 499, 600, 10).await.unwrap().is_empty());
    let third = s.claim_due_engine_jobs("cpu", 500, 600, 10).await.unwrap();
    assert_eq!(third[0].generation, 3);
    assert_eq!(
        s.finish_engine_job("j1", 3, &EngineJobFinish::Done(vec![7]), 501).await.unwrap(),
        EngineJobFinishOutcome::Applied { state: EngineJobState::Done }
    );
    let done = s.find_engine_job("j1").await.unwrap().unwrap();
    assert_eq!(
        (done.state.as_str(), done.result.as_deref(), done.finished_at),
        ("Done", Some([7].as_slice()), Some(501))
    );
    assert_eq!(
        s.finish_engine_job("j1", 3, &EngineJobFinish::Done(vec![8]), 502).await.unwrap(),
        EngineJobFinishOutcome::Stale { current_generation: 3, state: "Done".to_string() }
    );
    assert_eq!(
        s.finish_engine_job("missing", 1, &EngineJobFinish::Done(vec![]), 503).await.unwrap(),
        EngineJobFinishOutcome::Missing
    );
    // Cancel: pending is cancelled at once, running finishes as Cancelled.
    assert!(s.insert_engine_job(&job("j2", "broadcast"), 600).await.unwrap().is_inserted());
    assert!(s.cancel_engine_job("j2", 601).await.unwrap());
    assert_eq!(s.find_engine_job("j2").await.unwrap().unwrap().state, "Cancelled");
    assert!(s.insert_engine_job(&job("j3", "broadcast"), 600).await.unwrap().is_inserted());
    let running = s.claim_due_engine_jobs("cpu", 600, 700, 10).await.unwrap();
    assert_eq!(running[0].job_id, "j3");
    assert!(s.cancel_engine_job("j3", 602).await.unwrap());
    assert_eq!(
        s.finish_engine_job("j3", 1, &EngineJobFinish::Done(vec![1]), 603).await.unwrap(),
        EngineJobFinishOutcome::Applied { state: EngineJobState::Cancelled }
    );
    // Phase cancel and poison isolation.
    assert!(s.insert_engine_job(&job("j4", "sign"), 700).await.unwrap().is_inserted());
    assert!(s.insert_engine_job(&job("j5", "broadcast"), 700).await.unwrap().is_inserted());
    let backoff = |_: i64| 100;
    s.mark_engine_aggregate_poisoned("graph", "g1", "sign", "panic", 701, &backoff).await.unwrap();
    let claimable = s.claim_due_engine_jobs("cpu", 701, 800, 10).await.unwrap();
    assert_eq!(claimable.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j5"]);
    assert_eq!(s.clear_engine_aggregate_poison("graph", "g1", None).await.unwrap(), 1);
    assert_eq!(s.cancel_engine_jobs_for_phase("graph", "g1", "kickoff", 703).await.unwrap(), 2);
    assert_eq!(s.find_engine_job("j4").await.unwrap().unwrap().state, "Cancelled");
    assert!(s.find_engine_job("j5").await.unwrap().unwrap().cancel_requested);
    assert!(s.insert_engine_job(&job("j6", "broadcast"), 800).await.unwrap().is_inserted());
    // j5 is still running (leased until 800): its sibling j6 waits.
    assert!(s.claim_due_engine_jobs("cpu", 799, 900, 10).await.unwrap().is_empty());
    // Startup lease reset: the cancelled running job is not run again but
    // finished as Cancelled (the executor sweeps before it claims), then j6 runs.
    assert_eq!(s.reset_engine_job_leases().await.unwrap(), 1);
    let swept = s.finish_lapsed_cancelled_engine_jobs(801).await.unwrap();
    assert_eq!(swept.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j5"]);
    assert_eq!(swept[0].state, "Cancelled");
    assert!(s.finish_lapsed_cancelled_engine_jobs(802).await.unwrap().is_empty());
    let claimed = s.claim_due_engine_jobs("cpu", 802, 900, 10).await.unwrap();
    assert_eq!(claimed.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j6"]);
    // A poisoned action is claimable again once its backoff passed.
    assert!(s.insert_engine_job(&job("j7", "sign"), 900).await.unwrap().is_inserted());
    s.finish_engine_job("j6", 1, &EngineJobFinish::Done(vec![]), 900).await.unwrap();
    s.mark_engine_aggregate_poisoned("graph", "g1", "sign", "panic", 900, &backoff).await.unwrap();
    assert!(s.claim_due_engine_jobs("cpu", 950, 1000, 10).await.unwrap().is_empty());
    let claimed = s.claim_due_engine_jobs("cpu", 1000, 1100, 10).await.unwrap();
    assert_eq!(claimed.iter().map(|j| j.job_id.as_str()).collect::<Vec<_>>(), vec!["j7"]);
}

#[tokio::test]
async fn state_counts_and_purge() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    s.insert_engine_inbox_event(&event("e1", "a"), 10).await.unwrap();
    s.insert_engine_inbox_event(&event("e2", "a"), 10).await.unwrap();
    s.mark_engine_inbox_applied("e1", 11).await.unwrap();
    s.mark_engine_inbox_waiting("e2", "x", "y", 100, 11).await.unwrap();
    s.insert_engine_outbox_message(&outbox("o1", None), 10).await.unwrap();
    s.insert_engine_job(&job("j1", "a"), 10).await.unwrap();
    let counts = s.engine_state_counts().await.unwrap();
    let get = |table: &str, state: &str| {
        counts.iter().find(|c| c.table == table && c.state == state).map(|c| c.count).unwrap_or(0)
    };
    assert_eq!(get("inbox", "Applied"), 1);
    assert_eq!(get("inbox", "Pending"), 1);
    assert_eq!(get("inbox_waiting", "Waiting"), 1);
    assert_eq!(get("outbox", "Open"), 1);
    assert_eq!(get("job", "Pending"), 1);
    // Purge removes only terminal rows older than the cutoff.
    assert_eq!(s.purge_engine_terminal_rows(11).await.unwrap(), 0);
    assert_eq!(s.purge_engine_terminal_rows(12).await.unwrap(), 1);
    assert!(s.find_engine_inbox_event("e1").await.unwrap().is_none());
    assert!(s.find_engine_inbox_event("e2").await.unwrap().is_some());
    assert_eq!(s.list_engine_inbox_events_for_aggregate("test", "a", 10).await.unwrap().len(), 1);
}

/// Rejected network events stop counting against the quota long before
/// the terminal retention; everything else keeps its row.
#[tokio::test]
async fn rejected_network_rows_are_purged_early() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    for id in ["rejected", "parked", "fresh-rejected", "pending"] {
        s.insert_engine_inbox_event(&network_event(id, "alice", "Registered", 8), 100)
            .await
            .unwrap();
    }
    // A rejected local event is never the quota's business.
    s.insert_engine_inbox_event(&event("local", "x"), 100).await.unwrap();
    s.mark_engine_inbox_failed("local", "no", 150).await.unwrap();
    s.mark_engine_inbox_failed("rejected", "no", 150).await.unwrap();
    s.mark_engine_inbox_failed("fresh-rejected", "no", 950).await.unwrap();
    s.mark_engine_inbox_waiting("parked", "slot", "d", 1_000, 150).await.unwrap();
    assert_eq!(s.purge_rejected_network_inbox_rows(900).await.unwrap(), 1);
    for (id, kept) in [
        ("rejected", false),
        ("parked", true),
        ("fresh-rejected", true),
        ("pending", true),
        ("local", true),
    ] {
        assert_eq!(s.find_engine_inbox_event(id).await.unwrap().is_some(), kept, "{id}");
    }
}
