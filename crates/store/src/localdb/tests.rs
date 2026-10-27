use super::*;
use crate::{Instance, MetricsStateCount, Node, OperatorProof};
use indexmap::IndexMap;
use sqlx::types::Uuid;

async fn setup_db() -> LocalDB {
    create_local_db("sqlite::memory:").await
}

fn pegin_instance(instance_id: Uuid, status: &str) -> Instance {
    Instance {
        instance_id,
        network: "testnet".to_string(),
        input_utxos: "[]".to_string(),
        status: status.to_string(),
        created_at: 100,
        updated_at: 100,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_upsert_pegin_request_instance_refreshes_a_waiting_row() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let instance_id = Uuid::new_v4();

    let mut initing = pegin_instance(instance_id, "UserInited");
    initing.to_addr = "0xuser".to_string();
    initing.from_addr = "bcrt1quser".to_string();
    assert!(s.insert_instance_if_absent(&initing).await.unwrap());

    let mut request = pegin_instance(instance_id, "UserInited");
    request.to_addr = "0xuser".to_string();
    request.amount = 10_000;
    request.goat_tx_hash = "0xrequest".to_string();
    request.goat_tx_height = 500;
    request.status_updated_at = 200;
    request.created_at = 999;
    request.updated_at = 999;
    assert!(s.upsert_pegin_request_instance(&request).await.unwrap());

    let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(stored.status, "UserInited");
    assert_eq!(stored.amount, 10_000);
    assert_eq!(stored.goat_tx_hash, "0xrequest");
    assert_eq!(stored.goat_tx_height, 500);
    assert_eq!(stored.status_updated_at, 200);
    // An undecodable from_addr must not erase the one the request tag stored.
    assert_eq!(stored.from_addr, "bcrt1quser");
    // created_at belongs to whoever created the row.
    assert_eq!(stored.created_at, 100);
}

#[tokio::test]
async fn test_upsert_pegin_request_instance_replay_keeps_accrued_state() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let instance_id = Uuid::new_v4();

    let mut inited = pegin_instance(instance_id, "UserInited");
    inited.goat_tx_hash = "0xrequest".to_string();
    inited.goat_tx_height = 500;
    inited.committees_answers = IndexMap::from([("0xcommittee".to_string(), vec![1u8, 2, 3])]);
    inited.parameters = Some("{}".to_string());
    assert!(s.insert_instance_if_absent(&inited).await.unwrap());

    // A re-delivered request refreshes the row in place; everything the
    // instance accrued after the request must survive it.
    let mut replay = pegin_instance(instance_id, "UserInited");
    replay.goat_tx_hash = "0xrequest".to_string();
    replay.goat_tx_height = 500;
    assert!(s.upsert_pegin_request_instance(&replay).await.unwrap());
    let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(stored.committees_answers.get("0xcommittee"), Some(&vec![1u8, 2, 3]));
    assert_eq!(stored.parameters, Some("{}".to_string()));
    assert_eq!(stored.goat_tx_height, 500);
}

#[tokio::test]
async fn test_upsert_pegin_request_instance_rejects_regression() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let instance_id = Uuid::new_v4();

    let mut minted = pegin_instance(instance_id, "RelayerL2Minted");
    minted.goat_tx_hash = "0xrequest".to_string();
    minted.goat_tx_height = 500;
    minted.parameters = Some("{}".to_string());
    minted.post_pegin_txhash = Some("0xmint".to_string());
    assert!(s.insert_instance_if_absent(&minted).await.unwrap());

    // Once the instance moves on, a re-delivered request may not pull it back.
    let replay = pegin_instance(instance_id, "UserInited");
    assert!(!s.upsert_pegin_request_instance(&replay).await.unwrap());
    let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(stored.status, "RelayerL2Minted");
    assert_eq!(stored.parameters, Some("{}".to_string()));
    assert_eq!(stored.post_pegin_txhash, Some("0xmint".to_string()));
    assert_eq!(stored.goat_tx_height, 500);
}

#[tokio::test]
async fn test_upsert_pegin_request_instance_rejects_progressed_instance() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let instance_id = Uuid::new_v4();

    let progressed = pegin_instance(instance_id, "CommitteesAnswered");
    assert!(s.insert_instance_if_absent(&progressed).await.unwrap());

    let request = pegin_instance(instance_id, "UserInited");
    assert!(!s.upsert_pegin_request_instance(&request).await.unwrap());
    let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
    assert_eq!(stored.status, "CommitteesAnswered");
}

#[tokio::test]
async fn test_instance_update_rejects_stale_status_transition() {
    let db = setup_db().await;
    let instance_id = Uuid::new_v4();
    let mut storage = db.acquire().await.unwrap();
    assert!(
        storage
            .insert_instance_if_absent(&pegin_instance(instance_id, "RelayerL2Minted"))
            .await
            .unwrap()
    );

    let updated = storage
        .update_instance(
            &InstanceUpdate::new_with_instance_id(instance_id)
                .with_status("Timeout".to_string())
                .with_only_if_status_in(vec!["Presigned".to_string()]),
        )
        .await
        .unwrap();
    assert!(!updated);
    assert_eq!(
        storage.find_instance(&instance_id).await.unwrap().unwrap().status,
        "RelayerL2Minted"
    );
}

#[tokio::test]
async fn test_node_metrics_state_counts() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    sqlx::query(
        "INSERT INTO instance (instance_id, status, created_at, updated_at) VALUES ('in-1', 'Pending', 20, 20), ('in-2', 'Pending', 10, 10)",
    )
    .execute(s.conn())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO swap_escrow (escrow_hash, status, created_at, updated_at) VALUES ('0xaa', 'Initialize', 30, 30)",
    )
    .execute(s.conn())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO graph (graph_id, instance_id, status, kickoff_index, created_at, updated_at) VALUES ('graph-1', 'in-1', 'Created', 0, 40, 40), ('graph-2', 'in-2', 'Created', 1, 25, 25)",
    )
    .execute(s.conn())
    .await
    .unwrap();

    let counts = s.node_metrics_state_counts().await.unwrap();
    assert_eq!(
        counts.iter().find(|count| count.category == "instance" && count.state == "Pending"),
        Some(&MetricsStateCount {
            category: "instance".to_string(),
            state: "Pending".to_string(),
            count: 2,
            oldest_created_at: Some(10),
            last_success_at: None,
        })
    );
    assert_eq!(
        counts
            .iter()
            .find(|count| count.category == "swap_escrow" && count.state == "Initialize")
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        counts
            .iter()
            .find(|count| count.category == "graph" && count.state == "Created")
            .unwrap()
            .oldest_created_at,
        Some(25)
    );
    assert!(
        counts.iter().all(|count| {
            matches!(count.category.as_str(), "instance" | "swap_escrow" | "graph")
        })
    );
}

/// Verify confirmed operator bindings are loaded before unconfirmed identities.
#[tokio::test]
async fn confirmed_operator_bindings_are_loaded_first() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let operator = |peer_id: &str, updated_at: i64| Node {
        peer_id: peer_id.to_string(),
        actor: "Operator".to_string(),
        btc_pub_key: format!("key-of-{peer_id}"),
        binding_sig: "sig".to_string(),
        binding_issued_at: 1,
        updated_at,
        created_at: updated_at,
        ..Default::default()
    };
    s.upsert_node(&operator("confirmed", 10)).await.unwrap();
    for index in 0..4 {
        s.upsert_node(&operator(&format!("recent-{index}"), 900 + index)).await.unwrap();
    }
    // Not an operator, and an operator without a binding: never loaded.
    s.upsert_node(&Node { actor: "Committee".to_string(), ..operator("member", 999) })
        .await
        .unwrap();
    s.upsert_node(&Node { binding_sig: String::new(), ..operator("unbound", 999) }).await.unwrap();
    s.upsert_p2p_registered_peer("confirmed", "Operator", "aa").await.unwrap();

    let loaded: Vec<String> =
        s.load_p2p_peer_bindings(2).await.unwrap().into_iter().map(|node| node.peer_id).collect();
    assert_eq!(loaded, ["confirmed", "recent-3"]);
}

#[tokio::test]
async fn registered_peers_persist_and_shield_their_node_rows() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    s.upsert_p2p_registered_peer("member", "Committee", "").await.unwrap();
    s.upsert_p2p_registered_peer("member", "Committee", "").await.unwrap();
    s.upsert_p2p_registered_peer("other-member", "Committee", "").await.unwrap();
    s.upsert_p2p_registered_peer("operator", "Operator", "aa").await.unwrap();
    let load = async |s: &mut StorageProcessor<'_>| {
        let mut peers = s.load_p2p_registered_peers().await.unwrap();
        peers.sort();
        peers
    };
    let row =
        |peer: &str, kind: &str, key: &str| (peer.to_string(), kind.to_string(), key.to_string());
    assert_eq!(
        load(&mut s).await,
        [
            row("member", "Committee", ""),
            row("operator", "Operator", "aa"),
            row("other-member", "Committee", "")
        ],
        "keyless kinds never displace each other"
    );
    // Move the key's registration to the new peer.
    s.upsert_p2p_registered_peer("operator-moved", "Operator", "aa").await.unwrap();
    // A peer confirmed for another key keeps one row, for the new key.
    s.upsert_p2p_registered_peer("operator-moved", "Operator", "bb").await.unwrap();
    assert_eq!(
        load(&mut s).await,
        [
            row("member", "Committee", ""),
            row("operator-moved", "Operator", "bb"),
            row("other-member", "Committee", "")
        ]
    );
    s.delete_p2p_registered_peer("operator-moved", "Operator").await.unwrap();
    s.delete_p2p_registered_peer("other-member", "Committee").await.unwrap();
    assert_eq!(load(&mut s).await.len(), 1);

    for (peer_id, updated_at) in [("member", 10), ("sybil", 10), ("local", 10), ("live", 900)] {
        s.upsert_node(&Node {
            peer_id: peer_id.to_string(),
            actor: "Operator".to_string(),
            updated_at,
            created_at: updated_at,
            ..Default::default()
        })
        .await
        .unwrap();
    }
    // Only unregistered rows count toward capacity; stale rows may be evicted.
    assert!(s.node_row_admissible("sybil", 3, 0, "local").await.unwrap());
    assert!(s.node_row_admissible("newcomer", 4, 0, "local").await.unwrap());
    assert!(
        !s.node_row_admissible("newcomer", 3, 5, "local").await.unwrap(),
        "full, and every row was refreshed after the eviction horizon"
    );
    assert!(
        s.node_row_admissible("newcomer", 3, 500, "local").await.unwrap(),
        "the stalest unregistered row makes room"
    );
    let known = async |s: &mut StorageProcessor<'_>, peer_id: &str| {
        s.node_row_admissible(peer_id, 0, 0, "local").await.unwrap()
    };
    assert!(!known(&mut s, "sybil").await, "evicted: stale, unregistered, not this node");
    for kept in ["member", "local", "live"] {
        assert!(known(&mut s, kept).await, "{kept}");
    }

    s.upsert_node(&Node {
        peer_id: "left".to_string(),
        actor: "Watchtower".to_string(),
        updated_at: 20,
        created_at: 20,
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(s.purge_stale_unregistered_nodes(500, "local").await.unwrap(), 1);
    assert!(!known(&mut s, "left").await);
    assert!(known(&mut s, "member").await && known(&mut s, "local").await);
}

#[tokio::test]
async fn test_upsert_and_find_latest_hash_change() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    s.upsert_sequencer_set_hash_change(100, 1000, "aabbcc").await.unwrap();
    s.upsert_sequencer_set_hash_change(200, 2000, "ddeeff").await.unwrap();
    s.upsert_sequencer_set_hash_change(150, 1500, "112233").await.unwrap();

    let latest = s.find_latest_sequencer_set_hash_change().await.unwrap().unwrap();
    assert_eq!(latest.cosmos_block_height, 200);
    assert_eq!(latest.goat_block_height, 2000);
    assert_eq!(latest.validators_hash, "ddeeff");
}

#[tokio::test]
async fn test_upsert_hash_change_conflict() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    s.upsert_sequencer_set_hash_change(100, 1000, "aabbcc").await.unwrap();
    // Same cosmos_block_height, different data — should overwrite
    s.upsert_sequencer_set_hash_change(100, 1001, "ddeeff").await.unwrap();

    let latest = s.find_latest_sequencer_set_hash_change().await.unwrap().unwrap();
    assert_eq!(latest.cosmos_block_height, 100);
    assert_eq!(latest.goat_block_height, 1001);
    assert_eq!(latest.validators_hash, "ddeeff");
}

#[tokio::test]
async fn test_find_by_goat_block_at_or_before() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    s.upsert_sequencer_set_hash_change(100, 1000, "aa").await.unwrap();
    s.upsert_sequencer_set_hash_change(200, 2000, "bb").await.unwrap();
    s.upsert_sequencer_set_hash_change(300, 3000, "cc").await.unwrap();

    // Exact match
    let r = s
        .find_first_sequencer_set_hash_change_by_goat_block_at_or_before(2000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.goat_block_height, 2000);
    assert_eq!(r.validators_hash, "bb");

    // Between records — should return previous one
    let r = s
        .find_first_sequencer_set_hash_change_by_goat_block_at_or_before(2500)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.goat_block_height, 2000);
    assert_eq!(r.validators_hash, "bb");

    // Before all records — should return None
    let r = s.find_first_sequencer_set_hash_change_by_goat_block_at_or_before(500).await.unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn test_scan_state_upsert_and_get() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    assert!(s.get_sequencer_set_scan_state().await.unwrap().is_none());

    s.upsert_sequencer_set_scan_state(100, 1000, "aabbcc").await.unwrap();
    let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
    assert_eq!(state.next_cosmos_block_height, 100);
    assert_eq!(state.latest_goat_block_height, 1000);
    assert_eq!(state.latest_validators_hash, "aabbcc");

    // Update
    s.upsert_sequencer_set_scan_state(200, 2000, "ddeeff").await.unwrap();
    let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
    assert_eq!(state.next_cosmos_block_height, 200);
    assert_eq!(state.latest_validators_hash, "ddeeff");
}

// proof-builder-rpc keeps its proofs in these tables through the shared store migrations; offline sqlx
// checks would not notice the tables disappearing from the migrations, this does.
#[tokio::test]
async fn test_proof_builder_tables_are_migrated() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();

    // Ziren 2.0 removes the bundled v1 header proof. The table must still exist.
    assert!(
        s.find_latest_long_running_task_proof_by_name("header-chain".to_string())
            .await
            .unwrap()
            .is_none()
    );

    let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
    let proof = OperatorProof {
        instance_id,
        graph_id,
        operator_committed_blockhash: "00".repeat(32),
        execution_layer_block_number: 7,
        ..Default::default()
    };
    assert_eq!(s.create_operator_proof(&proof).await.unwrap(), 1);
    let stored = s
        .find_operator_proof_by_instance_and_graph(&instance_id, &graph_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.execution_layer_block_number, 7);
    assert!(s.proof_metrics_state_counts().await.is_ok());
}

use crate::{LongRunningTaskProof, OnDemandProofCompletion, OnDemandProofTable, WatchtowerProof};
fn on_demand_completion() -> OnDemandProofCompletion {
    OnDemandProofCompletion {
        path_to_proof: "proofs/1.bin".to_string(),
        public_value_hex: "00".to_string(),
        proof_size: 1,
        cycles: 2,
        proof_state: crate::ProofState::Proven.to_i64(),
        total_time_to_proof: 3,
        proving_time: 4,
        zkm_version: "v2".to_string(),
    }
}

async fn new_operator_proof(s: &mut StorageProcessor<'_>) -> OperatorProof {
    let proof = OperatorProof {
        instance_id: Uuid::new_v4(),
        graph_id: Uuid::new_v4(),
        proof_state: crate::ProofState::New.to_i64(),
        ..Default::default()
    };
    assert_eq!(s.create_operator_proof(&proof).await.unwrap(), 1);
    s.find_next_operator_proof().await.unwrap().unwrap()
}

#[tokio::test]
async fn test_complete_on_demand_proof_only_while_new() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let task = new_operator_proof(&mut s).await;
    let table = OnDemandProofTable::Operator;

    let completion = on_demand_completion();
    assert_eq!(s.complete_on_demand_proof_if_new(table, task.id, &completion).await.unwrap(), 1);
    assert_eq!(
        s.get_on_demand_proof_state(table, task.id).await.unwrap(),
        Some(crate::ProofState::Proven.to_i64())
    );
    // A finished task is never rewritten, including by a later timeout.
    assert_eq!(s.complete_on_demand_proof_if_new(table, task.id, &completion).await.unwrap(), 0);
    let timed_out = s
        .update_operator_proof_state_with_instance_graph(
            &task.instance_id,
            &task.graph_id,
            crate::ProofState::New.to_i64(),
            crate::ProofState::Failed.to_i64(),
        )
        .await
        .unwrap();
    assert_eq!(timed_out, 0);
    assert_eq!(s.get_on_demand_proof_state(table, i64::MAX).await.unwrap(), None);
}

#[tokio::test]
async fn test_timed_out_on_demand_proof_is_not_completed() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let task = new_operator_proof(&mut s).await;
    s.update_operator_proof_state_with_instance_graph(
        &task.instance_id,
        &task.graph_id,
        crate::ProofState::New.to_i64(),
        crate::ProofState::Failed.to_i64(),
    )
    .await
    .unwrap();

    let table = OnDemandProofTable::Operator;
    let completion = on_demand_completion();
    assert_eq!(s.complete_on_demand_proof_if_new(table, task.id, &completion).await.unwrap(), 0);
    assert_eq!(
        s.get_on_demand_proof_state(table, task.id).await.unwrap(),
        Some(crate::ProofState::Failed.to_i64())
    );

    let watchtower = WatchtowerProof {
        instance_id: Uuid::new_v4(),
        graph_id: Uuid::new_v4(),
        public_key: "pk".to_string(),
        proof_state: crate::ProofState::New.to_i64(),
        ..Default::default()
    };
    s.create_watchtower_proof(&watchtower).await.unwrap();
    let watchtower_task = s.find_next_watchtower_proof().await.unwrap().unwrap();
    s.update_watchtower_proof_state_with_instance_graph_pubkey(
        &watchtower.instance_id,
        &watchtower.graph_id,
        "pk",
        crate::ProofState::New.to_i64(),
        crate::ProofState::Failed.to_i64(),
    )
    .await
    .unwrap();
    let table = OnDemandProofTable::Watchtower;
    assert_eq!(
        s.complete_on_demand_proof_if_new(table, watchtower_task.id, &completion).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn test_count_pending_long_running_task_proofs() {
    let db = setup_db().await;
    let mut s = db.acquire().await.unwrap();
    let chain = "state-chain".to_string();
    for (start, state) in [
        (5, crate::ProofState::New),
        (10, crate::ProofState::Proven),
        (20, crate::ProofState::New),
        (30, crate::ProofState::Proving),
        (40, crate::ProofState::Failed),
    ] {
        s.create_long_running_task_proof(&LongRunningTaskProof {
            block_start: start,
            block_end: start + 10,
            chain_name: chain.clone(),
            proof_state: state.to_i64(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    assert_eq!(s.count_pending_long_running_task_proofs(&chain, 20).await.unwrap(), 2);
    assert_eq!(s.count_pending_long_running_task_proofs(&chain, 0).await.unwrap(), 3);
    assert_eq!(s.count_pending_long_running_task_proofs("header-chain", 0).await.unwrap(), 0);
}
