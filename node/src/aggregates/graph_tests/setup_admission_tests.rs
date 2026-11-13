//! Verifier admission of InitGraph to the CPU-heavy setup.

use super::*;
use crate::messages::{GOATMessage, GOATMessageContent, sign_init_graph};
use bitcoin::secp256k1::{Keypair, SECP256K1};
use libp2p::PeerId;

fn operator_key(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
}

impl Harness {
    /// A signed InitGraph from `peer`, as `inbound_event` would record it.
    async fn init_graph(
        &self,
        operator: &Keypair,
        peer: PeerId,
        instance_id: Uuid,
        graph_id: Uuid,
        tamper: bool,
    ) -> NewEvent {
        self.init_graph_from(operator, peer, peer, instance_id, graph_id, tamper).await
    }

    /// An InitGraph signed for `peer` but relayed by `source`.
    async fn init_graph_from(
        &self,
        operator: &Keypair,
        peer: PeerId,
        source: PeerId,
        instance_id: Uuid,
        graph_id: Uuid,
        tamper: bool,
    ) -> NewEvent {
        let mut init = sign_init_graph(instance_id, graph_id, operator, peer.to_bytes());
        if tamper {
            // Claim another operator's key under this signature.
            init.operator_pubkey = operator_key(1).public_key().into();
        }
        let operator_pubkey = init.operator_pubkey.to_string();
        let message =
            GOATMessage { actor: Actor::Operator, content: GOATMessageContent::InitGraph(init) }
                .serialize_message()
                .await
                .unwrap();
        let author = source.to_string();
        let inbound = InboundMessage {
            author: author.clone(),
            instance_id,
            graph_nonce: None,
            operator_pubkey: Some(operator_pubkey),
            message,
        };
        NewEvent::new(
            content_event_id(&author, "InitGraph", &graph_id.to_string(), &inbound.message),
            graph_ref(graph_id),
            "InitGraph",
            EventSource::Network,
            inbound.encode().unwrap(),
        )
        .with_author(&author)
    }

    async fn insert_instance_with_id(&self, instance_id: Uuid, status: InstanceBridgeInStatus) {
        let mut storage = self.db.acquire().await.unwrap();
        let instance = Instance { instance_id, status: status.to_string(), ..Default::default() };
        assert!(storage.insert_instance_if_absent(&instance).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_admits_one_setup_per_operator_on_a_live_instance() {
    let t = start(Actor::Verifier, false).await;
    let (operator, peer) = (operator_key(7), PeerId::random());
    let instance_id = Uuid::new_v4();

    // The instance is unknown here: wait for it instead of running the setup.
    let first = Uuid::new_v4();
    let event = t.submit(t.init_graph(&operator, peer, instance_id, first, false).await).await;
    t.wait_waiting(&event).await;
    t.insert_instance_with_id(instance_id, InstanceBridgeInStatus::CommitteesAnswered).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(t.called(JOB_VERIFIER_SETUP).is_empty(), "no setup before Peg-In-Prepare");

    t.set_instance_status(instance_id, InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    t.wait_job(first, JOB_VERIFIER_SETUP, EngineJobState::Done).await;

    // Another graph of the same operator and instance is ignored.
    let second = Uuid::new_v4();
    let event = t.submit(t.init_graph(&operator, peer, instance_id, second, false).await).await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    assert!(t.jobs_of(second).await.is_empty());

    // A forged signature is rejected; another operator is admitted.
    let forged = Uuid::new_v4();
    let event =
        t.submit(t.init_graph(&operator_key(8), peer, instance_id, forged, true).await).await;
    t.wait_inbox(&event, EngineInboxState::Failed).await;
    let other = Uuid::new_v4();
    let event = t
        .submit(t.init_graph(&operator_key(9), PeerId::random(), instance_id, other, false).await)
        .await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    t.wait_job(other, JOB_VERIFIER_SETUP, EngineJobState::Done).await;
    assert_eq!(t.called(JOB_VERIFIER_SETUP).len(), 2);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_ignores_init_graph_for_a_failed_instance() {
    let t = start(Actor::Verifier, false).await;
    let instance_id = t.insert_instance(InstanceBridgeInStatus::Timeout).await;
    let graph_id = Uuid::new_v4();
    let event = t
        .submit(
            t.init_graph(&operator_key(7), PeerId::random(), instance_id, graph_id, false).await,
        )
        .await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    assert!(t.jobs_of(graph_id).await.is_empty());
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_binds_the_admission_to_the_authenticated_init_graph() {
    let t = start(Actor::Verifier, false).await;
    let (operator, peer) = (operator_key(7), PeerId::random());
    let instance_id = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let other_instance = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;

    // A relayed copy under another instance is ignored and must not decide
    // which instance the graph's admission counts against.
    let first = Uuid::new_v4();
    let event = t
        .submit(
            t.init_graph_from(&operator, peer, PeerId::random(), other_instance, first, false)
                .await,
        )
        .await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    let event = t.submit(t.init_graph(&operator, peer, instance_id, first, false).await).await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    t.wait_job(first, JOB_VERIFIER_SETUP, EngineJobState::Done).await;

    // The same graph under another instance does not reuse the admission.
    let event = t.submit(t.init_graph(&operator, peer, other_instance, first, false).await).await;
    t.wait_inbox(&event, EngineInboxState::Failed).await;

    // The operator's second graph on the instance is still ignored.
    let second = Uuid::new_v4();
    let event = t.submit(t.init_graph(&operator, peer, instance_id, second, false).await).await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    assert!(t.jobs_of(second).await.is_empty());
    assert_eq!(t.called(JOB_VERIFIER_SETUP).len(), 1);
    t.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_closes_a_setup_whose_graph_never_arrives_at_the_abandon_height() {
    let t = start(Actor::Verifier, false).await;
    let (operator, peer) = (operator_key(7), PeerId::random());
    let instance_id = t.insert_instance(InstanceBridgeInStatus::UserBroadcastPeginPrepare).await;
    let graph_id = Uuid::new_v4();

    // The setup package goes out, then the operator goes offline before its
    // graph: the package would be resent forever.
    t.script(
        JOB_VERIFIER_SETUP,
        GraphPlan {
            messages: vec![planned(graph_id, "GenCircuits", PHASE_SETUP, Some(&peer.to_string()))],
            ..Default::default()
        },
    );
    let event = t.submit(t.init_graph(&operator, peer, instance_id, graph_id, false).await).await;
    t.wait_inbox(&event, EngineInboxState::Applied).await;
    let sent = outbox_id(graph_id, "GenCircuits", None);
    t.wait_outbox(&sent, EngineOutboxState::Open).await;
    assert_eq!(t.watched().await, BTreeMap::from([(graph_id, instance_id)]));

    let abandoned = SetupAbandoned { instance_id, abandon_height: 166, height: 167 };
    let event_id = t.submit(setup_abandoned_event(graph_id, &abandoned).unwrap()).await;
    t.wait_inbox(&event_id, EngineInboxState::Applied).await;
    let closed = t.wait_outbox(&sent, EngineOutboxState::Closed).await;
    assert_eq!(closed.close_reason.as_deref(), Some("setup abandoned"));
    assert!(t.graph_state(graph_id).await.abandoned);
    assert!(t.watched().await.is_empty(), "reported once");
    t.stop().await;
}
