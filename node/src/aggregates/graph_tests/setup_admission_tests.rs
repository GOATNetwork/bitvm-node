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
        let author = peer.to_string();
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
