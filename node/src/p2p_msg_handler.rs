//! The swarm's message handler: admission of inbound gossip, the control
//! worker for `NodeInfo` and ACKs, the admission maintenance task and the
//! direct `GetGraph` service. Protocol work runs on the engine.

use crate::action::{GOATMessage, GOATMessageContent, handle_inbound_p2p_message, send_to_peer};
use crate::env::get_local_node_info;
use crate::metrics_service::MetricsState;
use crate::middleware::get_graph::{GetGraphRequest, GetGraphResponse};
use crate::middleware::publisher::NetworkPublisher;
use crate::middleware::swarm::{BitvmSwarmWrapper, P2pMessageHandler, TickMessageType};
use crate::utils::detect_heart_beat;
use bitvm_lib::actors::Actor;
use client::goat_chain::GOATClient;
use futures::FutureExt;
use libp2p::PeerId;
use libp2p::gossipsub::MessageId;
use libp2p::request_response::ResponseChannel;
use std::sync::{Arc, OnceLock};
use store::localdb::LocalDB;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct BitvmNodeProcessor {
    pub local_db: LocalDB,
    pub goat_client: Arc<GOATClient>,
    pub metrics_state: MetricsState,
    pub shutdown_token: CancellationToken,
    pub worker: Arc<OnceLock<WorkerControl>>,
}

pub struct ImmediateMessage {
    pub source: PeerId,
    pub message: GOATMessage,
    _bytes: OwnedSemaphorePermit,
}

pub struct WorkerControl {
    immediate: mpsc::Sender<ImmediateMessage>,
    bytes: Arc<Semaphore>,
    joins: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

fn spawn_isolated_worker<F, Fut>(
    name: &'static str,
    shutdown: CancellationToken,
    work: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let runtime = tokio::runtime::Handle::current();
    let (done, finished) = tokio::sync::oneshot::channel();
    // Run named workers with 32 MiB stacks.
    let thread = std::thread::Builder::new()
        .name(name.into())
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            runtime.block_on(async move {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {},
                    result = std::panic::AssertUnwindSafe(async move { work().await }).catch_unwind() => {
                        if result.is_err() {
                            tracing::error!(event = "p2p_worker_panic", "worker panicked; stopping node");
                            shutdown.cancel();
                        }
                    }
                }
            });
            let _ = done.send(());
        })
        .expect("start isolated protocol worker");
    tokio::spawn(async move {
        finished.await.expect("isolated worker stopped unexpectedly");
        // Done is sent after dispatch futures have been dropped; joining only
        // waits for the thread's epilogue, never for business work.
        thread.join().expect("isolated worker panicked after shutdown");
    })
}

impl WorkerControl {
    pub fn enqueue(&self, source: PeerId, message: GOATMessage, bytes: usize) -> bool {
        let Ok(bytes) = u32::try_from(bytes.max(1)) else { return false };
        let Ok(permit) = self.bytes.clone().try_acquire_many_owned(bytes) else { return false };
        self.immediate.try_send(ImmediateMessage { source, message, _bytes: permit }).is_ok()
    }
}

impl BitvmNodeProcessor {
    /// Start the control worker and the admission maintenance task. Called at
    /// boot so maintenance (verifier-set retries, registry refreshes, drop
    /// summaries) runs before the first gossip message arrives.
    pub fn start(&self, publisher: NetworkPublisher) {
        self.worker.get_or_init(|| self.spawn_worker(publisher));
    }

    fn worker(&self, swarm: &BitvmSwarmWrapper) -> &WorkerControl {
        self.worker.get_or_init(|| self.spawn_worker(swarm.publisher()))
    }

    fn spawn_worker(&self, publisher: NetworkPublisher) -> WorkerControl {
        {
            // Control dispatch (NodeInfo, ACKs) runs on its own thread, off
            // the network loop; the engine runs everything else.
            let (tx, rx) = mpsc::channel(16);
            let mut processor = self.clone();
            processor.worker = Default::default();
            let control_processor = processor.clone();
            let control_publisher = publisher.clone();
            let control_join = spawn_isolated_worker(
                "bitvm-control",
                self.shutdown_token.clone(),
                move || async move {
                    control_processor.run_immediate_worker(control_publisher, rx).await;
                },
            );
            let maintenance_join = tokio::spawn(processor.run_admission_maintenance(publisher));
            WorkerControl {
                immediate: tx,
                bytes: Arc::new(Semaphore::new(16 * 1024 * 1024)),
                joins: tokio::sync::Mutex::new(vec![control_join, maintenance_join]),
            }
        }
    }

    async fn run_immediate_worker(
        &self,
        mut publisher: NetworkPublisher,
        mut immediate: mpsc::Receiver<ImmediateMessage>,
    ) {
        while let Some(message) = immediate.recv().await {
            if let Err(error) = crate::action::dispatch_immediate_message(
                &mut publisher,
                &self.local_db,
                &self.goat_client,
                message.source,
                message.message,
                &self.metrics_state,
            )
            .await
            {
                tracing::debug!(event = "p2p_control_worker", error = %error, "control message failed");
            }
        }
    }

    /// Refresh registrations, report drops and clock skew, purge stale node
    /// rows and flush deferred NodeInfo answers. This task is the sole caller
    /// of admission maintenance.
    async fn run_admission_maintenance(self, mut publisher: NetworkPublisher) {
        let mut clock = tokio::time::interval(std::time::Duration::from_secs(
            crate::env::REGULAR_TASK_INTERVAL_SECOND,
        ));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown_token.cancelled() => return,
                _ = clock.tick() => {}
            }
            // A pass is cut short by shutdown too: `graceful_shutdown` joins
            // this task.
            tokio::select! {
                biased;
                _ = self.shutdown_token.cancelled() => return,
                _ = async {
                    crate::action::run_p2p_admission_maintenance(&self.local_db, &self.goat_client)
                        .await;
                    crate::handle::flush_deferred_node_info_response(&mut publisher).await;
                } => {}
            }
        }
    }
}
impl P2pMessageHandler for BitvmNodeProcessor {
    async fn recv_and_dispatch(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        from_peer_id: PeerId,
        propagation_source: PeerId,
        sequence_number: Option<u64>,
        id: MessageId,
        message: &[u8],
    ) -> anyhow::Result<()> {
        let worker = self.worker(swarm);
        handle_inbound_p2p_message(
            swarm,
            &self.local_db,
            &self.goat_client,
            actor,
            from_peer_id,
            propagation_source,
            sequence_number,
            id,
            message,
            &self.metrics_state,
            worker,
        )
        .await
    }

    async fn handle_tick_message(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        _peer_id: PeerId,
        actor: Actor,
        msg_type: TickMessageType,
    ) -> anyhow::Result<()> {
        match msg_type {
            TickMessageType::HeartBeat => {
                match detect_heart_beat(swarm).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("detect_heart_beat: {e}");
                    }
                }
                tracing::debug!("Handling heartbeat tick message");
                Ok(())
            }
            TickMessageType::RegularlyAction => {
                // Nothing runs on the tick any more: the engine schedules its
                // own work and the admission maintenance has its own timer.
                let _ = (swarm, actor);
                Ok(())
            }
        }
    }

    async fn finish_subscribe_topic(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        _actor: Actor,
        topic: &str,
    ) -> anyhow::Result<()> {
        if topic == Actor::All.to_string() {
            let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
            match send_to_peer(swarm, GOATMessage::new(Actor::All, message_content)).await {
                Ok(_) => {}
                Err(e) => {
                    println!("finish_subscribe_topic: send request NodeInfo {e}");
                }
            }
        }
        Ok(())
    }

    /// Serve a stored graph definition to a direct `GetGraph` request. Any
    /// role answers from its own copy; the requester authenticates what it
    /// gets. Admission is a global budget by requester class first (it has no
    /// per-key table an unregistered flood could fill), then the per-peer
    /// bucket, the per-request cooldown and a cap on definitions in flight;
    /// the read and the serialization run off the network loop.
    fn serve_graph_request(
        &self,
        peer: PeerId,
        request: GetGraphRequest,
        channel: ResponseChannel<GetGraphResponse>,
        publisher: NetworkPublisher,
    ) -> Option<ResponseChannel<GetGraphResponse>> {
        let now = std::time::Instant::now();
        let registered =
            crate::p2p_admission::peer_registry().sender_class(&peer, now).is_registered();
        if !crate::p2p_admission::get_graph_response_budget(registered).allow(now) {
            tracing::debug!(event = "get_graph", outcome = "budget_spent", %peer, registered, "GetGraph refused");
            return Some(channel);
        }
        if !crate::p2p_admission::get_graph_peer_budget().allow(&peer, now) {
            tracing::debug!(event = "get_graph", outcome = "peer_budget_spent", %peer, "GetGraph refused");
            return Some(channel);
        }
        let gate_key = format!(
            "{peer}:{:?}:{:?}:{:?}",
            request.graph_id, request.operator_pubkey, request.graph_nonce
        );
        if !crate::p2p_admission::get_graph_response_gate().allow(&gate_key, now) {
            return Some(channel);
        }
        let Ok(slot) = crate::p2p_admission::get_graph_serve_slots().clone().try_acquire_owned()
        else {
            tracing::debug!(event = "get_graph", outcome = "busy", %peer, "GetGraph refused");
            return Some(channel);
        };
        let local_db = self.local_db.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let response = match crate::aggregates::graph_fetch::serve_graph_request(
                &local_db, &request,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(event = "get_graph", outcome = "serve_failed", %peer, error = %error, "could not serve GetGraph request");
                    GetGraphResponse::not_found()
                }
            };
            if let Err(error) = publisher.respond_graph(channel, response).await {
                tracing::debug!(event = "get_graph", outcome = "response_dropped", %peer, error = %error, "GetGraph response not delivered to the swarm");
            }
        });
        None
    }

    async fn graceful_shutdown(&self) -> anyhow::Result<()> {
        self.shutdown_token.cancel();
        if let Some(worker) = self.worker.get() {
            for join in std::mem::take(&mut *worker.joins.lock().await) {
                join.await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn blocking_business_work_does_not_block_the_network_executor() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker =
            super::spawn_isolated_worker("bitvm-test", shutdown.clone(), move || async move {
                let _ = entered.send(());
                // Deliberately no await: model synchronous graph reconstruction.
                let _ = wait.recv();
            });
        ready.await.unwrap();
        let network_progress = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            1
        })
        .await;
        let _ = release.send(());
        worker.await.unwrap();
        assert_eq!(network_progress.unwrap(), 1);

        let worker = super::spawn_isolated_worker("bitvm-test", shutdown.clone(), || async {
            std::future::pending::<()>().await;
        });
        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), worker).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ephemeral_queue_is_bounded_by_rows_and_bytes() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let control = super::WorkerControl {
            immediate: tx,
            bytes: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            joins: Default::default(),
        };
        let source = libp2p::PeerId::random();
        let message = || {
            super::GOATMessage::new(
                bitvm_lib::actors::Actor::All,
                super::GOATMessageContent::RequestNodeInfo(crate::action::NodeInfo::default()),
            )
        };
        assert!(!control.enqueue(source, message(), 5));
        assert!(control.enqueue(source, message(), 4));
        assert!(!control.enqueue(source, message(), 1));
        drop(rx.recv().await.unwrap());
        assert!(control.enqueue(source, message(), 1));
        assert!(!control.enqueue(source, message(), 1));
        assert_eq!(control.bytes.available_permits(), 3, "failed enqueue releases its permits");
    }
    use crate::action::{GOATMessage, GOATMessageContent, NodeInfo, send_to_peer};
    use crate::env::get_rpc_support_actors;
    use crate::middleware::swarm::{
        BitvmNetworkManager, BitvmSwarmConfig, BitvmSwarmWrapper, P2pMessageHandler,
        TickMessageType,
    };
    use crate::utils::{generate_local_key, save_node_info};
    use base64::Engine;
    use bitvm_lib::actors::Actor;
    use libp2p::PeerId;
    use libp2p::gossipsub::MessageId;
    use prometheus_client::registry::Registry;
    use store::localdb::LocalDB;
    use tokio_util::sync::CancellationToken;
    use tracing::Level;
    use tracing::warn;

    // Return (peer_key, peer_id)
    fn gen_local_key() -> anyhow::Result<(String, String)> {
        let local_key = generate_local_key();
        let base64_key =
            base64::engine::general_purpose::STANDARD.encode(&local_key.to_protobuf_encoding()?);
        Ok((base64_key, local_key.public().to_peer_id().to_string()))
    }

    fn generate_bootnode_url(peer_id: &str, port: u16) -> String {
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}")
    }

    async fn create_and_run_bitvm_network_manager(
        local_key: Option<String>,
        p2p_port: u16,
        bootnodes: Vec<String>,
        actor: Actor,
        local_db: Option<LocalDB>,
        cancel_token: CancellationToken,
    ) {
        let mut metric_registry = Registry::default();
        let local_key = if let Some(local_key) = local_key {
            local_key
        } else {
            let (local_key, _) = gen_local_key().expect("get rand_p2p_key");
            local_key
        };
        let mut bitvm_network_manager = BitvmNetworkManager::new(
            BitvmSwarmConfig {
                local_key,
                p2p_port,
                bootnodes,
                topic_names: vec![
                    Actor::Committee.to_string(),
                    Actor::Verifier.to_string(),
                    Actor::Operator.to_string(),
                    Actor::Watchtower.to_string(),
                    Actor::All.to_string(),
                ],
                heartbeat_interval: 2,
                regular_task_interval: 3,
            },
            &mut metric_registry,
        )
        .expect("create bitvm swarm");

        let local_db = if let Some(local_db) = local_db {
            local_db
        } else {
            store::create_local_db(&temp_sqlite_db_path()).await
        };
        bitvm_network_manager
            .run(actor, MockBitvmNodeProcessor { local_db }, cancel_token)
            .await
            .expect("Failed to run bitvm swarm");
    }

    #[derive(Debug)]
    struct MockBitvmNodeProcessor {
        pub local_db: LocalDB,
    }
    pub async fn detect_heart_beat(
        swarm: &mut BitvmSwarmWrapper,
        node_info: NodeInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("start detect_heart_beat");
        let message_content = GOATMessageContent::RequestNodeInfo(node_info);
        // send to actor
        let actors = get_rpc_support_actors();
        for actor in actors {
            match send_to_peer(swarm, GOATMessage::new(actor, message_content.clone())).await {
                Ok(_) => {}
                Err(err) => warn!("{err}"),
            }
        }
        Ok(())
    }
    impl P2pMessageHandler for MockBitvmNodeProcessor {
        #[tracing::instrument(level = Level::INFO)]
        async fn recv_and_dispatch(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            from_peer_id: PeerId,
            propagation_source: PeerId,
            _sequence_number: Option<u64>,
            id: MessageId,
            message: &[u8],
        ) -> anyhow::Result<()> {
            swarm.behaviour_mut().gossipsub.report_message_validation_result(
                &id,
                &propagation_source,
                libp2p::gossipsub::MessageAcceptance::Accept,
            );
            let message = GOATMessage::deserialize_message(message).await?;
            let content: &GOATMessageContent = message.content();
            if let (GOATMessageContent::RequestNodeInfo(node_info), _) = (content, actor) {
                save_node_info(&self.local_db, node_info).await.expect("save_node_info");
            }
            Ok(())
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn handle_tick_message(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _peer_id: PeerId,
            actor: Actor,
            msg_type: TickMessageType,
        ) -> anyhow::Result<()> {
            match msg_type {
                TickMessageType::HeartBeat => {
                    detect_heart_beat(
                        swarm,
                        NodeInfo {
                            peer_id: "test".to_string(),
                            actor: actor.to_string(),
                            goat_addr: "test".to_string(),
                            btc_pub_key: "btc_pub_key_test".to_string(),
                            socket_addr: "test".to_string(),
                            node_name: "".to_string(),
                            service_fee_rate: 0.0,
                            available_peg_btc: "0".to_string(),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                    Ok(())
                }
                TickMessageType::RegularlyAction => Ok(()),
            }
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn finish_subscribe_topic(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            topic: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn init() {
        let _ = tracing_subscriber::fmt().try_init();
    }

    fn temp_sqlite_db_path() -> String {
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        format!("sqlite:{}", tmp_db.path().as_os_str().to_str().unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_p2p_heart_beat() -> anyhow::Result<()> {
        init();
        let local_db = store::create_local_db(&temp_sqlite_db_path()).await;
        let local_db_clone = local_db.clone();
        let cancellation_token = CancellationToken::new();
        let cancel_token_clone = cancellation_token.clone();
        let (local_key, peer_id) = gen_local_key()?;
        let bootnode_url = generate_bootnode_url(&peer_id, 9100);
        tokio::spawn(create_and_run_bitvm_network_manager(
            Some(local_key),
            9100,
            vec![],
            Actor::Committee,
            Some(local_db),
            cancel_token_clone,
        ));
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let cancel_token_clone = cancellation_token.clone();
        tokio::spawn(create_and_run_bitvm_network_manager(
            None,
            9101,
            vec![bootnode_url],
            Actor::Operator,
            None,
            cancel_token_clone,
        ));

        let mut index = 1;
        let mut success = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if index == 10 {
                break;
            }

            let mut storage_processor =
                local_db_clone.acquire().await.expect("Failed to acquire local db processor");
            if let Some(node) = storage_processor
                .get_node_by_btc_pub_key("btc_pub_key_test")
                .await
                .expect("Failed to get btc_pub_key")
            {
                success = node.actor == Actor::Operator.to_string();
                break;
            }
            index += 1;
        }
        cancellation_token.cancel();
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(success);
        Ok(())
    }

    /// Publishes whatever the test queued, bytes as given, on the next tick. It
    /// stands in for a peer that is not running this implementation.
    struct RawPublisher {
        queue: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl P2pMessageHandler for RawPublisher {
        async fn recv_and_dispatch(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _actor: Actor,
            _from_peer_id: PeerId,
            propagation_source: PeerId,
            _sequence_number: Option<u64>,
            id: MessageId,
            _message: &[u8],
        ) -> anyhow::Result<()> {
            swarm.behaviour_mut().gossipsub.report_message_validation_result(
                &id,
                &propagation_source,
                libp2p::gossipsub::MessageAcceptance::Accept,
            );
            Ok(())
        }

        async fn handle_tick_message(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _peer_id: PeerId,
            _actor: Actor,
            msg_type: TickMessageType,
        ) -> anyhow::Result<()> {
            if !matches!(msg_type, TickMessageType::RegularlyAction) {
                return Ok(());
            }
            let topic = libp2p::gossipsub::IdentTopic::new(crate::middleware::get_topic_name(
                &Actor::Committee.to_string(),
            ));
            let mut queue = self.queue.lock().unwrap();
            // Publishing fails until the mesh has formed; keep the payload queued.
            queue.retain(|payload| {
                swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload.clone()).is_err()
            });
            Ok(())
        }

        async fn finish_subscribe_topic(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            _actor: Actor,
            _topic: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Accepts and records every payload that reaches it.
    struct Recorder {
        received: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl P2pMessageHandler for Recorder {
        async fn recv_and_dispatch(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _actor: Actor,
            _from_peer_id: PeerId,
            propagation_source: PeerId,
            _sequence_number: Option<u64>,
            id: MessageId,
            message: &[u8],
        ) -> anyhow::Result<()> {
            swarm.behaviour_mut().gossipsub.report_message_validation_result(
                &id,
                &propagation_source,
                libp2p::gossipsub::MessageAcceptance::Accept,
            );
            self.received.lock().unwrap().push(message.to_vec());
            Ok(())
        }

        async fn handle_tick_message(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            _peer_id: PeerId,
            _actor: Actor,
            _msg_type: TickMessageType,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn finish_subscribe_topic(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            _actor: Actor,
            _topic: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn swarm_config(local_key: String, p2p_port: u16, bootnodes: Vec<String>) -> BitvmSwarmConfig {
        BitvmSwarmConfig {
            local_key,
            p2p_port,
            bootnodes,
            topic_names: vec![Actor::Committee.to_string(), Actor::All.to_string()],
            heartbeat_interval: 3600,
            regular_task_interval: 1,
        }
    }

    async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..600 {
            if done() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("timed out waiting until {what}");
    }

    /// Verify the relay forwards admitted messages and withholds rejected ones.
    #[test]
    fn relay_forwards_admitted_messages_and_withholds_dropped_ones() {
        // The node processor's dispatch future is deep: `main` drives it on the
        // 8 MiB main thread, and it overflows the 2 MiB stack of a test thread.
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(relay_scenario());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn relay_scenario() {
        use crate::middleware::behaviour::MAX_GOSSIPSUB_TRANSMIT_SIZE;

        init();
        let cancel = CancellationToken::new();
        let relay_db = store::create_local_db(&temp_sqlite_db_path()).await;
        let (relay_key, relay_peer_id) = gen_local_key().unwrap();
        let relay_port = free_tcp_port();
        // The real processor announces itself on its heartbeat tick, which reads
        // the node identity from the environment.
        unsafe {
            std::env::set_var(crate::env::ENV_PEER_KEY, &relay_key);
            if std::env::var(crate::env::ENV_BITVM_SECRET).is_err() {
                std::env::set_var(crate::env::ENV_BITVM_SECRET, "seed:relay-admission-test");
            }
        }
        let bootnode = generate_bootnode_url(&relay_peer_id, relay_port);

        let relay = super::BitvmNodeProcessor {
            local_db: relay_db.clone(),
            goat_client: std::sync::Arc::new(client::goat_chain::GOATClient::new_mock_client().0),
            metrics_state: crate::metrics_service::MetricsState::new(std::sync::Arc::new(
                std::sync::Mutex::new(Registry::default()),
            )),
            shutdown_token: cancel.clone(),
            worker: Default::default(),
        };
        let mut relay_manager = BitvmNetworkManager::new(
            swarm_config(relay_key, relay_port, vec![]),
            &mut Registry::default(),
        )
        .unwrap();
        // The node processor's future is not `Send`; it runs on this task, next
        // to the scenario below, the same way `main` drives it.
        let relay_run = relay_manager.run(Actor::Committee, relay, cancel.clone());

        let queue = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let mut publisher_manager = BitvmNetworkManager::new(
            swarm_config(gen_local_key().unwrap().0, 0, vec![bootnode.clone()]),
            &mut Registry::default(),
        )
        .unwrap();
        let mut recorder_manager = BitvmNetworkManager::new(
            swarm_config(gen_local_key().unwrap().0, 0, vec![bootnode]),
            &mut Registry::default(),
        )
        .unwrap();
        let (publisher, publisher_cancel) = (RawPublisher { queue: queue.clone() }, cancel.clone());
        tokio::spawn(async move {
            publisher_manager.run(Actor::Operator, publisher, publisher_cancel).await.unwrap();
        });
        let (recorder, recorder_cancel) = (Recorder { received: received.clone() }, cancel.clone());
        tokio::spawn(async move {
            recorder_manager.run(Actor::Verifier, recorder, recorder_cancel).await.unwrap();
        });

        let scenario = async {
            // A committee round value: the Committee relay keeps it as an
            // engine inbox event of its graph.
            let protocol_message = |graph_id: uuid::Uuid| {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let keypair = bitcoin::secp256k1::Keypair::from_secret_key(
                    &secp,
                    &bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
                );
                let digest = bitcoin::secp256k1::Message::from_digest([3; 32]);
                GOATMessage::new(
                    Actor::Committee,
                    GOATMessageContent::AggNonceConsensus(crate::action::AggNonceConsensus {
                        instance_id: uuid::Uuid::new_v4(),
                        graph_id,
                        committee_pubkey: bitcoin::PublicKey::new(keypair.public_key()),
                        consensus_hash: [3; 32],
                        signature: secp.sign_schnorr(&digest, &keypair),
                    }),
                )
            };
            let (first, sentinel) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let first = protocol_message(first).serialize_message().await.unwrap();
            let sentinel = protocol_message(sentinel).serialize_message().await.unwrap();

            // The recorder is not connected to the publisher: whatever it sees came
            // through the relay, after the relay admitted it.
            queue.lock().unwrap().push(first.clone());
            wait_until("the relay forwarded the first protocol message", || {
                received.lock().unwrap().contains(&first)
            })
            .await;

            let oversized_json = vec![b'{'; crate::env::DEFAULT_P2P_MAX_JSON_MESSAGE_BYTES + 1];
            let undecodable = b"not a protocol message".to_vec();
            let mut binary_from_non_verifier = b"GOATBIN1".to_vec();
            binary_from_non_verifier.resize(MAX_GOSSIPSUB_TRANSMIT_SIZE / 4, 0);
            let junk = [oversized_json, undecodable, binary_from_non_verifier];
            // Wait for the sentinel after all preceding messages have been processed.
            queue.lock().unwrap().extend(junk.iter().cloned().chain([sentinel.clone()]));
            wait_until("the relay forwarded the sentinel", || {
                received.lock().unwrap().contains(&sentinel)
            })
            .await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let received = received.lock().unwrap().clone();
            for payload in &junk {
                assert!(
                    !received.contains(payload),
                    "the relay forwarded a {}-byte payload its own admission dropped",
                    payload.len()
                );
            }

            let mut storage = relay_db.acquire().await.unwrap();
            let queued = storage.engine_inbox_class_totals().await.unwrap();
            let (rows, bytes): (i64, i64) = queued
                .iter()
                .fold((0, 0), |(rows, bytes), usage| (rows + usage.rows, bytes + usage.bytes));
            assert!(rows <= 2, "only the two protocol messages may be queued, found {rows}");
            // An inbox event wraps the raw bytes in the admitted envelope
            // (author peer id, instance id); the junk payloads are kilobytes
            // to megabytes larger than that.
            let envelope_overhead = 2 * 128;
            assert!(
                bytes <= (first.len() + sentinel.len() + envelope_overhead) as i64,
                "the relay persisted {bytes} bytes; junk must never reach the inbox"
            );
        };
        tokio::select! {
            result = relay_run => panic!("the relay stopped before the scenario finished: {result:?}"),
            () = scenario => {}
        }
        cancel.cancel();
    }
}
