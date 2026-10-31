use crate::middleware::behaviour::AllBehavioursEvent;
use crate::middleware::{AllBehaviours, split_topic_name};
use crate::{env, middleware};
use anyhow::bail;
use base64::Engine;
use bitvm_lib::actors::Actor;
use futures::StreamExt;
use libp2p::gossipsub::MessageId;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub, kad, noise, tcp, yamux};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::HashMap;

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::select;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

pub struct BitvmSwarmWrapper(pub Swarm<AllBehaviours>);

impl std::fmt::Debug for BitvmSwarmWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitvmSwarm").field("inner", &"<Swarm<AllBehaviours>>").finish()
    }
}

impl BitvmSwarmWrapper {
    pub fn new(swarm: Swarm<AllBehaviours>) -> Self {
        Self(swarm)
    }

    pub fn inner(&self) -> &Swarm<AllBehaviours> {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut Swarm<AllBehaviours> {
        &mut self.0
    }
}

impl std::ops::Deref for BitvmSwarmWrapper {
    type Target = Swarm<AllBehaviours>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for BitvmSwarmWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

use strum::Display;

#[derive(Clone, Debug, Display)]
pub enum TickMessageType {
    HeartBeat,
    RegularlyAction,
}

#[allow(async_fn_in_trait)]
pub trait P2pMessageHandler {
    async fn recv_and_dispatch(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        from_peer_id: PeerId,
        id: MessageId,
        message: &[u8],
    ) -> anyhow::Result<()>;

    async fn handle_tick_message(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        peer_id: PeerId,
        actor: Actor,
        msg_type: TickMessageType,
    ) -> anyhow::Result<()>;

    async fn finish_subscribe_topic(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        topic: &str,
    ) -> anyhow::Result<()>;
}

#[derive(Clone, Debug)]
pub struct BitvmSwarmConfig {
    pub local_key: String,
    pub p2p_port: u16,
    pub bootnodes: Vec<String>,
    pub topic_names: Vec<String>,
    pub heartbeat_interval: u64,
    pub regular_task_interval: u64,
}

pub struct BitvmNetworkManager {
    config: BitvmSwarmConfig,
    peer_id: PeerId,
    swarm: BitvmSwarmWrapper,
    connected_peers: Gauge,
    required_topics_healthy: Gauge,
}
impl BitvmNetworkManager {
    pub fn new(
        config: BitvmSwarmConfig,
        metric_registry: &mut Registry,
    ) -> anyhow::Result<BitvmNetworkManager> {
        let connected_peers = Gauge::default();
        let required_topics_healthy = Gauge::default();
        metric_registry.register(
            "bitvm_node_p2p_connected_peers",
            "Number of currently connected P2P peers",
            connected_peers.clone(),
        );
        metric_registry.register(
            "bitvm_node_p2p_required_topics_healthy",
            "Whether the local role has a mesh peer for each required P2P topic",
            required_topics_healthy.clone(),
        );
        let key_pair = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
            base64::engine::general_purpose::STANDARD.decode(config.local_key.clone())?,
        ))?;

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key_pair.clone())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_bandwidth_metrics(metric_registry)
            .with_behaviour(AllBehaviours::new)?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
            })
            .build();

        debug!("bootnodes: {:?}", config.bootnodes);
        for peer in &config.bootnodes {
            let (peer_id, multi_addr) = parse_boot_node_str(peer)?;
            swarm.behaviour_mut().kademlia.add_address(&peer_id, multi_addr);
        }
        Ok(BitvmNetworkManager {
            config,
            swarm: BitvmSwarmWrapper::new(swarm),
            peer_id: key_pair.public().to_peer_id(),
            connected_peers,
            required_topics_healthy,
        })
    }

    pub fn get_peer_id_string(&self) -> String {
        self.peer_id.to_string()
    }

    fn refresh_required_topics_health(&self, actor: &Actor) {
        let role_topic = middleware::get_topic_name(&actor.to_string());
        let all_topic = middleware::get_topic_name(&Actor::All.to_string());
        let required_topics =
            if role_topic == all_topic { vec![role_topic] } else { vec![role_topic, all_topic] };
        let healthy = required_topics.into_iter().all(|topic| {
            let topic = gossipsub::IdentTopic::new(topic);
            self.swarm.behaviour().gossipsub.mesh_peers(&topic.hash()).next().is_some()
        });
        self.required_topics_healthy.set(i64::from(healthy));
    }
    pub async fn run<H: P2pMessageHandler>(
        &mut self,
        actor: Actor,
        msg_handler: H,
        cancellation_token: CancellationToken,
    ) -> anyhow::Result<String> {
        info!("subscribing to topics: {:?}", self.config.topic_names);
        let _topics = self
            .config
            .topic_names
            .iter()
            .map(|a| {
                let topic_name = middleware::get_topic_name(a);
                let gossipsub_topic = gossipsub::IdentTopic::new(topic_name.clone());
                self.swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic).unwrap();
                (topic_name, gossipsub_topic)
            })
            .collect::<HashMap<String, _>>();
        self.refresh_required_topics_health(&actor);

        if self.config.p2p_port > 0 {
            self.swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", self.config.p2p_port).parse()?)?;
        } else {
            self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        }

        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.swarm.select_next_some().await {
                if address.iter().any(|e| e == Protocol::Ip4(Ipv4Addr::LOCALHOST)) {
                    debug!("Ignoring localhost address to make sure the example works in Firefox");
                    continue;
                }
                info!(%address, "Listening");
                break address;
            }
        };
        info!("multi_addr: {}/p2p/{}", address.to_string(), self.peer_id.to_string());
        let mut heart_beat_interval = interval(Duration::from_secs(self.config.heartbeat_interval));
        let mut interval = interval(Duration::from_secs(self.config.regular_task_interval));
        loop {
            select! {
                    _ = cancellation_token.cancelled() => {
                        info!("Swarm received shutdown signal");
                        return Ok("swarm_shutdown".to_string());
                    }

                    _ticker = interval.tick() => {
                        match msg_handler.handle_tick_message(&mut self.swarm, self.peer_id, actor.clone(), TickMessageType::RegularlyAction).await {
                                Ok(_) => {}
                                Err(e) => { tracing::error!("Fail to handle tick message {e:?}") }
                            }
                        self.refresh_required_topics_health(&actor);

                    },

                    _ticker = heart_beat_interval.tick() =>{
                       match msg_handler.handle_tick_message(&mut self.swarm, self.peer_id, actor.clone(), TickMessageType::HeartBeat).await {
                                Ok(_) => {}
                                Err(e) => { tracing::error!("{e:?}") }
                            }
                        self.refresh_required_topics_health(&actor);
                    },

                    event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => tracing::debug!("Listening on {address:?}"),
                        SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Message {
                                                                      propagation_source,
                                                                      message_id: id,
                                                                      message,
                                                                  })) => {
                            let source = message.source.unwrap_or(propagation_source);
                            let data_prefix = hex::encode(&message.data[..message.data.len().min(16)]);
                            let data_starts_with_goatbin = message.data.starts_with(b"GOATBIN1");
                            match msg_handler.recv_and_dispatch(&mut self.swarm, actor.clone(),
                                source, id.clone(), &message.data).await {
                                Ok(_) => {},Err(e) => {
                                    tracing::error!(
                                        error = ?e,
                                        from_peer_id = %source,
                                        message_id = ?id,
                                        topic = %message.topic,
                                        data_len = message.data.len(),
                                        data_prefix,
                                        data_starts_with_goatbin,
                                        "Fail to handle p2p message"
                                    )
                            }
                        }
                        }
                        SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic})) => {
                            debug!("subscribing: {:?}, {:?}", peer_id, topic);
                            let topic_limb = match split_topic_name(topic.as_str()) {
                                Ok(topic_limb) => topic_limb,
                                Err(error) => {
                                    warn!(
                                        %peer_id,
                                        topic = %topic,
                                        %error,
                                        "Disconnecting peer subscribed to malformed topic"
                                    );
                                    let _ = self.swarm.disconnect_peer_id(peer_id);
                                    continue;
                                }
                            };
                            if topic_limb.0 != env::get_proto_base() {
                               continue;
                            }
                            let topic = topic_limb.1;

                            debug!("subscribed: {:?}, {:?}", peer_id, topic);
                            // Except for the bootNode, all other nodes need to request information from other nodes after registering the event `ALL`.
                            if self.config.bootnodes.is_empty(){
                                match msg_handler.finish_subscribe_topic(&mut self.swarm, actor.clone(), topic).await{
                                    Ok(_) => {},Err(e) => { tracing::error!("{e:?}") }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(AllBehavioursEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic})) => {
                            debug!("unsubscribed: {:?}, {:?}", peer_id, topic);
                        }
                        SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::RoutingUpdated{ peer, addresses,..})) => {
                            debug!("routing updated: {:?}, addresses:{:?}", peer, addresses);
                        }
                        SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                            result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                            ..
                        })) => {
                            // The example is considered failed as there
                            // should always be at least 1 reachable peer.
                            if ok.peers.is_empty() {
                                debug!("Query finished with no closest peers.");
                            }

                            debug!("Query finished with closest peers: {:#?}", ok.peers);
                            //return Ok(());
                        }
                        SwarmEvent::Behaviour(AllBehavioursEvent::Kademlia(kad::Event::InboundRequest {request})) => {
                            debug!("kademlia: {:?}", request);
                        }
                        SwarmEvent::NewExternalAddrOfPeer {peer_id, address} => {
                            debug!("new external address of peer: {} {}", peer_id, address);
                        }
                        SwarmEvent::ConnectionEstablished {peer_id, connection_id, endpoint, .. } => {
                            self.connected_peers.set(self.swarm.connected_peers().count() as i64);
                            debug!("connected to {peer_id}: {connection_id}, endpoint: {:?}", endpoint);
                        }
                        SwarmEvent::ConnectionClosed {peer_id, connection_id, .. } => {
                            self.connected_peers.set(self.swarm.connected_peers().count() as i64);
                            debug!("disconnected from {peer_id}: {connection_id}");
                        }
                        e => {
                            debug!("Unhandled {:?}", e);
                        }
                    }
                    self.refresh_required_topics_health(&actor);
                }
            }
        }
    }
}

fn parse_boot_node_str(boot_node_str: &str) -> anyhow::Result<(PeerId, Multiaddr)> {
    let multi_addr: Multiaddr = boot_node_str.parse()?;
    for protocol in multi_addr.iter() {
        if let Protocol::P2p(peer_id) = protocol {
            return Ok((peer_id, multi_addr));
        }
    }
    bail!("parse bootnode failed")
}
