use bitvm_lib::actors::Actor;
use libp2p::identity::Keypair;
use libp2p::{connection_limits, gossipsub, kad, kad::store::MemoryStore, swarm::StreamProtocol};
use libp2p_swarm_derive::NetworkBehaviour;
use std::time::Duration;
use tokio::io::{self};

pub const MAX_GOSSIPSUB_TRANSMIT_SIZE: usize = 16 * 1024 * 1024;

/// Peers may only register interest in the role topics of this protocol; a
/// subscription to anything else is ignored instead of being tracked.
pub type TopicFilter =
    gossipsub::MaxCountSubscriptionFilter<gossipsub::WhitelistSubscriptionFilter>;

/// Every role topic, whether or not this node subscribes to it.
fn protocol_topics() -> std::collections::HashSet<gossipsub::TopicHash> {
    [
        Actor::Committee,
        Actor::Operator,
        Actor::Verifier,
        Actor::Watchtower,
        Actor::Publisher,
        Actor::All,
    ]
    .iter()
    .map(|actor| gossipsub::IdentTopic::new(get_topic_name(&actor.to_string())).hash())
    .collect()
}

// We create a custom network behaviour that combines Kademlia and mDNS.
#[derive(NetworkBehaviour)]
pub struct AllBehaviours {
    /// Enforce bans and reserved inbound capacity before other behaviours.
    pub connection_gate: super::connection_gate::ConnectionGate,
    /// Ceilings on half-open inbound connections and on connections per peer.
    pub connection_limits: connection_limits::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    //pub mdns: mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour<gossipsub::IdentityTransform, TopicFilter>,
}
impl AllBehaviours {
    pub fn new(key: &Keypair) -> Self {
        let mut cfg = kad::Config::new(get_proto_name());
        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        // Use Kademlia for discovery only; ignore remote record and provider writes.
        cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
        let store = kad::store::MemoryStore::new(key.public().to_peer_id());
        let kademlia = kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg);
        //let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
        //    .unwrap();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(MAX_GOSSIPSUB_TRANSMIT_SIZE)
            // Require application admission before gossip forwarding.
            .validate_messages()
            .build()
            .map_err(io::Error::other)
            .unwrap();
        let topics = protocol_topics();
        let subscription_filter = gossipsub::MaxCountSubscriptionFilter {
            max_subscribed_topics: topics.len(),
            max_subscriptions_per_request: 4 * topics.len(),
            filter: gossipsub::WhitelistSubscriptionFilter(topics),
        };
        let gossipsub = gossipsub::Behaviour::new_with_subscription_filter(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
            None,
            subscription_filter,
        )
        .expect("Valid configuration");
        // Limit half-open inbound connections and connections per peer.
        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(crate::env::get_p2p_max_pending_incoming()))
                .with_max_established_per_peer(Some(crate::env::get_p2p_max_per_peer())),
        );
        // ConnectionGate enforces registered-aware inbound capacity.
        let connection_gate = super::connection_gate::ConnectionGate::new(
            crate::env::get_p2p_max_incoming() as usize,
            crate::env::get_p2p_inbound_registered_reserve() as usize,
            crate::env::get_p2p_reserved_peers(),
        );
        Self { connection_gate, connection_limits, kademlia, gossipsub }
    }
}

pub fn get_proto_name() -> StreamProtocol {
    let version = env!("CARGO_PKG_VERSION");
    let protocol = crate::env::get_proto_base();
    let kad_proto = format!("/{protocol}/kad/{version}");
    StreamProtocol::try_from_owned(kad_proto).expect("Valid kad proto")
}

pub fn get_topic_name(topic: &str) -> String {
    format!("{}/topic/{}", crate::env::get_proto_base(), topic)
}

pub fn split_topic_name(topic_hash: &str) -> anyhow::Result<(&str, &str)> {
    topic_hash
        .split_once("/topic/")
        .ok_or_else(|| anyhow::anyhow!("topic should be $proto/topic/$actor"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_split_topic_name() {
        let topic_short = "hello";
        let topic_full = get_topic_name(topic_short);
        let topic_split = split_topic_name(&topic_full).unwrap();
        assert_eq!(topic_split.1, topic_short);
        assert!(split_topic_name(topic_short).is_err());
    }
}
