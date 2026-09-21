//! Inbound connection quotas and bidirectional ban enforcement.
//! Reserved capacity covers registered identities and `P2P_RESERVED_PEERS`.
//! Unknown operators require a prior binding or explicit reserved-peer configuration.
//! Unlisted watchtowers and challengers use general capacity.

use std::collections::HashMap;
use std::convert::Infallible;
use std::task::{Context, Poll};
use std::time::Instant;

use libp2p::PeerId;
use libp2p::core::{ConnectedPoint, Endpoint, Multiaddr, transport::PortUse};
use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The peer is serving a local ban.
    Banned,
    /// Every inbound slot is taken.
    InboundFull,
    /// Only slots reserved for registered peers are left.
    ReservedForRegistered,
}

impl Refusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Banned => "banned",
            Self::InboundFull => "inbound_full",
            Self::ReservedForRegistered => "reserved_for_registered",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connection refused: {}", self.as_str())
    }
}

impl std::error::Error for Refusal {}

/// Inbound slot accounting.
#[derive(Debug)]
pub struct InboundSlots {
    max_inbound: usize,
    /// Slots of `max_inbound` only registered peers may take.
    registered_reserve: usize,
    /// Established inbound connections; `true` when admitted as registered.
    established: HashMap<ConnectionId, bool>,
}

impl InboundSlots {
    pub fn new(max_inbound: usize, registered_reserve: usize) -> Self {
        Self {
            max_inbound,
            registered_reserve: registered_reserve.min(max_inbound),
            established: HashMap::new(),
        }
    }

    pub fn admit(&self, registered: bool) -> Result<(), Refusal> {
        if self.established.len() >= self.max_inbound {
            return Err(Refusal::InboundFull);
        }
        let unregistered = self.established.values().filter(|registered| !**registered).count();
        if !registered && unregistered >= self.max_inbound - self.registered_reserve {
            return Err(Refusal::ReservedForRegistered);
        }
        Ok(())
    }

    fn opened(&mut self, connection: ConnectionId, registered: bool) {
        self.established.insert(connection, registered);
    }

    fn closed(&mut self, connection: &ConnectionId) {
        self.established.remove(connection);
    }
}

pub struct ConnectionGate {
    slots: InboundSlots,
    /// Peer ids the deployment guarantees a reserved slot to.
    reserved_peers: std::collections::HashSet<PeerId>,
    /// Class decided when the connection was admitted, until it is established.
    admitting: HashMap<ConnectionId, bool>,
}

impl ConnectionGate {
    pub fn new(
        max_inbound: usize,
        registered_reserve: usize,
        reserved_peers: std::collections::HashSet<PeerId>,
    ) -> Self {
        Self {
            slots: InboundSlots::new(max_inbound, registered_reserve),
            reserved_peers,
            admitting: HashMap::new(),
        }
    }

    /// Whether `peer` may use the reserved slots.
    fn is_privileged(&self, peer: &PeerId) -> bool {
        self.reserved_peers.contains(peer)
            || crate::p2p_admission::peer_registry()
                .sender_class(peer, Instant::now())
                .is_registered()
    }

    fn refuse(peer: &PeerId, refusal: Refusal) -> ConnectionDenied {
        if refusal == Refusal::ReservedForRegistered {
            crate::p2p_admission::note_refused_peer(*peer);
        }
        ConnectionDenied::new(refusal)
    }

    fn check_ban(peer: &PeerId) -> Result<(), ConnectionDenied> {
        if crate::p2p_admission::direct_peer_strikes().is_banned(peer, Instant::now()) {
            return Err(Self::refuse(peer, Refusal::Banned));
        }
        Ok(())
    }
}

impl NetworkBehaviour for ConnectionGate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Self::check_ban(&peer)?;
        let registered = self.is_privileged(&peer);
        self.slots.admit(registered).map_err(|refusal| Self::refuse(&peer, refusal))?;
        self.admitting.insert(connection_id, registered);
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Outbound dials are this node's own choice and are not limited, but a
        // ban holds in both directions.
        Self::check_ban(&peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                connection_id,
                endpoint: ConnectedPoint::Listener { .. },
                ..
            }) => {
                let registered = self.admitting.remove(&connection_id).unwrap_or(false);
                self.slots.opened(connection_id, registered);
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                self.slots.closed(&connection_id);
            }
            FromSwarm::ListenFailure(failure) => {
                self.admitting.remove(&failure.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify configured peers receive connection reservation only.
    #[test]
    fn listed_peers_may_use_the_reserved_slots() {
        let (watchtower, stranger) = (PeerId::random(), PeerId::random());
        let listed = crate::env::parse_reserved_peers(&format!(" {watchtower} ,not-a-peer-id,,"));
        assert_eq!(listed, std::collections::HashSet::from([watchtower]));

        let gate = ConnectionGate::new(4, 2, listed);
        assert!(gate.is_privileged(&watchtower));
        assert!(!gate.is_privileged(&stranger));
        assert!(
            !crate::p2p_admission::peer_registry()
                .sender_class(&watchtower, Instant::now())
                .is_registered(),
            "a reserved slot is not a sender class"
        );
    }

    /// Unregistered peers can fill only what is not reserved; registered peers
    /// still get in after that, up to the ceiling.
    #[test]
    fn reserved_inbound_slots_are_kept_for_registered_peers() {
        let mut slots = InboundSlots::new(4, 2);
        for _ in 0..2 {
            assert_eq!(slots.admit(false), Ok(()));
            slots.opened(ConnectionId::new_unchecked(slots.established.len()), false);
        }
        assert_eq!(slots.admit(false), Err(Refusal::ReservedForRegistered));
        for _ in 0..2 {
            assert_eq!(slots.admit(true), Ok(()));
            slots.opened(ConnectionId::new_unchecked(slots.established.len()), true);
        }
        assert_eq!(slots.admit(true), Err(Refusal::InboundFull));

        // A closed unregistered connection frees an open slot again.
        slots.closed(&ConnectionId::new_unchecked(0));
        assert_eq!(slots.admit(false), Ok(()));

        // Registered peers are not confined to the reserve.
        let mut slots = InboundSlots::new(3, 1);
        for index in 0..3 {
            assert_eq!(slots.admit(true), Ok(()));
            slots.opened(ConnectionId::new_unchecked(index), true);
        }
        assert_eq!(slots.admit(true), Err(Refusal::InboundFull));
    }
}
