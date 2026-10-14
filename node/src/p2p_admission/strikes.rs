//! Strikes against peers that keep sending refused direct messages, and the
//! peers refused for an unknown identity.

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub(super) const STRIKE_WINDOW: Duration = Duration::from_secs(60);
pub(super) const STRIKE_LIMIT: u32 = 256;
pub(super) const STRIKE_BAN: Duration = Duration::from_secs(10 * 60);
const STRIKE_MAX_TRACKED_PEERS: usize = 4_096;

#[derive(Debug, Default)]
struct StrikeState {
    /// Window start and strikes in it, per direct peer.
    strikes: HashMap<PeerId, (Instant, u32)>,
    banned_until: HashMap<PeerId, Instant>,
}

/// Temporary local bans based on attributable relay strikes; registered peers are exempt.
#[derive(Debug, Default)]
pub struct DirectPeerStrikes {
    state: Mutex<StrikeState>,
}

impl DirectPeerStrikes {
    /// Count one strike against `peer`. Returns `true` when it just reached the
    /// limit and should be banned now.
    pub fn strike(&self, peer: &PeerId, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.banned_until.contains_key(peer) {
            return false;
        }
        if !state.strikes.contains_key(peer) && state.strikes.len() >= STRIKE_MAX_TRACKED_PEERS {
            state.strikes.retain(|_, (started_at, _)| {
                now.saturating_duration_since(*started_at) < STRIKE_WINDOW
            });
            if state.strikes.len() >= STRIKE_MAX_TRACKED_PEERS {
                return false;
            }
        }
        let (started_at, count) = state.strikes.entry(*peer).or_insert((now, 0));
        if now.saturating_duration_since(*started_at) >= STRIKE_WINDOW {
            (*started_at, *count) = (now, 0);
        }
        *count += 1;
        if *count < STRIKE_LIMIT {
            return false;
        }
        state.strikes.remove(peer);
        state.banned_until.insert(*peer, now + STRIKE_BAN);
        true
    }

    /// Check the peer's current ban for each connection.
    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.banned_until.get(peer).is_some_and(|until| now < *until)
    }

    /// Peers whose ban has run out, removed from the ban list.
    pub fn take_expired_bans(&self, now: Instant) -> Vec<PeerId> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired: Vec<PeerId> = state
            .banned_until
            .iter()
            .filter(|(_, until)| now >= **until)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &expired {
            state.banned_until.remove(peer);
        }
        expired
    }
}

static DIRECT_PEER_STRIKES: LazyLock<DirectPeerStrikes> = LazyLock::new(DirectPeerStrikes::default);

pub fn direct_peer_strikes() -> &'static DirectPeerStrikes {
    &DIRECT_PEER_STRIKES
}

const REFUSED_PEERS_MAX: usize = 256;

static REFUSED_PEERS: Mutex<Vec<PeerId>> = Mutex::new(Vec::new());

/// Queue refused peers for committee lookup on the next maintenance pass.
pub fn note_refused_peer(peer: PeerId) {
    let mut refused = REFUSED_PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if refused.len() < REFUSED_PEERS_MAX && !refused.contains(&peer) {
        refused.push(peer);
    }
}

pub(super) fn take_refused_peers() -> Vec<PeerId> {
    std::mem::take(&mut *REFUSED_PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}
