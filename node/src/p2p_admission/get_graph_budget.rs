//! Budgets for serving `GetGraph` requests: per peer, per requester class
//! and concurrent reads.

use std::sync::LazyLock;
use std::time::Duration;

use super::gates::CooldownGate;
use super::rate::{GlobalRate, PeerRateLimiter};

/// How long one peer's identical `GetGraph` request stays on cooldown.
const GET_GRAPH_RESPONSE_COOLDOWN: Duration = Duration::from_secs(60);
const GRAPH_SET_MAX_ENTRIES: usize = 16_384;

static GET_GRAPH_RESPONSE_GATE: LazyLock<CooldownGate> =
    LazyLock::new(|| CooldownGate::new(GET_GRAPH_RESPONSE_COOLDOWN, GRAPH_SET_MAX_ENTRIES));

/// Cooldown for answering the same `GetGraph` request from the same peer.
pub fn get_graph_response_gate() -> &'static CooldownGate {
    &GET_GRAPH_RESPONSE_GATE
}

// Serving a definition reads and serializes up to tens of megabytes, so the
// total rate is bounded per requester class, whatever the number of peers.
static GET_GRAPH_RESPONSE_BUDGET_REGISTERED: LazyLock<GlobalRate> =
    LazyLock::new(|| GlobalRate::new(32.0, 2.0));
static GET_GRAPH_RESPONSE_BUDGET_UNREGISTERED: LazyLock<GlobalRate> =
    LazyLock::new(|| GlobalRate::new(8.0, 0.2));

/// One requester's share: a registered peer flooding requests runs out of
/// its own tokens before it can drain the class budget other members need.
static GET_GRAPH_PEER_BUDGET: LazyLock<PeerRateLimiter> =
    LazyLock::new(|| PeerRateLimiter::new(8.0, 0.5, 1024));

pub fn get_graph_peer_budget() -> &'static PeerRateLimiter {
    &GET_GRAPH_PEER_BUDGET
}

/// Aggregate `GetGraph` response budgets by requester registration class.
pub fn get_graph_response_budget(requester_registered: bool) -> &'static GlobalRate {
    if requester_registered {
        &GET_GRAPH_RESPONSE_BUDGET_REGISTERED
    } else {
        &GET_GRAPH_RESPONSE_BUDGET_UNREGISTERED
    }
}

/// Definitions being read and serialized for `GetGraph` at once. A request
/// that finds no free slot is refused, never queued.
pub const GET_GRAPH_SERVE_SLOTS: usize = 4;

static GET_GRAPH_SERVE_SLOTS_SEMAPHORE: LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(GET_GRAPH_SERVE_SLOTS)));

pub fn get_graph_serve_slots() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    &GET_GRAPH_SERVE_SLOTS_SEMAPHORE
}
