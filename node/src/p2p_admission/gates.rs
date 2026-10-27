//! Cooldown gates: one response per key per window, and the throttled node
//! table refreshes.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// NodeInfo broadcast response cooldown.
const NODE_INFO_RESPONSE_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
struct ResponseGateState {
    sent_at: Option<Instant>,
    pending: bool,
}

/// Coalesce NodeInfo requests into one response per cooldown.
#[derive(Debug)]
pub struct ResponseGate {
    state: Mutex<ResponseGateState>,
    cooldown: Duration,
}

impl ResponseGate {
    pub fn new(cooldown: Duration) -> Self {
        Self { state: Mutex::new(ResponseGateState::default()), cooldown }
    }

    fn cooled_down(&self, state: &ResponseGateState, now: Instant) -> bool {
        state.sent_at.is_none_or(|sent_at| now.saturating_duration_since(sent_at) >= self.cooldown)
    }

    /// `true` when the caller should respond now; otherwise the request is
    /// remembered for [`Self::take_pending`].
    pub fn try_respond(&self, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cooled_down(&state, now) {
            state.sent_at = Some(now);
            state.pending = false;
            true
        } else {
            state.pending = true;
            false
        }
    }

    /// `true` when a deferred request is due; the caller then responds.
    pub fn take_pending(&self, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.pending && self.cooled_down(&state, now) {
            state.sent_at = Some(now);
            state.pending = false;
            true
        } else {
            false
        }
    }
}

static NODE_INFO_RESPONSE_GATE: LazyLock<ResponseGate> =
    LazyLock::new(|| ResponseGate::new(NODE_INFO_RESPONSE_COOLDOWN));

pub fn node_info_response_gate() -> &'static ResponseGate {
    &NODE_INFO_RESPONSE_GATE
}

/// Cooldown for peer liveness updates.
const PEER_TIMESTAMP_COOLDOWN: Duration = Duration::from_secs(30);
const COOLDOWN_GATE_MAX_ENTRIES: usize = 8_192;

/// Minimum interval between full gate/set sweeps.
const GATE_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Bounded keyed timestamps; reject new keys when all entries are live.
#[derive(Debug, Default)]
struct BoundedStamps {
    stamps: HashMap<String, Instant>,
    swept_at: Option<Instant>,
}

impl BoundedStamps {
    fn is_live(&self, key: &str, ttl: Duration, now: Instant) -> bool {
        self.stamps.get(key).is_some_and(|at| now.saturating_duration_since(*at) < ttl)
    }

    /// Stamp `key` with `now`. Returns false when the table is full of live
    /// entries and `key` is not among them.
    fn stamp(&mut self, key: &str, ttl: Duration, max_entries: usize, now: Instant) -> bool {
        if !self.stamps.contains_key(key) && self.stamps.len() >= max_entries {
            if self
                .swept_at
                .is_none_or(|at| now.saturating_duration_since(at) >= GATE_SWEEP_INTERVAL)
            {
                self.swept_at = Some(now);
                self.stamps.retain(|_, at| now.saturating_duration_since(*at) < ttl);
            }
            if self.stamps.len() >= max_entries {
                return false;
            }
        }
        self.stamps.insert(key.to_string(), now);
        true
    }
}

/// Allows an action for a key at most once per cooldown, within a hard bound on
/// its own memory. A key it has no room to track is denied: every action gated
/// here is one the peer retries, and none is worth an unbounded table.
#[derive(Debug)]
pub struct CooldownGate {
    seen: Mutex<BoundedStamps>,
    cooldown: Duration,
    max_entries: usize,
}

impl CooldownGate {
    pub(super) fn new(cooldown: Duration, max_entries: usize) -> Self {
        Self { seen: Mutex::new(BoundedStamps::default()), cooldown, max_entries }
    }

    /// Whether `key` is inside its cooldown. Records nothing.
    #[cfg(test)]
    pub fn is_cooling(&self, key: &str, now: Instant) -> bool {
        let seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.is_live(key, self.cooldown, now)
    }

    /// `true` when the action for `key` may proceed, recording it as just done.
    pub fn allow(&self, key: &str, now: Instant) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        !seen.is_live(key, self.cooldown, now)
            && seen.stamp(key, self.cooldown, self.max_entries, now)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.seen.lock().unwrap().stamps.len()
    }
}

static PEER_TIMESTAMP_GATE: LazyLock<CooldownGate> =
    LazyLock::new(|| CooldownGate::new(PEER_TIMESTAMP_COOLDOWN, COOLDOWN_GATE_MAX_ENTRIES));

pub fn peer_timestamp_gate() -> &'static CooldownGate {
    &PEER_TIMESTAMP_GATE
}

static NODE_TABLE_PURGED_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// `true` at most once per `interval`: when the `node` table purge should run.
pub fn node_table_purge_due(interval: Duration, now: Instant) -> bool {
    let mut purged_at =
        NODE_TABLE_PURGED_AT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if purged_at.is_some_and(|at| now.saturating_duration_since(at) < interval) {
        return false;
    }
    *purged_at = Some(now);
    true
}
