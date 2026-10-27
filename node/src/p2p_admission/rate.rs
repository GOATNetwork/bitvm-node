//! Token buckets: per peer for immediate messages, per class and peer for the
//! inbox, and global for a resource no peer key bounds.

use anyhow::Result;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use super::DropReason;
use super::registry::SenderClass;

const IMMEDIATE_BURST: f64 = 240.0;
const IMMEDIATE_REFILL_PER_SEC: f64 = 2.0;
const IMMEDIATE_MAX_TRACKED_PEERS: usize = 4096;

/// Per-peer token bucket for messages that are dispatched without being queued.
#[derive(Debug)]
pub struct PeerRateLimiter {
    buckets: Mutex<HashMap<PeerId, RateBucket>>,
    burst: f64,
    refill_per_sec: f64,
    max_peers: usize,
}

impl PeerRateLimiter {
    pub fn new(burst: f64, refill_per_sec: f64, max_peers: usize) -> Self {
        Self { buckets: Mutex::new(HashMap::new()), burst, refill_per_sec, max_peers }
    }

    pub fn allow(&self, peer: &PeerId, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !buckets.contains_key(peer) && buckets.len() >= self.max_peers {
            // A bucket that has refilled completely belongs to an idle peer and
            // carries no state worth keeping.
            let (burst, refill_per_sec) = (self.burst, self.refill_per_sec);
            buckets.retain(|_, bucket| {
                let elapsed = now.saturating_duration_since(bucket.refilled_at).as_secs_f64();
                bucket.tokens + elapsed * refill_per_sec < burst
            });
            if buckets.len() >= self.max_peers {
                return false;
            }
        }
        let bucket = buckets.entry(*peer).or_insert_with(|| RateBucket::full(self.burst, now));
        bucket.refill(self.refill_per_sec, self.burst, now);
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

static IMMEDIATE_LIMITER: LazyLock<PeerRateLimiter> = LazyLock::new(|| {
    PeerRateLimiter::new(IMMEDIATE_BURST, IMMEDIATE_REFILL_PER_SEC, IMMEDIATE_MAX_TRACKED_PEERS)
});

pub fn immediate_limiter() -> &'static PeerRateLimiter {
    &IMMEDIATE_LIMITER
}

/// A token bucket carrying both a rate and a burst, refilled lazily on access.
#[derive(Clone, Copy, Debug)]
struct RateBucket {
    tokens: f64,
    refilled_at: Instant,
}

impl RateBucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self { tokens: burst, refilled_at: now }
    }

    fn refill(&mut self, rate: f64, burst: f64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled_at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.refilled_at = now;
    }
}

/// One message costs a whole message token plus `bytes` byte tokens.
#[derive(Clone, Copy, Debug)]
struct DualBucket {
    msgs: RateBucket,
    bytes: RateBucket,
}

/// Rate + burst for one tier, in messages and bytes per second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TierRate {
    pub msg_burst: u32,
    pub msg_per_sec: u32,
    pub byte_burst: i64,
    pub byte_per_sec: i64,
}

impl TierRate {
    fn new_bucket(&self, now: Instant) -> DualBucket {
        DualBucket {
            msgs: RateBucket::full(self.msg_burst as f64, now),
            bytes: RateBucket::full(self.byte_burst as f64, now),
        }
    }

    /// Refill then test whether one message of `bytes` fits, without spending.
    fn peek(&self, bucket: &mut DualBucket, bytes: i64, now: Instant) -> bool {
        self.peek_above(bucket, bytes, 0.0, now)
    }

    /// Check capacity while retaining the specified fraction of burst tokens.
    fn peek_above(&self, bucket: &mut DualBucket, bytes: i64, reserve: f64, now: Instant) -> bool {
        bucket.msgs.refill(self.msg_per_sec as f64, self.msg_burst as f64, now);
        bucket.bytes.refill(self.byte_per_sec as f64, self.byte_burst as f64, now);
        bucket.msgs.tokens - 1.0 >= self.msg_burst as f64 * reserve
            && bucket.bytes.tokens - bytes as f64 >= self.byte_burst as f64 * reserve
    }

    fn spend(&self, bucket: &mut DualBucket, bytes: i64) {
        bucket.msgs.tokens -= 1.0;
        bucket.bytes.tokens -= bytes as f64;
    }
}

/// Pre-decode message and byte limits: direct peer, author, unregistered class and global.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimits {
    pub direct_peer: TierRate,
    pub registered_author: TierRate,
    pub unregistered_author: TierRate,
    pub unregistered_total: TierRate,
    /// Forward-only budget for unregistered authors.
    pub unregistered_forward: TierRate,
    pub global: TierRate,
    /// Committee-only reserve in the global and direct-peer budgets.
    pub committee_reserve: f64,
    pub max_tracked_peers: usize,
}

impl RateLimits {
    pub const fn defaults() -> Self {
        const MIB: i64 = 1024 * 1024;
        Self {
            // Direct-peer rate ceiling.
            direct_peer: TierRate {
                msg_burst: 16_384,
                msg_per_sec: 4_096,
                byte_burst: 512 * MIB,
                byte_per_sec: 32 * MIB,
            },
            // Generous: one GenCircuits is ~11.5 MiB, and an operator may send a
            // few graph messages back to back.
            registered_author: TierRate {
                msg_burst: 8_192,
                msg_per_sec: 512,
                byte_burst: 256 * MIB,
                byte_per_sec: 8 * MIB,
            },
            // Room for one maximum-size JSON message and a node's heartbeats,
            // not for a stream.
            unregistered_author: TierRate {
                msg_burst: 32,
                msg_per_sec: 2,
                byte_burst: 4 * MIB,
                byte_per_sec: 128 * 1024,
            },
            // Shared budget for all unregistered authors.
            unregistered_total: TierRate {
                msg_burst: 1_024,
                msg_per_sec: 32,
                byte_burst: 32 * MIB,
                byte_per_sec: MIB,
            },
            // Sized for the chain observations honest unregistered nodes
            // (watchtowers, challengers) publish, not for bulk.
            unregistered_forward: TierRate {
                msg_burst: 256,
                msg_per_sec: 16,
                byte_burst: 8 * MIB,
                byte_per_sec: 512 * 1024,
            },
            global: TierRate {
                msg_burst: 16_384,
                msg_per_sec: 4_096,
                byte_burst: 512 * MIB,
                byte_per_sec: 32 * MIB,
            },
            committee_reserve: 0.25,
            max_tracked_peers: 8_192,
        }
    }
}

/// Idle duration before forgetting a tracked bucket.
pub(super) const RATE_BUCKET_IDLE_FORGET: Duration = Duration::from_secs(60);
/// Minimum interval between full-table sweeps.
const RATE_TABLE_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Bounded per-key buckets; excess keys share one overflow bucket.
#[derive(Debug)]
struct BucketTable {
    buckets: HashMap<PeerId, DualBucket>,
    overflow: DualBucket,
    swept_at: Option<Instant>,
}

/// Which bucket of a [`BucketTable`] a message is charged to.
#[derive(Clone, Copy, Debug)]
enum BucketSlot {
    Tracked(PeerId),
    Overflow,
}

impl BucketTable {
    fn new(overflow_tier: TierRate, now: Instant) -> Self {
        Self { buckets: HashMap::new(), overflow: overflow_tier.new_bucket(now), swept_at: None }
    }

    /// The slot `key` is charged to. `pinned` keys are always tracked: they are
    /// bounded by an on-chain registry, not by whoever generates key pairs.
    fn slot(
        &mut self,
        key: &PeerId,
        tier: TierRate,
        cap: usize,
        pinned: bool,
        now: Instant,
    ) -> BucketSlot {
        if !self.buckets.contains_key(key) {
            if self.buckets.len() >= cap
                && self
                    .swept_at
                    .is_none_or(|at| now.saturating_duration_since(at) >= RATE_TABLE_SWEEP_INTERVAL)
            {
                self.swept_at = Some(now);
                self.buckets.retain(|_, bucket| {
                    now.saturating_duration_since(bucket.msgs.refilled_at) < RATE_BUCKET_IDLE_FORGET
                });
            }
            if self.buckets.len() >= cap && !pinned {
                return BucketSlot::Overflow;
            }
            self.buckets.insert(*key, tier.new_bucket(now));
        }
        BucketSlot::Tracked(*key)
    }

    fn get(&self, slot: BucketSlot) -> DualBucket {
        match slot {
            BucketSlot::Tracked(key) => self.buckets[&key],
            BucketSlot::Overflow => self.overflow,
        }
    }

    fn set(&mut self, slot: BucketSlot, bucket: DualBucket) {
        match slot {
            BucketSlot::Tracked(key) => {
                self.buckets.insert(key, bucket);
            }
            BucketSlot::Overflow => self.overflow = bucket,
        }
    }
}

#[derive(Debug)]
struct RateState {
    direct: BucketTable,
    authors: BucketTable,
    unregistered_total: DualBucket,
    unregistered_forward: DualBucket,
    global: DualBucket,
}

/// Multi-tier pre-decode rate budget.
#[derive(Debug)]
pub struct InboundRateLimiter {
    state: Mutex<RateState>,
    limits: RateLimits,
}

impl InboundRateLimiter {
    pub fn new(limits: RateLimits) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(RateState {
                direct: BucketTable::new(limits.direct_peer, now),
                authors: BucketTable::new(limits.unregistered_author, now),
                unregistered_total: limits.unregistered_total.new_bucket(now),
                unregistered_forward: limits.unregistered_forward.new_bucket(now),
                global: limits.global.new_bucket(now),
            }),
            limits,
        }
    }

    /// Charge the relay budget for a message from an unregistered author that
    /// this node forwards without storing.
    pub fn charge_forward(&self, bytes: i64, now: Instant) -> Result<(), DropReason> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tier = self.limits.unregistered_forward;
        let mut bucket = state.unregistered_forward;
        let admitted = tier.peek(&mut bucket, bytes, now);
        if admitted {
            tier.spend(&mut bucket, bytes);
        }
        state.unregistered_forward = bucket;
        admitted.then_some(()).ok_or(DropReason::ForwardRate)
    }

    #[cfg(test)]
    pub(super) fn tracked_authors(&self) -> usize {
        self.state.lock().unwrap().authors.buckets.len()
    }

    /// Check all applicable rate tiers before charging any of them.
    pub fn charge(
        &self,
        direct_peer: &PeerId,
        author: &PeerId,
        class: SenderClass,
        bytes: i64,
        now: Instant,
    ) -> Result<(), DropReason> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let author_tier = if class.is_registered() {
            self.limits.registered_author
        } else {
            self.limits.unregistered_author
        };
        let cap = self.limits.max_tracked_peers;
        let direct_tier = self.limits.direct_peer;
        let registered = class.is_registered();
        let direct_slot = state.direct.slot(direct_peer, direct_tier, cap, false, now);
        let author_slot = state.authors.slot(author, author_tier, cap, registered, now);
        let mut direct = state.direct.get(direct_slot);
        let mut author_bucket = state.authors.get(author_slot);
        let mut unregistered = state.unregistered_total;
        let mut global = state.global;

        let charge_unregistered = !class.is_registered();
        // The shared tiers keep a reserve only the committee may draw on.
        let reserve =
            if class == SenderClass::Committee { 0.0 } else { self.limits.committee_reserve };
        let direct_ok = direct_tier.peek_above(&mut direct, bytes, reserve, now);
        let author_ok = author_tier.peek(&mut author_bucket, bytes, now);
        let unregistered_ok = !charge_unregistered
            || self.limits.unregistered_total.peek(&mut unregistered, bytes, now);
        let global_ok = self.limits.global.peek_above(&mut global, bytes, reserve, now);

        // Persist refilled buckets even when admission fails.
        let outcome = if !global_ok {
            Err(DropReason::GlobalRate)
        } else if !unregistered_ok {
            Err(DropReason::UnregisteredRate)
        } else if !author_ok {
            Err(DropReason::AuthorRate)
        } else if !direct_ok {
            Err(DropReason::DirectPeerRate)
        } else {
            direct_tier.spend(&mut direct, bytes);
            author_tier.spend(&mut author_bucket, bytes);
            if charge_unregistered {
                self.limits.unregistered_total.spend(&mut unregistered, bytes);
            }
            self.limits.global.spend(&mut global, bytes);
            Ok(())
        };
        state.direct.set(direct_slot, direct);
        state.authors.set(author_slot, author_bucket);
        state.unregistered_total = unregistered;
        state.global = global;
        outcome
    }
}

static INBOUND_RATE_LIMITER: LazyLock<InboundRateLimiter> =
    LazyLock::new(|| InboundRateLimiter::new(RateLimits::defaults()));

pub fn inbound_rate_limiter() -> &'static InboundRateLimiter {
    &INBOUND_RATE_LIMITER
}

/// A global token bucket, for a resource no per-peer key bounds.
#[derive(Debug)]
pub struct GlobalRate {
    bucket: Mutex<RateBucket>,
    rate: f64,
    burst: f64,
}

impl GlobalRate {
    pub(super) fn new(burst: f64, rate: f64) -> Self {
        Self { bucket: Mutex::new(RateBucket::full(burst, Instant::now())), rate, burst }
    }

    pub fn allow(&self, now: Instant) -> bool {
        let mut bucket = self.bucket.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        bucket.refill(self.rate, self.burst, now);
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}
