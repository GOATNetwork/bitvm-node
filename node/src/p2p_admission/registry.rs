//! The peer registry: which peers are committee members, verifiers or
//! operators on chain, with the budgets of the lookups that keep it current.

use anyhow::Result;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use strum::{Display, EnumString};

/// How admission classifies the author of a message: a committee member
/// registered by peer id on chain, a verifier (on-chain peer id registry) or
/// an operator (staked master key bound to the peer id by a NodeInfo binding
/// proof), or anyone else. Rate limits and the storage quota are per class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Display, EnumString)]
pub enum SenderClass {
    Committee,
    Registered,
    Unregistered,
}

impl SenderClass {
    /// Whether the sender's identity is backed by an on-chain registration.
    pub const fn is_registered(self) -> bool {
        !matches!(self, Self::Unregistered)
    }
}

const VERIFIER_SET_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub(super) const VERIFIER_SET_RETRY_INTERVAL: Duration = Duration::from_secs(30);
pub(super) const COMMITTEE_POSITIVE_TTL: Duration = Duration::from_secs(10 * 60);
pub(super) const COMMITTEE_NEGATIVE_TTL: Duration = Duration::from_secs(2 * 60);
/// Maximum stale age for retaining a registered classification during refresh.
pub(super) const COMMITTEE_STALE_LIMIT: Duration = Duration::from_secs(30 * 60);
const COMMITTEE_CACHE_MAX_ENTRIES: usize = 4096;
/// Lookup rate for committee candidates (peers announcing themselves as
/// committee by NodeInfo, or stored in the node table); known-member
/// refreshes are exempt.
pub(super) const COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE: u32 = 60;
pub(super) const COMMITTEE_MAX_IN_FLIGHT_LOOKUPS: usize = 16;
/// Maximum unknown-identity lookups in flight.
pub(super) const COMMITTEE_MAX_UNKNOWN_IN_FLIGHT: usize = 12;
pub(super) const REGISTRY_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Separate discovery budget for operator stake lookups.
pub(super) const OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE: u32 = 60;
const OPERATOR_MAX_IN_FLIGHT_LOOKUPS: usize = 16;
const OPERATOR_MAX_UNKNOWN_IN_FLIGHT: usize = 12;
pub(super) const REFUSED_PEER_LOOKUPS_PER_MINUTE: u32 = 30;

/// A confirmed operator binding keeps its class this long before re-validation;
/// a shorter window applies while the stake is still unknown.
pub(super) const OPERATOR_STAKE_TTL: Duration = Duration::from_secs(10 * 60);
pub(super) const OPERATOR_STAKE_STALE_LIMIT: Duration = Duration::from_secs(30 * 60);
const OPERATOR_CACHE_MAX_ENTRIES: usize = 4096;
/// Maximum persisted operator bindings loaded at startup.
pub const OPERATOR_BINDING_LOAD_LIMIT: i64 = OPERATOR_CACHE_MAX_ENTRIES as i64;

#[derive(Clone, Copy, Debug)]
struct CommitteeEntry {
    registered: bool,
    fetched_at: Instant,
}

impl CommitteeEntry {
    fn ttl(&self) -> Duration {
        if self.registered { COMMITTEE_POSITIVE_TTL } else { COMMITTEE_NEGATIVE_TTL }
    }

    fn needs_refresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.fetched_at) >= self.ttl()
    }

    fn is_registered(&self, now: Instant) -> bool {
        self.registered && now.saturating_duration_since(self.fetched_at) < COMMITTEE_STALE_LIMIT
    }
}

/// Canonical operator identity: the x-only master public key.
pub type OperatorKey = [u8; 32];

pub fn operator_key(pubkey: &bitcoin::XOnlyPublicKey) -> OperatorKey {
    pubkey.serialize()
}

/// A peer that proved (via a NodeInfo binding) it owns a master key, plus what
/// the chain says about that key's operator stake.
#[derive(Clone, Debug)]
struct OperatorBinding {
    pubkey: OperatorKey,
    issued_at: i64,
    /// `Some(true)` once the key is confirmed to be a sufficiently staked
    /// operator on chain; `None` until the lookup completes.
    staked: Option<bool>,
    fetched_at: Option<Instant>,
    /// Configured binding; bypasses discovery budget but still requires a positive stake verdict.
    trusted: bool,
}

impl OperatorBinding {
    fn needs_refresh(&self, now: Instant) -> bool {
        match self.fetched_at {
            None => true,
            Some(fetched_at) => now.saturating_duration_since(fetched_at) >= OPERATOR_STAKE_TTL,
        }
    }

    fn is_registered(&self, now: Instant) -> bool {
        self.staked == Some(true)
            && self
                .fetched_at
                .is_some_and(|at| now.saturating_duration_since(at) < OPERATOR_STAKE_STALE_LIMIT)
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    verifiers: HashSet<Vec<u8>>,
    verifiers_fetched_at: Option<Instant>,
    verifiers_attempted_at: Option<Instant>,
    verifiers_in_flight: bool,
    committee: HashMap<PeerId, CommitteeEntry>,
    committee_in_flight: HashSet<PeerId>,
    /// Operator bindings keyed by the peer that proved them.
    operators: HashMap<PeerId, OperatorBinding>,
    /// Reverse index from master key to its current peer ID.
    operator_owner: HashMap<OperatorKey, PeerId>,
    operators_in_flight: HashSet<PeerId>,
    committee_discovery: DiscoveryBudget,
    /// Separate lookup budget for connected neighbours.
    neighbour_discovery: DiscoveryBudget,
    /// For peers the connection gate refused; see [`LookupBudget::Refused`].
    refused_discovery: DiscoveryBudget,
    operator_discovery: DiscoveryBudget,
}

/// Per-minute budget for first-time (unknown-identity) registry lookups.
#[derive(Debug, Default)]
struct DiscoveryBudget {
    window_started_at: Option<Instant>,
    lookups_in_window: u32,
}

impl DiscoveryBudget {
    /// Charge one lookup. Returns false when the budget is exhausted.
    fn take(&mut self, per_minute: u32, now: Instant) -> bool {
        let window_open = self.window_started_at.is_some_and(|started_at| {
            now.saturating_duration_since(started_at) < Duration::from_secs(60)
        });
        if !window_open {
            self.window_started_at = Some(now);
            self.lookups_in_window = 0;
        }
        if self.lookups_in_window >= per_minute {
            return false;
        }
        self.lookups_in_window += 1;
        true
    }
}

/// Whose budget a first-time committee lookup is charged to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupBudget {
    /// Discovery budget for peers identified as committee candidates by NodeInfo or
    /// the node table. Durable messages do not trigger discovery.
    Candidate,
    /// A peer this node holds a connection with; bounded by the connection
    /// ceiling. Local bans depend on these lookups coming back.
    Neighbour,
    /// A peer whose connection was refused for lack of an open slot.
    Refused,
}

impl RegistryState {
    /// Claim the verifier set refresh if it is due. The caller must fetch it and
    /// call `record_verifier_set`, or it stays marked as in flight.
    fn claim_verifier_set_refresh(&mut self, now: Instant) -> bool {
        let due = match (self.verifiers_fetched_at, self.verifiers_attempted_at) {
            (_, Some(attempted_at))
                if now.saturating_duration_since(attempted_at) < VERIFIER_SET_RETRY_INTERVAL =>
            {
                false
            }
            (Some(fetched_at), _) => {
                now.saturating_duration_since(fetched_at) >= VERIFIER_SET_REFRESH_INTERVAL
            }
            (None, _) => true,
        };
        if !due || self.verifiers_in_flight {
            return false;
        }
        self.verifiers_in_flight = true;
        self.verifiers_attempted_at = Some(now);
        true
    }

    /// Claim a committee lookup for `peer` if one is due and a slot is free. The
    /// caller must resolve it with `record_committee_peer`.
    fn claim_committee_lookup(
        &mut self,
        peer: &PeerId,
        budget: LookupBudget,
        now: Instant,
    ) -> bool {
        if self.verifiers.contains(&peer.to_bytes()) || self.committee_in_flight.contains(peer) {
            return false;
        }
        let known_registered = match self.committee.get(peer) {
            Some(entry) if !entry.needs_refresh(now) => return false,
            Some(entry) => entry.registered,
            None => false,
        };
        // Known-member refreshes may use every slot without discovery charges.
        let in_flight = self.committee_in_flight.len();
        let admitted = if known_registered {
            in_flight < COMMITTEE_MAX_IN_FLIGHT_LOOKUPS
        } else {
            match budget {
                LookupBudget::Candidate => {
                    in_flight < COMMITTEE_MAX_UNKNOWN_IN_FLIGHT
                        && self
                            .committee_discovery
                            .take(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE, now)
                }
                LookupBudget::Neighbour => {
                    in_flight < COMMITTEE_MAX_IN_FLIGHT_LOOKUPS
                        && self
                            .neighbour_discovery
                            .take(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE, now)
                }
                LookupBudget::Refused => {
                    in_flight < COMMITTEE_MAX_UNKNOWN_IN_FLIGHT
                        && self.refused_discovery.take(REFUSED_PEER_LOOKUPS_PER_MINUTE, now)
                }
            }
        };
        if admitted {
            self.committee_in_flight.insert(*peer);
        }
        admitted
    }

    /// Claim a due operator lookup; confirmed operators bypass discovery limits.
    fn claim_operator_refresh(
        &mut self,
        peer: &PeerId,
        pubkey: &OperatorKey,
        now: Instant,
    ) -> bool {
        if self.operators_in_flight.contains(peer) {
            return false;
        }
        let known_registered = match self.operators.get(peer) {
            // Only the current owner of the key is worth validating.
            Some(binding) if binding.pubkey != *pubkey => return false,
            Some(binding) if !binding.needs_refresh(now) => return false,
            Some(binding) => binding.staked == Some(true) || binding.trusted,
            None => return false,
        };
        let in_flight = self.operators_in_flight.len();
        if known_registered {
            if in_flight >= OPERATOR_MAX_IN_FLIGHT_LOOKUPS {
                return false;
            }
        } else if in_flight >= OPERATOR_MAX_UNKNOWN_IN_FLIGHT
            || !self.operator_discovery.take(OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE, now)
        {
            return false;
        }
        self.operators_in_flight.insert(*peer);
        true
    }
}

/// Trust window for restored registrations awaiting chain refresh.
const SEEDED_TRUST: Duration = Duration::from_secs(5 * 60);

/// How far back a seeded entry is dated: due for re-validation right away, and
/// `SEEDED_TRUST` short of the stale limit at which it stops being trusted.
fn seeded_fetched_at(now: Instant, stale_limit: Duration) -> Instant {
    now.checked_sub(stale_limit.saturating_sub(SEEDED_TRUST)).unwrap_or(now)
}

/// Why a configured operator binding was not applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedBindingConflict {
    /// The peer already holds a binding, signed by another key.
    PeerBoundToAnotherKey(OperatorKey),
    /// The key is already bound, by its own signature, to another peer id.
    KeyBoundToAnotherPeer(PeerId),
}

/// What the caller should fetch from the chain, decided under the cache lock so
/// concurrent messages from one peer start a single lookup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RefreshPlan {
    pub verifier_set: bool,
    pub committee_peer: bool,
}

/// Cached chain registration; misses are Unregistered and trigger background lookups.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    state: Mutex<RegistryState>,
}

impl PeerRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn is_verifier(&self, peer: &PeerId) -> bool {
        self.lock().verifiers.contains(&peer.to_bytes())
    }

    /// Whether the verifier set was ever fetched; before that nobody is
    /// turned away for not being in it.
    pub fn verifier_set_loaded(&self) -> bool {
        self.lock().verifiers_fetched_at.is_some()
    }

    pub fn sender_class(&self, peer: &PeerId, now: Instant) -> SenderClass {
        let state = self.lock();
        if state.committee.get(peer).is_some_and(|entry| entry.is_registered(now)) {
            SenderClass::Committee
        } else if state.verifiers.contains(&peer.to_bytes())
            || state.operators.get(peer).is_some_and(|binding| binding.is_registered(now))
        {
            SenderClass::Registered
        } else {
            SenderClass::Unregistered
        }
    }

    /// Whether `peer` is a committee member, from the cache. For handlers whose
    /// authorisation is the committee specifically, not any registered sender.
    pub fn is_committee(&self, peer: &PeerId, now: Instant) -> bool {
        self.sender_class(peer, now) == SenderClass::Committee
    }

    /// Whether fresh chain results identify the peer as unregistered.
    pub fn is_known_unregistered(&self, peer: &PeerId, now: Instant) -> bool {
        // A stale "no" does not count: the peer may have registered since.
        let looked_up = self
            .lock()
            .committee
            .get(peer)
            .is_some_and(|entry| !entry.registered && !entry.needs_refresh(now));
        looked_up && !self.sender_class(peer, now).is_registered()
    }

    /// Committee peers the cache currently holds as registered, for ack sets.
    pub fn committee_peer_ids(&self, now: Instant) -> Vec<PeerId> {
        let state = self.lock();
        state
            .committee
            .iter()
            .filter(|(_, entry)| entry.is_registered(now))
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// The peer currently bound to an operator master key, if known.
    pub fn operator_peer_for(&self, pubkey: &OperatorKey) -> Option<PeerId> {
        self.lock().operator_owner.get(pubkey).copied()
    }

    /// Record a verified binding; newer issuance wins and each key maps to one peer.
    /// Returns whether the peer's previous persisted registration must be revoked.
    pub fn observe_operator_binding(
        &self,
        peer: &PeerId,
        pubkey: &OperatorKey,
        issued_at: i64,
    ) -> bool {
        let mut state = self.lock();
        let mut released_confirmed_key = false;
        // Move the key to the peer with the newer binding.
        if let Some(current_owner) = state.operator_owner.get(pubkey).copied()
            && current_owner != *peer
        {
            let newer = state
                .operators
                .get(&current_owner)
                // Require a strictly newer issuance time for ownership transfer.
                .is_none_or(|existing| issued_at > existing.issued_at);
            if !newer {
                return false;
            }
            state.operators.remove(&current_owner);
        }
        if let Some(previous) = state.operators.get_mut(peer) {
            if previous.pubkey == *pubkey {
                // Preserve the stake verdict when the peer re-announces the same key.
                previous.issued_at = previous.issued_at.max(issued_at);
                state.operator_owner.insert(*pubkey, *peer);
                return false;
            }
            // A peer that rebinds to a different key releases its old key's
            // ownership, and whatever was confirmed for that key with it.
            released_confirmed_key = previous.staked == Some(true);
            let previous_pubkey = previous.pubkey;
            if state.operator_owner.get(&previous_pubkey) == Some(peer) {
                state.operator_owner.remove(&previous_pubkey);
            }
        }
        if state.operators.len() >= OPERATOR_CACHE_MAX_ENTRIES
            && !state.operators.contains_key(peer)
        {
            let now = Instant::now();
            state.operators.retain(|_, binding| binding.is_registered(now) || binding.trusted);
            let live: HashSet<PeerId> = state.operators.keys().copied().collect();
            state.operator_owner.retain(|_, owner| live.contains(owner));
        }
        state.operator_owner.insert(*pubkey, *peer);
        state.operators.insert(
            *peer,
            OperatorBinding {
                pubkey: *pubkey,
                issued_at,
                staked: None,
                fetched_at: None,
                trusted: false,
            },
        );
        released_confirmed_key
    }

    /// Record a configured binding without overriding a signed binding.
    /// See `P2P_TRUSTED_OPERATOR_BINDINGS`.
    pub fn trust_operator_binding(
        &self,
        peer: &PeerId,
        pubkey: &OperatorKey,
    ) -> Result<(), TrustedBindingConflict> {
        let mut state = self.lock();
        if let Some(existing) = state.operators.get(peer)
            && existing.pubkey != *pubkey
        {
            return Err(TrustedBindingConflict::PeerBoundToAnotherKey(existing.pubkey));
        }
        if let Some(owner) = state.operator_owner.get(pubkey)
            && owner != peer
        {
            return Err(TrustedBindingConflict::KeyBoundToAnotherPeer(*owner));
        }
        state.operator_owner.insert(*pubkey, *peer);
        state.operators.entry(*peer).and_modify(|binding| binding.trusted = true).or_insert(
            OperatorBinding {
                pubkey: *pubkey,
                issued_at: 0,
                staked: None,
                fetched_at: None,
                trusted: true,
            },
        );
        Ok(())
    }

    /// Whether an operator stake lookup for `peer`/`pubkey` should start now.
    /// Claimed lookups must be resolved with [`Self::record_operator_stake`].
    pub fn plan_operator_refresh(&self, peer: &PeerId, pubkey: &OperatorKey, now: Instant) -> bool {
        self.lock().claim_operator_refresh(peer, pubkey, now)
    }

    /// Claim due operator refreshes, confirmed operators first.
    pub fn plan_due_operator_refreshes(&self, now: Instant) -> Vec<(PeerId, OperatorKey)> {
        let mut state = self.lock();
        let mut due: Vec<(PeerId, OperatorKey, bool)> = state
            .operators
            .iter()
            // Retry a negative stake verdict only after another announcement.
            .filter(|(peer, binding)| {
                binding.needs_refresh(now)
                    && (binding.staked != Some(false) || binding.trusted)
                    && !state.operators_in_flight.contains(*peer)
            })
            .map(|(peer, binding)| {
                (*peer, binding.pubkey, binding.staked == Some(true) || binding.trusted)
            })
            .collect();
        due.sort_by_key(|(_, _, known)| !*known);
        due.into_iter()
            .filter(|(peer, pubkey, _)| state.claim_operator_refresh(peer, pubkey, now))
            .map(|(peer, pubkey, _)| (peer, pubkey))
            .collect()
    }

    /// Record the verdict for the peer's current binding and return the persistence update.
    pub fn record_operator_stake(
        &self,
        peer: &PeerId,
        pubkey: &OperatorKey,
        staked: Option<bool>,
        now: Instant,
    ) -> Option<bool> {
        let mut state = self.lock();
        state.operators_in_flight.remove(peer);
        let staked = staked?;
        // Ignore a result for a binding that was superseded while in flight.
        let binding = state.operators.get_mut(peer).filter(|binding| binding.pubkey == *pubkey)?;
        binding.staked = Some(staked);
        binding.fetched_at = Some(now);
        Some(staked)
    }

    /// Restore a confirmed operator only when its current binding matches the stored key.
    /// Schedule immediate revalidation.
    pub fn seed_verified_operator(
        &self,
        peer: &PeerId,
        pubkey: &OperatorKey,
        issued_at: i64,
        now: Instant,
    ) {
        self.observe_operator_binding(peer, pubkey, issued_at);
        let mut state = self.lock();
        if let Some(binding) = state.operators.get_mut(peer)
            && binding.pubkey == *pubkey
            && binding.staked.is_none()
        {
            binding.staked = Some(true);
            binding.fetched_at = Some(seeded_fetched_at(now, OPERATOR_STAKE_STALE_LIMIT));
        }
    }

    /// Re-instate a committee member confirmed in an earlier session; see
    /// [`Self::seed_verified_operator`].
    pub fn seed_verified_committee_peer(&self, peer: &PeerId, now: Instant) {
        self.lock().committee.entry(*peer).or_insert(CommitteeEntry {
            registered: true,
            fetched_at: seeded_fetched_at(now, COMMITTEE_STALE_LIMIT),
        });
    }

    /// Claim due committee-member refreshes.
    pub fn plan_due_committee_refreshes(&self, now: Instant) -> Vec<PeerId> {
        let mut state = self.lock();
        let due: Vec<PeerId> = state
            .committee
            .iter()
            .filter(|(peer, entry)| {
                entry.registered
                    && entry.needs_refresh(now)
                    && !state.committee_in_flight.contains(*peer)
            })
            .map(|(peer, _)| *peer)
            .collect();
        let free = COMMITTEE_MAX_IN_FLIGHT_LOOKUPS.saturating_sub(state.committee_in_flight.len());
        let claimed: Vec<PeerId> = due.into_iter().take(free).collect();
        state.committee_in_flight.extend(claimed.iter().copied());
        claimed
    }

    /// Claim the lookups that are due. Whatever is claimed must be resolved with
    /// the matching `record_*` call, or it stays marked as in flight.
    pub fn plan_refresh(&self, peer: Option<&PeerId>, now: Instant) -> RefreshPlan {
        let mut state = self.lock();
        RefreshPlan {
            verifier_set: state.claim_verifier_set_refresh(now),
            committee_peer: peer.is_some_and(|peer| {
                state.claim_committee_lookup(peer, LookupBudget::Candidate, now)
            }),
        }
    }

    /// Claim only a candidate's committee lookup, using the discovery budget;
    /// the verifier set is left to [`refresh_registry_in_background`](super::registry_refresh::refresh_registry_in_background).
    pub fn plan_candidate_lookup(&self, peer: &PeerId, now: Instant) -> bool {
        self.lock().claim_committee_lookup(peer, LookupBudget::Candidate, now)
    }

    /// Whether the registry has never classified `peer`: no committee verdict,
    /// not in the verifier set and no operator binding.
    pub fn is_unclassified(&self, peer: &PeerId) -> bool {
        let state = self.lock();
        !state.committee.contains_key(peer)
            && !state.verifiers.contains(&peer.to_bytes())
            && !state.operators.contains_key(peer)
    }

    /// Claim only the neighbour's committee lookup, using the neighbour budget.
    pub fn plan_neighbour_lookup(&self, peer: &PeerId, now: Instant) -> bool {
        self.lock().claim_committee_lookup(peer, LookupBudget::Neighbour, now)
    }

    /// Claim refused-peer lookups using their separate budget.
    pub fn plan_refused_peer_lookup(&self, peer: &PeerId, now: Instant) -> bool {
        self.lock().claim_committee_lookup(peer, LookupBudget::Refused, now)
    }

    pub fn record_verifier_set(&self, verifiers: Option<Vec<Vec<u8>>>, now: Instant) {
        let mut state = self.lock();
        state.verifiers_in_flight = false;
        // Retain the previous verifier set on fetch failure.
        if let Some(verifiers) = verifiers {
            state.verifiers = verifiers.into_iter().collect();
            state.verifiers_fetched_at = Some(now);
        }
    }

    /// Record a committee lookup. Returns the definite verdict, for the caller
    /// to persist; see [`Self::record_operator_stake`].
    pub fn record_committee_peer(
        &self,
        peer: &PeerId,
        registered: Option<bool>,
        now: Instant,
    ) -> Option<bool> {
        let mut state = self.lock();
        state.committee_in_flight.remove(peer);
        let registered = registered?;
        let changed = Some(registered);
        if !state.committee.contains_key(peer)
            && state.committee.len() >= COMMITTEE_CACHE_MAX_ENTRIES
        {
            state.committee.retain(|_, entry| !entry.needs_refresh(now));
            if state.committee.len() >= COMMITTEE_CACHE_MAX_ENTRIES {
                if !registered {
                    return changed;
                }
                let evict = state
                    .committee
                    .iter()
                    .find(|(_, entry)| !entry.registered)
                    .map(|(peer, _)| *peer);
                if let Some(evict) = evict {
                    state.committee.remove(&evict);
                }
            }
        }
        state.committee.insert(*peer, CommitteeEntry { registered, fetched_at: now });
        changed
    }
}

static PEER_REGISTRY: LazyLock<PeerRegistry> = LazyLock::new(PeerRegistry::default);

pub fn peer_registry() -> &'static PeerRegistry {
    &PEER_REGISTRY
}
