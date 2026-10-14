//! Inbound gossip admission: envelope, identity, replay, rate and storage checks.
//! Durable messages are admitted before persistence and forwarding.
//! Rejected messages use gossipsub `Ignore`.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use store::InboxClassUsage;
use store::localdb::LocalDB;
use strum::{Display, EnumString};

use crate::action::{GOATMessage, GOATMessageContent, P2PMessageDelivery};
use crate::middleware::behaviour::MAX_GOSSIPSUB_TRANSMIT_SIZE;

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

/// How long a rejected network event keeps its inbox row, and so its share
/// of the author's quota, before the maintenance purge removes it.
pub const REJECTED_EVENT_TTL_SECS: i64 = 2 * 60 * 60;

const VERIFIER_SET_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const VERIFIER_SET_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const COMMITTEE_POSITIVE_TTL: Duration = Duration::from_secs(10 * 60);
const COMMITTEE_NEGATIVE_TTL: Duration = Duration::from_secs(2 * 60);
/// Maximum stale age for retaining a registered classification during refresh.
const COMMITTEE_STALE_LIMIT: Duration = Duration::from_secs(30 * 60);
const COMMITTEE_CACHE_MAX_ENTRIES: usize = 4096;
/// Lookup rate for committee candidates (peers announcing themselves as
/// committee by NodeInfo, or stored in the node table); known-member
/// refreshes are exempt.
const COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE: u32 = 60;
const COMMITTEE_MAX_IN_FLIGHT_LOOKUPS: usize = 16;
/// Maximum unknown-identity lookups in flight.
const COMMITTEE_MAX_UNKNOWN_IN_FLIGHT: usize = 12;
const REGISTRY_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Separate discovery budget for operator stake lookups.
const OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE: u32 = 60;
const OPERATOR_MAX_IN_FLIGHT_LOOKUPS: usize = 16;
const OPERATOR_MAX_UNKNOWN_IN_FLIGHT: usize = 12;
const REFUSED_PEER_LOOKUPS_PER_MINUTE: u32 = 30;

/// A confirmed operator binding keeps its class this long before re-validation;
/// a shorter window applies while the stake is still unknown.
const OPERATOR_STAKE_TTL: Duration = Duration::from_secs(10 * 60);
const OPERATOR_STAKE_STALE_LIMIT: Duration = Duration::from_secs(30 * 60);
const OPERATOR_CACHE_MAX_ENTRIES: usize = 4096;
/// Maximum persisted operator bindings loaded at startup.
pub const OPERATOR_BINDING_LOAD_LIMIT: i64 = OPERATOR_CACHE_MAX_ENTRIES as i64;

const IMMEDIATE_BURST: f64 = 240.0;
const IMMEDIATE_REFILL_PER_SEC: f64 = 2.0;
const IMMEDIATE_MAX_TRACKED_PEERS: usize = 4096;

/// NodeInfo broadcast response cooldown.
const NODE_INFO_RESPONSE_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quota {
    pub rows: i64,
    pub bytes: i64,
}

impl Quota {
    fn admits(&self, rows: i64, bytes: i64) -> bool {
        rows <= self.rows && bytes <= self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundLimits {
    pub max_json_bytes: usize,
    pub max_binary_bytes: usize,
    /// Every queued row, whatever its class.
    pub global: Quota,
    /// Global queue capacity reserved for committee.
    pub committee_reserve: Quota,
    /// Every queued row of one registered sender, in whichever class.
    pub registered_peer: Quota,
}

impl InboundLimits {
    /// Derive byte quotas from the global ceiling; row limits remain fixed.
    pub fn with_queued_bytes(max_json_bytes: usize, max_queued_bytes: i64) -> Self {
        Self {
            max_json_bytes,
            max_binary_bytes: MAX_GOSSIPSUB_TRANSMIT_SIZE,
            global: Quota { rows: 16_384, bytes: max_queued_bytes },
            committee_reserve: Quota { rows: 4_096, bytes: max_queued_bytes / 4 },
            registered_peer: Quota { rows: 1_024, bytes: max_queued_bytes / 8 },
        }
    }

    pub fn from_env() -> Self {
        Self::with_queued_bytes(
            crate::env::get_p2p_max_json_message_bytes(),
            crate::env::get_p2p_inbox_max_queued_bytes(),
        )
    }
}

static INBOUND_LIMITS: LazyLock<InboundLimits> = LazyLock::new(InboundLimits::from_env);

pub fn inbound_limits() -> &'static InboundLimits {
    &INBOUND_LIMITS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DropReason {
    OversizedJson,
    OversizedBinary,
    BinaryFromNonVerifier,
    /// A graph parameter endorsement from a peer outside the loaded verifier
    /// set: verifying one costs chain reads, and only verifiers send them.
    EndorsementFromNonVerifier,
    /// A registered author's message whose sequence number was already seen, or
    /// is older than the replay window: a verbatim re-publish by someone else.
    ReplayedSequence,
    /// Sequence number exceeds the accepted clock lead.
    FutureSequence,
    /// A message addressed to another role, from an unregistered author, beyond
    /// what this node relays for such authors.
    ForwardRate,
    DirectPeerRate,
    AuthorRate,
    UnregisteredRate,
    GlobalRate,
    Undecodable,
    UnexpectedBinaryKind,
    ImmediateRateLimited,
    /// The bounded queue in front of the control worker (NodeInfo, ACKs) had no
    /// room, by rows or by bytes. Distinct from `ImmediateRateLimited`: that one
    /// is a sender exceeding its rate, this one is the node falling behind.
    ControlQueueFull,
    SenderQuota,
    GlobalQuota,
    /// Not a message drop: a `NodeInfo` from a sender that is not registered was
    /// not stored because the `node` table is at its ceiling for such senders.
    NodeTableFull,
    /// NodeInfo rejected for invalid identity, fields or binding.
    NodeInfoRejected,
    /// Not a drop: the engine already held the event (same author and
    /// content); recorded in the periodic summary.
    DuplicatePayload,
}

impl DropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OversizedJson => "oversized_json",
            Self::OversizedBinary => "oversized_binary",
            Self::BinaryFromNonVerifier => "binary_from_non_verifier",
            Self::EndorsementFromNonVerifier => "endorsement_from_non_verifier",
            Self::ReplayedSequence => "replayed_sequence",
            Self::FutureSequence => "future_sequence",
            Self::ForwardRate => "forward_rate",
            Self::DirectPeerRate => "direct_peer_rate",
            Self::AuthorRate => "author_rate",
            Self::UnregisteredRate => "unregistered_rate",
            Self::GlobalRate => "global_rate",
            Self::Undecodable => "undecodable",
            Self::UnexpectedBinaryKind => "unexpected_binary_kind",
            Self::ImmediateRateLimited => "immediate_rate_limited",
            Self::ControlQueueFull => "control_queue_full",
            Self::SenderQuota => "sender_quota",
            Self::GlobalQuota => "global_quota",
            Self::NodeTableFull => "node_table_full",
            Self::NodeInfoRejected => "node_info_rejected",
            Self::DuplicatePayload => "duplicate_payload",
        }
    }

    /// Whether a drop is attributable to the direct peer, independent of local state and configuration.
    pub const fn blames_direct_peer(self) -> bool {
        matches!(self, Self::OversizedBinary | Self::Undecodable | Self::UnexpectedBinaryKind)
    }

    /// Whether the payload was decoded before it was dropped.
    pub const fn after_decode(self) -> bool {
        matches!(
            self,
            Self::UnexpectedBinaryKind
                | Self::EndorsementFromNonVerifier
                | Self::ForwardRate
                | Self::ImmediateRateLimited
                | Self::ControlQueueFull
                | Self::SenderQuota
                | Self::GlobalQuota
        )
    }
}

/// Checks that need nothing but the raw bytes and the sender's identity.
pub fn check_envelope(
    data: &[u8],
    sender_is_verifier: bool,
    limits: &InboundLimits,
) -> Result<(), DropReason> {
    if GOATMessage::is_binary_envelope(data) {
        if !sender_is_verifier {
            return Err(DropReason::BinaryFromNonVerifier);
        }
        if data.len() > limits.max_binary_bytes {
            return Err(DropReason::OversizedBinary);
        }
    } else if data.len() > limits.max_json_bytes {
        return Err(DropReason::OversizedJson);
    }
    Ok(())
}

/// Check whether a registered author's next inbox row fits its quotas.
/// Usage excludes the new row; unregistered authors are not persisted.
pub fn check_inbox_quota(
    class: SenderClass,
    content_len: usize,
    usage: &[InboxClassUsage],
    limits: &InboundLimits,
) -> Result<(), DropReason> {
    let content_len = content_len as i64;
    let total_rows: i64 = usage.iter().map(|usage| usage.rows).sum();
    let total_bytes: i64 = usage.iter().map(|usage| usage.bytes).sum();
    if !limits.global.admits(total_rows + 1, total_bytes + content_len) {
        return Err(DropReason::GlobalQuota);
    }
    if class != SenderClass::Committee {
        let committee = SenderClass::Committee.to_string();
        let (rows, bytes) = usage
            .iter()
            .filter(|usage| usage.admission_class != committee)
            .fold((0, 0), |(rows, bytes), usage| (rows + usage.rows, bytes + usage.bytes));
        let open = Quota {
            rows: limits.global.rows - limits.committee_reserve.rows,
            bytes: limits.global.bytes - limits.committee_reserve.bytes,
        };
        if !open.admits(rows + 1, bytes + content_len) {
            return Err(DropReason::GlobalQuota);
        }
    }

    // A sender can hold rows in more than one class: it is classified when each
    // row arrives, and a committee lookup may complete in between.
    let peer_rows: i64 = usage.iter().map(|usage| usage.peer_rows).sum();
    let peer_bytes: i64 = usage.iter().map(|usage| usage.peer_bytes).sum();
    if !limits.registered_peer.admits(peer_rows + 1, peer_bytes + content_len) {
        return Err(DropReason::SenderQuota);
    }
    Ok(())
}

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

    /// Registered verifier peer IDs; `None` means not yet fetched.
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
    /// the verifier set is left to [`refresh_registry_in_background`].
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

/// Persisted registration kinds.
const REGISTERED_KIND_COMMITTEE: &str = "Committee";
const REGISTERED_KIND_OPERATOR: &str = "Operator";

/// Persist a change in a peer's confirmed registration. Best effort: the cache
/// stays authoritative for this session, the table only warms the next one.
async fn persist_registration_change(
    local_db: &LocalDB,
    peer: &PeerId,
    kind: &str,
    pubkey: Option<&OperatorKey>,
    change: Option<bool>,
) {
    let Some(registered) = change else {
        return;
    };
    let peer_id = peer.to_string();
    let pubkey = pubkey.map(hex::encode).unwrap_or_default();
    let result = async {
        let mut storage = local_db.acquire().await?;
        if registered {
            storage.upsert_p2p_registered_peer(&peer_id, kind, &pubkey).await
        } else {
            storage.delete_p2p_registered_peer(&peer_id, kind).await
        }
    }
    .await;
    if let Err(error) = result {
        tracing::debug!(
            event = "p2p_admission",
            outcome = "registration_persist_failed",
            peer_id = %peer_id,
            kind,
            error = %error,
            "failed to persist a confirmed registration; it will be rediscovered after a restart"
        );
    }
}

/// Revoke persisted operator registration after a key change.
pub async fn revoke_persisted_operator(local_db: &LocalDB, peer: &PeerId) {
    persist_registration_change(local_db, peer, REGISTERED_KIND_OPERATOR, None, Some(false)).await;
}

/// Restore confirmed peers; operator bindings must be signature-checked and match stored keys.
pub async fn seed_registry_from_store(
    local_db: &LocalDB,
    registry: &PeerRegistry,
    operator_bindings: &HashMap<PeerId, (OperatorKey, i64)>,
    now: Instant,
) -> Result<u64> {
    let persisted = local_db.acquire().await?.load_p2p_registered_peers().await?;
    let mut seeded = 0;
    for (peer_id, kind, confirmed_pubkey) in persisted {
        let Ok(peer) = PeerId::from_str(&peer_id) else {
            continue;
        };
        match kind.as_str() {
            REGISTERED_KIND_COMMITTEE => {
                registry.seed_verified_committee_peer(&peer, now);
                seeded += 1;
            }
            REGISTERED_KIND_OPERATOR => {
                if let Some((pubkey, issued_at)) = operator_bindings.get(&peer)
                    && hex::encode(pubkey) == confirmed_pubkey
                {
                    registry.seed_verified_operator(&peer, pubkey, *issued_at, now);
                    seeded += 1;
                }
            }
            _ => {}
        }
    }
    Ok(seeded)
}

fn spawn_committee_lookup(local_db: &LocalDB, goat_client: &Arc<GOATClient>, peer: PeerId) {
    let registry = peer_registry();
    let (local_db, goat_client) = (local_db.clone(), goat_client.clone());
    tokio::spawn(async move {
        let registered = match tokio::time::timeout(
            REGISTRY_RPC_TIMEOUT,
            goat_client.committee_mana_is_validate_peer_id(&peer.to_bytes()),
        )
        .await
        {
            Ok(Ok(registered)) => Some(registered),
            Ok(Err(error)) => {
                tracing::debug!(
                    event = "p2p_admission",
                    outcome = "committee_lookup_failed",
                    peer_id = %peer,
                    error = %error,
                    "failed to look up a peer in the committee registry"
                );
                None
            }
            Err(_) => None,
        };
        let change = registry.record_committee_peer(&peer, registered, Instant::now());
        persist_registration_change(&local_db, &peer, REGISTERED_KIND_COMMITTEE, None, change)
            .await;
    });
}

fn spawn_operator_stake_lookup(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
    operator_key: OperatorKey,
) {
    use crate::utils::OperatorStakeStatus;

    let registry = peer_registry();
    // The stake is registered under the x-only key; the parity chosen here is
    // dropped again by the lookup.
    let Ok(xonly) = bitcoin::XOnlyPublicKey::from_slice(&operator_key) else {
        registry.record_operator_stake(&peer, &operator_key, Some(false), Instant::now());
        return;
    };
    let pubkey = bitcoin::PublicKey::new(xonly.public_key(bitcoin::secp256k1::Parity::Even));
    let (local_db, goat_client) = (local_db.clone(), goat_client.clone());
    tokio::spawn(async move {
        let staked = match tokio::time::timeout(
            REGISTRY_RPC_TIMEOUT,
            crate::utils::operator_stake_status(&goat_client, &pubkey),
        )
        .await
        {
            Ok(Ok(OperatorStakeStatus::Staked)) => Some(true),
            Ok(Ok(
                OperatorStakeStatus::NotRegistered | OperatorStakeStatus::Insufficient { .. },
            )) => Some(false),
            // Preserve the cached stake verdict on RPC failure.
            Ok(Err(error)) => {
                tracing::debug!(
                    event = "p2p_admission",
                    outcome = "operator_stake_lookup_failed",
                    peer_id = %peer,
                    error = %error,
                    "failed to confirm operator stake; leaving the binding unverified"
                );
                None
            }
            Err(_) => None,
        };
        let change = registry.record_operator_stake(&peer, &operator_key, staked, Instant::now());
        persist_registration_change(
            &local_db,
            &peer,
            REGISTERED_KIND_OPERATOR,
            Some(&operator_key),
            change,
        )
        .await;
    });
}

/// Look up a peer this node is connected to; see
/// [`PeerRegistry::plan_neighbour_lookup`].
pub fn refresh_neighbour_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
) {
    if peer_registry().plan_neighbour_lookup(&peer, Instant::now()) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
}

/// Schedule due verifier-set and candidate committee lookups without waiting.
/// Durable messages do not trigger these lookups.
pub fn refresh_registry_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: Option<PeerId>,
) {
    let registry = peer_registry();
    let plan = registry.plan_refresh(peer.as_ref(), Instant::now());
    if plan.verifier_set {
        let goat_client = goat_client.clone();
        tokio::spawn(async move {
            let fetched = match tokio::time::timeout(
                REGISTRY_RPC_TIMEOUT,
                goat_client.committee_mana_get_verifiers(),
            )
            .await
            {
                Ok(Ok(verifiers)) => Some(verifiers),
                Ok(Err(error)) => {
                    tracing::warn!(
                        event = "p2p_admission",
                        outcome = "verifier_set_refresh_failed",
                        error = %error,
                        "failed to refresh the registered verifier set; keeping the previous one"
                    );
                    None
                }
                Err(_) => {
                    tracing::warn!(
                        event = "p2p_admission",
                        outcome = "verifier_set_refresh_timeout",
                        "timed out refreshing the registered verifier set; keeping the previous one"
                    );
                    None
                }
            };
            registry.record_verifier_set(fetched, Instant::now());
        });
    }
    if let Some(peer) = peer.filter(|_| plan.committee_peer) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
}

/// Schedule refreshes for known registrations that are due.
pub fn refresh_due_registrations_in_background(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let registry = peer_registry();
    let now = Instant::now();
    refresh_registry_in_background(local_db, goat_client, None);
    for peer in registry.plan_due_committee_refreshes(now) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
    for peer in take_refused_peers() {
        if registry.plan_refused_peer_lookup(&peer, now) {
            spawn_committee_lookup(local_db, goat_client, peer);
        }
    }
    for (peer, operator_key) in registry.plan_due_operator_refreshes(now) {
        spawn_operator_stake_lookup(local_db, goat_client, peer, operator_key);
    }
}

/// Committee candidates the node table holds (self-declared by NodeInfo)
/// that the registry does not know as registered: looked up within the
/// candidate budget, so a member whose NodeInfo arrived while the budget was
/// spent, or before a restart, is classified by the maintenance tick instead
/// of by its first message.
const COMMITTEE_CANDIDATES_PER_TICK: u32 = 64;
const COMMITTEE_CANDIDATE_SCAN_INTERVAL: Duration = Duration::from_secs(60);
static COMMITTEE_CANDIDATES_SCANNED_AT: Mutex<Option<Instant>> = Mutex::new(None);

fn committee_candidate_scan_due(now: Instant) -> bool {
    let mut scanned_at =
        COMMITTEE_CANDIDATES_SCANNED_AT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if scanned_at
        .is_some_and(|at| now.saturating_duration_since(at) < COMMITTEE_CANDIDATE_SCAN_INTERVAL)
    {
        return false;
    }
    *scanned_at = Some(now);
    true
}

/// Look up the self-declared committee peers the registry has never
/// classified. Peers with a verdict, registered or not, are refreshed by their
/// own messages; the scan only covers announcements that arrived while the
/// discovery budget was spent or before a restart.
pub async fn revalidate_committee_candidates(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let registry = peer_registry();
    let now = Instant::now();
    if !committee_candidate_scan_due(now) {
        return;
    }
    let candidates = match local_db.acquire().await {
        Ok(mut storage) => {
            storage
                .find_nodes(
                    &store::localdb::NodeQuery::default()
                        .with_actor(bitvm_lib::actors::Actor::Committee.to_string())
                        .with_order("updated_at DESC".to_string())
                        .with_limit(COMMITTEE_CANDIDATES_PER_TICK),
                )
                .await
        }
        Err(error) => Err(error),
    };
    let candidates = match candidates {
        Ok((nodes, _)) => nodes,
        Err(error) => {
            tracing::debug!(event = "p2p_admission", outcome = "candidate_scan_failed", error = %error, "could not read committee candidates");
            return;
        }
    };
    for node in candidates {
        let Ok(peer) = PeerId::from_str(&node.peer_id) else { continue };
        if !registry.is_unclassified(&peer) {
            continue;
        }
        if registry.plan_candidate_lookup(&peer, now) {
            spawn_committee_lookup(local_db, goat_client, peer);
        }
    }
}

/// Confirm, off the event loop, that a proven operator binding belongs to a
/// sufficiently staked operator, and cache the verdict for classification.
pub fn refresh_operator_binding_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
    operator_key: OperatorKey,
) {
    if !peer_registry().plan_operator_refresh(&peer, &operator_key, Instant::now()) {
        return;
    }
    spawn_operator_stake_lookup(local_db, goat_client, peer, operator_key);
}

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
const RATE_BUCKET_IDLE_FORGET: Duration = Duration::from_secs(60);
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
    fn tracked_authors(&self) -> usize {
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
    fn new(cooldown: Duration, max_entries: usize) -> Self {
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
    fn len(&self) -> usize {
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

const STRIKE_WINDOW: Duration = Duration::from_secs(60);
const STRIKE_LIMIT: u32 = 256;
const STRIKE_BAN: Duration = Duration::from_secs(10 * 60);
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

fn take_refused_peers() -> Vec<PeerId> {
    std::mem::take(&mut *REFUSED_PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// How long one peer's identical `GetGraph` request stays on cooldown.
const GET_GRAPH_RESPONSE_COOLDOWN: Duration = Duration::from_secs(60);
const GRAPH_SET_MAX_ENTRIES: usize = 16_384;

/// A global token bucket, for a resource no per-peer key bounds.
#[derive(Debug)]
pub struct GlobalRate {
    bucket: Mutex<RateBucket>,
    rate: f64,
    burst: f64,
}

impl GlobalRate {
    fn new(burst: f64, rate: f64) -> Self {
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

/// Aggregate drop counters for periodic logging.
#[derive(Debug, Default)]
pub struct DropStats {
    counts: Mutex<HashMap<DropReason, u64>>,
}

impl DropStats {
    pub fn record(&self, reason: DropReason) {
        let mut counts = self.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *counts.entry(reason).or_default() += 1;
    }

    pub fn take(&self) -> Vec<(DropReason, u64)> {
        let mut counts = self.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut taken: Vec<_> = counts.drain().collect();
        taken.sort_by_key(|(reason, _)| reason.as_str());
        taken
    }
}

static DROP_STATS: LazyLock<DropStats> = LazyLock::new(DropStats::default);

pub fn record_drop(reason: DropReason) {
    DROP_STATS.record(reason);
}

/// Emit one line for everything dropped since the previous call.
pub fn log_drop_summary() {
    let dropped = DROP_STATS.take();
    if dropped.is_empty() {
        return;
    }
    let total: u64 = dropped.iter().map(|(_, count)| count).sum();
    let breakdown = dropped
        .iter()
        .map(|(reason, count)| format!("{}={count}", reason.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    tracing::warn!(
        event = "p2p_admission",
        outcome = "summary",
        total,
        breakdown,
        "inbound P2P messages dropped, de-duplicated or admitted unlogged by admission control"
    );
}

/// Number of sequence positions retained below the high-water mark.
const REPLAY_WINDOW: u64 = 1_024;
const REPLAY_MAX_TRACKED_AUTHORS: usize = 16_384;

/// Maximum accepted sequence-number lead over local wall time.
const REPLAY_MAX_FUTURE: Duration = Duration::from_secs(10 * 60);
/// Below-floor rejections of one author per tick that are worth an operator's
/// attention; see [`ReplayGuard::take_lockout_suspects`].
const REPLAY_LOCKOUT_SUSPECT_REJECTIONS: u32 = 8;

#[derive(Debug, Default)]
struct AuthorSequence {
    highest: u64,
    /// Sequence numbers seen within `REPLAY_WINDOW` of `highest`.
    recent: std::collections::BTreeSet<u64>,
    /// Rejection count since the last report; diagnostic only.
    rejected: u32,
}

/// Per-registered-author sequence window, in memory only: accept unseen numbers
/// within `REPLAY_WINDOW` of the highest one admitted. A restart re-opens every
/// window; what a replay can then re-inject is bounded by the engine inbox's
/// content-id dedup and, for a registered author, charged to its own rate budget.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    authors: Mutex<HashMap<PeerId, AuthorSequence>>,
    /// How far each registered author's numbering ran ahead of the local clock
    /// since the last report; see [`Self::take_clock_leads`].
    clock_leads: Mutex<HashMap<PeerId, u64>>,
}

/// Authors remembered per tick for the clock report. It is a diagnostic, and the
/// table must stay small whatever arrives.
const CLOCK_LEADS_MAX_AUTHORS: usize = 64;

impl ReplayGuard {
    /// Record `sequence_number` for `author`, or refuse it. `unix_nanos` is the
    /// local wall clock.
    pub fn admit(
        &self,
        author: &PeerId,
        sequence_number: Option<u64>,
        unix_nanos: u64,
    ) -> Result<(), DropReason> {
        // Require a signed sequence number.
        let sequence_number = sequence_number.ok_or(DropReason::ReplayedSequence)?;
        if sequence_number > unix_nanos {
            self.note_clock_lead(author, sequence_number - unix_nanos);
        }
        if sequence_number > unix_nanos.saturating_add(REPLAY_MAX_FUTURE.as_nanos() as u64) {
            return Err(DropReason::FutureSequence);
        }
        let mut authors = self.authors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !authors.contains_key(author) && authors.len() >= REPLAY_MAX_TRACKED_AUTHORS {
            // Only reachable if the registries outgrow the table; forgetting an
            // author merely re-opens its window once.
            if let Some(evicted) = authors.keys().next().copied() {
                authors.remove(&evicted);
            }
        }
        let state = authors.entry(*author).or_default();
        if sequence_number > state.highest {
            state.highest = sequence_number;
            let floor = sequence_number.saturating_sub(REPLAY_WINDOW);
            state.recent = state.recent.split_off(&floor);
        } else if state.highest - sequence_number >= REPLAY_WINDOW
            || state.recent.contains(&sequence_number)
        {
            state.rejected = state.rejected.saturating_add(1);
            return Err(DropReason::ReplayedSequence);
        }
        state.recent.insert(sequence_number);
        Ok(())
    }

    fn note_clock_lead(&self, author: &PeerId, lead_nanos: u64) {
        let mut leads = self.clock_leads.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if leads.len() < CLOCK_LEADS_MAX_AUTHORS || leads.contains_key(author) {
            let lead = leads.entry(*author).or_default();
            *lead = (*lead).max(lead_nanos);
        }
    }

    /// Return and clear each registered author's maximum clock lead since the previous call.
    pub fn take_clock_leads(&self) -> Vec<(PeerId, Duration)> {
        let mut leads = self.clock_leads.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        leads.drain().map(|(author, lead)| (author, Duration::from_nanos(lead))).collect()
    }

    /// Return authors exceeding the rejection reporting threshold.
    pub fn take_lockout_suspects(&self) -> Vec<(PeerId, u32)> {
        let mut authors = self.authors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        authors
            .iter_mut()
            .filter_map(|(author, state)| {
                let rejected = std::mem::take(&mut state.rejected);
                (rejected >= REPLAY_LOCKOUT_SUSPECT_REJECTIONS).then_some((*author, rejected))
            })
            .collect()
    }
}

/// The local wall clock in the unit gossipsub numbers its messages in.
pub fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
}

pub fn replay_guard() -> &'static ReplayGuard {
    &REPLAY_GUARD
}

static REPLAY_GUARD: LazyLock<ReplayGuard> = LazyLock::new(ReplayGuard::default);

/// How long the per-class inbox totals are served from memory.
const INBOX_CLASS_TOTALS_TTL: Duration = Duration::from_secs(2);

/// Cache per-class engine inbox totals and increment them on admission.
/// Applies and purges are reflected at the next cache refresh.
#[derive(Debug, Default)]
pub struct InboxUsageCache {
    totals: Mutex<Option<(Instant, Vec<InboxClassUsage>)>>,
}

impl InboxUsageCache {
    fn fresh(&self, now: Instant) -> Option<Vec<InboxClassUsage>> {
        let totals = self.totals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        totals
            .as_ref()
            .filter(|(at, _)| now.saturating_duration_since(*at) < INBOX_CLASS_TOTALS_TTL)
            .map(|(_, totals)| totals.clone())
    }

    fn store(&self, totals: Vec<InboxClassUsage>, now: Instant) {
        *self.totals.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((now, totals));
    }

    /// Count a row that is about to be queued.
    fn note_admitted(&self, class: SenderClass, bytes: i64) {
        let mut totals = self.totals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((_, totals)) = totals.as_mut() else {
            return;
        };
        let class = class.to_string();
        match totals.iter_mut().find(|usage| usage.admission_class == class) {
            Some(usage) => {
                usage.rows += 1;
                usage.bytes += bytes;
            }
            None => totals.push(InboxClassUsage {
                admission_class: class,
                rows: 1,
                bytes,
                ..Default::default()
            }),
        }
    }

    /// Combine cached class totals with fresh per-peer usage.
    async fn usage(
        &self,
        storage: &mut store::localdb::StorageProcessor<'_>,
        from_peer: &str,
        now: Instant,
    ) -> Result<Vec<InboxClassUsage>> {
        let mut usage = match self.fresh(now) {
            Some(totals) => totals,
            None => {
                let totals = storage.engine_inbox_class_totals().await?;
                self.store(totals.clone(), now);
                totals
            }
        };
        for peer in storage.engine_inbox_peer_usage(from_peer).await? {
            match usage.iter_mut().find(|total| total.admission_class == peer.admission_class) {
                Some(total) => {
                    total.peer_rows = peer.peer_rows;
                    total.peer_bytes = peer.peer_bytes;
                }
                None => usage.push(peer),
            }
        }
        Ok(usage)
    }
}

static INBOX_USAGE_CACHE: LazyLock<InboxUsageCache> = LazyLock::new(InboxUsageCache::default);

/// Injectable admission gates.
#[derive(Clone, Copy)]
pub struct AdmissionGates<'a> {
    pub registry: &'a PeerRegistry,
    pub replay_guard: &'a ReplayGuard,
    pub rate_limiter: &'a InboundRateLimiter,
    pub immediate_limiter: &'a PeerRateLimiter,
    pub usage_cache: &'a InboxUsageCache,
    pub limits: &'a InboundLimits,
    /// This node's role. A durable message no handler of this role acts on is
    /// relayed but not stored.
    pub local_actor: &'a bitvm_lib::actors::Actor,
}

impl AdmissionGates<'_> {
    /// Whether this node stores an admitted durable message of `kind`, or only
    /// relays it.
    pub fn keeps(&self, kind: crate::action::MessageKind) -> bool {
        kind.handled_by(self.local_actor)
    }
}

impl<'a> AdmissionGates<'a> {
    /// The process-wide gates the node runs with.
    pub fn global(local_actor: &'a bitvm_lib::actors::Actor) -> Self {
        Self {
            local_actor,
            registry: peer_registry(),
            replay_guard: &REPLAY_GUARD,
            rate_limiter: inbound_rate_limiter(),
            immediate_limiter: immediate_limiter(),
            usage_cache: &INBOX_USAGE_CACHE,
            limits: inbound_limits(),
        }
    }
}

/// One received gossipsub message, as admission sees it.
#[derive(Clone, Copy, Debug)]
pub struct InboundGossip<'a> {
    /// The neighbour that relayed the message to this node.
    pub direct_peer: &'a PeerId,
    /// The signed author.
    pub source: &'a PeerId,
    /// The author's gossipsub sequence number, covered by its signature.
    pub sequence_number: Option<u64>,
    pub data: &'a [u8],
}

/// What to do with one inbound gossipsub message.
pub enum InboundVerdict {
    /// Neither processed nor forwarded.
    Drop(DropReason),
    /// Dispatch now; nothing is persisted.
    Immediate(GOATMessage),
    /// Forward without persistence, dispatch or ACK.
    Forward,
    /// Record as an engine inbox event of its aggregate; the engine
    /// deduplicates by content id.
    Enqueue { message: GOATMessage, class: SenderClass },
}

/// Drop the rejected network events the quota should stop charging for,
/// after `REJECTED_EVENT_TTL_SECS`. The sender's outbox re-sends what still
/// matters; the terminal retention of the engine is for audit, not quota.
pub async fn purge_stale_network_events(local_db: &LocalDB) -> Result<u64> {
    let before = crate::rpc_service::current_time_secs() - REJECTED_EVENT_TTL_SECS;
    let purged = local_db.acquire().await?.purge_rejected_network_inbox_rows(before).await?;
    if purged > 0 {
        tracing::info!(event = "p2p_admission", purged, "rejected network events purged");
    }
    Ok(purged)
}

/// Evaluate admission without swarm or chain access; propagate database errors.
pub async fn evaluate_inbound_message(
    local_db: &LocalDB,
    gates: &AdmissionGates<'_>,
    inbound: &InboundGossip<'_>,
    now: Instant,
) -> Result<InboundVerdict> {
    let InboundGossip { direct_peer, source, sequence_number, data } = *inbound;
    if let Err(reason) = check_envelope(data, gates.registry.is_verifier(source), gates.limits) {
        return Ok(InboundVerdict::Drop(reason));
    }
    // Classification reads only the cache and never blocks.
    let class = gates.registry.sender_class(source, now);
    // Check replay before charging the registered author's rate budget.
    if class.is_registered()
        && let Err(reason) = gates.replay_guard.admit(source, sequence_number, unix_nanos_now())
    {
        return Ok(InboundVerdict::Drop(reason));
    }
    // Apply rate limits before decoding.
    if let Err(reason) =
        gates.rate_limiter.charge(direct_peer, source, class, data.len() as i64, now)
    {
        return Ok(InboundVerdict::Drop(reason));
    }
    let Ok(message) = GOATMessage::deserialize_message(data).await else {
        return Ok(InboundVerdict::Drop(DropReason::Undecodable));
    };
    // Require GenCircuits inside the binary envelope.
    if GOATMessage::is_binary_envelope(data)
        && !matches!(message.content, GOATMessageContent::GenCircuits(_))
    {
        return Ok(InboundVerdict::Drop(DropReason::UnexpectedBinaryKind));
    }
    // A verifier's endorsement of the graph parameters comes from the closed
    // on-chain verifier set; once that set is loaded nobody else gets a
    // committee node to verify one, which costs chain reads.
    if matches!(message.content, GOATMessageContent::VerifierGraphParamsEndorsement(_))
        && gates.registry.verifier_set_loaded()
        && !gates.registry.is_verifier(source)
    {
        return Ok(InboundVerdict::Drop(DropReason::EndorsementFromNonVerifier));
    }

    if message.content.p2p_delivery() == P2PMessageDelivery::Immediate {
        if !gates.immediate_limiter.allow(source, now) {
            return Ok(InboundVerdict::Drop(DropReason::ImmediateRateLimited));
        }
        return Ok(InboundVerdict::Immediate(message));
    }

    // Forward unhandled or unregistered messages within the forwarding budget.
    // Only registered authors enter the durable inbox; registration is learned
    // through NodeInfo and registry checks.
    if !gates.keeps(message.content.kind()) || !class.is_registered() {
        if !class.is_registered()
            && let Err(reason) = gates.rate_limiter.charge_forward(data.len() as i64, now)
        {
            return Ok(InboundVerdict::Drop(reason));
        }
        return Ok(InboundVerdict::Forward);
    }

    let from_peer = source.to_string();
    let mut storage = local_db.acquire().await?;
    let usage = gates.usage_cache.usage(&mut storage, &from_peer, now).await?;
    if let Err(reason) = check_inbox_quota(class, data.len(), &usage, gates.limits) {
        return Ok(InboundVerdict::Drop(reason));
    }
    gates.usage_cache.note_admitted(class, data.len() as i64);
    Ok(InboundVerdict::Enqueue { message, class })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{AggNonceConsensus, InitGraph, sign_init_graph};
    use bitvm_lib::actors::Actor;
    use uuid::Uuid;

    const SMALL: InboundLimits = InboundLimits {
        max_json_bytes: 1024,
        max_binary_bytes: 4096,
        global: Quota { rows: 6, bytes: 6000 },
        committee_reserve: Quota { rows: 0, bytes: 0 },
        registered_peer: Quota { rows: 3, bytes: 5000 },
    };

    fn usage(class: SenderClass, rows: i64, bytes: i64, peer: (i64, i64)) -> InboxClassUsage {
        InboxClassUsage {
            admission_class: class.to_string(),
            rows,
            bytes,
            peer_rows: peer.0,
            peer_bytes: peer.1,
        }
    }

    /// Use isolated gates in tests.
    struct TestGates {
        registry: PeerRegistry,
        replay_guard: ReplayGuard,
        rate_limiter: InboundRateLimiter,
        immediate_limiter: PeerRateLimiter,
        usage_cache: InboxUsageCache,
        local_actor: Actor,
    }

    /// A wall clock comfortably ahead of every sequence number the tests use.
    const WALL_CLOCK: u64 = 1_800_000_000 * 1_000_000_000;

    /// A distinct operator key per `index`. The registry never parses it.
    fn key(index: u32) -> OperatorKey {
        let mut key = [0x11; 32];
        key[..4].copy_from_slice(&index.to_be_bytes());
        key
    }

    impl TestGates {
        fn new(immediate_limiter: PeerRateLimiter) -> Self {
            Self {
                local_actor: Actor::Committee,
                registry: PeerRegistry::default(),
                replay_guard: ReplayGuard::default(),
                rate_limiter: InboundRateLimiter::new(RateLimits::defaults()),
                immediate_limiter,
                usage_cache: InboxUsageCache::default(),
            }
        }

        /// Evaluate `data` as authored and relayed by `source`.
        async fn evaluate(
            &self,
            local_db: &LocalDB,
            limits: &InboundLimits,
            source: &PeerId,
            sequence_number: u64,
            data: &[u8],
            now: Instant,
        ) -> InboundVerdict {
            let gates = AdmissionGates {
                registry: &self.registry,
                replay_guard: &self.replay_guard,
                rate_limiter: &self.rate_limiter,
                immediate_limiter: &self.immediate_limiter,
                usage_cache: &self.usage_cache,
                limits,
                local_actor: &self.local_actor,
            };
            let inbound = InboundGossip {
                direct_peer: source,
                source,
                sequence_number: Some(sequence_number),
                data,
            };
            evaluate_inbound_message(local_db, &gates, &inbound, now).await.unwrap()
        }
    }

    fn test_keypair(seed: u8) -> bitcoin::secp256k1::Keypair {
        bitcoin::secp256k1::Keypair::from_secret_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
    }

    /// A committee round value: a durable message a committee node stores.
    fn committee_vote() -> GOATMessage {
        let keypair = test_keypair(7);
        let digest = bitcoin::secp256k1::Message::from_digest([3; 32]);
        GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
                instance_id: Uuid::new_v4(),
                graph_id: Uuid::new_v4(),
                committee_pubkey: bitcoin::PublicKey::new(keypair.public_key()),
                consensus_hash: [3; 32],
                signature: bitcoin::secp256k1::Secp256k1::new().sign_schnorr(&digest, &keypair),
            }),
        )
    }

    /// A durable message a committee node stores (the tests run as Committee).
    async fn durable_bytes() -> Vec<u8> {
        committee_vote().serialize_message().await.unwrap()
    }

    /// An operator's recruitment: kept by verifiers, relayed by everyone else.
    fn init_graph() -> GOATMessage {
        let keypair = test_keypair(5);
        let init: InitGraph =
            sign_init_graph(Uuid::new_v4(), Uuid::new_v4(), &keypair, PeerId::random().to_bytes());
        GOATMessage::new(Actor::Verifier, GOATMessageContent::InitGraph(init))
    }

    #[test]
    fn envelope_limits_depend_on_the_encoding_and_the_sender() {
        let json = vec![b'{'; 1025];
        assert_eq!(check_envelope(&json, true, &SMALL), Err(DropReason::OversizedJson));
        assert_eq!(check_envelope(&json[..1024], false, &SMALL), Ok(()));

        let mut binary = b"GOATBIN1".to_vec();
        binary.resize(2048, 0);
        assert_eq!(check_envelope(&binary, false, &SMALL), Err(DropReason::BinaryFromNonVerifier));
        assert_eq!(check_envelope(&binary, true, &SMALL), Ok(()), "above the JSON ceiling");
        binary.resize(4097, 0);
        assert_eq!(check_envelope(&binary, true, &SMALL), Err(DropReason::OversizedBinary));
    }

    /// Verify GenCircuits fits the binary transport ceiling.
    #[tokio::test]
    async fn gen_circuits_fits_the_binary_envelope() {
        use crate::action::GenCircuits;
        use bitvm_lib::babe_adapter::{BABE_N_CC, build_setup_package};

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::GenCircuits(GenCircuits {
                instance_id: Uuid::new_v4(),
                graph_id: Uuid::new_v4(),
                verifier_pubkey: bitcoin::PublicKey::new(secret.public_key(&secp)),
                setup_package: build_setup_package(BABE_N_CC).unwrap(),
            }),
        );
        let bytes = message.serialize_message().await.unwrap();
        assert!(GOATMessage::is_binary_envelope(&bytes));
        let limits = InboundLimits::with_queued_bytes(2 << 20, 2 << 30);
        assert!(bytes.len() > limits.max_json_bytes, "GenCircuits is {} bytes", bytes.len());
        assert!(
            bytes.len() * 5 <= limits.max_binary_bytes * 4,
            "GenCircuits is {} bytes, within 20% of the {} byte ceiling",
            bytes.len(),
            limits.max_binary_bytes
        );
        assert_eq!(check_envelope(&bytes, true, &limits), Ok(()));
        assert!(
            (bytes.len() as i64) * 8 <= limits.registered_peer.bytes,
            "a verifier must be able to have several setups queued"
        );
    }

    /// Verify graph-bearing JSON fits the configured verifier-slot capacity.
    #[test]
    fn default_json_ceiling_fits_graphs_with_several_verifier_slots() {
        use bitvm_lib::types::BitvmGcCircuitData;
        use goat::assert_scripts::WireHash;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        // 0xff is the widest byte in JSON's decimal array encoding.
        let slot = BitvmGcCircuitData {
            verifier_pubkey: bitcoin::PublicKey::new(secret.public_key(&secp)),
            final_msg_hashlocks: vec![[0xff; 20]; bitvm_lib::babe_adapter::BABE_M_CC],
            wire_hashes: std::array::from_fn(|_| WireHash {
                true_label_hash: [0xff; 20],
                false_label_hash: [0xff; 20],
            }),
        };
        let slot_len = serde_json::to_vec(&slot).unwrap().len();
        assert!(
            slot_len * 8 <= crate::env::DEFAULT_P2P_MAX_JSON_MESSAGE_BYTES,
            "one GC slot is {slot_len} bytes of JSON"
        );
    }

    #[test]
    fn quota_is_charged_per_sender_and_globally() {
        use SenderClass::{Committee, Registered};

        assert_eq!(check_inbox_quota(Registered, 100, &[], &SMALL), Ok(()));

        // The sender's own rows, in whichever class they were admitted (a
        // committee lookup may complete between two of its messages).
        let own = [usage(Registered, 2, 200, (2, 200)), usage(Committee, 1, 100, (1, 100))];
        assert_eq!(check_inbox_quota(Committee, 100, &own, &SMALL), Err(DropReason::SenderQuota));
        let other = [usage(Registered, 3, 300, (0, 0))];
        assert_eq!(check_inbox_quota(Registered, 100, &other, &SMALL), Ok(()));
        let own_bytes = [usage(Registered, 1, 4950, (1, 4950))];
        assert_eq!(
            check_inbox_quota(Registered, 100, &own_bytes, &SMALL),
            Err(DropReason::SenderQuota)
        );

        // The global ceiling counts every class.
        let full = [usage(Committee, 3, 300, (0, 0)), usage(Registered, 3, 300, (0, 0))];
        assert_eq!(check_inbox_quota(Registered, 100, &full, &SMALL), Err(DropReason::GlobalQuota));
        let heavy = [usage(Registered, 1, 5950, (0, 0))];
        assert_eq!(
            check_inbox_quota(Registered, 100, &heavy, &SMALL),
            Err(DropReason::GlobalQuota)
        );
    }

    #[test]
    fn derived_quotas_nest_inside_the_global_ceiling() {
        let limits = InboundLimits::with_queued_bytes(2 << 20, 2 << 30);
        assert!(limits.registered_peer.bytes < limits.global.bytes);
        assert!(limits.committee_reserve.bytes < limits.global.bytes);
        assert!(limits.registered_peer.rows < limits.global.rows);
        assert!(limits.committee_reserve.rows < limits.global.rows);
        assert!(limits.max_json_bytes as i64 <= limits.registered_peer.bytes);
    }

    #[test]
    fn registry_classifies_from_cache_and_never_blocks() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let (verifier, member, stranger) = (PeerId::random(), PeerId::random(), PeerId::random());

        // Nothing is known yet: everyone is unregistered, and lookups are due.
        assert_eq!(registry.sender_class(&member, now), SenderClass::Unregistered);
        assert_eq!(
            registry.plan_refresh(Some(&member), now),
            RefreshPlan { verifier_set: true, committee_peer: true }
        );
        assert_eq!(
            registry.plan_refresh(Some(&member), now),
            RefreshPlan::default(),
            "a lookup already in flight is not started twice"
        );

        registry.record_verifier_set(Some(vec![verifier.to_bytes()]), now);
        registry.record_committee_peer(&member, Some(true), now);
        assert!(registry.is_verifier(&verifier));
        assert_eq!(registry.sender_class(&verifier, now), SenderClass::Registered);
        assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
        assert!(registry.is_committee(&member, now));
        assert!(!registry.is_committee(&verifier, now), "registered, but not the committee");
        assert_eq!(registry.sender_class(&stranger, now), SenderClass::Unregistered);
        assert_eq!(
            registry.plan_refresh(Some(&verifier), now),
            RefreshPlan::default(),
            "a verifier needs no committee lookup"
        );

        // Past its TTL the member is re-validated but keeps its class meanwhile.
        // The verifier set has aged out by then as well.
        let later = now + COMMITTEE_POSITIVE_TTL;
        assert_eq!(registry.sender_class(&member, later), SenderClass::Committee);
        assert_eq!(
            registry.plan_refresh(Some(&member), later),
            RefreshPlan { verifier_set: true, committee_peer: true }
        );
        registry.record_committee_peer(&member, None, later);
        assert_eq!(
            registry.sender_class(&member, later),
            SenderClass::Committee,
            "a failed lookup leaves the cached answer in place"
        );
        assert_eq!(
            registry.sender_class(&member, now + COMMITTEE_STALE_LIMIT),
            SenderClass::Unregistered,
            "but it is not trusted forever"
        );

        // A failed verifier refresh keeps the previous set and is retried soon,
        // but not on every message.
        registry.record_verifier_set(None, later);
        assert!(registry.is_verifier(&verifier));
        assert!(!registry.plan_refresh(None, later + Duration::from_secs(1)).verifier_set);
        assert!(registry.plan_refresh(None, later + VERIFIER_SET_RETRY_INTERVAL).verifier_set);
    }

    #[test]
    fn unknown_identities_cannot_starve_revalidation_of_known_members() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        registry.record_verifier_set(Some(vec![]), now);
        let member = PeerId::random();
        registry.record_committee_peer(&member, Some(true), now);

        let later = now + COMMITTEE_POSITIVE_TTL;
        let mut started = 0;
        for _ in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
            let stranger = PeerId::random();
            if registry.plan_refresh(Some(&stranger), later).committee_peer {
                started += 1;
                registry.record_committee_peer(&stranger, Some(false), later);
            }
        }
        assert_eq!(started, COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE);
        assert!(
            registry.plan_refresh(Some(&member), later).committee_peer,
            "re-validating a registered peer is not charged to the discovery budget"
        );
    }

    /// Item 5: even with the unknown-lookup slots saturated and in flight, a
    /// known member's re-check must still find a reserved slot.
    #[test]
    fn known_member_recheck_survives_saturated_unknown_lookups() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        registry.record_verifier_set(Some(vec![]), now);
        let member = PeerId::random();
        registry.record_committee_peer(&member, Some(true), now);

        // Fill and hold the unknown-lookup slots (do not resolve them).
        let mut unknown_in_flight = 0;
        for _ in 0..COMMITTEE_MAX_IN_FLIGHT_LOOKUPS * 2 {
            if registry.plan_refresh(Some(&PeerId::random()), now).committee_peer {
                unknown_in_flight += 1;
            }
        }
        assert_eq!(
            unknown_in_flight, COMMITTEE_MAX_UNKNOWN_IN_FLIGHT,
            "unknown lookups are capped below the total, leaving slots reserved"
        );
        let later = now + COMMITTEE_POSITIVE_TTL;
        assert!(
            registry.plan_refresh(Some(&member), later).committee_peer,
            "a known member re-check uses a reserved slot despite the unknown flood"
        );
    }

    /// An operator becomes registered only once its proven binding is confirmed
    /// to be a staked operator, and a key maps to one peer id at a time.
    #[test]
    fn operator_binding_grants_registered_only_after_stake_confirmation() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let peer = PeerId::random();
        let pubkey = &key(1);

        registry.observe_operator_binding(&peer, pubkey, 1);
        assert_eq!(
            registry.sender_class(&peer, now),
            SenderClass::Unregistered,
            "a proven binding alone is not enough; stake is unconfirmed"
        );
        assert!(registry.plan_operator_refresh(&peer, pubkey, now));
        assert!(
            !registry.plan_operator_refresh(&peer, pubkey, now),
            "a lookup already in flight is not started twice"
        );
        registry.record_operator_stake(&peer, pubkey, Some(true), now);
        assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);

        // Verify one key registers only one peer.
        let new_peer = PeerId::random();
        registry.observe_operator_binding(&new_peer, pubkey, 2);
        registry.record_operator_stake(&new_peer, pubkey, Some(true), now);
        assert_eq!(registry.sender_class(&new_peer, now), SenderClass::Registered);
        assert_eq!(
            registry.sender_class(&peer, now),
            SenderClass::Unregistered,
            "the superseded peer id loses the class"
        );

        // An older binding for a key already owned by another peer is ignored.
        registry.observe_operator_binding(&peer, pubkey, 1);
        assert_eq!(registry.sender_class(&peer, now), SenderClass::Unregistered);
    }

    /// The rate budget rejects a flood before decode, charges every tier, and
    /// only debits when all tiers pass.
    #[test]
    fn inbound_rate_budget_bounds_bytes_and_messages_per_tier() {
        const MIB: i64 = 1024 * 1024;
        let limits = RateLimits {
            direct_peer: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 100 * MIB,
                byte_per_sec: 0,
            },
            registered_author: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 100 * MIB,
                byte_per_sec: 0,
            },
            unregistered_author: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 2 * MIB,
                byte_per_sec: 0,
            },
            unregistered_total: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 3 * MIB,
                byte_per_sec: 0,
            },
            unregistered_forward: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 100 * MIB,
                byte_per_sec: 0,
            },
            global: TierRate {
                msg_burst: 100,
                msg_per_sec: 0,
                byte_burst: 100 * MIB,
                byte_per_sec: 0,
            },
            committee_reserve: 0.0,
            max_tracked_peers: 16,
        };
        let limiter = InboundRateLimiter::new(limits);
        let now = Instant::now();
        let relay = PeerId::random();
        use SenderClass::{Registered, Unregistered};

        // One unregistered author is capped at its own 2 MiB byte burst.
        let a = PeerId::random();
        assert!(limiter.charge(&relay, &a, Unregistered, MIB, now).is_ok());
        assert_eq!(
            limiter.charge(&relay, &a, Unregistered, 2 * MIB, now),
            Err(DropReason::AuthorRate),
            "the author's own bucket has only 1 MiB left"
        );

        // Verify distinct unregistered authors share the class byte budget.
        let (b, c, d) = (PeerId::random(), PeerId::random(), PeerId::random());
        assert!(limiter.charge(&relay, &b, Unregistered, MIB, now).is_ok());
        assert!(limiter.charge(&relay, &c, Unregistered, MIB, now).is_ok());
        assert_eq!(
            limiter.charge(&relay, &d, Unregistered, MIB, now),
            Err(DropReason::UnregisteredRate)
        );

        // A registered author is not charged against the unregistered pool, and
        // the messages rejected above did not drain the global tier: a fresh
        // registered author is still admitted up to the global burst.
        let op = PeerId::random();
        assert!(limiter.charge(&relay, &op, Registered, 50 * MIB, now).is_ok());
    }

    #[test]
    fn rate_limiter_refills_and_bounds_its_own_memory() {
        let limiter = PeerRateLimiter::new(2.0, 1.0, 2);
        let now = Instant::now();
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        assert!(limiter.allow(&a, now));
        assert!(limiter.allow(&a, now));
        assert!(!limiter.allow(&a, now), "the burst is spent");
        assert!(limiter.allow(&a, now + Duration::from_secs(1)), "one token per second");

        assert!(limiter.allow(&b, now + Duration::from_secs(1)));
        assert!(
            !limiter.allow(&c, now + Duration::from_secs(1)),
            "no room to track a new peer while the tracked ones are active"
        );
        assert!(
            limiter.allow(&c, now + Duration::from_secs(60)),
            "idle peers are forgotten to make room"
        );
    }

    #[test]
    fn response_gate_coalesces_requests_inside_the_cooldown() {
        let gate = ResponseGate::new(Duration::from_secs(10));
        let now = Instant::now();
        assert!(gate.try_respond(now));
        assert!(!gate.take_pending(now + Duration::from_secs(20)), "nothing was deferred");

        assert!(!gate.try_respond(now + Duration::from_secs(1)));
        assert!(!gate.try_respond(now + Duration::from_secs(2)));
        assert!(!gate.take_pending(now + Duration::from_secs(5)), "still cooling down");
        assert!(gate.take_pending(now + Duration::from_secs(10)), "one response for both");
        assert!(!gate.take_pending(now + Duration::from_secs(30)));
        assert!(gate.try_respond(now + Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn verdicts_follow_the_queue_state() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let source = PeerId::random();
        let limits = InboundLimits { registered_peer: Quota { rows: 1, bytes: 4096 }, ..SMALL };

        let verdict = gates.evaluate(&local_db, &limits, &source, 1, b"not a message", now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::Undecodable)));

        // An unregistered author's durable message is relayed, never stored.
        let first = durable_bytes().await;
        let verdict = gates.evaluate(&local_db, &limits, &source, 2, &first, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward));
        let key = key(1);
        gates.registry.observe_operator_binding(&source, &key, 1);
        gates.registry.record_operator_stake(&source, &key, Some(true), now);
        let verdict = gates.evaluate(&local_db, &limits, &source, 3, &first, now).await;
        let InboundVerdict::Enqueue { class, .. } = verdict else {
            panic!("an empty inbox admits the first message of a registered author");
        };
        assert_eq!(class, SenderClass::Registered);
        // What admission recorded: a queued network event of this author.
        let mut storage = local_db.acquire().await.unwrap();
        storage
            .insert_engine_inbox_event(
                &store::NewEngineInboxEvent {
                    event_id: "first".to_string(),
                    aggregate_kind: "graph".to_string(),
                    aggregate_id: "g".to_string(),
                    kind: "AggNonceConsensus".to_string(),
                    source: "network".to_string(),
                    author: source.to_string(),
                    admission_class: class.to_string(),
                    payload: first.clone(),
                    ack: None,
                },
                1,
            )
            .await
            .unwrap();
        drop(storage);

        // Another payload from the same sender is over its row quota, in
        // whichever class it is admitted.
        let second = durable_bytes().await;
        let verdict = gates.evaluate(&local_db, &limits, &source, 4, &second, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::SenderQuota)));
        gates.registry.record_committee_peer(&source, Some(true), now);
        let verdict = gates.evaluate(&local_db, &limits, &source, 5, &second, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::SenderQuota)));
    }

    /// Verify replay neither passes admission nor consumes rate budget.
    #[tokio::test]
    async fn replayed_registered_messages_are_dropped_before_the_rate_charge() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let member = PeerId::random();
        gates.registry.record_committee_peer(&member, Some(true), now);

        let message = durable_bytes().await;
        let verdict = gates.evaluate(&local_db, &SMALL, &member, 100, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
        for _ in 0..3 {
            let verdict = gates.evaluate(&local_db, &SMALL, &member, 100, &message, now).await;
            assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ReplayedSequence)));
        }

        // Unregistered authors use rate limits rather than replay tracking:
        // the same sequence number relayed twice is not a replay to them.
        let stranger = PeerId::random();
        let other = durable_bytes().await;
        for _ in 0..2 {
            let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 7, &other, now).await;
            assert!(matches!(verdict, InboundVerdict::Forward));
        }
    }

    #[test]
    fn replay_window_tolerates_reordering_but_not_reuse() {
        let guard = ReplayGuard::default();
        let author = PeerId::random();
        let base = 1_000_000;
        assert_eq!(guard.admit(&author, Some(base), WALL_CLOCK), Ok(()));
        assert_eq!(guard.admit(&author, Some(base + 5), WALL_CLOCK), Ok(()));
        assert_eq!(guard.admit(&author, Some(base + 3), WALL_CLOCK), Ok(()), "reordered, but new");
        assert_eq!(
            guard.admit(&author, Some(base + 3), WALL_CLOCK),
            Err(DropReason::ReplayedSequence)
        );
        assert_eq!(
            guard.admit(&author, Some(base + 5), WALL_CLOCK),
            Err(DropReason::ReplayedSequence)
        );
        assert_eq!(guard.admit(&author, None, WALL_CLOCK), Err(DropReason::ReplayedSequence));

        // The author restarts: numbering jumps to the new start-up time, and
        // everything from the previous session falls out of the window.
        let restarted = base + 10 * REPLAY_WINDOW;
        assert_eq!(guard.admit(&author, Some(restarted), WALL_CLOCK), Ok(()));
        assert_eq!(
            guard.admit(&author, Some(base + 4), WALL_CLOCK),
            Err(DropReason::ReplayedSequence)
        );
        assert_eq!(guard.admit(&author, Some(restarted - REPLAY_WINDOW + 1), WALL_CLOCK), Ok(()));
        assert_eq!(
            guard.admit(&author, Some(restarted - REPLAY_WINDOW), WALL_CLOCK),
            Err(DropReason::ReplayedSequence)
        );

        // Windows are per author.
        assert_eq!(guard.admit(&PeerId::random(), Some(base), WALL_CLOCK), Ok(()));
    }

    /// Verify re-announcement preserves stake classification.
    #[test]
    fn reannounced_operator_binding_keeps_its_stake_verdict() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let peer = PeerId::random();
        let pubkey = &key(1);

        registry.observe_operator_binding(&peer, pubkey, 100);
        assert!(registry.plan_operator_refresh(&peer, pubkey, now));
        assert_eq!(registry.record_operator_stake(&peer, pubkey, Some(true), now), Some(true));
        assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);

        registry.observe_operator_binding(&peer, pubkey, 400);
        assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);
        assert!(
            !registry.plan_operator_refresh(&peer, pubkey, now),
            "the verdict is still fresh, so no lookup is due"
        );

        // Keep the newest binding timestamp.
        let usurper = PeerId::random();
        registry.observe_operator_binding(&usurper, pubkey, 300);
        assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);
        assert!(!registry.plan_operator_refresh(&usurper, pubkey, now));

        // Every definite verdict is handed back for persisting, changed or not.
        let later = now + OPERATOR_STAKE_TTL;
        assert!(registry.plan_operator_refresh(&peer, pubkey, later));
        assert_eq!(registry.record_operator_stake(&peer, pubkey, Some(true), later), Some(true));
        assert!(registry.plan_operator_refresh(&peer, pubkey, later + OPERATOR_STAKE_TTL));
        assert_eq!(
            registry.record_operator_stake(&peer, pubkey, Some(false), later + OPERATOR_STAKE_TTL),
            Some(false)
        );
    }

    /// Self-signed operator bindings are free to mint. They may exhaust the
    /// operator discovery budget, but not the committee's, and not the
    /// re-validation of operators already confirmed.
    #[test]
    fn operator_binding_flood_spends_only_the_operator_discovery_budget() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        registry.record_verifier_set(Some(vec![]), now);
        let operator = PeerId::random();
        let real = key(0);
        registry.observe_operator_binding(&operator, &real, 1);
        assert!(registry.plan_operator_refresh(&operator, &real, now));
        registry.record_operator_stake(&operator, &real, Some(true), now);

        let mut started = 0;
        for index in 0..(OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
            let (sybil, sybil_key) = (PeerId::random(), key(index + 1));
            registry.observe_operator_binding(&sybil, &sybil_key, 1);
            if registry.plan_operator_refresh(&sybil, &sybil_key, now) {
                started += 1;
                registry.record_operator_stake(&sybil, &sybil_key, Some(false), now);
            }
        }
        // The real operator's own first lookup took one token of the same budget.
        assert_eq!(started + 1, OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE);

        assert!(
            registry.plan_refresh(Some(&PeerId::random()), now).committee_peer,
            "committee discovery has its own budget"
        );
        let due = registry.plan_due_operator_refreshes(now + OPERATOR_STAKE_TTL);
        assert!(
            due.first().is_some_and(|(peer, _)| *peer == operator),
            "the confirmed operator is re-validated first, outside the spent budget"
        );
    }

    /// Registrations confirmed in an earlier session are trusted at once and are
    /// re-validated as known members, not rediscovered through the budget.
    #[test]
    fn seeded_registrations_are_trusted_and_revalidated_as_known() {
        let registry = PeerRegistry::default();
        // `Instant` cannot be dated before the machine booted; keep clear of it.
        let now = Instant::now() + COMMITTEE_STALE_LIMIT;
        let (member, operator) = (PeerId::random(), PeerId::random());
        registry.seed_verified_committee_peer(&member, now);
        registry.seed_verified_operator(&operator, &key(0), 1, now);
        assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
        assert_eq!(registry.sender_class(&operator, now), SenderClass::Registered);

        // Spend both discovery budgets on strangers.
        registry.record_verifier_set(Some(vec![]), now);
        for index in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
            let stranger = PeerId::random();
            if registry.plan_refresh(Some(&stranger), now).committee_peer {
                registry.record_committee_peer(&stranger, Some(false), now);
            }
            let sybil_key = key(index + 1);
            registry.observe_operator_binding(&stranger, &sybil_key, 1);
            if registry.plan_operator_refresh(&stranger, &sybil_key, now) {
                registry.record_operator_stake(&stranger, &sybil_key, Some(false), now);
            }
        }

        assert_eq!(registry.plan_due_committee_refreshes(now), vec![member]);
        assert!(
            registry.plan_due_operator_refreshes(now).iter().any(|(peer, _)| *peer == operator)
        );
        // Revoke restored registrations after a negative chain answer.
        assert_eq!(registry.record_committee_peer(&member, Some(false), now), Some(false));
        assert_eq!(registry.sender_class(&member, now), SenderClass::Unregistered);
    }

    /// A flood of fresh identities must neither grow the bucket table nor evict
    /// the peers it already tracks: past the cap they share one bucket.
    #[test]
    fn rate_table_is_bounded_and_overflow_identities_share_one_bucket() {
        let tier = TierRate { msg_burst: 2, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
        let roomy =
            TierRate { msg_burst: 1_000, msg_per_sec: 0, byte_burst: 1 << 30, byte_per_sec: 0 };
        let limiter = InboundRateLimiter::new(RateLimits {
            direct_peer: roomy,
            registered_author: roomy,
            unregistered_author: tier,
            unregistered_total: roomy,
            unregistered_forward: roomy,
            global: roomy,
            committee_reserve: 0.0,
            max_tracked_peers: 4,
        });
        let now = Instant::now();
        let relay = PeerId::random();
        use SenderClass::{Registered, Unregistered};

        for _ in 0..4 {
            assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
        }
        // New authors share overflow capacity when the table is full.
        assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
        assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
        for _ in 0..64 {
            assert_eq!(
                limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now),
                Err(DropReason::AuthorRate)
            );
        }
        assert_eq!(limiter.tracked_authors(), 4, "fresh identities do not grow the table");

        // A registered author is bounded by the chain registry and always tracked.
        let member = PeerId::random();
        assert!(limiter.charge(&relay, &member, Registered, 1, now).is_ok());
        assert_eq!(limiter.tracked_authors(), 5);

        // Idle buckets are forgotten, making room for new authors again.
        let later = now + RATE_BUCKET_IDLE_FORGET;
        assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, later).is_ok());
        assert_eq!(limiter.tracked_authors(), 1);
    }

    /// Forgetting an idle bucket must not hand its owner tokens it had spent.
    #[test]
    fn default_tiers_refill_within_the_idle_forget_window() {
        let limits = RateLimits::defaults();
        for tier in [
            limits.direct_peer,
            limits.registered_author,
            limits.unregistered_author,
            limits.unregistered_total,
            limits.unregistered_forward,
            limits.global,
        ] {
            let window = RATE_BUCKET_IDLE_FORGET.as_secs() as i64;
            assert!(i64::from(tier.msg_burst) <= i64::from(tier.msg_per_sec) * window);
            assert!(tier.byte_burst <= tier.byte_per_sec * window);
        }
    }

    /// Verify admissions immediately update cached class totals.
    #[tokio::test]
    async fn cached_class_totals_count_admissions_immediately() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let limits = InboundLimits { global: Quota { rows: 2, bytes: 3000 }, ..SMALL };
        let member = |index: u8| {
            let peer = PeerId::random();
            gates.registry.record_committee_peer(&peer, Some(true), now);
            let _ = index;
            peer
        };

        // Nothing is inserted between evaluations: only the cache can know that
        // two rows are already on their way into the inbox.
        for sequence_number in 0..2 {
            let message = durable_bytes().await;
            let verdict = gates
                .evaluate(&local_db, &limits, &member(0), sequence_number, &message, now)
                .await;
            assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
        }
        let message = durable_bytes().await;
        let verdict = gates.evaluate(&local_db, &limits, &member(1), 9, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::GlobalQuota)));

        // Reload totals after cache expiry.
        let later = now + INBOX_CLASS_TOTALS_TTL;
        let verdict = gates.evaluate(&local_db, &limits, &member(2), 10, &message, later).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
    }

    #[tokio::test]
    async fn binary_envelope_is_reserved_for_gen_circuits_from_verifiers() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let source = PeerId::random();

        // A small message wrapped in the binary envelope: well-formed, but it
        // is not the payload the envelope exists for.
        let message = committee_vote();
        let mut wrapped = b"GOATBIN1".to_vec();
        wrapped.extend(bincode::serialize(&message).unwrap());

        let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &wrapped, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::BinaryFromNonVerifier)));

        gates.registry.record_verifier_set(Some(vec![source.to_bytes()]), now);
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &wrapped, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::UnexpectedBinaryKind)));
    }

    /// A verifier's endorsement of the graph parameters.
    fn verifier_endorsement() -> GOATMessage {
        use crate::action::VerifierGraphParamsEndorsement;
        let keypair = test_keypair(9);
        let digest = bitcoin::secp256k1::Message::from_digest([5; 32]);
        GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
                instance_id: Uuid::new_v4(),
                graph_id: Uuid::new_v4(),
                verifier_pubkey: bitcoin::PublicKey::new(keypair.public_key()),
                verifier_index: 0,
                canonical_graph_params_hash: [5; 32],
                signature: bitcoin::secp256k1::Secp256k1::new().sign_schnorr(&digest, &keypair),
            }),
        )
    }

    #[tokio::test]
    async fn parameter_endorsements_come_from_the_verifier_set_once_it_is_loaded() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let (verifier, stranger) = (PeerId::random(), PeerId::random());
        // The stranger is registered (a committee peer), just not a verifier.
        gates.registry.record_committee_peer(&stranger, Some(true), now);
        let message = verifier_endorsement().serialize_message().await.unwrap();

        // Before the set is known nobody is turned away on it.
        let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 1, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));

        gates.registry.record_verifier_set(Some(vec![verifier.to_bytes()]), now);
        let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 2, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::EndorsementFromNonVerifier)));
        let verdict = gates.evaluate(&local_db, &SMALL, &verifier, 1, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
    }

    #[tokio::test]
    async fn immediate_messages_are_rate_limited_per_sender() {
        use crate::action::NodeInfo;

        let local_db = store::create_local_db("sqlite::memory:").await;
        let gates = TestGates::new(PeerRateLimiter::new(1.0, 0.0, 16));
        let now = Instant::now();
        let source = PeerId::random();
        let request = GOATMessage::new(
            Actor::All,
            GOATMessageContent::RequestNodeInfo(NodeInfo {
                peer_id: source.to_string(),
                actor: "Operator".to_string(),
                goat_addr: String::new(),
                btc_pub_key: String::new(),
                socket_addr: String::new(),
                node_name: String::new(),
                service_fee_rate: 0.0,
                available_peg_btc: "0".to_string(),
                ..Default::default()
            }),
        )
        .serialize_message()
        .await
        .unwrap();

        let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &request, now).await;
        assert!(matches!(verdict, InboundVerdict::Immediate(_)));
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &request, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ImmediateRateLimited)));
        let other = PeerId::random();
        let verdict = gates.evaluate(&local_db, &SMALL, &other, 1, &request, now).await;
        assert!(matches!(verdict, InboundVerdict::Immediate(_)), "limits are per sender");
    }

    /// Verify equivalent key encodings share one operator identity.
    #[test]
    fn operator_identity_ignores_how_the_key_is_spelled() {
        use crate::action::{NodeInfo, sign_node_info_binding, verify_node_info_binding};
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9; 32]).unwrap());
        let compressed = bitcoin::PublicKey::new(keypair.public_key());
        let mut other_parity = compressed.to_string();
        other_parity.replace_range(..2, if other_parity.starts_with("02") { "03" } else { "02" });
        let mut uncompressed = compressed;
        uncompressed.compressed = false;
        let spellings = [
            compressed.to_string(),
            compressed.to_string().to_uppercase(),
            other_parity,
            uncompressed.to_string(),
        ];

        let registry = PeerRegistry::default();
        let now = Instant::now();
        let mut keys = HashSet::new();
        let mut peers = Vec::new();
        for (index, spelling) in spellings.iter().enumerate() {
            let peer = PeerId::random();
            let issued_at = 100 + index as i64;
            let node_info = NodeInfo {
                peer_id: peer.to_string(),
                btc_pub_key: spelling.clone(),
                binding_sig: sign_node_info_binding(
                    &peer.to_string(),
                    spelling,
                    issued_at,
                    &keypair,
                ),
                binding_issued_at: issued_at,
                ..Default::default()
            };
            let verified = verify_node_info_binding(&node_info)
                .unwrap_or_else(|| panic!("{spelling} is a valid spelling of the key"));
            let operator = operator_key(&verified);
            keys.insert(operator);
            registry.observe_operator_binding(&peer, &operator, issued_at);
            if registry.plan_operator_refresh(&peer, &operator, now) {
                registry.record_operator_stake(&peer, &operator, Some(true), now);
            }
            peers.push(peer);
        }
        assert_eq!(keys.len(), 1, "every spelling is the same operator");
        let registered =
            peers.iter().filter(|peer| registry.sender_class(peer, now).is_registered()).count();
        assert_eq!(registered, 1, "one stake backs one peer id, however the key is written");
        assert!(registry.sender_class(peers.last().unwrap(), now).is_registered());
    }

    /// Verify equal timestamps cannot transfer ownership and key changes revoke prior registration.
    #[test]
    fn operator_key_changes_hands_only_forward_and_rebinding_revokes() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let (first, second) = (PeerId::random(), PeerId::random());
        let (staked, unstaked) = (key(1), key(2));

        assert!(!registry.observe_operator_binding(&first, &staked, 100));
        assert!(registry.plan_operator_refresh(&first, &staked, now));
        assert_eq!(registry.record_operator_stake(&first, &staked, Some(true), now), Some(true));

        registry.observe_operator_binding(&second, &staked, 100);
        assert!(registry.sender_class(&first, now).is_registered(), "same issue time: no change");
        assert!(!registry.plan_operator_refresh(&second, &staked, now));

        // Moving to an unstaked key gives up the confirmed one ...
        assert!(registry.observe_operator_binding(&first, &unstaked, 200));
        assert!(!registry.sender_class(&first, now).is_registered());
        // ... and the negative verdict for the new key is still handed back, so
        // the store is cleaned even though nothing "changed" for this binding.
        assert!(registry.plan_operator_refresh(&first, &unstaked, now));
        assert_eq!(
            registry.record_operator_stake(&first, &unstaked, Some(false), now),
            Some(false)
        );
        // A verdict for the key the peer no longer holds is ignored.
        assert_eq!(registry.record_operator_stake(&first, &staked, Some(true), now), None);
    }

    /// A stored confirmation is restored only for the key it was made for.
    #[tokio::test]
    async fn stored_operator_confirmation_is_bound_to_its_key() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let now = Instant::now() + OPERATOR_STAKE_STALE_LIMIT;
        let (kept, rebound, member) = (PeerId::random(), PeerId::random(), PeerId::random());
        let (staked, unstaked) = (key(1), key(2));
        {
            let mut storage = local_db.acquire().await.unwrap();
            for peer in [&kept, &rebound] {
                storage
                    .upsert_p2p_registered_peer(
                        &peer.to_string(),
                        REGISTERED_KIND_OPERATOR,
                        &hex::encode(if peer == &kept { staked } else { key(3) }),
                    )
                    .await
                    .unwrap();
            }
            storage
                .upsert_p2p_registered_peer(&member.to_string(), REGISTERED_KIND_COMMITTEE, "")
                .await
                .unwrap();
        }
        // `rebound` was confirmed for key 3 but now presents a (validly signed)
        // binding for an unstaked key.
        let bindings = HashMap::from([(kept, (staked, 10)), (rebound, (unstaked, 20))]);
        let registry = PeerRegistry::default();
        for (peer, (operator, issued_at)) in &bindings {
            registry.observe_operator_binding(peer, operator, *issued_at);
        }
        let seeded = seed_registry_from_store(&local_db, &registry, &bindings, now).await.unwrap();
        assert_eq!(seeded, 2, "the kept operator and the committee member");
        assert_eq!(registry.sender_class(&kept, now), SenderClass::Registered);
        assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
        assert_eq!(registry.sender_class(&rebound, now), SenderClass::Unregistered);

        // The revocation a re-binding triggers removes the stored row.
        revoke_persisted_operator(&local_db, &rebound).await;
        let stored = local_db.acquire().await.unwrap().load_p2p_registered_peers().await.unwrap();
        assert!(!stored.iter().any(|(peer_id, _, _)| *peer_id == rebound.to_string()));
    }

    #[test]
    fn committee_reserve_is_closed_to_other_senders() {
        use SenderClass::{Committee, Registered};
        let limits = InboundLimits { committee_reserve: Quota { rows: 2, bytes: 2000 }, ..SMALL };

        // Four rows from staked operators fill everything outside the reserve.
        let crowded = [usage(Registered, 4, 400, (0, 0))];
        assert_eq!(
            check_inbox_quota(Registered, 100, &crowded, &limits),
            Err(DropReason::GlobalQuota)
        );
        assert_eq!(check_inbox_quota(Committee, 100, &crowded, &limits), Ok(()));
        // Committee rows do not count against the others' share.
        let committee_heavy = [usage(Committee, 3, 300, (0, 0)), usage(Registered, 2, 200, (0, 0))];
        assert_eq!(check_inbox_quota(Registered, 100, &committee_heavy, &limits), Ok(()));
        // The committee is still bounded by the global ceiling.
        let full = [usage(Committee, 6, 600, (0, 0))];
        assert_eq!(check_inbox_quota(Committee, 100, &full, &limits), Err(DropReason::GlobalQuota));
    }

    /// Verify a full gate rejects new live keys.
    #[test]
    fn gates_and_sets_refuse_new_keys_when_full_of_live_ones() {
        let now = Instant::now();
        let gate = CooldownGate::new(Duration::from_secs(60), 4);
        for index in 0..4 {
            assert!(gate.allow(&format!("key-{index}"), now));
        }
        for index in 4..64 {
            assert!(!gate.allow(&format!("key-{index}"), now + Duration::from_secs(1)));
        }
        assert_eq!(gate.len(), 4);
        assert!(gate.is_cooling("key-0", now + Duration::from_secs(1)));
        assert!(!gate.is_cooling("key-9", now + Duration::from_secs(1)), "never recorded");
        // Expired keys make room again, once the sweep interval has passed.
        assert!(gate.allow("late", now + Duration::from_secs(61)));
        assert_eq!(gate.len(), 1);
    }

    #[test]
    fn global_rate_spends_its_burst_and_refills_at_its_rate() {
        let rate = GlobalRate::new(2.0, 1.0);
        let now = Instant::now();
        assert!(rate.allow(now));
        assert!(rate.allow(now));
        assert!(!rate.allow(now), "the burst is spent");
        assert!(rate.allow(now + Duration::from_secs(1)), "one token per second comes back");
        assert!(!rate.allow(now + Duration::from_secs(1)));
    }

    /// Verify future sequence numbers do not move the window.
    #[test]
    fn future_sequence_numbers_cannot_raise_the_mark() {
        let guard = ReplayGuard::default();
        let author = PeerId::random();
        let ahead = WALL_CLOCK + REPLAY_MAX_FUTURE.as_nanos() as u64;
        assert_eq!(
            guard.admit(&author, Some(ahead + 1), WALL_CLOCK),
            Err(DropReason::FutureSequence)
        );
        assert_eq!(
            guard.admit(&author, Some(ahead - REPLAY_WINDOW), WALL_CLOCK),
            Ok(()),
            "nothing was recorded: the window did not move up to the refused number"
        );
        assert_eq!(guard.admit(&author, Some(ahead), WALL_CLOCK), Ok(()), "inside the tolerance");

        // The corrected clock numbers lower than the mark: refused, and surfaced
        // for the operator once it keeps happening.
        assert!(guard.take_lockout_suspects().is_empty());
        for offset in 0..REPLAY_LOCKOUT_SUSPECT_REJECTIONS as u64 {
            assert_eq!(
                guard.admit(&author, Some(WALL_CLOCK - REPLAY_WINDOW * 2 + offset), WALL_CLOCK),
                Err(DropReason::ReplayedSequence)
            );
        }
        assert_eq!(
            guard.take_lockout_suspects(),
            vec![(author, REPLAY_LOCKOUT_SUSPECT_REJECTIONS)]
        );
        assert!(guard.take_lockout_suspects().is_empty(), "reported once per tick");
    }

    #[test]
    fn direct_peer_is_banned_at_the_strike_limit_and_released_later() {
        let strikes = DirectPeerStrikes::default();
        let now = Instant::now();
        let (flooder, bystander) = (PeerId::random(), PeerId::random());
        for _ in 0..(STRIKE_LIMIT - 1) {
            assert!(!strikes.strike(&flooder, now));
        }
        assert!(!strikes.strike(&bystander, now));
        assert!(strikes.strike(&flooder, now), "the limit is reached exactly once");
        assert!(!strikes.strike(&flooder, now), "already banned");
        assert!(strikes.take_expired_bans(now).is_empty());
        assert_eq!(strikes.take_expired_bans(now + STRIKE_BAN), vec![flooder]);

        // Strikes spread thinner than the window never add up.
        let slow = PeerId::random();
        for round in 0..(STRIKE_LIMIT * 2) {
            assert!(!strikes.strike(&slow, now + STRIKE_WINDOW * round));
        }

        // Only verdicts that do not depend on this node's state are blamed on
        // the neighbour; and an unanswered lookup is not "known unregistered".
        assert!(DropReason::Undecodable.blames_direct_peer());
        assert!(DropReason::UnexpectedBinaryKind.blames_direct_peer());
        for local in [
            DropReason::SenderQuota,
            DropReason::ReplayedSequence,
            // An honest relay earns this one just by being the only neighbour.
            DropReason::DirectPeerRate,
            // The JSON ceiling is configurable, so nodes may disagree on it.
            DropReason::OversizedJson,
            DropReason::BinaryFromNonVerifier,
        ] {
            assert!(!local.blames_direct_peer(), "{local:?} depends on this node");
        }
        assert!(!strikes.is_banned(&bystander, now));
        let banned = PeerId::random();
        for _ in 0..STRIKE_LIMIT {
            strikes.strike(&banned, now);
        }
        assert!(strikes.is_banned(&banned, now), "a ban holds against reconnecting");
        assert!(!strikes.is_banned(&banned, now + STRIKE_BAN));
        let registry = PeerRegistry::default();
        assert!(!registry.is_known_unregistered(&flooder, now));
        registry.record_committee_peer(&flooder, Some(false), now);
        assert!(registry.is_known_unregistered(&flooder, now));
        registry.record_committee_peer(&bystander, Some(true), now);
        assert!(!registry.is_known_unregistered(&bystander, now));
    }

    /// A durable message no handler of this node's role acts on is relayed, but
    /// takes no inbox row and no quota.
    #[tokio::test]
    async fn messages_for_another_role_are_forwarded_without_being_stored() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let now = Instant::now();
        let source = PeerId::random();
        gates.registry.record_committee_peer(&source, Some(true), now);
        let vote = durable_bytes().await;

        gates.local_actor = Actor::Verifier;
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &vote, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward), "a verifier node has no handler");
        gates.local_actor = Actor::Committee;
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &vote, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
    }

    /// Every kind `dispatch` or an aggregate handles is kept by `handled_by`
    /// for the roles that handle it, and relayed for the others.
    #[test]
    fn handled_kinds_follow_the_role_table() {
        use crate::action::MessageKind;

        let roles = [Actor::Committee, Actor::Operator, Actor::Verifier, Actor::Watchtower];
        // Immediate kinds reach every role's dispatch.
        for kind in [
            MessageKind::GraphSetupAck,
            MessageKind::RequestNodeInfo,
            MessageKind::ResponseNodeInfo,
        ] {
            for role in &roles {
                assert!(kind.handled_by(role), "{kind} for {role}");
            }
        }
        // The PeginConfirm round is the committee's.
        for kind in [
            MessageKind::PeginConfirmNonce,
            MessageKind::PeginConfirmNonceConsensus,
            MessageKind::PeginConfirmPartialSig,
        ] {
            assert!(kind.handled_by(&Actor::Committee), "{kind}");
            for role in [Actor::Operator, Actor::Verifier, Actor::Watchtower] {
                assert!(!kind.handled_by(&role), "{kind} for {role}");
            }
        }
        // Graph-phase kinds follow the Graph aggregate's routing table.
        assert!(MessageKind::InitGraph.handled_by(&Actor::Verifier));
        assert!(!MessageKind::InitGraph.handled_by(&Actor::Committee));
        assert!(MessageKind::GraphFinalize.handled_by(&Actor::Watchtower));
    }

    /// Verify committee-only reserves in shared rate tiers.
    #[test]
    fn shared_rate_tiers_keep_a_reserve_for_the_committee() {
        let tier = TierRate { msg_burst: 8, msg_per_sec: 0, byte_burst: 8_000, byte_per_sec: 0 };
        let roomy =
            TierRate { msg_burst: 1_000, msg_per_sec: 0, byte_burst: 1 << 30, byte_per_sec: 0 };
        let limiter = InboundRateLimiter::new(RateLimits {
            direct_peer: roomy,
            registered_author: roomy,
            unregistered_author: roomy,
            unregistered_total: roomy,
            unregistered_forward: roomy,
            global: tier,
            committee_reserve: 0.25,
            max_tracked_peers: 16,
        });
        let now = Instant::now();
        let relay = PeerId::random();
        use SenderClass::{Committee, Registered, Unregistered};

        // Six of eight messages are open to everyone ...
        for _ in 0..6 {
            assert!(limiter.charge(&relay, &PeerId::random(), Registered, 100, now).is_ok());
        }
        assert_eq!(
            limiter.charge(&relay, &PeerId::random(), Registered, 100, now),
            Err(DropReason::GlobalRate)
        );
        assert_eq!(
            limiter.charge(&relay, &PeerId::random(), Unregistered, 100, now),
            Err(DropReason::GlobalRate)
        );
        // ... and the last two only to the committee.
        for _ in 0..2 {
            assert!(limiter.charge(&relay, &PeerId::random(), Committee, 100, now).is_ok());
        }
        assert_eq!(
            limiter.charge(&relay, &PeerId::random(), Committee, 100, now),
            Err(DropReason::GlobalRate)
        );
    }

    /// Verify unregistered forward-only traffic is rate-limited.
    #[tokio::test]
    async fn forwarding_for_unregistered_authors_is_budgeted() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        // A committee node relays the operator's recruitment to verifiers.
        let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let tier = TierRate { msg_burst: 2, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
        gates.rate_limiter = InboundRateLimiter::new(RateLimits {
            unregistered_forward: tier,
            ..RateLimits::defaults()
        });
        let now = Instant::now();

        for sequence_number in 0..2 {
            let data = init_graph().serialize_message().await.unwrap();
            let verdict = gates
                .evaluate(&local_db, &SMALL, &PeerId::random(), sequence_number, &data, now)
                .await;
            assert!(matches!(verdict, InboundVerdict::Forward));
        }
        let data = init_graph().serialize_message().await.unwrap();
        let verdict = gates.evaluate(&local_db, &SMALL, &PeerId::random(), 9, &data, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ForwardRate)));

        let member = PeerId::random();
        gates.registry.record_committee_peer(&member, Some(true), now);
        let verdict = gates.evaluate(&local_db, &SMALL, &member, 1, &data, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward), "registered authors are not charged");
    }

    /// A durable message this role handles is relayed, not stored, while its
    /// author is unregistered; once the author is known it is stored.
    #[tokio::test]
    async fn durable_messages_from_unregistered_authors_are_relayed_not_stored() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
        let tier = TierRate { msg_burst: 1, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
        gates.rate_limiter = InboundRateLimiter::new(RateLimits {
            unregistered_forward: tier,
            ..RateLimits::defaults()
        });
        let now = Instant::now();
        let source = PeerId::random();
        let vote = durable_bytes().await;

        let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &vote, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward));
        // The relay budget is the unregistered one; past it the message is dropped.
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &vote, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ForwardRate)));
        // Nothing was queued for the quota.
        assert!(
            local_db.acquire().await.unwrap().engine_inbox_class_totals().await.unwrap().is_empty()
        );

        gates.registry.record_committee_peer(&source, Some(true), now);
        let verdict = gates.evaluate(&local_db, &SMALL, &source, 3, &vote, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { class: SenderClass::Committee, .. }));
    }

    /// Verify neighbour discovery is independent of author discovery.
    #[test]
    fn neighbour_lookups_have_their_own_budget() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        registry.record_verifier_set(Some(vec![]), now);
        for _ in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
            let author = PeerId::random();
            if registry.plan_refresh(Some(&author), now).committee_peer {
                registry.record_committee_peer(&author, Some(false), now);
            }
        }
        let neighbour = PeerId::random();
        assert!(!registry.plan_refresh(Some(&neighbour), now).committee_peer, "budget spent");
        assert!(registry.plan_neighbour_lookup(&neighbour, now));

        // Verify refused peers cannot consume neighbour discovery budget.
        let mut refused = 0;
        for _ in 0..(REFUSED_PEER_LOOKUPS_PER_MINUTE * 2) {
            let peer = PeerId::random();
            if registry.plan_refused_peer_lookup(&peer, now) {
                refused += 1;
                registry.record_committee_peer(&peer, Some(false), now);
            }
        }
        assert_eq!(refused, REFUSED_PEER_LOOKUPS_PER_MINUTE);
        assert!(registry.plan_neighbour_lookup(&PeerId::random(), now));
    }

    /// Verify committee-only lookup does not claim verifier-set refresh.
    #[test]
    fn neighbour_lookup_does_not_claim_the_verifier_set() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        // The verifier set has never been fetched, so it is due.
        assert!(registry.plan_neighbour_lookup(&PeerId::random(), now));
        assert!(registry.plan_refused_peer_lookup(&PeerId::random(), now));
        assert!(
            registry.plan_refresh(None, now).verifier_set,
            "the verifier set is still there to be claimed by a caller that fetches it"
        );
    }

    /// Verify configured bindings still require confirmed stake.
    #[test]
    fn trusted_operator_binding_needs_the_chain_but_not_the_budget() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        // Spend the operator discovery budget on self-signed bindings.
        for index in 0..(OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
            let (sybil, sybil_key) = (PeerId::random(), key(index + 10));
            registry.observe_operator_binding(&sybil, &sybil_key, 1);
            if registry.plan_operator_refresh(&sybil, &sybil_key, now) {
                registry.record_operator_stake(&sybil, &sybil_key, Some(false), now);
            }
        }
        let (newcomer, newcomer_key) = (PeerId::random(), key(1));
        registry.observe_operator_binding(&newcomer, &newcomer_key, 1);
        assert!(!registry.plan_operator_refresh(&newcomer, &newcomer_key, now), "budget spent");

        let (trusted, trusted_key) = (PeerId::random(), key(2));
        assert_eq!(registry.trust_operator_binding(&trusted, &trusted_key), Ok(()));
        assert!(!registry.sender_class(&trusted, now).is_registered(), "configured is not staked");
        let due = registry.plan_due_operator_refreshes(now);
        assert!(due.contains(&(trusted, trusted_key)), "looked up despite the spent budget");
        assert!(
            due.iter().all(|(_, operator)| *operator == trusted_key),
            "keys the chain said are not staked are not swept again, and the newcomer still \
             has no budget: {} due",
            due.len()
        );
        registry.record_operator_stake(&trusted, &trusted_key, Some(true), now);
        assert_eq!(registry.sender_class(&trusted, now), SenderClass::Registered);

        // The operator's own signed announcement later keeps the verdict ...
        registry.observe_operator_binding(&trusted, &trusted_key, 500);
        assert!(registry.sender_class(&trusted, now).is_registered());
        // ... and if it moves to another peer id, its signature outranks the
        // static configuration.
        let moved = PeerId::random();
        registry.observe_operator_binding(&moved, &trusted_key, 600);
        assert!(!registry.sender_class(&trusted, now).is_registered());
    }

    /// Verify signed bindings take precedence over configuration.
    #[test]
    fn configured_binding_does_not_override_a_signed_one() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let (operator, other_peer) = (PeerId::random(), PeerId::random());
        let (signed_key, configured_key) = (key(1), key(2));

        // Restored from the store: the operator's own signed binding, confirmed.
        registry.seed_verified_operator(&operator, &signed_key, 100, now);
        let now = now + Duration::from_secs(1);
        assert!(registry.sender_class(&operator, now).is_registered());

        // The config still names an older key for that peer ...
        assert_eq!(
            registry.trust_operator_binding(&operator, &configured_key),
            Err(TrustedBindingConflict::PeerBoundToAnotherKey(signed_key))
        );
        // ... or names the operator's key under a peer id it has moved away from.
        assert_eq!(
            registry.trust_operator_binding(&other_peer, &signed_key),
            Err(TrustedBindingConflict::KeyBoundToAnotherPeer(operator))
        );
        assert!(registry.sender_class(&operator, now).is_registered(), "the signed binding stands");
        assert!(!registry.sender_class(&other_peer, now).is_registered());

        // Agreeing with the signed binding keeps its verdict and adds the trust.
        assert_eq!(registry.trust_operator_binding(&operator, &signed_key), Ok(()));
        assert!(registry.sender_class(&operator, now).is_registered());

        // The same peer configured twice with different keys: first one stands.
        let fresh = PeerId::random();
        assert_eq!(registry.trust_operator_binding(&fresh, &key(3)), Ok(()));
        assert_eq!(
            registry.trust_operator_binding(&fresh, &key(4)),
            Err(TrustedBindingConflict::PeerBoundToAnotherKey(key(3)))
        );
    }

    /// Verify clock leads are recorded within and beyond tolerance.
    #[test]
    fn clock_leads_are_reported_per_author_and_then_forgotten() {
        let guard = ReplayGuard::default();
        let (slightly_ahead, far_ahead, on_time) =
            (PeerId::random(), PeerId::random(), PeerId::random());
        let minute = Duration::from_secs(60).as_nanos() as u64;

        assert_eq!(guard.admit(&on_time, Some(WALL_CLOCK - minute), WALL_CLOCK), Ok(()));
        assert_eq!(guard.admit(&slightly_ahead, Some(WALL_CLOCK + 2 * minute), WALL_CLOCK), Ok(()));
        assert_eq!(guard.admit(&slightly_ahead, Some(WALL_CLOCK + 3 * minute), WALL_CLOCK), Ok(()));
        assert_eq!(
            guard.admit(&far_ahead, Some(WALL_CLOCK + 30 * minute), WALL_CLOCK),
            Err(DropReason::FutureSequence)
        );

        let mut leads = guard.take_clock_leads();
        leads.sort_by_key(|(_, lead)| *lead);
        assert_eq!(
            leads,
            vec![
                (slightly_ahead, Duration::from_secs(3 * 60)),
                (far_ahead, Duration::from_secs(30 * 60))
            ],
            "the largest lead per author; an author on time is not listed"
        );
        assert!(guard.take_clock_leads().is_empty());
    }

    /// Verify only successful recovery closes the gate.
    /// A "no" that has gone stale is not grounds for acting against a neighbour.
    #[test]
    fn a_stale_negative_is_not_known_unregistered() {
        let registry = PeerRegistry::default();
        let now = Instant::now();
        let peer = PeerId::random();
        registry.record_committee_peer(&peer, Some(false), now);
        assert!(registry.is_known_unregistered(&peer, now));
        assert!(!registry.is_known_unregistered(&peer, now + COMMITTEE_NEGATIVE_TTL));
    }

    #[test]
    fn trusted_operator_bindings_are_parsed_strictly() {
        use crate::env::parse_trusted_operator_bindings;
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9; 32]).unwrap());
        let pubkey = bitcoin::PublicKey::new(keypair.public_key());
        let xonly = bitcoin::XOnlyPublicKey::from(pubkey).serialize();
        let (first, second) = (PeerId::random(), PeerId::random());
        let value = format!(
            " {first}={pubkey} , not-a-binding, {second} = {} ,{first}=zz,",
            pubkey.to_string().to_uppercase()
        );
        assert_eq!(
            parse_trusted_operator_bindings(&value),
            vec![(first, xonly), (second, xonly)],
            "malformed entries are skipped, and every spelling is the same key"
        );
        assert!(parse_trusted_operator_bindings("").is_empty());
    }
}
