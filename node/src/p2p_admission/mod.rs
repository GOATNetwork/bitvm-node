//! Inbound gossip admission: envelope, identity, replay, rate and storage checks.
//! Durable messages are admitted before persistence and forwarding.
//! Rejected messages use gossipsub `Ignore`.

mod gates;
mod get_graph_budget;
mod limits;
mod maintenance;
mod rate;
mod registry;
mod registry_refresh;
mod replay;
mod strikes;
#[cfg(test)]
mod tests;

use crate::messages::{GOATMessage, GOATMessageContent, P2PMessageDelivery};
use anyhow::Result;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use store::InboxClassUsage;
use store::localdb::LocalDB;

pub use gates::{
    CooldownGate, ResponseGate, node_info_response_gate, node_table_purge_due, peer_timestamp_gate,
};
pub use get_graph_budget::{
    GET_GRAPH_SERVE_SLOTS, get_graph_peer_budget, get_graph_response_budget,
    get_graph_response_gate, get_graph_serve_slots,
};
pub use limits::{InboundLimits, Quota, inbound_limits};
pub use maintenance::{
    NODE_TABLE_EVICTABLE_AFTER_SECS, NODE_TABLE_MAX_UNREGISTERED_ROWS,
    load_persisted_peer_bindings, run_p2p_admission_maintenance,
};
pub use rate::{
    GlobalRate, InboundRateLimiter, PeerRateLimiter, RateLimits, TierRate, immediate_limiter,
    inbound_rate_limiter,
};
pub use registry::{
    OPERATOR_BINDING_LOAD_LIMIT, OperatorKey, PeerRegistry, RefreshPlan, SenderClass,
    TrustedBindingConflict, operator_key, peer_registry,
};
pub use registry_refresh::{
    refresh_due_registrations_in_background, refresh_neighbour_in_background,
    refresh_operator_binding_in_background, refresh_registry_in_background,
    revalidate_committee_candidates, revoke_persisted_operator, seed_registry_from_store,
};
pub use replay::{ReplayGuard, replay_guard, unix_nanos_now};
pub use strikes::{DirectPeerStrikes, direct_peer_strikes, note_refused_peer};

/// How long a rejected network event keeps its inbox row, and so its share
/// of the author's quota, before the maintenance purge removes it.
pub const REJECTED_EVENT_TTL_SECS: i64 = 2 * 60 * 60;

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
    pub fn keeps(&self, kind: crate::messages::MessageKind) -> bool {
        kind.handled_by(self.local_actor)
    }
}

impl<'a> AdmissionGates<'a> {
    /// The process-wide gates the node runs with.
    pub fn global(local_actor: &'a bitvm_lib::actors::Actor) -> Self {
        Self {
            local_actor,
            registry: peer_registry(),
            replay_guard: replay_guard(),
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
    let before = crate::clock::current_time_secs() - REJECTED_EVENT_TTL_SECS;
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
