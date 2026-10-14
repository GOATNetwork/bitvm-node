//! What the Instance and Graph aggregates share: the messages between the
//! network, the applies and the jobs, the membership probe and scan marks.

use super::{graph, instance};
use crate::messages::{BusinessRef, GOATMessage, GOATMessageContent, HasBusinessRef};
use crate::utils::committee_instance_keys_envelope_path;
use bitvm_lib::actors::Actor;
use engine::{ApplyContext, EventSource, NewEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use store::InstanceBridgeInStatus;
use uuid::Uuid;

/// How long a message may wait for a definition that never arrives before
/// it is dropped; the instance deadline normally ends the wait first.
pub const PARKED_MESSAGE_TTL_SECS: i64 = 2 * 24 * 60 * 60;

// ----------------------------------------------------------------- messages

/// A network message handed to the aggregate: the raw wire bytes plus the
/// identity the admission layer already decoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundMessage {
    pub author: String,
    pub instance_id: Uuid,
    pub graph_nonce: Option<u64>,
    pub operator_pubkey: Option<String>,
    pub message: Vec<u8>,
}

impl InboundMessage {
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }
}

/// A message the apply writes to the outbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedMessage {
    pub outbox_id: String,
    pub phase_ref: String,
    pub kind: String,
    /// Target role topic.
    pub actor: String,
    pub payload: Vec<u8>,
    /// Heavy message: recipient peer id -> delivery id.
    pub ack_set: Option<BTreeMap<String, String>>,
}

/// A follow-up job the apply enqueues once the plan is committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextJob {
    pub action: String,
    pub params: Vec<u8>,
    pub delay_secs: Option<i64>,
}

/// Delivery id of a heavy message: `H("goat/graph-setup-delivery/v2", sender,
/// recipient, SHA-256(payload))`, the same on both ends.
pub fn delivery_id(sender_peer: &str, recipient_peer: &str, payload: &[u8]) -> String {
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();
    let mut hasher = Sha256::new();
    hasher.update(b"goat/graph-setup-delivery/v2");
    for field in [sender_peer.as_bytes(), recipient_peer.as_bytes(), payload_hash.as_slice()] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("graph-setup-v2:{}", hex::encode(hasher.finalize()))
}

/// Content id of a network message: `H(author ‖ kind ‖ business_ref ‖ H(payload))`.
pub fn content_event_id(author: &str, kind: &str, business: &str, payload: &[u8]) -> String {
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();
    let mut hasher = Sha256::new();
    for field in [author.as_bytes(), kind.as_bytes(), business.as_bytes(), payload_hash.as_slice()]
    {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("msg:{kind}:{}", hex::encode(hasher.finalize()))
}

/// The inbox event for an admitted network message: a graph-phase message
/// for the Graph aggregate, a PeginConfirm round message for the Instance
/// aggregate, or `None` when this role takes the kind through neither.
pub fn inbound_event(
    actor: &Actor,
    author: &str,
    local_peer: &str,
    decoded: &GOATMessage,
    raw: &[u8],
) -> anyhow::Result<Option<NewEvent>> {
    let kind = decoded.content.event_type();
    let business = decoded.content.business_ref();
    let (BusinessRef::Graph { instance_id, .. } | BusinessRef::Instance { instance_id }) = business
    else {
        return Ok(None);
    };
    let (aggregate, business_id, ack) = match business {
        BusinessRef::Graph { graph_id, .. } if graph::engine_handles(kind, actor) => (
            graph::graph_ref(graph_id),
            format!("{instance_id}:{graph_id}"),
            graph::ack_required(kind),
        ),
        BusinessRef::Instance { .. } if instance::engine_handles(kind, actor) => {
            (instance::instance_ref(instance_id), instance_id.to_string(), false)
        }
        _ => return Ok(None),
    };
    let (graph_nonce, operator_pubkey) = match &decoded.content {
        GOATMessageContent::CreateGraph(message) => {
            (Some(message.graph_nonce), Some(message.graph.parameters.operator_pubkey.to_string()))
        }
        GOATMessageContent::GraphFinalize(message) => {
            (Some(message.graph_nonce), Some(message.graph.parameters.operator_pubkey.to_string()))
        }
        GOATMessageContent::InitGraph(message) => (None, Some(message.operator_pubkey.to_string())),
        _ => (None, None),
    };
    let inbound = InboundMessage {
        author: author.to_string(),
        instance_id,
        graph_nonce,
        operator_pubkey,
        message: raw.to_vec(),
    };
    let mut event = NewEvent::new(
        content_event_id(author, kind, &business_id, raw),
        aggregate,
        kind,
        EventSource::Network,
        inbound.encode()?,
    )
    .with_author(author);
    if ack {
        event = event.with_ack(author, delivery_id(author, local_peer, raw));
    }
    Ok(Some(event))
}

// --------------------------------------------------------------- membership

/// Whether this committee node holds the key of an instance, which is what
/// makes the instance's graph messages its business. A cheap local check for
/// the apply; the jobs verify membership against Goat.
pub trait MembershipProbe: Send + Sync {
    fn holds_instance_key(&self, instance_id: Uuid) -> bool;

    /// Whether the author of a message is a peer the registry holds as
    /// registered on chain. A parked message from anyone else waits for the
    /// definition to arrive by itself: no GetGraph pull is spent on it.
    fn is_registered_peer(&self, _peer: &str) -> bool {
        true
    }
}

/// The instance key envelope on disk, and the peer registry.
pub struct EnvelopeProbe;

impl MembershipProbe for EnvelopeProbe {
    fn holds_instance_key(&self, instance_id: Uuid) -> bool {
        committee_instance_keys_envelope_path(instance_id).exists()
    }

    fn is_registered_peer(&self, peer: &str) -> bool {
        libp2p::PeerId::from_str(peer).is_ok_and(|peer| {
            crate::p2p_admission::peer_registry()
                .sender_class(&peer, std::time::Instant::now())
                .is_registered()
        })
    }
}

/// The instance is in a failure state; an unknown instance is not.
pub(super) async fn instance_failed(
    ctx: &mut ApplyContext<'_>,
    instance_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(ctx
        .storage
        .find_instance(&instance_id)
        .await?
        .and_then(|instance| InstanceBridgeInStatus::from_str(&instance.status).ok())
        .is_some_and(|status| status.is_failed()))
}

// -------------------------------------------------------------------- scans

/// `(height, status)` of the last scan recorded per id: a scan at the same
/// tip for the same status would repeat the same facts.
pub(super) struct ScanMarks<S> {
    marks: Mutex<HashMap<Uuid, (i64, S)>>,
}

impl<S: PartialEq> ScanMarks<S> {
    /// Marks kept before the table is started over.
    const LIMIT: usize = 50_000;

    pub(super) fn new() -> Self {
        Self { marks: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, (i64, S)>> {
        self.marks.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn seen(&self, id: Uuid, height: i64, status: S) -> bool {
        self.lock().get(&id).is_some_and(|mark| *mark == (height, status))
    }

    pub(super) fn mark(&self, id: Uuid, height: i64, status: S) {
        let mut marks = self.lock();
        if marks.len() >= Self::LIMIT {
            marks.clear();
        }
        marks.insert(id, (height, status));
    }

    pub(super) fn forget(&self, id: Uuid) {
        self.lock().remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_and_content_ids_are_stable_and_bound() {
        let a = delivery_id("peer-a", "peer-b", b"payload");
        assert_eq!(a, delivery_id("peer-a", "peer-b", b"payload"));
        assert_ne!(a, delivery_id("peer-b", "peer-a", b"payload"));
        assert_ne!(a, delivery_id("peer-a", "peer-b", b"other"));
        assert!(a.starts_with("graph-setup-v2:"));
        let c = content_event_id("peer-a", "CreateGraph", "i:g", b"payload");
        assert_eq!(c, content_event_id("peer-a", "CreateGraph", "i:g", b"payload"));
        assert_ne!(c, content_event_id("peer-b", "CreateGraph", "i:g", b"payload"));
        assert_ne!(c, content_event_id("peer-a", "GraphFinalize", "i:g", b"payload"));
    }

    #[test]
    fn scan_marks_remember_one_tip_per_id() {
        let marks = ScanMarks::new();
        let id = Uuid::nil();
        assert!(!marks.seen(id, 10, 1));
        marks.mark(id, 10, 1);
        assert!(marks.seen(id, 10, 1));
        assert!(!marks.seen(id, 11, 1) && !marks.seen(id, 10, 2));
        marks.forget(id);
        assert!(!marks.seen(id, 10, 1));
    }
}
