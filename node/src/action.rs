//! Wire messages of the node and the gossip entry point: the envelope, the
//! message kinds and their routing table, admission of an inbound gossip
//! message into the engine inbox or the control queue, and the single
//! publish function every sender goes through.

use crate::aggregates::graph::inbound_event;
use crate::handle::{HandlerContext, dispatch as handle_dispatch};
use crate::metrics_service::MetricsState;
use crate::middleware::AllBehaviours;
use crate::middleware::publisher::MessagePublisher;
use crate::rpc_service::current_time_secs;
use crate::utils::*;
use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::CACSetupPackage;
use bitvm_lib::committee::*;
use bitvm_lib::types::SimplifiedBitvmGcGraph;
use client::goat_chain::GOATClient;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm, gossipsub};
use musig2::{PartialSignature, PubNonce};
use node_macros::MessageBusinessRef;
use secp256k1::{
    Keypair, Message as SecpMessage, SECP256K1, schnorr::Signature as SchnorrSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::LocalDB;
use strum::{Display, EnumDiscriminants, EnumIter, IntoStaticStr};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: GOATMessageContent,
}

const GOAT_MESSAGE_BIN_PREFIX: &[u8] = b"GOATBIN1";
/// A `node` row of an unregistered peer may be evicted to make room for a new
/// one once it has gone this long without a refresh: three missed heartbeats.
pub const NODE_TABLE_EVICTABLE_AFTER_SECS: i64 = 3 * crate::env::HEARTBEAT_INTERVAL_SECOND as i64;
/// Maximum unregistered node rows.
pub const NODE_TABLE_MAX_UNREGISTERED_ROWS: i64 = 4_096;
/// A `node` row of a peer that is not registered is deleted once it has not been
/// refreshed for this long; live nodes refresh theirs on every heartbeat.
const NODE_TABLE_STALE_SECS: i64 = 7 * 24 * 60 * 60;
const NODE_TABLE_PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Maximum accepted binding timestamp lead.
pub const NODE_INFO_BINDING_MAX_FUTURE_SECS: i64 = 10 * 60;
/// Budget of one control message (NodeInfo, ACK): they touch the registry and
/// the engine outbox only.
const IMMEDIATE_DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Delivery semantics for externally received P2P messages.
///
/// Durable messages are recorded as engine inbox events of their aggregate.
/// Immediate messages carry recoverable peer state or ACKs and can be resent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2PMessageDelivery {
    Inbox,
    Immediate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BusinessRef {
    Instance { instance_id: Uuid },
    Graph { instance_id: Uuid, graph_id: Uuid },
    Unscoped,
}

pub trait HasBusinessRef {
    fn business_ref(&self) -> BusinessRef;
}

#[derive(Serialize, Deserialize, Clone, EnumDiscriminants, MessageBusinessRef)]
#[strum_discriminants(name(MessageKind))]
#[strum_discriminants(derive(Display, EnumIter, IntoStaticStr))]
pub enum GOATMessageContent {
    #[business_ref(graph)]
    CreateGraph(CreateGraph),
    #[business_ref(graph)]
    InitGraph(InitGraph),
    #[business_ref(graph)]
    GenCircuits(GenCircuits),
    #[business_ref(graph)]
    CutCircuits(CutCircuits),
    #[business_ref(graph)]
    SolderingProofReady(SolderingProofReady),
    #[business_ref(unscoped)]
    GraphSetupAck(GraphSetupAck),
    #[business_ref(graph)]
    VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement),
    #[business_ref(graph)]
    NonceGeneration(NonceGeneration),
    #[business_ref(graph)]
    AggNonceConsensus(AggNonceConsensus),
    #[business_ref(graph)]
    CommitteePresign(CommitteePresign),
    #[business_ref(graph)]
    EndorseGraph(EndorseGraph),
    #[business_ref(graph)]
    GraphFinalize(GraphFinalize),
    #[business_ref(instance)]
    PeginConfirmNonce(PeginConfirmNonce),
    #[business_ref(instance)]
    PeginConfirmNonceConsensus(PeginConfirmNonceConsensus),
    #[business_ref(instance)]
    PeginConfirmPartialSig(PeginConfirmPartialSig),
    #[business_ref(unscoped)]
    RequestNodeInfo(NodeInfo),
    #[business_ref(unscoped)]
    ResponseNodeInfo(NodeInfo),
}

impl MessageKind {
    /// Receiver roles that take the kind: the control dispatcher for the
    /// immediate kinds, the Graph aggregate (`aggregates::graph::route_action`)
    /// for the graph phases, the Instance aggregate
    /// (`aggregates::instance::route_action`) for the PeginConfirm round.
    pub fn handled_by(self, actor: &Actor) -> bool {
        match self {
            Self::GraphSetupAck | Self::RequestNodeInfo | Self::ResponseNodeInfo => true,
            Self::InitGraph
            | Self::GenCircuits
            | Self::CutCircuits
            | Self::SolderingProofReady
            | Self::CreateGraph
            | Self::VerifierGraphParamsEndorsement
            | Self::NonceGeneration
            | Self::AggNonceConsensus
            | Self::CommitteePresign
            | Self::EndorseGraph
            | Self::GraphFinalize => {
                let kind: &'static str = self.into();
                crate::aggregates::graph::engine_handles(kind, actor)
            }
            Self::PeginConfirmNonce
            | Self::PeginConfirmNonceConsensus
            | Self::PeginConfirmPartialSig => {
                let kind: &'static str = self.into();
                crate::aggregates::instance::engine_handles(kind, actor)
            }
        }
    }
}

impl GOATMessageContent {
    pub fn kind(&self) -> MessageKind {
        self.into()
    }

    /// New messages default to the durable inbox and must explicitly opt into
    /// immediate processing when they are safe to drop.
    pub const fn p2p_delivery(&self) -> P2PMessageDelivery {
        match self {
            Self::RequestNodeInfo(_) | Self::ResponseNodeInfo(_) | Self::GraphSetupAck(_) => {
                P2PMessageDelivery::Immediate
            }
            _ => P2PMessageDelivery::Inbox,
        }
    }

    /// Stable message name for logs/metrics. Keep this independent of `Debug`, whose
    /// output can include protocol payloads (and, for proofs, be very large).
    pub fn event_type(&self) -> &'static str {
        self.kind().into()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InitGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_pubkey: PublicKey,
    pub operator_peer_id: Vec<u8>,
    pub signature: SchnorrSignature,
}

const INIT_GRAPH_SIGNATURE_DOMAIN: &[u8] = b"bitvm2-node/init-graph/v1";

fn init_graph_signature_message(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_pubkey: &PublicKey,
    operator_peer_id: &[u8],
) -> SecpMessage {
    let mut hasher = Sha256::new();
    hasher.update(INIT_GRAPH_SIGNATURE_DOMAIN);
    hasher.update(instance_id.as_bytes());
    hasher.update(graph_id.as_bytes());
    hasher.update(operator_pubkey.to_bytes());
    hasher.update((operator_peer_id.len() as u32).to_be_bytes());
    hasher.update(operator_peer_id);
    SecpMessage::from_digest(hasher.finalize().into())
}

pub fn sign_init_graph(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_keypair: &Keypair,
    operator_peer_id: Vec<u8>,
) -> InitGraph {
    let operator_pubkey = operator_keypair.public_key().into();
    let signature = SECP256K1.sign_schnorr(
        &init_graph_signature_message(instance_id, graph_id, &operator_pubkey, &operator_peer_id),
        operator_keypair,
    );
    InitGraph { instance_id, graph_id, operator_pubkey, operator_peer_id, signature }
}

pub fn verify_init_graph_signature(message: &InitGraph) -> bool {
    SECP256K1
        .verify_schnorr(
            &message.signature,
            &init_graph_signature_message(
                message.instance_id,
                message.graph_id,
                &message.operator_pubkey,
                &message.operator_peer_id,
            ),
            &XOnlyPublicKey::from(message.operator_pubkey),
        )
        .is_ok()
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GenCircuits {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub setup_package: CACSetupPackage,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CutCircuits {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub candidate_index: usize,
    pub selected_circuit_indexes: Vec<usize>,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SolderingProofReady {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub candidate_index: usize,
    pub payload_hash: [u8; 32],
    pub total_len: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphSetupAck {
    pub delivery_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifierGraphParamsEndorsement {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub verifier_pubkey: PublicKey,
    pub verifier_index: usize,
    pub canonical_graph_params_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvmGcGraph,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NonceGeneration {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonces: CommitteePubNonces,
    pub nonce_sigs: CommitteeNonceSignatures,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct AggNonceConsensus {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub consensus_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CommitteePresign {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_partial_sigs: CommitteePartialSignatures,
    pub agg_nonces: CommitteeAggNonces,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct EndorseGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub committee_evm_address: EvmAddress,
    pub committee_sig_for_graph: Vec<u8>, // ECDSA signature signed with committee evm keypair
    pub committee_sig_for_params: Vec<u8>, // ECDSA signature over canonical_graph_params_hash
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GraphFinalize {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub graph: SimplifiedBitvmGcGraph,
    pub endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
    pub params_endorse_sigs: Vec<(PublicKey, EvmAddress, Vec<u8>)>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonce {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub pub_nonce: PubNonce,
    pub nonce_sig: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmNonceConsensus {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub consensus_hash: [u8; 32],
    pub signature: SchnorrSignature,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PeginConfirmPartialSig {
    pub instance_id: Uuid,
    pub committee_pubkey: PublicKey,
    pub partial_sig: PartialSignature,
    pub endorse_sig: Vec<u8>, // ECDSA signature signed with committee evm keypair
}
/// Others

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct NodeInfo {
    pub peer_id: String,
    pub actor: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub node_name: String,
    pub service_fee_rate: f64,
    pub available_peg_btc: String,
    /// Hex master-key Schnorr signature over peer ID, public key and issuance time.
    #[serde(default)]
    pub binding_sig: String,
    /// Unix seconds when the binding was signed. Orders re-bindings so one key
    /// maps to a single peer id at a time.
    #[serde(default)]
    pub binding_issued_at: i64,
}

const NODE_INFO_BINDING_DOMAIN: &[u8] = b"bitvm2-node/node-info-binding/v1";

fn node_info_binding_message(peer_id: &str, btc_pub_key: &str, issued_at: i64) -> SecpMessage {
    let mut hasher = Sha256::new();
    hasher.update(NODE_INFO_BINDING_DOMAIN);
    hasher.update((peer_id.len() as u32).to_be_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.update((btc_pub_key.len() as u32).to_be_bytes());
    hasher.update(btc_pub_key.as_bytes());
    hasher.update(issued_at.to_be_bytes());
    SecpMessage::from_digest(hasher.finalize().into())
}

/// Sign the binding that proves `master_keypair`'s key authorised `peer_id`.
pub fn sign_node_info_binding(
    peer_id: &str,
    btc_pub_key: &str,
    issued_at: i64,
    master_keypair: &Keypair,
) -> String {
    let signature = SECP256K1
        .sign_schnorr(&node_info_binding_message(peer_id, btc_pub_key, issued_at), master_keypair);
    hex::encode(signature.serialize())
}

/// Verify the NodeInfo binding and return its parsed public key.
pub fn verify_node_info_binding(node_info: &NodeInfo) -> Option<XOnlyPublicKey> {
    if node_info.binding_sig.is_empty() {
        return None;
    }
    let pubkey = PublicKey::from_str(&node_info.btc_pub_key).ok()?;
    let xonly = XOnlyPublicKey::from(pubkey);
    let signature_bytes = hex::decode(&node_info.binding_sig).ok()?;
    let signature = SchnorrSignature::from_slice(&signature_bytes).ok()?;
    SECP256K1
        .verify_schnorr(
            &signature,
            &node_info_binding_message(
                &node_info.peer_id,
                &node_info.btc_pub_key,
                node_info.binding_issued_at,
            ),
            &xonly,
        )
        .ok()
        .map(|()| xonly)
}

impl GOATMessage {
    pub fn new(actor: Actor, content: GOATMessageContent) -> Self {
        Self { actor, content }
    }

    pub fn content(&self) -> &GOATMessageContent {
        &self.content
    }

    pub async fn serialize_message(&self) -> Result<Vec<u8>> {
        let cloned = self.clone();
        tokio::task::spawn_blocking(move || {
            if matches!(&cloned.content, GOATMessageContent::GenCircuits(_)) {
                let mut encoded = bincode::serialize(&cloned)
                    .context("failed to serialize bincode GOATMessage")?;
                let mut message = Vec::with_capacity(GOAT_MESSAGE_BIN_PREFIX.len() + encoded.len());
                message.extend_from_slice(GOAT_MESSAGE_BIN_PREFIX);
                message.append(&mut encoded);
                Ok(message)
            } else {
                serde_json::to_vec(&cloned).context("failed to serialize legacy JSON GOATMessage")
            }
        })
        .await?
    }

    /// Whether `message` uses the bincode envelope, which only `GenCircuits` does.
    pub fn is_binary_envelope(message: &[u8]) -> bool {
        message.starts_with(GOAT_MESSAGE_BIN_PREFIX)
    }

    pub async fn deserialize_message(message: &[u8]) -> Result<GOATMessage> {
        let cloned = message.to_vec();
        tokio::task::spawn_blocking(move || {
            if let Some(encoded) = cloned.strip_prefix(GOAT_MESSAGE_BIN_PREFIX) {
                bincode::deserialize(encoded).context("failed to deserialize bincode GOATMessage")
            } else {
                serde_json::from_slice(&cloned)
                    .context("failed to deserialize legacy JSON GOATMessage")
            }
        })
        .await?
    }
}

/// Report exactly one forwarding verdict for each received gossipsub message.
fn report_gossip_validation(
    swarm: &mut Swarm<AllBehaviours>,
    id: &MessageId,
    propagation_source: &PeerId,
    acceptance: gossipsub::MessageAcceptance,
) {
    let cached = swarm.behaviour_mut().gossipsub.report_message_validation_result(
        id,
        propagation_source,
        acceptance,
    );
    if !cached {
        tracing::debug!(
            event = "p2p_message",
            outcome = "validation_report_missed",
            message_id = %hex::encode(&id.0),
            "gossipsub had already evicted the message awaiting validation"
        );
    }
}

/// Apply admission before routing; a dropped message is not an error.
#[allow(clippy::too_many_arguments)]
pub async fn handle_inbound_p2p_message(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    actor: Actor,
    from_peer_id: PeerId,
    propagation_source: PeerId,
    sequence_number: Option<u64>,
    id: MessageId,
    message: &[u8],
    metrics_state: &MetricsState,
    worker: &crate::p2p_msg_handler::WorkerControl,
) -> Result<()> {
    use crate::p2p_admission::{self, InboundVerdict};
    use gossipsub::MessageAcceptance;

    let now = Instant::now();
    let verdict = p2p_admission::evaluate_inbound_message(
        local_db,
        &p2p_admission::AdmissionGates::global(&actor),
        &p2p_admission::InboundGossip {
            direct_peer: &propagation_source,
            source: &from_peer_id,
            sequence_number,
            data: message,
        },
        now,
    )
    .await;
    let verdict = match verdict {
        Ok(verdict) => verdict,
        Err(error) => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Ignore);
            return Err(error).context("evaluate inbound P2P message admission");
        }
    };

    match verdict {
        InboundVerdict::Drop(reason) => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Ignore);
            if reason.blames_direct_peer() {
                strike_direct_peer(swarm, local_db, goat_client, propagation_source, now);
            }
            if reason == p2p_admission::DropReason::Undecodable {
                metrics_state.record_p2p_receive(false);
            } else if reason.after_decode() {
                metrics_state.record_p2p_receive(true);
            }
            p2p_admission::record_drop(reason);
            Ok(())
        }
        // Forward messages for other roles without persistence or ACK.
        InboundVerdict::Forward => {
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            Ok(())
        }
        // Record durable messages before allowing forwarding: graph-phase
        // messages for the Graph aggregate, PeginConfirm round messages for
        // the Instance aggregate. The engine deduplicates by content id and
        // ACKs heavy messages once they are durably applied.
        InboundVerdict::Enqueue { message: decoded, class } => {
            let author = from_peer_id.to_string();
            let event =
                match inbound_event(&actor, &author, &crate::env::get_peer_id(), &decoded, message)
                {
                    Ok(Some(event)) => Ok(Some(event)),
                    Ok(None) => crate::aggregates::instance::inbound_event(
                        &actor, &author, &decoded, message,
                    ),
                    Err(error) => Err(error),
                };
            let recorded = match event {
                Ok(Some(event)) => {
                    record_engine_message(
                        local_db,
                        event.with_admission_class(class.to_string()),
                        &decoded,
                        from_peer_id,
                        message.len(),
                    )
                    .await
                }
                // Kept by `handled_by` but routed by no aggregate: a table
                // mismatch, not a bad message.
                Ok(None) => Err(anyhow::anyhow!(
                    "{} is handled by {actor} but no aggregate routes it",
                    decoded.content.event_type()
                )),
                Err(error) => Err(error),
            };
            if let Err(error) = recorded {
                report_gossip_validation(
                    swarm,
                    &id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                return Err(error);
            }
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            Ok(())
        }
        InboundVerdict::Immediate(decoded) => {
            if !worker.enqueue(from_peer_id, decoded, message.len()) {
                report_gossip_validation(
                    swarm,
                    &id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                p2p_admission::record_drop(p2p_admission::DropReason::ControlQueueFull);
                return Ok(());
            }
            report_gossip_validation(swarm, &id, &propagation_source, MessageAcceptance::Accept);
            metrics_state.record_p2p_receive(true);
            refresh_peer_timestamp_throttled(local_db, from_peer_id, now).await;
            Ok(())
        }
    }
}

/// Dispatch a control message (NodeInfo, ACK) on the control worker.
pub(crate) async fn dispatch_immediate_message(
    publisher: &mut (dyn MessagePublisher + Sync),
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    from_peer_id: PeerId,
    message: GOATMessage,
    metrics_state: &MetricsState,
) -> Result<()> {
    let message_type = message.content.event_type();
    let started_at = Instant::now();
    let mut handler_ctx = HandlerContext { publisher, local_db, goat_client, from_peer_id };
    let result = match tokio::time::timeout(
        IMMEDIATE_DISPATCH_TIMEOUT,
        handle_dispatch(&mut handler_ctx, message.content()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("control message exceeded its dispatch budget")),
    };
    metrics_state
        .record_message_dispatch(message_type, if result.is_ok() { "success" } else { "failed" });
    match &result {
        Ok(()) => tracing::debug!(
            event = "message_dispatch_result",
            outcome = "handled",
            message_type,
            from_peer_id = %from_peer_id,
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            "control message dispatched"
        ),
        Err(err) => tracing::warn!(
            event = "message_dispatch_result",
            outcome = "failed",
            message_type,
            from_peer_id = %from_peer_id,
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            error = %err,
            "control message dispatch failed"
        ),
    }
    result
}

/// Count relay strikes and temporarily ban repeat offenders.
/// Registered peers and peers with unresolved registration are exempt.
fn strike_direct_peer(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    direct_peer: PeerId,
    now: Instant,
) {
    let registry = crate::p2p_admission::peer_registry();
    if !registry.is_known_unregistered(&direct_peer, now) {
        crate::p2p_admission::refresh_neighbour_in_background(local_db, goat_client, direct_peer);
        return;
    }
    if !crate::p2p_admission::direct_peer_strikes().strike(&direct_peer, now) {
        return;
    }
    // The strike table now lists the peer as banned, and the connection gate
    // consults it for every connection: closing this one is all that is left.
    let _ = swarm.disconnect_peer_id(direct_peer);
    tracing::warn!(
        event = "p2p_admission",
        outcome = "direct_peer_banned",
        peer_id = %direct_peer,
        "temporarily ignoring a neighbour that keeps relaying invalid messages"
    );
}

/// Refresh peer liveness at most once per cooldown.
async fn refresh_peer_timestamp_throttled(local_db: &LocalDB, from_peer_id: PeerId, now: Instant) {
    let peer = from_peer_id.to_string();
    if !crate::p2p_admission::peer_timestamp_gate().allow(&peer, now) {
        return;
    }
    if let Err(error) = update_node_timestamp(local_db, &peer).await {
        tracing::debug!(
            event = "p2p_message",
            outcome = "peer_timestamp_update_failed",
            from_peer_id = %peer,
            error = %error,
            "failed to refresh peer liveness timestamp"
        );
    }
}

/// Record an admitted durable message as an inbox event of its aggregate.
/// The engine deduplicates by content id and ACKs a heavy message again when
/// its material is already applied or parked.
async fn record_engine_message(
    local_db: &LocalDB,
    event: engine::NewEvent,
    decoded: &GOATMessage,
    from_peer_id: PeerId,
    content_size: usize,
) -> Result<()> {
    let outcome = match crate::engine_bridge::engine_handle() {
        Some(engine) => engine.submit(event).await.context("record inbound message")?,
        None => {
            crate::engine_bridge::submit_event(local_db, event)
                .await
                .context("record inbound message")?;
            engine::SubmitOutcome::Inserted
        }
    };
    if matches!(outcome, engine::SubmitOutcome::Duplicate { .. }) {
        crate::p2p_admission::record_drop(crate::p2p_admission::DropReason::DuplicatePayload);
    }
    tracing::info!(
        event = "engine_inbox",
        outcome = ?outcome,
        message_type = decoded.content.event_type(),
        from_peer_id = %from_peer_id,
        content_size,
        "received durable message"
    );
    Ok(())
}

/// Restore persisted operator bindings, re-verify signatures and refresh stake asynchronously.
pub async fn load_persisted_peer_bindings(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
) -> Result<u64> {
    let bindings = local_db
        .acquire()
        .await?
        .load_p2p_peer_bindings(crate::p2p_admission::OPERATOR_BINDING_LOAD_LIMIT)
        .await?;
    let registry = crate::p2p_admission::peer_registry();
    let mut loaded = 0;
    let mut verified_bindings = std::collections::HashMap::new();
    for node in bindings {
        let node_info = NodeInfo {
            peer_id: node.peer_id.clone(),
            btc_pub_key: node.btc_pub_key.clone(),
            binding_sig: node.binding_sig.clone(),
            binding_issued_at: node.binding_issued_at,
            ..Default::default()
        };
        let Some(operator_key) = verify_node_info_binding(&node_info) else {
            continue;
        };
        if node.binding_issued_at > current_time_secs() + NODE_INFO_BINDING_MAX_FUTURE_SECS {
            continue;
        }
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            let operator_key = crate::p2p_admission::operator_key(&operator_key);
            registry.observe_operator_binding(&peer_id, &operator_key, node.binding_issued_at);
            verified_bindings.insert(peer_id, (operator_key, node.binding_issued_at));
            loaded += 1;
        }
    }
    // Apply configured bindings only where no signed binding exists; stake still requires confirmation.
    for (peer_id, operator_key) in crate::env::get_p2p_trusted_operator_bindings() {
        match registry.trust_operator_binding(&peer_id, &operator_key) {
            Ok(()) => loaded += 1,
            Err(conflict) => tracing::warn!(
                event = "p2p_admission",
                outcome = "trusted_binding_ignored",
                peer_id = %peer_id,
                configured_key = %hex::encode(operator_key),
                conflict = ?conflict,
                env = crate::env::ENV_P2P_TRUSTED_OPERATOR_BINDINGS,
                "configured operator binding disagrees with one the operator signed; keeping \
                 the signed binding — update or remove the configured entry"
            ),
        }
    }
    // Peers confirmed on chain in an earlier session keep their class and are
    // re-validated as known members, outside the discovery budget.
    loaded += crate::p2p_admission::seed_registry_from_store(
        local_db,
        registry,
        &verified_bindings,
        Instant::now(),
    )
    .await?;
    // Everything loaded is due; the unconfirmed remainder is picked up by the
    // regular tick as lookup slots free up.
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    Ok(loaded)
}

/// A clock disagreement below this is not worth reporting.
const CLOCK_LEAD_REPORT_THRESHOLD: Duration = Duration::from_secs(60);

/// Warn about registered authors whose message numbering is ahead of the local clock.
fn report_clock_leads(leads: Vec<(PeerId, Duration)>) {
    let ahead: Vec<&(PeerId, Duration)> =
        leads.iter().filter(|(_, lead)| *lead >= CLOCK_LEAD_REPORT_THRESHOLD).collect();
    let max_lead = ahead.iter().map(|(_, lead)| *lead).max().unwrap_or_default();
    match ahead.as_slice() {
        [] => {}
        [(peer, lead)] => tracing::warn!(
            event = "p2p_admission",
            outcome = "author_clock_ahead",
            peer_id = %peer,
            lead_secs = lead.as_secs(),
            "a registered author's clock is ahead of this node's; past the tolerance its \
             messages are refused as coming from the future"
        ),
        several => tracing::error!(
            event = "p2p_admission",
            outcome = "local_clock_behind_suspected",
            authors = several.len(),
            max_lead_secs = max_lead.as_secs(),
            "several registered authors' clocks are ahead of this node's: check this node's \
             clock (NTP). Past the tolerance their messages are refused as coming from the future"
        ),
    }
}

/// Refresh registrations, summarize drops and purge stale node rows.
pub async fn run_p2p_admission_maintenance(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let now = Instant::now();
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    crate::p2p_admission::revalidate_committee_candidates(local_db, goat_client).await;
    crate::p2p_admission::log_drop_summary();
    // Expired bans only need forgetting: the gate compares against the clock.
    crate::p2p_admission::direct_peer_strikes().take_expired_bans(now);
    report_clock_leads(crate::p2p_admission::replay_guard().take_clock_leads());
    for (peer, rejected) in crate::p2p_admission::replay_guard().take_lockout_suspects() {
        tracing::warn!(
            event = "p2p_admission",
            outcome = "replay_lockout_suspected",
            peer_id = %peer,
            rejected,
            "a registered author keeps being refused as a replay; if it is not under \
             attack, its clock stepped back or another instance shares its key"
        );
    }

    if !crate::p2p_admission::node_table_purge_due(NODE_TABLE_PURGE_INTERVAL, now) {
        return;
    }
    let result = async {
        local_db
            .acquire()
            .await?
            .purge_stale_unregistered_nodes(
                current_time_secs() - NODE_TABLE_STALE_SECS,
                &crate::env::get_peer_id(),
            )
            .await
    }
    .await;
    match result {
        Ok(0) => {}
        Ok(purged) => tracing::info!(
            event = "p2p_admission",
            outcome = "stale_nodes_purged",
            purged,
            "removed node rows of unregistered peers that stopped announcing themselves"
        ),
        Err(error) => tracing::warn!(
            event = "p2p_admission",
            outcome = "maintenance_write_failed",
            error = %error,
            "failed to purge stale node rows; retried next tick"
        ),
    }
}

/// Publish one message on its role topic; every sender goes through here.
pub async fn send_to_peer(
    swarm: &mut dyn MessagePublisher,
    message: GOATMessage,
) -> Result<MessageId> {
    let target_actor = message.actor.to_string();
    let message_type = message.content.event_type();
    let topic = crate::middleware::get_topic_name(&target_actor);
    let gossipsub_topic = gossipsub::IdentTopic::new(topic);
    let serialized = match message.serialize_message().await {
        Ok(serialized) => serialized,
        Err(error) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(false);
            }
            return Err(error);
        }
    };
    // Receivers drop what exceeds their envelope limit without telling anyone,
    // so an outgrown message has to be loud on the sending side.
    let limits = crate::p2p_admission::inbound_limits();
    let receiver_limit = if GOATMessage::is_binary_envelope(&serialized) {
        limits.max_binary_bytes
    } else {
        limits.max_json_bytes
    };
    if serialized.len() > receiver_limit {
        if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
            metrics_state.record_p2p_oversized_message();
        }
        tracing::error!(
            event = "p2p_message_publish",
            outcome = "oversized",
            target_actor,
            message_type,
            content_size = serialized.len(),
            receiver_limit,
            "outbound protocol message exceeds the inbound size limit peers enforce"
        );
    }
    match swarm.publish_message(gossipsub_topic, serialized).await {
        Ok(message_id) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(true);
            }
            tracing::info!(
                event = "p2p_message_publish",
                outcome = "published",
                target_actor,
                message_type,
                message_id = ?message_id,
                "published protocol message"
            );
            Ok(message_id)
        }
        Err(err) => {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_p2p_publish(false);
            }
            tracing::warn!(
                event = "p2p_message_publish",
                outcome = "failed",
                target_actor,
                message_type,
                error = %err,
                "failed to publish protocol message"
            );
            Err(anyhow::anyhow!("publish {message_type} to {target_actor}: {err}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soldering_proof_ready_is_descriptor_only() {
        let ready = SolderingProofReady {
            instance_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            graph_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            candidate_index: 3,
            payload_hash: [0xabu8; 32],
            total_len: 1024,
        };

        let value = serde_json::to_value(ready).unwrap();
        let object = value.as_object().unwrap();

        assert!(object.contains_key("instance_id"));
        assert!(object.contains_key("graph_id"));
        assert!(object.contains_key("candidate_index"));
        assert!(object.contains_key("payload_hash"));
        assert!(object.contains_key("total_len"));
        assert!(!object.contains_key("payload_path"));
        assert!(!object.contains_key("payload"));
        assert!(!object.contains_key("setup_package"));
        assert!(!object.contains_key("verifier_pubkey"));
    }

    #[test]
    fn every_wire_kind_is_routed_or_immediate() {
        use strum::IntoEnumIterator;

        let roles = [Actor::Committee, Actor::Operator, Actor::Verifier, Actor::Watchtower];
        for kind in MessageKind::iter() {
            let handled = roles.iter().any(|role| kind.handled_by(role));
            assert!(handled, "{kind} is kept by no role: it would only ever be relayed");
        }
    }
}
