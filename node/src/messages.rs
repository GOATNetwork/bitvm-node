//! Wire messages of the node: the envelope, the message kinds and their
//! routing table, and the signatures that bind InitGraph and NodeInfo to
//! their authors.

use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::CACSetupPackage;
use bitvm_lib::committee::*;
use bitvm_lib::types::SimplifiedBitvmGcGraph;
use musig2::{PartialSignature, PubNonce};
use node_macros::MessageBusinessRef;
use secp256k1::{
    Keypair, Message as SecpMessage, SECP256K1, schnorr::Signature as SchnorrSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use strum::{Display, EnumDiscriminants, EnumIter, IntoStaticStr};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct GOATMessage {
    pub actor: Actor,
    pub content: GOATMessageContent,
}

const GOAT_MESSAGE_BIN_PREFIX: &[u8] = b"GOATBIN1";
/// Maximum accepted binding timestamp lead.
pub const NODE_INFO_BINDING_MAX_FUTURE_SECS: i64 = 10 * 60;
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
                serde_json::to_vec(&cloned).context("failed to serialize JSON GOATMessage")
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
                serde_json::from_slice(&cloned).context("failed to deserialize JSON GOATMessage")
            }
        })
        .await?
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
