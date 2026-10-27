//! NodeInfo validation and the node table rows it keeps current.

use crate::env::*;
use crate::messages::{GOATMessage, GOATMessageContent, NodeInfo};
use crate::middleware::AllBehaviours;
use crate::middleware::publisher::publish_to_role;
use alloy::primitives::Address as EvmAddress;
use anyhow::Result;
use bitcoin::PublicKey;
use bitvm_lib::actors::Actor;
use libp2p::{PeerId, Swarm};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use store::localdb::LocalDB;

use store::Node;
use stun_client::{Attribute, Class, Client};
use tracing::warn;

/// Upper bound for the operator-supplied node name, which `GET /v1/nodes`
/// returns verbatim.
const MAX_NODE_NAME_LEN: usize = 64;

/// Upper bound for the advertised `host:port` string.
const MAX_SOCKET_ADDR_LEN: usize = 128;

/// Every `NodeInfo` field is self-declared by the sender, yet the node registry
/// is keyed by `peer_id`. The one identity a peer cannot forge is the gossipsub
/// message source: the swarm runs with `MessageAuthenticity::Signed` and strict
/// validation, so `message.source` is bound to the sender's libp2p key. Key the
/// registry row on that identity and never on the `peer_id` inside the payload,
/// otherwise any peer can overwrite any other node's record.
pub fn node_info_matches_sender(node_info: &NodeInfo, from_peer_id: &PeerId) -> bool {
    node_info.peer_id == from_peer_id.to_string()
}

/// Reject payloads that cannot be persisted safely. These fields are served
/// verbatim by `GET /v1/nodes` and drive on-chain lookups and reward
/// attribution in `node_available_pbtc_update_monitor` and `add_node_reward`.
pub fn validate_node_info_payload(node_info: &NodeInfo) -> std::result::Result<(), String> {
    if PeerId::from_str(&node_info.peer_id).is_err() {
        return Err(format!("invalid peer_id {}", node_info.peer_id));
    }
    if Actor::from_str(&node_info.actor).is_err() {
        return Err(format!("invalid actor {}", node_info.actor));
    }
    if !node_info.goat_addr.is_empty() && EvmAddress::from_str(&node_info.goat_addr).is_err() {
        return Err(format!("invalid goat_addr {}", node_info.goat_addr));
    }
    if !node_info.btc_pub_key.is_empty() && PublicKey::from_str(&node_info.btc_pub_key).is_err() {
        return Err(format!("invalid btc_pub_key {}", node_info.btc_pub_key));
    }
    if !node_info.available_peg_btc.is_empty()
        && alloy::primitives::U256::from_str(&node_info.available_peg_btc).is_err()
    {
        return Err(format!("invalid available_peg_btc {}", node_info.available_peg_btc));
    }
    if !node_info.service_fee_rate.is_finite() || !(0.0..=1.0).contains(&node_info.service_fee_rate)
    {
        return Err(format!("invalid service_fee_rate {}", node_info.service_fee_rate));
    }
    if node_info.node_name.chars().count() > MAX_NODE_NAME_LEN
        || node_info.node_name.chars().any(char::is_control)
    {
        return Err(format!("invalid node_name of {} chars", node_info.node_name.chars().count()));
    }
    validate_node_socket_addr(&node_info.socket_addr)
}

/// The advertised socket address is only ever displayed and dialed by clients,
/// so require a plain `host:port` string that cannot smuggle control characters
/// into API responses.
fn validate_node_socket_addr(socket_addr: &str) -> std::result::Result<(), String> {
    if socket_addr.is_empty() {
        return Ok(());
    }
    if socket_addr.chars().count() > MAX_SOCKET_ADDR_LEN
        || socket_addr.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(format!("invalid socket_addr of {} chars", socket_addr.chars().count()));
    }
    let Some((host, port)) = socket_addr.rsplit_once(':') else {
        return Err(format!("socket_addr {socket_addr} is missing a port"));
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(format!("socket_addr {socket_addr} is not a valid host:port"));
    }
    Ok(())
}

pub async fn save_node_info(local_db: &LocalDB, node_info: &NodeInfo) -> Result<()> {
    // Reachable once per announcement from any peer: not louder than debug.
    tracing::debug!("save_node_info for {}", node_info.peer_id);
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    storage_process
        .upsert_node(&Node {
            peer_id: node_info.peer_id.clone(),
            actor: node_info.actor.clone(),
            node_name: node_info.node_name.clone(),
            goat_addr: node_info.goat_addr.clone(),
            btc_pub_key: node_info.btc_pub_key.clone(),
            socket_addr: node_info.socket_addr.clone(),
            reward: "0".to_string(),
            service_fee_rate: node_info.service_fee_rate,
            available_peg_btc: node_info.available_peg_btc.clone(),
            binding_sig: node_info.binding_sig.clone(),
            binding_issued_at: node_info.binding_issued_at,
            updated_at: current_time,
            created_at: current_time,
        })
        .await?;
    Ok(())
}

pub async fn save_local_info(local_db: &LocalDB) {
    let node = get_local_node_info();
    // Peers apply the same validation to the NodeInfo this node broadcasts, so a
    // malformed local config would silently drop this node from every peer's
    // registry. Surface it here instead, where the operator reads the logs.
    if let Err(reason) = validate_node_info_payload(&node) {
        tracing::error!(
            "local node info will be rejected by peers: {reason}; fix the node configuration"
        );
    }
    match save_node_info(local_db, &node).await {
        Ok(_) => {}
        Err(err) => tracing::error!("save local node err: {err}"),
    }
}

pub async fn update_node_timestamp(local_db: &LocalDB, peer_id: &str) -> Result<()> {
    tracing::debug!("update timestamp for {peer_id}");
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut storage_process = local_db.acquire().await?;
    match storage_process.update_node_timestamp(peer_id, current_time).await {
        Ok(_) => {}
        Err(err) => warn!("{err}"),
    };
    Ok(())
}

pub async fn detect_heart_beat(swarm: &mut Swarm<AllBehaviours>) -> Result<()> {
    tracing::info!("start detect_heart_beat");
    let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
    // send to actor
    let actors = get_rpc_support_actors();
    for actor in actors {
        match publish_to_role(swarm, GOATMessage::new(actor, message_content.clone())).await {
            Ok(_) => {}
            Err(err) => warn!("{err}"),
        }
    }
    Ok(())
}

/// Retrieve the server's public IP via NAT protocol and combine it with
/// the configured RPC monitoring port`rpc_addr` to generate the external RPC service address.
pub async fn set_node_external_socket_addr_env(rpc_addr: &str) -> Result<()> {
    if get_proof_server_url().is_some() || std::env::var(ENV_EXTERNAL_SOCKET_ADDR).is_ok() {
        // not provide proof server
        return Ok(());
    }
    let addr = SocketAddr::from_str(rpc_addr)?;
    let mut client = Client::new("0.0.0.0:0", None).await?;
    let message_res = client.binding_request("stun.l.google.com:19302", None).await;
    if message_res.is_err() {
        warn!("fail to get message from stun.l.google.com:19302, err :{:?}", message_res.err());
        return Ok(());
    }
    let message = message_res?;
    if message.get_class() != Class::SuccessResponse {
        warn!(
            "fail to get message from stun.l.google.com:19302, return class :{:?}",
            message.get_class()
        );
        return Ok(());
    }
    if let Some(socket_addr) = Attribute::get_xor_mapped_address(&message) {
        unsafe {
            std::env::set_var(
                ENV_EXTERNAL_SOCKET_ADDR,
                SocketAddr::new(socket_addr.ip(), addr.port()).to_string(),
            );
        }
    }
    Ok(())
}

pub fn reflect_goat_address(addr_op: Option<String>) -> (bool, Option<String>) {
    if let Some(addr) = addr_op
        && let Ok(addr) = EvmAddress::from_str(&addr)
    {
        return (true, Some(addr.to_string()));
    }
    (false, None)
}

#[cfg(test)]
mod node_info_tests {
    use super::*;

    /// One field mutation applied to an otherwise valid payload.
    type NodeInfoMutation = fn(&mut NodeInfo);

    fn valid_node_info(peer_id: &str) -> NodeInfo {
        NodeInfo {
            peer_id: peer_id.to_string(),
            actor: Actor::Operator.to_string(),
            goat_addr: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            btc_pub_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            socket_addr: "127.0.0.1:8080".to_string(),
            node_name: "zkm".to_string(),
            service_fee_rate: 0.001,
            available_peg_btc: "1000".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn node_info_is_accepted_only_for_its_own_sender() {
        let sender = PeerId::random();
        let other = PeerId::random();
        let node_info = valid_node_info(&sender.to_string());

        assert!(node_info_matches_sender(&node_info, &sender));
        assert!(!node_info_matches_sender(&node_info, &other));
    }

    #[test]
    fn valid_node_info_payload_is_accepted() {
        let node_info = valid_node_info(&PeerId::random().to_string());
        assert!(validate_node_info_payload(&node_info).is_ok());
    }

    #[test]
    fn optional_node_info_fields_may_be_empty() {
        let mut node_info = valid_node_info(&PeerId::random().to_string());
        node_info.goat_addr = String::new();
        node_info.btc_pub_key = String::new();
        node_info.socket_addr = String::new();
        node_info.available_peg_btc = String::new();
        node_info.node_name = String::new();
        assert!(validate_node_info_payload(&node_info).is_ok());
    }

    #[test]
    fn malformed_node_info_fields_are_rejected() {
        let peer_id = PeerId::random().to_string();
        let cases: Vec<(&str, NodeInfoMutation)> = vec![
            ("peer_id", |n| n.peer_id = "not-a-peer-id".to_string()),
            ("actor", |n| n.actor = "Auditor".to_string()),
            ("goat_addr", |n| n.goat_addr = "0xdeadbeef".to_string()),
            ("btc_pub_key", |n| n.btc_pub_key = "02zz".to_string()),
            ("available_peg_btc", |n| n.available_peg_btc = "lots".to_string()),
            ("service_fee_rate NaN", |n| n.service_fee_rate = f64::NAN),
            ("service_fee_rate range", |n| n.service_fee_rate = 42.0),
            ("node_name length", |n| n.node_name = "a".repeat(MAX_NODE_NAME_LEN + 1)),
            ("node_name control", |n| n.node_name = "a\nb".to_string()),
            ("socket_addr length", |n| {
                n.socket_addr = format!("{}:8080", "a".repeat(MAX_SOCKET_ADDR_LEN))
            }),
            ("socket_addr port", |n| n.socket_addr = "host".to_string()),
            ("socket_addr host", |n| n.socket_addr = ":8080".to_string()),
            ("socket_addr control", |n| n.socket_addr = "127.0.0.1 :8080".to_string()),
        ];

        for (label, mutate) in cases {
            let mut node_info = valid_node_info(&peer_id);
            mutate(&mut node_info);
            assert!(
                validate_node_info_payload(&node_info).is_err(),
                "expected {label} to be rejected"
            );
        }
    }
}
