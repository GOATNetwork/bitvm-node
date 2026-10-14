//! Control message handling: ACKs settle the engine outbox, NodeInfo messages
//! update peer information and registration. Every other message kind is
//! recorded for the engine by `action::handle_inbound_p2p_message`.

use crate::action::*;
use crate::clock::current_time_secs;
use crate::middleware::publisher::MessagePublisher;
use crate::utils::*;
use anyhow::Result;
use bitvm_lib::actors::Actor;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;

pub struct ControlContext<'a> {
    /// `Sync` so handlers may hold the context across awaits in a `Send` task.
    pub publisher: &'a mut (dyn MessagePublisher + Sync),
    pub local_db: &'a LocalDB,
    pub goat_client: &'a Arc<GOATClient>,
    pub from_peer_id: PeerId,
}

pub async fn dispatch_control(
    ctx: &mut ControlContext<'_>,
    content: &GOATMessageContent,
) -> Result<()> {
    match content {
        GOATMessageContent::GraphSetupAck(GraphSetupAck { delivery_id }) => {
            // ACKs settle the engine outbox.
            let Some(engine) = crate::engine_bridge::engine_handle() else {
                return Ok(());
            };
            let outcome = engine.acknowledge(&ctx.from_peer_id.to_string(), delivery_id).await?;
            tracing::debug!(
                delivery_id,
                from_peer_id = %ctx.from_peer_id,
                outcome = ?outcome,
                "processed GraphSetupAck"
            );
            Ok(())
        }
        GOATMessageContent::RequestNodeInfo(node_info) => {
            handle_request_node_info(ctx, node_info).await
        }
        GOATMessageContent::ResponseNodeInfo(node_info) => {
            handle_response_node_info(ctx, node_info).await
        }
        _ => Ok(()),
    }
}

/// A `NodeInfo` payload is entirely self-declared, so only accept it as the
/// sender's own record: the registry is keyed by `peer_id`, and without this
/// check any peer could overwrite any other node's row.
fn accept_node_info(ctx: &ControlContext<'_>, node_info: &NodeInfo, message_kind: &str) -> bool {
    let Err(reason) = check_node_info(ctx, node_info) else {
        return true;
    };
    // Log registered-peer failures individually and aggregate unregistered-peer failures.
    let registered = crate::p2p_admission::peer_registry()
        .sender_class(&ctx.from_peer_id, std::time::Instant::now())
        .is_registered();
    if registered {
        tracing::warn!("Ignore {message_kind} from {}: {reason}", ctx.from_peer_id);
    } else {
        crate::p2p_admission::record_drop(crate::p2p_admission::DropReason::NodeInfoRejected);
        tracing::debug!("Ignore {message_kind} from {}: {reason}", ctx.from_peer_id);
    }
    false
}

fn check_node_info(
    ctx: &ControlContext<'_>,
    node_info: &NodeInfo,
) -> std::result::Result<(), String> {
    if !node_info_matches_sender(node_info, &ctx.from_peer_id) {
        return Err(format!("payload claims peer_id {}", node_info.peer_id));
    }
    validate_node_info_payload(node_info)?;
    if node_info.binding_sig.is_empty() {
        return Ok(());
    }
    // A present-but-invalid binding is a forgery attempt (claiming another key's
    // authorisation), not a benign omission, so reject the whole payload.
    if crate::action::verify_node_info_binding(node_info).is_none() {
        return Err("node info binding signature is invalid".to_string());
    }
    // `binding_issued_at` orders re-bindings, newest winning. One dated far ahead
    // would win against every honest re-binding until that date.
    if node_info.binding_issued_at
        > current_time_secs() + crate::action::NODE_INFO_BINDING_MAX_FUTURE_SECS
    {
        return Err("node info binding is dated in the future".to_string());
    }
    Ok(())
}

/// Record verified operator bindings by x-only key; confirm stake asynchronously.
async fn learn_node_info_binding(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    node_info: &NodeInfo,
) {
    if node_info.actor != Actor::Operator.to_string() {
        return;
    }
    let Some(operator_key) = crate::action::verify_node_info_binding(node_info) else {
        return;
    };
    let operator_key = crate::p2p_admission::operator_key(&operator_key);
    if let Ok(peer_id) = PeerId::from_str(&node_info.peer_id) {
        let released_confirmed_key = crate::p2p_admission::peer_registry()
            .observe_operator_binding(&peer_id, &operator_key, node_info.binding_issued_at);
        if released_confirmed_key {
            // The peer moved to another key: what was confirmed for the old one
            // must not be there to be restored after a restart.
            crate::p2p_admission::revoke_persisted_operator(local_db, &peer_id).await;
        }
        crate::p2p_admission::refresh_operator_binding_in_background(
            local_db,
            goat_client,
            peer_id,
            operator_key,
        );
    }
}

/// Store accepted NodeInfo within the unregistered-row limit and learn its binding.
async fn record_node_info(ctx: &ControlContext<'_>, node_info: &NodeInfo) -> Result<()> {
    let registered = crate::p2p_admission::peer_registry()
        .sender_class(&ctx.from_peer_id, std::time::Instant::now())
        .is_registered();
    let admissible = registered
        || ctx
            .local_db
            .acquire()
            .await?
            .node_row_admissible(
                &node_info.peer_id,
                crate::action::NODE_TABLE_MAX_UNREGISTERED_ROWS,
                current_time_secs() - crate::action::NODE_TABLE_EVICTABLE_AFTER_SECS,
                &crate::env::get_peer_id(),
            )
            .await?;
    if admissible {
        save_node_info(ctx.local_db, node_info).await?;
    } else {
        crate::p2p_admission::record_drop(crate::p2p_admission::DropReason::NodeTableFull);
    }
    // The binding is learned either way: it lives in the bounded registry, and
    // an operator must be able to become registered while the table is full.
    learn_node_info_binding(ctx.local_db, ctx.goat_client, node_info).await;
    // A self-declared committee node is a candidate for the registry's
    // committee lookup (within its budget); a durable message never is.
    if node_info.actor == Actor::Committee.to_string() {
        crate::p2p_admission::refresh_registry_in_background(
            ctx.local_db,
            ctx.goat_client,
            Some(ctx.from_peer_id),
        );
    }
    Ok(())
}

async fn handle_request_node_info(
    ctx: &mut ControlContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "RequestNodeInfo") {
        record_node_info(ctx, node_info).await?;
    }
    // Answer regardless: the response only carries this node's own public info,
    // and staying silent would break discovery for a misconfigured peer.
    // Coalesce recent requests into one broadcast response.
    if crate::p2p_admission::node_info_response_gate().try_respond(std::time::Instant::now()) {
        publish_node_info_response(ctx.publisher).await?;
    }
    Ok(())
}

async fn publish_node_info_response(swarm: &mut dyn MessagePublisher) -> Result<()> {
    let message_content = GOATMessageContent::ResponseNodeInfo(crate::env::get_local_node_info());
    publish_to_role(swarm, GOATMessage::new(Actor::All, message_content)).await?;
    Ok(())
}

/// Answer the `RequestNodeInfo`s that arrived while the previous response was
/// still cooling down. Called from the regular tick.
pub async fn flush_deferred_node_info_response(swarm: &mut dyn MessagePublisher) {
    if !crate::p2p_admission::node_info_response_gate().take_pending(std::time::Instant::now()) {
        return;
    }
    if let Err(error) = publish_node_info_response(swarm).await {
        tracing::debug!(
            event = "p2p_node_info",
            outcome = "deferred_response_failed",
            error = %error,
            "failed to publish the deferred node info response; peers will ask again"
        );
    }
}

async fn handle_response_node_info(
    ctx: &mut ControlContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "ResponseNodeInfo") {
        record_node_info(ctx, node_info).await?;
    }
    Ok(())
}
