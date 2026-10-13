use crate::action::*;
use crate::aggregates::graph::operator_start_event;
use crate::aggregates::graph_jobs::signing_nonce_id;
use crate::aggregates::graph_setup::{
    build_babe_prover_state, decode_soldering_proof_payload, find_verifier_index_by_pubkey,
    selected_candidate_for_graph_index, validate_verifier_slot,
};
use crate::aggregates::instance::{SigningGate, signing_gate};
use crate::engine_bridge::submit_event;
use crate::env::{
    get_bitvm_key, get_operator_graph_start_cutoff_blocks, get_soldering_proof_payload_store_path,
    is_relayer,
};
use crate::error::SpecialError;
use crate::metrics_service::MetricsState;
use crate::middleware::publisher::MessagePublisher;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus;
use crate::soldering_payload_store::{
    read_soldering_proof_store_payload, soldering_proof_payload_store_path,
};
use crate::utils::*;
use anyhow::{Context, Result, anyhow, bail, ensure};
use ark_serialize::CanonicalSerialize;
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::{
    BabeBundleBuilder, BabeChallengeAssertWitness, ChallengeAssertWitnessRaw, TxAssertWitness,
    WOTS_SIG_COUNT, assert_wots_message, build_assert_witness, build_real_challenge_assert_witness,
    expand_compact_soldering_proof_payload, recover_operator_proof_from_assert_witness,
    recover_real_wrongly_challenged_witness,
};
use bitvm_lib::committee::*;
use bitvm_lib::keys::*;
use bitvm_lib::operator::*;
use bitvm_lib::types::{BitvmGcGraph, BitvmGcInstanceParameters};
use bitvm_lib::verifier::*;
use client::goat_chain::{DisproveTxType, WithdrawStatus};
use client::graphs::graph_query::BridgeInRequestEvent;
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use goat::wots::{Wots, Wots96};
use libp2p::PeerId;
use libp2p::gossipsub::MessageId;
use secp256k1::{Message as SecpMessage, SECP256K1};
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{GoatTxType, GraphStatus, InstanceBridgeInStatus, SerializableTxid};
use uuid::Uuid;

pub struct HandlerContext<'a> {
    /// `Sync` so handlers may hold the context across awaits in a `Send` job.
    pub swarm: &'a mut (dyn MessagePublisher + Sync),
    pub local_db: &'a LocalDB,
    pub btc_client: &'a Arc<BTCClient>,
    pub goat_client: &'a Arc<GOATClient>,
    pub http_client: &'a HttpAsyncClient,
    pub soldering_builder: &'a Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: &'a MetricsState,
    pub actor: Actor,
    pub from_peer_id: PeerId,
    pub id: MessageId,
    pub is_self_peer: bool,
}

async fn load_or_create_committee_instance_keypair(
    local_db: &LocalDB,
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<bitcoin::key::Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    match committee_master_key.load_instance_keypair(instance_id, &envelope_path) {
        Ok(keypair) => Ok(keypair),
        Err(load_err) => {
            if !is_io_not_found_error(&load_err) {
                return Err(load_err).with_context(|| {
                    format!(
                        "load committee instance keypair failed for {} at {} (refuse auto-overwrite for non-missing envelope)",
                        instance_id,
                        envelope_path.display()
                    )
                });
            }
            // A deleted key is never regenerated (docs/node-protocol.md §10.2).
            if local_db
                .acquire()
                .await?
                .find_instance(&instance_id)
                .await?
                .is_some_and(|instance| instance.key_deleted)
            {
                bail!(
                    "committee instance key for {instance_id} was deleted; refusing to regenerate it"
                );
            }
            tracing::info!(
                "committee instance key not found for {} at {}: {}, creating new envelope",
                instance_id,
                envelope_path.display(),
                load_err
            );
            committee_master_key
                .create_instance_keypair_envelope(instance_id, &envelope_path)
                .with_context(|| {
                    format!(
                        "create committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                })?;
            committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(
                || {
                    format!(
                        "reload committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                },
            )
        }
    }
}

pub async fn dispatch(ctx: &mut HandlerContext<'_>, content: &GOATMessageContent) -> Result<()> {
    match (content, &ctx.actor) {
        (GOATMessageContent::GraphSetupAck(GraphSetupAck { delivery_id }), _) => {
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
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                ..
            }),
            Actor::Committee,
        ) => {
            handle_pegin_request_committee(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
            )
            .await
        }
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                ..
            }),
            _,
        ) => {
            handle_pegin_request_default(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
            )
            .await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), Actor::Operator) => {
            handle_confirm_instance_operator(ctx, *instance_id).await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), _) => {
            handle_confirm_instance_default(ctx, *instance_id).await
        }
        (
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_nonce_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                pub_nonce,
                nonce_sig,
                content,
            )
            .await
        }
        (
            GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                consensus_hash,
                signature,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_nonce_consensus_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                *consensus_hash,
                signature,
                content,
            )
            .await
        }
        (
            GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                partial_sig,
                endorse_sig,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_partial_sig_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                partial_sig,
                endorse_sig,
                content,
            )
            .await
        }
        (
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_kickoff_ready_operator(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Committee,
        ) => handle_kickoff_sent_committee(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Verifier,
        ) => handle_kickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }), _) => {
            handle_kickoff_sent_default(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
            Actor::Verifier,
        ) => handle_prekickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }), _) => {
            handle_prekickoff_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id,
                graph_id,
                challenge_txid,
            }),
            Actor::Operator,
        ) => {
            handle_challenge_sent_operator(ctx, *instance_id, *graph_id, *challenge_txid, content)
                .await
        }
        (GOATMessageContent::ChallengeSent(ChallengeSent { instance_id, graph_id, .. }), _) => {
            handle_challenge_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
                instance_id,
                graph_id,
            }),
            Actor::Watchtower,
        ) => {
            handle_watchtower_challenge_init_sent_watchtower(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                instance_id,
                graph_id,
                watchtower_index,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *watchtower_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_timeout_operator(ctx, *instance_id, *graph_id, content)
                .await
        }
        (GOATMessageContent::NackReady(NackReady { instance_id, graph_id }), Actor::Verifier) => {
            handle_nack_ready_verifier(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinReady(OperatorCommitPubinReady {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_operator_commit_pubin_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinTimeout(OperatorCommitPubinTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Verifier,
        ) => {
            handle_operator_commit_pubin_timeout_verifier(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_assert_ready_operator(ctx, *instance_id, *graph_id).await,
        (
            GOATMessageContent::AssertSent(AssertSent { instance_id, graph_id, assert_txid }),
            Actor::Verifier,
        ) => handle_assert_sent_verifier(ctx, *instance_id, *graph_id, *assert_txid, content).await,
        (
            GOATMessageContent::ChallengeAssertSent(ChallengeAssertSent {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                ..
            }),
            Actor::Operator,
        ) => {
            handle_challenge_assert_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WronglyChallengeTimeout(WronglyChallengeTimeout {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                ..
            }),
            Actor::Verifier,
        ) => {
            handle_wrongly_challenge_timeout_verifier(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id,
                graph_id,
                disprove_type,
                index,
                challenge_finish_txid,
                ..
            }),
            Actor::Committee,
        ) => {
            handle_disprove_sent_committee(
                ctx,
                *instance_id,
                *graph_id,
                *disprove_type,
                *index,
                *challenge_finish_txid,
                content,
            )
            .await
        }
        (GOATMessageContent::DisproveSent(DisproveSent { instance_id, graph_id, .. }), _) => {
            handle_disprove_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take1_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take1_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), _) => {
            handle_take1_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take2_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take2_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), _) => {
            handle_take2_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::RequestNodeInfo(node_info), _) => {
            handle_request_node_info(ctx, node_info).await
        }
        (GOATMessageContent::ResponseNodeInfo(node_info), _) => {
            handle_response_node_info(ctx, node_info).await
        }
        _ => Ok(()),
    }
}

/// Apply the business-key cooldown to stored-value recovery.
async fn publish_stored(
    ctx: &mut HandlerContext<'_>,
    gate_key: &str,
    target: Actor,
    content: GOATMessageContent,
    origin: StoredValue,
) -> Result<()> {
    let now = std::time::Instant::now();
    let gate = crate::p2p_admission::protocol_republish_gate();
    let message = GOATMessage::new(target, content);
    if origin == StoredValue::Found && gate.is_cooling(gate_key, now) {
        return Ok(());
    }
    send_protocol_message(ctx.swarm, ctx.local_db, message, origin).await?;
    gate.allow(gate_key, now);
    Ok(())
}

/// The committee key this node signs with for `instance_id`.
fn local_committee_pubkey(instance_id: Uuid) -> Result<PublicKey> {
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    Ok(load_committee_instance_keypair(&committee_master_key, instance_id)?.public_key().into())
}

/// Recover this node's own PeginConfirm value; leave live outbox rows on their retry schedule.
async fn redeliver_own_pegin_confirm_value(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    gate_key: &str,
    sender: &PublicKey,
    content: &GOATMessageContent,
) -> Result<()> {
    if ctx.id != GOATMessage::default_message_id()
        || *sender != local_committee_pubkey(instance_id)?
    {
        return Ok(());
    }
    publish_stored(ctx, gate_key, Actor::Committee, content.clone(), StoredValue::Found).await
}

fn make_message(ctx: &HandlerContext<'_>, content: &GOATMessageContent) -> GOATMessage {
    GOATMessage::new(ctx.actor.clone(), content.clone())
}

fn validate_watchtower_branches(graph: &BitvmGcGraph) -> Result<usize> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if watchtower_num == 0 {
        bail!("graph has no watchtower slots");
    }
    if graph.parameters.watchtower_ack_hashlocks.len() != watchtower_num
        || graph.watchtower_challenge_timeouts.len() != watchtower_num
        || graph.operator_challenge_nacks.len() != watchtower_num
    {
        bail!(
            "graph watchtower branch lengths differ: watchtowers={}, ack_hashlocks={}, timeouts={}, nacks={}",
            watchtower_num,
            graph.parameters.watchtower_ack_hashlocks.len(),
            graph.watchtower_challenge_timeouts.len(),
            graph.operator_challenge_nacks.len()
        );
    }
    Ok(watchtower_num)
}

fn validate_challenge_witness_index(
    verifier_index: usize,
    challenge_witness: &BabeChallengeAssertWitness,
) -> Result<()> {
    if challenge_witness.verifier_index != verifier_index {
        bail!(
            "challenge witness verifier index {} does not match message verifier index {verifier_index}",
            challenge_witness.verifier_index
        );
    }
    Ok(())
}

fn validate_expected_challenge_assert_txid(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    challenge_assert_txid: Txid,
) -> Result<()> {
    validate_verifier_slot(graph, verifier_index)?;
    let expected_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
    if challenge_assert_txid != expected_txid {
        bail!(
            "challenge assert txid {challenge_assert_txid} does not match graph verifier assert txid {expected_txid}"
        );
    }
    Ok(())
}

/// Resolve the request metadata a `PeginRequest` carries from the canonical
/// `BridgeInRequest` event this node indexed itself.
///
/// The message is gossiped, so its tx hash, height and timestamp are all
/// sender-controlled, and the height alone decides
/// whether the instance ever matches the response-window query in
/// `instance_window_expiration_monitor`. The event watcher already stores the
/// canonical request transaction in `goat_tx_record`, so take all three values
/// from there and never from the message.
///
/// Returns `None` when the event watcher has not indexed the request yet. The
/// current trigger is ignored in that case: once the watcher observes the
/// event, `instance_answers_monitor` creates a canonical local `PeginRequest`.
async fn resolve_pegin_request_metadata(
    local_db: &LocalDB,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<Option<(String, i64, i64)>> {
    let tx_record = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_goat_tx_record(
                &instance_id,
                &Uuid::nil(),
                &GoatTxType::BridgeInRequest.to_string(),
            )
            .await?
    };
    let Some(tx_record) = tx_record else {
        tracing::info!(
            "Ignore PeginRequest for {instance_id}: no local BridgeInRequest event record yet; \
             the event watcher will enqueue the canonical request"
        );
        return Ok(None);
    };
    if tx_record.tx_hash != pegin_request_tx_hash || tx_record.height != pegin_request_height {
        // Not fatal - the canonical record wins either way - but a mismatch is
        // the signature of a forged or stale request, so make it visible.
        tracing::warn!(
            "PeginRequest for {instance_id} claims tx {pegin_request_tx_hash} at height \
             {pegin_request_height}, the indexed BridgeInRequest is tx {} at height {}",
            tx_record.tx_hash,
            tx_record.height
        );
    }
    // The block timestamp comes from the same indexed event; fall back to now
    // rather than to anything the sender supplied.
    let timestamp = tx_record
        .extra
        .as_deref()
        .and_then(|extra| serde_json::from_str::<BridgeInRequestEvent>(extra).ok())
        .and_then(|event| event.block_timestamp.parse::<i64>().ok())
        .unwrap_or_else(current_time_secs);
    Ok(Some((tx_record.tx_hash, tx_record.height, timestamp)))
}

fn should_ignore_invalid_pegin_request(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginRequest(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore PeginRequest for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_invalid_pegin_data(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginData(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore ConfirmInstance for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_committee_error(
    e: &anyhow::Error,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    ctx: &HandlerContext<'_>,
    context: &str,
) -> bool {
    let peer = ctx.from_peer_id.to_string();
    match e.downcast_ref::<SpecialError>() {
        Some(SpecialError::InvalidCommittee(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: {err_msg}"
                );
            } else {
                tracing::warn!("Ignore {context} for {instance_id} from {peer}: {err_msg}");
            }
            true
        }
        Some(SpecialError::EvmReverted(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            } else {
                tracing::warn!(
                    "Ignore {context} for {instance_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            }
            true
        }
        _ => false,
    }
}

async fn ensure_self_or_valid_committee(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    received_committee_pubkey: &PublicKey,
    context: &str,
) -> Result<bool> {
    if ctx.is_self_peer {
        return Ok(true);
    }
    if let Err(e) = validate_committee(
        ctx.goat_client,
        &ctx.from_peer_id,
        instance_id,
        received_committee_pubkey,
    )
    .await
    {
        if should_ignore_committee_error(&e, instance_id, graph_id, ctx, context) {
            return Ok(false);
        }
        bail!(e);
    }
    Ok(true)
}

async fn refresh_and_compensate(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
    compensation_anchor_status: GraphStatus,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>, bool)> {
    let refresh =
        refresh_graph(ctx.local_db, ctx.btc_client, ctx.goat_client, instance_id, graph_id, graph)
            .await?;
    let graph_status = refresh.status;
    let sub_status = refresh.sub_status;
    tracing::info!("Graph {graph_id} latest status: {graph_status}");
    if refresh.status_transition_accepted {
        compensate_graph_events(
            ctx.local_db,
            ctx.btc_client,
            instance_id,
            graph_id,
            graph,
            refresh.scan.as_ref(),
            compensation_anchor_status,
            graph_status,
        )
        .await?;
    }
    Ok((graph_status, sub_status, refresh.status_transition_accepted))
}

async fn get_graph_for_refresh(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<BitvmGcGraph> {
    let graph = get_graph(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    BitvmGcGraph::from_simplified(&graph)
}

async fn get_graph_for_refresh_or_defer(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: &GOATMessage,
) -> Result<Option<BitvmGcGraph>> {
    let graph = match get_graph_or_defer(ctx.local_db, instance_id, graph_id, message).await? {
        Some(g) => g,
        None => return Ok(None),
    };
    Ok(Some(BitvmGcGraph::from_simplified(&graph)?))
}

async fn refresh_graph_status(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: Option<&GOATMessage>,
    compensate_from_status: GraphStatus,
) -> Result<Option<(BitvmGcGraph, GraphStatus, Option<ChallengeSubStatus>)>> {
    let graph = match message {
        Some(message) => {
            match get_graph_for_refresh_or_defer(ctx, instance_id, graph_id, message).await? {
                Some(v) => v,
                None => return Ok(None),
            }
        }
        None => get_graph_for_refresh(ctx, instance_id, graph_id).await?,
    };
    let (graph_status, sub_status, status_transition_accepted) =
        refresh_and_compensate(ctx, instance_id, graph_id, &graph, compensate_from_status).await?;
    if !status_transition_accepted {
        tracing::warn!(
            "Ignore graph action for {instance_id}:{graph_id}: chain scan status was rejected or graph is missing"
        );
        return Ok(None);
    }
    Ok(Some((graph, graph_status, sub_status)))
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. bind the request metadata to the event this node indexed itself
    let Some((pegin_request_tx_hash, pegin_request_height, pegin_timestamp)) =
        resolve_pegin_request_metadata(
            ctx.local_db,
            instance_id,
            pegin_request_tx_hash,
            pegin_request_height,
        )
        .await?
    else {
        return Ok(());
    };
    // 2. read & check the pegin request data
    let (user_info, pegin_amount, answered_by) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };

    // 3. save the pegin request data to local db
    let stored = store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash,
            pegin_request_height,
            pegin_timestamp,
        },
    )
    .await?;
    if !stored {
        // The instance has already moved on, so answering now would be a
        // duplicate on-chain call for a request this node handled long ago.
        return Ok(());
    }
    // 4. call Gateway.answerPeginRequest
    //
    // PeginRequest is gossiped and re-deliverable, and the pegin data stays
    // Pending while answers accumulate, so nothing above notices a replay.
    // Gateway.answerPeginRequest does not reject a repeat answer either - it
    // overwrites the stored pubkey and re-emits CommitteeResponse - so without
    // this every re-delivery spends another transaction. The contract keys
    // answers on msg.sender, so compare against the signer that sends it.
    if answered_by.contains(&ctx.goat_client.get_default_signer_address()) {
        tracing::info!(
            "Skip answerPeginRequest for {instance_id}: this committee already answered"
        );
        return Ok(());
    }
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair =
        load_or_create_committee_instance_keypair(ctx.local_db, &committee_master_key, instance_id)
            .await?;
    let pubkey_for_instance = instance_keypair.public_key().into();
    ctx.goat_client.gateway_answer_pegin_request(&instance_id, &pubkey_for_instance).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. bind the request metadata to the event this node indexed itself
    let Some((pegin_request_tx_hash, pegin_request_height, pegin_timestamp)) =
        resolve_pegin_request_metadata(
            ctx.local_db,
            instance_id,
            pegin_request_tx_hash,
            pegin_request_height,
        )
        .await?
    else {
        return Ok(());
    };
    // 2. read & check the pegin request data
    let (user_info, pegin_amount, _) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };
    // 3. save the pegin request data to local db
    store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash,
            pegin_request_height,
            pegin_timestamp,
        },
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // Triggered by the Peg-In-Prepare confirmation. From here the Graph
    // aggregate owns the setup session (docs/node-protocol.md §10.7.2),
    // including the wait for the previous slot to settle.
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey: PublicKey = operator_master_key.master_keypair().public_key().into();
    // 0. A graph exists already: its deliveries live in the engine outbox.
    if let Some(graph) = get_graph_by_instance_id_and_operator_pubkey(
        ctx.local_db,
        instance_id,
        &local_operator_pubkey,
    )
    .await?
    {
        let graph_id = graph.parameters.graph_id;
        tracing::info!("Graph already created for {instance_id}, graph_id: {graph_id}");
        crate::engine_bridge::wake(&crate::aggregates::graph::graph_ref(graph_id));
        return Ok(());
    }
    // 1. A pending session resumes from its saved state; the start event is
    //    one per graph id, so a repeat is a no-op.
    let pending_graph_id = ctx
        .local_db
        .acquire()
        .await?
        .find_pending_graph_init_by_instance_and_operator_pubkey(
            &instance_id,
            &local_operator_pubkey.to_string(),
        )
        .await?
        .map(|pending| pending.graph_id);
    if let Some(graph_id) = pending_graph_id {
        tracing::info!("Resume pending graph setup for {instance_id}, graph_id: {graph_id}");
        submit_event(
            ctx.local_db,
            operator_start_event(instance_id, graph_id, &local_operator_pubkey.to_string())?,
        )
        .await?;
        return Ok(());
    }

    if let Some(reason) = graph_start_blocked(ctx, instance_id).await? {
        tracing::info!(
            event = "graph_start_cutoff",
            instance_id = %instance_id,
            reason = %reason,
            "not starting a new graph for this instance"
        );
        return Ok(());
    }
    // 2. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        bail!("Invalid ConfirmInstance: pegin deposit tx {pegin_deposit_txid} not found on chain");
    }
    // 3. save the instance data, open the session and start the aggregate.
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    let graph_id = Uuid::new_v4();
    ctx.local_db
        .acquire()
        .await?
        .upsert_pending_graph_init(&instance_id, &local_operator_pubkey.to_string(), &graph_id)
        .await?;
    submit_event(
        ctx.local_db,
        operator_start_event(instance_id, graph_id, &local_operator_pubkey.to_string())?,
    )
    .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // triggered by PeginDeposit tx
    // 1. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        return Ok(());
    }
    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    Ok(())
}

/// Start, or resume after a restart, the committee's PeginConfirm round once
/// the instance holds enough finalized graphs: the deterministic nonce is
/// stored, then published, and the round proceeds from the stored values.
/// Run by the Instance aggregate's `start_pegin_confirm` job on entering
/// Presigned (docs/node-protocol.md §10.7.1).
pub(crate) async fn start_pegin_confirm_round(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    if let CommitteeMembership::NotMember(reason) =
        local_committee_membership(ctx.goat_client, instance_id).await?
    {
        tracing::info!(
            event = "pegin_confirm_round",
            instance_id = %instance_id,
            outcome = "not_member",
            reason,
            "this node is not in the instance's committee"
        );
        return Ok(());
    }
    if !has_required_presigned_graphs(ctx.local_db, instance_id).await? {
        tracing::info!(
            event = "pegin_confirm_round",
            instance_id = %instance_id,
            outcome = "not_ready",
            "not enough finalized graphs for the PeginConfirm round"
        );
        return Ok(());
    }
    let instance_parameters = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    let stored_pub_nonce =
        get_committee_pub_nonce_for_instance(ctx.local_db, instance_id, &local_committee_pubkey)
            .await?;
    if stored_pub_nonce.is_none() {
        if signing_closed(ctx, instance_id, "PeginConfirm nonce").await? {
            // Nothing new after T0; stored values are still re-sent below.
        } else if get_committee_partial_sig_for_instance(
            ctx.local_db,
            instance_id,
            &local_committee_pubkey,
        )
        .await?
        .is_some()
        {
            tracing::warn!(
                "Skip PeginConfirm nonce for {instance_id}: local committee partial signature already exists"
            );
        } else {
            let (_, pub_nonce, nonce_sig) = committee_master_key
                .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
            let message_content = GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                pub_nonce: pub_nonce.clone(),
                nonce_sig,
            });
            store_committee_pub_nonce_for_instance(
                ctx.local_db,
                instance_id,
                local_committee_pubkey,
                pub_nonce,
            )
            .await?;
            send_protocol_message(
                ctx.swarm,
                ctx.local_db,
                GOATMessage::new(Actor::Committee, message_content),
                StoredValue::Fresh,
            )
            .await?;
        }
    }
    if let Some(pub_nonce) = stored_pub_nonce {
        // Recover the stored nonce proof without recomputing MuSig signatures.
        let (_, expected_nonce, nonce_sig) = committee_master_key
            .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
        if expected_nonce != pub_nonce {
            bail!("stored pegin public nonce differs from deterministic nonce");
        }
        publish_stored(
            ctx,
            &format!("pegin-nonce:{instance_id}"),
            Actor::Committee,
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
            StoredValue::Found,
        )
        .await?;
    }
    maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await
}

async fn pegin_confirm_nonce_consensus_context(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<
    Option<(
        BitvmGcInstanceParameters,
        Vec<PublicKey>,
        Vec<musig2::PubNonce>,
        musig2::AggNonce,
        [u8; 32],
    )>,
> {
    let instance_parameters = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces.len() < committee_pubkeys.len() {
        return Ok(None);
    }
    let ordered_pub_nonces =
        order_committee_values(&committee_pubkeys, pub_nonces, "pegin committee pub nonces")?;
    let agg_nonce = nonce_aggregation(&ordered_pub_nonces);
    let consensus_hash = pegin_confirm_nonce_consensus_hash(
        &instance_parameters,
        &committee_pubkeys,
        &ordered_pub_nonces,
    )?;
    Ok(Some((
        instance_parameters,
        committee_pubkeys,
        ordered_pub_nonces,
        agg_nonce,
        consensus_hash,
    )))
}

async fn has_complete_pegin_confirm_nonce_consensus(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    committee_pubkeys: &[PublicKey],
    consensus_hash: [u8; 32],
) -> Result<bool> {
    let consensus_votes =
        get_committee_agg_nonce_consensus_for_instance(ctx.local_db, instance_id).await?;
    if consensus_votes.len() != committee_pubkeys.len() {
        return Ok(false);
    }
    let ordered_votes = order_committee_values(
        committee_pubkeys,
        consensus_votes
            .into_iter()
            .map(|(committee_pubkey, vote_hash, signature)| {
                (committee_pubkey, (vote_hash, signature))
            })
            .collect(),
        "PeginConfirm agg nonce consensus",
    )?;
    for (committee_pubkey, (received_hash, signature)) in
        committee_pubkeys.iter().zip(ordered_votes)
    {
        ensure!(
            received_hash == consensus_hash,
            "committee PeginConfirm nonce consensus differs for instance {instance_id} and committee {committee_pubkey}"
        );
        SECP256K1
            .verify_schnorr(
                &signature,
                &SecpMessage::from_digest(consensus_hash),
                &XOnlyPublicKey::from(*committee_pubkey),
            )
            .map_err(|error| {
                SpecialError::InvalidPeginData(format!(
                    "invalid PeginConfirm nonce consensus signature for instance {instance_id} and committee {committee_pubkey}: {error}"
                ))
            })?;
    }
    Ok(true)
}

async fn broadcast_pegin_confirm_if_presigned(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    instance_parameters: &BitvmGcInstanceParameters,
    committee_pubkeys: &[PublicKey],
) -> Result<()> {
    if !is_relayer() {
        return Ok(());
    }
    if let Some(reason) = pegin_confirm_broadcast_blocked(ctx, instance_id).await? {
        tracing::info!(
            event = "signing_gate",
            instance_id = %instance_id,
            reason = %reason,
            "not broadcasting Peg-In-Confirm"
        );
        return Ok(());
    }
    let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    let partial_sigs = get_committee_partial_sigs_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces.len() != committee_pubkeys.len() || partial_sigs.len() != committee_pubkeys.len()
    {
        return Ok(());
    }
    let pub_nonces =
        order_committee_values(committee_pubkeys, pub_nonces, "pegin committee pub nonces")?;
    let partial_sigs =
        order_committee_values(committee_pubkeys, partial_sigs, "pegin committee partial sigs")?;
    let mut pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let context = instance_parameters.get_base_context();
    let full_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
        .map_err(|error| {
            anyhow!("Failed to aggregate PeginConfirm signatures for {instance_id}: {error}")
        })?;
    let connector_z = instance_parameters.connector_z();
    pegin_confirm.push_input_0_signature(&connector_z, full_sig);
    let result = broadcast_tx(ctx.btc_client, pegin_confirm.tx()).await;
    ctx.metrics_state.record_pegin_confirm(result.is_ok());
    result?;
    Ok(())
}

/// Bind the PeginConfirm signing nonce to the nonce transcript it signs for;
/// a second transcript under the same nonce is refused (§10.4).
async fn authorize_pegin_confirm_signing(
    local_db: &LocalDB,
    instance_id: Uuid,
    pub_nonce: &musig2::PubNonce,
    consensus_hash: [u8; 32],
) -> Result<()> {
    let nonce_id = signing_nonce_id("pegin-confirm", &pub_nonce.serialize());
    let transcript = hex::encode(consensus_hash);
    let authorization = local_db
        .acquire()
        .await?
        .authorize_signing(
            "instance",
            &instance_id.to_string(),
            &nonce_id,
            &transcript,
            current_time_secs(),
        )
        .await?;
    if let store::SigningAuthorization::Conflict { existing_digest } = authorization {
        bail!(SpecialError::InvalidPeginData(format!(
            "PeginConfirm nonce for {instance_id} is already authorized for transcript {existing_digest}; refusing {transcript}"
        )));
    }
    Ok(())
}

async fn maybe_vote_and_sign_pegin_confirm(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    let Some((instance_parameters, committee_pubkeys, _pub_nonces, agg_nonce, consensus_hash)) =
        pegin_confirm_nonce_consensus_context(ctx, instance_id).await?
    else {
        return Ok(());
    };
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    if let Some(stored_partial_sig) =
        get_committee_partial_sig_for_instance(ctx.local_db, instance_id, &local_committee_pubkey)
            .await?
    {
        // Recreate a missing endorsement while preserving the stored partial signature.
        let stored_endorse_sig = get_committee_endorse_sigs_for_pegin(ctx.local_db, instance_id)
            .await?
            .into_iter()
            .find(|(committee_pubkey, _)| *committee_pubkey == local_committee_pubkey)
            .map(|(_, endorse_sig)| endorse_sig);
        let endorse_sig = match stored_endorse_sig {
            Some(endorse_sig) => endorse_sig,
            None => {
                let pegin_txid = instance_parameters.build_pegin_tx()?.1.tx().compute_txid();
                let endorse_sig = endorse_pegin(ctx.goat_client, instance_id, &pegin_txid)
                    .await?
                    .as_bytes()
                    .to_vec();
                store_committee_endorse_sig_for_pegin(
                    ctx.local_db,
                    instance_id,
                    local_committee_pubkey,
                    endorse_sig.clone(),
                )
                .await?;
                endorse_sig
            }
        };
        publish_stored(
            ctx,
            &format!("pegin-confirm-partial-sig:{instance_id}"),
            Actor::Committee,
            GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                partial_sig: stored_partial_sig,
                endorse_sig,
            }),
            StoredValue::Found,
        )
        .await?;
        return broadcast_pegin_confirm_if_presigned(
            ctx,
            instance_id,
            &instance_parameters,
            &committee_pubkeys,
        )
        .await;
    }

    let consensus_votes =
        get_committee_agg_nonce_consensus_for_instance(ctx.local_db, instance_id).await?;
    if let Some((_, stored_hash, _)) = consensus_votes
        .iter()
        .find(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
        && *stored_hash != consensus_hash
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "local PeginConfirm nonce consensus differs for instance {instance_id}"
        )));
    }
    // Stored, then published: see the same step for graphs in
    // `maybe_vote_and_presign_graph`.
    let local_vote = consensus_votes
        .iter()
        .find(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
        .map(|(_, _, signature)| *signature);
    if local_vote.is_none()
        && signing_closed(ctx, instance_id, "PeginConfirm nonce consensus vote").await?
    {
        return Ok(());
    }
    let (signature, origin) = match local_vote {
        Some(signature) => (signature, StoredValue::Found),
        None => {
            let signature = SECP256K1
                .sign_schnorr(&SecpMessage::from_digest(consensus_hash), &instance_keypair);
            store_committee_agg_nonce_consensus_for_instance(
                ctx.local_db,
                instance_id,
                local_committee_pubkey,
                consensus_hash,
                signature,
            )
            .await?;
            (signature, StoredValue::Fresh)
        }
    };
    publish_stored(
        ctx,
        &format!("pegin-confirm-nonce-consensus:{instance_id}"),
        Actor::Committee,
        GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
            instance_id,
            committee_pubkey: local_committee_pubkey,
            consensus_hash,
            signature,
        }),
        origin,
    )
    .await?;
    if !has_complete_pegin_confirm_nonce_consensus(
        ctx,
        instance_id,
        &committee_pubkeys,
        consensus_hash,
    )
    .await?
    {
        tracing::info!(
            "Defer PeginConfirm partial signature for {instance_id}: waiting for agg nonce consensus"
        );
        return Ok(());
    }

    if signing_closed(ctx, instance_id, "PeginConfirm partial signature").await? {
        return Ok(());
    }
    let (sec_nonce, pub_nonce, _) = committee_master_key
        .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
    // Authorization before the signature (docs/node-protocol.md §10.4): the
    // deterministic nonce signs exactly one transcript, the agreed nonce set.
    authorize_pegin_confirm_signing(ctx.local_db, instance_id, &pub_nonce, consensus_hash).await?;
    let mut pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    let committee_context = instance_parameters.get_committee_context(instance_keypair)?;
    let partial_sig = pegin_confirm
        .sign_input_0_musig2(&committee_context, &sec_nonce, &agg_nonce)
        .map_err(|error| anyhow!("Failed to sign PeginConfirm for {instance_id}: {error}"))?;
    let endorse_sig =
        endorse_pegin(ctx.goat_client, instance_id, &pegin_confirm.tx().compute_txid()).await?;
    store_committee_partial_sig_for_instance(
        ctx.local_db,
        instance_id,
        local_committee_pubkey,
        partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        ctx.local_db,
        instance_id,
        local_committee_pubkey,
        endorse_sig.as_bytes().to_vec(),
    )
    .await?;
    publish_stored(
        ctx,
        &format!("pegin-confirm-partial-sig:{instance_id}"),
        Actor::Committee,
        GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
            instance_id,
            committee_pubkey: local_committee_pubkey,
            partial_sig,
            endorse_sig: endorse_sig.as_bytes().to_vec(),
        }),
        StoredValue::Fresh,
    )
    .await?;
    broadcast_pegin_confirm_if_presigned(ctx, instance_id, &instance_parameters, &committee_pubkeys)
        .await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_nonce_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    pub_nonce: &musig2::PubNonce,
    nonce_sig: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmNonce",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonce
    if !verify_public_nonce(nonce_sig, pub_nonce, &XOnlyPublicKey::from(*received_committee_pubkey))
    {
        tracing::warn!(
            "Ignore PeginConfirmNonce for {instance_id} from {}: invalid pub_nonce or nonce_sig",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    // 2. save the pub_nonce to local db
    store_committee_pub_nonce_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        pub_nonce.clone(),
    )
    .await?;
    redeliver_own_pegin_confirm_value(
        ctx,
        instance_id,
        &format!("pegin-nonce:{instance_id}"),
        received_committee_pubkey,
        content,
    )
    .await?;
    // 3. Agree on the full nonce transcript before generating a partial signature.
    maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_nonce_consensus_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    received_consensus_hash: [u8; 32],
    signature: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmNonceConsensus",
    )
    .await?
    {
        return Ok(());
    }
    let message = make_message(ctx, content);
    let Some((_, _, _, _, expected_consensus_hash)) =
        pegin_confirm_nonce_consensus_context(ctx, instance_id).await?
    else {
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces before validating PeginConfirm nonce consensus",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmNonceConsensus for {instance_id}: waiting for committee pub nonces"
        );
        return Ok(());
    };
    if received_consensus_hash != expected_consensus_hash {
        tracing::warn!(
            "Ignore PeginConfirmNonceConsensus for {instance_id} from {}: consensus hash mismatch",
            received_committee_pubkey
        );
        return Ok(());
    }
    if SECP256K1
        .verify_schnorr(
            signature,
            &SecpMessage::from_digest(expected_consensus_hash),
            &XOnlyPublicKey::from(*received_committee_pubkey),
        )
        .is_err()
    {
        tracing::warn!(
            "Ignore PeginConfirmNonceConsensus for {instance_id} from {}: invalid signature",
            received_committee_pubkey
        );
        return Ok(());
    }
    store_committee_agg_nonce_consensus_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        received_consensus_hash,
        *signature,
    )
    .await?;
    // A locally queued copy is the recovery monitor re-delivering this node's own
    // stored vote, as the nonce and partial-signature handlers do for theirs.
    redeliver_own_pegin_confirm_value(
        ctx,
        instance_id,
        &format!("pegin-confirm-nonce-consensus:{instance_id}"),
        received_committee_pubkey,
        content,
    )
    .await?;
    maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_partial_sig_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    partial_sig: &musig2::PartialSignature,
    endorse_sig: &[u8],
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmPartialSig",
    )
    .await?
    {
        return Ok(());
    }
    let message = make_message(ctx, content);
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces_unchecked.len() != committee_pubkeys.len() {
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmPartialSig for {instance_id}: waiting for committee pub nonces"
        );
        return Ok(());
    }
    let received_pub_nonce = match pub_nonces_unchecked
        .iter()
        .find(|(pubkey, _)| pubkey == received_committee_pubkey)
        .map(|(_, pub_nonce)| pub_nonce.clone())
    {
        Some(pub_nonce) => pub_nonce,
        None => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: missing signer pub nonce",
                received_committee_pubkey
            );
            return Ok(());
        }
    };
    let pub_nonces = match order_committee_values(
        &committee_pubkeys,
        pub_nonces_unchecked,
        "pegin committee pub nonces",
    ) {
        Ok(pub_nonces) => pub_nonces,
        Err(e) => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid pub nonce set: {e}",
                received_committee_pubkey
            );
            return Ok(());
        }
    };
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let instance_params = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let consensus_hash =
        pegin_confirm_nonce_consensus_hash(&instance_params, &committee_pubkeys, &pub_nonces)?;
    if !has_complete_pegin_confirm_nonce_consensus(
        ctx,
        instance_id,
        &committee_pubkeys,
        consensus_hash,
    )
    .await?
    {
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            30,
            MessageDeferReason::CommitteeNonceConsensusPending,
            "waiting for committee PeginConfirm agg nonce consensus",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmPartialSig for {instance_id}: waiting for agg nonce consensus"
        );
        return Ok(());
    }
    if let Err(e) = verify_pegin_confirm_partial_sig(
        &instance_params,
        &committee_pubkeys,
        received_committee_pubkey,
        &received_pub_nonce,
        &agg_nonce,
        *partial_sig,
    ) {
        tracing::warn!(
            "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid partial signature: {e}",
            received_committee_pubkey
        );
        return Ok(());
    }
    let pegin_confirm = instance_params.build_pegin_tx()?.1;
    let pegin_txid = pegin_confirm.tx().compute_txid();
    match verify_pegin_endorsement(
        ctx.goat_client,
        instance_id,
        received_committee_pubkey,
        &pegin_txid,
        endorse_sig,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid endorsement signature",
                received_committee_pubkey
            );
            return Ok(());
        }
        Err(e) => {
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                30,
                MessageDeferReason::ValidationRetry,
                &format!("failed to verify committee endorsement signature: {e}"),
            )
            .await?;
            tracing::warn!(
                "Retry PeginConfirmPartialSig later for {instance_id} from {}: failed to verify endorsement signature: {e}",
                received_committee_pubkey
            );
            return Ok(());
        }
    }
    // 1. save the validated partial signature & endorsement signature to local db
    store_committee_partial_sig_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        *partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        endorse_sig.to_owned(),
    )
    .await?;
    redeliver_own_pegin_confirm_value(
        ctx,
        instance_id,
        &format!("pegin-confirm-partial-sig:{instance_id}"),
        received_committee_pubkey,
        content,
    )
    .await?;
    broadcast_pegin_confirm_if_presigned(ctx, instance_id, &instance_params, &committee_pubkeys)
        .await
}

/// The T0 gate (docs/node-protocol.md §10.2): no new protocol signature for
/// an instance in F or at `h >= H_p + T0`. Stored values may still be re-sent.
async fn signing_closed(ctx: &HandlerContext<'_>, instance_id: Uuid, what: &str) -> Result<bool> {
    match signing_gate(ctx.local_db, ctx.btc_client, instance_id).await? {
        SigningGate::Open => Ok(false),
        SigningGate::Closed(reason) => {
            tracing::info!(
                event = "signing_gate",
                instance_id = %instance_id,
                what,
                reason = %reason,
                "refusing to produce a new protocol signature"
            );
            Ok(true)
        }
    }
}

/// The relayer broadcasts Peg-In-Confirm only before T0 and while no
/// Peg-In-Cancel is confirmed (docs/node-protocol.md §10.2).
async fn pegin_confirm_broadcast_blocked(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<Option<String>> {
    let instance = ctx.local_db.acquire().await?.find_instance(&instance_id).await?;
    let Some(instance) = instance else {
        return Ok(Some("instance not found".to_string()));
    };
    if let SigningGate::Closed(reason) =
        signing_gate(ctx.local_db, ctx.btc_client, instance_id).await?
    {
        return Ok(Some(reason));
    }
    if let Some(cancel_txid) = instance.pegin_cancel_txid
        && let Some(cancel_tx) = ctx.btc_client.get_tx_info(&cancel_txid.0).await?
        && cancel_tx.status.confirmed
    {
        return Ok(Some(format!("Peg-In-Cancel {} is confirmed", cancel_txid.0)));
    }
    Ok(None)
}

/// Local operator policy (docs/node-protocol.md §10.2): no new graph for an
/// instance in F or past `Prepare height + OPERATOR_GRAPH_START_CUTOFF_BLOCKS`.
async fn graph_start_blocked(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<Option<String>> {
    let instance = ctx.local_db.acquire().await?.find_instance(&instance_id).await?;
    let Some(instance) = instance else {
        return Ok(None);
    };
    if let Ok(status) = InstanceBridgeInStatus::from_str(&instance.status)
        && status.is_failed()
    {
        return Ok(Some(format!("instance is {status}")));
    }
    if instance.btc_height > 0 {
        let cutoff = instance.btc_height + get_operator_graph_start_cutoff_blocks();
        let height = i64::from(ctx.btc_client.get_height().await?);
        if height > cutoff {
            return Ok(Some(format!("height {height} is past the graph start cutoff {cutoff}")));
        }
    }
    Ok(None)
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by InitWithdraw event from GoatChain
    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(ctx.local_db, instance_id, graph_id, &message).await? {
        Some(g) => g,
        None => return Ok(()),
    };
    let mut graph = BitvmGcGraph::from_simplified(&graph)?;
    let operator_pubkey = graph.parameters.operator_pubkey;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let node_pubkey: PublicKey = operator_master_key.master_keypair().public_key().into();
    if node_pubkey != operator_pubkey {
        tracing::warn!("Ignore KickoffReady for {instance_id}:{graph_id}: not my graph");
        return Ok(());
    }
    // 1. check the withdraw status on GoatChain
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffReady for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    // 2. check prekickoff nonce & broadcast previous pre-kickoff if needed
    let start_nonce =
        match get_latest_pegout_finalized_graph(ctx.local_db, &operator_pubkey).await? {
            Some((n, _)) => n + 1,
            None => 0,
        };
    for current_nonce in start_nonce..graph.parameters.graph_nonce {
        let (current_instance_id, current_graph_id) = match get_graph_id_by_nonce(
            ctx.local_db,
            current_nonce,
            &operator_pubkey,
        )
        .await?
        {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: missing previous graph {current_nonce}"
                );
                return Ok(());
            }
        };
        let current_graph =
            match get_graph_or_defer(ctx.local_db, current_instance_id, current_graph_id, &message)
                .await?
            {
                Some(g) => g,
                None => return Ok(()),
            };
        let mut current_graph = BitvmGcGraph::from_simplified(&current_graph)?;
        let current_graph_refresh = refresh_graph(
            ctx.local_db,
            ctx.btc_client,
            ctx.goat_client,
            current_instance_id,
            current_graph_id,
            &current_graph,
        )
        .await?;
        let current_graph_status = current_graph_refresh.status;
        if current_graph_refresh.status_transition_accepted {
            compensate_graph_events(
                ctx.local_db,
                ctx.btc_client,
                current_instance_id,
                current_graph_id,
                &current_graph,
                current_graph_refresh.scan.as_ref(),
                // This is a recovery scan, not a transition from the local
                // projection. Start from the protocol baseline so a previous
                // crash between status persistence and message enqueue can be
                // repaired by idempotent message upserts.
                GraphStatus::OperatorPresigned,
                current_graph_status,
            )
            .await?;
        }
        if current_graph_status.is_closed() {
            continue;
        } else if current_graph_status.is_pegout_started() {
            tracing::warn!(
                "Ignore KickoffReady for {instance_id}:{graph_id}: previous graph {current_graph_id} already started pegout"
            );
            let nonce_interval =
                graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
            let min_pegout_time_secs = take1_timelock_with_config(
                ctx.btc_client.network(),
                &current_graph.parameters.timelock_config,
            ) as u64
                * avg_block_time_secs(ctx.btc_client.network());
            let delay_secs = min_pegout_time_secs * nonce_interval;
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::PreviousGraphPending,
                "previous graph has an active pegout flow",
            )
            .await?;
            return Ok(());
        } else if current_graph_status.is_obsoleted() {
            operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
            tracing::info!(
                "Operator {operator_pubkey} skipped obsoleted graph {current_instance_id}:{current_graph_id}"
            );
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::ChainStatePending,
                "waiting for the previous obsoleted graph skip transaction to propagate",
            )
            .await?;
            return Ok(());
        } else {
            let graph_data_on_goat =
                ctx.goat_client.gateway_get_graph_data(&current_graph_id).await?;
            if graph_data_on_goat.operator_pubkey != [0u8; 32] {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: previous available graph exists for Operator {operator_pubkey}: {current_instance_id}:{current_graph_id}, please withdraw it first"
                );
                let nonce_interval =
                    graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
                let min_pegout_time_secs = take1_timelock_with_config(
                    ctx.btc_client.network(),
                    &current_graph.parameters.timelock_config,
                ) as u64
                    * avg_block_time_secs(ctx.btc_client.network());
                let delay_secs = min_pegout_time_secs * nonce_interval;
                defer_or_enqueue_message(
                    ctx.local_db,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::PreviousGraphPending,
                    "previous graph is available for pegout",
                )
                .await?;
                return Ok(());
            } else {
                operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
                tracing::info!(
                    "Operator {operator_pubkey} skipped non-posted graph {current_instance_id}:{current_graph_id}"
                );
                let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
                defer_or_enqueue_message(
                    ctx.local_db,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::ChainStatePending,
                    "waiting for the previous graph skip transaction to propagate",
                )
                .await?;
                return Ok(());
            }
        }
    }
    // 3. sign & broadcast prekickoff & kickoff txns
    operator_kickoff(ctx.btc_client, &mut graph).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    // 1. update status
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorKickOff)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) try to call Gateway.proceedWithdraw
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_tx = match ctx.btc_client.get_tx(&kickoff_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not found on chain: {kickoff_txid}"
            );
            return Ok(());
        }
    };
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "kickoff transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_btc_height < kickoff_height {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network())
            * (kickoff_height - goat_confirmed_btc_height);
        let message = make_message(ctx, content);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "kickoff block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client.gateway_process_withdraw(ctx.btc_client, &graph_id, &kickoff_tx).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check kickoff tx status on Bitcoin chain
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            // Retry after Bitcoin confirmation.
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "kickoff transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry KickoffSent later for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
            );
            return Ok(());
        }
    };
    handle_previous_graph_after_prekickoff(ctx, instance_id, graph_id, &graph, &message).await?;
    let take1_txid = graph.take1.tx().compute_txid();
    let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
    let kickoff_challenge_outpoint = challenge_tx.input[0].previous_output;
    if let Some(spent_txid) = outpoint_spent_txid(
        ctx.btc_client,
        &kickoff_challenge_outpoint.txid,
        kickoff_challenge_outpoint.vout as u64,
    )
    .await?
    {
        let spent_tx_name = if spent_txid == take1_txid { "Take1" } else { "Challenge" };
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: challenge connector already spent by {spent_tx_name} tx: {spent_txid}"
        );
        return Ok(());
    }
    // 2. check withdraw status, if it's invalid, sign & broadcast challenge txn
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await? as u32;
    if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
        if kickoff_height >= goat_confirmed_btc_height {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network())
                * (kickoff_height - goat_confirmed_btc_height) as u64;
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::GoatSpvPending,
                "kickoff block is not available through GOAT SPV",
            )
            .await?;
            tracing::info!(
                "Retry Challenge later for {instance_id}:{graph_id}: kickoff tx block is not posted to GOAT SPV yet"
            );
            return Ok(());
        }

        let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
        let challenge_txid = challenge_tx.compute_txid();
        if ctx.btc_client.get_tx(&challenge_txid).await?.is_none() {
            send_challenge_tx(ctx.btc_client, &graph).await?;
        }
    } else {
        tracing::info!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: withdraw already initiated, status: {withdraw_status:?}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let _graph = refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?;
    Ok(())
}

async fn handle_previous_graph_after_prekickoff(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
    message: &GOATMessage,
) -> Result<()> {
    if !tx_on_chain(
        ctx.btc_client,
        &graph.parameters.prekickoff_parameters.cur_prekickoff_txn.tx().compute_txid(),
    )
    .await?
    {
        tracing::warn!(
            "Ignore prekickoff follow-up for {instance_id}:{graph_id}: prekickoff tx not on chain"
        );
        return Ok(());
    }

    let graph_nonce = graph.parameters.graph_nonce;
    if graph_nonce == 0 {
        return Ok(());
    }

    let (prev_instance_id, prev_graph_id) =
        get_graph_id_by_nonce(ctx.local_db, graph_nonce - 1, &graph.parameters.operator_pubkey)
            .await?
            .ok_or_else(|| anyhow!("Prev graph not found for {instance_id}:{graph_id}"))?;
    let prev_graph =
        match get_graph_or_defer(ctx.local_db, prev_instance_id, prev_graph_id, message).await? {
            Some(g) => g,
            None => return Ok(()),
        };
    let prev_graph = BitvmGcGraph::from_simplified(&prev_graph)?;
    let (prev_graph_status, _prev_graph_sub_status, status_transition_accepted) =
        refresh_and_compensate(
            ctx,
            prev_instance_id,
            prev_graph_id,
            &prev_graph,
            // Do not use the persisted status as a compensation anchor: it
            // may have been committed just before a crash. Idempotent message
            // upserts make a baseline recovery scan safe to retry.
            GraphStatus::OperatorPresigned,
        )
        .await?;
    if !status_transition_accepted {
        tracing::warn!(
            "Ignore prekickoff follow-up for {instance_id}:{graph_id}: previous graph status scan was rejected"
        );
        return Ok(());
    }
    if !tx_on_chain(ctx.btc_client, &prev_graph.kickoff.tx().compute_txid()).await? {
        verifier_force_skip_kickoff(ctx.btc_client, &prev_graph).await?;
    } else if !prev_graph_status.is_closed() {
        verifier_quick_challenge(ctx.btc_client, &prev_graph).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by PreKickoff tx
    let message = make_message(ctx, content);
    let graph = match get_graph_for_refresh_or_defer(ctx, instance_id, graph_id, &message).await? {
        Some(graph) => graph,
        None => return Ok(()),
    };

    let (_, _, status_transition_accepted) =
        refresh_and_compensate(ctx, instance_id, graph_id, &graph, GraphStatus::PreKickoff).await?;
    if !status_transition_accepted {
        // PreKickoffSent may arrive after KickoffSent or an event-watcher
        // update. The state transition is then correctly rejected as stale,
        // but the confirmed pre-kickoff still proves that the previous graph
        // must be reconciled.
        tracing::info!(
            event = "prekickoff_reconciliation",
            outcome = "current_status_stale",
            "reconciling previous graph despite stale PreKickoff transition"
        );
    }

    // Check the previous graph independently from whether this graph could
    // still transition to PreKickoff. The helper revalidates the on-chain
    // pre-kickoff transaction before it can broadcast any disprove action.
    handle_previous_graph_after_prekickoff(ctx, instance_id, graph_id, &graph, &message).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by PreKickoff tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::PreKickoff).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Challenge tx
    let message = make_message(ctx, content);
    let (mut graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check the challenge tx status on Bitcoin chain
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: watchtower challenge init already sent"
        );
        return Ok(());
    }
    if let Some(challenge_tx) = ctx.btc_client.get_tx(&challenge_txid).await? {
        let challenge_outpoint = graph
            .kickoff
            .connector_a_input()
            .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?
            .outpoint;
        if challenge_tx.input[0].previous_output != challenge_outpoint {
            tracing::warn!(
                "Ignore ChallengeSent for {instance_id}:{graph_id}: invalid challenge tx input"
            );
            return Ok(());
        }
    } else {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: challenge tx not found on chain"
        );
        return Ok(());
    }
    // 2. if the challenge is confirmed, sign & broadcast watchtower-challenge-init txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let watchtower_challenge_init_tx =
        operator_sign_watchtower_challenge_init(operator_master_key.master_keypair(), &mut graph)?;
    let anchor_vout = watchtower_challenge_init_tx.output.len() as u64 - 1;
    let watchtower_challenge_init_tx_total_input_amount =
        graph.watchtower_challenge_init.prev_outs().iter().map(|o| o.value).sum();
    let child_tx = build_cpfp_txns(
        ctx.btc_client,
        &watchtower_challenge_init_tx,
        anchor_vout,
        watchtower_challenge_init_tx_total_input_amount,
    )
    .await?;
    match child_tx {
        Some(tx) => {
            broadcast_package(ctx.btc_client, &[watchtower_challenge_init_tx, tx], true).await?
        }
        None => broadcast_tx(ctx.btc_client, &watchtower_challenge_init_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Challenge tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_init_sent_watchtower(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by WatchtowerChallengeInit tx
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let node_index = match graph
        .parameters
        .watchtower_pubkeys
        .iter()
        .position(|pk| *pk == watchtower_keypair.public_key().x_only_public_key().0)
    {
        Some(index) => index,
        None => {
            tracing::warn!(
                "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: node not a watchtower"
            );
            return Ok(());
        }
    };
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge init not on chain"
        );
        return Ok(());
    }
    let watchtower_challenge_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(node_index) as u64;
    if outpoint_spent_txid(
        ctx.btc_client,
        &watchtower_challenge_init_txid,
        watchtower_challenge_vout,
    )
    .await?
    .is_some()
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge already spent"
        );
        return Ok(());
    }
    // watchtower should always challenge
    let watchtower_proof = match get_watchtower_commitment(
        ctx.local_db,
        ctx.btc_client,
        ctx.http_client,
        instance_id,
        graph_id,
    )
    .await?
    {
        (Some(p), _) => p,
        (None, wait_secs) => {
            tracing::warn!(
                "Retry WatchtowerChallengeInitSent for {instance_id}:{graph_id} later: watchtower proof not ready, retry after {wait_secs} seconds"
            );
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                wait_secs,
                MessageDeferReason::ProofPending,
                "watchtower proof commitment is not ready",
            )
            .await?;
            return Ok(());
        }
    };
    let watchtower_challenge_txid = match send_watchtower_challenge_tx(
        ctx.btc_client,
        &graph,
        node_index,
        watchtower_proof,
    )
    .await
    {
        Ok(txid) => txid,
        Err(e) => {
            // Retry broadcast failures until the connector is spent.
            tracing::warn!(
                "Retry WatchtowerChallengeInitSent for {instance_id}:{graph_id} later: failed to send watchtower challenge tx: {e}"
            );
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                30,
                MessageDeferReason::BitcoinTransactionPending,
                "watchtower challenge transaction could not be broadcast",
            )
            .await?;
            return Ok(());
        }
    };
    tracing::info!(
        "WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower_index={node_index}, txid={watchtower_challenge_txid}"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id, watchtower_index = watchtower_index))]
async fn handle_watchtower_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    watchtower_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;
    if watchtower_index >= watchtower_num {
        bail!("watchtower index {watchtower_index} out of range for {watchtower_num} slots");
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index) as u64;
    let Some((watchtower_spent_txid, watchtower_vin, _txin)) =
        outpoint_spent_txin(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
    else {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} is not spent yet"
        );
        return Ok(());
    };
    if watchtower_vin != 0 {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by tx {watchtower_spent_txid} at unexpected input index {watchtower_vin}"
        );
        return Ok(());
    }
    let timeout_txid = graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
    if watchtower_spent_txid == timeout_txid {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by timeout tx {timeout_txid}"
        );
        return Ok(());
    }

    let ack_vout =
        output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
    if let Some(spent_txid) =
        outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout).await?
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: ack connector {watchtower_index} already spent by {spent_txid}"
        );
        return Ok(());
    }

    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let preimage = operator_master_key.preimage_for_graph(graph_id, watchtower_index);
    let ack_connector_input = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|e| anyhow!("failed to get ack connector input: {e}"))?;
    let ack_input = operator_sign_challenge_ack(&graph, watchtower_index, &preimage)?;
    let ack_txid = build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_master_key.master_keypair(),
        vec![ack_input],
        ack_connector_input.amount,
        vec![goat::scripts::p2a_output()],
    )
    .await?;
    tracing::info!(
        "Operator challenge ACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={ack_txid}"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_timeout_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }

    let watchtower_num = validate_watchtower_branches(&graph)?;
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
            .is_some()
            || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
                .await?
                .is_some()
        {
            continue;
        }

        let timeout_tx = operator_sign_watchtower_challenge_timeout(
            operator_master_key.master_keypair(),
            &mut graph,
            watchtower_index,
        )?;
        if tx_on_chain(ctx.btc_client, &timeout_tx.compute_txid()).await? {
            continue;
        }
        let timeout_txid = timeout_tx.compute_txid();
        let timeout_tx_total_input_amount = graph.watchtower_challenge_timeouts[watchtower_index]
            .prev_outs()
            .iter()
            .map(|o| o.value)
            .sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
        tracing::info!(
            "Watchtower challenge timeout sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={timeout_txid}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nack_ready_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore NackReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
        .await?
        .is_some()
    {
        tracing::warn!("Ignore NackReady for {instance_id}:{graph_id}: connector-F already spent");
        return Ok(());
    }

    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let Some(watchtower_spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
                .await?
        else {
            continue;
        };

        let timeout_txid =
            graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
        if watchtower_spent_txid == timeout_txid {
            continue;
        }

        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
            .await?
            .is_some()
        {
            continue;
        }

        let nack = graph
            .operator_challenge_nacks
            .get(watchtower_index)
            .ok_or_else(|| anyhow!("invalid watchtower index {watchtower_index}"))?;
        let nack_tx = nack.tx().clone();
        let nack_txid = nack_tx.compute_txid();
        if tx_on_chain(ctx.btc_client, &nack_txid).await? {
            return Ok(());
        }
        let nack_tx_total_input_amount = nack.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, nack_tx, nack_tx_total_input_amount).await?;
        tracing::info!(
            "Operator challenge NACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={nack_txid}"
        );
        return Ok(());
    }

    tracing::warn!(
        "Ignore NackReady for {instance_id}:{graph_id}: no watchtower branch is ready for NACK"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let Some((graph, _graph_status, _graph_sub_status)) =
        refresh_graph_status(ctx, instance_id, graph_id, Some(&message), GraphStatus::Challenge)
            .await?
    else {
        return Ok(());
    };

    // compute the 96-byte guest pubin
    let watchtower_challenge_init_txid =
        SerializableTxid::from(graph.watchtower_challenge_init.tx().compute_txid());
    let num_watchtowers = graph.parameters.watchtower_pubkeys.len();
    let watchtower_timeout_txids: Vec<Txid> =
        graph.watchtower_challenge_timeouts.iter().map(|tx| tx.tx().compute_txid()).collect();
    let wait_secs = avg_block_time_secs(ctx.btc_client.network()) as usize;
    let WatchtowerChallengeInfo {
        included_watchtowers: included_watchtowers_bits,
        resolved_branch_txids,
        ..
    } = match get_watchtower_challenge_info(
        ctx.btc_client,
        &watchtower_challenge_init_txid,
        &watchtower_timeout_txids,
        num_watchtowers,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::info!(
                "Retry OperatorCommitPubinReady later for {instance_id}:{graph_id}: challenge info is not ready: {e}"
            );
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                wait_secs,
                MessageDeferReason::ProtocolInputsPending,
                "watchtower challenge branches are not resolved yet",
            )
            .await?;
            return Ok(());
        }
    };
    let (btc_best_block_hash, included_watchtowers_bitmap) =
        match compute_operator_pubin_blockhash_and_bitmap(
            ctx.btc_client,
            &resolved_branch_txids,
            &included_watchtowers_bits,
        )
        .await
        {
            Ok(inputs) => inputs,
            Err(e) => {
                tracing::info!(
                    "Retry OperatorCommitPubinReady later for {instance_id}:{graph_id}: operator pubin inputs are not ready: {e}"
                );
                defer_or_enqueue_message(
                    ctx.local_db,
                    &message,
                    wait_secs,
                    MessageDeferReason::ProtocolInputsPending,
                    &e.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
    let guest_pubin = build_operator_guest_pubin(
        &btc_best_block_hash,
        &graph.parameters.pubin_disprove_constant,
        &included_watchtowers_bitmap,
    );

    // sign and broadcast
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let commit_pubin_wots_sk = operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id).0;
    let signed_input = operator_sign_commit_pubin(&graph, &commit_pubin_wots_sk, &guest_pubin)?;
    let connector_e_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow!("failed to get connector-e input: {e}"))?
        .amount;
    let operator_keypair = operator_master_key.master_keypair();
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_keypair,
        vec![signed_input],
        connector_e_amount,
        vec![],
    )
    .await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let connector_e_vout =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_e_vout)
        .await?
        .is_some()
        || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
            .await?
            .is_some()
    {
        tracing::warn!(
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: timeout input already spent"
        );
        return Ok(());
    }

    let timeout_tx = graph.operator_commit_timeout.tx().clone();
    let timeout_txid = timeout_tx.compute_txid();
    if tx_on_chain(ctx.btc_client, &timeout_txid).await? {
        return Ok(());
    }
    let timeout_tx_total_input_amount =
        graph.operator_commit_timeout.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
    tracing::info!(
        "Operator commit pubin timeout sent for {instance_id}:{graph_id}: txid={timeout_txid}"
    );
    Ok(())
}

// after the watchtower challenge flow is complete, build proof and broadcast Assert transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
    );
    let (mut graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    let (operator_proof, wait_secs) = get_operator_proof(
        ctx.local_db,
        ctx.http_client,
        &graph,
        ctx.btc_client,
        instance_id,
        graph_id,
    )
    .await?;

    if wait_secs > 0 {
        tracing::info!(
            "Retry AssertReady later for {instance_id}:{graph_id}: operator proof is not ready"
        );
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            wait_secs,
            MessageDeferReason::ProofPending,
            "operator proof is not ready",
        )
        .await?;
        return Ok(());
    }

    let Some(operator_proof) = operator_proof else {
        return Ok(());
    };
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let assert_secret_key = operator_master_key.assert_wots_keypair_for_graph(graph_id).0;

    let dynamic_input = operator_assert_dynamic_input(&operator_proof.public_inputs)?;
    let assert_witness =
        build_assert_witness(&operator_proof.proof, &assert_secret_key, dynamic_input)?;
    let assert_message = assert_wots_message(&assert_witness)?;
    let mut asserted_operator_proof = Vec::new();
    operator_proof.proof.serialize_compressed(&mut asserted_operator_proof)?;
    let mut setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    if let Some(existing) = &operator_state.asserted_operator_proof
        && existing != &asserted_operator_proof
    {
        bail!("operator assertion proof conflicts with persisted proof");
    }
    operator_state.asserted_operator_proof = Some(asserted_operator_proof);
    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &setup_state)?;

    let assert_tx = operator_sign_assert(
        &mut graph,
        &assert_secret_key,
        &assert_message,
        &assert_witness.pi2,
        &assert_witness.pi3,
    )?;
    let assert_tx_total_input_amount =
        graph.operator_assert.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, assert_tx, assert_tx_total_input_amount).await?;

    Ok(())
}

/// Recovers a `BabeChallengeAssertWitness` from the on-chain challenge assert tx.
fn recover_challenge_assert_witness(
    challenge_assert_tx: &bitcoin::Transaction,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    let txin = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("challenge assert tx has no input"))?;
    let items: Vec<Vec<u8>> = txin.witness.to_vec();
    let expected_len = 2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM + 2;
    if items.len() != expected_len {
        bail!(
            "unexpected challenge assert witness length: {} (expected {expected_len})",
            items.len()
        );
    }
    let mut bitcoin_witness = bitcoin::Witness::new();
    for item in &items[..2 * WOTS_SIG_COUNT] {
        bitcoin_witness.push(item);
    }
    let wots_sig = Wots96::raw_witness_to_signature(&bitcoin_witness).to_vec();
    let input_labels: Vec<[u8; 16]> = items
        [2 * WOTS_SIG_COUNT..2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM]
        .iter()
        .map(|item| item.as_slice().try_into())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("challenge assert label item is not 16 bytes"))?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: ChallengeAssertWitnessRaw { input_labels, wots_sig },
    })
}

/// Collects the on-chain ACK TxIns from all watchtowers that submitted a challenge_ack.
/// Unspent ACK connectors are skipped; spent connectors must resolve to the spending input.
async fn collect_ack_txins(
    btc_client: &BTCClient,
    wci_txid: &Txid,
    watchtower_timeout_txids: &[Txid],
) -> Result<Vec<bitcoin::TxIn>> {
    let mut ack_txins = Vec::new();
    for (i, timeout_txid) in watchtower_timeout_txids.iter().enumerate() {
        let ack_vout = output_topology::watchtower_challenge_init::ack_connector(i) as u64;
        let Some(ack_spent_txid) = outpoint_spent_txid(btc_client, wci_txid, ack_vout).await?
        else {
            continue;
        };
        if &ack_spent_txid == timeout_txid {
            continue;
        }
        let Some((_spent_txid, _vin, txin)) =
            outpoint_spent_txin(btc_client, wci_txid, ack_vout).await?
        else {
            bail!("ACK spending tx {ack_spent_txid} for watchtower {i} is unavailable");
        };
        ack_txins.push(txin);
    }
    Ok(ack_txins)
}

// verify Operator DynamicPublicInput and Proof; broadcast PubinDisprove or ChallengeAssert as needed.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };

    let Some(assert_tx) = ctx.btc_client.get_tx(&assert_txid).await? else {
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: assert tx {assert_txid} not found on chain"
        );
        return Ok(());
    };

    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(());
    };
    validate_verifier_slot(&graph, verifier_index)?;

    // ChallengeAssert may only be skipped after this graph's commit-pubin is
    // on-chain and proves consistent with the assert witness. OperatorAssert
    // can otherwise be broadcast before connector-E is spent.
    let connector_e_input = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|error| anyhow!("failed to resolve connector-E input: {error}"))?;
    let connector_e_outpoint = connector_e_input.outpoint;
    let Some(connector_e_spent_txid) = outpoint_spent_txid(
        ctx.btc_client,
        &connector_e_outpoint.txid,
        connector_e_outpoint.vout as u64,
    )
    .await?
    else {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network());
        let message = make_message(ctx, content);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::ProtocolInputsPending,
            "operator commit-pubin is not on chain yet",
        )
        .await?;
        tracing::info!(
            "Retry AssertSent later for {instance_id}:{graph_id}: operator commit-pubin is not on chain yet"
        );
        return Ok(());
    };

    let mut pubin_consistent = false;
    if connector_e_spent_txid != graph.operator_commit_timeout.tx().compute_txid() {
        if !ctx.btc_client.get_tx_status(&connector_e_spent_txid).await?.confirmed {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::ProtocolInputsPending,
                "operator commit-pubin transaction is not confirmed yet",
            )
            .await?;
            return Ok(());
        }
        let Some(commit_pubin_tx) = ctx.btc_client.get_tx(&connector_e_spent_txid).await? else {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::ProtocolInputsPending,
                "operator commit-pubin transaction is not available yet",
            )
            .await?;
            return Ok(());
        };
        let assert_txin = assert_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
        let commit_pubin_txin = commit_pubin_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator commit-pubin transaction has no input"))?;
        let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let watchtower_timeout_txids = graph
            .watchtower_challenge_timeouts
            .iter()
            .map(|tx| tx.tx().compute_txid())
            .collect::<Vec<_>>();
        let ack_txins =
            match collect_ack_txins(ctx.btc_client, &wci_txid, &watchtower_timeout_txids).await {
                Ok(txins) => txins,
                Err(error) => {
                    let delay_secs = avg_block_time_secs(ctx.btc_client.network());
                    let message = make_message(ctx, content);
                    defer_or_enqueue_message(
                        ctx.local_db,
                        &message,
                        delay_secs as usize,
                        MessageDeferReason::ProtocolInputsPending,
                        &format!("operator ACK inputs are not ready: {error}"),
                    )
                    .await?;
                    return Ok(());
                }
            };
        match validate_pubin_disprove(&graph, commit_pubin_txin, assert_txin, &ack_txins) {
            Ok(Some((witness_data, _))) => {
                // PubinDisprove is not pre-signed, so fund it directly rather
                // than relying on CPFP.
                let pubin_disprove_tx_total_input_amount = graph
                    .operator_assert
                    .connector_d_input()
                    .map_err(|e| anyhow!("failed to get connector-d input: {e}"))?
                    .amount;
                let pubin_disprove_txin = build_pubin_disprove_txin(&graph, witness_data)?;
                let pubin_disprove_tx = bitcoin::Transaction {
                    version: bitcoin::transaction::Version(2),
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![pubin_disprove_txin],
                    output: vec![
                        goat::scripts::p2a_output(),
                        // Keep the transaction above Bitcoin Core's minimum
                        // non-witness relay size.
                        bitcoin::TxOut {
                            value: Amount::ZERO,
                            script_pubkey: goat::scripts::generate_opreturn_script(
                                PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                            ),
                        },
                    ],
                };
                let verifier_keypair = VerifierMasterKey::new(get_bitvm_key()?).master_keypair();
                build_sign_and_broadcast_tx(
                    ctx.btc_client,
                    verifier_keypair,
                    pubin_disprove_tx.input,
                    pubin_disprove_tx_total_input_amount,
                    pubin_disprove_tx.output,
                )
                .await?;
                return Ok(());
            }
            Ok(None) => {
                pubin_consistent = true;
            }
            Err(error) => tracing::warn!(
                "PubinDisprove validation failed for {instance_id}:{graph_id}: {error}; proceeding to ChallengeAssert"
            ),
        }
    }

    // recover TxAssertWitness from the assert tx witness.
    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(&graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;
    if pubin_consistent && assert_witness.verify_groth16_proof(&vk, &[static_input]) {
        tracing::info!(
            "Skip ChallengeAssert for {instance_id}:{graph_id}: operator assert proof is valid"
        );
        return Ok(());
    }

    let strict = false;
    broadcast_verifier_challenge_assert_tx(
        ctx.local_db,
        ctx.btc_client,
        &graph,
        instance_id,
        graph_id,
        &assert_tx,
        strict,
    )
    .await?;

    Ok(())
}

const PUBIN_DISPROVE_OP_RETURN_DATA: &[u8] = b"pubin-disprove";

pub async fn broadcast_verifier_challenge_assert_tx(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_tx: &bitcoin::Transaction,
    strict: bool,
) -> Result<Option<(Txid, usize)>> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        if strict {
            bail!("local verifier has no graph slot for {instance_id}:{graph_id}");
        }
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(None);
    };
    validate_verifier_slot(graph, verifier_index)?;

    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;

    let Some(saved_verifier_state) =
        load_babe_setup_state(local_db, instance_id, graph_id)?.and_then(|state| state.verifier)
    else {
        if strict {
            bail!("missing BABE verifier setup state for {instance_id}:{graph_id}");
        }
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: missing BABE verifier setup state"
        );
        return Ok(None);
    };
    if saved_verifier_state.soldering_proof_ready.is_none() {
        if strict {
            bail!("missing soldering proof reference for {instance_id}:{graph_id}");
        }
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: missing soldering proof reference"
        );
        return Ok(None);
    }
    let challenge_witness = build_real_challenge_assert_witness(
        &saved_verifier_state.private_state,
        &saved_verifier_state.setup_package,
        &saved_verifier_state.finalized_indices,
        &vk,
        static_input,
        &assert_witness,
        verifier_index,
    )?;
    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txin = assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let challenge_assert_tx =
        build_verifier_assert_tx(graph, operator_assert_txin, verifier_index, labels)?;
    let challenge_assert_txid = challenge_assert_tx.compute_txid();
    if btc_client.get_tx(&challenge_assert_txid).await?.is_some() {
        tracing::info!(
            "Verifier ChallengeAssert already exists for {instance_id}:{graph_id}: verifier_index={verifier_index}, txid={challenge_assert_txid}"
        );
        return Ok(Some((challenge_assert_txid, verifier_index)));
    }
    let challenge_assert_tx_total_input_amount =
        graph.verifier_asserts[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc_client, challenge_assert_tx, challenge_assert_tx_total_input_amount)
        .await?;

    Ok(Some((challenge_assert_txid, verifier_index)))
}

// compute msg after ChallengeAssert is broadcast and broadcast WronglyChallenge transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_assert_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    validate_verifier_slot(&graph, verifier_index)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;

    let Some(challenge_assert_tx) = ctx.btc_client.get_tx(&challenge_assert_txid).await? else {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network());
        let message = make_message(ctx, content);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::BitcoinTransactionPending,
            "ChallengeAssert transaction is not available from the Bitcoin backend",
        )
        .await?;
        tracing::info!(
            "Retry ChallengeAssertSent later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    };

    let challenge_witness = recover_challenge_assert_witness(&challenge_assert_tx, verifier_index)?;
    validate_challenge_witness_index(verifier_index, &challenge_witness)?;

    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txid = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("published verifier assert transaction has no input"))?
        .previous_output
        .txid;
    let operator_assert_tx =
        ctx.btc_client.get_tx(&operator_assert_txid).await?.ok_or_else(|| {
            anyhow!("published operator assert transaction {operator_assert_txid} is unavailable")
        })?;
    let operator_assert_txin = operator_assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("published operator assert transaction has no input"))?;
    let operator_assert_witness = extract_operator_assert_witness(&graph, &operator_assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let expected_challenge_assert =
        build_verifier_assert_tx(&graph, operator_assert_txin.clone(), verifier_index, labels)?;
    if expected_challenge_assert.input.first().map(|input| &input.witness)
        != challenge_assert_tx.input.first().map(|input| &input.witness)
    {
        bail!("published verifier assert witness does not match BABE challenge labels");
    }

    let setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let candidate = selected_candidate_for_graph_index(&operator_state, verifier_index)?;
    let soldering_proof_ready = candidate.soldering_proof_ready.as_ref().ok_or_else(|| {
        anyhow!("missing soldering proof reference for verifier slot {verifier_index}")
    })?;
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        soldering_proof_ready.candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = read_soldering_proof_store_payload(&payload_path)
        .await
        .with_context(|| format!("read soldering proof payload from {payload_path}"))?;
    let payload = decode_soldering_proof_payload(soldering_proof_ready, &payload)?;
    let (_, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand compact soldering proof payload for challenge")?;
    let prover_state = build_babe_prover_state(&candidate.setup_package, finalized, soldering)?;
    let assert_witness = TxAssertWitness {
        wots_sig: challenge_witness.witness.wots_sig.clone(),
        pi2: operator_assert_witness.pi2,
        pi3: operator_assert_witness.pi3,
    };
    let proof = recover_operator_proof_from_assert_witness(&assert_witness)
        .context("recover asserted operator proof from on-chain assert witness")?;
    let vk = crate::vk::get_vk()
        .await
        .context("load Groth16 verifying key for BABE wrongly challenged")?;
    let (_, dyn_pubin) = assert_witness.try_recover_pi1_xd().ok_or_else(|| {
        anyhow!("cannot recover dynamic input from challenge witness WOTS signature")
    })?;
    let wrongly_challenged_witness = recover_real_wrongly_challenged_witness(
        &prover_state,
        &challenge_witness,
        &proof,
        vk,
        dyn_pubin,
    )?;
    let (wrongly_challenged_input, input_amount) = operator_sign_wrongly_challenged(
        &graph,
        verifier_index,
        &wrongly_challenged_witness.final_msg,
    )?;

    let operator_keypair = OperatorMasterKey::new(get_bitvm_key()?).master_keypair();
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_keypair,
        vec![wrongly_challenged_input],
        input_amount,
        vec![
            goat::scripts::p2a_output(),
            // This makes the non-witness transaction size safely exceed the
            // relay minimum even before the locally funded fee input is added.
            bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: goat::scripts::generate_opreturn_script(
                    WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                ),
            },
        ],
    )
    .await?;

    Ok(())
}

const WRONGLY_CHALLENGED_OP_RETURN_DATA: &[u8] = b"wrongly-challenged";

// broadcast NoWithdraw after the ChallengeAssert timelock expires.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_wrongly_challenge_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        None,
        GraphStatus::Disprove,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    validate_verifier_slot(&graph, verifier_index)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != local_verifier_pubkey {
        tracing::debug!(
            "Ignore WronglyChallengeTimeout for {instance_id}:{graph_id}: local verifier does not own slot {verifier_index}"
        );
        return Ok(());
    }

    let delay_secs = avg_block_time_secs(ctx.btc_client.network());
    let message = make_message(ctx, content);
    if ctx.btc_client.get_tx(&challenge_assert_txid).await?.is_none() {
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::BitcoinTransactionPending,
            "ChallengeAssert transaction is not available from the Bitcoin backend",
        )
        .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    }

    let challenge_assert_height = match ctx
        .btc_client
        .get_tx_status(&challenge_assert_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "ChallengeAssert transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} is not confirmed"
            );
            return Ok(());
        }
    };

    let disprove_height = challenge_assert_height
        + disprove_timelock_with_config(
            graph.parameters.instance_parameters.network,
            &graph.parameters.timelock_config,
        ) as u64;
    let bitcoin_height = ctx.btc_client.get_height().await? as u64;
    if bitcoin_height < disprove_height {
        let retry_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (disprove_height - bitcoin_height);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            retry_secs as usize,
            MessageDeferReason::TimelockPending,
            "disprove timelock has not expired",
        )
        .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: disprove timelock has not expired"
        );
        return Ok(());
    }
    if let Some(spent_txid) = outpoint_spent_txid(ctx.btc_client, &challenge_assert_txid, 0).await?
    {
        tracing::info!(
            "Skip Disprove for {instance_id}:{graph_id} slot {verifier_index}: verifier assertion output already spent by {spent_txid}"
        );
        return Ok(());
    }

    let disprove_tx = build_disprove_tx(&graph, verifier_index, None)?;
    let disprove_tx_total_input_amount =
        graph.disproves[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, disprove_tx, disprove_tx_total_input_amount).await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id
))]
async fn handle_disprove_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    disprove_type: DisproveTxType,
    index: usize,
    challenge_finish_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Disprove tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        None,
        GraphStatus::Disprove,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawDisprove on GoatChain
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Disproved {
        tracing::warn!(
            "Relayer Ignore finishWithdrawDisproved for {instance_id}:{graph_id}: already posted"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let take1_txid = graph.take1.tx().compute_txid();
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let challenge_start_tx = if let Some(spent_txid) =
        outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?
    {
        if spent_txid == take1_txid {
            tracing::warn!(
                "Ignore DisproveSent for {instance_id}:{graph_id}: graph already finalized by Take1 tx: {spent_txid}"
            );
            return Ok(());
        }
        ctx.btc_client.get_tx(&spent_txid).await?
    } else {
        None
    };
    let challenge_finish_tx = match ctx.btc_client.get_tx(&challenge_finish_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx {challenge_finish_txid} not found on chain"
            );
            return Ok(());
        }
    };
    let challenge_finish_height = match ctx
        .btc_client
        .get_tx_status(&challenge_finish_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "challenge finish transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < challenge_finish_height {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network())
            * (challenge_finish_height - goat_confirmed_height);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "challenge finish block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    let result = ctx
        .goat_client
        .gateway_finish_withdraw_disproved(
            ctx.btc_client,
            &graph_id,
            disprove_type,
            index as u64,
            challenge_start_tx.as_ref(),
            &challenge_finish_tx,
        )
        .await;
    ctx.metrics_state.record_withdraw_finalize(result.is_ok());
    result?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_disprove_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Disprove tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Disprove).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::OperatorKickOff {
        tracing::warn!(
            "Ignore Take1Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let guardian_connector_vout = output_topology::kickoff::guardian_connector() as u64;
    if outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?.is_some()
        || outpoint_spent_txid(ctx.btc_client, &kickoff_txid, guardian_connector_vout)
            .await?
            .is_some()
    {
        tracing::warn!("Ignore Take1Ready for {instance_id}:{graph_id}: connectors already spent");
        return Ok(());
    }
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
            );
            return Ok(());
        }
    };
    if !is_take1_timelock_expired(ctx.btc_client, kickoff_height, &graph.parameters.timelock_config)
        .await?
    {
        tracing::warn!(
            "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx timelock not expired yet"
        );
        return Ok(());
    }
    // 1. sign & broadcast take1 txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let take1_tx = operator_sign_take1(operator_graph_keypair, &mut graph)?;
    let anchor_vout = take1_tx.output.len() as u64 - 1;
    let take1_tx_total_input_amount = graph.take1.prev_outs().iter().map(|o| o.value).sum();
    let child_tx =
        build_cpfp_txns(ctx.btc_client, &take1_tx, anchor_vout, take1_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take1_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take1_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawHappyPath on GoatChain
    let take1_txid = graph.take1.tx().compute_txid();
    let take1_tx = match ctx.btc_client.get_tx(&take1_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take1Sent for {instance_id}:{graph_id}: take1 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::WithdrawKickoffPending,
            "withdraw is initialized but kickoff has not been posted",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
        );
        return Ok(());
    }
    if withdraw_status != WithdrawStatus::Processing {
        tracing::warn!(
            "Relayer Ignore finishWithdrawHappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
        );
        return Ok(());
    }
    let take1_height = match ctx.btc_client.get_tx_status(&take1_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "take1 transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take1_height {
        let delay_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (take1_height - goat_confirmed_height);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "take1 block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_happy_path(ctx.btc_client, &graph_id, &take1_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore Take2Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let operator_assert_txid = graph.operator_assert.tx().compute_txid();
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    // Take2 spends Connector-0, Connector-D, Connector-F, and Guardian Connector. Recheck every input before
    // signing so a stale Take2Ready cannot race an already-spent connector.
    let take2_inputs =
        graph.take2.tx().input.iter().map(|txin| txin.previous_output).collect::<Vec<OutPoint>>();
    for previous_output in take2_inputs {
        if let Some(spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &previous_output.txid, previous_output.vout as u64)
                .await?
        {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: take2 input {}:{} already spent by {}",
                previous_output.txid,
                previous_output.vout,
                spent_txid
            );
            return Ok(());
        }
    }
    let operator_assert_height = match ctx
        .btc_client
        .get_tx_status(&operator_assert_txid)
        .await?
        .block_height
    {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: assert init tx not confirmed yet"
            );
            return Ok(());
        }
    };
    let watchtower_challenge_init_height = match ctx
        .btc_client
        .get_tx_status(&watchtower_challenge_init_txid)
        .await?
        .block_height
    {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
            );
            return Ok(());
        }
    };
    if !is_take2_timelock_expired(
        ctx.btc_client,
        operator_assert_height,
        watchtower_challenge_init_height,
        &graph.parameters.timelock_config,
    )
    .await?
    {
        tracing::warn!(
            "Ignore Take2Ready for {instance_id}:{graph_id}: take2 timelock not expired yet"
        );
        return Ok(());
    }
    // 1. sign & broadcast take2 txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let take2_tx = operator_sign_take2(operator_graph_keypair, &mut graph)?;
    let anchor_vout = take2_tx.output.len() as u64 - 1;
    let take2_tx_total_input_amount = graph.take2.prev_outs().iter().map(|o| o.value).sum();
    let child_tx =
        build_cpfp_txns(ctx.btc_client, &take2_tx, anchor_vout, take2_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take2_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take2_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawUnhappyPath on GoatChain
    let take2_txid = graph.take2.tx().compute_txid();
    let take2_tx = match ctx.btc_client.get_tx(&take2_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take2Sent for {instance_id}:{graph_id}: take2 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::WithdrawKickoffPending,
            "withdraw is initialized but kickoff has not been posted",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
        );
        return Ok(());
    }
    if withdraw_status != WithdrawStatus::Processing {
        tracing::warn!(
            "Relayer Ignore finishWithdrawUnhappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
        );
        return Ok(());
    }
    let take2_height = match ctx.btc_client.get_tx_status(&take2_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            defer_or_enqueue_message(
                ctx.local_db,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "take2 transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take2_height {
        let delay_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (take2_height - goat_confirmed_height);
        defer_or_enqueue_message(
            ctx.local_db,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "take2 block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_unhappy_path(ctx.btc_client, &graph_id, &take2_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2).await?;
    Ok(())
}

/// A `NodeInfo` payload is entirely self-declared, so only accept it as the
/// sender's own record: the registry is keyed by `peer_id`, and without this
/// check any peer could overwrite any other node's row.
fn accept_node_info(ctx: &HandlerContext<'_>, node_info: &NodeInfo, message_kind: &str) -> bool {
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
    ctx: &HandlerContext<'_>,
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
async fn record_node_info(ctx: &HandlerContext<'_>, node_info: &NodeInfo) -> Result<()> {
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
    Ok(())
}

async fn handle_request_node_info(
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "RequestNodeInfo") {
        record_node_info(ctx, node_info).await?;
    }
    // Answer regardless: the response only carries this node's own public info,
    // and staying silent would break discovery for a misconfigured peer.
    // Coalesce recent requests into one broadcast response.
    if crate::p2p_admission::node_info_response_gate().try_respond(std::time::Instant::now()) {
        publish_node_info_response(ctx.swarm).await?;
    }
    Ok(())
}

async fn publish_node_info_response(swarm: &mut dyn MessagePublisher) -> Result<()> {
    let message_content = GOATMessageContent::ResponseNodeInfo(crate::env::get_local_node_info());
    send_to_peer(swarm, GOATMessage::new(Actor::All, message_content)).await?;
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
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "ResponseNodeInfo") {
        record_node_info(ctx, node_info).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    #[tokio::test]
    async fn missing_pegin_event_is_ignored_without_enqueuing_retry() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::new_v4();

        let metadata =
            resolve_pegin_request_metadata(&local_db, instance_id, "0xuntrusted", i64::MAX)
                .await
                .unwrap();

        assert!(metadata.is_none());
        let mut storage_processor = local_db.acquire().await.unwrap();
        let queued = storage_processor
            .find_message_by_business_id(&instance_id, "PeginRequest")
            .await
            .unwrap();
        assert!(queued.is_none());
    }

    // ── collect_ack_txins ─────────────────────────────────────────────────────

    fn make_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn make_confirmed_ack_tx(ack_txid: Txid, wci_txid: Txid, ack_vout: u32) -> esplora_client::Tx {
        use esplora_client::{TxStatus, Vin};
        let preimage = b"test-ack-preimage".to_vec();
        esplora_client::Tx {
            txid: ack_txid,
            version: 2,
            locktime: 0,
            vin: vec![Vin {
                txid: wci_txid,
                vout: ack_vout,
                prevout: None,
                scriptsig: bitcoin::ScriptBuf::default(),
                witness: vec![preimage],
                sequence: 1,
                is_coinbase: false,
            }],
            vout: vec![],
            size: 1,
            weight: 1,
            status: TxStatus {
                confirmed: true,
                block_height: Some(800_000),
                block_hash: None,
                block_time: Some(1_000_000),
            },
            fee: 0,
        }
    }

    #[tokio::test]
    async fn collect_ack_txins_returns_only_spent_connectors() {
        let (btc_client, mock) = client::btc_chain::BTCClient::new_mock_client();
        let wci_txid = make_txid(0x00);
        let ack_txid_0 = make_txid(0x01);
        let timeout_txid_1 = make_txid(0x03);
        let timeout_txids = vec![make_txid(0x10), timeout_txid_1, make_txid(0x12)];

        // Watchtower 0 ACKed
        let vout_0 = output_topology::watchtower_challenge_init::ack_connector(0) as u32;
        mock.set_tx(ack_txid_0, make_confirmed_ack_tx(ack_txid_0, wci_txid, vout_0));

        // Watchtower 1 timed out; the timeout spend must not count as an ACK.
        let vout_1 = output_topology::watchtower_challenge_init::ack_connector(1) as u32;
        mock.set_tx(timeout_txid_1, make_confirmed_ack_tx(timeout_txid_1, wci_txid, vout_1));

        // Watchtower 2 ACKed
        let ack_txid_2 = make_txid(0x02);
        let vout_2 = output_topology::watchtower_challenge_init::ack_connector(2) as u32;
        mock.set_tx(ack_txid_2, make_confirmed_ack_tx(ack_txid_2, wci_txid, vout_2));

        let txins = collect_ack_txins(&btc_client, &wci_txid, &timeout_txids).await.unwrap();

        assert_eq!(txins.len(), 2);
        assert_eq!(txins[0].previous_output.vout, vout_0);
        assert_eq!(txins[1].previous_output.vout, vout_2);
    }

    // ── recover_challenge_assert_witness ──────────────────────────────────────

    fn build_challenge_assert_tx(
        sig: &<Wots96 as Wots>::Signature,
        labels: &[[u8; 16]],
    ) -> bitcoin::Transaction {
        let mut witness = bitcoin::Witness::new();
        let raw_wots = Wots96::signature_to_raw_witness(sig);
        for item in raw_wots.iter() {
            witness.push(item);
        }
        for label in labels {
            witness.push(label.as_slice());
        }
        witness.push([0xde, 0xad]); // placeholder script
        witness.push([0xbe, 0xef]); // placeholder control block
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn { witness, ..Default::default() }],
            output: vec![],
        }
    }

    #[test]
    fn recover_challenge_assert_witness_extracts_wots_sig_and_labels() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-challenge-witness");
        let msg = [0x42u8; 96];
        let sig = Wots96::sign(&sk, &msg);

        let labels: Vec<[u8; 16]> =
            (0..goat::assert_scripts::INPUT_WIRE_NUM).map(|i| [(i % 256) as u8; 16]).collect();

        let tx = build_challenge_assert_tx(&sig, &labels);
        let verifier_index = 3;
        let recovered = recover_challenge_assert_witness(&tx, verifier_index).unwrap();

        assert_eq!(recovered.verifier_index, verifier_index);
        assert_eq!(recovered.witness.wots_sig.len(), WOTS_SIG_COUNT);
        assert_eq!(recovered.witness.input_labels.len(), goat::assert_scripts::INPUT_WIRE_NUM);

        let mut bw = bitcoin::Witness::new();
        for item in Wots96::signature_to_raw_witness(&sig).iter() {
            bw.push(item);
        }
        assert_eq!(recovered.witness.wots_sig, Wots96::raw_witness_to_signature(&bw).to_vec());

        // labels are correctly extracted
        for (i, label) in recovered.witness.input_labels.iter().enumerate() {
            assert_eq!(label[0], (i % 256) as u8, "label {i} mismatch");
        }
    }

    #[test]
    fn recover_challenge_assert_witness_rejects_wrong_length() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-wrong-len");
        let sig = Wots96::sign(&sk, &[0u8; 96]);
        let labels: Vec<[u8; 16]> = vec![[0u8; 16]; goat::assert_scripts::INPUT_WIRE_NUM];

        // one label short
        let mut short_labels = labels.clone();
        short_labels.pop();
        let bad_tx = build_challenge_assert_tx(&sig, &short_labels);
        assert!(recover_challenge_assert_witness(&bad_tx, 0).is_err());

        // no inputs at all
        let empty_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(recover_challenge_assert_witness(&empty_tx, 0).is_err());
    }

    #[test]
    fn wrongly_challenge_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "wrongly-challenge transaction is {} non-witness bytes",
            tx.base_size()
        );
    }

    #[test]
    fn pubin_disprove_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "pubin-disprove transaction is {} non-witness bytes",
            tx.base_size()
        );
    }
}
