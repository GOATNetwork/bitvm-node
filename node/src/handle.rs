use crate::action::*;
use crate::aggregates::graph::operator_start_event;
use crate::aggregates::graph_jobs::signing_nonce_id;
use crate::aggregates::instance::{SigningGate, signing_gate};
use crate::engine_bridge::submit_event;
use crate::env::{get_bitvm_key, get_operator_graph_start_cutoff_blocks, is_relayer};
use crate::error::SpecialError;
use crate::metrics_service::MetricsState;
use crate::middleware::publisher::MessagePublisher;
use crate::rpc_service::current_time_secs;
use crate::utils::*;
use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use bitvm_lib::committee::*;
use bitvm_lib::keys::*;
use bitvm_lib::types::BitvmGcInstanceParameters;
use client::graphs::graph_query::BridgeInRequestEvent;
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use libp2p::PeerId;
use libp2p::gossipsub::MessageId;
use secp256k1::{Message as SecpMessage, SECP256K1};
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{GoatTxType, InstanceBridgeInStatus};
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
}
