//! Instance maintenance that is not yet an engine job (refactor step 2):
//! handing new Goat peg-in requests to the committee answer handler,
//! re-sending the committee's stored PeginConfirm values, and swap escrow
//! timeouts. Every status decision of an instance lives in the Instance
//! aggregate (`crate::aggregates::instance`); the chain facts it needs are
//! gathered by `crate::aggregates::instance_scan`.

use crate::action::{
    GOATMessage, GOATMessageContent, MessageDeferReason, PeginConfirmNonce,
    PeginConfirmNonceConsensus, PeginConfirmPartialSig, PeginRequest, RetryableDispatchError,
    RetryableDispatchReason, defer_or_enqueue_message,
};
use crate::aggregates::instance::{SigningGate, signing_gate};
use crate::aggregates::instance_scan::find_one_instance_page;
use crate::env::{get_bitvm_key, get_instance_maintenance_batch_size};
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::event_watch_task::generate_instance_from_bridge_in_request_event;
use crate::utils::{
    SELF_SENDER, gen_instance_parameters_local, get_committee_agg_nonce_consensus_for_instance,
    get_committee_endorse_sigs_for_pegin, get_committee_partial_sig_for_instance,
    get_committee_pub_nonce_for_instance, load_committee_instance_keypair,
    store_committee_pub_nonce_for_instance, upsert_message,
};
use bitvm_lib::actors::Actor;
use bitvm_lib::keys::CommitteeMasterKey;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use store::localdb::{InstanceQuery, LocalDB};
use store::{GoatTxProcessingStatus, GoatTxType, InstanceBridgeInStatus};
use tracing::{info, warn};
use uuid::Uuid;

const TASK_KEY_PEGIN_CONFIRM_RECOVERY: &str = "pegin_confirm_recovery_monitor";

fn finish_recovery_enqueue(
    result: anyhow::Result<()>,
    instance_id: Uuid,
    action: &'static str,
) -> anyhow::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error)
            if error.chain().any(|cause| {
                cause.downcast_ref::<RetryableDispatchError>().is_some_and(|retryable| {
                    retryable.reason == RetryableDispatchReason::ResourceLocked
                })
            }) =>
        {
            warn!(
                event = "pegin_confirm_recovery",
                outcome = "resource_locked",
                instance_id = %instance_id,
                action,
                error = %error,
                "skip recovery enqueue while the local message is actively claimed"
            );
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Hand every pending Goat `BridgeInRequest` to the `PeginRequest` handler
/// while its response window is open. A request this node only saw after the
/// window is recorded as `UserDiscarded` when the user's inputs are already
/// spent, so the RPC can show the outcome; otherwise it is left alone.
pub async fn instance_answers_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let tx_records = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .get_goat_tx_record_by_processing_status(
                &GoatTxType::BridgeInRequest.to_string(),
                &GoatTxProcessingStatus::Pending.to_string(),
            )
            .await?
    };
    if tx_records.is_empty() {
        return Ok(());
    }
    let current_height = goat_client.get_finalized_block_number().await?;
    let response_window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    for tx_record in tx_records {
        let event = tx_record
            .extra
            .as_deref()
            .map(serde_json::from_str::<BridgeInRequestEvent>)
            .transpose()?;
        let is_outside_response_window = tx_record.height + response_window_blocks < current_height;
        let discarded_instance = match event.as_ref() {
            Some(event) if is_outside_response_window => {
                info!(
                    "instance_answers_monitor: instance_id:{} BridgeInRequest is outside the response window",
                    tx_record.instance_id
                );
                match generate_instance_from_bridge_in_request_event(
                    btc_client,
                    goat_client,
                    event,
                    true,
                )
                .await
                {
                    Ok((mut instance, false)) => {
                        instance.status = InstanceBridgeInStatus::UserDiscarded.to_string();
                        Some(instance)
                    }
                    Ok((_, true)) => None,
                    Err(error) => {
                        warn!(
                            instance_id = %tx_record.instance_id,
                            error = %error,
                            "could not rebuild the instance of a late BridgeInRequest"
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        let mut tx = local_db.start_transaction().await?;
        if let Some(event) = event {
            if is_outside_response_window {
                if let Some(instance) = discarded_instance
                    && tx.insert_instance_if_absent(&instance).await?
                {
                    info!(
                        "instance_answers_monitor: instance_id:{} recorded as UserDiscarded, its inputs are spent",
                        instance.instance_id
                    );
                }
            } else {
                upsert_message(
                    &mut tx,
                    false,
                    SELF_SENDER.to_string(),
                    Actor::All,
                    GOATMessageContent::PeginRequest(PeginRequest {
                        instance_id: tx_record.instance_id,
                        pegin_request_tx_hash: tx_record.tx_hash,
                        pegin_request_height: tx_record.height,
                        pegin_timestamp: event
                            .block_timestamp
                            .parse::<i64>()
                            .unwrap_or_else(|_| current_time_secs()),
                    }),
                    0,
                    0,
                )
                .await?;
            }
        }

        tx.update_goat_tx_record_processing_status(
            &tx_record.graph_id,
            &tx_record.instance_id,
            &tx_record.tx_type,
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Re-publish persisted PeginConfirm signing material until the transaction is visible on Bitcoin.
/// This never derives a new partial signature: it only reuses the deterministic nonce or stored signature.
/// A fresh nonce is only derived while the T0 gate is open.
pub async fn pegin_confirm_recovery_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    actor: &Actor,
) -> anyhow::Result<()> {
    if actor != &Actor::Committee {
        return Ok(());
    }

    let instances = find_one_instance_page(
        local_db,
        TASK_KEY_PEGIN_CONFIRM_RECOVERY,
        InstanceQuery::default().with_status(InstanceBridgeInStatus::Presigned.to_string()),
        get_instance_maintenance_batch_size(),
    )
    .await?;
    if instances.is_empty() {
        return Ok(());
    }

    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    for instance in instances {
        let Some(pegin_confirm_txid) = instance.pegin_confirm_txid.clone() else {
            warn!(
                instance_id = %instance.instance_id,
                "skip PeginConfirm recovery: instance has no expected PeginConfirm txid"
            );
            continue;
        };
        match btc_client.get_tx(&pegin_confirm_txid.0).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(error) => {
                warn!(
                    instance_id = %instance.instance_id,
                    error = %error,
                    "defer PeginConfirm recovery: unable to query Bitcoin transaction"
                );
                continue;
            }
        }

        let instance_id = instance.instance_id;
        let instance_parameters = gen_instance_parameters_local(&instance)?;
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();

        if let Some(partial_sig) =
            get_committee_partial_sig_for_instance(local_db, instance_id, &local_committee_pubkey)
                .await?
        {
            let Some((_, endorse_sig)) =
                get_committee_endorse_sigs_for_pegin(local_db, instance_id)
                    .await?
                    .into_iter()
                    .find(|(pubkey, _)| *pubkey == local_committee_pubkey)
            else {
                warn!(
                    instance_id = %instance_id,
                    "skip PeginConfirm partial signature recovery: local endorsement signature is missing"
                );
                continue;
            };
            let message = GOATMessage::new(
                Actor::Committee,
                GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                    instance_id,
                    committee_pubkey: local_committee_pubkey,
                    partial_sig,
                    endorse_sig,
                }),
            );
            if !finish_recovery_enqueue(
                defer_or_enqueue_message(
                    local_db,
                    &message,
                    0,
                    MessageDeferReason::RecoveryRepublish,
                    "re-publishing persisted pegin-confirm partial signature",
                )
                .await,
                instance_id,
                "republish_partial_signature",
            )? {
                continue;
            }
            tracing::info!(
                event = "pegin_confirm_recovery",
                action = "republish_partial_signature",
                instance_id = %instance_id,
                "queued persisted PeginConfirm partial signature for re-publication"
            );
            continue;
        }

        let stored_pub_nonce =
            get_committee_pub_nonce_for_instance(local_db, instance_id, &local_committee_pubkey)
                .await?;
        if stored_pub_nonce.is_none()
            && let SigningGate::Closed(reason) =
                signing_gate(local_db, btc_client, instance_id).await?
        {
            tracing::info!(
                event = "signing_gate",
                instance_id = %instance_id,
                what = "PeginConfirm nonce",
                reason = %reason,
                "not starting the PeginConfirm round"
            );
            continue;
        }
        let (_, derived_pub_nonce, nonce_sig) = committee_master_key
            .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
        let pub_nonce = match stored_pub_nonce {
            Some(stored_pub_nonce) => {
                if stored_pub_nonce != derived_pub_nonce {
                    anyhow::bail!(
                        "stored PeginConfirm nonce differs from deterministic nonce for instance {instance_id}"
                    );
                }
                stored_pub_nonce
            }
            None => {
                store_committee_pub_nonce_for_instance(
                    local_db,
                    instance_id,
                    local_committee_pubkey,
                    derived_pub_nonce.clone(),
                )
                .await?;
                derived_pub_nonce
            }
        };
        let message = GOATMessage::new(
            Actor::Committee,
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
        );
        if !finish_recovery_enqueue(
            defer_or_enqueue_message(
                local_db,
                &message,
                0,
                MessageDeferReason::RecoveryRepublish,
                "re-publishing persisted pegin-confirm nonce",
            )
            .await,
            instance_id,
            "republish_nonce",
        )? {
            continue;
        }
        tracing::info!(
            event = "pegin_confirm_recovery",
            action = "republish_nonce",
            instance_id = %instance_id,
            "queued persisted PeginConfirm nonce for re-publication"
        );
        if let Some((_, consensus_hash, signature)) =
            get_committee_agg_nonce_consensus_for_instance(local_db, instance_id)
                .await?
                .into_iter()
                .find(|(pubkey, _, _)| *pubkey == local_committee_pubkey)
        {
            let message = GOATMessage::new(
                Actor::Committee,
                GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
                    instance_id,
                    committee_pubkey: local_committee_pubkey,
                    consensus_hash,
                    signature,
                }),
            );
            if !finish_recovery_enqueue(
                defer_or_enqueue_message(
                    local_db,
                    &message,
                    0,
                    MessageDeferReason::RecoveryRepublish,
                    "re-publishing persisted PeginConfirm nonce consensus",
                )
                .await,
                instance_id,
                "republish_nonce_consensus",
            )? {
                continue;
            }
            tracing::info!(
                event = "pegin_confirm_recovery",
                action = "republish_nonce_consensus",
                instance_id = %instance_id,
                "queued persisted PeginConfirm nonce consensus for re-publication"
            );
        }
    }
    Ok(())
}

/// Mark still-initializing swap escrows whose refund deadline has passed as
/// timed out.
pub async fn swap_escrow_timeout_monitor(local_db: &LocalDB) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let timed_out = storage_processor.timeout_expired_swap_escrows(current_time_secs()).await?;
    if timed_out > 0 {
        info!("marked {timed_out} swap escrows as timed out");
    }
    Ok(())
}
