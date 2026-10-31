use crate::action::{
    ConfirmInstance, GOATMessage, GOATMessageContent, MessageDeferReason, PeginConfirmNonce,
    PeginConfirmNonceConsensus, PeginConfirmPartialSig, PeginRequest, PostReady,
    push_local_unhandled_messages_with_reason,
};
use crate::env::{
    COMMITTEE_INSTANCE_KEYS_DIR, get_bitvm_key, get_committee_instance_key_delete_timelock_blocks,
    get_instance_maintenance_batch_size, get_instance_presigned_time_expired_secs,
    is_enable_committee_instance_key_delete,
};
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::event_watch_task::generate_instance_from_bridge_in_request_event;
use crate::utils::{
    SELF_SENDER, check_bridge_in_uxto_available_or_self_spent, gen_instance_parameters_local,
    get_committee_agg_nonce_consensus_for_instance, get_committee_endorse_sigs_for_pegin,
    get_committee_partial_sig_for_instance, get_committee_pub_nonce_for_instance,
    load_committee_instance_keypair, store_committee_pub_nonce_for_instance, upsert_message,
};
use bitvm_lib::actors::Actor;
use bitvm_lib::keys::CommitteeMasterKey;
use bitvm_lib::timelocks::default_connector_z_timelock_blocks;
use bitvm_lib::transactions::base::BaseTransaction;
use client::Utxo;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::vec;
use store::localdb::{InstanceQuery, InstanceUpdate, LocalDB, StorageProcessor};
use store::{GoatTxProcessingStatus, GoatTxType, Instance, InstanceBridgeInStatus};
use tracing::{info, warn};
use uuid::Uuid;

const TASK_KEY_INSTANCE_WINDOW_EXPIRATION: &str = "instance_window_expiration_monitor";
const TASK_KEY_INSTANCE_EXPIRATION: &str = "instance_expiration_monitor";
const TASK_KEY_INSTANCE_BTC_TX: &str = "instance_btc_tx_monitor";
const TASK_KEY_PEGIN_CONFIRM_RECOVERY: &str = "pegin_confirm_recovery_monitor";

#[derive(Clone, Debug)]
struct InstancePageState {
    watermark: i64,
    cursor: Option<(i64, Uuid)>,
}

static INSTANCE_PAGE_STATES: LazyLock<Mutex<HashMap<&'static str, InstancePageState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_or_init_instance_page_state(task_key: &'static str) -> InstancePageState {
    let mut state = INSTANCE_PAGE_STATES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    state
        .entry(task_key)
        .or_insert_with(|| InstancePageState { watermark: current_time_secs(), cursor: None })
        .clone()
}

fn reset_instance_page_state(task_key: &'static str) {
    let mut state = INSTANCE_PAGE_STATES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    state.insert(task_key, InstancePageState { watermark: current_time_secs(), cursor: None });
}

fn advance_instance_page_state(task_key: &'static str, watermark: i64, last: (i64, Uuid)) {
    let mut state = INSTANCE_PAGE_STATES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    state.insert(task_key, InstancePageState { watermark, cursor: Some(last) });
}

async fn find_one_instance_page(
    local_db: &LocalDB,
    task_key: &'static str,
    mut query: InstanceQuery,
    batch_size: u32,
) -> anyhow::Result<Vec<Instance>> {
    let page_state = get_or_init_instance_page_state(task_key);
    query = query
        .with_order("created_at ASC, instance_id ASC".to_string())
        .with_limit(batch_size)
        .with_raw_condition(format!("created_at <= {}", page_state.watermark));

    if let Some((created_at, instance_id)) = page_state.cursor {
        query = query.with_raw_condition(format!(
            "(created_at > {created_at} OR (created_at = {created_at} AND instance_id > '{instance_id}'))"
        ));
    }

    let instances = {
        let mut storage_processor = local_db.acquire().await?;
        let (instances, _) = storage_processor.find_instances(query).await?;
        instances
    };

    if instances.is_empty() {
        reset_instance_page_state(task_key);
        return Ok(instances);
    }

    if instances.len() < batch_size as usize {
        reset_instance_page_state(task_key);
    } else if let Some(last) = instances.last() {
        advance_instance_page_state(
            task_key,
            page_state.watermark,
            (last.created_at, last.instance_id),
        );
    }

    Ok(instances)
}

async fn update_instance<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    params: &InstanceUpdate,
) -> anyhow::Result<()> {
    match storage_processor.update_instance(params).await {
        Ok(true) => info!("update instance with input: {:?}", params),
        Ok(false) => info!("skip stale instance update with input: {:?}", params),
        Err(err) => {
            warn!("update_instance_status with input: {:?} failed {}, will try later", params, err);
        }
    }
    Ok(())
}

/// for committee
/// handle bridge-in request events on GOAT
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
    let current_height = goat_client.get_finalized_block_number().await?;
    let response_window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    for tx_record in tx_records {
        let event = tx_record
            .extra
            .as_deref()
            .map(serde_json::from_str::<BridgeInRequestEvent>)
            .transpose()?;
        let is_outside_response_window = tx_record.height + response_window_blocks < current_height;
        let discarded_instance = if is_outside_response_window {
            if let Some(event) = event.as_ref() {
                info!(
                    "instance_answers_monitor: instance_id:{} BridgeInRequest is outside the response window",
                    tx_record.instance_id
                );

                if let Ok((mut instance, input_utxo_available)) =
                    generate_instance_from_bridge_in_request_event(
                        btc_client,
                        goat_client,
                        event,
                        true,
                    )
                    .await
                    && !input_utxo_available
                {
                    info!(
                        "instance_answers_monitor: instance_id:{} BridgeInRequest is outside the response window and input utxos not available",
                        tx_record.instance_id
                    );
                    // for the case: if bridgeIn confirm is broadcast,but L2 not minted,
                    // instance status will been updated to L2Minted when normal finished
                    instance.status = InstanceBridgeInStatus::UserDiscarded.to_string();
                    Some(instance)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut tx = local_db.start_transaction().await?;
        if let Some(event) = event {
            if is_outside_response_window {
                if let Some(instance) = discarded_instance {
                    tx.upsert_instance(&instance).await?;
                }
            } else {
                upsert_message(
                    &mut tx,
                    false,
                    tx_record.instance_id,
                    None,
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

/// check committee answers for bridge-in request after response window expired
pub async fn instance_window_expiration_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let batch_size = get_instance_maintenance_batch_size();
    let window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    let current_height = goat_client.get_latest_block_number().await?;
    let instances = find_one_instance_page(
        local_db,
        TASK_KEY_INSTANCE_WINDOW_EXPIRATION,
        InstanceQuery::default()
            .with_status(InstanceBridgeInStatus::UserInited.to_string())
            .with_pegin_request_height_threshold(current_height - window_blocks),
        batch_size,
    )
    .await?;

    let committee_quorum_size = goat_client.committee_mana_quorum_size().await?;
    for snapshot in instances {
        let pegin_data = match goat_client.gateway_get_pegin_data(&snapshot.instance_id).await {
            Ok(pegin_data) => pegin_data,
            Err(err) => {
                warn!(
                    "failed to get pegin data for instance {}, err: {}",
                    snapshot.instance_id, err
                );
                continue;
            }
        };

        // The RPC call above can take arbitrarily long. Re-read while holding
        // SQLite's write lock, then make the decision and its update in the
        // same short transaction so a late committee response cannot be
        // overwritten by the stale page snapshot.
        let mut storage_processor = local_db.start_immediate_transaction().await?;
        let Some(mut instance) = storage_processor.find_instance(&snapshot.instance_id).await?
        else {
            storage_processor.commit().await?;
            continue;
        };
        if instance.status != InstanceBridgeInStatus::UserInited.to_string() {
            info!(
                "skip expired response-window reconciliation for instance {} in status {}",
                instance.instance_id, instance.status
            );
            storage_processor.commit().await?;
            continue;
        }

        for (committee_addr, pubkey) in
            pegin_data.committee_addresses.iter().zip(pegin_data.committee_pubkeys)
        {
            instance.committees_answers.insert(committee_addr.to_string(), pubkey);
        }

        let reached_quorum = committee_quorum_size <= instance.committees_answers.len() as u64;
        let next_status = if reached_quorum {
            if let Err(err) = update_pegin_txids(&mut instance) {
                warn!(
                    "instance_window_expiration_monitor failed to update pegin txids for instance {}, err: {err:?}",
                    instance.instance_id
                );
            }
            InstanceBridgeInStatus::CommitteesAnswered
        } else {
            InstanceBridgeInStatus::NoEnoughCommitteesAnswered
        };

        let mut update = InstanceUpdate::new_with_instance_id(instance.instance_id)
            .with_status(next_status.to_string())
            .with_committees_answers(instance.committees_answers.clone())
            .with_only_if_status_in(vec![InstanceBridgeInStatus::UserInited.to_string()]);
        if reached_quorum {
            if let Some(btc_txid) = instance.btc_txid.clone() {
                update = update.with_btc_txid(btc_txid);
            }
            if let Some(pegin_confirm_txid) = instance.pegin_confirm_txid.clone() {
                update = update.with_pegin_confirm_txid(pegin_confirm_txid);
            }
            if let Some(pegin_cancel_txid) = instance.pegin_cancel_txid.clone() {
                update = update.with_pegin_cancel_txid(pegin_cancel_txid);
            }
        }

        if !storage_processor.update_instance(&update).await? {
            warn!("skip stale response-window update for instance {}", instance.instance_id);
        }
        storage_processor.commit().await?;
    }

    Ok(())
}

fn update_pegin_txids(instance: &mut Instance) -> anyhow::Result<()> {
    let (pegin_deposit_tx, pegin_confirm_tx, pegin_refund_tx) =
        gen_instance_parameters_local(instance)?.build_pegin_tx()?;
    instance.btc_txid = Some(pegin_deposit_tx.tx().compute_txid().into());
    instance.pegin_confirm_txid = Some(pegin_confirm_tx.finalize().compute_txid().into());
    instance.pegin_cancel_txid = Some(pegin_refund_tx.finalize().compute_txid().into());
    Ok(())
}

/// check pegin-cancel timelock
pub async fn instance_expiration_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    let batch_size = get_instance_maintenance_batch_size();
    let current_time = current_time_secs();
    let current_height = btc_client.get_height().await? as i64;
    let instances = {
        let mut storage_processor = local_db.acquire().await?;
        let expired_num = storage_processor
            .update_expired_instance(
                &InstanceBridgeInStatus::UserBroadcastPeginPrepare.to_string(),
                &InstanceBridgeInStatus::PresignedFailed.to_string(),
                current_time - get_instance_presigned_time_expired_secs(),
            )
            .await?;
        info!("Presigned expired instances is {expired_num}");
        let _ = storage_processor;
        find_one_instance_page(
            local_db,
            TASK_KEY_INSTANCE_EXPIRATION,
            InstanceQuery::default().with_statuses(vec![
                InstanceBridgeInStatus::Presigned.to_string(),
                InstanceBridgeInStatus::PresignedFailed.to_string(),
            ]),
            batch_size,
        )
        .await?
    };

    let lock_height = default_connector_z_timelock_blocks(btc_client.network()) as i64;
    let mut storage_processor = local_db.acquire().await?;
    for instance in instances {
        if instance.btc_height > 0 && current_height > instance.btc_height + lock_height {
            update_instance(
                &mut storage_processor,
                &InstanceUpdate::new_with_instance_id(instance.instance_id)
                    .with_status(InstanceBridgeInStatus::Timeout.to_string()),
            )
            .await?;
        } else {
            info!("instance;{} not expired", instance.instance_id);
        }
    }
    Ok(())
}

/// check if pegin-deposit/cancel/confirm tx confirmed on chain, and update instance status accordingly
pub async fn instance_btc_tx_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    info!("check user broadcast Pegin-Prepare");
    let batch_size = get_instance_maintenance_batch_size();

    let instances = find_one_instance_page(
        local_db,
        TASK_KEY_INSTANCE_BTC_TX,
        InstanceQuery::default().with_statuses(vec![
            InstanceBridgeInStatus::UserInited.to_string(),
            InstanceBridgeInStatus::CommitteesAnswered.to_string(),
            InstanceBridgeInStatus::Presigned.to_string(),
            InstanceBridgeInStatus::Timeout.to_string(),
        ]),
        batch_size,
    )
    .await?;
    for instance in instances {
        let (txid_op, next_status) = match InstanceBridgeInStatus::from_str(&instance.status) {
            Ok(status) => match status {
                InstanceBridgeInStatus::UserInited => {
                    (None, InstanceBridgeInStatus::CommitteesAnswered)
                }
                InstanceBridgeInStatus::CommitteesAnswered => {
                    (instance.btc_txid.clone(), InstanceBridgeInStatus::UserBroadcastPeginPrepare)
                }
                InstanceBridgeInStatus::Presigned => (
                    instance.pegin_confirm_txid.clone(),
                    InstanceBridgeInStatus::RelayerL1Broadcasted,
                ),
                InstanceBridgeInStatus::Timeout => {
                    (instance.pegin_cancel_txid.clone(), InstanceBridgeInStatus::UserCanceled)
                }
                _ => (None, status),
            },
            Err(err) => {
                warn!(
                    "failed to parse instance:{}, {} status: {}",
                    instance.instance_id,
                    instance.status,
                    err.to_string()
                );
                continue;
            }
        };
        if let Some(txid) = txid_op.clone()
            && let Ok(status) = btc_client.get_tx_status(&txid.0).await
            && status.confirmed
        {
            let mut tx = local_db.start_transaction().await?;
            let mut instance_update = InstanceUpdate::new_with_instance_id(instance.instance_id)
                .with_status(next_status.to_string());
            match next_status {
                InstanceBridgeInStatus::UserBroadcastPeginPrepare => {
                    instance_update = instance_update
                        .with_btc_height(status.block_height.unwrap_or_default() as i64);
                    upsert_message(
                        &mut tx,
                        false,
                        instance.instance_id,
                        None,
                        SELF_SENDER.to_string(),
                        Actor::All,
                        GOATMessageContent::ConfirmInstance(ConfirmInstance {
                            instance_id: instance.instance_id,
                        }),
                        0,
                        0,
                    )
                    .await?;
                }
                InstanceBridgeInStatus::RelayerL1Broadcasted => {
                    upsert_message(
                        &mut tx,
                        false,
                        instance.instance_id,
                        None,
                        SELF_SENDER.to_string(),
                        Actor::All,
                        GOATMessageContent::PostReady(PostReady {
                            instance_id: instance.instance_id,
                        }),
                        0,
                        0,
                    )
                    .await?;
                }
                _ => {}
            }
            update_instance(&mut tx, &instance_update).await?;
            tx.commit().await?;
        } else {
            warn!(
                "instance:{}, status{}, check tx_id:{:?} is not chain ",
                instance.instance_id, instance.status, txid_op
            );
            if [
                InstanceBridgeInStatus::CommitteesAnswered,
                InstanceBridgeInStatus::UserBroadcastPeginPrepare,
            ]
            .contains(&next_status)
                && let utxos = serde_json::from_str::<Vec<Utxo>>(&instance.input_utxos)?
                && let Some(user_prepare_tx) = instance.btc_txid
                && !check_bridge_in_uxto_available_or_self_spent(
                    btc_client,
                    Some(user_prepare_tx.0.to_string()),
                    &utxos,
                )
                .await?
            {
                warn!(
                    "instance:{}, pegin prepare tx input utxos has been spent in other tx",
                    instance.instance_id
                );
                let mut storage_processor = local_db.acquire().await?;
                update_instance(
                    &mut storage_processor,
                    &InstanceUpdate::new_with_instance_id(instance.instance_id)
                        .with_status(InstanceBridgeInStatus::UserDiscarded.to_string()),
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Re-publish persisted PeginConfirm signing material until the transaction is visible on Bitcoin.
/// This never derives a new partial signature: it only reuses the deterministic nonce or stored signature.
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
            push_local_unhandled_messages_with_reason(
                local_db,
                instance_id,
                &message,
                0,
                MessageDeferReason::RecoveryRepublish,
                "re-publishing persisted pegin-confirm partial signature",
            )
            .await?;
            tracing::info!(
                event = "pegin_confirm_recovery",
                action = "republish_partial_signature",
                instance_id = %instance_id,
                "queued persisted PeginConfirm partial signature for re-publication"
            );
            continue;
        }

        let (_, derived_pub_nonce, nonce_sig) = committee_master_key
            .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
        let pub_nonce = match get_committee_pub_nonce_for_instance(
            local_db,
            instance_id,
            &local_committee_pubkey,
        )
        .await?
        {
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
        push_local_unhandled_messages_with_reason(
            local_db,
            instance_id,
            &message,
            0,
            MessageDeferReason::RecoveryRepublish,
            "re-publishing persisted pegin-confirm nonce",
        )
        .await?;
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
            push_local_unhandled_messages_with_reason(
                local_db,
                instance_id,
                &message,
                0,
                MessageDeferReason::RecoveryRepublish,
                "re-publishing persisted PeginConfirm nonce consensus",
            )
            .await?;
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

fn list_committee_instance_key_envelopes() -> anyhow::Result<Vec<(Uuid, PathBuf)>> {
    let dir = PathBuf::from(COMMITTEE_INSTANCE_KEYS_DIR);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut envelopes = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            warn!("invalid committee key envelope filename: {}", path.display());
            continue;
        };
        match Uuid::parse_str(stem) {
            Ok(instance_id) => envelopes.push((instance_id, path)),
            Err(err) => {
                warn!("skip non-instance envelope file {}: {}", path.display(), err);
            }
        }
    }
    Ok(envelopes)
}

pub async fn instance_committee_key_cleanup_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    if !is_enable_committee_instance_key_delete() {
        return Ok(());
    }

    let envelopes = list_committee_instance_key_envelopes()?;
    if envelopes.is_empty() {
        return Ok(());
    }

    let current_height = btc_client.get_height().await? as i64;
    let delete_timelock_blocks = get_committee_instance_key_delete_timelock_blocks();
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let mut storage_processor = local_db.acquire().await?;

    for (instance_id, envelope_path) in envelopes {
        let Some(instance) = storage_processor.find_instance(&instance_id).await? else {
            warn!(
                "committee key envelope exists but instance missing: {} ({})",
                instance_id,
                envelope_path.display()
            );
            continue;
        };

        let Some(pegin_confirm_txid) = instance.pegin_confirm_txid else {
            continue;
        };

        let tx_status = match btc_client.get_tx_status(&pegin_confirm_txid.0).await {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    "failed to query pegin-confirm tx status for instance {}: {}",
                    instance_id, err
                );
                continue;
            }
        };
        if !tx_status.confirmed {
            continue;
        }
        let Some(confirmed_height) = tx_status.block_height else {
            continue;
        };
        if (confirmed_height as i64 + delete_timelock_blocks) > current_height {
            continue;
        }

        match committee_master_key.delete_instance_keypair_envelope(instance_id, &envelope_path) {
            Ok(()) => {
                info!(
                    "deleted committee instance key envelope for {} at {}",
                    instance_id,
                    envelope_path.display()
                );
            }
            Err(err) => {
                warn!(
                    "failed to delete committee instance key envelope for {} at {}: {}",
                    instance_id,
                    envelope_path.display(),
                    err
                );
            }
        }
    }

    Ok(())
}
