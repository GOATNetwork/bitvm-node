//! Instance maintenance that is not a chain scan: handing new Goat peg-in
//! requests to the Instance aggregate, and swap escrow timeouts. Every status
//! decision of an instance lives in the Instance aggregate
//! (`crate::aggregates::instance`); the chain facts it needs are gathered by
//! `crate::aggregates::instance_scan`.

use crate::aggregates::instance::{PeginRequested, pegin_request_event};
use crate::engine_bridge::record_event_in;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::event_watch_task::generate_instance_from_bridge_in_request_event;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use engine::EngineHandle;
use store::localdb::LocalDB;
use store::{GoatTxProcessingStatus, GoatTxType, InstanceBridgeInStatus};
use tracing::{info, warn};

/// Store pending Goat bridge-in requests. Submit pegin_request events only while
/// the response window is open; late requests are handled by the answer-window scan.
pub async fn pegin_request_monitor(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    engine: &EngineHandle,
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
        let instance_id = tx_record.instance_id;
        let event = tx_record
            .extra
            .as_deref()
            .map(serde_json::from_str::<BridgeInRequestEvent>)
            .transpose()?;
        let is_outside_response_window = tx_record.height + response_window_blocks < current_height;
        // The row is built from the indexed event and Goat's pegin data; the
        // request's inputs are checked by the committee's answer job.
        let instance = match event.as_ref() {
            Some(event) => {
                match generate_instance_from_bridge_in_request_event(btc_client, goat_client, event)
                    .await
                {
                    Ok(instance) => Some(instance),
                    Err(error) => {
                        warn!(
                            event = "pegin_request",
                            instance_id = %instance_id,
                            error = %error,
                            "could not build the instance of a BridgeInRequest; retried next tick"
                        );
                        continue;
                    }
                }
            }
            None => None,
        };

        let mut tx = local_db.start_transaction().await?;
        if let Some(instance) = instance {
            if is_outside_response_window {
                if tx.insert_instance_if_absent(&instance).await? {
                    info!(
                        event = "pegin_request",
                        instance_id = %instance_id,
                        outcome = "late",
                        "BridgeInRequest seen after its response window; the answer-window scan decides"
                    );
                }
            } else {
                // A row created by the RPC (UserIniting) is refreshed; a row
                // that moved on is left alone.
                tx.upsert_pegin_request_instance(
                    &instance,
                    &[
                        InstanceBridgeInStatus::UserIniting.to_string(),
                        InstanceBridgeInStatus::UserInited.to_string(),
                    ],
                )
                .await?;
                record_event_in(
                    &mut tx,
                    pegin_request_event(
                        instance_id,
                        &PeginRequested {
                            tx_hash: tx_record.tx_hash.clone(),
                            height: tx_record.height,
                        },
                    )?,
                )
                .await?;
            }
        } else {
            warn!(
                event = "pegin_request",
                instance_id = %instance_id,
                "BridgeInRequest record carries no event; skipped"
            );
        }
        tx.update_goat_tx_record_processing_status(
            &tx_record.graph_id,
            &instance_id,
            &tx_record.tx_type,
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
        if !is_outside_response_window {
            engine.wake_for(&crate::aggregates::instance::instance_ref(instance_id));
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
