//! Gateway events: withdraws, bridge-ins, committee answers and posted graphs.

use crate::aggregates::graph::{graph_posted_event, graph_pull_event};
use crate::aggregates::graph_fetch::GraphLookup;
use crate::aggregates::graph_pegout::{
    goat_status_event, withdraw_cancel_event, withdraw_init_event,
};
use crate::aggregates::instance::l2_minted_event;
use crate::clock::current_time_secs;
use crate::engine_bridge::record_event_in;
use crate::utils::{
    generate_instance_from_bridge_in_request_event, obsolete_instance_graphs_except,
    reflect_goat_address, strip_hex_prefix_owned,
};
use alloy::primitives::U256;
use bitvm_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    BlockRange, BridgeInEvent, BridgeInRequestEvent, CancelWithdrawEvent, CommitteeResponseEvent,
    GatewayEventEntity, InitWithdrawEvent, PostGraphDataEvent, ProceedWithdrawEvent,
    UserGraphWithdrawEvent, WithdrawDisprovedEvent, WithdrawHappyEvent, WithdrawPathsEvent,
    WithdrawUnhappyEvent, get_gateway_events_query,
};
use std::ops::AddAssign;
use std::str::FromStr;
use std::sync::Arc;
use store::localdb::{GraphRuntimeUpdate, NodeQuery, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphStatus, GraphStatusSource,
    GraphStatusTransitionOutcome, InstanceBridgeInStatus,
};
use tracing::{info, warn};
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_gateway_events<'a>(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    graph_url: &str,
    event_entities: &[GatewayEventEntity],
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
    let query_res = client
        .execute_query(
            graph_url,
            &get_gateway_events_query(
                event_entities,
                Some(BlockRange::new(from_height, to_height)),
            ),
        )
        .await?;

    let mut init_withdraw_events: Vec<InitWithdrawEvent> = vec![];
    let mut cancel_withdraw_events = vec![];
    let mut proceed_withdraw_events: Vec<ProceedWithdrawEvent> = vec![];
    let mut withdraw_paths_events: Vec<WithdrawPathsEvent> = vec![];
    let mut withdraw_disproved_events: Vec<WithdrawDisprovedEvent> = vec![];
    let mut bridge_in_request_events: Vec<BridgeInRequestEvent> = vec![];
    let mut committee_response_events: Vec<CommitteeResponseEvent> = vec![];
    let mut bridge_in_events: Vec<BridgeInEvent> = vec![];
    let mut post_graph_data_events: Vec<PostGraphDataEvent> = vec![];
    for event_entity in event_entities {
        let entity = event_entity.clone();
        if let Some(value_vec) = query_res[entity.to_string()].as_array() {
            match entity {
                GatewayEventEntity::InitWithdraws => {
                    init_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::CancelWithdraws => {
                    cancel_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::ProceedWithdraws => {
                    proceed_withdraw_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::WithdrawHappyPaths => {
                    let events: Vec<WithdrawHappyEvent> =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                    let mut events: Vec<WithdrawPathsEvent> =
                        events.into_iter().map(WithdrawPathsEvent::WithdrawHappyEvent).collect();
                    withdraw_paths_events.append(&mut events);
                }
                GatewayEventEntity::WithdrawUnhappyPaths => {
                    let events: Vec<WithdrawUnhappyEvent> =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                    let mut events: Vec<WithdrawPathsEvent> =
                        events.into_iter().map(WithdrawPathsEvent::WithdrawUnhappyEvent).collect();
                    withdraw_paths_events.append(&mut events);
                }
                GatewayEventEntity::WithdrawDisproveds => {
                    withdraw_disproved_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::BridgeInRequests => {
                    bridge_in_request_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::CommitteeResponses => {
                    committee_response_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::BridgeIns => {
                    bridge_in_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
                GatewayEventEntity::PostGraphDatas => {
                    post_graph_data_events =
                        serde_json::from_value(serde_json::Value::Array(value_vec.clone()))?;
                }
            };
        }
    }
    info!(
        "get user init withdraw events: {}, cancel withdraw events: {}, proceed_withdraw_events: {}, \
         withdraw_paths_events: {},  withdraw_disproved_events: {}, bridge_in_request_events: {}  \
         committee_response_events: {}, bridge_in_events: {}  post_graph_data_events: {} block range {from_height}:{to_height}",
        init_withdraw_events.len(),
        cancel_withdraw_events.len(),
        proceed_withdraw_events.len(),
        withdraw_paths_events.len(),
        withdraw_disproved_events.len(),
        bridge_in_request_events.len(),
        committee_response_events.len(),
        bridge_in_events.len(),
        post_graph_data_events.len(),
    );
    handle_user_withdraw_events(storage_processor, init_withdraw_events, cancel_withdraw_events)
        .await?;
    handle_proceed_withdraw_events(storage_processor, proceed_withdraw_events).await?;
    handle_withdraw_paths_events(storage_processor, withdraw_paths_events).await?;
    handle_withdraw_disproved_events(storage_processor, withdraw_disproved_events).await?;
    handle_bridge_in_request_events(storage_processor, bridge_in_request_events).await?;
    handle_committee_response_events(storage_processor, committee_response_events).await?;
    handle_bridge_in_events(
        storage_processor,
        btc_client.clone(),
        goat_client.clone(),
        bridge_in_events,
    )
    .await?;
    handle_post_graph_data_events(&actor, storage_processor, post_graph_data_events).await?;
    Ok(())
}

async fn handle_user_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    init_withdraw_events: Vec<InitWithdrawEvent>,
    cancel_withdraw_events: Vec<CancelWithdrawEvent>,
) -> anyhow::Result<()> {
    // Within a block, cancels go first: a cancel and a new init of the same
    // graph in one block must leave the new withdraw active. The opposite
    // order (an init cancelled in its own block) leaves a stale withdraw
    // active, which the kickoff ignores after checking it on Goat.
    let mut user_withdraw_events: Vec<UserGraphWithdrawEvent> =
        cancel_withdraw_events.into_iter().map(UserGraphWithdrawEvent::CancelWithdraw).collect();
    user_withdraw_events
        .extend(init_withdraw_events.into_iter().map(UserGraphWithdrawEvent::InitWithdraw));
    user_withdraw_events.sort_by_key(|v| v.get_block_number());
    for event in user_withdraw_events {
        match event {
            UserGraphWithdrawEvent::InitWithdraw(init_event) => {
                let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&init_event.instance_id))?;
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&init_event.graph_id))?;
                if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? {
                    continue;
                }
                if !storage_processor
                    .update_graph_runtime(
                        &GraphRuntimeUpdate::new(instance_id, graph_id)
                            .with_bridge_out_start_at(current_time_secs())
                            .with_init_withdraw_tx_hash(init_event.transaction_hash.clone()),
                    )
                    .await?
                {
                    warn!("ignore InitWithdraw for missing graph {instance_id}:{graph_id}");
                    continue;
                }
                // The Graph aggregate takes the withdraw from here.
                record_event_in(
                    storage_processor,
                    withdraw_init_event(graph_id, &init_event.transaction_hash)?,
                )
                .await?;
                storage_processor
                    .upsert_goat_tx_record(&GoatTxRecord {
                        instance_id,
                        graph_id,
                        tx_type: GoatTxType::InitWithdraw.to_string(),
                        tx_hash: init_event.transaction_hash,
                        height: init_event.block_number.parse::<i64>()?,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Processed.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?
            }
            UserGraphWithdrawEvent::CancelWithdraw(cancel_event) => {
                let instance_id =
                    Uuid::from_str(&strip_hex_prefix_owned(&cancel_event.instance_id))?;
                let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&cancel_event.graph_id))?;
                if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? {
                    continue;
                }
                if !storage_processor
                    .update_graph_runtime(
                        &GraphRuntimeUpdate::new(instance_id, graph_id)
                            .with_bridge_out_start_at(0)
                            .with_init_withdraw_tx_hash("".to_string()),
                    )
                    .await?
                {
                    warn!("ignore CancelWithdraw for missing graph {instance_id}:{graph_id}");
                    continue;
                }
                record_event_in(
                    storage_processor,
                    withdraw_cancel_event(graph_id, &cancel_event.transaction_hash)?,
                )
                .await?;
                storage_processor
                    .upsert_goat_tx_record(&GoatTxRecord {
                        instance_id,
                        graph_id,
                        tx_type: GoatTxType::CancelWithdraw.to_string(),
                        tx_hash: cancel_event.transaction_hash,
                        height: cancel_event.block_number.parse::<i64>()?,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Skipped.to_string(),
                        extra: None,
                        created_at: current_time_secs(),
                    })
                    .await?
            }
        }
    }
    Ok(())
}

async fn handle_proceed_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    proceed_withdraw_events: Vec<ProceedWithdrawEvent>,
) -> anyhow::Result<()> {
    // The record only marks the event as seen; nothing reads its status.
    let processing_status = GoatTxProcessingStatus::Skipped.to_string();
    for event in proceed_withdraw_events {
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?;
        let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?;
        if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? {
            continue;
        }
        let height = event.block_number.parse::<i64>()?;
        if !storage_processor
            .update_graph_runtime(
                &GraphRuntimeUpdate::new(instance_id, graph_id)
                    .with_proceed_withdraw_height(height),
            )
            .await?
        {
            warn!("ignore ProceedWithdraw for missing graph {instance_id}:{graph_id}");
            continue;
        }
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type: GoatTxType::ProceedWithdraw.to_string(),
                tx_hash: event.transaction_hash,
                height,
                is_local: false,
                processing_status: processing_status.clone(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
    }
    Ok(())
}

async fn apply_gateway_graph_status<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    instance_id: Uuid,
    graph_id: Uuid,
    target: GraphStatus,
) -> anyhow::Result<GraphStatusTransitionOutcome> {
    match storage_processor
        .transition_graph_status(instance_id, graph_id, target, GraphStatusSource::GoatEvent, None)
        .await?
    {
        outcome @ (GraphStatusTransitionOutcome::Applied
        | GraphStatusTransitionOutcome::AlreadyCurrent) => Ok(outcome),
        GraphStatusTransitionOutcome::Rejected { current } => {
            warn!(
                "ignore stale gateway graph event: graph={graph_id}, target={target}, current={current}"
            );
            Ok(GraphStatusTransitionOutcome::Rejected { current })
        }
        GraphStatusTransitionOutcome::NotFound => {
            warn!("no local row for graph {graph_id}; gateway event ignored: target={target}");
            Ok(GraphStatusTransitionOutcome::NotFound)
        }
    }
}

async fn graph_belongs_to_instance<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> anyhow::Result<bool> {
    match storage_processor.find_graph(&graph_id).await? {
        Some(graph) if graph.instance_id == instance_id => Ok(true),
        Some(graph) => {
            warn!(
                "ignore gateway event with mismatched graph instance: graph={graph_id}, event_instance={instance_id}, stored_instance={}",
                graph.instance_id
            );
            Ok(false)
        }
        None => {
            warn!("ignore gateway event for missing graph {instance_id}:{graph_id}");
            Ok(false)
        }
    }
}

async fn handle_withdraw_paths_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_paths_events: Vec<WithdrawPathsEvent>,
) -> anyhow::Result<()> {
    for event in withdraw_paths_events {
        let (graph_id, instance_id, tx_type, status) = match event.clone() {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => (
                v.graph_id.clone(),
                v.instance_id.clone(),
                GoatTxType::WithdrawHappyPath.to_string(),
                GraphStatus::OperatorTake1,
            ),
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => (
                v.graph_id.clone(),
                v.instance_id.clone(),
                GoatTxType::WithdrawUnhappyPath.to_string(),
                GraphStatus::OperatorTake2,
            ),
        };
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&graph_id))?;
        let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&instance_id))?;
        if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? {
            continue;
        }

        let reward_add = U256::from_str(&event.reward_amount_str()).unwrap_or_default();
        let (flag, goat_addr) = reflect_goat_address(Some(event.operator_addr()));
        if !flag {
            warn!(
                "handle_withdraw_paths_events failed as cast operator address failed, detail: {}, {}",
                event.tx_hash(),
                event.operator_addr()
            );
            continue;
        }
        let outcome =
            apply_gateway_graph_status(storage_processor, instance_id, graph_id, status).await?;
        if !matches!(
            outcome,
            GraphStatusTransitionOutcome::Applied | GraphStatusTransitionOutcome::AlreadyCurrent
        ) {
            continue;
        }
        let obsoleted_graph_ids =
            obsolete_instance_graphs_except(storage_processor, instance_id, Some(graph_id)).await?;
        if !obsoleted_graph_ids.is_empty() {
            info!(
                instance_id = %instance_id,
                completed_graph_id = %graph_id,
                obsoleted_graph_ids = ?obsoleted_graph_ids,
                "marked other instance graphs obsolete after completed withdrawal"
            );
        }
        let is_new_event = storage_processor
            .find_graph_goat_tx_record(&instance_id, &graph_id, &tx_type)
            .await?
            .is_none();
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type: tx_type.clone(),
                tx_hash: event.tx_hash(),
                height: event.get_block_number(),
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
        if is_new_event {
            add_node_reward(storage_processor, &goat_addr.unwrap(), reward_add).await?;
        }
        // The aggregate mirrors the settlement and releases the next slot.
        record_event_in(storage_processor, goat_status_event(graph_id, status, &event.tx_hash())?)
            .await?;
    }
    Ok(())
}

async fn handle_withdraw_disproved_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    withdraw_disproved_events: Vec<WithdrawDisprovedEvent>,
) -> anyhow::Result<()> {
    for event in withdraw_disproved_events {
        let graph_id = Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id))?;
        let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?;
        if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? {
            continue;
        }
        let (flag, verifier_addr) = reflect_goat_address(Some(event.challenger_addr.clone()));
        if !flag {
            warn!(
                "handle_withdraw_disproved_events failed as cast verifier address failed, detail: {}, {}",
                event.transaction_hash, event.challenger_addr
            );
            continue;
        }
        let (flag, disprover_addr) = reflect_goat_address(Some(event.disprover_addr.clone()));
        if !flag {
            warn!(
                "handle_withdraw_disproved_events failed as cast disprover address failed, detail: {}, {}",
                event.transaction_hash, event.disprover_addr
            );
            continue;
        }

        let outcome = apply_gateway_graph_status(
            storage_processor,
            instance_id,
            graph_id,
            GraphStatus::Disprove,
        )
        .await?;
        if !matches!(
            outcome,
            GraphStatusTransitionOutcome::Applied | GraphStatusTransitionOutcome::AlreadyCurrent
        ) {
            continue;
        }
        let tx_type = GoatTxType::WithdrawDisproved.to_string();
        let is_new_event = storage_processor
            .find_graph_goat_tx_record(&instance_id, &graph_id, &tx_type)
            .await?
            .is_none();
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id,
                graph_id,
                tx_type,
                tx_hash: event.transaction_hash.clone(),
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: None,
                created_at: current_time_secs(),
            })
            .await?;
        if is_new_event {
            if let Some(metrics_state) = crate::metrics_service::node_metrics_state() {
                metrics_state.record_pegout_disprove();
            }
            add_node_reward(
                storage_processor,
                &verifier_addr.unwrap(),
                U256::from_str(&event.challenger_amount_sats).unwrap_or_default(),
            )
            .await?;
            add_node_reward(
                storage_processor,
                &disprover_addr.unwrap(),
                U256::from_str(&event.disprover_amount_sats).unwrap_or_default(),
            )
            .await?;
        }
        record_event_in(
            storage_processor,
            goat_status_event(graph_id, GraphStatus::Disprove, &event.transaction_hash)?,
        )
        .await?;
    }
    Ok(())
}

async fn handle_bridge_in_request_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    bridge_in_request_events: Vec<BridgeInRequestEvent>,
) -> anyhow::Result<()> {
    for event in bridge_in_request_events {
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?,
                graph_id: Uuid::nil(),
                tx_type: GoatTxType::BridgeInRequest.to_string(),
                tx_hash: event.transaction_hash.clone(),
                height: event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: Some(serde_json::to_string(&event)?),
                created_at: current_time_secs(),
            })
            .await?;
    }
    Ok(())
}

async fn handle_committee_response_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    committee_response_events: Vec<CommitteeResponseEvent>,
) -> anyhow::Result<()> {
    for event in committee_response_events {
        if let Ok(instance_id) = &Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)) {
            // Convert hex string to [u8; 32]
            if let Ok(pubkey_bytes) = hex::decode(&event.committee_pubkey) {
                if pubkey_bytes.len() == 33 {
                    let mut pubkey = [0u8; 33];
                    pubkey.copy_from_slice(&pubkey_bytes);
                    storage_processor
                        .update_instance_committee_answer(
                            instance_id,
                            &event.committee_address,
                            pubkey.to_vec(),
                        )
                        .await?;
                } else {
                    warn!("committee_pubkey length is not 33 bytes: {}", event.committee_pubkey);
                }
            } else {
                warn!("failed to decode committee_pubkey: {}", event.committee_pubkey);
            }
        } else {
            warn!("failed to parse instance id:{event:?}");
        }
    }
    Ok(())
}

async fn handle_bridge_in_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    bridge_in_events: Vec<BridgeInEvent>,
) -> anyhow::Result<()> {
    for event in bridge_in_events {
        let post_pegin_txhash = event.transaction_hash.clone();
        let Ok(instance_id) = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)) else {
            warn!("failed to parse instance id of BridgeIn event: {event:?}");
            continue;
        };
        let mut row_exists = storage_processor.find_instance(&instance_id).await?.is_some();
        if !row_exists
            && let Some(tx_record) = storage_processor
                .find_graph_goat_tx_record(
                    &instance_id,
                    &Uuid::nil(),
                    &GoatTxType::BridgeInRequest.to_string(),
                )
                .await?
        {
            // A request seen in history whose instance was never built: build
            // it in its final state.
            warn!("Instance {instance_id} is finished but not find in db. we will create it");
            if let Some(extra) = tx_record.extra.as_ref()
                && let Ok(bridge_event) = serde_json::from_str::<BridgeInRequestEvent>(extra)
            {
                match generate_instance_from_bridge_in_request_event(
                    btc_client.as_ref(),
                    goat_client.as_ref(),
                    &bridge_event,
                )
                .await
                {
                    Ok(mut instance) => {
                        info!(
                            "Instance {instance_id} is created and set status to RelayerL2Minted"
                        );
                        instance.status = InstanceBridgeInStatus::RelayerL2Minted.to_string();
                        instance.post_pegin_txhash = Some(post_pegin_txhash.clone());
                        if !storage_processor.insert_instance_if_absent(&instance).await? {
                            info!(
                                "Instance {instance_id} was created concurrently; applying mint event"
                            );
                        }
                        row_exists = true;
                    }
                    Err(error) => warn!(
                        event = "event_watch",
                        instance_id = %instance_id,
                        error = %error,
                        "could not build the instance of a BridgeIn; mint event skipped"
                    ),
                }
            }

            if tx_record.processing_status == GoatTxProcessingStatus::Pending.to_string() {
                info!(
                    "Instance {instance_id} related goat tx BridgeInRequest set event processing status skipped"
                );
                storage_processor
                    .update_goat_tx_record_processing_status(
                        &Uuid::nil(),
                        &instance_id,
                        &GoatTxType::BridgeInRequest.to_string(),
                        &GoatTxProcessingStatus::Skipped.to_string(),
                    )
                    .await?;
            }
        }
        if !row_exists {
            // Without a row the event would park forever; nothing local to update.
            warn!(
                event = "event_watch",
                instance_id = %instance_id,
                tx_hash = %post_pegin_txhash,
                "BridgeIn for an instance this node never saw the request of; mint event skipped"
            );
            continue;
        }
        // The Instance aggregate applies the mint, or alerts when it holds the instance in a
        // failure state.
        record_event_in(storage_processor, l2_minted_event(instance_id, &post_pegin_txhash)?)
            .await?;
    }
    Ok(())
}

async fn handle_post_graph_data_events<'a>(
    actor: &Actor,
    storage_processor: &mut StorageProcessor<'a>,
    post_graph_data_events: Vec<PostGraphDataEvent>,
) -> anyhow::Result<()> {
    for event in post_graph_data_events {
        match (
            Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)),
            Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id)),
        ) {
            (Ok(instance_id), Ok(graph_id)) => {
                let outcome = apply_gateway_graph_status(
                    storage_processor,
                    instance_id,
                    graph_id,
                    GraphStatus::OperatorDataPushed,
                )
                .await?;
                // Watching roles fetch a finalized definition when the posted graph is absent
                // locally.
                if matches!(outcome, GraphStatusTransitionOutcome::NotFound)
                    && matches!(actor, Actor::Verifier | Actor::Watchtower)
                {
                    record_event_in(
                        storage_processor,
                        graph_pull_event(
                            graph_id,
                            GraphLookup::Id { instance_id, graph_id, finalized: true },
                        )?,
                    )
                    .await?;
                }
                // Posted: the Graph aggregate closes every delivery of the graph.
                record_event_in(storage_processor, graph_posted_event(graph_id)?).await?;
            }
            _ => warn!("failed to parse graph event identifiers: {event:?}"),
        }
    }
    Ok(())
}

async fn add_node_reward(
    storage_processor: &mut StorageProcessor<'_>,
    goat_addr: &str,
    add_value: U256,
) -> anyhow::Result<()> {
    let (nodes, _) = storage_processor
        .find_nodes(&NodeQuery::default().with_goat_addr(goat_addr.to_string()))
        .await?;
    for node in nodes {
        let mut reward = U256::from_str(&node.reward).unwrap_or_default();
        reward.add_assign(&add_value);
        storage_processor.update_node_reward_by_peer_id(&node.peer_id, &reward.to_string()).await?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::localdb::LocalDB;

    async fn db() -> (LocalDB, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.db");
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", path.display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        (db, dir)
    }

    fn posted(instance_id: Uuid, graph_id: Uuid) -> PostGraphDataEvent {
        PostGraphDataEvent {
            id: "1".to_string(),
            transaction_hash: "0xaa".to_string(),
            block_number: "1".to_string(),
            instance_id: format!("0x{}", instance_id.simple()),
            graph_id: format!("0x{}", graph_id.simple()),
        }
    }

    #[tokio::test]
    async fn a_posted_graph_unknown_locally_is_pulled_by_the_watching_roles() {
        let (db, _dir) = db().await;
        for (actor, pulled) in [
            (Actor::Verifier, true),
            (Actor::Watchtower, true),
            (Actor::Operator, false),
            (Actor::Committee, false),
        ] {
            let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
            let mut tx = db.start_transaction().await.unwrap();
            handle_post_graph_data_events(&actor, &mut tx, vec![posted(instance_id, graph_id)])
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let mut storage = db.acquire().await.unwrap();
            let pull = storage
                .find_engine_inbox_event(&format!("graph:{graph_id}:pull:finalized"))
                .await
                .unwrap();
            assert_eq!(pull.is_some(), pulled, "{actor}");
            // The posted event is recorded for every role.
            assert!(
                storage
                    .find_engine_inbox_event(&format!("graph:{graph_id}:posted"))
                    .await
                    .unwrap()
                    .is_some(),
                "{actor}"
            );
        }
    }
}
