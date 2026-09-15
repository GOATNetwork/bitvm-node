use crate::env;
use crate::env::{
    ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_GOAT_SWAP_CONTRACT_ADDRESS,
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, get_goat_address_from_env,
    get_goat_gateway_event_filter_from_from_env, get_goat_gateway_event_filter_gap_from_env,
    get_goat_gateway_the_graph_urls_from_env, get_goat_swap_event_filter_from_from_env,
    get_goat_swap_event_filter_gap_from_env, get_goat_swap_the_graph_urls_from_env, get_network,
};
use crate::metrics_service::{EventWatchState, MetricsState};
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::get_timestamp_from_contract_data;
use crate::utils::evm_swap_utils::{extract_claim_data_from_tx, extract_escrow_data_from_tx};
use crate::utils::{
    GenerateInstanceParams, generate_instance, get_bridge_out_global_stats,
    obsolete_instance_graphs_except, outpoint_available, reflect_goat_address,
    strip_hex_prefix_owned,
};
use alloy::primitives::{Address as EvmAddress, U256};
use alloy::sol_types::SolValue;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, Txid};
use bitvm_lib::actors::Actor;
use bitvm_lib::types::UserInfo;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, GoatInitConfig};
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    BlockRange, BridgeInEvent, BridgeInRequestEvent, CancelWithdrawEvent, CommitteeResponseEvent,
    GatewayEventEntity, InitWithdrawEvent, PostGraphDataEvent, ProceedWithdrawEvent,
    SwapClaimEvent, SwapConfig, SwapEventEntity, SwapInitializeEvent, SwapRefundEvent,
    TheGraphConfig, UserGraphWithdrawEvent, WatchContractType, WatchEventConfig,
    WithdrawDisprovedEvent, WithdrawHappyEvent, WithdrawPathsEvent, WithdrawUnhappyEvent,
    get_bridge_out_events_query, get_gateway_events_query,
};
use goat::transactions::base::Input;
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::ops::AddAssign;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::{
    GraphRuntimeUpdate, InstanceUpdate, LocalDB, NodeQuery, StorageProcessor, SwapEscrowUpdate,
};
use store::{
    GoatTxProcessingStatus, GoatTxRecord, GoatTxType, GraphStatus, GraphStatusSource,
    GraphStatusTransitionOutcome, Instance, InstanceBridgeInStatus, MessageState, SwapEscrow,
    SwapEscrowStatus, WatchContract, WatchContractStatus, normalize_escrow_hash,
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

async fn refresh_event_watch_metrics(
    local_db: &LocalDB,
    goat_client: &GOATClient,
    metrics_state: &MetricsState,
) -> anyhow::Result<()> {
    let finalized_height = goat_client.get_finalized_block_number().await.map_err(|error| {
        metrics_state.record_goat_backend_probe(false);
        warn!(event = "metrics_backend_probe", backend = "goat", operation = "get_finalized_block_number", error = %error, "event watcher lag probe failed");
        error
    })?;
    metrics_state.record_goat_backend_probe(true);

    let snapshot = async {
        let mut storage = local_db.acquire().await?;
        storage.event_watch_metrics_snapshot(finalized_height).await
    }
    .await
    .map_err(|error| {
        metrics_state.record_db_error(&error);
        warn!(event = "metrics_event_watch", error = %error, "failed to collect event watcher state");
        error
    })?;

    metrics_state.apply_event_watch_lag(snapshot.lag_blocks);
    let state = if snapshot.failed_count > 0 {
        EventWatchState::Failed
    } else if snapshot.syncing_count > 0 {
        EventWatchState::Syncing
    } else {
        EventWatchState::Healthy
    };
    metrics_state.set_event_watch_state(state);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_block_range_events<'a>(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    watch_events_config: &WatchEventConfig,
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<()> {
    match watch_events_config {
        WatchEventConfig::Gateway(config) => {
            fetch_and_handle_gateway_events(
                actor,
                btc_client,
                goat_client.clone(),
                client,
                storage_processor,
                &config.the_graph_url,
                &config.event_entities,
                from_height,
                to_height,
            )
            .await?;
        }
        WatchEventConfig::Swap(config) => {
            fetch_and_handle_bridge_out_events(
                goat_client.clone(),
                client,
                storage_processor,
                &config.graph_config.address,
                &config.graph_config.the_graph_url,
                &config.graph_config.event_entities,
                from_height,
                to_height,
                config.peg_btc_address,
            )
            .await?;
        }
    }
    Ok(())
}

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
    handle_proceed_withdraw_events(actor.clone(), storage_processor, proceed_withdraw_events)
        .await?;
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
    handle_post_graph_data_events(storage_processor, post_graph_data_events).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_handle_bridge_out_events<'a>(
    goat_client: Arc<GOATClient>,
    client: &GraphQueryClient,
    storage_processor: &mut StorageProcessor<'a>,
    contract_addr: &EvmAddress,
    graph_url: &str,
    event_entities: &[SwapEventEntity],
    from_height: i64,
    to_height: i64,
    gateway_peg_btc_address: EvmAddress,
) -> anyhow::Result<()> {
    let query_res = client
        .execute_query(
            graph_url,
            &get_bridge_out_events_query(
                event_entities,
                Some(BlockRange::new(from_height, to_height)),
            ),
        )
        .await?;
    for event_entity in event_entities {
        let entity = event_entity.clone();
        if let Some(value_vec) = query_res[entity.to_string()].as_array() {
            match entity {
                SwapEventEntity::Initializes => {
                    handle_swap_init_events(
                        storage_processor,
                        goat_client.clone(),
                        contract_addr,
                        &gateway_peg_btc_address,
                        serde_json::from_value::<Vec<SwapInitializeEvent>>(
                            serde_json::Value::Array(value_vec.clone()),
                        )?,
                    )
                    .await?;
                }
                SwapEventEntity::Claims => {
                    handle_swap_claim_events(
                        storage_processor,
                        goat_client.clone(),
                        contract_addr,
                        &gateway_peg_btc_address,
                        serde_json::from_value::<Vec<SwapClaimEvent>>(serde_json::Value::Array(
                            value_vec.clone(),
                        ))?,
                    )
                    .await?;
                }
                SwapEventEntity::Refunds => {
                    handle_swap_refund_events(
                        storage_processor,
                        &gateway_peg_btc_address,
                        serde_json::from_value::<Vec<SwapRefundEvent>>(serde_json::Value::Array(
                            value_vec.clone(),
                        ))?,
                    )
                    .await?;
                }
            };
        }
    }
    Ok(())
}

async fn handle_user_withdraw_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    init_withdraw_events: Vec<InitWithdrawEvent>,
    cancel_withdraw_events: Vec<CancelWithdrawEvent>,
) -> anyhow::Result<()> {
    let mut user_withdraw_events: Vec<UserGraphWithdrawEvent> =
        init_withdraw_events.into_iter().map(UserGraphWithdrawEvent::InitWithdraw).collect();
    let mut user_cancel_withdraw_events: Vec<UserGraphWithdrawEvent> =
        cancel_withdraw_events.into_iter().map(UserGraphWithdrawEvent::CancelWithdraw).collect();
    user_withdraw_events.append(&mut user_cancel_withdraw_events);
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
                storage_processor
                    .upsert_goat_tx_record(&GoatTxRecord {
                        instance_id,
                        graph_id,
                        tx_type: GoatTxType::InitWithdraw.to_string(),
                        tx_hash: init_event.transaction_hash,
                        height: init_event.block_number.parse::<i64>()?,
                        is_local: false,
                        processing_status: GoatTxProcessingStatus::Pending.to_string(),
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
    actor: Actor,
    storage_processor: &mut StorageProcessor<'a>,
    proceed_withdraw_events: Vec<ProceedWithdrawEvent>,
) -> anyhow::Result<()> {
    let processing_status = if actor == Actor::Operator && env::get_proof_server_url().is_none() {
        GoatTxProcessingStatus::Pending.to_string()
    } else {
        GoatTxProcessingStatus::Skipped.to_string()
    };
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

        // for history events
        storage_processor
            .update_goat_tx_record_processing_status(
                &graph_id,
                &instance_id,
                &GoatTxType::InitWithdraw.to_string(),
                &GoatTxProcessingStatus::Processed.to_string(),
            )
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
            warn!("ignore gateway graph event for missing graph {graph_id}: target={target}");
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
        storage_processor
            .update_messages_state_by_business_id(
                &graph_id,
                None,
                MessageState::Pending.to_string(),
                MessageState::Cancelled.to_string(),
            )
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
        storage_processor
            .update_messages_state_by_business_id(
                &graph_id,
                None,
                MessageState::Pending.to_string(),
                MessageState::Cancelled.to_string(),
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
                    warn!("committee_pubkey length is not 32 bytes: {}", event.committee_pubkey);
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
        if let Ok(instance_id) = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))
            && !storage_processor
                .update_instance(
                    &InstanceUpdate::new_with_instance_id(instance_id)
                        .with_status(InstanceBridgeInStatus::RelayerL2Minted.to_string())
                        .with_post_pegin(event.transaction_hash),
                )
                .await?
            && let Some(tx_record) = storage_processor
                .find_graph_goat_tx_record(
                    &instance_id,
                    &Uuid::nil(),
                    &GoatTxType::BridgeInRequest.to_string(),
                )
                .await?
        {
            // it will happened when handle history events
            warn!("Instance {instance_id} is finished but not find in db. we will create it");
            if let Some(extra) = tx_record.extra.as_ref()
                && let Ok(bridge_event) = serde_json::from_str::<BridgeInRequestEvent>(extra)
                && let Ok((mut instance, _)) = generate_instance_from_bridge_in_request_event(
                    btc_client.as_ref(),
                    goat_client.as_ref(),
                    &bridge_event,
                    false,
                )
                .await
            {
                info!("Instance {instance_id} is created and set status to RelayerL2Minted");
                instance.status = InstanceBridgeInStatus::RelayerL2Minted.to_string();
                storage_processor.upsert_instance(&instance).await?;
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
    }
    Ok(())
}

async fn handle_swap_init_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    goat_client: Arc<GOATClient>,
    swap_contract_address: &EvmAddress,
    gateway_peg_btc_address: &EvmAddress,
    init_events: Vec<SwapInitializeEvent>,
) -> anyhow::Result<()> {
    for event in init_events {
        let Some(escrow_data) = extract_escrow_data_from_tx(
            &goat_client,
            &event.transaction_hash,
            swap_contract_address,
            &hex::decode(strip_hex_prefix_owned(&event.escrow_hash))?.try_into().map_err(
                |v: Vec<u8>| anyhow::anyhow!("escrow_hash length is {}, expected 32", v.len()),
            )?,
        )
        .await?
        else {
            warn!("failed to parse escrow_data for event:{event:?}");
            continue;
        };
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let create_time = event.block_timestamp.parse::<i64>()?;
        let event_height = event.block_number.parse::<i64>()?;
        let escrow = SwapEscrow {
            escrow_hash: escrow_hash.clone(),
            network: get_network().to_string(),
            status: SwapEscrowStatus::Initialize.to_string(),
            offerer_addr: escrow_data.offerer.to_string(),
            claimer_addr: escrow_data.claimer.to_string(),
            token: escrow_data.token.to_string(),
            amount: escrow_data.amount.to_string(),
            refund_deadline: get_timestamp_from_contract_data(&escrow_data.refundData.0),
            escrow_data: Some(hex::encode(escrow_data.abi_encode())),
            init_tx_hash: event.transaction_hash.clone(),
            init_tx_height: event_height,
            status_updated_at: create_time,
            created_at: create_time,
            ..Default::default()
        };
        // Swap records are derived exclusively from the on-chain Initialize
        // event; duplicate event scans must not overwrite the first record.
        let initialized = storage_processor.insert_swap_escrow_if_absent(&escrow).await?;
        if initialized && escrow_data.token == *gateway_peg_btc_address {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut initial_amount =
                U256::from_str(&bridge_out_global_stats.initial_amount).unwrap_or_default();
            initial_amount.add_assign(&escrow_data.amount);
            bridge_out_global_stats.initial_amount = initial_amount.to_string();
            bridge_out_global_stats.initial_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap initialize stats included: tx_hash={}, escrow_hash={}, token={}, amount={}",
                event.transaction_hash, escrow_hash, escrow_data.token, escrow_data.amount,
            );
        } else if initialized {
            info!(
                "swap initialize stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}, token={}, expect_token={}",
                event.transaction_hash, escrow_hash, escrow_data.token, gateway_peg_btc_address,
            );
        } else {
            info!(
                "swap initialize ignored for resolved or previously initialized escrow {escrow_hash}"
            );
        }
    }
    Ok(())
}

async fn handle_swap_claim_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    goat_client: Arc<GOATClient>,
    swap_contract_address: &EvmAddress,
    gateway_peg_btc_address: &EvmAddress,
    claim_events: Vec<SwapClaimEvent>,
) -> anyhow::Result<()> {
    for event in claim_events {
        let Some(claim_data) = extract_claim_data_from_tx(
            &goat_client,
            &event.transaction_hash,
            swap_contract_address,
            &hex::decode(strip_hex_prefix_owned(&event.escrow_hash))?.try_into().map_err(
                |v: Vec<u8>| anyhow::anyhow!("escrow_hash length is {}, expected 32", v.len()),
            )?,
        )
        .await?
        else {
            warn!("failed to parse claim_data for event:{event:?}");
            continue;
        };
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let Some(escrow) = storage_processor.find_swap_escrow(&escrow_hash).await? else {
            warn!(
                "swap claim ignored for unknown escrow {escrow_hash}, tx_hash={}",
                event.transaction_hash
            );
            continue;
        };
        let btc_addr = Address::from_script(
            bitcoin::Script::from_bytes(&claim_data.output_script),
            get_network(),
        )
        .map(|address| address.to_string())
        .unwrap_or_else(|error| {
            warn!(
                escrow_hash = %escrow_hash,
                tx_hash = %event.transaction_hash,
                output_script = %hex::encode(&claim_data.output_script),
                %error,
                "swap claim output script is not a Bitcoin address; storing an empty display address"
            );
            String::new()
        });
        // The claim event is authoritative: it also overrides a locally
        // derived Timeout.
        let transitioned = storage_processor
            .update_swap_escrow(
                &SwapEscrowUpdate::new(escrow_hash.clone())
                    .with_status(SwapEscrowStatus::Claim.to_string())
                    .with_claim_tx_hash(event.transaction_hash.clone())
                    .with_claim_btc_txid(claim_data.txid.into())
                    .with_btc_addr(btc_addr)
                    .with_only_if_status_in(vec![
                        SwapEscrowStatus::Initialize.to_string(),
                        SwapEscrowStatus::Timeout.to_string(),
                    ]),
            )
            .await?;
        if !transitioned {
            info!(
                "swap claim ignored for resolved escrow {escrow_hash} with status {}",
                escrow.status
            );
            continue;
        }
        if escrow.token == gateway_peg_btc_address.to_string() {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut claim_amount =
                U256::from_str(&bridge_out_global_stats.claim_amount).unwrap_or_default();
            claim_amount.add_assign(&U256::from_str(&escrow.amount).unwrap_or_default());
            bridge_out_global_stats.claim_amount = claim_amount.to_string();
            bridge_out_global_stats.claim_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap claim stats included: tx_hash={}, escrow_hash={}, amount={}",
                event.transaction_hash, escrow_hash, escrow.amount,
            );
        } else {
            info!(
                "swap claim stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}",
                event.transaction_hash, escrow_hash,
            );
        }
    }
    Ok(())
}

async fn handle_swap_refund_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    gateway_peg_btc_address: &EvmAddress,
    refund_events: Vec<SwapRefundEvent>,
) -> anyhow::Result<()> {
    for event in refund_events {
        let escrow_hash = normalize_escrow_hash(&event.escrow_hash);
        let Some(escrow) = storage_processor.find_swap_escrow(&escrow_hash).await? else {
            warn!(
                "swap refund ignored for unknown escrow {escrow_hash}, tx_hash={}",
                event.transaction_hash
            );
            continue;
        };
        // The refund event is authoritative: it also overrides a locally
        // derived Timeout.
        let transitioned = storage_processor
            .update_swap_escrow(
                &SwapEscrowUpdate::new(escrow_hash.clone())
                    .with_status(SwapEscrowStatus::Refund.to_string())
                    .with_refund_tx_hash(event.transaction_hash.clone())
                    .with_only_if_status_in(vec![
                        SwapEscrowStatus::Initialize.to_string(),
                        SwapEscrowStatus::Timeout.to_string(),
                    ]),
            )
            .await?;
        if !transitioned {
            info!(
                "swap refund ignored for resolved escrow {escrow_hash} with status {}",
                escrow.status
            );
            continue;
        }
        if escrow.token == gateway_peg_btc_address.to_string() {
            let mut bridge_out_global_stats =
                get_bridge_out_global_stats(storage_processor).await?;
            let mut refund_amount =
                U256::from_str(&bridge_out_global_stats.refund_amount).unwrap_or_default();
            refund_amount.add_assign(&U256::from_str(&escrow.amount).unwrap_or_default());
            bridge_out_global_stats.refund_amount = refund_amount.to_string();
            bridge_out_global_stats.refund_txn += 1;
            storage_processor.upsert_bridge_out_global_stats(&bridge_out_global_stats).await?;
            info!(
                "swap refund stats included: tx_hash={}, escrow_hash={}, amount={}",
                event.transaction_hash, escrow_hash, escrow.amount,
            );
        } else {
            info!(
                "swap refund stats skipped(non-pegBTC): tx_hash={}, escrow_hash={}",
                event.transaction_hash, escrow_hash,
            );
        }
    }
    Ok(())
}

pub(super) async fn generate_instance_from_bridge_in_request_event(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    event: &BridgeInRequestEvent,
    is_check_utxos: bool,
) -> anyhow::Result<(Instance, bool)> {
    let mut input_utxo_available = true;
    let instance_id = Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id))?;
    let pegin_data = goat_client.gateway_get_pegin_data(&instance_id).await?;
    let inputs: Vec<Input> = pegin_data
        .user_inputs
        .iter()
        .map(|u| Input {
            outpoint: OutPoint { txid: Txid::from_byte_array(u.txid), vout: u.vout },
            amount: Amount::from_sat(u.amount_sats),
        })
        .collect();

    if is_check_utxos {
        for input in &inputs {
            if !outpoint_available(btc_client, &input.outpoint.txid, input.outpoint.vout.into())
                .await?
            {
                input_utxo_available = false;
                break;
            }
        }
    }

    let user_change_address: Address<NetworkUnchecked> =
        Address::from_str(&event.user_change_address)?;
    let user_refund_addr: Address<NetworkUnchecked> =
        Address::from_str(&event.user_refund_address)?;
    let network = get_network();
    let user_info = UserInfo {
        depositor_evm_address: EvmAddress::from_str(&event.depositor_address)?.into_array(),
        txn_fees: event.txn_fees.clone().map(|s| s.parse::<u64>().unwrap_or(0)),
        inputs,
        user_xonly_pubkey: XOnlyPublicKey::from_str(&strip_hex_prefix_owned(
            &event.user_xonly_pubkey,
        ))?,
        user_change_address: user_change_address.require_network(network)?,
        user_refund_address: user_refund_addr.require_network(network)?,
    };
    let instance = generate_instance(
        btc_client,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount: Amount::from_sat(event.pegin_amount_sats.parse::<u64>().unwrap_or(0)),
            pegin_request_tx_hash: event.transaction_hash.clone(),
            pegin_request_height: event.block_number.parse::<i64>().unwrap_or(0),
            pegin_timestamp: event.block_timestamp.parse::<i64>().unwrap_or(current_time_secs()),
        },
    )
    .await?;
    Ok((instance, input_utxo_available))
}
async fn handle_post_graph_data_events<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    post_graph_data_events: Vec<PostGraphDataEvent>,
) -> anyhow::Result<()> {
    for event in post_graph_data_events {
        match (
            Uuid::from_str(&strip_hex_prefix_owned(&event.instance_id)),
            Uuid::from_str(&strip_hex_prefix_owned(&event.graph_id)),
        ) {
            (Ok(instance_id), Ok(graph_id)) => {
                let _ = apply_gateway_graph_status(
                    storage_processor,
                    instance_id,
                    graph_id,
                    GraphStatus::OperatorDataPushed,
                )
                .await?;
            }
            _ => warn!("failed to parse graph event identifiers: {event:?}"),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_history_events(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    query_client: &GraphQueryClient,
    watch_contract: WatchContract,
    watch_events_config: WatchEventConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let task_name = watch_events_config.get_watch_contract_type().to_string();
    info!("Start into fetch_history_events from:{} for {task_name}", watch_contract.from_height);
    // let goat_client = GOATClient::new(env::goat_config_from_env().await, env::get_goat_network());
    let mut watch_contract = watch_contract.clone();
    let local_db_clone = local_db.clone();
    let contract_addr = watch_contract.contract_addr.clone();
    let async_fn = || async move {
        let task_name = watch_events_config.get_watch_contract_type().to_string();
        loop {
            // let current_finalized = goat_client.get_finalized_block_number().await;
            let current_finalized = match query_client
                .get_sync_block_height(&watch_contract.the_graph_url)
                .await
            {
                Ok(Some(v)) => v,
                Ok(None) => {
                    warn!(
                        "fetch_history_events:fail to get graph sync block height, will try later, empty value returned"
                    );
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Err(e) => {
                    warn!(
                        "fetch_history_events:fail to get graph sync block height, will try later, err:{e:#}"
                    );
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };

            if watch_contract.from_height > current_finalized {
                info!(
                    "Contract {task_name} fetch history events will finish, as current finalize height: {current_finalized} is litter than watch from height: {}",
                    watch_contract.from_height,
                );
                continue;
            }

            let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
            let mut tx = local_db.start_transaction().await?;

            fetch_and_handle_block_range_events(
                actor.clone(),
                btc_client.clone(),
                goat_client.clone(),
                query_client,
                &mut tx,
                &watch_events_config,
                watch_contract.from_height,
                to_height,
            )
            .await?;
            info!(
                "Contract {task_name} finish load history event from: {}, to: {to_height}",
                watch_contract.from_height
            );
            watch_contract.from_height = to_height + 1;
            watch_contract.status = WatchContractStatus::Syncing.to_string();
            watch_contract.updated_at = current_time_secs();

            if to_height >= current_finalized {
                info!("Contract {task_name} Finish load history at {to_height}");
                watch_contract.status = WatchContractStatus::Synced.to_string();
                tx.upsert_watch_contract(&watch_contract).await?;
                tx.commit().await?;
                break;
            }
            tx.upsert_watch_contract(&watch_contract).await?;
            tx.commit().await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let err = match async_fn().await {
        Ok(_) => false,
        Err(err) => {
            warn!("{task_name} fetch_history_events failed,err:{:?}", err);
            true
        }
    };
    if err {
        let mut storage_processor = local_db_clone.acquire().await?;
        let _ = storage_processor
            .update_watch_contract_status(
                &contract_addr,
                &WatchContractStatus::Failed.to_string(),
                current_time_secs(),
            )
            .await;
    }
    Ok(())
}

pub async fn monitor_events(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    watch_configs: Vec<WatchEventConfig>,
) -> anyhow::Result<()> {
    for watch_config in watch_configs {
        if watch_config.get_watch_events_len() == 0 {
            continue;
        }
        monitor_events_item(
            actor.clone(),
            btc_client.clone(),
            goat_client.clone(),
            local_db,
            watch_config,
        )
        .await?;
    }

    Ok(())
}

pub async fn monitor_events_item(
    actor: Actor,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    local_db: &LocalDB,
    watch_events_config: WatchEventConfig,
) -> anyhow::Result<()> {
    info!("start tick monitor_events");
    let mut storage_processor = local_db.acquire().await?;
    let mut watch_contract = get_watch_contract(
        &mut storage_processor,
        &watch_events_config.get_watch_contract().to_string(),
        watch_events_config.get_watch_contract_type(),
    )
    .await?;

    let query_client = GraphQueryClient::new();
    // let current_finalized = goat_client.get_finalized_block_number().await?;
    let current_finalized = match query_client
        .get_sync_block_height(&watch_contract.the_graph_url)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            warn!(
                "monitor_events_item:fail to get graph sync block height, will try later, empty value returned"
            );
            return Ok(());
        }
        Err(e) => {
            warn!(
                "monitor_events_item:fail to get graph sync block height, will try later, err:{e:#}"
            );
            return Ok(());
        }
    };

    if watch_contract.from_height == 0 || watch_contract.from_height >= current_finalized {
        warn!(
            "watch_contract start height is zero or bigger than current height, not do watch jobs"
        );
        return Ok(());
    }
    if watch_contract.status == WatchContractStatus::Syncing.to_string()
        && watch_contract.updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS > current_time_secs()
    {
        info!("Event sync not finished ");
        return Ok(());
    }
    if watch_contract.from_height + watch_contract.gap < current_finalized {
        let watch_contract_clone = watch_contract.clone();
        let local_db_clone = local_db.clone();
        let query_client_clone = query_client.clone();
        let watch_events_config_clone = watch_events_config.clone();
        tokio::spawn(async move {
            if let Err(error) = fetch_history_events(
                actor.clone(),
                btc_client.clone(),
                goat_client,
                &local_db_clone,
                &query_client_clone,
                watch_contract_clone,
                watch_events_config_clone,
            )
            .await
            {
                warn!(event = "event_watch_history_sync", error = %error, "event watcher history sync task exited unexpectedly");
            }
        });
        return Ok(());
    }

    let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
    let mut tx = local_db.start_transaction().await?;
    fetch_and_handle_block_range_events(
        actor.clone(),
        btc_client,
        goat_client,
        &query_client,
        &mut tx,
        &watch_events_config,
        watch_contract.from_height,
        to_height,
    )
    .await?;
    info!("finish monitor event from: {}, to: {to_height}", watch_contract.from_height);
    watch_contract.from_height = to_height + 1;
    watch_contract.status = WatchContractStatus::Synced.to_string();
    watch_contract.updated_at = current_time_secs();
    tx.upsert_watch_contract(&watch_contract).await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_watch_event_task(
    actor: Actor,
    local_db: LocalDB,
    btc_client: Arc<BTCClient>,
    goat_client: Arc<GOATClient>,
    interval: u64,
    cancellation_token: CancellationToken,
    goat_init_config: GoatInitConfig,
    metrics_state: MetricsState,
) -> anyhow::Result<String> {
    let gateway_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set gateway contract address"))?;
    let swap_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_SWAP_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set swap contract address"))?;
    let events_map: HashMap<Actor, Vec<WatchEventConfig>> = HashMap::from([
        (
            Actor::Committee,
            vec![
                WatchEventConfig::Gateway(TheGraphConfig {
                    address: gateway_contract,
                    the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                    event_entities: vec![
                        GatewayEventEntity::InitWithdraws,
                        GatewayEventEntity::CancelWithdraws,
                        GatewayEventEntity::ProceedWithdraws,
                        GatewayEventEntity::WithdrawHappyPaths,
                        GatewayEventEntity::WithdrawUnhappyPaths,
                        GatewayEventEntity::WithdrawDisproveds,
                        GatewayEventEntity::BridgeInRequests,
                        GatewayEventEntity::BridgeIns,
                        GatewayEventEntity::PostGraphDatas,
                    ],
                }),
                WatchEventConfig::Swap(SwapConfig {
                    graph_config: TheGraphConfig {
                        address: swap_contract,
                        the_graph_url: get_goat_swap_the_graph_urls_from_env(),
                        event_entities: vec![
                            SwapEventEntity::Initializes,
                            SwapEventEntity::Claims,
                            SwapEventEntity::Refunds,
                        ],
                    },
                    peg_btc_address: goat_init_config.peg_btc_address.expect(
                        "peg_btc_address must be set (requires GOAT_GATEWAY_CONTRACT_ADDRESS)",
                    ),
                }),
            ],
        ),
        (
            Actor::Operator,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
        (
            Actor::Verifier,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
        (
            Actor::Verifier,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
        (
            Actor::Watchtower,
            vec![WatchEventConfig::Gateway(TheGraphConfig {
                address: gateway_contract,
                the_graph_url: get_goat_gateway_the_graph_urls_from_env(),
                event_entities: vec![
                    GatewayEventEntity::InitWithdraws,
                    GatewayEventEntity::CancelWithdraws,
                    GatewayEventEntity::ProceedWithdraws,
                    GatewayEventEntity::WithdrawHappyPaths,
                    GatewayEventEntity::WithdrawUnhappyPaths,
                    GatewayEventEntity::WithdrawDisproveds,
                    GatewayEventEntity::BridgeInRequests,
                    GatewayEventEntity::BridgeIns,
                    GatewayEventEntity::PostGraphDatas,
                ],
            })],
        ),
    ]);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                let started_at = Instant::now();
                // Execute the normal monitoring logic
                match monitor_events(
                        actor.clone(),
                        btc_client.clone(),
                        goat_client.clone(),
                        &local_db,
                       events_map.get(&actor).cloned().unwrap_or_default(),
                    )
                    .await
                    {
                        Ok(_) => {
                            metrics_state.record_task_run(
                                "event_watcher",
                                "success",
                                started_at.elapsed(),
                            );
                            let local_db = local_db.clone();
                            let goat_client = goat_client.clone();
                            let metrics_state = metrics_state.clone();
                            tokio::spawn(async move {
                                if let Ok(Err(error)) = tokio::time::timeout(
                                    Duration::from_secs(30),
                                    refresh_event_watch_metrics(
                                        &local_db,
                                        goat_client.as_ref(),
                                        &metrics_state,
                                    ),
                                )
                                .await
                                {
                                    metrics_state.set_event_watch_state(EventWatchState::Failed);
                                    warn!(event = "metrics_event_watch", error = %error, "failed to refresh event watcher metrics");
                                }
                            });
                        }
                        Err(e) => {
                            metrics_state.set_event_watch_state(EventWatchState::Failed);
                            metrics_state.record_task_run(
                                "event_watcher",
                                "failed",
                                started_at.elapsed(),
                            );
                            warn!("fail to monitor events: {e}");
                        }
                    }
            }
            _ = cancellation_token.cancelled() => {
                info!("Watch event task received shutdown signal");
                return Ok("watch_shutdown".to_string());
            }
        }
    }
}

async fn get_watch_contract<'a>(
    storage_processor: &mut StorageProcessor<'a>,
    contract_addr: &str,
    contract_type: WatchContractType,
) -> anyhow::Result<WatchContract> {
    let (from_height, the_graph_url, gap) = match contract_type {
        WatchContractType::Gateway => (
            get_goat_gateway_event_filter_from_from_env(),
            get_goat_gateway_the_graph_urls_from_env(),
            get_goat_gateway_event_filter_gap_from_env(),
        ),
        WatchContractType::Swap => (
            get_goat_swap_event_filter_from_from_env(),
            get_goat_swap_the_graph_urls_from_env(),
            get_goat_swap_event_filter_gap_from_env(),
        ),
    };

    if let Some(mut watch_contract) = storage_processor.find_watch_contract(contract_addr).await? {
        if from_height > watch_contract.from_height {
            watch_contract.from_height = from_height;
        }
        if the_graph_url != watch_contract.the_graph_url {
            watch_contract.the_graph_url = the_graph_url;
        }

        if gap != watch_contract.gap {
            watch_contract.gap = gap
        }
        Ok(watch_contract)
    } else {
        Ok(WatchContract {
            contract_addr: contract_addr.to_string(),
            the_graph_url,
            gap,
            from_height,
            status: WatchContractStatus::UnSync.to_string(),
            extra: None,
            updated_at: current_time_secs(),
            created_at: current_time_secs(),
        })
    }
}

pub async fn is_processing_gateway_history_events(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<bool> {
    let gateway_contract: EvmAddress = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or(anyhow::anyhow!("need to set gateway contract address"))?;
    let mut storage_processor = local_db.acquire().await?;
    // use finalized block height to judge is processing history events
    let current_finalized = goat_client.get_finalized_block_number().await?;
    let watch_contract = get_watch_contract(
        &mut storage_processor,
        &gateway_contract.to_string(),
        WatchContractType::Gateway,
    )
    .await?;
    Ok(watch_contract.from_height + watch_contract.gap < current_finalized
        || watch_contract.status == WatchContractStatus::Syncing.to_string())
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
