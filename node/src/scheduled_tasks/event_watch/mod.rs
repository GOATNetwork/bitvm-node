//! Goat event watching: the history sync and the live monitor over the
//! gateway and swap contracts, with the handlers in `gateway` and
//! `bridge_out`.

mod bridge_out;
mod gateway;

use crate::clock::current_time_secs;
use crate::env::{
    ENV_GOAT_GATEWAY_CONTRACT_ADDRESS, ENV_GOAT_SWAP_CONTRACT_ADDRESS,
    LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS, get_goat_address_from_env,
    get_goat_gateway_event_filter_from_from_env, get_goat_gateway_event_filter_gap_from_env,
    get_goat_gateway_the_graph_urls_from_env, get_goat_swap_event_filter_from_from_env,
    get_goat_swap_event_filter_gap_from_env, get_goat_swap_the_graph_urls_from_env,
};
use crate::metrics_service::{EventWatchState, MetricsState};
use alloy::primitives::Address as EvmAddress;
use bitvm_lib::actors::Actor;
use client::btc_chain::BTCClient;
use client::goat_chain::{GOATClient, GoatInitConfig};
use client::graphs::GraphQueryClient;
use client::graphs::graph_query::{
    GatewayEventEntity, SwapConfig, SwapEventEntity, TheGraphConfig, WatchContractType,
    WatchEventConfig,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use store::localdb::{LocalDB, StorageProcessor};
use store::{WatchContract, WatchContractStatus};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use bridge_out::{apply_bridge_out_events, fetch_bridge_out_events};
use gateway::{apply_gateway_events, fetch_gateway_events};

/// How long a history sync waits when the indexer tip is below its cursor.
const HISTORY_SYNC_TIP_BEHIND_WAIT: Duration = Duration::from_secs(5);

/// Contracts whose history sync task runs in this process.
static HISTORY_SYNC_IN_FLIGHT: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// A contract's history-sync slot; dropping it, also when the task panics,
/// frees the slot.
struct HistorySyncGuard(String);

impl HistorySyncGuard {
    fn try_acquire(contract_addr: &str) -> Option<Self> {
        let mut in_flight =
            HISTORY_SYNC_IN_FLIGHT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        in_flight.insert(contract_addr.to_string()).then(|| Self(contract_addr.to_string()))
    }
}

impl Drop for HistorySyncGuard {
    fn drop(&mut self) {
        HISTORY_SYNC_IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

async fn refresh_event_watch_metrics(
    local_db: &LocalDB,
    goat_client: &GOATClient,
    metrics_state: &MetricsState,
) -> anyhow::Result<()> {
    let finalized_height = goat_client.get_finalized_block_number().await.inspect_err(|error| {
        metrics_state.backend_probe_failed("goat", "get_finalized_block_number", error);
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
    let watch = gateway_watch_contract(local_db).await?;
    let indexed = indexed_height(&GraphQueryClient::new(), &watch).await.inspect_err(|error| {
        metrics_state.backend_probe_failed("graph", "get_sync_block_height", error);
    })?;
    if let Err(error) = check_indexer_lag(indexed, finalized_height, watch.gap) {
        metrics_state.backend_probe_failed("graph", "indexer_lag", &error);
        metrics_state.set_event_watch_state(EventWatchState::Failed);
        return Err(error);
    }
    metrics_state.record_backend_call("graph", true, None);
    let gateway_pending = history_sync_pending(&watch, indexed, current_time_secs())?;
    let other_syncing = snapshot.syncing_count
        > i64::from(watch.status == WatchContractStatus::Syncing.to_string());
    let state = if snapshot.failed_count > 0 {
        EventWatchState::Failed
    } else if gateway_pending || other_syncing {
        EventWatchState::Syncing
    } else {
        EventWatchState::Healthy
    };
    metrics_state.set_event_watch_state(state);
    Ok(())
}

/// The events of one block range, fetched with every network read they need.
pub enum RangeEvents {
    Gateway(gateway::GatewayRange),
    Swap(bridge_out::SwapRange),
}

/// Fetch a block range: the subgraph, Goat and Bitcoin reads, outside any
/// write transaction.
pub async fn fetch_block_range_events(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    client: &GraphQueryClient,
    local_db: &LocalDB,
    watch_events_config: &WatchEventConfig,
    from_height: i64,
    to_height: i64,
) -> anyhow::Result<RangeEvents> {
    Ok(match watch_events_config {
        WatchEventConfig::Gateway(config) => RangeEvents::Gateway(
            fetch_gateway_events(
                btc_client,
                goat_client,
                client,
                local_db,
                &config.the_graph_url,
                &config.event_entities,
                from_height,
                to_height,
            )
            .await?,
        ),
        WatchEventConfig::Swap(config) => RangeEvents::Swap(
            fetch_bridge_out_events(
                goat_client,
                client,
                &config.graph_config.address,
                &config.graph_config.the_graph_url,
                &config.graph_config.event_entities,
                from_height,
                to_height,
            )
            .await?,
        ),
    })
}

/// Write a fetched range; the caller holds the write transaction.
pub async fn apply_block_range_events<'a>(
    actor: &Actor,
    storage_processor: &mut StorageProcessor<'a>,
    watch_events_config: &WatchEventConfig,
    events: RangeEvents,
) -> anyhow::Result<()> {
    match (watch_events_config, events) {
        (_, RangeEvents::Gateway(range)) => {
            apply_gateway_events(actor, storage_processor, range).await
        }
        (WatchEventConfig::Swap(config), RangeEvents::Swap(range)) => {
            apply_bridge_out_events(storage_processor, range, config.peg_btc_address).await
        }
        (WatchEventConfig::Gateway(_), RangeEvents::Swap(_)) => {
            anyhow::bail!("swap events fetched for a gateway watch")
        }
    }
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
                // The indexer tip fell below the cursor (reindex or replica lag):
                // wait for it to catch up instead of spinning on the RPC.
                info!(
                    "Contract {task_name} history sync waits for the indexer: finalized height {current_finalized} is below the watch from height {}",
                    watch_contract.from_height,
                );
                sleep(HISTORY_SYNC_TIP_BEHIND_WAIT).await;
                continue;
            }

            let to_height = current_finalized.min(watch_contract.from_height + watch_contract.gap);
            let events = fetch_block_range_events(
                &btc_client,
                &goat_client,
                query_client,
                local_db,
                &watch_events_config,
                watch_contract.from_height,
                to_height,
            )
            .await?;
            // Only writes from here: IMMEDIATE takes the write lock up front
            // instead of failing with BUSY_SNAPSHOT after reading.
            let mut tx = local_db.start_immediate_transaction().await?;
            apply_block_range_events(&actor, &mut tx, &watch_events_config, events).await?;
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
    let current_finalized =
        indexed_height(&query_client, &watch_contract).await.inspect_err(|error| {
            crate::metrics_service::record_backend_failure("graph", "get_sync_block_height", error);
        })?;

    if watch_contract.from_height == 0 || watch_contract.from_height >= current_finalized {
        // A misconfigured (zero) or not yet reachable start height: say it once at
        // WARN, then at debug on every later tick.
        static WATCH_RANGE_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let message = format!(
            "watch_contract {} start height {} is zero or not below the current height {}, not do watch jobs",
            watch_contract.contract_addr, watch_contract.from_height, current_finalized
        );
        if WATCH_RANGE_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!("{message}");
        } else {
            warn!("{message}");
        }
        return Ok(());
    }
    if watch_contract.status == WatchContractStatus::Syncing.to_string()
        && watch_contract.updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS > current_time_secs()
    {
        info!("Event sync not finished ");
        return Ok(());
    }
    if watch_contract.from_height + watch_contract.gap < current_finalized {
        // One history sync per contract. The gate above sees `Syncing` only
        // after the task commits its first batch, so claim the contract here,
        // in this process and in its row, before the task starts.
        let Some(sync_guard) = HistorySyncGuard::try_acquire(&watch_contract.contract_addr) else {
            info!("Event sync not finished ");
            return Ok(());
        };
        watch_contract.status = WatchContractStatus::Syncing.to_string();
        watch_contract.updated_at = current_time_secs();
        storage_processor.upsert_watch_contract(&watch_contract).await?;
        let watch_contract_clone = watch_contract.clone();
        let local_db_clone = local_db.clone();
        let query_client_clone = query_client.clone();
        let watch_events_config_clone = watch_events_config.clone();
        tokio::spawn(async move {
            let _sync_guard = sync_guard;
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
    drop(storage_processor);
    let events = fetch_block_range_events(
        &btc_client,
        &goat_client,
        &query_client,
        local_db,
        &watch_events_config,
        watch_contract.from_height,
        to_height,
    )
    .await?;
    // Only writes from here: IMMEDIATE takes the write lock up front instead
    // of failing with BUSY_SNAPSHOT after reading.
    let mut tx = local_db.start_immediate_transaction().await?;
    apply_block_range_events(&actor, &mut tx, &watch_events_config, events).await?;
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
                                let refresh = tokio::time::timeout(
                                    Duration::from_secs(30),
                                    refresh_event_watch_metrics(
                                        &local_db,
                                        goat_client.as_ref(),
                                        &metrics_state,
                                    ),
                                )
                                .await;
                                let result = match refresh {
                                    Ok(result) => result,
                                    Err(error) => Err(anyhow::anyhow!("event watch health refresh timed out: {error}")),
                                };
                                if let Err(error) = result {
                                    metrics_state.set_event_watch_state(EventWatchState::Failed);
                                    if metrics_state.backend_unavailable("goat") {
                                        tracing::debug!(event = "metrics_event_watch", error = %error, "failed to refresh event watcher metrics (Goat unavailable)");
                                    } else {
                                        warn!(event = "metrics_event_watch", error = %error, "failed to refresh event watcher metrics");
                                    }
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
                            metrics_state.set_event_watch_state(EventWatchState::Failed);
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

async fn gateway_watch_contract(local_db: &LocalDB) -> anyhow::Result<WatchContract> {
    let gateway = get_goat_address_from_env(ENV_GOAT_GATEWAY_CONTRACT_ADDRESS)
        .ok_or_else(|| anyhow::anyhow!("need to set gateway contract address"))?;
    let mut storage = local_db.acquire().await?;
    get_watch_contract(&mut storage, &gateway.to_string(), WatchContractType::Gateway).await
}

async fn indexed_height(client: &GraphQueryClient, watch: &WatchContract) -> anyhow::Result<i64> {
    let height = client
        .get_sync_block_height(&watch.the_graph_url)
        .await?
        .ok_or_else(|| anyhow::anyhow!("subgraph metadata has no indexed block height"))?;
    anyhow::ensure!(height >= 0, "subgraph indexed height is negative");
    Ok(height)
}

fn history_sync_pending(watch: &WatchContract, indexed: i64, now: i64) -> anyhow::Result<bool> {
    anyhow::ensure!(
        watch.gap > 0 && watch.from_height >= 0 && indexed >= 0,
        "invalid event watcher cursor, gap or indexed height"
    );
    let behind = watch.from_height < indexed;
    let live_sync = watch.status == WatchContractStatus::Syncing.to_string()
        && watch.updated_at.saturating_add(LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS) > now;
    Ok(watch.from_height.saturating_add(watch.gap) < indexed || (behind && live_sync))
}

fn check_indexer_lag(indexed: i64, finalized: i64, allowed_lag: i64) -> anyhow::Result<()> {
    anyhow::ensure!(
        indexed >= 0 && finalized >= 0 && allowed_lag > 0,
        "invalid indexer height or lag budget"
    );
    let lag = finalized.saturating_sub(indexed);
    anyhow::ensure!(
        lag <= allowed_lag,
        "subgraph indexing is behind GOAT finalized height: indexed={indexed}, finalized={finalized}, lag={lag}, allowed={allowed_lag}"
    );
    Ok(())
}

/// Compare the cursor with what the indexer can actually serve, independently of GOAT RPC.
pub async fn is_processing_gateway_history_events(local_db: &LocalDB) -> anyhow::Result<bool> {
    let watch = gateway_watch_contract(local_db).await?;
    let indexed = indexed_height(&GraphQueryClient::new(), &watch).await?;
    history_sync_pending(&watch, indexed, current_time_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_sync_tracks_indexed_backlog_and_expires_stale_status() {
        let mut watch = WatchContract {
            from_height: 100,
            gap: 10,
            updated_at: 1000,
            status: WatchContractStatus::Synced.to_string(),
            ..Default::default()
        };
        assert!(!history_sync_pending(&watch, 100, 1001).unwrap());
        assert!(!history_sync_pending(&watch, 110, 1001).unwrap());
        assert!(history_sync_pending(&watch, 111, 1001).unwrap());
        watch.status = WatchContractStatus::Syncing.to_string();
        assert!(history_sync_pending(&watch, 105, 1001).unwrap());
        assert!(!history_sync_pending(&watch, 100, 1001).unwrap());
        let expired = 1000 + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS;
        assert!(!history_sync_pending(&watch, 105, expired).unwrap());
        assert!(history_sync_pending(&watch, 111, expired).unwrap());
        watch.gap = 0;
        assert!(history_sync_pending(&watch, 105, expired).is_err());
    }

    #[test]
    fn indexer_lag_is_a_backend_fault_separate_from_history_backlog() {
        assert!(check_indexer_lag(100, 110, 10).is_ok());
        assert!(check_indexer_lag(110, 100, 10).is_ok());
        assert!(check_indexer_lag(100, 111, 10).is_err());
        assert!(check_indexer_lag(-1, 100, 10).is_err());
    }

    #[tokio::test]
    async fn unavailable_or_unhealthy_metadata_is_not_treated_as_history_sync() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (metadata, expected) in [
            (serde_json::json!({"block":{"number":123},"hasIndexingErrors":false}), Some(123)),
            (serde_json::Value::Null, None),
            (serde_json::json!({"block":{"number":123},"hasIndexingErrors":true}), None),
            (serde_json::json!({"block":{"number":-1}}), None),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 8192];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                let body = serde_json::json!({"data":{"_meta":metadata}}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let watch = WatchContract { the_graph_url: url, ..Default::default() };
            let result = indexed_height(&GraphQueryClient::new(), &watch).await;
            assert_eq!(result.ok(), expected);
            server.await.unwrap();
        }
    }

    #[test]
    fn history_sync_guard_is_exclusive_per_contract() {
        let first = HistorySyncGuard::try_acquire("0xabc").expect("free slot");
        assert!(HistorySyncGuard::try_acquire("0xabc").is_none());
        let other = HistorySyncGuard::try_acquire("0xdef").expect("another contract is free");
        drop(first);
        assert!(HistorySyncGuard::try_acquire("0xabc").is_some());
        drop(other);
    }
}

#[cfg(test)]
mod pagination_tests;
