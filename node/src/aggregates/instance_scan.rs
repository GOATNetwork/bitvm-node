//! Collect Instance chain facts outside the apply transaction.
//!
//! Maintenance records answer-window results and Bitcoin snapshots as inbox
//! events. Snapshots include transaction visibility, input spends and tip height
//! for deadline decisions.

use super::common::ScanMarks;
use super::instance::{AnswerWindow, BtcSnapshot, TxFact};
use crate::clock::current_time_secs;
use crate::env::{get_instance_maintenance_batch_size, is_enable_committee_instance_key_delete};
use crate::utils::check_bridge_in_uxto_available_or_self_spent;
use bitcoin::Txid;
use bitvm_lib::actors::Actor;
use client::Utxo;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use engine::EngineHandle;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use store::localdb::{InstanceQuery, LocalDB};
use store::{Instance, InstanceBridgeInStatus};
use tracing::{debug, warn};
use uuid::Uuid;

const TASK_KEY_ANSWER_WINDOW: &str = "instance_answer_window_scan";
const TASK_KEY_BTC: &str = "instance_btc_scan";
const SCAN_MARKS_LIMIT: usize = 50_000;

// ----------------------------------------------------------------- paging

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

/// One page of instances per tick, in creation order, so a large table is
/// walked across ticks instead of blocking one.
pub(crate) async fn find_one_instance_page(
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

// ------------------------------------------------------------ answer window

/// Record the committee answers of every `UserInited` instance whose Goat
/// response window is over. The apply decides quorum.
pub async fn scan_answer_windows(
    local_db: &LocalDB,
    goat_client: &GOATClient,
    engine: &EngineHandle,
) -> anyhow::Result<()> {
    let window_blocks = goat_client.gateway_get_response_window_blocks().await? as i64;
    let goat_height = goat_client.get_latest_block_number().await?;
    let instances = find_one_instance_page(
        local_db,
        TASK_KEY_ANSWER_WINDOW,
        InstanceQuery::default()
            .with_status(InstanceBridgeInStatus::UserInited.to_string())
            .with_pegin_request_height_threshold(goat_height - window_blocks),
        get_instance_maintenance_batch_size(),
    )
    .await?;
    if instances.is_empty() {
        return Ok(());
    }
    let quorum = goat_client.committee_mana_quorum_size().await?;
    for instance in instances {
        let pegin_data = match goat_client.gateway_get_pegin_data(&instance.instance_id).await {
            Ok(pegin_data) => pegin_data,
            Err(error) => {
                warn!(
                    event = "instance_scan",
                    instance_id = %instance.instance_id,
                    error = %error,
                    "failed to read pegin data for the answer window"
                );
                continue;
            }
        };
        let answers: IndexMap<String, Vec<u8>> = pegin_data
            .committee_addresses
            .iter()
            .map(ToString::to_string)
            .zip(pegin_data.committee_pubkeys)
            .collect();
        let window = AnswerWindow { goat_height, window_blocks, quorum, answers };
        engine.submit(window.event(instance.instance_id)?).await?;
    }
    Ok(())
}

// ------------------------------------------------------------------ bitcoin

static SCAN_MARKS: LazyLock<ScanMarks<InstanceBridgeInStatus>> = LazyLock::new(ScanMarks::new);

/// Timeout instances whose Peg-In-Confirm confirmed anyway. The apply reports
/// them once; the row stays `Timeout` for manual handling and there is nothing
/// left to watch, so they leave the scan (until a restart, which reports again).
static SETTLED_TIMEOUTS: LazyLock<Mutex<HashSet<Uuid>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn settled_timeout(instance_id: Uuid) -> bool {
    SETTLED_TIMEOUTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(&instance_id)
}

fn mark_settled_timeout(instance_id: Uuid) {
    let mut settled = SETTLED_TIMEOUTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if settled.len() >= SCAN_MARKS_LIMIT {
        settled.clear();
    }
    settled.insert(instance_id);
}

/// Statuses the Bitcoin scan follows. The key-deletion statuses are only
/// followed on committee nodes with deletion enabled.
fn scanned_statuses(actor: &Actor) -> (Vec<String>, bool) {
    use InstanceBridgeInStatus::*;
    let key_scan = *actor == Actor::Committee && is_enable_committee_instance_key_delete();
    let mut statuses = vec![CommitteesAnswered, UserBroadcastPeginPrepare, Presigned, Timeout];
    if key_scan {
        statuses.extend([RelayerL1Broadcasted, RelayerL2Minted]);
    }
    (statuses.iter().map(ToString::to_string).collect(), key_scan)
}

/// Record a Bitcoin snapshot for every live instance.
pub async fn scan_instances_on_bitcoin(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    engine: &EngineHandle,
    actor: &Actor,
) -> anyhow::Result<()> {
    let (statuses, key_scan) = scanned_statuses(actor);
    let mut query = InstanceQuery::default().with_statuses(statuses);
    if key_scan {
        query = query.with_raw_condition(format!(
            "(status NOT IN ('{}', '{}') OR key_deleted = 0)",
            InstanceBridgeInStatus::RelayerL1Broadcasted,
            InstanceBridgeInStatus::RelayerL2Minted
        ));
    }
    let instances = find_one_instance_page(
        local_db,
        TASK_KEY_BTC,
        query,
        get_instance_maintenance_batch_size(),
    )
    .await?;
    if instances.is_empty() {
        return Ok(());
    }
    let height = i64::from(btc_client.get_height().await?);
    for instance in instances {
        let instance_id = instance.instance_id;
        let Ok(status) = InstanceBridgeInStatus::from_str(&instance.status) else {
            warn!(event = "instance_scan", instance_id = %instance_id, status = %instance.status, "unknown instance status");
            continue;
        };
        if SCAN_MARKS.seen(instance_id, height, status) {
            continue;
        }
        if status == InstanceBridgeInStatus::Timeout && settled_timeout(instance_id) {
            continue;
        }
        match gather_snapshot(btc_client, &instance, status, height).await {
            Ok(Some(snapshot)) => {
                let confirm_confirmed =
                    snapshot.confirm.as_ref().is_some_and(|fact| fact.confirmed);
                engine.submit(snapshot.event(instance_id)?).await?;
                SCAN_MARKS.mark(instance_id, height, status);
                if status == InstanceBridgeInStatus::Timeout && confirm_confirmed {
                    mark_settled_timeout(instance_id);
                }
            }
            Ok(None) => SCAN_MARKS.forget(instance_id),
            Err(error) => warn!(
                event = "instance_scan",
                instance_id = %instance_id,
                status = %status,
                height,
                error = %error,
                "snapshot failed; retried on the next tick"
            ),
        }
    }
    Ok(())
}

/// One call per transaction: existence, confirmation and height together, so
/// an RPC failure is an error and never mistaken for "not in the mempool".
async fn tx_fact(btc_client: &BTCClient, txid: &Txid) -> anyhow::Result<TxFact> {
    Ok(match btc_client.get_tx_info(txid).await? {
        None => TxFact::UNKNOWN,
        Some(tx) => TxFact {
            confirmed: tx.status.confirmed,
            block_height: tx.status.block_height.map(i64::from),
            in_mempool: !tx.status.confirmed,
        },
    })
}

/// Gather the facts the apply needs for `status`. `None` when nothing about
/// this status is decided on Bitcoin.
pub async fn gather_snapshot(
    btc_client: &BTCClient,
    instance: &Instance,
    status: InstanceBridgeInStatus,
    height: i64,
) -> anyhow::Result<Option<BtcSnapshot>> {
    use InstanceBridgeInStatus::*;
    let mut snapshot =
        BtcSnapshot { height, status_at_scan: status.to_string(), ..Default::default() };
    let utxos: Vec<Utxo> = serde_json::from_str(&instance.input_utxos)?;
    let prepare_txid = instance.btc_txid.as_ref().map(|txid| txid.0);
    let confirm_txid = instance.pegin_confirm_txid.as_ref().map(|txid| txid.0);
    let cancel_txid = instance.pegin_cancel_txid.as_ref().map(|txid| txid.0);

    match status {
        // Without the Prepare txid a spend cannot be told from the user's own
        // Prepare: nothing is decided until it is derived.
        CommitteesAnswered => {
            if let Some(prepare_txid) = prepare_txid {
                let prepare = tx_fact(btc_client, &prepare_txid).await?;
                if prepare.confirmed {
                    // The scan may cross to Confirm or Cancel in one pass.
                    if let Some(txid) = confirm_txid {
                        snapshot.confirm = Some(tx_fact(btc_client, &txid).await?);
                    }
                    if let Some(txid) = cancel_txid {
                        snapshot.cancel = Some(tx_fact(btc_client, &txid).await?);
                    }
                } else {
                    snapshot.inputs_available = Some(
                        check_bridge_in_uxto_available_or_self_spent(
                            btc_client,
                            Some(prepare_txid.to_string()),
                            &utxos,
                        )
                        .await?,
                    );
                }
                snapshot.prepare = Some(prepare);
            }
        }
        UserBroadcastPeginPrepare | Presigned => {
            if let Some(txid) = confirm_txid {
                snapshot.confirm = Some(tx_fact(btc_client, &txid).await?);
            }
            if let Some(txid) = cancel_txid {
                snapshot.cancel = Some(tx_fact(btc_client, &txid).await?);
            }
            if status == UserBroadcastPeginPrepare
                && let Some(prepare_txid) = prepare_txid
            {
                let prepare = tx_fact(btc_client, &prepare_txid).await?;
                if !prepare.confirmed {
                    snapshot.inputs_available = Some(
                        check_bridge_in_uxto_available_or_self_spent(
                            btc_client,
                            Some(prepare_txid.to_string()),
                            &utxos,
                        )
                        .await?,
                    );
                }
                snapshot.prepare = Some(prepare);
            }
        }
        Timeout => {
            if let Some(txid) = cancel_txid {
                snapshot.cancel = Some(tx_fact(btc_client, &txid).await?);
            }
            if let Some(txid) = confirm_txid {
                snapshot.confirm = Some(tx_fact(btc_client, &txid).await?);
            }
        }
        RelayerL1Broadcasted | RelayerL2Minted => {
            let Some(txid) = confirm_txid.filter(|_| !instance.key_deleted) else {
                return Ok(None);
            };
            snapshot.confirm = Some(tx_fact(btc_client, &txid).await?);
        }
        // Nothing of the Answer phase is decided on Bitcoin: the Prepare txid is unknown, so a
        // spent input may be the user's own Prepare.
        UserInited | UserCanceled | NoEnoughCommitteesAnswered | UserDiscarded => {
            return Ok(None);
        }
    }
    debug!(
        event = "instance_scan",
        instance_id = %instance.instance_id,
        status = %status,
        height,
        prepare = ?snapshot.prepare,
        confirm = ?snapshot.confirm,
        cancel = ?snapshot.cancel,
        inputs_available = ?snapshot.inputs_available,
        "bitcoin snapshot"
    );
    Ok(Some(snapshot))
}
