//! Collect Instance chain facts outside the apply transaction.
//!
//! Maintenance records answer-window results and Bitcoin snapshots as inbox
//! events. Snapshots include transaction visibility, input spends and tip height
//! for deadline decisions.

use super::common::ScanMarks;
use super::instance::{AnswerWindow, BtcSnapshot, PeginRequested, TxFact, pegin_request_event};
use crate::clock::current_time_secs;
use crate::engine_bridge::record_event_in;
use crate::env::{get_instance_maintenance_batch_size, is_enable_committee_instance_key_delete};
use crate::error::{FailureClass, SpecialError, classify_failure, panic_message};
use crate::utils::{
    check_bridge_in_uxto_available_or_self_spent, generate_instance_from_bridge_in_request_event,
};
use bitcoin::Txid;
use bitvm_lib::actors::Actor;
use client::Utxo;
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use client::graphs::graph_query::BridgeInRequestEvent;
use engine::EngineHandle;
use futures::FutureExt;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use store::localdb::{InstanceQuery, LocalDB};
use store::{GoatTxProcessingStatus, GoatTxRecord, GoatTxType, Instance, InstanceBridgeInStatus};
use tracing::{debug, error, info, warn};
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
    let mut failures = 0;
    for tx_record in tx_records {
        let operation = process_pegin_request_record(
            local_db,
            btc_client,
            goat_client,
            engine,
            &tx_record,
            current_height,
            response_window_blocks,
        );
        if let Err(error) = isolate_pegin_request(local_db, &tx_record, operation).await {
            failures += 1;
            warn!(event = "pegin_request", instance_id = %tx_record.instance_id,
                error = %error, "BridgeInRequest processing failed; continuing with the next record");
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} BridgeInRequest records failed during this tick");
    }
    Ok(())
}

/// Keep a poisoned request from unwinding the monitor or blocking later records.
async fn isolate_pegin_request(
    local_db: &LocalDB,
    record: &GoatTxRecord,
    operation: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let status = match AssertUnwindSafe(operation).catch_unwind().await {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(error)) => {
            if !matches!(classify_failure(&error), FailureClass::Permanent(_)) {
                return Err(error);
            }
            warn!(event = "pegin_request", instance_id = %record.instance_id, error = %error,
                "invalid BridgeInRequest skipped");
            GoatTxProcessingStatus::Skipped
        }
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            error!(event = "pegin_request_panic", instance_id = %record.instance_id,
                error = message, "BridgeInRequest panicked; marking failed");
            local_db
                .acquire()
                .await?
                .update_goat_tx_record_processing_status(
                    &record.graph_id,
                    &record.instance_id,
                    &record.tx_type,
                    &GoatTxProcessingStatus::Failed.to_string(),
                )
                .await?;
            anyhow::bail!("BridgeInRequest panicked: {message}");
        }
    };
    local_db
        .acquire()
        .await?
        .update_goat_tx_record_processing_status(
            &record.graph_id,
            &record.instance_id,
            &record.tx_type,
            &status.to_string(),
        )
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_pegin_request_record(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    engine: &EngineHandle,
    tx_record: &GoatTxRecord,
    current_height: i64,
    response_window_blocks: i64,
) -> anyhow::Result<()> {
    let instance_id = tx_record.instance_id;
    let event_json = tx_record.extra.as_deref().ok_or_else(|| {
        SpecialError::InvalidPeginRequest("BridgeInRequest record carries no event".into())
    })?;
    let event = serde_json::from_str::<BridgeInRequestEvent>(event_json).map_err(|error| {
        SpecialError::InvalidPeginRequest(format!("malformed BridgeInRequest event: {error}"))
    })?;
    let is_outside_response_window = tx_record.height + response_window_blocks < current_height;
    // Build before starting a transaction so backend errors cannot leave partial rows.
    let instance =
        match generate_instance_from_bridge_in_request_event(btc_client, goat_client, &event).await
        {
            Ok(instance) => instance,
            Err(error) if classify_failure(&error) == FailureClass::Transient => return Err(error),
            Err(error) => {
                // Preserve the existing rejection of malformed data and contract refusals.
                warn!(event = "pegin_request", instance_id = %instance_id, error = %error,
                "could not build the instance of a BridgeInRequest; request skipped");
                local_db
                    .acquire()
                    .await?
                    .update_goat_tx_record_processing_status(
                        &tx_record.graph_id,
                        &instance_id,
                        &tx_record.tx_type,
                        &GoatTxProcessingStatus::Skipped.to_string(),
                    )
                    .await?;
                return Ok(());
            }
        };
    let mut tx = local_db.start_transaction().await?;
    if is_outside_response_window {
        if tx.insert_instance_if_absent(&instance).await? {
            info!(event = "pegin_request", instance_id = %instance_id, outcome = "late",
                "BridgeInRequest seen after its response window; the answer-window scan decides");
        }
    } else {
        // A re-indexed request refreshes its row; a row that moved on is left alone.
        tx.upsert_pegin_request_instance(&instance).await?;
        record_event_in(
            &mut tx,
            pegin_request_event(
                instance_id,
                &PeginRequested { tx_hash: tx_record.tx_hash.clone() },
            )?,
        )
        .await?;
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Address, hashes::Hash, key::Keypair, secp256k1::SECP256K1};
    use client::goat_chain::{PeginData, PeginStatus};

    async fn database() -> (LocalDB, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("requests.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        (db, dir)
    }

    fn pending_record(id: u128) -> GoatTxRecord {
        GoatTxRecord {
            instance_id: Uuid::from_u128(id),
            graph_id: Uuid::nil(),
            tx_type: GoatTxType::BridgeInRequest.to_string(),
            processing_status: GoatTxProcessingStatus::Pending.to_string(),
            height: id as i64,
            ..Default::default()
        }
    }

    async fn status(db: &LocalDB, record: &GoatTxRecord) -> String {
        db.acquire()
            .await
            .unwrap()
            .find_graph_goat_tx_record(&record.instance_id, &record.graph_id, &record.tx_type)
            .await
            .unwrap()
            .unwrap()
            .processing_status
    }

    #[tokio::test]
    async fn malformed_requests_do_not_block_valid_requests_and_backend_errors_retry() {
        let (db, _dir) = database().await;
        let (btc, btc_mock) = BTCClient::new_mock_client();
        let (goat, goat_mock) = GOATClient::new_mock_client();
        let (engine, _acks) =
            engine::EngineBuilder::new(db.clone(), engine::EngineConfig::default()).build();
        let key = Keypair::from_seckey_slice(SECP256K1, &[7; 32]).unwrap().x_only_public_key().0;
        let address = Address::p2tr(SECP256K1, key, None, crate::env::get_network());
        let txid = Txid::from_byte_array([3; 32]);
        btc_mock.set_tx(
            txid,
            esplora_client::Tx {
                txid,
                version: 2,
                locktime: 0,
                vin: vec![],
                vout: vec![esplora_client::Vout {
                    value: 50_000,
                    scriptpubkey: address.script_pubkey(),
                }],
                size: 1,
                weight: 1,
                fee: 0,
                status: esplora_client::TxStatus {
                    confirmed: true,
                    block_height: Some(1),
                    block_hash: None,
                    block_time: None,
                },
            },
        );
        let mut records = Vec::new();
        let mut retry_data = None;
        for id in 1..=4 {
            let mut record = pending_record(id);
            let event = BridgeInRequestEvent {
                id: id.to_string(),
                transaction_hash: format!("request-{id}"),
                block_number: id.to_string(),
                block_timestamp: "1".into(),
                instance_id: record.instance_id.to_string(),
                depositor_address: format!("0x{}", "11".repeat(20)),
                pegin_amount_sats: "10000".into(),
                txn_fees: ["100".into(), "100".into(), "100".into()],
                user_xonly_pubkey: key.to_string(),
                user_change_address: address.to_string(),
                user_refund_address: address.to_string(),
            };
            let data = PeginData {
                status: PeginStatus::Pending,
                instance_id: *record.instance_id.as_bytes(),
                depositor_address: [0x11; 20],
                pegin_amount_sats: 10_000,
                txn_fees: [100; 3],
                user_inputs: vec![client::goat_chain::Utxo {
                    txid: txid.to_byte_array(),
                    vout: if id == 1 { u32::MAX } else { 0 },
                    amount_sats: 50_000,
                }],
                user_xonly_pubkey: key.serialize(),
                user_change_addr: address.to_string(),
                user_refund_addr: address.to_string(),
                pegin_txid: [0; 32],
                created_at: 1,
                committee_addresses: vec![],
                committee_pubkeys: vec![],
            };
            goat_mock.set_pegin_data(*record.instance_id.as_bytes(), Ok(data.clone()));
            if id == 1 {
                let error = generate_instance_from_bridge_in_request_event(&btc, &goat, &event)
                    .await
                    .unwrap_err();
                assert!(matches!(classify_failure(&error), FailureClass::Permanent(_)));
                assert!(error.to_string().contains("output count"));
            }
            if id == 3 {
                retry_data = Some(data);
                goat_mock.set_pegin_data(
                    *record.instance_id.as_bytes(),
                    Err("503 service unavailable".into()),
                );
            }
            record.extra =
                Some(if id == 2 { "{".into() } else { serde_json::to_string(&event).unwrap() });
            db.acquire().await.unwrap().upsert_goat_tx_record(&record).await.unwrap();
            records.push(record);
        }
        assert!(pegin_request_monitor(&db, &btc, &goat, &engine.handle()).await.is_err());
        for (record, expected) in records.iter().zip(["Skipped", "Skipped", "Pending", "Processed"])
        {
            assert_eq!(status(&db, record).await, expected);
        }
        assert!(
            db.acquire()
                .await
                .unwrap()
                .find_instance(&records[0].instance_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.acquire()
                .await
                .unwrap()
                .find_instance(&records[3].instance_id)
                .await
                .unwrap()
                .is_some()
        );
        goat_mock.set_pegin_data(*records[2].instance_id.as_bytes(), Ok(retry_data.unwrap()));
        pegin_request_monitor(&db, &btc, &goat, &engine.handle()).await.unwrap();
        assert_eq!(status(&db, &records[2]).await, "Processed");
    }

    #[tokio::test]
    async fn request_panic_rolls_back_its_transaction_and_does_not_block_the_next_record() {
        let (db, _dir) = database().await;
        let poisoned = pending_record(1);
        let next = pending_record(2);
        for record in [&poisoned, &next] {
            db.acquire().await.unwrap().upsert_goat_tx_record(record).await.unwrap();
        }
        let operation = async {
            let mut tx = db.start_transaction().await?;
            tx.update_goat_tx_record_processing_status(
                &poisoned.graph_id,
                &poisoned.instance_id,
                &poisoned.tx_type,
                "Processed",
            )
            .await?;
            tx.update_goat_tx_record_processing_status(
                &next.graph_id,
                &next.instance_id,
                &next.tx_type,
                "Processed",
            )
            .await?;
            tokio::task::yield_now().await;
            panic!("unexpected request failure");
        };
        assert!(isolate_pegin_request(&db, &poisoned, operation).await.is_err());
        assert_eq!(status(&db, &poisoned).await, "Failed");
        assert_eq!(status(&db, &next).await, "Pending");
        isolate_pegin_request(&db, &next, async {
            db.acquire()
                .await?
                .update_goat_tx_record_processing_status(
                    &next.graph_id,
                    &next.instance_id,
                    &next.tx_type,
                    "Processed",
                )
                .await
        })
        .await
        .unwrap();
        assert_eq!(status(&db, &next).await, "Processed");
    }
}
