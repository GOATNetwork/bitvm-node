use crate::utils::{QueryBuilder, QueryParam, create_place_holders};
use crate::{
    BridgeOutGlobalStats, EventWatchMetricsSnapshot, GoatTxRecord, Graph, GraphBtcTxVoutMonitor,
    GraphRawData, GraphStatus, GraphStatusSource, GraphStatusTransitionOutcome, Instance,
    MetricsStateCount, Node, NodeAlertMetricsSnapshot, NodesOverview, PeginGraphProcessData,
    PeginInstanceProcessData, PendingGraphInit, SequencerSetHashChange, SequencerSetScanState,
    SerializableTxid, SwapEscrow, SwapEscrowStatus, WatchContract,
};

use indexmap::IndexMap;
use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::types::Uuid;
use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn get_current_timestamp_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Clone, Debug)]
pub struct LocalDB {
    pub path: String,
    pub is_mem: bool,
    pub conn: SqlitePool,
}

#[derive(Debug)]
pub enum ConnectionHolder<'a> {
    Pooled(PoolConnection<Sqlite>),
    Direct(SqliteConnection),
    Transaction(Transaction<'a, Sqlite>),
}

#[derive(Debug)]
pub struct StorageProcessor<'a> {
    pub conn: ConnectionHolder<'a>,
    pub in_transaction: bool,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
/// sqlx's own default, made explicit: how long a statement waits for SQLite's
/// write lock before failing with "database is locked".
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

impl LocalDB {
    pub async fn new(path: &str, is_mem: bool) -> LocalDB {
        Self::new_with_busy_timeout(path, is_mem, DEFAULT_BUSY_TIMEOUT).await
    }

    /// `busy_timeout` must cover the longest write transaction the process
    /// holds (the engine's apply), or every other writer fails while it runs.
    pub async fn new_with_busy_timeout(
        path: &str,
        is_mem: bool,
        busy_timeout: Duration,
    ) -> LocalDB {
        if !Sqlite::database_exists(path).await.unwrap_or(false) {
            tracing::info!("Creating database {}", path);
            match Sqlite::create_database(path).await {
                Ok(_) => tracing::info!(
                    event = "database_lifecycle",
                    outcome = "created",
                    "local database created"
                ),
                Err(error) => panic!("error: {error}"),
            }
        } else {
            tracing::info!("Database already exists");
        }

        let mut options = SqliteConnectOptions::from_str(path)
            .unwrap()
            .create_if_missing(true)
            .busy_timeout(busy_timeout);
        if !is_mem {
            // File-backed nodes run event watchers, P2P handlers, and maintenance tasks
            // concurrently. WAL allows their readers to proceed while a short write commits.
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        let conn = SqlitePool::connect_with(options).await.unwrap();
        Self { path: path.to_string(), is_mem, conn }
    }

    pub async fn migrate(&self) {
        match MIGRATOR.run(&self.conn).await {
            Ok(_) => tracing::info!("Migration success"),
            Err(error) => {
                panic!("error: {error:?}");
            }
        }
    }

    pub async fn acquire<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Pooled(self.conn.acquire().await?),
            in_transaction: false,
        })
    }
    pub async fn start_transaction<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Transaction(self.conn.begin().await?),
            in_transaction: true,
        })
    }

    /// Start a short write transaction before reading state that will be
    /// immediately reconciled. This prevents a stale snapshot from dropping
    /// a concurrent update between the read and the conditional write.
    pub async fn start_immediate_transaction<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Transaction(self.conn.begin_with("BEGIN IMMEDIATE").await?),
            in_transaction: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct InstanceQuery {
    pub from_addr: Option<String>,
    pub statuses: Vec<String>,
    pub earliest_updated: Option<i64>,
    pub pegin_request_height_threshold: Option<i64>,
    pub order: Option<String>,
    pub raw_conditions: Vec<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl InstanceQuery {
    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.statuses.push(status);
        self
    }

    pub fn with_statuses(mut self, statuses: Vec<String>) -> Self {
        self.statuses = statuses;
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_pegin_request_height_threshold(mut self, threshold: i64) -> Self {
        self.pegin_request_height_threshold = Some(threshold);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_raw_condition(mut self, raw_condition: String) -> Self {
        self.raw_conditions.push(raw_condition);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);
        if let Some(from_addr) = &self.from_addr {
            query_builder.and_where("from_addr = ?", Some(QueryParam::Text(from_addr.clone())));
        }

        if !self.statuses.is_empty() {
            query_builder.and_where_in("status", &self.statuses, false);
        }
        if let Some(earliest_updated) = self.earliest_updated {
            query_builder.and_where("updated_at >= ?", Some(QueryParam::Int(earliest_updated)));
        }
        if let Some(pegin_request_height_threshold) = self.pegin_request_height_threshold {
            query_builder.and_where(
                "goat_tx_height < ?",
                Some(QueryParam::Int(pegin_request_height_threshold)),
            );
        }
        for raw_condition in &self.raw_conditions {
            query_builder.add_raw_condition(raw_condition);
        }

        if let Some(order) = &self.order {
            query_builder.apply_order(order);
        }
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

/// Instance field update parameters
///
/// Provides a more elegant way to specify which instance fields to update
#[derive(Debug, Clone)]
pub struct InstanceUpdate {
    pub instance_id: Uuid,
    pub from_addr: Option<String>,
    pub to_addr: Option<String>,
    pub btc_txid: Option<SerializableTxid>,
    pub status: Option<String>,
    pub pegin_confirm_txid: Option<SerializableTxid>,
    pub pegin_cancel_txid: Option<SerializableTxid>,
    pub post_pegin_txhash: Option<String>,
    pub btc_height: Option<i64>,
    pub committees_answers: Option<IndexMap<String, Vec<u8>>>,
    pub key_deleted: Option<bool>,
    pub only_if_status_in: Option<Vec<String>>,
}

impl InstanceUpdate {
    /// Create new update parameters
    pub fn new_with_instance_id(instance_id: Uuid) -> Self {
        Self {
            instance_id,
            from_addr: None,
            to_addr: None,
            btc_txid: None,
            status: None,
            pegin_confirm_txid: None,
            pegin_cancel_txid: None,
            post_pegin_txhash: None,
            btc_height: None,
            committees_answers: None,
            key_deleted: None,
            only_if_status_in: None,
        }
    }

    /// Set from_addr
    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    /// Set btc txid
    pub fn with_btc_txid(mut self, btc_txid: SerializableTxid) -> Self {
        self.btc_txid = Some(btc_txid);
        self
    }
    /// Set status
    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    /// Set pegin confirmation transaction ID.
    pub fn with_pegin_confirm_txid(mut self, txid: SerializableTxid) -> Self {
        self.pegin_confirm_txid = Some(txid);
        self
    }

    /// Set pegin cancellation transaction ID.
    pub fn with_pegin_cancel_txid(mut self, txid: SerializableTxid) -> Self {
        self.pegin_cancel_txid = Some(txid);
        self
    }

    /// Set post pegin information
    pub fn with_post_pegin(mut self, txid: String) -> Self {
        self.post_pegin_txhash = Some(txid);
        self
    }

    /// Set committees answers
    pub fn with_committees_answers(
        mut self,
        committees_answers: IndexMap<String, Vec<u8>>,
    ) -> Self {
        self.committees_answers = Some(committees_answers);
        self
    }

    /// Set btc height
    pub fn with_btc_height(mut self, btc_height: i64) -> Self {
        self.btc_height = Some(btc_height);
        self
    }

    /// Record whether the committee instance key envelope has been deleted.
    pub fn with_key_deleted(mut self, key_deleted: bool) -> Self {
        self.key_deleted = Some(key_deleted);
        self
    }

    /// Apply this update only while the instance is still in one of the
    /// expected states. The condition is folded into the UPDATE statement.
    pub fn with_only_if_status_in(mut self, statuses: Vec<String>) -> Self {
        self.only_if_status_in = Some(statuses);
        self
    }

    /// Check if any fields need to be updated
    pub fn has_updates(&self) -> bool {
        self.from_addr.is_some()
            || self.to_addr.is_some()
            || self.btc_txid.is_some()
            || self.status.is_some()
            || self.pegin_confirm_txid.is_some()
            || self.pegin_cancel_txid.is_some()
            || self.post_pegin_txhash.is_some()
            || self.btc_height.is_some()
            || self.committees_answers.is_some()
            || self.key_deleted.is_some()
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::update(base_sql);
        // Set field
        if let Some(ref status) = self.status {
            query_builder.set_field("status", QueryParam::Text(status.clone()));
            query_builder
                .set_field("status_updated_at", QueryParam::Int(get_current_timestamp_secs()));
        }

        if let Some(ref txid) = self.pegin_confirm_txid {
            query_builder.set_field("pegin_confirm_txid", QueryParam::BTCTxid(txid.clone()));
        }

        if let Some(ref txid) = self.pegin_cancel_txid {
            query_builder.set_field("pegin_cancel_txid", QueryParam::BTCTxid(txid.clone()));
        }

        if let Some(ref txid) = self.post_pegin_txhash {
            query_builder.set_field("post_pegin_txhash", QueryParam::Text(txid.clone()));
        }

        if let Some(pegin_prepare_height) = self.btc_height {
            query_builder.set_field("btc_height", QueryParam::Int(pegin_prepare_height));
        }

        if let Some(ref to_addr) = self.to_addr {
            query_builder.set_field("to_addr", QueryParam::Text(to_addr.clone()));
        }

        if let Some(ref from_addr) = self.from_addr {
            query_builder.set_field("from_addr", QueryParam::Text(from_addr.clone()));
        }

        if let Some(ref btc_txid) = self.btc_txid {
            query_builder.set_field("btc_txid", QueryParam::BTCTxid(btc_txid.clone()));
        }

        if let Some(ref committees_answers) = self.committees_answers {
            let committees_answers = serde_json::to_string(committees_answers)
                .expect("IndexMap<String, Vec<u8>> serialization is infallible");
            query_builder.set_field("committees_answers", QueryParam::Text(committees_answers));
        }

        if let Some(key_deleted) = self.key_deleted {
            query_builder.set_field("key_deleted", QueryParam::Int(i64::from(key_deleted)));
        }

        // Add update time
        let current_time = get_current_timestamp_secs();
        query_builder.set_field("updated_at", QueryParam::Int(current_time));

        // Add WHERE clause
        query_builder.and_where(
            "hex(instance_id) = ? COLLATE NOCASE ",
            Some(QueryParam::Text(hex::encode(self.instance_id))),
        );

        if let Some(ref statuses) = self.only_if_status_in {
            if statuses.is_empty() {
                // An empty allow-list must reject the update rather than
                // silently dropping the compare-and-swap guard.
                query_builder.and_where("1 = 0", None);
            } else {
                query_builder.and_where_in("status", statuses, false);
            }
        }

        query_builder
    }
}

/// Filter parameters for listing swap escrows.
#[derive(Clone, Debug, Default)]
pub struct SwapEscrowQuery {
    pub offerer_addr: Option<String>,
    pub statuses: Vec<String>,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl SwapEscrowQuery {
    pub fn with_offerer_addr(mut self, offerer_addr: String) -> Self {
        self.offerer_addr = Some(offerer_addr);
        self
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.statuses.push(status);
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);
        if let Some(offerer_addr) = &self.offerer_addr {
            query_builder
                .and_where("offerer_addr = ?", Some(QueryParam::Text(offerer_addr.clone())));
        }
        if !self.statuses.is_empty() {
            query_builder.and_where_in("status", &self.statuses, false);
        }
        if let Some(order) = &self.order {
            query_builder.apply_order(order);
        }
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

/// Swap escrow field update parameters, keyed by escrow hash.
#[derive(Debug, Clone, Default)]
pub struct SwapEscrowUpdate {
    pub escrow_hash: String,
    pub status: Option<String>,
    pub claimer_addr: Option<String>,
    pub btc_addr: Option<String>,
    pub token: Option<String>,
    pub amount: Option<String>,
    pub refund_deadline: Option<i64>,
    pub escrow_data: Option<String>,
    pub init_tx_hash: Option<String>,
    pub init_tx_height: Option<i64>,
    pub claim_tx_hash: Option<String>,
    pub claim_btc_txid: Option<SerializableTxid>,
    pub refund_tx_hash: Option<String>,
    pub only_if_status_in: Option<Vec<String>>,
}

impl SwapEscrowUpdate {
    pub fn new(escrow_hash: String) -> Self {
        Self { escrow_hash, ..Self::default() }
    }

    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_btc_addr(mut self, btc_addr: String) -> Self {
        self.btc_addr = Some(btc_addr);
        self
    }

    pub fn with_claim_tx_hash(mut self, tx_hash: String) -> Self {
        self.claim_tx_hash = Some(tx_hash);
        self
    }

    pub fn with_claim_btc_txid(mut self, txid: SerializableTxid) -> Self {
        self.claim_btc_txid = Some(txid);
        self
    }

    pub fn with_refund_tx_hash(mut self, tx_hash: String) -> Self {
        self.refund_tx_hash = Some(tx_hash);
        self
    }

    /// Apply this update only while the escrow is still in one of the
    /// expected states. The condition is folded into the UPDATE statement.
    pub fn with_only_if_status_in(mut self, statuses: Vec<String>) -> Self {
        self.only_if_status_in = Some(statuses);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::update(base_sql);
        if let Some(ref status) = self.status {
            query_builder.set_field("status", QueryParam::Text(status.clone()));
            query_builder
                .set_field("status_updated_at", QueryParam::Int(get_current_timestamp_secs()));
        }
        if let Some(ref claimer_addr) = self.claimer_addr {
            query_builder.set_field("claimer_addr", QueryParam::Text(claimer_addr.clone()));
        }
        if let Some(ref btc_addr) = self.btc_addr {
            query_builder.set_field("btc_addr", QueryParam::Text(btc_addr.clone()));
        }
        if let Some(ref token) = self.token {
            query_builder.set_field("token", QueryParam::Text(token.clone()));
        }
        if let Some(ref amount) = self.amount {
            query_builder.set_field("amount", QueryParam::Text(amount.clone()));
        }
        if let Some(refund_deadline) = self.refund_deadline {
            query_builder.set_field("refund_deadline", QueryParam::Int(refund_deadline));
        }
        if let Some(ref escrow_data) = self.escrow_data {
            query_builder.set_field("escrow_data", QueryParam::Text(escrow_data.clone()));
        }
        if let Some(ref init_tx_hash) = self.init_tx_hash {
            query_builder.set_field("init_tx_hash", QueryParam::Text(init_tx_hash.clone()));
        }
        if let Some(init_tx_height) = self.init_tx_height {
            query_builder.set_field("init_tx_height", QueryParam::Int(init_tx_height));
        }
        if let Some(ref claim_tx_hash) = self.claim_tx_hash {
            query_builder.set_field("claim_tx_hash", QueryParam::Text(claim_tx_hash.clone()));
        }
        if let Some(ref claim_btc_txid) = self.claim_btc_txid {
            query_builder.set_field("claim_btc_txid", QueryParam::BTCTxid(claim_btc_txid.clone()));
        }
        if let Some(ref refund_tx_hash) = self.refund_tx_hash {
            query_builder.set_field("refund_tx_hash", QueryParam::Text(refund_tx_hash.clone()));
        }

        query_builder.set_field("updated_at", QueryParam::Int(get_current_timestamp_secs()));

        query_builder
            .and_where("escrow_hash = ?", Some(QueryParam::Text(self.escrow_hash.clone())));
        if let Some(ref statuses) = self.only_if_status_in {
            if statuses.is_empty() {
                // An empty allow-list must reject the update rather than
                // silently dropping the compare-and-swap guard.
                query_builder.and_where("1 = 0", None);
            } else {
                query_builder.and_where_in("status", statuses, false);
            }
        }
        query_builder
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphQuery {
    pub statuses: Vec<String>,
    pub operator_pubkey: Option<String>,
    pub kickoff_index: Option<i64>,
    pub from_addr: Option<String>,
    pub graph_id: Option<String>,
    pub pegin_txid: Option<SerializableTxid>,
    pub raw_conditions: Vec<String>,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl GraphQuery {
    pub fn with_status(mut self, status: String) -> Self {
        self.statuses.push(status);
        self
    }

    pub fn with_statuses(mut self, statuses: Vec<String>) -> Self {
        self.statuses = statuses;
        self
    }
    pub fn with_raw_condition(mut self, raw_condition: String) -> Self {
        self.raw_conditions.push(raw_condition);
        self
    }

    pub fn with_operator_pubkey(mut self, operator_pubkey: String) -> Self {
        self.operator_pubkey = Some(operator_pubkey);
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    pub fn with_kickoff_index(mut self, kickoff_index: i64) -> Self {
        self.kickoff_index = Some(kickoff_index);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);
        // Add WHERE conditions
        if !self.statuses.is_empty() {
            query_builder.and_where_in("status", &self.statuses, false);
        }

        if let Some(from_addr) = &self.from_addr {
            query_builder.and_where("from_addr = ?", Some(QueryParam::Text(from_addr.clone())));
        }

        if let Some(operator) = &self.operator_pubkey {
            query_builder
                .and_where("operator_pubkey = ?", Some(QueryParam::Text(operator.clone())));
        }

        if let Some(kickoff_index) = self.kickoff_index {
            query_builder.and_where("kickoff_index = ?", Some(QueryParam::Int(kickoff_index)));
        }

        if let Some(pegin_txid) = &self.pegin_txid {
            query_builder
                .and_where("pegin_txid = ?", Some(QueryParam::BTCTxid(pegin_txid.clone())));
        }

        if let Some(graph_id) = &self.graph_id {
            query_builder.and_where(
                "hex(graph_id) = ? COLLATE NOCASE",
                Some(QueryParam::Text(graph_id.clone())),
            );
        }
        for raw_condition in &self.raw_conditions {
            query_builder.add_raw_condition(raw_condition);
        }
        if let Some(order) = &self.order {
            query_builder.apply_order(order)
        }
        // Add pagination
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

/// Runtime graph fields that are not part of the signed graph definition.
///
/// Status is intentionally absent. All graph status changes must go through
/// `StorageProcessor::transition_graph_status` so a stale event cannot replace
/// a later chain-observed state.
#[derive(Clone, Debug)]
pub struct GraphRuntimeUpdate {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub challenge_txid: Option<SerializableTxid>,
    pub bridge_out_start_at: Option<i64>,
    pub init_withdraw_tx_hash: Option<String>,
    pub proceed_withdraw_height: Option<i64>,
}

impl GraphRuntimeUpdate {
    /// Create new update parameters
    pub fn new(instance_id: Uuid, graph_id: Uuid) -> Self {
        Self {
            instance_id,
            graph_id,
            challenge_txid: None,
            bridge_out_start_at: None,
            init_withdraw_tx_hash: None,
            proceed_withdraw_height: None,
        }
    }

    /// Set challenge transaction ID
    pub fn with_challenge_txid(mut self, challenge_txid: SerializableTxid) -> Self {
        self.challenge_txid = Some(challenge_txid);
        self
    }

    /// Set bridge out start time
    pub fn with_bridge_out_start_at(mut self, bridge_out_start_at: i64) -> Self {
        self.bridge_out_start_at = Some(bridge_out_start_at);
        self
    }

    /// Set init withdraw transaction ID
    pub fn with_init_withdraw_tx_hash(mut self, init_withdraw_tx_hash: String) -> Self {
        self.init_withdraw_tx_hash = Some(init_withdraw_tx_hash);
        self
    }

    /// Set proceed withdraw tx height at goat chain
    pub fn with_proceed_withdraw_height(mut self, proceed_withdraw_height: i64) -> Self {
        self.proceed_withdraw_height = Some(proceed_withdraw_height);
        self
    }

    /// Check if any fields need to be updated
    pub fn has_updates(&self) -> bool {
        self.challenge_txid.is_some()
            || self.bridge_out_start_at.is_some()
            || self.init_withdraw_tx_hash.is_some()
            || self.proceed_withdraw_height.is_some()
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::update(base_sql);
        // Add SET fields
        if let Some(ref challenge_txid) = self.challenge_txid {
            query_builder.set_field("challenge_txid", QueryParam::BTCTxid(challenge_txid.clone()));
        }
        if let Some(bridge_out_start_at) = self.bridge_out_start_at {
            query_builder.set_field("bridge_out_start_at", QueryParam::Int(bridge_out_start_at));
        }
        if let Some(proceed_withdraw_height) = self.proceed_withdraw_height {
            query_builder
                .set_field("proceed_withdraw_height", QueryParam::Int(proceed_withdraw_height));
        }
        if let Some(ref init_withdraw_tx_hash) = self.init_withdraw_tx_hash {
            if init_withdraw_tx_hash.is_empty() {
                // Set NULL value
                query_builder.set_field_null("init_withdraw_tx_hash");
            } else {
                query_builder.set_field(
                    "init_withdraw_tx_hash",
                    QueryParam::Text(init_withdraw_tx_hash.clone()),
                );
            }
        }
        // Add update time
        let current_time = get_current_timestamp_secs();
        query_builder.set_field("updated_at", QueryParam::Int(current_time));

        // Add WHERE clause
        query_builder.and_where(
            "hex(graph_id) = ? COLLATE NOCASE",
            Some(QueryParam::Text(hex::encode(self.graph_id))),
        );
        query_builder.and_where(
            "hex(instance_id) = ? COLLATE NOCASE",
            Some(QueryParam::Text(hex::encode(self.instance_id))),
        );

        query_builder
    }
}

#[derive(Clone, Debug, Default)]
pub struct NodeQuery {
    pub actor: Option<String>,
    pub goat_addr: Option<String>,
    pub time_threshold: Option<i64>,
    pub is_in_time_threshold: bool,
    pub order: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}
impl NodeQuery {
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_goat_addr(mut self, goat_addr: String) -> Self {
        self.goat_addr = Some(goat_addr);
        self
    }

    pub fn with_order(mut self, order: String) -> Self {
        self.order = Some(order);
        self
    }

    pub fn with_pagination(mut self, offset: u32, limit: u32) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn get_query_builder(&self, base_sql: &str) -> QueryBuilder {
        let mut query_builder = QueryBuilder::new(base_sql);

        // Add WHERE conditions
        if let Some(actor) = &self.actor {
            query_builder.and_where("actor = ?", Some(QueryParam::Text(actor.clone())));
        }

        if let Some(goat_addr) = &self.goat_addr {
            query_builder.and_where("goat_addr = ?", Some(QueryParam::Text(goat_addr.clone())));
        }

        if let Some(time_threshold) = &self.time_threshold {
            if self.is_in_time_threshold {
                query_builder.and_where("updated_at > ?", Some(QueryParam::Int(*time_threshold)));
            } else {
                query_builder.and_where("updated_at <= ?", Some(QueryParam::Int(*time_threshold)));
            }
        }

        if let Some(order) = &self.order {
            query_builder.apply_order(order)
        }

        // Add pagination
        query_builder.apply_pagination(self.limit, self.offset);
        query_builder
    }
}

impl<'a> StorageProcessor<'a> {
    pub fn conn(&mut self) -> &mut SqliteConnection {
        match &mut self.conn {
            ConnectionHolder::Pooled(conn) => conn,
            ConnectionHolder::Direct(conn) => conn,
            ConnectionHolder::Transaction(conn) => conn,
        }
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        if let ConnectionHolder::Transaction(transaction) = self.conn {
            transaction.commit().await?;
            Ok(())
        } else {
            panic!(
                "StorageProcessor::commit can only be invoked after calling StorageProcessor::begin_transaction"
            );
        }
    }

    /// Returns grouped instance, graph, and queue state counts for Node metrics.
    pub async fn node_metrics_state_counts(&mut self) -> anyhow::Result<Vec<MetricsStateCount>> {
        let counts = sqlx::query_as::<_, MetricsStateCount>(
            r#"
            SELECT
                'instance' AS category,
                status AS state,
                COUNT(*) AS count,
                MIN(created_at) AS oldest_created_at,
                NULL AS last_success_at
            FROM instance
            GROUP BY status
            UNION ALL
            SELECT
                'swap_escrow' AS category,
                status AS state,
                COUNT(*) AS count,
                MIN(created_at) AS oldest_created_at,
                NULL AS last_success_at
            FROM swap_escrow
            GROUP BY status
            UNION ALL
            SELECT
                'graph' AS category,
                status AS state,
                COUNT(*) AS count,
                MIN(created_at) AS oldest_created_at,
                NULL AS last_success_at
            FROM graph
            GROUP BY status
            ORDER BY category, state
            "#,
        )
        .fetch_all(self.conn())
        .await?;
        Ok(counts)
    }

    /// Returns local aggregate values for flow-stall and operator-liquidity alerts.
    pub async fn node_alert_metrics_snapshot(
        &mut self,
        local_peer_id: &str,
    ) -> anyhow::Result<NodeAlertMetricsSnapshot> {
        let snapshot = sqlx::query_as::<_, NodeAlertMetricsSnapshot>(
            r#"
            SELECT
                (
                    SELECT MIN(status_updated_at)
                    FROM instance
                    WHERE status NOT IN (
                        'RelayerL2Minted', 'PresignedFailed', 'RelayerL2MintedFailed',
                        'Timeout', 'UserCanceled', 'NoEnoughCommitteesAnswered', 'UserDiscarded',
                        'Failed', 'Success', 'Canceled'
                    )
                ) AS pegin_oldest_active_status_updated_at,
                (
                    SELECT MIN(status_updated_at)
                    FROM instance
                    WHERE status = 'UserInited'
                ) AS pegin_oldest_committee_wait_status_updated_at,
                (
                    SELECT MIN(status_updated_at)
                    FROM swap_escrow
                    WHERE status NOT IN ('Claim', 'Timeout', 'Refund')
                ) AS pegout_oldest_active_status_updated_at,
                (
                    SELECT available_peg_btc
                    FROM node
                    WHERE peer_id = ? AND actor = 'Operator'
                    LIMIT 1
                ) AS operator_available_pegbtc
            "#,
        )
        .bind(local_peer_id)
        .fetch_one(self.conn())
        .await?;
        Ok(snapshot)
    }

    /// Returns aggregate local progress for the configured event watchers.
    pub async fn event_watch_metrics_snapshot(
        &mut self,
        finalized_height: i64,
    ) -> anyhow::Result<EventWatchMetricsSnapshot> {
        Ok(sqlx::query_as::<_, EventWatchMetricsSnapshot>(
            r#"
            SELECT
                COALESCE(MAX(MAX(? - from_height + 1, 0)), 0) AS lag_blocks,
                COUNT(*) AS watcher_count,
                COALESCE(SUM(CASE WHEN status IN ('UnSync', 'Syncing') THEN 1 ELSE 0 END), 0)
                    AS syncing_count,
                COALESCE(SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END), 0)
                    AS failed_count
            FROM watch_contract
            WHERE from_height != 0
            "#,
        )
        .bind(finalized_height)
        .fetch_one(self.conn())
        .await?)
    }

    /// Insert an instance only when its ID is not already present.
    ///
    /// Parameters:
    /// - instance: The complete instance data to insert
    ///
    /// Returns:
    /// - Ok(true) if the instance was inserted
    /// - Ok(false) if an instance with the same ID already exists
    /// - Err if the operation failed
    pub async fn insert_instance_if_absent(&mut self, instance: &Instance) -> anyhow::Result<bool> {
        let committees_answers_json = serde_json::to_string(&instance.committees_answers)?;
        let res = sqlx::query(
            "INSERT INTO instance (instance_id, network, from_addr, to_addr, amount, fees, input_utxos, status, goat_tx_hash, goat_tx_height,
                        user_xonly_pubkey, user_change_addr, user_refund_addr, btc_txid, pegin_confirm_txid, pegin_cancel_txid, committees_answers,
                       pegin_data_tx_hash, btc_height, parameters, status_updated_at, post_pegin_txhash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(instance_id) DO NOTHING",
        )
        .bind(instance.instance_id)
        .bind(&instance.network)
        .bind(&instance.from_addr)
        .bind(&instance.to_addr)
        .bind(instance.amount)
        .bind(instance.fees)
        .bind(&instance.input_utxos)
        .bind(&instance.status)
        .bind(&instance.goat_tx_hash)
        .bind(instance.goat_tx_height)
        .bind(instance.user_xonly_pubkey)
        .bind(&instance.user_change_addr)
        .bind(&instance.user_refund_addr)
        .bind(&instance.btc_txid)
        .bind(&instance.pegin_confirm_txid)
        .bind(&instance.pegin_cancel_txid)
        .bind(committees_answers_json)
        .bind(&instance.pegin_data_tx_hash)
        .bind(instance.btc_height)
        .bind(&instance.parameters)
        .bind(instance.status_updated_at)
        .bind(&instance.post_pegin_txhash)
        .bind(instance.created_at)
        .bind(instance.updated_at)
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Create a bridge-in instance from a pegin request, or refresh one that
    /// has not moved past the pegin-request stage yet.
    ///
    /// The request monitor writes the row from the indexed Goat event and may
    /// see the same request again, so a full-row replacement would let a late
    /// or repeated request roll a live instance back to its initial row and
    /// clear everything the later stages wrote. The write is therefore a
    /// compare-and-swap over the current status, and it only touches
    /// the columns a pegin request owns:
    /// committee answers, instance parameters and the BTC-side fields are never
    /// overwritten. The caller is responsible for passing canonical request
    /// metadata - `goat_tx_hash`/`goat_tx_height` are refreshed from it, so that
    /// a re-indexed event can still correct them.
    ///
    /// Returns:
    /// - Ok(true) if the row was inserted or updated
    /// - Ok(false) if an existing row was left untouched because its status
    ///   is outside `allowed_statuses`
    pub async fn upsert_pegin_request_instance(
        &mut self,
        instance: &Instance,
    ) -> anyhow::Result<bool> {
        let committees_answers_json = serde_json::to_string(&instance.committees_answers)?;
        // The row is refreshed only while it still waits for the committee's
        // answers; a row that moved on keeps what it accrued.
        let sql = "INSERT INTO instance \
             (instance_id, network, from_addr, to_addr, amount, fees, input_utxos, \
              status, goat_tx_hash, goat_tx_height, user_xonly_pubkey, user_change_addr, \
              user_refund_addr, btc_txid, pegin_confirm_txid, pegin_cancel_txid, committees_answers, \
              pegin_data_tx_hash, btc_height, parameters, status_updated_at, \
              post_pegin_txhash, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(instance_id) DO UPDATE SET \
               network = excluded.network, \
               from_addr = CASE WHEN excluded.from_addr = '' \
                   THEN instance.from_addr ELSE excluded.from_addr END, \
               to_addr = excluded.to_addr, \
               amount = excluded.amount, \
               fees = excluded.fees, \
               input_utxos = excluded.input_utxos, \
               status = excluded.status, \
               goat_tx_hash = excluded.goat_tx_hash, \
               goat_tx_height = excluded.goat_tx_height, \
               user_xonly_pubkey = excluded.user_xonly_pubkey, \
               user_change_addr = excluded.user_change_addr, \
               user_refund_addr = excluded.user_refund_addr, \
               status_updated_at = excluded.status_updated_at, \
               updated_at = excluded.updated_at \
             WHERE instance.status = ?";
        let query = sqlx::query(sql)
            .bind(instance.instance_id)
            .bind(&instance.network)
            .bind(&instance.from_addr)
            .bind(&instance.to_addr)
            .bind(instance.amount)
            .bind(instance.fees)
            .bind(&instance.input_utxos)
            .bind(&instance.status)
            .bind(&instance.goat_tx_hash)
            .bind(instance.goat_tx_height)
            .bind(instance.user_xonly_pubkey)
            .bind(&instance.user_change_addr)
            .bind(&instance.user_refund_addr)
            .bind(&instance.btc_txid)
            .bind(&instance.pegin_confirm_txid)
            .bind(&instance.pegin_cancel_txid)
            .bind(committees_answers_json)
            .bind(&instance.pegin_data_tx_hash)
            .bind(instance.btc_height)
            .bind(&instance.parameters)
            .bind(instance.status_updated_at)
            .bind(&instance.post_pegin_txhash)
            .bind(instance.created_at)
            .bind(instance.updated_at)
            .bind(crate::InstanceBridgeInStatus::UserInited.to_string());
        let res = query.execute(self.conn()).await?;
        Ok(res.rows_affected() > 0)
    }

    /// Find a single instance by its ID
    ///
    /// Retrieves an instance from the database using its unique instance_id.
    ///
    /// Parameters:
    /// - instance_id: The UUID of the instance to find
    ///
    /// Returns:
    /// - Ok(Some(instance)) if the instance was found
    /// - Ok(None) if no instance with the given ID exists
    /// - Err if the query failed
    pub async fn find_instance(&mut self, instance_id: &Uuid) -> anyhow::Result<Option<Instance>> {
        let row = sqlx::query_as::<_, Instance>("SELECT * FROM instance WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_optional(self.conn())
            .await?;
        Ok(row)
    }

    /// Find multiple instances with filtering and pagination
    ///
    /// Retrieves instances from the database with optional filtering criteria
    /// and pagination support. Uses QueryBuilder for dynamic query construction.
    ///
    /// Parameters:
    /// - params: InstanceQuery containing all filter criteria and pagination options
    ///
    /// Returns:
    /// - Ok((instances, total_count)) where instances is a vector of matching instances
    ///   and total_count is the total number of instances matching the criteria
    /// - Err if the query failed
    pub async fn find_instances(
        &mut self,
        params: InstanceQuery,
    ) -> anyhow::Result<(Vec<Instance>, i64)> {
        let mut count_params = params.clone();
        (count_params.order, count_params.offset) = (None, None);
        let instances_query_builder = params.get_query_builder("SELECT * FROM instance");
        let count_query_builder =
            count_params.get_query_builder("SELECT count(*) as total_instances FROM instance");
        // Execute data query
        let sql = instances_query_builder.get_sql();
        let mut data_query = sqlx::query_as::<_, Instance>(&sql);
        data_query = instances_query_builder.query_as(data_query);
        // Execute count query
        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);
        Ok((
            data_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_instances"),
        ))
    }
    /// Insert a swap escrow only when its escrow hash is not already present.
    ///
    /// The chain-event watcher is the sole writer for Initialize records;
    /// the escrow-hash primary key makes event replays idempotent.
    pub async fn insert_swap_escrow_if_absent(
        &mut self,
        escrow: &SwapEscrow,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO swap_escrow \
             (escrow_hash, network, status, offerer_addr, claimer_addr, btc_addr, token, amount, \
              refund_deadline, escrow_data, init_tx_hash, init_tx_height, claim_tx_hash, \
              claim_btc_txid, refund_tx_hash, status_updated_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(escrow_hash) DO NOTHING",
            escrow.escrow_hash,
            escrow.network,
            escrow.status,
            escrow.offerer_addr,
            escrow.claimer_addr,
            escrow.btc_addr,
            escrow.token,
            escrow.amount,
            escrow.refund_deadline,
            escrow.escrow_data,
            escrow.init_tx_hash,
            escrow.init_tx_height,
            escrow.claim_tx_hash,
            escrow.claim_btc_txid,
            escrow.refund_tx_hash,
            escrow.status_updated_at,
            escrow.created_at,
            escrow.updated_at
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Find a swap escrow by its (normalized) escrow hash.
    pub async fn find_swap_escrow(
        &mut self,
        escrow_hash: &str,
    ) -> anyhow::Result<Option<SwapEscrow>> {
        let row =
            sqlx::query_as::<_, SwapEscrow>("SELECT * FROM swap_escrow WHERE escrow_hash = ?")
                .bind(escrow_hash)
                .fetch_optional(self.conn())
                .await?;
        Ok(row)
    }

    /// Find swap escrows with filtering and pagination.
    ///
    /// Returns the matching page together with the total match count.
    pub async fn find_swap_escrows(
        &mut self,
        params: SwapEscrowQuery,
    ) -> anyhow::Result<(Vec<SwapEscrow>, i64)> {
        let mut count_params = params.clone();
        (count_params.order, count_params.offset) = (None, None);
        let escrows_query_builder = params.get_query_builder("SELECT * FROM swap_escrow");
        let count_query_builder =
            count_params.get_query_builder("SELECT count(*) as total_escrows FROM swap_escrow");
        let sql = escrows_query_builder.get_sql();
        let mut data_query = sqlx::query_as::<_, SwapEscrow>(&sql);
        data_query = escrows_query_builder.query_as(data_query);
        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);
        Ok((
            data_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_escrows"),
        ))
    }

    /// Update swap escrow fields using the builder pattern.
    pub async fn update_swap_escrow(&mut self, params: &SwapEscrowUpdate) -> anyhow::Result<bool> {
        let query_builder = params.get_query_builder("swap_escrow");
        let update_sql = query_builder.get_sql();
        let mut query = sqlx::query(&update_sql);
        query = query_builder.query(query);
        let result = query.execute(self.conn()).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Mark still-initializing swap escrows whose refund deadline has passed
    /// as timed out. Returns the number of escrows transitioned.
    pub async fn timeout_expired_swap_escrows(&mut self, current_time: i64) -> anyhow::Result<u64> {
        let initialize_status = SwapEscrowStatus::Initialize.to_string();
        let timeout_status = SwapEscrowStatus::Timeout.to_string();
        let row = sqlx::query!(
            "UPDATE swap_escrow SET status = ?, status_updated_at = ?, updated_at = ? \
             WHERE status = ? AND refund_deadline > 0 AND refund_deadline < ?",
            timeout_status,
            current_time,
            current_time,
            initialize_status,
            current_time
        )
        .execute(self.conn())
        .await?;
        Ok(row.rows_affected())
    }

    /// Update instance fields using builder pattern
    ///
    /// This is the most elegant update method, using the InstanceUpdate builder pattern
    /// Provides type safety and clear API
    pub async fn update_instance(&mut self, params: &InstanceUpdate) -> anyhow::Result<bool> {
        if !params.has_updates() {
            return Ok(false);
        }
        let query_builder = params.get_query_builder("instance");
        // Get SQL and parameters
        let update_sql = query_builder.get_sql();
        // Execute query
        let mut query = sqlx::query(&update_sql);
        query = query_builder.query(query);
        let result = query.execute(self.conn()).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Add or update a single committee answer for an instance
    ///
    /// This method merges one committee answer atomically so concurrent event
    /// handlers cannot overwrite each other's answers with stale full maps.
    pub async fn update_instance_committee_answer(
        &mut self,
        instance_id: &Uuid,
        committee_addr: &str,
        pubkey: Vec<u8>,
    ) -> anyhow::Result<bool> {
        let committee_patch = serde_json::json!({ (committee_addr): pubkey }).to_string();
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query(
            "UPDATE instance \
             SET committees_answers = json_patch(COALESCE(committees_answers, '{}'), json(?)), \
                 updated_at = ? \
             WHERE instance_id = ?",
        )
        .bind(committee_patch)
        .bind(current_time)
        .bind(instance_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_instance_parameters(
        &mut self,
        instance_id: &Uuid,
        parameters: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE instance SET parameters = ?,  updated_at = ? WHERE instance_id = ?",
            parameters,
            current_time,
            instance_id
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_instance_parameters_by_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<String>> {
        let res =
            sqlx::query!("SELECT parameters FROM instance WHERE instance_id = ?", instance_id)
                .fetch_optional(self.conn())
                .await?;
        Ok(res.and_then(|record| record.parameters))
    }

    pub async fn upsert_pending_graph_init(
        &mut self,
        instance_id: &Uuid,
        operator_pubkey: &str,
        graph_id: &Uuid,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query(
            "INSERT INTO pending_graph_init
             (instance_id, operator_pubkey, graph_id, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(instance_id, operator_pubkey) DO UPDATE SET
                 graph_id = excluded.graph_id,
                 updated_at = excluded.updated_at",
        )
        .bind(instance_id)
        .bind(operator_pubkey)
        .bind(graph_id)
        .bind(current_time)
        .bind(current_time)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn find_pending_graph_init_by_instance_and_operator_pubkey(
        &mut self,
        instance_id: &Uuid,
        operator_pubkey: &str,
    ) -> anyhow::Result<Option<PendingGraphInit>> {
        Ok(sqlx::query_as::<_, PendingGraphInit>(
            "SELECT instance_id, operator_pubkey, graph_id, created_at, updated_at
             FROM pending_graph_init
             WHERE instance_id = ? AND operator_pubkey = ?",
        )
        .bind(instance_id)
        .bind(operator_pubkey)
        .fetch_optional(self.conn())
        .await?)
    }

    /// Every open setup session of an instance (one per local operator).
    pub async fn list_pending_graph_inits_by_instance(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<PendingGraphInit>> {
        Ok(sqlx::query_as::<_, PendingGraphInit>(
            "SELECT instance_id, operator_pubkey, graph_id, created_at, updated_at
             FROM pending_graph_init
             WHERE instance_id = ?",
        )
        .bind(instance_id)
        .fetch_all(self.conn())
        .await?)
    }

    /// Every open setup session of an operator.
    pub async fn list_pending_graph_inits_by_operator(
        &mut self,
        operator_pubkey: &str,
    ) -> anyhow::Result<Vec<PendingGraphInit>> {
        Ok(sqlx::query_as::<_, PendingGraphInit>(
            "SELECT instance_id, operator_pubkey, graph_id, created_at, updated_at
             FROM pending_graph_init
             WHERE operator_pubkey = ?
             ORDER BY created_at ASC, graph_id ASC",
        )
        .bind(operator_pubkey)
        .fetch_all(self.conn())
        .await?)
    }

    pub async fn find_pending_graph_init_by_graph_id(
        &mut self,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<PendingGraphInit>> {
        Ok(sqlx::query_as::<_, PendingGraphInit>(
            "SELECT instance_id, operator_pubkey, graph_id, created_at, updated_at
             FROM pending_graph_init
             WHERE graph_id = ?",
        )
        .bind(graph_id)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn delete_pending_graph_init(
        &mut self,
        instance_id: &Uuid,
        operator_pubkey: &str,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM pending_graph_init WHERE instance_id = ? AND operator_pubkey = ?",
        )
        .bind(instance_id)
        .bind(operator_pubkey)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Insert a graph definition or verify a compatible replay.
    ///
    /// The canonical definition hash is an identity fence: a new graph may
    /// never reuse an existing graph id and inherit its runtime projection.
    /// Compatible replays may only fill missing non-identity metadata; they
    /// never replace status, observed transaction ids, or withdraw metadata.
    pub async fn upsert_graph_definition(&mut self, graph: &Graph) -> anyhow::Result<u64> {
        if graph.definition_hash.is_empty() {
            anyhow::bail!("graph {} is missing its definition hash", graph.graph_id);
        }
        if graph.status != GraphStatus::OperatorPresigned.to_string()
            || !graph.sub_status.is_empty()
            || graph.challenge_txid.is_some()
            || graph.init_withdraw_tx_hash.is_some()
            || graph.bridge_out_start_at != 0
            || graph.proceed_withdraw_height != 0
        {
            anyhow::bail!(
                "graph {} definition writes must use the OperatorPresigned baseline without runtime data",
                graph.graph_id
            );
        }
        let verifier_assert_txids_json = serde_json::to_string(&graph.verifier_assert_txids)?;
        let disprove_txids_json = serde_json::to_string(&graph.disprove_txids)?;
        let watchtower_challenge_timeout_txids_json =
            serde_json::to_string(&graph.watchtower_challenge_timeout_txids)?;
        let operator_challenge_nack_txids_json =
            serde_json::to_string(&graph.operator_challenge_nack_txids)?;
        let res = sqlx::query(
            "INSERT INTO graph (graph_id, instance_id, kickoff_index, from_addr, to_addr, amount, challenge_amount,
                    status, sub_status, operator_pubkey, definition_hash, cur_prekickoff_txid, next_prekickoff, force_skip_kickoff_txid,
                    quick_challenge_txid, challenge_incomplete_kickoff_txid, pegin_txid, kickoff_txid, take1_txid,
                    challenge_txid, take2_txid, watchtower_challenge_init_txid, operator_assert_txid, verifier_assert_txids, disprove_txids,
                    watchtower_challenge_timeout_txids, operator_challenge_nack_txids, operator_commit_timeout_txid,
                    init_withdraw_tx_hash, bridge_out_start_at, status_updated_at, proceed_withdraw_height, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(graph_id) DO UPDATE SET
                    from_addr = CASE
                        WHEN graph.from_addr = '' AND excluded.from_addr <> '' THEN excluded.from_addr
                        ELSE graph.from_addr
                    END,
                    to_addr = CASE
                        WHEN graph.to_addr = '' AND excluded.to_addr <> '' THEN excluded.to_addr
                        ELSE graph.to_addr
                    END
             WHERE graph.definition_hash = excluded.definition_hash
               AND graph.instance_id = excluded.instance_id",
        )
        .bind(graph.graph_id)
        .bind(graph.instance_id)
        .bind(graph.kickoff_index)
        .bind(&graph.from_addr)
        .bind(&graph.to_addr)
        .bind(graph.amount)
        .bind(graph.challenge_amount)
        .bind(GraphStatus::OperatorPresigned.to_string())
        .bind("")
        .bind(&graph.operator_pubkey)
        .bind(&graph.definition_hash)
        .bind(graph.cur_prekickoff_txid.clone())
        .bind(graph.next_prekickoff.clone())
        .bind(graph.force_skip_kickoff_txid.clone())
        .bind(graph.quick_challenge_txid.clone())
        .bind(graph.challenge_incomplete_kickoff_txid.clone())
        .bind(graph.pegin_txid.clone())
        .bind(graph.kickoff_txid.clone())
        .bind(graph.take1_txid.clone())
        .bind(Option::<SerializableTxid>::None)
        .bind(graph.take2_txid.clone())
        .bind(graph.watchtower_challenge_init_txid.clone())
        .bind(graph.operator_assert_txid.clone())
        .bind(verifier_assert_txids_json)
        .bind(disprove_txids_json)
        .bind(watchtower_challenge_timeout_txids_json)
        .bind(operator_challenge_nack_txids_json)
        .bind(graph.operator_commit_timeout_txid.clone())
        .bind(Option::<String>::None)
        .bind(0_i64)
        .bind(graph.status_updated_at)
        .bind(0_i64)
        .bind(graph.created_at)
        .bind(graph.updated_at)
        .execute(self.conn())
        .await?;
        if res.rows_affected() == 0 {
            let Some(existing) = self.find_graph(&graph.graph_id).await? else {
                anyhow::bail!("graph {} disappeared while storing its definition", graph.graph_id);
            };
            if existing.definition_hash != graph.definition_hash {
                anyhow::bail!(
                    "conflicting graph definition for graph_id {}: existing={}, incoming={}",
                    graph.graph_id,
                    existing.definition_hash,
                    graph.definition_hash
                );
            }
            if existing.instance_id != graph.instance_id {
                anyhow::bail!(
                    "graph definition instance mismatch for graph_id {}: existing={}, incoming={}",
                    graph.graph_id,
                    existing.instance_id,
                    graph.instance_id
                );
            }
        }
        Ok(res.rows_affected())
    }

    pub async fn update_graph_runtime(
        &mut self,
        params: &GraphRuntimeUpdate,
    ) -> anyhow::Result<bool> {
        if !params.has_updates() {
            return Ok(false);
        }
        let query_builder = params.get_query_builder("graph");
        let update_sql = query_builder.get_sql();
        let query = sqlx::query(&update_sql);
        let query = query_builder.query(query);
        let result = query.execute(self.conn()).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically advance a graph status according to its evidence source.
    ///
    /// The conditional UPDATE is the authority check. The follow-up read only
    /// distinguishes an idempotent replay from a stale event; it never decides
    /// whether a write is permitted.
    pub async fn transition_graph_status(
        &mut self,
        instance_id: Uuid,
        graph_id: Uuid,
        target: GraphStatus,
        source: GraphStatusSource,
        sub_status: Option<String>,
    ) -> anyhow::Result<GraphStatusTransitionOutcome> {
        if !target.is_protocol_status() {
            anyhow::bail!("frontend-only graph status {target} cannot be persisted");
        }

        let allowed_from = target.allowed_transition_from(source);
        if allowed_from.is_empty() {
            // Some verified scans merely observe a baseline state (for
            // example, an operator-pre-signed graph). There is no authorized
            // predecessor edge to write in that case; return the current
            // projection without mutating it.
            return self.graph_status_transition_outcome(instance_id, graph_id, target).await;
        }

        let allowed_from: Vec<String> = allowed_from.iter().map(ToString::to_string).collect();
        let current_time = get_current_timestamp_secs();
        let mut query_builder = QueryBuilder::update("graph");
        query_builder.set_field("status", QueryParam::Text(target.to_string()));
        if let Some(sub_status) = sub_status.as_ref() {
            query_builder.set_field("sub_status", QueryParam::Text(sub_status.clone()));
        }
        query_builder.set_field("status_updated_at", QueryParam::Int(current_time));
        query_builder.set_field("updated_at", QueryParam::Int(current_time));
        query_builder.and_where(
            "hex(graph_id) = ? COLLATE NOCASE",
            Some(QueryParam::Text(hex::encode(graph_id))),
        );
        query_builder.and_where(
            "hex(instance_id) = ? COLLATE NOCASE",
            Some(QueryParam::Text(hex::encode(instance_id))),
        );
        query_builder.and_where_in("status", &allowed_from, false);

        let update_sql = query_builder.get_sql();
        let query = query_builder.query(sqlx::query(&update_sql));
        if query.execute(self.conn()).await?.rows_affected() > 0 {
            return Ok(GraphStatusTransitionOutcome::Applied);
        }

        // A zero-row conditional update has two distinct meanings: this can
        // be an idempotent replay, or another writer may have moved the row to
        // a state which rejects this transition. The follow-up read reports
        // that distinction; it never authorizes a write.
        let outcome = self.graph_status_transition_outcome(instance_id, graph_id, target).await?;
        if !matches!(outcome, GraphStatusTransitionOutcome::AlreadyCurrent) {
            return Ok(outcome);
        }

        let Some(sub_status) = sub_status else {
            return Ok(GraphStatusTransitionOutcome::AlreadyCurrent);
        };

        let current_time = get_current_timestamp_secs();
        let result = sqlx::query(
            "UPDATE graph SET sub_status = ?, updated_at = ? \
             WHERE graph_id = ? AND instance_id = ? AND status = ?",
        )
        .bind(sub_status)
        .bind(current_time)
        .bind(graph_id)
        .bind(instance_id)
        .bind(target.to_string())
        .execute(self.conn())
        .await?;
        if result.rows_affected() > 0 {
            return Ok(GraphStatusTransitionOutcome::AlreadyCurrent);
        }

        // The row may have changed between the outcome read and the optional
        // sub-status update. Re-read so a concurrent transition is never
        // misreported as an idempotent replay or a missing graph.
        self.graph_status_transition_outcome(instance_id, graph_id, target).await
    }

    async fn graph_status_transition_outcome(
        &mut self,
        instance_id: Uuid,
        graph_id: Uuid,
        target: GraphStatus,
    ) -> anyhow::Result<GraphStatusTransitionOutcome> {
        let Some(current_graph) = self.find_graph(&graph_id).await? else {
            return Ok(GraphStatusTransitionOutcome::NotFound);
        };
        if current_graph.instance_id != instance_id {
            return Ok(GraphStatusTransitionOutcome::NotFound);
        }
        let current = GraphStatus::from_str(&current_graph.status).map_err(|_| {
            anyhow::anyhow!(
                "graph {graph_id} has invalid persisted status {}",
                current_graph.status
            )
        })?;
        Ok(if current == target {
            GraphStatusTransitionOutcome::AlreadyCurrent
        } else {
            GraphStatusTransitionOutcome::Rejected { current }
        })
    }

    /// The one graph an operator may hold in a slot.
    pub async fn find_graph_by_operator_slot(
        &mut self,
        operator_pubkey: &str,
        graph_nonce: i64,
    ) -> anyhow::Result<Option<Graph>> {
        let row = sqlx::query_as::<_, Graph>(
            "SELECT * FROM graph WHERE operator_pubkey = ? AND kickoff_index = ?",
        )
        .bind(operator_pubkey)
        .bind(graph_nonce)
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn find_graph(&mut self, graph_id: &Uuid) -> anyhow::Result<Option<Graph>> {
        let row = sqlx::query_as::<_, Graph>(
            "SELECT *
             FROM graph
             WHERE graph_id = ?",
        )
        .bind(graph_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn find_graphs(&mut self, params: GraphQuery) -> anyhow::Result<(Vec<Graph>, i64)> {
        // Build base query
        let mut count_params = params.clone();
        (count_params.offset, count_params.limit) = (None, None);
        let query_builder = params.get_query_builder(
            "SELECT graph_id,
                    instance_id,
                    kickoff_index,
                    from_addr,
                    to_addr,
                    amount,
                    challenge_amount,
                    status,
                    sub_status,
                    operator_pubkey,
                    definition_hash,
                    cur_prekickoff_txid,
                    next_prekickoff,
                    force_skip_kickoff_txid,
                    quick_challenge_txid,
                    challenge_incomplete_kickoff_txid,
                    pegin_txid,
                    kickoff_txid,
                    take1_txid,
                    challenge_txid,
                    take2_txid,
                    watchtower_challenge_init_txid,
                    operator_assert_txid,
                    verifier_assert_txids,
                    disprove_txids,
                    watchtower_challenge_timeout_txids,
                    operator_challenge_nack_txids,
                    operator_commit_timeout_txid,
                    init_withdraw_tx_hash,
                    bridge_out_start_at,
                    status_updated_at,
                    proceed_withdraw_height,
                    CASE
                        WHEN bridge_out_start_at > 0
                        THEN bridge_out_start_at
                        ELSE created_at
                    END AS created_at,
                    updated_at
             FROM graph",
        );

        let count_query_builder =
            count_params.get_query_builder("SELECT count(graph_id) as total_graphs FROM graph");
        let sql = query_builder.get_sql();
        let mut graphs_query = sqlx::query_as::<_, Graph>(&sql);
        graphs_query = query_builder.query_as(graphs_query);
        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);

        Ok((
            graphs_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_graphs"),
        ))
    }

    pub async fn get_graphs_by_instance_id(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Vec<Graph>> {
        let res = sqlx::query_as::<_, Graph>(
            "SELECT *
             FROM graph
             WHERE instance_id = ?",
        )
        .bind(instance_id)
        .fetch_all(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn get_graph_id_by_instance_id_and_operator_pubkey(
        &mut self,
        instance_id: &Uuid,
        operator_pubkey: &str,
    ) -> anyhow::Result<Option<Uuid>> {
        let res = sqlx::query_as::<_, Graph>(
            "SELECT *
             FROM graph
             WHERE instance_id = ? AND operator_pubkey = ?",
        )
        .bind(instance_id)
        .bind(operator_pubkey)
        .fetch_optional(self.conn())
        .await?;
        Ok(res.map(|graph| graph.graph_id))
    }

    pub async fn get_operator_graphs(&mut self, params: GraphQuery) -> anyhow::Result<Vec<Graph>> {
        let graph_query_builder = params.get_query_builder("SELECT * FROM graph");
        let operator_graph_sql = graph_query_builder.get_sql();
        let mut operator_graphs_query = sqlx::query_as::<_, Graph>(&operator_graph_sql);
        operator_graphs_query = graph_query_builder.query_as(operator_graphs_query);
        Ok(operator_graphs_query.fetch_all(self.conn()).await?)
    }

    pub async fn update_node_timestamp(
        &mut self,
        peer_id: &str,
        timestamp: i64,
    ) -> anyhow::Result<()> {
        let result =
            sqlx::query!(r#"UPDATE node SET updated_at = ? WHERE peer_id = ?"#, timestamp, peer_id)
                .execute(self.conn())
                .await?;

        if result.rows_affected() == 0 {
            // Any peer that never announced itself lands here, once per message
            // burst, so this must not be louder than debug.
            tracing::debug!("Node {peer_id} not found in DB, no rows updated");
        }

        Ok(())
    }

    pub async fn find_graph_neighbor_ids(
        &mut self,
        graph_id: Uuid,
        range: i64,
    ) -> anyhow::Result<Vec<(i64, Uuid)>> {
        #[derive(sqlx::FromRow)]
        struct GraphIds {
            pub graph_id: Uuid,
            pub kickoff_index: i64,
        }
        if let Some(graph) = self.find_graph(&graph_id).await? {
            let start = 0.max(graph.kickoff_index - range);
            let end = graph.kickoff_index + range;
            let res = sqlx::query_as!(
                GraphIds,
                "SELECT graph_id AS \"graph_id:Uuid\", kickoff_index
                 FROM graph
                 WHERE operator_pubkey = ?
                   AND kickoff_index >= ?
                   AND kickoff_index <= ?",
                graph.operator_pubkey,
                start,
                end
            )
            .fetch_all(self.conn())
            .await?;

            Ok(res.into_iter().map(|g| (g.kickoff_index, g.graph_id)).collect())
        } else {
            Ok(vec![])
        }
    }
    /// Insert or update node without reward field
    pub async fn upsert_node(&mut self, node: &Node) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            r#"
            INSERT INTO node (peer_id, node_name, actor, goat_addr, btc_pub_key, socket_addr, service_fee_rate, available_peg_btc,
                              binding_sig, binding_issued_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (peer_id) DO UPDATE SET actor             = excluded.actor,
                                                node_name         = excluded.node_name,
                                                goat_addr         = excluded.goat_addr,
                                                btc_pub_key       = excluded.btc_pub_key,
                                                service_fee_rate       = excluded.service_fee_rate,
                                                available_peg_btc = excluded.available_peg_btc,
                                                socket_addr       = excluded.socket_addr,
                                                binding_sig       = excluded.binding_sig,
                                                binding_issued_at = excluded.binding_issued_at,
                                                updated_at        = excluded.updated_at
            "#,
            node.peer_id,
            node.node_name,
            node.actor,
            node.goat_addr,
            node.btc_pub_key,
            node.socket_addr,
            node.service_fee_rate,
            node.available_peg_btc,
            node.binding_sig,
            node.binding_issued_at,
            node.created_at,
            node.updated_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    // Do not update the `updated_at` field; this field is updated based on heartbeat messages
    // and is used to determine whether a node is alive.
    pub async fn update_node_reward_by_peer_id(
        &mut self,
        peer_id: &str,
        reward: &str,
    ) -> anyhow::Result<()> {
        sqlx::query!(r#"UPDATE node SET reward = reward + ? WHERE peer_id = ?"#, reward, peer_id)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn get_node_by_btc_pub_key(
        &mut self,
        btc_pub_key: &str,
    ) -> anyhow::Result<Option<Node>> {
        Ok(sqlx::query_as!(Node, r#"SELECT *  FROM node WHERE btc_pub_key = ?"#, btc_pub_key)
            .fetch_optional(self.conn())
            .await?)
    }

    pub async fn find_nodes(&mut self, params: &NodeQuery) -> anyhow::Result<(Vec<Node>, i64)> {
        let data_query_builder = params.get_query_builder("SELECT *  FROM node");
        let mut count_params = params.clone();
        (count_params.offset, count_params.limit) = (None, None);
        let count_query_builder =
            count_params.get_query_builder("SELECT count(peer_id) as total_nodes FROM node");

        let data_sql = data_query_builder.get_sql();
        let mut nodes_query = sqlx::query_as::<_, Node>(&data_sql);
        nodes_query = data_query_builder.query_as(nodes_query);

        let count_sql = count_query_builder.get_sql();
        let mut count_query = sqlx::query(&count_sql);
        count_query = count_query_builder.query(count_query);

        Ok((
            nodes_query.fetch_all(self.conn()).await?,
            count_query.fetch_one(self.conn()).await?.get::<i64, &str>("total_nodes"),
        ))
    }

    pub async fn node_overview(&mut self, time_threshold: i64) -> anyhow::Result<NodesOverview> {
        let records = sqlx::query!(
            r#"SELECT count(*) AS total,
                    actor,
                    SUM(CASE WHEN updated_at >= ? THEN 1 ELSE 0 END) AS online,
                    SUM(CASE WHEN updated_at < ? THEN 1 ELSE 0 END) AS offline
             FROM node
             GROUP BY actor"#,
            time_threshold,
            time_threshold
        )
        .fetch_all(self.conn())
        .await?;

        let mut res = NodesOverview::default();
        for record in records {
            res.total += record.total;
            match record.actor.as_str() {
                "Verifier" => {
                    res.offline_verifiers += record.offline;
                    res.online_verifiers += record.online;
                }
                "Operator" => {
                    (res.offline_operators, res.online_operators) = (record.offline, record.online);
                }
                "Committee" => {
                    (res.offline_committees, res.online_committees) =
                        (record.offline, record.online);
                }
                "Watchtower" => {
                    (res.offline_watchtowers, res.online_watchtowers) =
                        (record.offline, record.online);
                }
                _ => {}
            };
        }
        Ok(res)
    }

    pub async fn node_by_id(&mut self, peer_id: &str) -> anyhow::Result<Option<Node>> {
        let res = sqlx::query_as!(Node, r#"SELECT * FROM node WHERE peer_id = ?"#, peer_id)
            .fetch_optional(self.conn())
            .await?;
        Ok(res)
    }

    pub async fn get_sum_bridge_in_txn(
        &mut self,
        statuses: &[String],
    ) -> anyhow::Result<(i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct BridgeInRow {
            pub total: i64,
            pub tx_count: i64,
        }

        let query_str = format!(
            "SELECT SUM(amount) AS total, COUNT(*) AS tx_count
             FROM instance
             WHERE status IN ({})",
            create_place_holders(statuses)
        );
        let mut query = sqlx::query_as::<_, BridgeInRow>(&query_str);
        for status in statuses {
            query = query.bind(status);
        }
        let record = query.fetch_one(self.conn()).await?;
        Ok((record.total, record.tx_count))
    }

    pub async fn get_sum_peg_out(&mut self, statuses: &[String]) -> anyhow::Result<(i64, i64)> {
        #[derive(sqlx::FromRow)]
        struct BridgeOutRow {
            pub total: i64,
            pub tx_count: i64,
        }

        let query_str = format!(
            "SELECT SUM(amount) AS total, COUNT(*) AS tx_count
            FROM graph
            WHERE status IN
                  ({})",
            create_place_holders(statuses)
        );
        let mut query = sqlx::query_as::<_, BridgeOutRow>(&query_str);
        for status in statuses {
            query = query.bind(status);
        }
        let record = query.fetch_one(self.conn()).await?;
        Ok((record.total, record.tx_count))
    }

    pub async fn get_nodes_info(&mut self, time_threshold: i64) -> anyhow::Result<(i64, i64)> {
        let total = sqlx::query!(r#"SELECT COUNT(peer_id) AS total FROM node"#)
            .fetch_one(self.conn())
            .await?
            .total;
        let time_pri =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 - time_threshold;
        tracing::info!("{time_pri}");
        let alive = sqlx::query!(
            r#"SELECT COUNT(peer_id) AS alive FROM node WHERE updated_at >= ?"#,
            time_pri
        )
        .fetch_one(self.conn())
        .await?
        .alive;
        Ok((total, alive))
    }

    /// Load up to `limit` operator bindings, confirmed operators first.
    /// The caller re-verifies signatures.
    pub async fn load_p2p_peer_bindings(&mut self, limit: i64) -> anyhow::Result<Vec<Node>> {
        let rows = sqlx::query_as::<_, Node>(
            "SELECT * FROM node \
             WHERE binding_sig != '' AND btc_pub_key != '' AND actor = 'Operator' \
             ORDER BY peer_id IN (SELECT peer_id FROM p2p_registered_peer \
                                  WHERE kind = 'Operator') DESC, \
                      updated_at DESC \
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        Ok(rows)
    }

    /// Persist confirmed registration; an operator key may belong to only one peer.
    pub async fn upsert_p2p_registered_peer(
        &mut self,
        peer_id: &str,
        kind: &str,
        pubkey: &str,
    ) -> anyhow::Result<()> {
        if !pubkey.is_empty() {
            sqlx::query(
                "DELETE FROM p2p_registered_peer WHERE kind = ? AND pubkey = ? AND peer_id != ?",
            )
            .bind(kind)
            .bind(pubkey)
            .bind(peer_id)
            .execute(self.conn())
            .await?;
        }
        sqlx::query(
            "INSERT INTO p2p_registered_peer (peer_id, kind, pubkey, verified_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (peer_id, kind) DO UPDATE SET pubkey = excluded.pubkey, \
                                                       verified_at = excluded.verified_at",
        )
        .bind(peer_id)
        .bind(kind)
        .bind(pubkey)
        .bind(get_current_timestamp_secs())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn delete_p2p_registered_peer(
        &mut self,
        peer_id: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM p2p_registered_peer WHERE peer_id = ? AND kind = ?")
            .bind(peer_id)
            .bind(kind)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    /// `(peer_id, kind, pubkey)` of every peer confirmed in an earlier session.
    pub async fn load_p2p_registered_peers(
        &mut self,
    ) -> anyhow::Result<Vec<(String, String, String)>> {
        let rows = sqlx::query("SELECT peer_id, kind, pubkey FROM p2p_registered_peer")
            .fetch_all(self.conn())
            .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("peer_id")?, row.try_get("kind")?, row.try_get("pubkey")?)))
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Allow existing peers or a new unregistered row below `max_rows`.
    /// At capacity, evict the oldest unregistered row older than `evict_stale_before`.
    pub async fn node_row_admissible(
        &mut self,
        peer_id: &str,
        max_rows: i64,
        evict_stale_before: i64,
        local_peer_id: &str,
    ) -> anyhow::Result<bool> {
        let row = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM node WHERE peer_id = ?) AS known, \
                    (SELECT COUNT(*) FROM node \
                     WHERE peer_id NOT IN (SELECT peer_id FROM p2p_registered_peer)) AS total",
        )
        .bind(peer_id)
        .fetch_one(self.conn())
        .await?;
        let known: i64 = row.try_get("known")?;
        let total: i64 = row.try_get("total")?;
        if known != 0 || total < max_rows {
            return Ok(true);
        }
        let evicted = sqlx::query(
            "DELETE FROM node WHERE peer_id = ( \
                 SELECT peer_id FROM node \
                 WHERE updated_at < ? AND peer_id != ? \
                   AND peer_id NOT IN (SELECT peer_id FROM p2p_registered_peer) \
                 ORDER BY updated_at ASC LIMIT 1)",
        )
        .bind(evict_stale_before)
        .bind(local_peer_id)
        .execute(self.conn())
        .await?;
        Ok(evicted.rows_affected() > 0)
    }

    /// Delete stale node rows except this node and confirmed registered peers.
    pub async fn purge_stale_unregistered_nodes(
        &mut self,
        updated_before: i64,
        local_peer_id: &str,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM node \
             WHERE updated_at < ? AND peer_id != ? \
               AND peer_id NOT IN (SELECT peer_id FROM p2p_registered_peer)",
        )
        .bind(updated_before)
        .bind(local_peer_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn upsert_pegin_instance_process_data(
        &mut self,
        pegin_instance_process_data: &PeginInstanceProcessData,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO pegin_instance_process_data
                (instance_id, process_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(instance_id) DO UPDATE
                SET process_data = excluded.process_data,
                    updated_at       = excluded.updated_at",
            pegin_instance_process_data.instance_id,
            pegin_instance_process_data.process_data,
            pegin_instance_process_data.created_at,
            pegin_instance_process_data.updated_at
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_pegin_instance_process_data(
        &mut self,
        instance_id: &Uuid,
    ) -> anyhow::Result<Option<PeginInstanceProcessData>> {
        let row = sqlx::query_as!(
            PeginInstanceProcessData,
            "SELECT
                instance_id AS  \"instance_id:Uuid\",
                process_data,
                created_at,
                updated_at
             FROM pegin_instance_process_data
             WHERE instance_id = ?",
            instance_id
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn upsert_pegin_graph_process_data(
        &mut self,
        pegin_graph_process_data: &PeginGraphProcessData,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query!(
            "INSERT INTO pegin_graph_process_data
                (graph_id, instance_id, process_data, is_endorsed, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(graph_id) DO UPDATE
                SET process_data = excluded.process_data,
                    instance_id  = excluded.instance_id,
                    is_endorsed  = excluded.is_endorsed,
                    updated_at   = excluded.updated_at",
            pegin_graph_process_data.graph_id,
            pegin_graph_process_data.instance_id,
            pegin_graph_process_data.process_data,
            pegin_graph_process_data.is_endorsed,
            pegin_graph_process_data.created_at,
            pegin_graph_process_data.updated_at
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn find_pegin_graph_process_data(
        &mut self,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<PeginGraphProcessData>> {
        let row = sqlx::query_as!(
            PeginGraphProcessData,
            "SELECT
                graph_id AS  \"graph_id:Uuid\",
                instance_id AS  \"instance_id:Uuid\",
                process_data,
                is_endorsed,
                created_at,
                updated_at
             FROM pegin_graph_process_data
             WHERE graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(row)
    }

    pub async fn get_pegin_graph_endorsed_len_by_instance_id(
        &mut self,
        instance_id: &Uuid,
        is_endorsed: bool,
    ) -> anyhow::Result<i64> {
        let record = sqlx::query!(
            r#"SELECT count(*) AS length
               FROM pegin_graph_process_data
               WHERE instance_id = ? AND is_endorsed = ?"#,
            instance_id,
            is_endorsed
        )
        .fetch_one(self.conn())
        .await?;
        Ok(record.length)
    }

    pub async fn upsert_graph_raw_data(
        &mut self,
        instance_id: Uuid,
        graph_raw_data: GraphRawData,
        definition_hash: &str,
    ) -> anyhow::Result<u64> {
        if definition_hash.is_empty() {
            anyhow::bail!(
                "graph {} raw definition is missing its canonical definition hash",
                graph_raw_data.graph_id
            );
        }
        let Some(graph) = self.find_graph(&graph_raw_data.graph_id).await? else {
            anyhow::bail!(
                "cannot store raw definition for missing graph {}",
                graph_raw_data.graph_id
            );
        };
        if graph.instance_id != instance_id {
            anyhow::bail!(
                "raw definition instance does not match graph {}: stored={}, incoming={instance_id}",
                graph_raw_data.graph_id,
                graph.instance_id
            );
        }
        if graph.definition_hash != definition_hash {
            anyhow::bail!(
                "raw definition hash does not match graph {}: stored={}, incoming={definition_hash}",
                graph_raw_data.graph_id,
                graph.definition_hash
            );
        }

        let result = sqlx::query(
            "INSERT INTO graph_raw_data (graph_id, raw_data, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(graph_id) DO UPDATE SET
                 raw_data = excluded.raw_data,
                 updated_at = excluded.updated_at",
        )
        .bind(graph_raw_data.graph_id)
        .bind(graph_raw_data.raw_data)
        .bind(graph_raw_data.created_at)
        .bind(graph_raw_data.updated_at)
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn find_graph_raw_data(
        &mut self,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<GraphRawData>> {
        let row = sqlx::query_as!(
            GraphRawData,
            "SELECT
                graph_id AS \"graph_id:Uuid\",
                raw_data,
                created_at,
                updated_at
            FROM graph_raw_data WHERE graph_id = ?",
            graph_id
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row)
    }

    /// Check graph data exists under both IDs without reading the blob.
    pub async fn find_watch_contract(
        &mut self,
        addr: &str,
    ) -> anyhow::Result<Option<WatchContract>> {
        Ok(sqlx::query_as!(
            WatchContract,
            "SELECT *
             FROM watch_contract
             WHERE contract_addr = ?",
            addr
        )
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn upsert_watch_contract(
        &mut self,
        watch_contract: &WatchContract,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "INSERT INTO watch_contract (contract_addr, the_graph_url, gap, from_height, status, extra, updated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (contract_addr) DO UPDATE SET the_graph_url = excluded.the_graph_url,
                                            gap            = excluded.gap,
                                            from_height    = excluded.from_height,
                                            status         = excluded.status,
                                            extra          = excluded.extra,
                                            updated_at     = excluded.updated_at",
            watch_contract.contract_addr,
            watch_contract.the_graph_url,
            watch_contract.gap,
            watch_contract.from_height,
            watch_contract.status,
            watch_contract.extra,
            watch_contract.updated_at,
            watch_contract.created_at
        ).execute(self.conn()).await;
        Ok(())
    }

    pub async fn update_watch_contract_status(
        &mut self,
        contract_addr: &str,
        status: &str,
        updated_at: i64,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query!(
            "UPDATE watch_contract SET status = ?,  updated_at = ? WHERE contract_addr = ?",
            status,
            updated_at,
            contract_addr,
        )
        .execute(self.conn())
        .await;
        Ok(())
    }

    pub async fn upsert_goat_tx_record(
        &mut self,
        goat_tx_record: &GoatTxRecord,
    ) -> anyhow::Result<()> {
        let mut update_goat_tx_record = goat_tx_record.clone();
        if let Some(goat_tx_record_store) = self
            .find_graph_goat_tx_record(
                &goat_tx_record.instance_id,
                &goat_tx_record.graph_id,
                &goat_tx_record.tx_type,
            )
            .await?
        {
            update_goat_tx_record.created_at = goat_tx_record_store.created_at;
            update_goat_tx_record.is_local = goat_tx_record_store.is_local;
            if goat_tx_record_store.is_processed() {
                update_goat_tx_record.processing_status = goat_tx_record_store.processing_status;
            }
            if update_goat_tx_record.height < goat_tx_record_store.height {
                update_goat_tx_record.height = goat_tx_record_store.height;
            }
            if goat_tx_record_store.extra.is_some() && update_goat_tx_record.extra.is_none() {
                update_goat_tx_record.extra = goat_tx_record_store.extra.clone();
            }

            if !goat_tx_record_store.tx_hash.is_empty() {
                update_goat_tx_record.tx_hash = goat_tx_record_store.tx_hash.clone();
            }
        }
        sqlx::query!(
            "INSERT OR
            REPLACE INTO goat_tx_record (instance_id,
                            graph_id,
                            tx_type,
                            tx_hash,
                            height,
                            is_local,
                            processing_status,
                            extra,
                            created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            update_goat_tx_record.instance_id,
            update_goat_tx_record.graph_id,
            update_goat_tx_record.tx_type,
            update_goat_tx_record.tx_hash,
            update_goat_tx_record.height,
            update_goat_tx_record.is_local,
            update_goat_tx_record.processing_status,
            update_goat_tx_record.extra,
            update_goat_tx_record.created_at
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }

    pub async fn find_graph_goat_tx_record(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        tx_type: &str,
    ) -> anyhow::Result<Option<GoatTxRecord>> {
        Ok(sqlx::query_as!(
            GoatTxRecord,
            "SELECT instance_id AS \"instance_id:Uuid\",
                        graph_id  AS \"graph_id:Uuid\",
                        tx_type,
                        tx_hash,
                        height,
                        is_local,
                        processing_status,
                        extra,
                        created_at
            FROM goat_tx_record
            WHERE instance_id = ?
                AND graph_id = ?
                AND tx_type = ?",
            instance_id,
            graph_id,
            tx_type
        )
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn get_goat_tx_record_by_processing_status(
        &mut self,
        tx_type: &str,
        processing_status: &str,
    ) -> anyhow::Result<Vec<GoatTxRecord>> {
        Ok(sqlx::query_as!(
            GoatTxRecord,
            "SELECT instance_id AS \"instance_id:Uuid\",
                        graph_id  AS \"graph_id:Uuid\",
                        tx_type, tx_hash,
                        height,
                        is_local,
                        processing_status,
                        extra,
                        created_at
            FROM goat_tx_record
            WHERE tx_type = ?
                AND processing_status = ?
                ORDER BY height ASC",
            tx_type,
            processing_status
        )
        .fetch_all(self.conn())
        .await?)
    }

    pub async fn update_goat_tx_record_processing_status(
        &mut self,
        graph_id: &Uuid,
        instance_id: &Uuid,
        tx_type: &str,
        status: &str,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            "UPDATE goat_tx_record
             SET processing_status = ?
             where instance_id = ?
               AND graph_id = ?
               AND tx_type = ?",
            status,
            instance_id,
            graph_id,
            tx_type
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn upsert_graph_btc_tx_vout_monitor(
        &mut self,
        monitor: &GraphBtcTxVoutMonitor,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();

        let res = sqlx::query!(
            r#"
            INSERT OR REPLACE INTO graph_btc_tx_vout_monitor
            (graph_id, tx_name, txid, height, vout_len, monitor_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            monitor.graph_id,
            monitor.tx_name,
            monitor.txid,
            monitor.height,
            monitor.vout_len,
            monitor.monitor_data,
            monitor.created_at,
            current_time
        )
        .execute(self.conn())
        .await?;

        Ok(res.rows_affected())
    }

    pub async fn find_graph_btc_tx_vout_monitor(
        &mut self,
        graph_id: &Uuid,
        txid: &SerializableTxid,
    ) -> anyhow::Result<Option<GraphBtcTxVoutMonitor>> {
        let row = sqlx::query_as!(
            GraphBtcTxVoutMonitor,
            r#"
            SELECT
                graph_id AS "graph_id: Uuid",
                tx_name,
                txid AS "txid: SerializableTxid",
                height,
                vout_len,
                monitor_data,
                created_at,
                updated_at
            FROM graph_btc_tx_vout_monitor
            WHERE graph_id = ? AND txid = ?
            "#,
            graph_id,
            txid
        )
        .fetch_optional(self.conn())
        .await?;

        Ok(row)
    }

    pub async fn upsert_bridge_out_global_stats(
        &mut self,
        bridge_out_stats: &BridgeOutGlobalStats,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"INSERT INTO bridge_out_global_stats (id, initial_txn, initial_amount, claim_txn, claim_amount, refund_txn,
                                                   refund_amount,updated_at, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT (id) DO UPDATE SET initial_txn    = excluded.initial_txn,
                                             initial_amount = excluded.initial_amount,
                                             claim_txn      = excluded.claim_txn,
                                             claim_amount   = excluded.claim_amount,
                                             refund_txn     = excluded.refund_txn,
                                             refund_amount  = excluded.refund_amount,
                                             updated_at     = excluded.updated_at"#,
            bridge_out_stats.id,
            bridge_out_stats.initial_txn,
            bridge_out_stats.initial_amount,
            bridge_out_stats.claim_txn,
            bridge_out_stats.claim_amount,
            bridge_out_stats.refund_txn,
            bridge_out_stats.refund_amount,
            bridge_out_stats.updated_at,
            bridge_out_stats.created_at,
        ).execute(self.conn())
            .await?;
        Ok(())
    }
    pub async fn find_bridge_out_global_stats_by_id(
        &mut self,
        id: i64,
    ) -> anyhow::Result<Option<BridgeOutGlobalStats>> {
        let res = sqlx::query_as!(
            BridgeOutGlobalStats,
            r#"SELECT * from bridge_out_global_stats WHERE id = ?"#,
            id
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn upsert_sequencer_set_hash_change(
        &mut self,
        cosmos_block_height: i64,
        goat_block_height: i64,
        validators_hash: &str,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query(
            r#"INSERT INTO sequencer_set_hash_changes (cosmos_block_height, goat_block_height, validators_hash, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (cosmos_block_height) DO UPDATE
               SET goat_block_height = excluded.goat_block_height,
                   validators_hash = excluded.validators_hash,
                   updated_at = excluded.updated_at"#,
        )
        .bind(cosmos_block_height)
        .bind(goat_block_height)
        .bind(validators_hash)
        .bind(current_time)
        .bind(current_time)
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn find_latest_sequencer_set_hash_change(
        &mut self,
    ) -> anyhow::Result<Option<SequencerSetHashChange>> {
        let res = sqlx::query_as::<_, SequencerSetHashChange>(
            "SELECT * FROM sequencer_set_hash_changes ORDER BY cosmos_block_height DESC LIMIT 1",
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn find_first_sequencer_set_hash_change_by_goat_block_at_or_before(
        &mut self,
        goat_block_height: i64,
    ) -> anyhow::Result<Option<SequencerSetHashChange>> {
        let res = sqlx::query_as::<_, SequencerSetHashChange>(
            "SELECT * FROM sequencer_set_hash_changes WHERE goat_block_height <= ? ORDER BY goat_block_height DESC LIMIT 1",
        )
        .bind(goat_block_height)
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn get_sequencer_set_scan_state(
        &mut self,
    ) -> anyhow::Result<Option<SequencerSetScanState>> {
        let res = sqlx::query_as::<_, SequencerSetScanState>(
            "SELECT * FROM sequencer_set_scan_state WHERE id = 1 LIMIT 1",
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn upsert_sequencer_set_scan_state(
        &mut self,
        next_cosmos_block_height: i64,
        latest_goat_block_height: i64,
        latest_validators_hash: &str,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query(
            r#"INSERT INTO sequencer_set_scan_state (id, next_cosmos_block_height, latest_goat_block_height, latest_validators_hash, created_at, updated_at)
               VALUES (1, ?, ?, ?, ?, ?)
               ON CONFLICT (id) DO UPDATE
               SET next_cosmos_block_height = excluded.next_cosmos_block_height,
                   latest_goat_block_height = excluded.latest_goat_block_height,
                   latest_validators_hash = excluded.latest_validators_hash,
                   updated_at = excluded.updated_at"#,
        )
        .bind(next_cosmos_block_height)
        .bind(latest_goat_block_height)
        .bind(latest_validators_hash)
        .bind(current_time)
        .bind(current_time)
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }
}

// fn truncate_string(s: &str, max_len: usize) -> &str {
//     if s.len() > max_len { &s[..max_len] } else { s }
// }

pub async fn create_local_db(db_path: &str) -> LocalDB {
    create_local_db_with_busy_timeout(db_path, DEFAULT_BUSY_TIMEOUT).await
}

pub async fn create_local_db_with_busy_timeout(db_path: &str, busy_timeout: Duration) -> LocalDB {
    // Only in-memory databases skip WAL; a file-backed node needs its readers
    // to proceed while the engine holds the write lock.
    let is_mem = db_path.contains(":memory:");
    let local_db = LocalDB::new_with_busy_timeout(db_path, is_mem, busy_timeout).await;
    local_db.migrate().await;
    local_db
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_db() -> LocalDB {
        create_local_db("sqlite::memory:").await
    }

    fn pegin_instance(instance_id: Uuid, status: &str) -> Instance {
        Instance {
            instance_id,
            network: "testnet".to_string(),
            input_utxos: "[]".to_string(),
            status: status.to_string(),
            created_at: 100,
            updated_at: 100,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_upsert_pegin_request_instance_refreshes_a_waiting_row() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let instance_id = Uuid::new_v4();

        let mut initing = pegin_instance(instance_id, "UserInited");
        initing.to_addr = "0xuser".to_string();
        initing.from_addr = "bcrt1quser".to_string();
        assert!(s.insert_instance_if_absent(&initing).await.unwrap());

        let mut request = pegin_instance(instance_id, "UserInited");
        request.to_addr = "0xuser".to_string();
        request.amount = 10_000;
        request.goat_tx_hash = "0xrequest".to_string();
        request.goat_tx_height = 500;
        request.status_updated_at = 200;
        request.created_at = 999;
        request.updated_at = 999;
        assert!(s.upsert_pegin_request_instance(&request).await.unwrap());

        let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(stored.status, "UserInited");
        assert_eq!(stored.amount, 10_000);
        assert_eq!(stored.goat_tx_hash, "0xrequest");
        assert_eq!(stored.goat_tx_height, 500);
        assert_eq!(stored.status_updated_at, 200);
        // An undecodable from_addr must not erase the one the request tag stored.
        assert_eq!(stored.from_addr, "bcrt1quser");
        // created_at belongs to whoever created the row.
        assert_eq!(stored.created_at, 100);
    }

    #[tokio::test]
    async fn test_upsert_pegin_request_instance_replay_keeps_accrued_state() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let instance_id = Uuid::new_v4();

        let mut inited = pegin_instance(instance_id, "UserInited");
        inited.goat_tx_hash = "0xrequest".to_string();
        inited.goat_tx_height = 500;
        inited.committees_answers = IndexMap::from([("0xcommittee".to_string(), vec![1u8, 2, 3])]);
        inited.parameters = Some("{}".to_string());
        assert!(s.insert_instance_if_absent(&inited).await.unwrap());

        // A re-delivered request refreshes the row in place; everything the
        // instance accrued after the request must survive it.
        let mut replay = pegin_instance(instance_id, "UserInited");
        replay.goat_tx_hash = "0xrequest".to_string();
        replay.goat_tx_height = 500;
        assert!(s.upsert_pegin_request_instance(&replay).await.unwrap());
        let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(stored.committees_answers.get("0xcommittee"), Some(&vec![1u8, 2, 3]));
        assert_eq!(stored.parameters, Some("{}".to_string()));
        assert_eq!(stored.goat_tx_height, 500);
    }

    #[tokio::test]
    async fn test_upsert_pegin_request_instance_rejects_regression() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let instance_id = Uuid::new_v4();

        let mut minted = pegin_instance(instance_id, "RelayerL2Minted");
        minted.goat_tx_hash = "0xrequest".to_string();
        minted.goat_tx_height = 500;
        minted.parameters = Some("{}".to_string());
        minted.post_pegin_txhash = Some("0xmint".to_string());
        assert!(s.insert_instance_if_absent(&minted).await.unwrap());

        // Once the instance moves on, a re-delivered request may not pull it back.
        let replay = pegin_instance(instance_id, "UserInited");
        assert!(!s.upsert_pegin_request_instance(&replay).await.unwrap());
        let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(stored.status, "RelayerL2Minted");
        assert_eq!(stored.parameters, Some("{}".to_string()));
        assert_eq!(stored.post_pegin_txhash, Some("0xmint".to_string()));
        assert_eq!(stored.goat_tx_height, 500);
    }

    #[tokio::test]
    async fn test_upsert_pegin_request_instance_rejects_progressed_instance() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let instance_id = Uuid::new_v4();

        let progressed = pegin_instance(instance_id, "CommitteesAnswered");
        assert!(s.insert_instance_if_absent(&progressed).await.unwrap());

        let request = pegin_instance(instance_id, "UserInited");
        assert!(!s.upsert_pegin_request_instance(&request).await.unwrap());
        let stored = s.find_instance(&instance_id).await.unwrap().unwrap();
        assert_eq!(stored.status, "CommitteesAnswered");
    }

    #[tokio::test]
    async fn test_instance_update_rejects_stale_status_transition() {
        let db = setup_db().await;
        let instance_id = Uuid::new_v4();
        let mut storage = db.acquire().await.unwrap();
        assert!(
            storage
                .insert_instance_if_absent(&pegin_instance(instance_id, "RelayerL2Minted"))
                .await
                .unwrap()
        );

        let updated = storage
            .update_instance(
                &InstanceUpdate::new_with_instance_id(instance_id)
                    .with_status("Timeout".to_string())
                    .with_only_if_status_in(vec!["Presigned".to_string()]),
            )
            .await
            .unwrap();
        assert!(!updated);
        assert_eq!(
            storage.find_instance(&instance_id).await.unwrap().unwrap().status,
            "RelayerL2Minted"
        );
    }

    #[tokio::test]
    async fn test_node_metrics_state_counts() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        sqlx::query(
            "INSERT INTO instance (instance_id, status, created_at, updated_at) VALUES ('in-1', 'Pending', 20, 20), ('in-2', 'Pending', 10, 10)",
        )
        .execute(s.conn())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO swap_escrow (escrow_hash, status, created_at, updated_at) VALUES ('0xaa', 'Initialize', 30, 30)",
        )
        .execute(s.conn())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO graph (graph_id, instance_id, status, kickoff_index, created_at, updated_at) VALUES ('graph-1', 'in-1', 'Created', 0, 40, 40), ('graph-2', 'in-2', 'Created', 1, 25, 25)",
        )
        .execute(s.conn())
        .await
        .unwrap();

        let counts = s.node_metrics_state_counts().await.unwrap();
        assert_eq!(
            counts.iter().find(|count| count.category == "instance" && count.state == "Pending"),
            Some(&MetricsStateCount {
                category: "instance".to_string(),
                state: "Pending".to_string(),
                count: 2,
                oldest_created_at: Some(10),
                last_success_at: None,
            })
        );
        assert_eq!(
            counts
                .iter()
                .find(|count| count.category == "swap_escrow" && count.state == "Initialize")
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            counts
                .iter()
                .find(|count| count.category == "graph" && count.state == "Created")
                .unwrap()
                .oldest_created_at,
            Some(25)
        );
        assert!(counts.iter().all(|count| {
            matches!(count.category.as_str(), "instance" | "swap_escrow" | "graph")
        }));
    }

    /// Verify confirmed operator bindings are loaded before unconfirmed identities.
    #[tokio::test]
    async fn confirmed_operator_bindings_are_loaded_first() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let operator = |peer_id: &str, updated_at: i64| Node {
            peer_id: peer_id.to_string(),
            actor: "Operator".to_string(),
            btc_pub_key: format!("key-of-{peer_id}"),
            binding_sig: "sig".to_string(),
            binding_issued_at: 1,
            updated_at,
            created_at: updated_at,
            ..Default::default()
        };
        s.upsert_node(&operator("confirmed", 10)).await.unwrap();
        for index in 0..4 {
            s.upsert_node(&operator(&format!("recent-{index}"), 900 + index)).await.unwrap();
        }
        // Not an operator, and an operator without a binding: never loaded.
        s.upsert_node(&Node { actor: "Committee".to_string(), ..operator("member", 999) })
            .await
            .unwrap();
        s.upsert_node(&Node { binding_sig: String::new(), ..operator("unbound", 999) })
            .await
            .unwrap();
        s.upsert_p2p_registered_peer("confirmed", "Operator", "aa").await.unwrap();

        let loaded: Vec<String> = s
            .load_p2p_peer_bindings(2)
            .await
            .unwrap()
            .into_iter()
            .map(|node| node.peer_id)
            .collect();
        assert_eq!(loaded, ["confirmed", "recent-3"]);
    }

    #[tokio::test]
    async fn registered_peers_persist_and_shield_their_node_rows() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        s.upsert_p2p_registered_peer("member", "Committee", "").await.unwrap();
        s.upsert_p2p_registered_peer("member", "Committee", "").await.unwrap();
        s.upsert_p2p_registered_peer("other-member", "Committee", "").await.unwrap();
        s.upsert_p2p_registered_peer("operator", "Operator", "aa").await.unwrap();
        let load = async |s: &mut StorageProcessor<'_>| {
            let mut peers = s.load_p2p_registered_peers().await.unwrap();
            peers.sort();
            peers
        };
        let row = |peer: &str, kind: &str, key: &str| {
            (peer.to_string(), kind.to_string(), key.to_string())
        };
        assert_eq!(
            load(&mut s).await,
            [
                row("member", "Committee", ""),
                row("operator", "Operator", "aa"),
                row("other-member", "Committee", "")
            ],
            "keyless kinds never displace each other"
        );
        // Move the key's registration to the new peer.
        s.upsert_p2p_registered_peer("operator-moved", "Operator", "aa").await.unwrap();
        // A peer confirmed for another key keeps one row, for the new key.
        s.upsert_p2p_registered_peer("operator-moved", "Operator", "bb").await.unwrap();
        assert_eq!(
            load(&mut s).await,
            [
                row("member", "Committee", ""),
                row("operator-moved", "Operator", "bb"),
                row("other-member", "Committee", "")
            ]
        );
        s.delete_p2p_registered_peer("operator-moved", "Operator").await.unwrap();
        s.delete_p2p_registered_peer("other-member", "Committee").await.unwrap();
        assert_eq!(load(&mut s).await.len(), 1);

        for (peer_id, updated_at) in [("member", 10), ("sybil", 10), ("local", 10), ("live", 900)] {
            s.upsert_node(&Node {
                peer_id: peer_id.to_string(),
                actor: "Operator".to_string(),
                updated_at,
                created_at: updated_at,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        // Only unregistered rows count toward capacity; stale rows may be evicted.
        assert!(s.node_row_admissible("sybil", 3, 0, "local").await.unwrap());
        assert!(s.node_row_admissible("newcomer", 4, 0, "local").await.unwrap());
        assert!(
            !s.node_row_admissible("newcomer", 3, 5, "local").await.unwrap(),
            "full, and every row was refreshed after the eviction horizon"
        );
        assert!(
            s.node_row_admissible("newcomer", 3, 500, "local").await.unwrap(),
            "the stalest unregistered row makes room"
        );
        let known = async |s: &mut StorageProcessor<'_>, peer_id: &str| {
            s.node_row_admissible(peer_id, 0, 0, "local").await.unwrap()
        };
        assert!(!known(&mut s, "sybil").await, "evicted: stale, unregistered, not this node");
        for kept in ["member", "local", "live"] {
            assert!(known(&mut s, kept).await, "{kept}");
        }

        s.upsert_node(&Node {
            peer_id: "left".to_string(),
            actor: "Watchtower".to_string(),
            updated_at: 20,
            created_at: 20,
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(s.purge_stale_unregistered_nodes(500, "local").await.unwrap(), 1);
        assert!(!known(&mut s, "left").await);
        assert!(known(&mut s, "member").await && known(&mut s, "local").await);
    }

    #[tokio::test]
    async fn test_upsert_and_find_latest_hash_change() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        s.upsert_sequencer_set_hash_change(100, 1000, "aabbcc").await.unwrap();
        s.upsert_sequencer_set_hash_change(200, 2000, "ddeeff").await.unwrap();
        s.upsert_sequencer_set_hash_change(150, 1500, "112233").await.unwrap();

        let latest = s.find_latest_sequencer_set_hash_change().await.unwrap().unwrap();
        assert_eq!(latest.cosmos_block_height, 200);
        assert_eq!(latest.goat_block_height, 2000);
        assert_eq!(latest.validators_hash, "ddeeff");
    }

    #[tokio::test]
    async fn test_upsert_hash_change_conflict() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        s.upsert_sequencer_set_hash_change(100, 1000, "aabbcc").await.unwrap();
        // Same cosmos_block_height, different data — should overwrite
        s.upsert_sequencer_set_hash_change(100, 1001, "ddeeff").await.unwrap();

        let latest = s.find_latest_sequencer_set_hash_change().await.unwrap().unwrap();
        assert_eq!(latest.cosmos_block_height, 100);
        assert_eq!(latest.goat_block_height, 1001);
        assert_eq!(latest.validators_hash, "ddeeff");
    }

    #[tokio::test]
    async fn test_find_by_goat_block_at_or_before() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        s.upsert_sequencer_set_hash_change(100, 1000, "aa").await.unwrap();
        s.upsert_sequencer_set_hash_change(200, 2000, "bb").await.unwrap();
        s.upsert_sequencer_set_hash_change(300, 3000, "cc").await.unwrap();

        // Exact match
        let r = s
            .find_first_sequencer_set_hash_change_by_goat_block_at_or_before(2000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.goat_block_height, 2000);
        assert_eq!(r.validators_hash, "bb");

        // Between records — should return previous one
        let r = s
            .find_first_sequencer_set_hash_change_by_goat_block_at_or_before(2500)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.goat_block_height, 2000);
        assert_eq!(r.validators_hash, "bb");

        // Before all records — should return None
        let r =
            s.find_first_sequencer_set_hash_change_by_goat_block_at_or_before(500).await.unwrap();
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn test_scan_state_upsert_and_get() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        assert!(s.get_sequencer_set_scan_state().await.unwrap().is_none());

        s.upsert_sequencer_set_scan_state(100, 1000, "aabbcc").await.unwrap();
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 100);
        assert_eq!(state.latest_goat_block_height, 1000);
        assert_eq!(state.latest_validators_hash, "aabbcc");

        // Update
        s.upsert_sequencer_set_scan_state(200, 2000, "ddeeff").await.unwrap();
        let state = s.get_sequencer_set_scan_state().await.unwrap().unwrap();
        assert_eq!(state.next_cosmos_block_height, 200);
        assert_eq!(state.latest_validators_hash, "ddeeff");
    }
}
