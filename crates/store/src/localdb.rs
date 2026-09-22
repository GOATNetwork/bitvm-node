use crate::utils::{QueryBuilder, QueryParam, create_place_holders};
use crate::{
    BridgeOutGlobalStats, EventWatchMetricsSnapshot, GoatTxRecord, Graph, GraphBtcTxVoutMonitor,
    GraphRawData, GraphStatus, GraphStatusSource, GraphStatusTransitionOutcome, Instance,
    LongRunningTaskProof, Message, MessageDebugOverview, MessageDebugReason, MetricsStateCount,
    Node, NodeAlertMetricsSnapshot, NodesOverview, OperatorProof, P2pInboxAdmissionClass,
    P2pInboxClassUsage, P2pInboxMessage, P2pOutboxMessage, PeginGraphProcessData,
    PeginInstanceProcessData, PendingGraphInit, SequencerSetHashChange, SequencerSetScanState,
    SerializableTxid, SwapEscrow, SwapEscrowStatus, WatchContract, WatchtowerProof,
};

use indexmap::IndexMap;
use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteRow};
use sqlx::types::Uuid;
use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

fn get_current_timestamp_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Columns every `message` SELECT must fetch.
const MESSAGE_COLUMNS: &str = "message_id, business_id, from_peer, actor, msg_type, content, \
     message_version, state, weight, lock_time_until, attempt_count, abandon_count, last_error, \
     created_at";

/// Columns every `p2p_inbox` SELECT must fetch.
const P2P_INBOX_COLUMNS: &str = "message_id, business_id, actor, from_peer, msg_type, content, \
     content_size, state, attempt_count, abandon_count, next_retry_at, lease_until, lease_token, \
     last_error, admission_class, content_hash, created_at, updated_at";

fn message_from_row(row: &SqliteRow) -> Result<Message, sqlx::Error> {
    Ok(Message {
        message_id: row.try_get("message_id")?,
        business_id: row.try_get("business_id")?,
        actor: row.try_get("actor")?,
        from_peer: row.try_get("from_peer")?,
        msg_type: row.try_get("msg_type")?,
        content: row.try_get("content")?,
        state: row.try_get("state")?,
        message_version: row.try_get("message_version")?,
        weight: row.try_get("weight")?,
        lock_time_until: row.try_get("lock_time_until")?,
        attempt_count: row.try_get("attempt_count")?,
        abandon_count: row.try_get("abandon_count")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
    })
}

fn p2p_inbox_message_from_row(row: &SqliteRow) -> Result<P2pInboxMessage, sqlx::Error> {
    Ok(P2pInboxMessage {
        message_id: row.try_get("message_id")?,
        business_id: row.try_get("business_id")?,
        actor: row.try_get("actor")?,
        from_peer: row.try_get("from_peer")?,
        msg_type: row.try_get("msg_type")?,
        content: row.try_get("content")?,
        content_size: row.try_get("content_size")?,
        state: row.try_get("state")?,
        attempt_count: row.try_get("attempt_count")?,
        abandon_count: row.try_get("abandon_count")?,
        next_retry_at: row.try_get("next_retry_at")?,
        lease_until: row.try_get("lease_until")?,
        lease_token: row.try_get("lease_token")?,
        last_error: row.try_get("last_error")?,
        admission_class: row.try_get("admission_class")?,
        content_hash: row.try_get("content_hash")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn p2p_outbox_message_from_row(row: &SqliteRow) -> Result<P2pOutboxMessage, sqlx::Error> {
    Ok(P2pOutboxMessage {
        message_id: row.try_get("message_id")?,
        msg_type: row.try_get("msg_type")?,
        content: row.try_get("content")?,
        state: row.try_get("state")?,
        attempt_count: row.try_get("attempt_count")?,
        next_retry_at: row.try_get("next_retry_at")?,
        lease_until: row.try_get("lease_until")?,
        last_error: row.try_get("last_error")?,
        retry_until: row.try_get("retry_until")?,
        retry_interval_secs: row.try_get("retry_interval_secs")?,
        ack_peer_id: row.try_get("ack_peer_id")?,
        publish_count: row.try_get("publish_count")?,
        created_at: row.try_get("created_at")?,
    })
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

#[derive(Clone, Debug, Default)]
pub struct MessageQueueStats {
    pub pending_ready: i64,
    pub pending_locked: i64,
    pub failed: i64,
    pub oldest_pending_at: Option<i64>,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
impl LocalDB {
    pub async fn new(path: &str, is_mem: bool) -> LocalDB {
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

        let mut options = SqliteConnectOptions::from_str(path).unwrap().create_if_missing(true);
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

    pub fn with_earliest_updated(mut self, earliest_updated: i64) -> Self {
        self.earliest_updated = Some(earliest_updated);
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

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
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

    pub fn with_raw_conditions(mut self, raw_conditions: Vec<String>) -> Self {
        self.raw_conditions = raw_conditions;
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
            only_if_status_in: None,
        }
    }

    /// Set from_addr
    pub fn with_from_addr(mut self, from_addr: String) -> Self {
        self.from_addr = Some(from_addr);
        self
    }

    /// Set to_addr
    pub fn with_to_addr(mut self, to_addr: String) -> Self {
        self.to_addr = Some(to_addr);
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

    pub fn with_claimer_addr(mut self, claimer_addr: String) -> Self {
        self.claimer_addr = Some(claimer_addr);
        self
    }

    pub fn with_btc_addr(mut self, btc_addr: String) -> Self {
        self.btc_addr = Some(btc_addr);
        self
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub fn with_amount(mut self, amount: String) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn with_refund_deadline(mut self, refund_deadline: i64) -> Self {
        self.refund_deadline = Some(refund_deadline);
        self
    }

    pub fn with_escrow_data(mut self, escrow_data: String) -> Self {
        self.escrow_data = Some(escrow_data);
        self
    }

    pub fn with_init_tx(mut self, tx_hash: String, tx_height: i64) -> Self {
        self.init_tx_hash = Some(tx_hash);
        self.init_tx_height = Some(tx_height);
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

    pub fn with_raw_conditions(mut self, raw_conditions: Vec<String>) -> Self {
        self.raw_conditions = raw_conditions;
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

    pub fn with_graph_id(mut self, graph_id: String) -> Self {
        self.graph_id = Some(graph_id);
        self
    }

    pub fn with_pegin_txid(mut self, pegin_txid: SerializableTxid) -> Self {
        self.pegin_txid = Some(pegin_txid);
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

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
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

    pub fn with_time_threshold(mut self, time_threshold: i64, is_in_time_threshold: bool) -> Self {
        self.time_threshold = Some(time_threshold);
        self.is_in_time_threshold = is_in_time_threshold;
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

    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
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
            UNION ALL
            SELECT
                'message' AS category,
                state,
                COUNT(*) AS count,
                MIN(created_at) AS oldest_created_at,
                NULL AS last_success_at
            FROM message
            GROUP BY state
            UNION ALL
            SELECT
                'p2p_inbox' AS category,
                state,
                COUNT(*) AS count,
                MIN(created_at) AS oldest_created_at,
                NULL AS last_success_at
            FROM p2p_inbox
            GROUP BY state
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

    /// Returns grouped proof task counts, ages, and latest success times for Proof Builder metrics.
    pub async fn proof_metrics_state_counts(&mut self) -> anyhow::Result<Vec<MetricsStateCount>> {
        let counts = sqlx::query_as::<_, MetricsStateCount>(
            r#"
            SELECT
                chain_name AS category,
                CAST(proof_state AS TEXT) AS state,
                COUNT(*) AS count,
                MIN(CASE WHEN proof_state IN (0, 1) THEN created_at END) AS oldest_created_at,
                MAX(CASE WHEN proof_state = 2 THEN updated_at END) AS last_success_at
            FROM long_running_task_proof
            GROUP BY chain_name, proof_state
            UNION ALL
            SELECT
                'operator' AS category,
                CAST(proof_state AS TEXT) AS state,
                COUNT(*) AS count,
                MIN(CASE WHEN proof_state IN (0, 1) THEN created_at END) AS oldest_created_at,
                MAX(CASE WHEN proof_state = 2 THEN updated_at END) AS last_success_at
            FROM operator_proof
            GROUP BY proof_state
            UNION ALL
            SELECT
                'watchtower' AS category,
                CAST(proof_state AS TEXT) AS state,
                COUNT(*) AS count,
                MIN(CASE WHEN proof_state IN (0, 1) THEN created_at END) AS oldest_created_at,
                MAX(CASE WHEN proof_state = 2 THEN updated_at END) AS last_success_at
            FROM watchtower_proof
            GROUP BY proof_state
            ORDER BY category, state
            "#,
        )
        .fetch_all(self.conn())
        .await?;
        Ok(counts)
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
    /// `PeginRequest` is a re-deliverable P2P message, so a full-row replacement
    /// would let a replayed or forged request roll a live instance back to its
    /// initial row and clear everything the later stages wrote. The write is
    /// therefore a compare-and-swap over the current status, and it only touches
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
        allowed_statuses: &[String],
    ) -> anyhow::Result<bool> {
        let committees_answers_json = serde_json::to_string(&instance.committees_answers)?;
        // An empty allow-list must reject the update rather than silently
        // dropping the compare-and-swap guard.
        let status_guard = if allowed_statuses.is_empty() {
            "1 = 0".to_string()
        } else {
            let placeholders = allowed_statuses.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            format!("instance.status IN ({placeholders})")
        };
        let sql = format!(
            "INSERT INTO instance \
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
             WHERE {status_guard}"
        );
        let mut query = sqlx::query(&sql)
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
            .bind(instance.updated_at);
        for status in allowed_statuses {
            query = query.bind(status);
        }
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

    /// Update expired instances status
    ///
    /// Updates the status of instances that have expired based on a time threshold.
    /// This is typically used for cleanup operations to mark old instances as expired.
    ///
    /// Parameters:
    /// - current_status: The current status to match for instances to be updated
    /// - expired_status: The new status to set for expired instances
    /// - time_threshold: Timestamp threshold - instances updated before this time will be marked as expired
    ///
    /// Returns:
    /// - Ok(affected_rows) number of instances that were updated
    /// - Err if the update operation failed
    pub async fn update_expired_instance(
        &mut self,
        current_status: &str,
        expired_status: &str,
        time_threshold: i64,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let row = sqlx::query!(
            r#"UPDATE instance SET status = ?, status_updated_at = ?, updated_at = ?  WHERE status = ? AND updated_at < ?"#,
            expired_status,
            current_time,
            current_time,
            current_status,
            time_threshold
        )
            .execute(self.conn())
            .await?;
        Ok(row.rows_affected())
    }

    /// Transition an instance only when it is still in the expected status.
    pub async fn update_instance_status_if_current(
        &mut self,
        instance_id: &Uuid,
        current_status: &str,
        new_status: &str,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let result = sqlx::query!(
            "UPDATE instance SET status = ?, status_updated_at = ?, updated_at = ? \
             WHERE instance_id = ? AND status = ?",
            new_status,
            current_time,
            current_time,
            instance_id,
            current_status,
        )
        .execute(self.conn())
        .await?;

        Ok(result.rows_affected() > 0)
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

    pub async fn find_graphs_by_status_group_by_operator(
        &mut self,
        status: &str,
    ) -> anyhow::Result<Vec<Graph>> {
        let row = sqlx::query_as::<_, Graph>(
            "SELECT *
             FROM graph
             WHERE status = ? ORDER BY  operator_pubkey,  kickoff_index",
        )
        .bind(status)
        .fetch_all(self.conn())
        .await?;
        Ok(row)
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

    pub async fn get_graph_pre_kickoff_chain_by_cur_pre_kickoff(
        &mut self,
        current_pre_kickoff: SerializableTxid,
    ) -> anyhow::Result<Option<(Uuid, Uuid, SerializableTxid, SerializableTxid)>> {
        #[derive(sqlx::FromRow)]
        struct NextPrekickoffRow {
            pub graph_id: Uuid,
            pub instance_id: Uuid,
            pub cur_prekickoff_txid: SerializableTxid,
            pub next_prekickoff: SerializableTxid,
        }
        let res = sqlx::query_as::<_, NextPrekickoffRow>(
            "SELECT graph_id,  instance_id,  cur_prekickoff_txid, next_prekickoff FROM graph WHERE cur_prekickoff_txid  = ?",
        )
            .bind(current_pre_kickoff)
            .fetch_optional(self.conn())
            .await?;
        Ok(res.map(|v| (v.graph_id, v.instance_id, v.cur_prekickoff_txid, v.next_prekickoff)))
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

    /// Complete the exact local queue claim handed to a worker.
    pub async fn complete_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
    ) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query(
            "UPDATE message \
             SET state = 'Processed', content = X'', lock_time_until = 0, \
                 abandon_count = 0, last_error = NULL, updated_at = ? \
             WHERE message_id = ? AND message_version = ? AND state = 'Processing'",
        )
        .bind(current_time)
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;

        Ok(res.rows_affected() > 0)
    }

    /// Cancel queued local work for a business object, including work which has
    /// already been claimed. Claim completion/defer writes require `Processing`,
    /// so an in-flight worker cannot overwrite the terminal cancellation.
    pub async fn cancel_messages_by_business_id(
        &mut self,
        business_id: &Uuid,
        msg_type: Option<String>,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = match msg_type {
            Some(msg_type) => {
                sqlx::query(
                    "UPDATE message \
                     SET state = 'Cancelled', lock_time_until = 0, updated_at = ? \
                     WHERE business_id = ? AND msg_type = ? \
                       AND state IN ('Pending', 'Processing')",
                )
                .bind(current_time)
                .bind(business_id)
                .bind(msg_type)
                .execute(self.conn())
                .await?
            }
            None => {
                sqlx::query(
                    "UPDATE message \
                     SET state = 'Cancelled', lock_time_until = 0, updated_at = ? \
                     WHERE business_id = ? AND state IN ('Pending', 'Processing')",
                )
                .bind(current_time)
                .bind(business_id)
                .execute(self.conn())
                .await?
            }
        };
        Ok(res.rows_affected())
    }

    pub async fn set_messages_expired(&mut self, expired: i64) -> anyhow::Result<()> {
        sqlx::query!(
            r#"UPDATE message
             SET state = 'Expired'
             WHERE state IN ('Pending', 'Processing')
               AND updated_at < ?"#,
            expired
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn delete_old_messages(&mut self, expired: i64) -> anyhow::Result<()> {
        sqlx::query!(r#"DELETE FROM message WHERE  updated_at < ?"#, expired)
            .execute(self.conn())
            .await?;
        Ok(())
    }

    pub async fn find_message_by_business_id(
        &mut self,
        business_id: &Uuid,
        msg_type: &str,
    ) -> anyhow::Result<Option<Message>> {
        let row = sqlx::query(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM message WHERE business_id = ? AND msg_type = ?"
        ))
        .bind(business_id)
        .bind(msg_type)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| message_from_row(&row)).transpose()?)
    }
    pub async fn find_messages_by_id(
        &mut self,
        message_id: &str,
    ) -> anyhow::Result<Option<Message>> {
        let row =
            sqlx::query(&format!("SELECT {MESSAGE_COLUMNS} FROM message WHERE message_id = ?"))
                .bind(message_id)
                .fetch_optional(self.conn())
                .await?;
        Ok(row.map(|row| message_from_row(&row)).transpose()?)
    }

    /// Retire local messages whose claims keep failing to report an outcome.
    ///
    /// A surviving `message` row makes the producer treat the work as already
    /// created, so retiring on repeated handler errors would strand it until the
    /// reaper; repeated abandons mean the node went down mid-dispatch on this
    /// payload, which retrying cannot fix.
    pub async fn quarantine_local_messages(
        &mut self,
        now: i64,
        max_abandons: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Quarantined', \
                 abandon_count = abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END, \
                 lock_time_until = 0, \
                 last_error = ?, updated_at = ? \
             WHERE state IN ('Pending', 'Processing') \
               AND lock_time_until <= ? \
               AND abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END >= ?",
        )
        .bind(format!("quarantined: exceeded max abandoned claims ({max_abandons})"))
        .bind(now)
        .bind(now)
        .bind(max_abandons)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Rows the local dispatcher may attempt right now, oldest first.
    ///
    /// Nothing is written here: the dispatcher claims each row with
    /// [`Self::claim_local_message`] immediately before dispatching it. Claiming
    /// a whole batch up front meant that an abort or kill mid-dispatch charged
    /// an unfinished attempt to every row in the batch, so healthy messages
    /// followed the poison message into quarantine.
    pub async fn list_claimable_local_messages(
        &mut self,
        now: i64,
        expired: i64,
        limit: i64,
        max_abandons: i64,
    ) -> anyhow::Result<Vec<Message>> {
        let rows = sqlx::query(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM message \
             WHERE state IN ('Pending', 'Processing') \
               AND lock_time_until <= ? \
               AND updated_at >= ? \
               AND abandon_count < ? \
             ORDER BY created_at ASC \
             LIMIT ?"
        ))
        .bind(now)
        .bind(expired)
        .bind(max_abandons)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        rows.iter().map(message_from_row).collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Claim exactly one local message for dispatch.
    ///
    /// Without a durable claim, a handler that panicked left the row `Pending`
    /// with its lock untouched, so the very next tick re-read it and panicked
    /// again with no backoff at all. Charging the claim before dispatch means
    /// the record survives an abort or a kill, not just an unwinding panic.
    ///
    /// Re-claiming a row that is still `Processing` means the previous attempt
    /// never reported an outcome, which is charged as an abandon.
    /// `message_version` is deliberately left alone: callers guard their
    /// completion writes with the version they were handed, and bumping it here
    /// would make every one of those writes miss. Returns `None` when the row
    /// is no longer claimable: cancelled, re-armed under a new version, or
    /// locked since it was listed.
    pub async fn claim_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
        now: i64,
        lease_until: i64,
    ) -> anyhow::Result<Option<Message>> {
        let row = sqlx::query(&format!(
            "UPDATE message \
             SET state = 'Processing', \
                 abandon_count = abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END, \
                 lock_time_until = ?, updated_at = ? \
             WHERE message_id = ? AND message_version = ? \
               AND state IN ('Pending', 'Processing') \
               AND lock_time_until <= ? \
             RETURNING {MESSAGE_COLUMNS}"
        ))
        .bind(lease_until)
        .bind(now)
        .bind(message_id)
        .bind(message_version)
        .bind(now)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| message_from_row(&row)).transpose()?)
    }

    /// List and claim up to `limit` rows in one call.
    ///
    /// Production dispatchers claim one row at a time; this convenience exists
    /// for tests and tooling that need a whole batch held under a lease.
    pub async fn claim_local_messages(
        &mut self,
        now: i64,
        lease_until: i64,
        expired: i64,
        limit: i64,
        max_abandons: i64,
    ) -> anyhow::Result<Vec<Message>> {
        let candidates =
            self.list_claimable_local_messages(now, expired, limit, max_abandons).await?;
        let mut claimed = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if let Some(message) = self
                .claim_local_message(
                    &candidate.message_id,
                    candidate.message_version,
                    now,
                    lease_until,
                )
                .await?
            {
                claimed.push(message);
            }
        }
        Ok(claimed)
    }

    /// Record a failed dispatch attempt and reschedule it with backoff.
    ///
    /// `attempt_count` is observability only. Only an unfinished claim increments
    /// `abandon_count` and contributes to quarantine. This is for a handler
    /// error reported to the dispatcher, which is a completed attempt; a handler
    /// rescheduling its own row uses [`Self::self_defer_local_message`].
    pub async fn defer_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
        lock_time_until: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Pending', attempt_count = attempt_count + 1, \
                 abandon_count = 0, lock_time_until = ?, last_error = ?, updated_at = ? \
             WHERE message_id = ? AND message_version = ? AND state = 'Processing'",
        )
        .bind(lock_time_until)
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Reschedule the row a handler is currently running, at that handler's
    /// own request.
    ///
    /// Unlike [`Self::defer_local_message`], the consecutive-abandon counter is
    /// left untouched: the handler is still running and may yet panic, and
    /// resetting here let a handler that reschedules itself and then panics
    /// start every round from zero, so it never reached quarantine. The
    /// dispatcher resets the counter with
    /// [`Self::confirm_local_message_self_defer`] once the handler returned.
    pub async fn self_defer_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
        lock_time_until: i64,
        reason: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Pending', attempt_count = attempt_count + 1, \
                 lock_time_until = ?, last_error = ?, updated_at = ? \
             WHERE message_id = ? AND message_version = ? AND state = 'Processing'",
        )
        .bind(lock_time_until)
        .bind(reason.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Acknowledge a self-deferred row once its handler has returned.
    ///
    /// Only at this point is the attempt known to have reported an outcome, so
    /// only here does the consecutive-abandon counter reset. Returns `false`
    /// when the row is not `Pending` under this claim version, which means it
    /// was not self-deferred by the caller.
    pub async fn confirm_local_message_self_defer(
        &mut self,
        message_id: &str,
        message_version: i64,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE message SET abandon_count = 0, updated_at = ? \
             WHERE message_id = ? AND message_version = ? AND state = 'Pending'",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record a handler panic before shutting down the process. Unlike a normal
    /// defer, this increments the consecutive unfinished-attempt counter and
    /// pushes the next attempt out by `backoff_secs` per recorded abandon, so a
    /// supervisor restart cannot replay the payload at full speed.
    ///
    /// A handler may reschedule its own row and then panic, leaving the row
    /// `Pending` already. The version guard still identifies the claim, so the
    /// abandon is charged either way and the longer of the two delays wins.
    pub async fn abandon_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
        now: i64,
        backoff_secs: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Pending', abandon_count = abandon_count + 1, \
                 lock_time_until = MAX(lock_time_until, ? + ? * (abandon_count + 1)), \
                 last_error = ?, updated_at = ? \
             WHERE message_id = ? AND message_version = ? \
               AND state IN ('Processing', 'Pending')",
        )
        .bind(now)
        .bind(backoff_secs)
        .bind(error.chars().take(1024).collect::<String>())
        .bind(now)
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Terminally drop a local message whose payload the node can never process.
    pub async fn fail_local_message(
        &mut self,
        message_id: &str,
        message_version: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Failed', content = X'', lock_time_until = 0, \
                 last_error = ?, updated_at = ? \
             WHERE message_id = ? AND message_version = ? AND state = 'Processing'",
        )
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_version)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Release local claims during a graceful process shutdown. The database is
    /// process-local, so every `Processing` row belongs to this node process.
    pub async fn release_processing_local_messages(&mut self) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Pending', lock_time_until = 0, updated_at = ? \
             WHERE state = 'Processing'",
        )
        .bind(get_current_timestamp_secs())
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Startup sweep for claims left behind by a process that no longer exists.
    ///
    /// The database is process-local, so at startup every `Processing` row is
    /// an attempt that never reported an outcome. Charging it now, rather than
    /// when the lease lapses, keeps the row from sitting locked for the whole
    /// lease while every producer that touches it backs off with
    /// ResourceLocked. The same per-abandon backoff as a panic applies.
    pub async fn reclaim_processing_local_messages(
        &mut self,
        now: i64,
        backoff_secs: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE message \
             SET state = 'Pending', abandon_count = abandon_count + 1, \
                 lock_time_until = ? + ? * (abandon_count + 1), \
                 last_error = 'reclaimed at startup: previous process exited mid-dispatch', \
                 updated_at = ? \
             WHERE state = 'Processing'",
        )
        .bind(now)
        .bind(backoff_secs)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn get_message_queue_stats(
        &mut self,
        actor: &str,
        now: i64,
    ) -> anyhow::Result<MessageQueueStats> {
        let row = sqlx::query(
            r#"SELECT
                    COALESCE(SUM(CASE WHEN state = 'Pending' AND lock_time_until <= ? THEN 1 ELSE 0 END), 0) AS pending_ready,
                    COALESCE(SUM(CASE WHEN state = 'Pending' AND lock_time_until > ? THEN 1 ELSE 0 END), 0) AS pending_locked,
                    COALESCE(SUM(CASE WHEN state IN ('Failed', 'Quarantined') THEN 1 ELSE 0 END), 0) AS failed,
                    MIN(CASE WHEN state = 'Pending' THEN created_at END) AS oldest_pending_at
               FROM message
               WHERE actor = ?"#,
        )
        .bind(now)
        .bind(now)
        .bind(actor)
        .fetch_one(self.conn())
        .await?;
        Ok(MessageQueueStats {
            pending_ready: row.try_get("pending_ready")?,
            pending_locked: row.try_get("pending_locked")?,
            failed: row.try_get("failed")?,
            oldest_pending_at: row.try_get("oldest_pending_at")?,
        })
    }

    pub async fn find_message_debug_overviews(
        &mut self,
        business_id: &Uuid,
    ) -> anyhow::Result<Vec<MessageDebugOverview>> {
        Ok(sqlx::query_as::<_, MessageDebugOverview>(
            r#"SELECT m.message_id,
                      m.actor,
                      m.msg_type,
                      m.state,
                      m.lock_time_until,
                      m.created_at,
                      m.updated_at,
                      COALESCE(reason_counts.reason_count, 0) AS reason_count,
                      latest_reason.reason_code AS last_reason_code,
                      latest_reason.reason_detail AS last_reason_detail,
                      latest_reason.last_seen_at AS last_reason_seen_at
               FROM message m
               LEFT JOIN (
                    SELECT message_id, COUNT(*) AS reason_count
                    FROM message_debug_reason
                    GROUP BY message_id
               ) reason_counts ON reason_counts.message_id = m.message_id
               LEFT JOIN message_debug_reason latest_reason
                    ON latest_reason.rowid = (
                        SELECT rowid
                        FROM message_debug_reason
                        WHERE message_id = m.message_id
                        ORDER BY last_seen_at DESC, occurrences DESC, reason_code ASC
                        LIMIT 1
                    )
               WHERE m.business_id = ?
               ORDER BY m.updated_at DESC"#,
        )
        .bind(business_id)
        .fetch_all(self.conn())
        .await?)
    }

    pub async fn find_message_debug_overview(
        &mut self,
        message_id: &str,
    ) -> anyhow::Result<Option<MessageDebugOverview>> {
        Ok(sqlx::query_as::<_, MessageDebugOverview>(
            r#"SELECT m.message_id,
                      m.actor,
                      m.msg_type,
                      m.state,
                      m.lock_time_until,
                      m.created_at,
                      m.updated_at,
                      COALESCE(reason_counts.reason_count, 0) AS reason_count,
                      latest_reason.reason_code AS last_reason_code,
                      latest_reason.reason_detail AS last_reason_detail,
                      latest_reason.last_seen_at AS last_reason_seen_at
               FROM message m
               LEFT JOIN (
                    SELECT message_id, COUNT(*) AS reason_count
                    FROM message_debug_reason
                    GROUP BY message_id
               ) reason_counts ON reason_counts.message_id = m.message_id
               LEFT JOIN message_debug_reason latest_reason
                    ON latest_reason.rowid = (
                        SELECT rowid
                        FROM message_debug_reason
                        WHERE message_id = m.message_id
                        ORDER BY last_seen_at DESC, occurrences DESC, reason_code ASC
                        LIMIT 1
                    )
               WHERE m.message_id = ?"#,
        )
        .bind(message_id)
        .fetch_optional(self.conn())
        .await?)
    }

    pub async fn find_message_debug_reasons(
        &mut self,
        message_id: &str,
    ) -> anyhow::Result<Vec<MessageDebugReason>> {
        Ok(sqlx::query_as::<_, MessageDebugReason>(
            "SELECT reason_code, reason_detail, first_seen_at, last_seen_at, occurrences \
             FROM message_debug_reason WHERE message_id = ? \
             ORDER BY last_seen_at DESC, reason_code ASC",
        )
        .bind(message_id)
        .fetch_all(self.conn())
        .await?)
    }

    pub async fn upsert_message_debug_reason(
        &mut self,
        message_id: &str,
        reason_code: &str,
        reason_detail: &str,
    ) -> anyhow::Result<()> {
        let now = get_current_timestamp_secs();
        sqlx::query(
            "INSERT INTO message_debug_reason \
                (message_id, reason_code, reason_detail, first_seen_at, last_seen_at, occurrences) \
             VALUES (?, ?, ?, ?, ?, 1) \
             ON CONFLICT(message_id, reason_code, reason_detail) DO UPDATE SET \
                 last_seen_at = excluded.last_seen_at, \
                 occurrences = message_debug_reason.occurrences + 1",
        )
        .bind(message_id)
        .bind(reason_code)
        .bind(reason_detail.chars().take(512).collect::<String>())
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Insert a local message, or refresh an existing one.
    ///
    /// Terminal states are excluded so a retired row stays retired.
    /// [`Self::fail_local_message`] and [`Self::quarantine_local_messages`]
    /// both mean the payload must not run again automatically;
    /// without the exclusion a periodic producer re-upserting the same
    /// deterministic message_id would resurrect it on every tick.
    pub async fn upsert_message(&mut self, msg: Message) -> anyhow::Result<bool> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query(
            r#"INSERT INTO message (message_id, business_id, from_peer, actor, msg_type, content, state, message_version,  lock_time_until, weight, updated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(message_id)  DO UPDATE SET business_id = excluded.business_id,
                                                    from_peer = excluded.from_peer,
                                                    actor = excluded.actor,
                                                    msg_type = excluded.msg_type,
                                                    content = excluded.content,
                                                    state = excluded.state,
                                                    message_version = message.message_version + 1,
                                                    lock_time_until = excluded.lock_time_until,
                                                    weight = excluded.weight,
                                                    last_error = NULL,
                                                    updated_at = excluded.updated_at
             WHERE message.state NOT IN ('Processing', 'Cancelled', 'Failed', 'Quarantined')"#,
        )
        .bind(msg.message_id)
        .bind(msg.business_id)
        .bind(msg.from_peer)
        .bind(msg.actor)
        .bind(msg.msg_type)
        .bind(msg.content)
        .bind(msg.state)
        .bind(msg.message_version)
        .bind(msg.lock_time_until)
        .bind(msg.weight)
        .bind(current_time)
        .bind(current_time)
        .execute(self.conn())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Persist an externally received P2P message before it is dispatched.
    /// Replays of the same gossipsub message are deliberately ignored so a
    /// terminal row cannot be repopulated with its (potentially large) content.
    pub async fn insert_p2p_inbox_message(
        &mut self,
        message: &P2pInboxMessage,
    ) -> anyhow::Result<bool> {
        let now = get_current_timestamp_secs();
        let admission_class = if message.admission_class.is_empty() {
            P2pInboxAdmissionClass::Unregistered.to_string()
        } else {
            message.admission_class.clone()
        };
        let result = sqlx::query(
            "INSERT INTO p2p_inbox \
                (message_id, business_id, actor, from_peer, msg_type, content, content_size, \
                    state, attempt_count, next_retry_at, lease_until, lease_token, \
                    admission_class, content_hash, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', 0, 0, 0, '', ?, ?, ?, ?) \
             ON CONFLICT(message_id) DO NOTHING",
        )
        .bind(&message.message_id)
        .bind(message.business_id)
        .bind(&message.actor)
        .bind(&message.from_peer)
        .bind(&message.msg_type)
        .bind(&message.content)
        .bind(message.content_size)
        .bind(admission_class)
        .bind(&message.content_hash)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Test oracle for class totals and per-peer usage, including quarantined payloads.
    #[cfg(test)]
    async fn p2p_inbox_usage(
        &mut self,
        from_peer: &str,
    ) -> anyhow::Result<Vec<P2pInboxClassUsage>> {
        let rows = sqlx::query(
            "SELECT admission_class, \
                    COUNT(*) AS total_rows, \
                    COALESCE(SUM(content_size), 0) AS total_bytes, \
                    COALESCE(SUM(CASE WHEN from_peer = ? THEN 1 ELSE 0 END), 0) AS peer_rows, \
                    COALESCE(SUM(CASE WHEN from_peer = ? THEN content_size ELSE 0 END), 0) \
                        AS peer_bytes \
             FROM p2p_inbox \
             WHERE state IN ('Pending', 'Processing', 'Quarantined') \
             GROUP BY admission_class",
        )
        .bind(from_peer)
        .bind(from_peer)
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(P2pInboxClassUsage {
                    admission_class: row.try_get("admission_class")?,
                    rows: row.try_get("total_rows")?,
                    bytes: row.try_get("total_bytes")?,
                    peer_rows: row.try_get("peer_rows")?,
                    peer_bytes: row.try_get("peer_bytes")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Per-class queued payload totals, without per-peer usage.
    pub async fn p2p_inbox_class_totals(&mut self) -> anyhow::Result<Vec<P2pInboxClassUsage>> {
        let rows = sqlx::query(
            "SELECT admission_class, \
                    COUNT(*) AS total_rows, \
                    COALESCE(SUM(content_size), 0) AS total_bytes \
             FROM p2p_inbox \
             WHERE state IN ('Pending', 'Processing', 'Quarantined') \
             GROUP BY admission_class",
        )
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(P2pInboxClassUsage {
                    admission_class: row.try_get("admission_class")?,
                    rows: row.try_get("total_rows")?,
                    bytes: row.try_get("total_bytes")?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Per-peer payload usage by class; `rows` and `bytes` remain zero.
    pub async fn p2p_inbox_peer_usage(
        &mut self,
        from_peer: &str,
    ) -> anyhow::Result<Vec<P2pInboxClassUsage>> {
        let rows = sqlx::query(
            "SELECT admission_class, \
                    COUNT(*) AS peer_rows, \
                    COALESCE(SUM(content_size), 0) AS peer_bytes \
             FROM p2p_inbox \
             WHERE state IN ('Pending', 'Processing', 'Quarantined') \
               AND admission_class IN ('Committee', 'Registered', 'Unregistered') \
               AND from_peer = ? \
             GROUP BY admission_class",
        )
        .bind(from_peer)
        .fetch_all(self.conn())
        .await?;
        rows.iter()
            .map(|row| {
                Ok(P2pInboxClassUsage {
                    admission_class: row.try_get("admission_class")?,
                    peer_rows: row.try_get("peer_rows")?,
                    peer_bytes: row.try_get("peer_bytes")?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Whether the sender already has this payload in a non-terminal row.
    pub async fn has_queued_p2p_inbox_payload(
        &mut self,
        from_peer: &str,
        content_hash: &[u8],
    ) -> anyhow::Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM p2p_inbox \
             WHERE from_peer = ? AND content_hash = ? AND state IN ('Pending', 'Processing') \
             LIMIT 1",
        )
        .bind(from_peer)
        .bind(content_hash)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.is_some())
    }

    /// Expire Pending rows by `created_at`; `None` selects every admission class.
    pub async fn expire_pending_p2p_inbox_messages(
        &mut self,
        admission_class: Option<P2pInboxAdmissionClass>,
        created_before: i64,
    ) -> anyhow::Result<u64> {
        let class_predicate =
            if admission_class.is_some() { " AND admission_class = ?" } else { "" };
        let query = format!(
            "UPDATE p2p_inbox \
             SET state = 'Failed', content = X'', lease_until = 0, next_retry_at = 0, \
                 last_error = 'expired: still pending past the inbox retention window', \
                 updated_at = ? \
             WHERE state = 'Pending' AND created_at < ?{class_predicate}"
        );
        let mut query = sqlx::query(&query).bind(get_current_timestamp_secs()).bind(created_before);
        if let Some(admission_class) = admission_class {
            query = query.bind(admission_class.to_string());
        }
        Ok(query.execute(self.conn()).await?.rows_affected())
    }

    /// Move inbox rows that repeatedly abandoned a claim out of the work set.
    ///
    /// `attempt_count` remains a pure diagnostic counter. Only `abandon_count`
    /// is a poison-message signal: the claim
    /// charge is committed before dispatch, so it is recorded even when the
    /// process is aborted or killed rather than unwinding.
    ///
    /// Content is retained until the terminal-row TTL so an operator can inspect
    /// and manually requeue the message.
    pub async fn quarantine_p2p_inbox_messages(
        &mut self,
        now: i64,
        max_abandons: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Quarantined', \
                 abandon_count = abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END, \
                 lease_until = 0, next_retry_at = 0, \
                 last_error = ?, updated_at = ? \
             WHERE state IN ('Pending', 'Processing') \
               AND lease_until <= ? \
               AND abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END >= ?",
        )
        .bind(format!("quarantined: exceeded max abandoned claims ({max_abandons})"))
        .bind(now)
        .bind(now)
        .bind(max_abandons)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Inbox rows the dispatcher may attempt right now, oldest first. Nothing
    /// is written; see [`Self::list_claimable_local_messages`] for why rows are
    /// claimed one at a time instead of as a batch.
    pub async fn list_claimable_p2p_inbox_messages(
        &mut self,
        now: i64,
        limit: i64,
        max_abandons: i64,
        excluded_message_ids: &[String],
    ) -> anyhow::Result<Vec<P2pInboxMessage>> {
        self.list_claimable_p2p_inbox_messages_in(
            now,
            limit,
            0,
            max_abandons,
            excluded_message_ids,
            "",
        )
        .await
    }

    /// List each class's reserved share, then lend unused capacity in C/R/U order.
    pub async fn list_claimable_p2p_inbox_messages_by_class(
        &mut self,
        now: i64,
        limit: i64,
        registered_reserve: i64,
        unregistered_reserve: i64,
        max_abandons: i64,
        excluded_message_ids: &[String],
    ) -> anyhow::Result<Vec<P2pInboxMessage>> {
        const COMMITTEE: &str = " AND admission_class = 'Committee'";
        const REGISTERED: &str = " AND admission_class = 'Registered'";
        const UNREGISTERED: &str = " AND admission_class NOT IN ('Committee', 'Registered')";

        let limit = limit.max(0);
        let unregistered_reserve = unregistered_reserve.clamp(0, limit);
        let registered_reserve = registered_reserve.clamp(0, limit - unregistered_reserve);
        let shares = [
            (COMMITTEE, limit - registered_reserve - unregistered_reserve),
            (REGISTERED, registered_reserve),
            (UNREGISTERED, unregistered_reserve),
        ];

        // Guaranteed shares first ...
        let mut rows: [Vec<P2pInboxMessage>; 3] = Default::default();
        for (index, (class, share)) in shares.iter().enumerate() {
            rows[index] = self
                .list_claimable_p2p_inbox_messages_in(
                    now,
                    *share,
                    0,
                    max_abandons,
                    excluded_message_ids,
                    class,
                )
                .await?;
        }
        // ... then whatever a class left of its share is lent out, in priority
        // order, to the classes that have more to claim.
        for (index, (class, _)) in shares.iter().enumerate() {
            let free = limit - rows.iter().map(|rows| rows.len() as i64).sum::<i64>();
            let more = self
                .list_claimable_p2p_inbox_messages_in(
                    now,
                    free,
                    rows[index].len() as i64,
                    max_abandons,
                    excluded_message_ids,
                    class,
                )
                .await?;
            rows[index].extend(more);
        }
        Ok(rows.into_iter().flatten().collect())
    }

    async fn list_claimable_p2p_inbox_messages_in(
        &mut self,
        now: i64,
        limit: i64,
        offset: i64,
        max_abandons: i64,
        excluded_message_ids: &[String],
        class_predicate: &'static str,
    ) -> anyhow::Result<Vec<P2pInboxMessage>> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let excluded_predicate = if excluded_message_ids.is_empty() {
            String::new()
        } else {
            format!(" AND message_id NOT IN ({})", create_place_holders(excluded_message_ids))
        };
        let query = format!(
            "SELECT {P2P_INBOX_COLUMNS} \
             FROM p2p_inbox \
             WHERE ((state = 'Pending' AND next_retry_at <= ?) \
                OR (state = 'Processing' AND lease_until <= ?)) \
               AND abandon_count < ?{excluded_predicate}{class_predicate} \
             ORDER BY created_at ASC, message_id ASC \
             LIMIT ? OFFSET ?"
        );
        let mut query = sqlx::query(&query).bind(now).bind(now).bind(max_abandons);
        for message_id in excluded_message_ids {
            query = query.bind(message_id);
        }
        let rows = query.bind(limit).bind(offset).fetch_all(self.conn()).await?;
        rows.iter()
            .map(p2p_inbox_message_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Claim exactly one inbox row under a fresh lease token.
    ///
    /// Re-claiming a row that is still `Processing` means the previous attempt
    /// never reported an outcome: the worker panicked, the process died, or it
    /// hung past the lease. That is charged separately from an ordinary handler
    /// error so that a transient outage cannot push healthy messages toward
    /// quarantine. Returns `None` when the row is no longer claimable.
    pub async fn claim_p2p_inbox_message(
        &mut self,
        message_id: &str,
        now: i64,
        lease_until: i64,
    ) -> anyhow::Result<Option<P2pInboxMessage>> {
        let lease_token = Uuid::new_v4().to_string();
        let row = sqlx::query(&format!(
            "UPDATE p2p_inbox \
             SET state = 'Processing', attempt_count = attempt_count + 1, \
                 abandon_count = abandon_count + CASE WHEN state = 'Processing' THEN 1 ELSE 0 END, \
                 lease_until = ?, lease_token = ?, updated_at = ? \
             WHERE message_id = ? \
               AND ((state = 'Pending' AND next_retry_at <= ?) \
                 OR (state = 'Processing' AND lease_until <= ?)) \
             RETURNING {P2P_INBOX_COLUMNS}"
        ))
        .bind(lease_until)
        .bind(&lease_token)
        .bind(now)
        .bind(message_id)
        .bind(now)
        .bind(now)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.map(|row| p2p_inbox_message_from_row(&row)).transpose()?)
    }

    /// List and claim up to `limit` inbox rows in one call. Production
    /// dispatchers claim one row at a time; this is for tests and tooling.
    pub async fn claim_p2p_inbox_messages(
        &mut self,
        now: i64,
        lease_until: i64,
        limit: i64,
        max_abandons: i64,
        excluded_message_ids: &[String],
    ) -> anyhow::Result<Vec<P2pInboxMessage>> {
        let candidates = self
            .list_claimable_p2p_inbox_messages(now, limit, max_abandons, excluded_message_ids)
            .await?;
        let mut claimed = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if let Some(message) =
                self.claim_p2p_inbox_message(&candidate.message_id, now, lease_until).await?
            {
                claimed.push(message);
            }
        }
        Ok(claimed)
    }

    pub async fn complete_p2p_inbox_message(
        &mut self,
        message_id: &str,
        lease_token: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Processed', content = X'', lease_until = 0, next_retry_at = 0, \
                 updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn retry_p2p_inbox_message(
        &mut self,
        message_id: &str,
        lease_token: &str,
        next_retry_at: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', abandon_count = 0, lease_until = 0, \
                 next_retry_at = ?, last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(next_retry_at)
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record a panic from the current lease before terminating the process.
    /// The next attempt is pushed out by `backoff_secs` per recorded abandon so
    /// a supervisor restart cannot replay the payload at full speed.
    pub async fn abandon_p2p_inbox_message(
        &mut self,
        message_id: &str,
        lease_token: &str,
        now: i64,
        backoff_secs: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', abandon_count = abandon_count + 1, lease_until = 0, \
                 lease_token = '', next_retry_at = ? + ? * (abandon_count + 1), \
                 last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(now)
        .bind(backoff_secs)
        .bind(error.chars().take(1024).collect::<String>())
        .bind(now)
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Return claimed work to the queue without charging it as a processing
    /// attempt. This is used when capacity is unavailable before dispatch.
    pub async fn defer_p2p_inbox_message(
        &mut self,
        message_id: &str,
        lease_token: &str,
        next_retry_at: i64,
        reason: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', attempt_count = MAX(attempt_count - 1, 0), lease_until = 0, \
                 next_retry_at = ?, last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(next_retry_at)
        .bind(reason)
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn fail_p2p_inbox_message(
        &mut self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Failed', content = X'', lease_until = 0, next_retry_at = 0, \
                 last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Drop terminal inbox rows once they are older than `expired_before`.
    ///
    /// Processed/failed payloads are already released. Quarantined payloads are
    /// retained only for this bounded inspection/requeue window. Anything still
    /// claimable is left alone.
    pub async fn purge_terminal_p2p_inbox_messages(
        &mut self,
        expired_before: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM p2p_inbox \
             WHERE state IN ('Processed', 'Failed', 'Quarantined') AND updated_at < ?",
        )
        .bind(expired_before)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete the oldest terminal rows beyond `max_rows`, up to `limit` per call.
    pub async fn purge_p2p_inbox_over_terminal_cap(
        &mut self,
        max_rows: i64,
        limit: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM p2p_inbox WHERE message_id IN ( \
                 SELECT message_id FROM p2p_inbox \
                 WHERE state IN ('Processed', 'Failed', 'Quarantined') \
                 ORDER BY updated_at ASC \
                 LIMIT MIN(?, MAX( \
                     (SELECT COUNT(*) FROM p2p_inbox \
                      WHERE state IN ('Processed', 'Failed', 'Quarantined')) - ?, 0)))",
        )
        .bind(limit)
        .bind(max_rows)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Clear the oldest Quarantined payloads until retained bytes are within `max_bytes`.
    pub async fn trim_quarantined_p2p_inbox_payloads(
        &mut self,
        max_bytes: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE p2p_inbox SET content = X'', content_size = 0, updated_at = ? \
             WHERE state = 'Quarantined' AND length(content) > 0 AND message_id IN ( \
                 SELECT message_id FROM ( \
                     SELECT message_id, \
                            SUM(content_size) OVER ( \
                                ORDER BY updated_at DESC \
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running \
                     FROM p2p_inbox WHERE state = 'Quarantined' AND length(content) > 0 \
                 ) WHERE running - content_size >= ?)",
        )
        .bind(get_current_timestamp_secs())
        .bind(max_bytes)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
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

    /// Raise the persisted replay marks to `marks` (`peer_id -> highest sequence
    /// number admitted`). A mark never moves down.
    pub async fn raise_p2p_replay_marks(&mut self, marks: &[(String, i64)]) -> anyhow::Result<()> {
        for (peer_id, highest) in marks {
            sqlx::query(
                "INSERT INTO p2p_replay_mark (peer_id, highest) VALUES (?, ?) \
                 ON CONFLICT (peer_id) DO UPDATE SET highest = MAX(highest, excluded.highest)",
            )
            .bind(peer_id)
            .bind(highest)
            .execute(self.conn())
            .await?;
        }
        Ok(())
    }

    pub async fn load_p2p_replay_marks(&mut self) -> anyhow::Result<Vec<(String, i64)>> {
        let rows = sqlx::query("SELECT peer_id, highest FROM p2p_replay_mark")
            .fetch_all(self.conn())
            .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("peer_id")?, row.try_get("highest")?)))
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    /// Remove marks for unregistered peers, retaining verifier peer IDs in `keep`.
    pub async fn prune_p2p_replay_marks(&mut self, keep: &[String]) -> anyhow::Result<u64> {
        let keep_predicate = if keep.is_empty() {
            String::new()
        } else {
            format!(" AND peer_id NOT IN ({})", create_place_holders(keep))
        };
        let query = format!(
            "DELETE FROM p2p_replay_mark \
             WHERE peer_id NOT IN (SELECT peer_id FROM p2p_registered_peer){keep_predicate}"
        );
        let mut query = sqlx::query(&query);
        for peer_id in keep {
            query = query.bind(peer_id);
        }
        Ok(query.execute(self.conn()).await?.rows_affected())
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

    /// Drop the persisted replay marks of `peer_ids`.
    pub async fn delete_p2p_replay_marks(&mut self, peer_ids: &[String]) -> anyhow::Result<u64> {
        if peer_ids.is_empty() {
            return Ok(0);
        }
        let query = format!(
            "DELETE FROM p2p_replay_mark WHERE peer_id IN ({})",
            create_place_holders(peer_ids)
        );
        let mut query = sqlx::query(&query);
        for peer_id in peer_ids {
            query = query.bind(peer_id);
        }
        Ok(query.execute(self.conn()).await?.rows_affected())
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

    pub async fn renew_p2p_inbox_lease(
        &mut self,
        message_id: &str,
        lease_token: &str,
        lease_until: i64,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox SET lease_until = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND lease_token = ?",
        )
        .bind(lease_until)
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(lease_token)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Release inbox claims during a graceful process shutdown without charging
    /// them as abandoned executions.
    pub async fn release_processing_p2p_inbox_messages(&mut self) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', lease_until = 0, lease_token = '', \
                 next_retry_at = 0, updated_at = ? \
             WHERE state = 'Processing'",
        )
        .bind(get_current_timestamp_secs())
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// Startup sweep for inbox claims left behind by a process that no longer
    /// exists. See [`Self::reclaim_processing_local_messages`].
    pub async fn reclaim_processing_p2p_inbox_messages(
        &mut self,
        now: i64,
        backoff_secs: i64,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', abandon_count = abandon_count + 1, lease_until = 0, \
                 lease_token = '', next_retry_at = ? + ? * (abandon_count + 1), \
                 last_error = 'reclaimed at startup: previous process exited mid-dispatch', \
                 updated_at = ? \
             WHERE state = 'Processing'",
        )
        .bind(now)
        .bind(backoff_secs)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn requeue_p2p_inbox_message(&mut self, message_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_inbox \
             SET state = 'Pending', abandon_count = 0, next_retry_at = 0, lease_until = 0, \
                 lease_token = '', last_error = NULL, updated_at = ? \
             WHERE message_id = ? AND state = 'Quarantined' AND length(content) > 0",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn insert_p2p_outbox_message(
        &mut self,
        message_id: &str,
        msg_type: &str,
        content: &[u8],
    ) -> anyhow::Result<bool> {
        let now = get_current_timestamp_secs();
        let result = sqlx::query(
            "INSERT INTO p2p_outbox \
                (message_id, msg_type, content, state, attempt_count, next_retry_at, lease_until, created_at, updated_at) \
             VALUES (?, ?, ?, 'Pending', 0, 0, 0, ?, ?) \
             ON CONFLICT(message_id) DO NOTHING",
        )
        .bind(message_id)
        .bind(msg_type)
        .bind(content)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Enqueue an outbound message, allowing a terminal message to be
    /// deliberately announced again while preserving an in-flight attempt.
    pub async fn enqueue_p2p_outbox_message(
        &mut self,
        message_id: &str,
        msg_type: &str,
        content: &[u8],
    ) -> anyhow::Result<bool> {
        let now = get_current_timestamp_secs();
        let result = sqlx::query(
            "INSERT INTO p2p_outbox \
                (message_id, msg_type, content, state, attempt_count, next_retry_at, lease_until, created_at, updated_at) \
             VALUES (?, ?, ?, 'Pending', 0, 0, 0, ?, ?) \
             ON CONFLICT(message_id) DO UPDATE SET \
                msg_type = excluded.msg_type, content = excluded.content, state = 'Pending', \
                attempt_count = 0, next_retry_at = 0, lease_until = 0, last_error = NULL, updated_at = excluded.updated_at \
             WHERE p2p_outbox.state IN ('Processed', 'Failed')",
        )
        .bind(message_id)
        .bind(msg_type)
        .bind(content)
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Queue a graph-setup notification for a bounded retransmission window.
    ///
    /// A non-empty `ack_peer_id` is the only ACK that may stop this retry
    /// loop early. Broadcast messages without an authenticated recipient keep
    /// publishing until their window expires.
    /// `first_publish_at`: first outbox delivery time; zero makes the row immediately due.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_p2p_outbox_retry_message(
        &mut self,
        message_id: &str,
        msg_type: &str,
        content: &[u8],
        retry_until: i64,
        retry_interval_secs: i64,
        ack_peer_id: Option<&str>,
        first_publish_at: i64,
    ) -> anyhow::Result<bool> {
        let now = get_current_timestamp_secs();
        let result = sqlx::query(
            "INSERT INTO p2p_outbox \
                (message_id, msg_type, content, state, attempt_count, next_retry_at, lease_until, retry_until, retry_interval_secs, ack_peer_id, created_at, updated_at) \
             VALUES (?, ?, ?, 'Pending', 0, ?, 0, ?, ?, ?, ?, ?) \
             ON CONFLICT(message_id) DO NOTHING",
        )
        .bind(message_id)
        .bind(msg_type)
        .bind(content)
        .bind(first_publish_at)
        .bind(retry_until)
        .bind(retry_interval_secs)
        .bind(ack_peer_id.unwrap_or_default())
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Claim due outbox rows in ascending `next_retry_at` order.
    pub async fn claim_p2p_outbox_messages(
        &mut self,
        now: i64,
        lease_until: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<P2pOutboxMessage>> {
        let rows = sqlx::query(
            "SELECT message_id, msg_type, content, state, attempt_count, next_retry_at, lease_until, last_error, retry_until, retry_interval_secs, ack_peer_id, publish_count, created_at \
             FROM p2p_outbox \
             WHERE ((state = 'Pending' AND next_retry_at <= ?) \
                OR (state = 'Processing' AND lease_until <= ?) \
             ) AND (retry_until = 0 OR retry_until > ?) \
             ORDER BY next_retry_at ASC, created_at ASC LIMIT ?",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(limit)
        .fetch_all(self.conn())
        .await?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let mut message = p2p_outbox_message_from_row(&row)?;
            let result = sqlx::query(
                "UPDATE p2p_outbox SET state = 'Processing', attempt_count = attempt_count + 1, lease_until = ?, updated_at = ? \
                 WHERE message_id = ? AND ((state = 'Pending' AND next_retry_at <= ?) \
                    OR (state = 'Processing' AND lease_until <= ?))",
            )
            .bind(lease_until)
            .bind(now)
            .bind(&message.message_id)
            .bind(now)
            .bind(now)
            .execute(self.conn())
            .await?;
            if result.rows_affected() > 0 {
                message.state = "Processing".to_owned();
                message.attempt_count += 1;
                message.lease_until = lease_until;
                claimed.push(message);
            }
        }
        Ok(claimed)
    }

    /// End a bounded-retry message once its delivery window is exhausted.
    pub async fn expire_p2p_outbox_retry_messages(&mut self, now: i64) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'RetryExhausted', \
                 content = CASE WHEN msg_type IN ('InitGraph','GenCircuits','CutCircuits','SolderingProofReady') THEN content ELSE X'' END, \
                 lease_until = 0, next_retry_at = 0, \
                 retry_until = CASE WHEN msg_type IN ('InitGraph','GenCircuits','CutCircuits','SolderingProofReady') THEN retry_until ELSE 0 END, \
                 retry_interval_secs = CASE WHEN msg_type IN ('InitGraph','GenCircuits','CutCircuits','SolderingProofReady') THEN retry_interval_secs ELSE 0 END, \
                 ack_peer_id = CASE WHEN msg_type IN ('InitGraph','GenCircuits','CutCircuits','SolderingProofReady') THEN ack_peer_id ELSE '' END, \
                 last_error = 'retry window expired without expected ACK', updated_at = ? \
             WHERE retry_until > 0 AND retry_until <= ? AND state IN ('Pending', 'Processing')",
        )
        .bind(now)
        .bind(now)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected())
    }

    /// At most one retained setup payload per pass, oldest recovery first.
    pub async fn next_exhausted_setup(
        &mut self,
        now: i64,
    ) -> anyhow::Result<Option<(String, Vec<u8>, i64)>> {
        Ok(sqlx::query_as(
            "SELECT message_id, content, created_at FROM p2p_outbox \
             WHERE state = 'RetryExhausted' AND length(content) > 0 \
               AND msg_type IN ('InitGraph','GenCircuits','CutCircuits','SolderingProofReady') \
               AND updated_at <= ? ORDER BY updated_at, message_id LIMIT 1",
        )
        .bind(now - 60)
        .fetch_optional(self.conn())
        .await?)
    }

    /// Called inside an immediate transaction: transfer bytes, never reopen a terminal row.
    pub async fn recover_setup_delivery(
        &mut self,
        id: &str,
        canonical_id: &str,
        now: i64,
        window: i64,
        resume: bool,
    ) -> anyhow::Result<()> {
        if resume {
            let next_id = format!("{canonical_id}:recovery:{now}");
            sqlx::query(
                "INSERT INTO p2p_outbox (message_id,msg_type,content,state,attempt_count,next_retry_at,lease_until, \
                 retry_until,retry_interval_secs,ack_peer_id,publish_count,created_at,updated_at) \
                 SELECT ?,msg_type,content,'Pending',0,?,0,?,retry_interval_secs,ack_peer_id,publish_count,created_at,? \
                 FROM p2p_outbox WHERE message_id = ? AND state = 'RetryExhausted' AND length(content) > 0",
            ).bind(next_id).bind(now).bind(now + window).bind(now).bind(id).execute(self.conn()).await?;
        }
        sqlx::query("UPDATE p2p_outbox SET content = X'', updated_at = ? WHERE message_id = ? AND state = 'RetryExhausted'")
            .bind(now).bind(id).execute(self.conn()).await?;
        Ok(())
    }

    /// Record a publish that went through and set when the row is next due.
    pub async fn schedule_p2p_outbox_retry(
        &mut self,
        message_id: &str,
        next_retry_at: i64,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Pending', lease_until = 0, next_retry_at = ?, \
                 publish_count = publish_count + 1, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing' AND retry_until > 0",
        )
        .bind(next_retry_at)
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Make a waiting row due at once. For a caller whose own publish of the
    /// message failed: the row was scheduled on the assumption that it would not.
    pub async fn expedite_p2p_outbox_message(&mut self, message_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET next_retry_at = 0, updated_at = ? \
             WHERE message_id = ? AND state = 'Pending' AND next_retry_at > 0",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// State and stored payload length of one outbox entry, for diagnostics and
    /// tests. A terminal entry has dropped its payload.
    pub async fn p2p_outbox_entry_state(
        &mut self,
        message_id: &str,
    ) -> anyhow::Result<Option<(String, i64)>> {
        let row = sqlx::query(
            "SELECT state, length(content) AS content_len FROM p2p_outbox WHERE message_id = ?",
        )
        .bind(message_id)
        .fetch_optional(self.conn())
        .await?;
        row.map(|row| Ok((row.try_get("state")?, row.try_get("content_len")?))).transpose()
    }

    pub async fn acknowledge_p2p_outbox_message(
        &mut self,
        message_id: &str,
        peer_id: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Processed', content = X'', lease_until = 0, next_retry_at = 0, updated_at = ? \
             WHERE (message_id = ? OR substr(message_id, 1, length(?) + 10) = ? || ':recovery:') \
               AND ack_peer_id = ? AND ack_peer_id != '' \
               AND state IN ('Pending', 'Processing', 'RetryExhausted')",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_id)
        .bind(message_id)
        .bind(peer_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Stop a local setup notification once a later protocol step makes it
    /// obsolete and release its potentially large payload immediately.
    pub async fn cancel_p2p_outbox_message(&mut self, message_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Cancelled', content = X'', lease_until = 0, next_retry_at = 0, \
                 updated_at = ? \
             WHERE (message_id = ? OR substr(message_id, 1, length(?) + 10) = ? || ':recovery:') \
               AND state IN ('Pending', 'Processing', 'RetryExhausted')",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .bind(message_id)
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn complete_p2p_outbox_message(&mut self, message_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Processed', content = X'', lease_until = 0, next_retry_at = 0, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing'",
        )
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn retry_p2p_outbox_message(
        &mut self,
        message_id: &str,
        next_retry_at: i64,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Pending', lease_until = 0, next_retry_at = ?, last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing'",
        )
        .bind(next_retry_at)
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn fail_p2p_outbox_message(
        &mut self,
        message_id: &str,
        error: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE p2p_outbox SET state = 'Failed', content = X'', lease_until = 0, next_retry_at = 0, \
                 last_error = ?, updated_at = ? \
             WHERE message_id = ? AND state = 'Processing'",
        )
        .bind(error.chars().take(1024).collect::<String>())
        .bind(get_current_timestamp_secs())
        .bind(message_id)
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record that a chain-derived graph message has been durably enqueued.
    ///
    /// Queue rows are intentionally pruned after their retention period, but
    /// replaying an old SyncGraph must not recreate already-completed protocol
    /// actions. The caller inserts this marker and its queue row in one
    /// transaction.
    pub async fn insert_graph_compensation_marker(
        &mut self,
        graph_id: Uuid,
        message_id: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "INSERT INTO graph_compensation_marker (graph_id, message_id, created_at) \
             VALUES (?, ?, ?) ON CONFLICT(graph_id, message_id) DO NOTHING",
        )
        .bind(graph_id)
        .bind(message_id)
        .bind(get_current_timestamp_secs())
        .execute(self.conn())
        .await?;
        Ok(result.rows_affected() > 0)
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
    pub async fn has_graph_of_instance(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM graph \
             WHERE graph_id = ? AND instance_id = ? \
               AND EXISTS (SELECT 1 FROM graph_raw_data WHERE graph_raw_data.graph_id = graph.graph_id) \
             LIMIT 1",
        )
        .bind(graph_id)
        .bind(instance_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(row.is_some())
    }

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

    pub async fn create_long_running_task_proof(
        &mut self,
        long_running_task_proof: &LongRunningTaskProof,
    ) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT
             INTO long_running_task_proof (block_start, block_end, chain_name, path_to_proof, public_value_hex, proof_size, cycles, proof_state, total_time_to_proof, proving_time,
                                           zkm_version, extra, updated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            long_running_task_proof.block_start,
            long_running_task_proof.block_end,
            long_running_task_proof.chain_name,
            long_running_task_proof.path_to_proof,
            long_running_task_proof.public_value_hex,
            long_running_task_proof.proof_size,
            long_running_task_proof.cycles,
            long_running_task_proof.proof_state,
            long_running_task_proof.total_time_to_proof,
            long_running_task_proof.proving_time,
            long_running_task_proof.zkm_version,
            long_running_task_proof.extra,
            long_running_task_proof.updated_at,
            long_running_task_proof.created_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    /// Deletes all persisted proof tasks for one proof chain.
    pub async fn delete_long_running_task_proofs_by_name(
        &mut self,
        chain_name: &str,
    ) -> anyhow::Result<u64> {
        let res = sqlx::query("DELETE FROM long_running_task_proof WHERE chain_name = ?")
            .bind(chain_name)
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_long_running_task_proof_success(
        &mut self,
        block_start: i64,
        chain_name: &str,
        batch_size: i64,
        path_to_proof: String,
        public_value_hex: String,
        proof_size: i64,
        cycles: i64,
        proof_state: i64,
        total_time_to_proof: i64,
        proving_time: i64,
        zkm_version: &str,
    ) -> anyhow::Result<u64> {
        let block_end = block_start + batch_size;
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE long_running_task_proof
             SET path_to_proof = ?,
                 cycles = ?,
                 proof_state = ?,
                 total_time_to_proof = ?,
                 proving_time = ?,
                 zkm_version = ?,
                 block_end = ?,
                 public_value_hex = ?,
                 proof_size = ?,
                 updated_at = ?
             WHERE block_start = ? AND chain_name = ?",
            path_to_proof,
            cycles,
            proof_state,
            total_time_to_proof,
            proving_time,
            zkm_version,
            block_end,
            public_value_hex,
            proof_size,
            current_time,
            block_start,
            chain_name,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_long_running_task_proof_state(
        &mut self,
        block_start: i64,
        chain_name: &str,
        batch_size: i64,
        proof_state: i64,
    ) -> anyhow::Result<u64> {
        let block_end = block_start + batch_size;
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE long_running_task_proof
             SET proof_state = ?,
                 block_end = ?,
                 updated_at = ?
             WHERE block_start = ? AND chain_name = ?",
            proof_state,
            block_end,
            current_time,
            block_start,
            chain_name,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn find_all_running_task_proofs_by_name(
        &mut self,
        chain_name: String,
    ) -> anyhow::Result<Vec<LongRunningTaskProof>> {
        let res = sqlx::query_as!(
            LongRunningTaskProof,
            "SELECT block_start, block_end, chain_name, path_to_proof, public_value_hex, proof_size, cycles, proof_state, total_time_to_proof, proving_time,
                                           zkm_version, extra, updated_at, created_at FROM long_running_task_proof
             WHERE chain_name = ?",
            chain_name,
        )
            .fetch_all(self.conn())
            .await?;
        Ok(res)
    }

    pub async fn find_long_running_task_proof_including_block_number(
        &mut self,
        block_number: i64,
        chain_name: String,
    ) -> anyhow::Result<Option<LongRunningTaskProof>> {
        let res = sqlx::query_as!(
            LongRunningTaskProof,
            "SELECT block_start, block_end, chain_name, path_to_proof, public_value_hex, proof_size, cycles, proof_state, total_time_to_proof, proving_time,
                                           zkm_version, extra, updated_at, created_at FROM long_running_task_proof
           
             WHERE block_end > ? and block_start <= ? AND chain_name = ? LIMIT 1",
            block_number,
            block_number,
            chain_name,
        )
            .fetch_optional(self.conn())
            .await?;
        Ok(res)
    }

    pub async fn find_latest_long_running_task_proof_by_name_and_state(
        &mut self,
        chain_name: String,
        proof_state: i64,
    ) -> anyhow::Result<Option<LongRunningTaskProof>> {
        let res = sqlx::query_as!(
            LongRunningTaskProof,
            "SELECT
                block_start,
                block_end,
                chain_name,
                path_to_proof,
                public_value_hex,
                proof_size,
                cycles,
                proof_state,
                total_time_to_proof,
                proving_time,
                zkm_version,
                extra,
                updated_at,
                created_at
            FROM long_running_task_proof
            WHERE chain_name = ?
            AND proof_state = ?
            ORDER BY block_start DESC
            LIMIT 1",
            chain_name,
            proof_state,
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn find_latest_long_running_task_proof_by_name(
        &mut self,
        chain_name: String,
    ) -> anyhow::Result<Option<LongRunningTaskProof>> {
        let res = sqlx::query_as!(
            LongRunningTaskProof,
            "SELECT
                block_start,
                block_end,
                chain_name,
                path_to_proof,
                public_value_hex,
                proof_size,
                cycles,
                proof_state,
                total_time_to_proof,
                proving_time,
                zkm_version,
                extra,
                updated_at,
                created_at
            FROM long_running_task_proof
            WHERE chain_name = ?
            ORDER BY block_start DESC
            LIMIT 1",
            chain_name,
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn create_operator_proof(
        &mut self,
        operator_proof: &OperatorProof,
    ) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT
             INTO operator_proof (instance_id, graph_id, execution_layer_block_number, path_to_proof, public_value_hex, proof_size, cycles, proof_state, total_time_to_proof, proving_time,
                                 zkm_version, extra, updated_at, created_at, operator_committed_blockhash)
             VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            operator_proof.instance_id,
            operator_proof.graph_id,
            operator_proof.execution_layer_block_number,
            operator_proof.path_to_proof,
            operator_proof.public_value_hex,
            operator_proof.proof_size,
            operator_proof.cycles,
            operator_proof.proof_state,
            operator_proof.total_time_to_proof,
            operator_proof.proving_time,
            operator_proof.zkm_version,
            operator_proof.extra,
            operator_proof.updated_at,
            operator_proof.created_at,
            operator_proof.operator_committed_blockhash,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_operator_proof(
        &mut self,
        id: i64,
        path_to_proof: String,
        public_value_hex: String,
        proof_size: i64,
        cycles: i64,
        proof_state: i64,
        total_time_to_proof: i64,
        proving_time: i64,
        zkm_version: &str,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE operator_proof
             SET path_to_proof = ?,
                 public_value_hex = ?,
                 proof_size = ?,
                 cycles = ?,
                 proof_state = ?,
                 total_time_to_proof = ?,
                 proving_time = ?,
                 zkm_version = ?,
                 updated_at = ?
             WHERE id = ?",
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles,
            proof_state,
            total_time_to_proof,
            proving_time,
            zkm_version,
            current_time,
            id,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_operator_proof_state_with_instance_graph(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        old_proof_state: i64,
        new_proof_state: i64,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE operator_proof
             SET proof_state = ?,
                 updated_at = ?
             WHERE instance_id = ? AND graph_id = ? AND  proof_state = ?",
            new_proof_state,
            current_time,
            instance_id,
            graph_id,
            old_proof_state
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn find_operator_proof_by_instance_and_graph(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<Option<OperatorProof>> {
        let res = sqlx::query_as::<_, OperatorProof>(
            "SELECT * FROM operator_proof
                 WHERE instance_id = ?
                   AND graph_id = ?",
        )
        .bind(instance_id)
        .bind(graph_id)
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn find_next_operator_proof(&mut self) -> anyhow::Result<Option<OperatorProof>> {
        let res = sqlx::query_as::<_, OperatorProof>(
            "SELECT * FROM operator_proof
                 WHERE proof_state == 0
                 ORDER BY id ASC
                 LIMIT 1",
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_watchtower_proof(
        &mut self,
        id: i64,
        path_to_proof: String,
        public_value_hex: String,
        proof_size: i64,
        cycles: i64,
        proof_state: i64,
        total_time_to_proof: i64,
        proving_time: i64,
        zkm_version: &str,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE watchtower_proof
             SET path_to_proof = ?,
                 public_value_hex = ?,
                 proof_size = ?,
                 cycles = ?,
                 proof_state = ?,
                 total_time_to_proof = ?,
                 proving_time = ?,
                 zkm_version = ?,
                 updated_at = ?
             WHERE id = ?",
            path_to_proof,
            public_value_hex,
            proof_size,
            cycles,
            proof_state,
            total_time_to_proof,
            proving_time,
            zkm_version,
            current_time,
            id,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }
    pub async fn update_watchtower_proof_state_with_instance_graph_pubkey(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        public_key: &str,
        old_proof_state: i64,
        new_proof_state: i64,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE watchtower_proof
             SET proof_state = ?,
                 updated_at = ?
             WHERE   instance_id = ?
                    AND graph_id = ?
                    AND  public_key = ? AND proof_state = ?",
            new_proof_state,
            current_time,
            instance_id,
            graph_id,
            public_key,
            old_proof_state
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_watchtower_proof_challenge_txid(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        node_index: i32,
        challenge_txid: &str,
        included: bool,
    ) -> anyhow::Result<u64> {
        let current_time = get_current_timestamp_secs();
        let res = sqlx::query!(
            "UPDATE watchtower_proof
             SET challenge_txid = ?,
                included =?,
                updated_at = ?
             WHERE instance_id = ?
                AND graph_id = ?
                AND node_index = ?",
            challenge_txid,
            included,
            current_time,
            instance_id,
            graph_id,
            node_index,
        )
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn update_watchtower_proof_node_index(
        &mut self,
        id: i64,
        instance_id: &Uuid,
        graph_id: &Uuid,
        node_index: i32,
    ) -> anyhow::Result<u64> {
        let res = sqlx::query(
            "UPDATE watchtower_proof
             SET node_index = ?
             WHERE id = ?
                AND instance_id = ?
                AND graph_id = ?",
        )
        .bind(node_index)
        .bind(id)
        .bind(instance_id)
        .bind(graph_id)
        .execute(self.conn())
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn find_watchtower_proof_by_instance_and_graph(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> anyhow::Result<Vec<WatchtowerProof>> {
        let res = sqlx::query_as::<_, WatchtowerProof>(
            "SELECT *
                  FROM watchtower_proof
                  WHERE instance_id = ?
                    AND graph_id = ?
                  ORDER BY node_index ASC, id ASC",
        )
        .bind(instance_id)
        .bind(graph_id)
        .fetch_all(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn find_watchtower_proof_by_instance_and_graph_and_pubkey(
        &mut self,
        instance_id: &Uuid,
        graph_id: &Uuid,
        public_key: &str,
    ) -> anyhow::Result<Option<WatchtowerProof>> {
        let res = sqlx::query_as::<_, WatchtowerProof>(
            "SELECT *
                  FROM watchtower_proof
                  WHERE instance_id = ?
                    AND graph_id = ?
                    AND  public_key = ?",
        )
        .bind(instance_id)
        .bind(graph_id)
        .bind(public_key)
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn find_next_watchtower_proof(&mut self) -> anyhow::Result<Option<WatchtowerProof>> {
        let res = sqlx::query_as::<_, WatchtowerProof>(
            "SELECT *
                  FROM watchtower_proof
                  WHERE proof_state == 0
                  ORDER BY id ASC
                  lIMIT 1",
        )
        .fetch_optional(self.conn())
        .await?;
        Ok(res)
    }

    pub async fn create_watchtower_proof(
        &mut self,
        watchtower_proof: &WatchtowerProof,
    ) -> anyhow::Result<u64> {
        let res = sqlx::query!(
            "INSERT
             INTO watchtower_proof (instance_id, graph_id, public_key, challenge_txid, challenge_init_txid, execution_layer_block_number,
                                   path_to_proof,
                                   public_value_hex, proof_size,
                                   cycles, proof_state, total_time_to_proof, proving_time,
                                   zkm_version, node_index, included,
                                   extra, updated_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            watchtower_proof.instance_id,
            watchtower_proof.graph_id,
            watchtower_proof.public_key,
            watchtower_proof.challenge_txid,
            watchtower_proof.challenge_init_txid,
            watchtower_proof.execution_layer_block_number,
            watchtower_proof.path_to_proof,
            watchtower_proof.public_value_hex,
            watchtower_proof.proof_size,
            watchtower_proof.cycles,
            watchtower_proof.proof_state,
            watchtower_proof.total_time_to_proof,
            watchtower_proof.proving_time,
            watchtower_proof.zkm_version,
            watchtower_proof.node_index,
            watchtower_proof.included,
            watchtower_proof.extra,
            watchtower_proof.updated_at,
            watchtower_proof.created_at,
        )
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
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
    let local_db = LocalDB::new(db_path, true).await;
    local_db.migrate().await;
    local_db
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MessageState;

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

    fn pegin_request_statuses() -> Vec<String> {
        vec![
            crate::InstanceBridgeInStatus::UserIniting.to_string(),
            crate::InstanceBridgeInStatus::UserInited.to_string(),
        ]
    }

    #[tokio::test]
    async fn test_upsert_pegin_request_instance_initializes_and_promotes() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let instance_id = Uuid::new_v4();

        let mut initing = pegin_instance(instance_id, "UserIniting");
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
        assert!(
            s.upsert_pegin_request_instance(&request, &pegin_request_statuses()).await.unwrap()
        );

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
        assert!(s.upsert_pegin_request_instance(&replay, &pegin_request_statuses()).await.unwrap());
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
        assert!(
            !s.upsert_pegin_request_instance(&replay, &pegin_request_statuses()).await.unwrap()
        );
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
        assert!(
            !s.upsert_pegin_request_instance(&request, &pegin_request_statuses()).await.unwrap()
        );
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
            "INSERT INTO graph (graph_id, instance_id, status, created_at, updated_at) VALUES ('graph-1', 'in-1', 'Created', 40, 40), ('graph-2', 'in-2', 'Created', 25, 25)",
        )
        .execute(s.conn())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, created_at, updated_at) VALUES ('message-1', 'in-1', 'operator', 'test', X'00', 'Pending', 15, 15)",
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
        assert_eq!(
            counts
                .iter()
                .find(|count| count.category == "message" && count.state == "Pending")
                .unwrap()
                .count,
            1
        );
    }

    /// A retired row must stay retired: a periodic producer re-upserting the same
    /// deterministic message_id would otherwise resurrect it on every tick.
    #[tokio::test]
    async fn upsert_does_not_resurrect_a_retired_message() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        let msg = Message {
            message_id: "retired-1".to_string(),
            business_id,
            actor: "Operator".to_string(),
            from_peer: "self".to_string(),
            msg_type: "AssertReady".to_string(),
            content: vec![1, 2],
            state: MessageState::Pending.to_string(),
            ..Default::default()
        };
        assert!(s.upsert_message(msg.clone()).await.unwrap());

        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(
            s.fail_local_message("retired-1", claimed[0].message_version, "handler panicked")
                .await
                .unwrap()
        );

        // The producer tries again with the same deterministic id.
        assert!(!s.upsert_message(msg).await.unwrap(), "a retired row must not be revived");
        let row = s.find_messages_by_id("retired-1").await.unwrap().unwrap();
        assert_eq!(row.state, "Failed");
        assert!(row.content.is_empty(), "the retired payload must stay released");
    }

    #[tokio::test]
    async fn upsert_does_not_replace_an_active_local_claim() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        let mut message = Message {
            message_id: "active-1".to_owned(),
            business_id,
            actor: "Operator".to_owned(),
            from_peer: "self".to_owned(),
            msg_type: "AssertReady".to_owned(),
            content: vec![1, 2],
            state: MessageState::Pending.to_string(),
            ..Default::default()
        };
        assert!(s.upsert_message(message.clone()).await.unwrap());
        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert_eq!(claimed.len(), 1);

        message.content = vec![9, 9];
        assert!(!s.upsert_message(message).await.unwrap());
        let stored = s.find_messages_by_id("active-1").await.unwrap().unwrap();
        assert_eq!(stored.state, "Processing");
        assert_eq!(stored.content, vec![1, 2]);
        assert_eq!(stored.message_version, claimed[0].message_version);
    }

    #[tokio::test]
    async fn producer_replay_does_not_forgive_an_abandoned_local_claim() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let message = Message {
            message_id: "abandoned-replay-1".to_owned(),
            business_id: Uuid::new_v4(),
            actor: "Operator".to_owned(),
            from_peer: "self".to_owned(),
            msg_type: "AssertReady".to_owned(),
            content: vec![1, 2],
            state: MessageState::Pending.to_string(),
            ..Default::default()
        };
        assert!(s.upsert_message(message.clone()).await.unwrap());
        sqlx::query("UPDATE message SET abandon_count = 2 WHERE message_id = ?")
            .bind(&message.message_id)
            .execute(s.conn())
            .await
            .unwrap();

        assert!(s.upsert_message(message.clone()).await.unwrap());
        let stored = s.find_messages_by_id(&message.message_id).await.unwrap().unwrap();
        assert_eq!(stored.abandon_count, 2);
    }

    #[tokio::test]
    async fn self_defer_cannot_be_overwritten_by_stale_completion() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES ('self-defer-1', ?, 'Operator', 'AssertReady', X'0102', 'Pending', 0, 10, 10)",
        )
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();
        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert!(
            s.self_defer_local_message(
                "self-defer-1",
                claimed[0].message_version,
                150,
                "not ready"
            )
            .await
            .unwrap()
        );
        assert!(
            !s.complete_local_message("self-defer-1", claimed[0].message_version).await.unwrap()
        );
        let stored = s.find_messages_by_id("self-defer-1").await.unwrap().unwrap();
        assert_eq!(stored.state, "Pending");
        assert_eq!(stored.attempt_count, 1);
    }

    #[tokio::test]
    async fn cancellation_reaches_pending_and_processing_local_messages() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        for (message_id, msg_type, state, lock_time_until) in [
            ("cancel-processing", "AssertReady", "Processing", 500),
            ("cancel-pending", "PostReady", "Pending", 400),
            ("keep-processed", "KickoffReady", "Processed", 0),
        ] {
            sqlx::query(
                "INSERT INTO message \
                 (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
                 VALUES (?, ?, 'Operator', ?, X'01', ?, ?, 10, 10)",
            )
            .bind(message_id)
            .bind(business_id)
            .bind(msg_type)
            .bind(state)
            .bind(lock_time_until)
            .execute(s.conn())
            .await
            .unwrap();
        }

        assert_eq!(
            s.cancel_messages_by_business_id(&business_id, Some("AssertReady".to_owned()))
                .await
                .unwrap(),
            1
        );
        let processing = s.find_messages_by_id("cancel-processing").await.unwrap().unwrap();
        assert_eq!(processing.state, "Cancelled");
        assert_eq!(processing.lock_time_until, 0);
        assert_eq!(s.cancel_messages_by_business_id(&business_id, None).await.unwrap(), 1);
        assert_eq!(
            s.find_messages_by_id("cancel-pending").await.unwrap().unwrap().state,
            "Cancelled"
        );
        assert_eq!(
            s.find_messages_by_id("keep-processed").await.unwrap().unwrap().state,
            "Processed"
        );
    }

    /// Every `message` SELECT must fetch the full column set `message_from_row`
    /// reads. Adding a column and updating only some of the hand-written SELECT
    /// lists fails at runtime, not at compile time, so pin all of them here.
    #[tokio::test]
    async fn every_message_query_hydrates_the_full_row() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES (?, ?, 'Operator', 'AssertReady', X'0102', 'Pending', 0, 10, 10)",
        )
        .bind("hydrate-1")
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();

        let by_id = s.find_messages_by_id("hydrate-1").await.unwrap().expect("row by id");
        assert_eq!(by_id.attempt_count, 0);
        assert_eq!(by_id.abandon_count, 0);
        assert!(by_id.last_error.is_none());

        let by_business = s
            .find_message_by_business_id(&business_id, "AssertReady")
            .await
            .unwrap()
            .expect("row by business id");
        assert_eq!(by_business.message_id, "hydrate-1");

        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].message_id, "hydrate-1");
    }

    fn admission_inbox_message(
        message_id: &str,
        from_peer: &str,
        admission_class: P2pInboxAdmissionClass,
        content: Vec<u8>,
    ) -> P2pInboxMessage {
        P2pInboxMessage {
            message_id: message_id.to_string(),
            actor: "Committee".to_string(),
            from_peer: from_peer.to_string(),
            msg_type: "KickoffSent".to_string(),
            content_size: content.len() as i64,
            content_hash: Some(content.clone()),
            content,
            admission_class: admission_class.to_string(),
            ..Default::default()
        }
    }

    /// Quota accounting must see what a sender currently makes the node store:
    /// queued rows only, split by class, with the sender's own share.
    #[tokio::test]
    async fn inbox_usage_counts_queued_rows_per_class_and_sender() {
        use P2pInboxAdmissionClass::{Registered, Unregistered};
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        for (message_id, from_peer, class, size) in [
            ("usage-1", "peer-a", Registered, 10),
            ("usage-2", "peer-a", Unregistered, 20),
            ("usage-3", "peer-b", Unregistered, 30),
            ("usage-4", "peer-b", Unregistered, 40),
        ] {
            let message = admission_inbox_message(message_id, from_peer, class, vec![7; size]);
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
        }
        // A terminal row has dropped its payload and must stop counting.
        let claimed = s.claim_p2p_inbox_message("usage-4", 100, 200).await.unwrap().unwrap();
        assert!(s.complete_p2p_inbox_message("usage-4", &claimed.lease_token).await.unwrap());
        // A claimed row still holds its payload.
        assert!(s.claim_p2p_inbox_message("usage-3", 100, 200).await.unwrap().is_some());

        let mut usage = s.p2p_inbox_usage("peer-b").await.unwrap();
        usage.sort_by(|a, b| a.admission_class.cmp(&b.admission_class));
        assert_eq!(
            usage,
            vec![
                P2pInboxClassUsage {
                    admission_class: "Registered".to_string(),
                    rows: 1,
                    bytes: 10,
                    peer_rows: 0,
                    peer_bytes: 0,
                },
                P2pInboxClassUsage {
                    admission_class: "Unregistered".to_string(),
                    rows: 2,
                    bytes: 50,
                    peer_rows: 1,
                    peer_bytes: 30,
                },
            ]
        );
    }

    /// The usage query runs for every inbound message; it must be answered from
    /// the covering index, never by reading rows that carry multi-megabyte blobs.
    #[tokio::test]
    async fn inbox_usage_is_answered_from_the_covering_index() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let plan: Vec<String> = sqlx::query(
            "EXPLAIN QUERY PLAN \
             SELECT admission_class, COUNT(*), COALESCE(SUM(content_size), 0), \
                    COALESCE(SUM(CASE WHEN from_peer = 'p' THEN content_size ELSE 0 END), 0) \
             FROM p2p_inbox WHERE state IN ('Pending', 'Processing', 'Quarantined') \
             GROUP BY admission_class",
        )
        .fetch_all(s.conn())
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("detail"))
        .collect();
        assert!(
            plan.iter().any(|step| step.contains("COVERING INDEX idx_p2p_inbox_admission")),
            "unexpected plan: {plan:?}"
        );
    }

    /// A row written without a classification defaults to `Unregistered` rather
    /// than silently joining the registered pool.
    #[tokio::test]
    async fn unclassified_inbox_rows_default_to_unregistered() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let message = P2pInboxMessage {
            message_id: "unclassified-1".to_string(),
            actor: "Operator".to_string(),
            from_peer: "peer".to_string(),
            msg_type: "CreateGraph".to_string(),
            content: vec![1, 2, 3],
            content_size: 3,
            ..Default::default()
        };
        assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
        let usage = s.p2p_inbox_usage("peer").await.unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].admission_class, "Unregistered");
        assert!(!s.has_queued_p2p_inbox_payload("peer", &[1, 2, 3]).await.unwrap());
    }

    /// Verify quota accounting and cleanup of quarantined payloads and terminal rows.
    #[tokio::test]
    async fn quarantined_payloads_count_and_are_capped() {
        use P2pInboxAdmissionClass::Unregistered;
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        for (message_id, updated_at) in [("q-old", 100), ("q-new", 200)] {
            let message = admission_inbox_message(message_id, "peer", Unregistered, vec![9; 1000]);
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
            sqlx::query(
                "UPDATE p2p_inbox SET state = 'Quarantined', updated_at = ? WHERE message_id = ?",
            )
            .bind(updated_at)
            .bind(message_id)
            .execute(s.conn())
            .await
            .unwrap();
        }
        let usage = s.p2p_inbox_usage("peer").await.unwrap();
        assert_eq!(usage.iter().map(|u| u.bytes).sum::<i64>(), 2000, "quarantine counts");

        // Keep only ~1000 bytes: the oldest quarantined payload is cleared.
        assert_eq!(s.trim_quarantined_p2p_inbox_payloads(1000).await.unwrap(), 1);
        let cleared: i64 =
            sqlx::query("SELECT length(content) AS len FROM p2p_inbox WHERE message_id = 'q-old'")
                .fetch_one(s.conn())
                .await
                .unwrap()
                .get("len");
        assert_eq!(cleared, 0, "the oldest payload was cleared");
        let kept: i64 =
            sqlx::query("SELECT length(content) AS len FROM p2p_inbox WHERE message_id = 'q-new'")
                .fetch_one(s.conn())
                .await
                .unwrap()
                .get("len");
        assert_eq!(kept, 1000, "the newest payload is retained");

        // The row cap deletes the oldest terminal rows beyond the ceiling.
        assert_eq!(s.purge_p2p_inbox_over_terminal_cap(1, 10).await.unwrap(), 1);
        let remaining: i64 = sqlx::query("SELECT COUNT(*) AS n FROM p2p_inbox")
            .fetch_one(s.conn())
            .await
            .unwrap()
            .get("n");
        assert_eq!(remaining, 1);
    }

    /// Verify split usage queries match the combined query and use the covering index.
    #[tokio::test]
    async fn split_inbox_usage_matches_and_seeks_the_sender() {
        use P2pInboxAdmissionClass::{Registered, Unregistered};
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        for (message_id, from_peer, class, size) in [
            ("split-1", "peer-a", Registered, 10),
            ("split-2", "peer-a", Unregistered, 20),
            ("split-3", "peer-b", Unregistered, 30),
        ] {
            let message = admission_inbox_message(message_id, from_peer, class, vec![7; size]);
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
        }
        let mut combined = s.p2p_inbox_usage("peer-a").await.unwrap();
        combined.sort_by(|a, b| a.admission_class.cmp(&b.admission_class));
        let mut totals = s.p2p_inbox_class_totals().await.unwrap();
        totals.sort_by(|a, b| a.admission_class.cmp(&b.admission_class));
        for peer in s.p2p_inbox_peer_usage("peer-a").await.unwrap() {
            let total =
                totals.iter_mut().find(|t| t.admission_class == peer.admission_class).unwrap();
            total.peer_rows = peer.peer_rows;
            total.peer_bytes = peer.peer_bytes;
        }
        assert_eq!(totals, combined);

        let plan: Vec<String> = sqlx::query(
            "EXPLAIN QUERY PLAN \
             SELECT admission_class, COUNT(*), COALESCE(SUM(content_size), 0) \
             FROM p2p_inbox \
             WHERE state IN ('Pending', 'Processing', 'Quarantined') \
               AND admission_class IN ('Registered', 'Unregistered') \
               AND from_peer = 'p' \
             GROUP BY admission_class",
        )
        .fetch_all(s.conn())
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("detail"))
        .collect();
        assert!(
            plan.iter().any(|step| step.contains("COVERING INDEX idx_p2p_inbox_admission")
                && step.contains("from_peer=?")),
            "the sender's rows must be reached by an index seek: {plan:?}"
        );
    }

    /// Registered rows take the batch ahead of older unregistered ones, but a
    /// reserved share keeps the unregistered queue moving.
    #[tokio::test]
    async fn claimable_listing_drains_registered_rows_first() {
        use P2pInboxAdmissionClass::{Committee, Registered, Unregistered};
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let mut created_at = 100;
        let mut insert = async |s: &mut StorageProcessor<'_>, id: String, class| {
            let message = admission_inbox_message(&id, "peer", class, id.clone().into_bytes());
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
            sqlx::query("UPDATE p2p_inbox SET created_at = ? WHERE message_id = ?")
                .bind(created_at)
                .bind(&id)
                .execute(s.conn())
                .await
                .unwrap();
            created_at += 1;
        };
        // The flood arrived first ...
        for index in 0..8 {
            insert(&mut s, format!("flood-{index}"), Unregistered).await;
        }
        // ... and the registered messages queue up behind it, the committee's
        // last of all.
        for index in 0..4 {
            insert(&mut s, format!("member-{index}"), Registered).await;
        }
        for index in 4..6 {
            insert(&mut s, format!("member-{index}"), Committee).await;
        }
        let ids = |rows: Vec<P2pInboxMessage>| -> Vec<String> {
            rows.into_iter().map(|row| row.message_id).collect()
        };

        let plain = ids(s.list_claimable_p2p_inbox_messages(1000, 4, 3, &[]).await.unwrap());
        assert_eq!(plain, ["flood-0", "flood-1", "flood-2", "flood-3"], "oldest first");

        let fair =
            ids(s.list_claimable_p2p_inbox_messages_by_class(1000, 4, 1, 1, 3, &[]).await.unwrap());
        assert_eq!(fair, ["member-4", "member-5", "member-0", "flood-0"], "committee first");

        // With fewer registered rows than the batch, the rest goes to the others.
        let fair = ids(s
            .list_claimable_p2p_inbox_messages_by_class(1000, 10, 2, 2, 3, &[])
            .await
            .unwrap());
        assert_eq!(fair.len(), 10);
        assert_eq!(fair.iter().filter(|id| id.starts_with("member-")).count(), 6);
        assert_eq!(&fair[6..], ["flood-0", "flood-1", "flood-2", "flood-3"]);

        // A committee backlog that would fill every batch does not starve the
        // other registered senders, nor the unregistered ones.
        for index in 0..8 {
            insert(&mut s, format!("committee-backlog-{index}"), Committee).await;
        }
        let fair =
            ids(s.list_claimable_p2p_inbox_messages_by_class(1000, 4, 1, 1, 3, &[]).await.unwrap());
        assert_eq!(fair, ["member-4", "member-5", "member-0", "flood-0"]);

        // Lend unused reserved capacity to committee first.
        let fair = ids(s
            .list_claimable_p2p_inbox_messages_by_class(1000, 16, 6, 4, 3, &[])
            .await
            .unwrap());
        assert_eq!(fair.len(), 16);
        assert_eq!(fair.iter().filter(|id| id.starts_with("flood-")).count(), 4);
        assert_eq!(fair.iter().filter(|id| id.starts_with("committee-backlog-")).count(), 6);
        let mut unique = fair.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            16,
            "borrowing continues a class's listing, it does not repeat it"
        );
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

    /// A sync request names both ids. A real graph under another instance's id
    /// is not a graph this node holds for that request.
    #[tokio::test]
    async fn graph_is_held_only_under_its_own_instance() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let (instance, graph, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        sqlx::query(
            "INSERT INTO graph (graph_id, instance_id, status, created_at, updated_at) \
             VALUES (?, ?, 'Created', 1, 1)",
        )
        .bind(graph)
        .bind(instance)
        .execute(s.conn())
        .await
        .unwrap();
        assert!(!s.has_graph_of_instance(&instance, &graph).await.unwrap(), "no data stored yet");
        sqlx::query("INSERT INTO graph_raw_data (graph_id, raw_data) VALUES (?, 'x')")
            .bind(graph)
            .execute(s.conn())
            .await
            .unwrap();
        assert!(s.has_graph_of_instance(&instance, &graph).await.unwrap());
        assert!(!s.has_graph_of_instance(&other, &graph).await.unwrap(), "wrong instance");
        assert!(!s.has_graph_of_instance(&instance, &other).await.unwrap(), "unknown graph");
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

        // Replay marks only move up, and are kept for registered peers and the
        // verifiers the caller names.
        s.raise_p2p_replay_marks(&[("member".into(), 50), ("verifier".into(), 7)]).await.unwrap();
        s.raise_p2p_replay_marks(&[("member".into(), 40), ("gone".into(), 9)]).await.unwrap();
        assert_eq!(s.prune_p2p_replay_marks(&["verifier".to_string()]).await.unwrap(), 1);
        let mut marks = s.load_p2p_replay_marks().await.unwrap();
        marks.sort();
        assert_eq!(marks, [("member".to_string(), 50), ("verifier".to_string(), 7)]);

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

        s.raise_p2p_replay_marks(&[("locked-out".into(), 99)]).await.unwrap();
        assert_eq!(s.delete_p2p_replay_marks(&["locked-out".to_string()]).await.unwrap(), 1);
        assert_eq!(s.delete_p2p_replay_marks(&[]).await.unwrap(), 0);
    }

    /// Only a copy that is still queued suppresses a re-publish; once it reached
    /// a terminal state the same payload may be delivered again.
    #[tokio::test]
    async fn queued_payload_lookup_ignores_other_senders_and_terminal_rows() {
        use P2pInboxAdmissionClass::Registered;
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let message = admission_inbox_message("dup-1", "peer-a", Registered, vec![9; 8]);
        assert!(s.insert_p2p_inbox_message(&message).await.unwrap());

        assert!(s.has_queued_p2p_inbox_payload("peer-a", &[9; 8]).await.unwrap());
        assert!(!s.has_queued_p2p_inbox_payload("peer-b", &[9; 8]).await.unwrap());
        assert!(!s.has_queued_p2p_inbox_payload("peer-a", &[8; 8]).await.unwrap());

        let claimed = s.claim_p2p_inbox_message("dup-1", 100, 200).await.unwrap().unwrap();
        assert!(
            s.has_queued_p2p_inbox_payload("peer-a", &[9; 8]).await.unwrap(),
            "a claimed row is still in flight"
        );
        assert!(s.complete_p2p_inbox_message("dup-1", &claimed.lease_token).await.unwrap());
        assert!(!s.has_queued_p2p_inbox_payload("peer-a", &[9; 8]).await.unwrap());
    }

    /// Verify Pending expiry uses `created_at`, not the last retry time.
    #[tokio::test]
    async fn pending_inbox_rows_expire_by_class_and_age() {
        use P2pInboxAdmissionClass::{Registered, Unregistered};
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        for (message_id, class, created_at) in [
            ("expire-old-unregistered", Unregistered, 100),
            ("expire-new-unregistered", Unregistered, 900),
            ("expire-old-registered", Registered, 100),
            ("expire-claimed-unregistered", Unregistered, 100),
        ] {
            let message = admission_inbox_message(message_id, "peer", class, vec![5; 16]);
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
            sqlx::query(
                "UPDATE p2p_inbox SET created_at = ?, updated_at = 5000 WHERE message_id = ?",
            )
            .bind(created_at)
            .bind(message_id)
            .execute(s.conn())
            .await
            .unwrap();
        }
        let now = get_current_timestamp_secs();
        assert!(
            s.claim_p2p_inbox_message("expire-claimed-unregistered", now, now + 300)
                .await
                .unwrap()
                .is_some()
        );

        assert_eq!(s.expire_pending_p2p_inbox_messages(Some(Unregistered), 500).await.unwrap(), 1);
        let states: Vec<(String, String, i64)> = sqlx::query(
            "SELECT message_id, state, length(content) AS len FROM p2p_inbox ORDER BY message_id",
        )
        .fetch_all(s.conn())
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get("message_id"), row.get("state"), row.get("len")))
        .collect();
        assert_eq!(
            states,
            vec![
                ("expire-claimed-unregistered".to_string(), "Processing".to_string(), 16),
                ("expire-new-unregistered".to_string(), "Pending".to_string(), 16),
                ("expire-old-registered".to_string(), "Pending".to_string(), 16),
                ("expire-old-unregistered".to_string(), "Failed".to_string(), 0),
            ]
        );

        // The class-independent ceiling reaches every remaining pending row.
        assert_eq!(s.expire_pending_p2p_inbox_messages(None, 1000).await.unwrap(), 2);
        assert_eq!(s.p2p_inbox_usage("peer").await.unwrap().iter().map(|u| u.rows).sum::<i64>(), 1);
    }

    /// Verify only unfinished claims increment abandon_count.
    #[tokio::test]
    async fn test_inbox_abandon_is_charged_only_for_unfinished_claims() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let message = P2pInboxMessage {
            message_id: "inbox-abandon-1".to_string(),
            actor: "Operator".to_string(),
            from_peer: "peer".to_string(),
            msg_type: "CreateGraph".to_string(),
            content: vec![1, 2, 3],
            content_size: 3,
            ..Default::default()
        };
        assert!(s.insert_p2p_inbox_message(&message).await.unwrap());

        // First claim of a Pending row: a retry attempt, not an abandon.
        let claimed = s.claim_p2p_inbox_messages(100, 200, 10, 3, &[]).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt_count, 1);
        assert_eq!(claimed[0].abandon_count, 0);

        // The handler returned a retryable error and the row went back to Pending.
        assert!(
            s.retry_p2p_inbox_message(
                &message.message_id,
                &claimed[0].lease_token,
                150,
                "storage busy"
            )
            .await
            .unwrap()
        );
        let claimed = s.claim_p2p_inbox_messages(160, 260, 10, 3, &[]).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt_count, 2, "a retry is recorded");
        assert_eq!(claimed[0].abandon_count, 0, "a retry must not charge the abandon budget");

        // Now simulate a worker that died mid-dispatch: the row is still
        // Processing and its lease has expired.
        let claimed = s.claim_p2p_inbox_messages(400, 500, 10, 3, &[]).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt_count, 3);
        assert_eq!(claimed[0].abandon_count, 1, "an unfinished claim charges the abandon budget");

        assert!(
            s.retry_p2p_inbox_message(
                &message.message_id,
                &claimed[0].lease_token,
                450,
                "dependency pending",
            )
            .await
            .unwrap()
        );
        let claimed = s.claim_p2p_inbox_messages(460, 560, 10, 3, &[]).await.unwrap();
        assert_eq!(claimed[0].abandon_count, 0, "a reported outcome resets consecutive abandons");
    }

    /// Verify repeated abandonment quarantines the retained payload.
    #[tokio::test]
    async fn test_inbox_quarantines_repeatedly_abandoned_message() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let message = P2pInboxMessage {
            message_id: "inbox-poison-1".to_string(),
            actor: "Operator".to_string(),
            from_peer: "peer".to_string(),
            msg_type: "GraphFinalize".to_string(),
            content: vec![9; 64],
            content_size: 64,
            ..Default::default()
        };
        assert!(s.insert_p2p_inbox_message(&message).await.unwrap());

        // Claims that never report an outcome, each one lease apart. On the
        // sweep after the third expired claim, that final abandon is recorded
        // as part of the quarantine transition.
        let mut now = 100;
        for attempt in 1..=3 {
            let claimed = s.claim_p2p_inbox_messages(now, now + 10, 10, 3, &[]).await.unwrap();
            assert_eq!(claimed.len(), 1, "claim {attempt} should still be served");
            assert_eq!(
                claimed[0].abandon_count,
                attempt - 1,
                "claim {attempt} charges one abandon per unfinished predecessor"
            );
            now += 100;
        }

        let quarantined = s.quarantine_p2p_inbox_messages(now, 3).await.unwrap();
        assert_eq!(quarantined, 1);

        let claimed = s.claim_p2p_inbox_messages(now, now + 10, 10, 3, &[]).await.unwrap();
        assert!(claimed.is_empty(), "a quarantined message must not be claimed again");

        let row =
            sqlx::query("SELECT state, content, last_error FROM p2p_inbox WHERE message_id = ?")
                .bind(&message.message_id)
                .fetch_one(s.conn())
                .await
                .unwrap();
        assert_eq!(row.get::<String, _>("state"), "Quarantined");
        assert_eq!(row.get::<Vec<u8>, _>("content"), message.content);
        assert!(row.get::<Option<String>, _>("last_error").is_some());

        assert!(s.requeue_p2p_inbox_message(&message.message_id).await.unwrap());
        let requeued = s.claim_p2p_inbox_messages(now, now + 10, 10, 3, &[]).await.unwrap();
        assert_eq!(requeued.len(), 1);
        assert_eq!(requeued[0].abandon_count, 0);
    }

    /// Verify local claims hold a lease.
    #[tokio::test]
    async fn test_local_claim_holds_lease_and_charges_abandon() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES (?, ?, 'Operator', 'AssertReady', X'0102', 'Pending', 0, 10, 10)",
        )
        .bind("local-claim-1")
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();

        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].abandon_count, 0);

        // Still inside the lease: the message must not be handed out again.
        let claimed_again = s.claim_local_messages(150, 250, 0, 10, 3).await.unwrap();
        assert!(claimed_again.is_empty(), "a leased message must not be re-claimed");

        // Lease expired with no outcome reported: that is an abandon.
        let reclaimed = s.claim_local_messages(300, 400, 0, 10, 3).await.unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].abandon_count, 1);
    }

    #[tokio::test]
    async fn graceful_shutdown_releases_claims_without_charging_abandon() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES ('shutdown-local', ?, 'Operator', 'AssertReady', X'01', 'Pending', 0, 10, 10)",
        )
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();
        let inbox = P2pInboxMessage {
            message_id: "shutdown-inbox".to_owned(),
            actor: "Operator".to_owned(),
            from_peer: "peer".to_owned(),
            msg_type: "CreateGraph".to_owned(),
            content: vec![1],
            content_size: 1,
            ..Default::default()
        };
        assert!(s.insert_p2p_inbox_message(&inbox).await.unwrap());
        assert_eq!(s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap().len(), 1);
        assert_eq!(s.claim_p2p_inbox_messages(100, 200, 10, 3, &[]).await.unwrap().len(), 1);

        assert_eq!(s.release_processing_local_messages().await.unwrap(), 1);
        assert_eq!(s.release_processing_p2p_inbox_messages().await.unwrap(), 1);

        let local = s.find_messages_by_id("shutdown-local").await.unwrap().unwrap();
        assert_eq!(local.state, "Pending");
        assert_eq!(local.abandon_count, 0);
        let inbox = sqlx::query(
            "SELECT state, abandon_count, lease_token FROM p2p_inbox WHERE message_id = ?",
        )
        .bind("shutdown-inbox")
        .fetch_one(s.conn())
        .await
        .unwrap();
        assert_eq!(inbox.get::<String, _>("state"), "Pending");
        assert_eq!(inbox.get::<i64, _>("abandon_count"), 0);
        assert!(inbox.get::<String, _>("lease_token").is_empty());
    }

    /// Deferring a local message records the retry, but only abandoned claims
    /// contribute to quarantine.
    #[tokio::test]
    async fn test_local_defer_charges_attempts_but_only_abandons_quarantine() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES (?, ?, 'Operator', 'AssertReady', X'0102', 'Pending', 0, 10, 10)",
        )
        .bind("local-defer-1")
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();

        let claimed = s.claim_local_messages(100, 200, 0, 10, 3).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(
            s.defer_local_message(&claimed[0].message_id, claimed[0].message_version, 150, "boom")
                .await
                .unwrap()
        );

        let reclaimed = s.claim_local_messages(160, 260, 0, 10, 3).await.unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].attempt_count, 1, "defer records the attempt");
        assert_eq!(reclaimed[0].abandon_count, 0, "defer must not charge the abandon budget");

        // A deferred message is NOT quarantined however many times it errors:
        // the local queue has no error budget, because a surviving row makes the
        // producer treat the work as already created.
        assert_eq!(s.quarantine_local_messages(300, 3).await.unwrap(), 0);

        // Abandoned claims are what retires it. The quarantine sweep counts the
        // final expired Processing lease.
        let mut now = 400;
        for _ in 0..3 {
            s.claim_local_messages(now, now + 10, 0, 10, 3).await.unwrap();
            now += 100;
        }
        assert_eq!(s.quarantine_local_messages(now, 3).await.unwrap(), 1);
        let row = sqlx::query("SELECT state, content FROM message WHERE message_id = ?")
            .bind("local-defer-1")
            .fetch_one(s.conn())
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("state"), "Quarantined");
        assert_eq!(row.get::<Vec<u8>, _>("content"), vec![1, 2]);
    }

    /// Rows are claimed one at a time immediately before dispatch, so an abort
    /// mid-dispatch charges only the row that was actually running.
    #[tokio::test]
    async fn local_claims_are_taken_per_message_not_per_batch() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        for (message_id, created_at) in [("first", 10), ("second", 20)] {
            sqlx::query(
                "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
                 VALUES (?, ?, 'Operator', 'AssertReady', X'01', 'Pending', 0, ?, ?)",
            )
            .bind(message_id)
            .bind(business_id)
            .bind(created_at)
            .bind(created_at)
            .execute(s.conn())
            .await
            .unwrap();
        }

        let candidates = s.list_claimable_local_messages(100, 0, 10, 3).await.unwrap();
        assert_eq!(
            candidates.iter().map(|message| message.message_id.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(
            candidates.iter().all(|message| message.state == "Pending"),
            "listing must not write"
        );

        let claimed = s
            .claim_local_message("first", candidates[0].message_version, 100, 200)
            .await
            .unwrap()
            .expect("first claim");
        assert_eq!(claimed.state, "Processing");
        assert_eq!(claimed.lock_time_until, 200);
        assert_eq!(s.find_messages_by_id("second").await.unwrap().unwrap().state, "Pending");

        // Inside the lease the same row is not claimable again.
        assert!(
            s.claim_local_message("first", claimed.message_version, 150, 250)
                .await
                .unwrap()
                .is_none()
        );
        // A row re-armed under a new version since it was listed is skipped too.
        assert!(
            s.claim_local_message("second", candidates[1].message_version + 1, 100, 200)
                .await
                .unwrap()
                .is_none()
        );
        // Once the lease lapses, the reclaim charges the unfinished attempt.
        let reclaimed = s
            .claim_local_message("first", claimed.message_version, 300, 400)
            .await
            .unwrap()
            .expect("reclaim");
        assert_eq!(reclaimed.abandon_count, 1);
    }

    #[tokio::test]
    async fn inbox_claims_are_taken_per_message_not_per_batch() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        for message_id in ["inbox-first", "inbox-second"] {
            let message = P2pInboxMessage {
                message_id: message_id.to_owned(),
                actor: "Operator".to_owned(),
                from_peer: "peer".to_owned(),
                msg_type: "CreateGraph".to_owned(),
                content: vec![1],
                content_size: 1,
                ..Default::default()
            };
            assert!(s.insert_p2p_inbox_message(&message).await.unwrap());
        }
        let candidates = s.list_claimable_p2p_inbox_messages(100, 10, 3, &[]).await.unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|message| message.state == "Pending" && message.lease_token.is_empty()),
            "listing must not write"
        );

        let claimed =
            s.claim_p2p_inbox_message("inbox-first", 100, 200).await.unwrap().expect("claim");
        assert_eq!(claimed.state, "Processing");
        assert_eq!(claimed.attempt_count, 1);
        assert_eq!(claimed.lease_until, 200);
        assert!(!claimed.lease_token.is_empty());
        assert!(s.claim_p2p_inbox_message("inbox-first", 150, 250).await.unwrap().is_none());
        let second = sqlx::query("SELECT state FROM p2p_inbox WHERE message_id = 'inbox-second'")
            .fetch_one(s.conn())
            .await
            .unwrap();
        assert_eq!(second.get::<String, _>("state"), "Pending");
    }

    /// An unclean exit leaves claims behind. At startup they are provably
    /// abandoned, so they are charged and released immediately with a backoff
    /// instead of sitting locked until the lease lapses.
    #[tokio::test]
    async fn startup_reclaim_charges_abandon_and_applies_backoff() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES ('startup-local', ?, 'Operator', 'AssertReady', X'01', 'Pending', 0, 10, 10)",
        )
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();
        let inbox = P2pInboxMessage {
            message_id: "startup-inbox".to_owned(),
            actor: "Operator".to_owned(),
            from_peer: "peer".to_owned(),
            msg_type: "CreateGraph".to_owned(),
            content: vec![1],
            content_size: 1,
            ..Default::default()
        };
        assert!(s.insert_p2p_inbox_message(&inbox).await.unwrap());
        assert_eq!(s.claim_local_messages(100, 700, 0, 10, 3).await.unwrap().len(), 1);
        assert_eq!(s.claim_p2p_inbox_messages(100, 400, 10, 3, &[]).await.unwrap().len(), 1);

        assert_eq!(s.reclaim_processing_local_messages(1000, 60).await.unwrap(), 1);
        assert_eq!(s.reclaim_processing_p2p_inbox_messages(1000, 60).await.unwrap(), 1);

        let local = s.find_messages_by_id("startup-local").await.unwrap().unwrap();
        assert_eq!(local.state, "Pending");
        assert_eq!(local.abandon_count, 1);
        assert_eq!(local.lock_time_until, 1060, "the first abandon backs off by one interval");
        let inbox_row = sqlx::query(
            "SELECT state, abandon_count, next_retry_at, lease_token FROM p2p_inbox WHERE message_id = 'startup-inbox'",
        )
        .fetch_one(s.conn())
        .await
        .unwrap();
        assert_eq!(inbox_row.get::<String, _>("state"), "Pending");
        assert_eq!(inbox_row.get::<i64, _>("abandon_count"), 1);
        assert_eq!(inbox_row.get::<i64, _>("next_retry_at"), 1060);
        assert!(inbox_row.get::<String, _>("lease_token").is_empty());

        // Nothing is claimable until the backoff has passed.
        assert!(s.list_claimable_local_messages(1030, 0, 10, 3).await.unwrap().is_empty());
        assert_eq!(s.list_claimable_local_messages(1060, 0, 10, 3).await.unwrap().len(), 1);
        assert!(s.list_claimable_p2p_inbox_messages(1030, 10, 3, &[]).await.unwrap().is_empty());
        assert_eq!(s.list_claimable_p2p_inbox_messages(1060, 10, 3, &[]).await.unwrap().len(), 1);
    }

    /// A handler that reschedules its own row and then panics must accumulate
    /// abandons across restarts. The self-defer must not reset the counter,
    /// because the handler is still running when it happens; only the
    /// dispatcher's confirmation after a normal return may reset it.
    #[tokio::test]
    async fn panic_after_self_defer_accumulates_abandons_until_quarantine() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) \
             VALUES ('panic-local', ?, 'Operator', 'AssertReady', X'01', 'Pending', 0, 10, 10)",
        )
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();

        let mut now = 100;
        for round in 1..=3 {
            // The row is Pending, so the restart's reclaim sweep leaves it alone
            // and the next tick claims it without a charge.
            let candidate = s.find_messages_by_id("panic-local").await.unwrap().unwrap();
            let claimed = s
                .claim_local_message("panic-local", candidate.message_version, now, now + 600)
                .await
                .unwrap()
                .expect("claim");
            assert_eq!(claimed.abandon_count, round - 1);
            // The handler reschedules itself, then panics.
            assert!(
                s.self_defer_local_message(
                    "panic-local",
                    claimed.message_version,
                    now + 5,
                    "not ready"
                )
                .await
                .unwrap()
            );
            assert!(
                s.abandon_local_message(
                    "panic-local",
                    claimed.message_version,
                    now,
                    60,
                    "panicked"
                )
                .await
                .unwrap()
            );
            let row = s.find_messages_by_id("panic-local").await.unwrap().unwrap();
            assert_eq!(row.state, "Pending");
            assert_eq!(row.abandon_count, round, "round {round} adds to the preserved count");
            assert_eq!(row.lock_time_until, now + 60 * round, "backoff grows with the count");
            now = row.lock_time_until + 1;
        }

        // The sweep on the next tick retires it instead of dispatching again.
        assert_eq!(s.quarantine_local_messages(now, 3).await.unwrap(), 1);
        assert_eq!(
            s.find_messages_by_id("panic-local").await.unwrap().unwrap().state,
            "Quarantined"
        );
    }

    /// A self-defer is only a reported outcome once the handler has returned,
    /// so the counter survives the self-defer and resets on confirmation.
    #[tokio::test]
    async fn self_defer_keeps_abandons_until_the_dispatcher_confirms_it() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, abandon_count, created_at, updated_at) \
             VALUES ('confirm-local', ?, 'Operator', 'AssertReady', X'01', 'Pending', 0, 2, 10, 10)",
        )
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();
        let candidate = s.find_messages_by_id("confirm-local").await.unwrap().unwrap();
        let claimed = s
            .claim_local_message("confirm-local", candidate.message_version, 100, 700)
            .await
            .unwrap()
            .expect("claim");
        assert_eq!(claimed.abandon_count, 2, "a claim from Pending is not charged");

        assert!(
            s.self_defer_local_message("confirm-local", claimed.message_version, 150, "not ready")
                .await
                .unwrap()
        );
        let row = s.find_messages_by_id("confirm-local").await.unwrap().unwrap();
        assert_eq!(row.state, "Pending");
        assert_eq!(row.attempt_count, 1);
        assert_eq!(row.abandon_count, 2, "the self-defer must not reset the counter");

        // The dispatcher confirms once the handler returned normally.
        assert!(
            s.confirm_local_message_self_defer("confirm-local", claimed.message_version)
                .await
                .unwrap()
        );
        assert_eq!(s.find_messages_by_id("confirm-local").await.unwrap().unwrap().abandon_count, 0);
        // A different claim generation, or a row that is not Pending, is not confirmed.
        assert!(
            !s.confirm_local_message_self_defer("confirm-local", claimed.message_version + 1)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_message_debug_reasons_are_deduplicated() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();
        let business_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO message (message_id, business_id, actor, msg_type, content, state, lock_time_until, created_at, updated_at) VALUES (?, ?, 'Operator', 'AssertReady', X'00', 'Pending', 30, 10, 20)",
        )
        .bind("message-debug-1")
        .bind(business_id)
        .execute(s.conn())
        .await
        .unwrap();

        for _ in 0..2 {
            s.upsert_message_debug_reason(
                "message-debug-1",
                "operator_proof_pending",
                "operator proof is not ready",
            )
            .await
            .unwrap();
        }
        s.upsert_message_debug_reason(
            "message-debug-1",
            "handler_error",
            "proof RPC request timed out",
        )
        .await
        .unwrap();

        let messages = s.find_message_debug_overviews(&business_id).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].reason_count, 2);

        let reasons = s.find_message_debug_reasons("message-debug-1").await.unwrap();
        assert_eq!(reasons.len(), 2);
        assert!(reasons.iter().any(|reason| {
            reason.reason_code == "operator_proof_pending" && reason.occurrences == 2
        }));
        assert!(
            reasons
                .iter()
                .any(|reason| reason.reason_code == "handler_error" && reason.occurrences == 1)
        );
    }

    #[tokio::test]
    async fn test_proof_metrics_state_counts() {
        let db = setup_db().await;
        let mut s = db.acquire().await.unwrap();

        sqlx::query("DELETE FROM long_running_task_proof").execute(s.conn()).await.unwrap();

        sqlx::query(
            "INSERT INTO long_running_task_proof (block_start, block_end, chain_name, proof_state, created_at, updated_at) VALUES (0, 1, 'header-chain', 2, 40, 90), (1, 2, 'header-chain', 2, 20, 100), (2, 3, 'header-chain', 0, 10, 10)",
        )
        .execute(s.conn())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO operator_proof (instance_id, graph_id, execution_layer_block_number, operator_committed_blockhash, proof_state, created_at, updated_at) VALUES ('instance', 'graph', 0, 'hash', 2, 50, 80)",
        )
        .execute(s.conn())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO watchtower_proof (instance_id, graph_id, public_key, challenge_txid, challenge_init_txid, execution_layer_block_number, proof_state, created_at, updated_at) VALUES ('instance', 'graph', 'key', 'challenge', 'init', 0, 1, 60, 70)",
        )
        .execute(s.conn())
        .await
        .unwrap();

        let counts = s.proof_metrics_state_counts().await.unwrap();
        assert_eq!(
            counts.iter().find(|count| count.category == "header-chain" && count.state == "2"),
            Some(&MetricsStateCount {
                category: "header-chain".to_string(),
                state: "2".to_string(),
                count: 2,
                oldest_created_at: None,
                last_success_at: Some(100),
            })
        );
        assert_eq!(
            counts
                .iter()
                .find(|count| count.category == "operator" && count.state == "2")
                .unwrap()
                .last_success_at,
            Some(80)
        );
        assert_eq!(
            counts
                .iter()
                .find(|count| count.category == "watchtower" && count.state == "1")
                .unwrap()
                .last_success_at,
            None
        );
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
