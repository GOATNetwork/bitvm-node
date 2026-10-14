//! Instance rows: peg-in requests, their answers, parameters and process data.

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::utils::{QueryBuilder, QueryParam};
use crate::{Instance, PeginInstanceProcessData, SerializableTxid};

use indexmap::IndexMap;
use sqlx::Row;
use sqlx::types::Uuid;

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

impl StorageProcessor<'_> {
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
}
