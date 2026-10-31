//! Graph rows: pending inits, definitions, runtime columns, status transitions,
//! raw data and the monitored outpoints.

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::utils::{QueryBuilder, QueryParam};
use crate::{
    Graph, GraphBtcTxVoutMonitor, GraphRawData, GraphStatus, GraphStatusSource,
    GraphStatusTransitionOutcome, PeginGraphProcessData, PendingGraphInit, SerializableTxid,
};

use sqlx::Row;
use sqlx::types::Uuid;
use std::str::FromStr;

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

impl StorageProcessor<'_> {
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
}
