//! Node rows and the persisted peer registrations.

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::utils::{QueryBuilder, QueryParam};
use crate::{Node, NodesOverview};

use sqlx::Row;
use sqlx::types::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

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

impl StorageProcessor<'_> {
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
}
