//! Counts and sums for metrics, the overview and the bridge-out statistics.

use super::StorageProcessor;
use crate::utils::create_place_holders;
use crate::{
    BridgeOutGlobalStats, EventWatchMetricsSnapshot, MetricsStateCount, NodeAlertMetricsSnapshot,
};

impl StorageProcessor<'_> {
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
}
