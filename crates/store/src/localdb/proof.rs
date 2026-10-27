//! Proof-builder storage: the operator, watchtower and long-running chain proof rows and their
//! metrics counts. Used by proof-builder-rpc (the node itself does not read these tables).

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::{
    LongRunningTaskProof, MetricsStateCount, OnDemandProofCompletion, OnDemandProofTable,
    OperatorProof, WatchtowerProof,
};
use sqlx::types::Uuid;

impl StorageProcessor<'_> {
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
}

impl StorageProcessor<'_> {
    /// Finishes an on-demand proof task only while it is still `New`.
    ///
    /// A timeout request may mark the task `Failed` while its proof is queued or
    /// running; that state wins and this update affects no row.
    pub async fn complete_on_demand_proof_if_new(
        &mut self,
        table: OnDemandProofTable,
        id: i64,
        completion: &OnDemandProofCompletion,
    ) -> anyhow::Result<u64> {
        let sql = format!(
            "UPDATE {}
             SET path_to_proof = ?,
                 public_value_hex = ?,
                 proof_size = ?,
                 cycles = ?,
                 proof_state = ?,
                 total_time_to_proof = ?,
                 proving_time = ?,
                 zkm_version = ?,
                 updated_at = ?
             WHERE id = ? AND proof_state = ?",
            table.table_name()
        );
        let res = sqlx::query(&sql)
            .bind(&completion.path_to_proof)
            .bind(&completion.public_value_hex)
            .bind(completion.proof_size)
            .bind(completion.cycles)
            .bind(completion.proof_state)
            .bind(completion.total_time_to_proof)
            .bind(completion.proving_time)
            .bind(&completion.zkm_version)
            .bind(get_current_timestamp_secs())
            .bind(id)
            .bind(crate::ProofState::New.to_i64())
            .execute(self.conn())
            .await?;
        Ok(res.rows_affected())
    }

    /// Returns the current proof state of an on-demand proof task.
    pub async fn get_on_demand_proof_state(
        &mut self,
        table: OnDemandProofTable,
        id: i64,
    ) -> anyhow::Result<Option<i64>> {
        let sql = format!("SELECT proof_state FROM {} WHERE id = ?", table.table_name());
        let state = sqlx::query_scalar::<_, i64>(&sql).bind(id).fetch_optional(self.conn()).await?;
        Ok(state)
    }

    /// Counts unfinished (`New` or `Proving`) tasks of one proof chain starting at or after
    /// `from_block`.
    pub async fn count_pending_long_running_task_proofs(
        &mut self,
        chain_name: &str,
        from_block: i64,
    ) -> anyhow::Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM long_running_task_proof
             WHERE chain_name = ? AND block_start >= ? AND proof_state IN (?, ?)",
        )
        .bind(chain_name)
        .bind(from_block)
        .bind(crate::ProofState::New.to_i64())
        .bind(crate::ProofState::Proving.to_i64())
        .fetch_one(self.conn())
        .await?;
        Ok(count)
    }
}
