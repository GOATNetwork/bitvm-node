//! Goat-side records: watched contracts, Goat transactions and the sequencer
//! set hash history.

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::{GoatTxRecord, SequencerSetHashChange, SequencerSetScanState, WatchContract};

use sqlx::types::Uuid;

impl StorageProcessor<'_> {
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
