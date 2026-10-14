//! Swap escrow rows.

use super::{StorageProcessor, get_current_timestamp_secs};
use crate::utils::{QueryBuilder, QueryParam};
use crate::{SerializableTxid, SwapEscrow, SwapEscrowStatus};

use sqlx::Row;

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

impl StorageProcessor<'_> {
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
}
