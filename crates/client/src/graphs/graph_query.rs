use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum WatchContractType {
    Gateway,
    Swap,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TheGraphConfig<T> {
    pub address: Address,
    pub the_graph_url: String,
    pub event_entities: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapConfig {
    #[serde(flatten)]
    pub graph_config: TheGraphConfig<SwapEventEntity>,
    pub peg_btc_address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum WatchEventConfig {
    Gateway(TheGraphConfig<GatewayEventEntity>),
    Swap(SwapConfig),
}

impl WatchEventConfig {
    pub fn get_watch_events_len(&self) -> usize {
        match self {
            WatchEventConfig::Gateway(config) => config.event_entities.len(),
            WatchEventConfig::Swap(config) => config.graph_config.event_entities.len(),
        }
    }

    pub fn get_watch_contract(&self) -> Address {
        match self {
            WatchEventConfig::Gateway(config) => config.address,
            WatchEventConfig::Swap(config) => config.graph_config.address,
        }
    }
    pub fn get_watch_contract_type(&self) -> WatchContractType {
        match self {
            WatchEventConfig::Gateway(_) => WatchContractType::Gateway,
            WatchEventConfig::Swap(_) => WatchContractType::Swap,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum GatewayEventEntity {
    #[strum(serialize = "initWithdraws")]
    InitWithdraws,
    #[strum(serialize = "cancelWithdraws")]
    CancelWithdraws,
    #[strum(serialize = "proceedWithdraws")]
    ProceedWithdraws,
    #[strum(serialize = "withdrawHappyPaths")]
    WithdrawHappyPaths,
    #[strum(serialize = "withdrawUnhappyPaths")]
    WithdrawUnhappyPaths,
    #[strum(serialize = "withdrawDisproveds")]
    WithdrawDisproveds,
    #[strum(serialize = "bridgeInRequests")]
    BridgeInRequests,
    #[strum(serialize = "committeeResponses")]
    CommitteeResponses,
    #[strum(serialize = "bridgeIns")]
    BridgeIns,
    #[strum(serialize = "postGraphDatas")]
    PostGraphDatas,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum SwapEventEntity {
    #[strum(serialize = "initializes")]
    Initializes,
    #[strum(serialize = "claims")]
    Claims,
    #[strum(serialize = "refunds")]
    Refunds,
}

/// Event fields and range filters shared by the paginated reader.
pub trait EventEntity: ToString {
    fn add_event_query(&self, builder: QueryBuilder, range: BlockRange) -> QueryBuilder;
}

impl EventEntity for GatewayEventEntity {
    fn add_event_query(&self, builder: QueryBuilder, range: BlockRange) -> QueryBuilder {
        self.add_single_query(builder, Some(range))
    }
}

impl EventEntity for SwapEventEntity {
    fn add_event_query(&self, builder: QueryBuilder, range: BlockRange) -> QueryBuilder {
        self.add_single_query(builder, Some(range))
    }
}

impl GatewayEventEntity {
    pub fn add_single_query(
        &self,
        builder: QueryBuilder,
        block_range: Option<BlockRange>,
    ) -> QueryBuilder {
        let mut builder = builder;
        let tag = self.to_string();
        builder = builder.add_query(&tag);
        match self {
            GatewayEventEntity::PostGraphDatas
            | GatewayEventEntity::InitWithdraws
            | GatewayEventEntity::CancelWithdraws => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
            GatewayEventEntity::ProceedWithdraws => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "kickoffTxid")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            GatewayEventEntity::WithdrawHappyPaths | GatewayEventEntity::WithdrawUnhappyPaths => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "operatorAddress")
                    .add_field(&tag, "rewardAmountSats")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            GatewayEventEntity::WithdrawDisproveds => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "graphId")
                    .add_field(&tag, "disproveTxType")
                    .add_field(&tag, "txnIndex")
                    .add_field(&tag, "challengeStartTxid")
                    .add_field(&tag, "challengeFinishTxid")
                    .add_field(&tag, "challengerAddress")
                    .add_field(&tag, "disproverAddress")
                    .add_field(&tag, "challengerRewardAmount")
                    .add_field(&tag, "disproverRewardAmount")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            GatewayEventEntity::BridgeInRequests => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "depositorAddress")
                    .add_field(&tag, "peginAmountSats")
                    .add_field(&tag, "txnFees")
                    .add_field(&tag, "userXonlyPubkey")
                    .add_field(&tag, "userChangeAddress")
                    .add_field(&tag, "userRefundAddress")
                    .add_field(&tag, "blockNumber")
                    .add_field(&tag, "blockTimestamp")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
            GatewayEventEntity::CommitteeResponses => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "committeeAddress")
                    .add_field(&tag, "committeePubkey")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
            GatewayEventEntity::BridgeIns => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "instanceId")
                    .add_field(&tag, "depositorAddress")
                    .add_field(&tag, "peginAmountSats")
                    .add_field(&tag, "feeAmountSats")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
        }

        if let Some(range) = block_range {
            builder = builder
                .add_filter(&tag, "blockNumber_gte", &range.start_block.to_string())
                .add_filter(&tag, "blockNumber_lte", &range.end_block.to_string())
        }
        builder
    }
}

impl SwapEventEntity {
    pub fn add_single_query(
        &self,
        builder: QueryBuilder,
        block_range: Option<BlockRange>,
    ) -> QueryBuilder {
        let mut builder = builder;
        let tag = self.to_string();
        builder = builder.add_query(&tag);
        match self {
            SwapEventEntity::Initializes => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "offerer")
                    .add_field(&tag, "claimer")
                    .add_field(&tag, "escrowHash")
                    .add_field(&tag, "claimHandler")
                    .add_field(&tag, "refundHandler")
                    .add_field(&tag, "blockTimestamp")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
            SwapEventEntity::Claims => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "offerer")
                    .add_field(&tag, "claimer")
                    .add_field(&tag, "escrowHash")
                    .add_field(&tag, "claimHandler")
                    .add_field(&tag, "witnessResult")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }

            SwapEventEntity::Refunds => {
                builder = builder
                    .add_field(&tag, "id")
                    .add_field(&tag, "offerer")
                    .add_field(&tag, "claimer")
                    .add_field(&tag, "escrowHash")
                    .add_field(&tag, "witnessResult")
                    .add_field(&tag, "refundHandler")
                    .add_field(&tag, "transactionHash")
                    .add_field(&tag, "blockNumber")
                    .set_order_by(&tag, "blockNumber", "asc");
            }
        }

        if let Some(range) = block_range {
            builder = builder
                .add_filter(&tag, "blockNumber_gte", &range.start_block.to_string())
                .add_filter(&tag, "blockNumber_lte", &range.end_block.to_string())
        }
        builder
    }
}

pub fn get_meta_data_query() -> String {
    let mut builder = QueryBuilder::new();
    let tag = "_meta".to_string();
    builder = builder.add_query(&tag);
    builder = builder.add_field(&tag, "block { number }");
    builder.build()
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UserGraphWithdrawEvent {
    InitWithdraw(InitWithdrawEvent),
    CancelWithdraw(CancelWithdrawEvent),
}

impl UserGraphWithdrawEvent {
    pub fn get_block_number(&self) -> i64 {
        match self {
            UserGraphWithdrawEvent::InitWithdraw(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
            UserGraphWithdrawEvent::CancelWithdraw(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CancelWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProceedWithdrawEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "kickoffTxid")]
    pub kickoff_txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawHappyEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "operatorAddress")]
    pub operator_addr: String,
    #[serde(rename = "rewardAmountSats")]
    pub reward_amount_sats: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawUnhappyEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "operatorAddress")]
    pub operator_addr: String,
    #[serde(rename = "rewardAmountSats")]
    pub reward_amount_sats: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WithdrawPathsEvent {
    WithdrawHappyEvent(WithdrawHappyEvent),
    WithdrawUnhappyEvent(WithdrawUnhappyEvent),
}

impl WithdrawPathsEvent {
    pub fn get_block_number(&self) -> i64 {
        match self {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => {
                v.block_number.parse::<i64>().expect("fail to decode block number")
            }
        }
    }
    pub fn reward_amount_sats(&self) -> i64 {
        match self {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => {
                v.reward_amount_sats.parse::<i64>().expect("fail to decode reward amount sats")
            }
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => {
                v.reward_amount_sats.parse::<i64>().expect("fail to decode reward amount sats")
            }
        }
    }

    pub fn reward_amount_str(&self) -> String {
        match self {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => v.reward_amount_sats.clone(),
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => v.reward_amount_sats.clone(),
        }
    }
    pub fn operator_addr(&self) -> String {
        match self {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => v.operator_addr.clone(),
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => v.operator_addr.clone(),
        }
    }
    pub fn tx_hash(&self) -> String {
        match self {
            WithdrawPathsEvent::WithdrawHappyEvent(v) => v.transaction_hash.clone(),
            WithdrawPathsEvent::WithdrawUnhappyEvent(v) => v.transaction_hash.clone(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawDisprovedEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
    #[serde(rename = "disproveTxType")]
    pub disprove_tx_type: i64,
    #[serde(rename = "txnIndex")]
    pub tx_index: String,
    #[serde(rename = "challengeStartTxid")]
    pub challenge_start_txid: String,
    #[serde(rename = "challengeFinishTxid")]
    pub challenge_finish_txid: String,
    #[serde(rename = "challengerAddress")]
    pub challenger_addr: String,
    #[serde(rename = "challengerRewardAmount")]
    pub challenger_amount_sats: String,
    #[serde(rename = "disproverAddress")]
    pub disprover_addr: String,
    #[serde(rename = "disproverRewardAmount")]
    pub disprover_amount_sats: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInput {
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "amountSats")]
    pub amount_sats: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeInRequestEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "depositorAddress")]
    pub depositor_address: String,
    #[serde(rename = "peginAmountSats")]
    pub pegin_amount_sats: String,
    #[serde(rename = "txnFees")]
    pub txn_fees: [String; 3],
    #[serde(rename = "userXonlyPubkey")]
    pub user_xonly_pubkey: String,
    #[serde(rename = "userChangeAddress")]
    pub user_change_address: String,
    #[serde(rename = "userRefundAddress")]
    pub user_refund_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitteeResponseEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "committeeAddress")]
    pub committee_address: String,
    #[serde(rename = "committeePubkey")]
    pub committee_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeInEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "depositorAddress")]
    pub depositor_address: String,
    #[serde(rename = "peginAmountSats")]
    pub pegin_amount_sats: String,
    #[serde(rename = "feeAmountSats")]
    pub fee_amount_sats: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostGraphDataEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "graphId")]
    pub graph_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapInitializeEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: String,
    #[serde(rename = "offerer")]
    pub offerer: String,
    #[serde(rename = "claimer")]
    pub claimer: String,
    #[serde(rename = "escrowHash")]
    pub escrow_hash: String,
    #[serde(rename = "claimHandler")]
    pub claim_handler: String,
    #[serde(rename = "refundHandler")]
    pub refund_handler: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapClaimEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "offerer")]
    pub offerer: String,
    #[serde(rename = "claimer")]
    pub claimer: String,
    #[serde(rename = "escrowHash")]
    pub escrow_hash: String,
    #[serde(rename = "claimHandler")]
    pub claim_handler: String,
    #[serde(rename = "witnessResult")]
    pub witness_result: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapRefundEvent {
    pub id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "offerer")]
    pub offerer: String,
    #[serde(rename = "claimer")]
    pub claimer: String,
    #[serde(rename = "escrowHash")]
    pub escrow_hash: String,
    #[serde(rename = "refundHandler")]
    pub refund_handler: String,
    #[serde(rename = "witnessResult")]
    pub witness_result: String,
}

#[derive(Debug, Clone)]
pub struct BlockRange {
    start_block: i64,
    end_block: i64,
}

impl BlockRange {
    pub fn new(start_block: i64, end_block: i64) -> Self {
        Self { start_block, end_block }
    }
}

#[derive(Debug)]
pub struct QueryBuilder {
    queries: Vec<SingleQuery>,
}
#[derive(Debug)]
struct SingleQuery {
    entity: String,
    fields: Vec<String>,
    filters: Vec<(String, String)>,
    order_by: Option<String>,
    order_direction: Option<String>,
    first: Option<usize>,
    skip: Option<usize>,
}

impl SingleQuery {
    pub fn has_conditions(&self) -> bool {
        !self.filters.is_empty()
            || self.order_by.is_some()
            || self.order_direction.is_some()
            || self.first.is_some()
            || self.skip.is_some()
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl QueryBuilder {
    pub fn new() -> Self {
        Self { queries: Vec::new() }
    }

    pub fn add_query(mut self, entity: &str) -> Self {
        self.queries.push(SingleQuery {
            entity: entity.to_string(),
            fields: Vec::new(),
            filters: Vec::new(),
            order_by: None,
            order_direction: None,
            first: None,
            skip: None,
        });
        self
    }

    pub fn add_field(mut self, entity: &str, field: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.fields.push(field.to_string());
        }
        self
    }

    pub fn add_filter(mut self, entity: &str, field: &str, value: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.filters.push((field.to_string(), value.to_string()));
        }
        self
    }

    pub fn set_order_by(mut self, entity: &str, field: &str, direction: &str) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.order_by = Some(field.to_string());
            query.order_direction = Some(direction.to_string());
        }
        self
    }

    pub fn set_pagination(mut self, entity: &str, first: usize, skip: Option<usize>) -> Self {
        if let Some(query) = self.queries.iter_mut().find(|q| q.entity == entity) {
            query.first = Some(first);
            query.skip = skip;
        }
        self
    }

    pub fn build(self) -> String {
        let mut query = String::from("query {");
        for q in self.queries {
            let has_conditions = q.has_conditions();
            query.push_str(&format!("\n{}", q.entity));
            if has_conditions {
                query.push('(');
            }
            // Add where clause if there are filters
            if !q.filters.is_empty() {
                query.push_str("where: {");
                for (field, value) in q.filters {
                    query.push_str(&format!("{field}: {}, ", serde_json::Value::String(value)));
                }
                query.push_str("}, ");
            }
            // Add order by if specified
            if let (Some(order_by), Some(direction)) = (q.order_by, q.order_direction) {
                query.push_str(&format!("orderBy: {order_by}, orderDirection: {direction}, "));
            }
            // Add pagination if specified
            if let Some(first) = q.first {
                query.push_str(&format!("first: {first},"));
            }
            if let Some(skip) = q.skip {
                query.push_str(&format!("skip: {skip},"));
            }
            if has_conditions {
                query.push_str(") ");
            }
            // Add fields
            query.push('{');
            for field in q.fields {
                query.push_str(&format!("{field} "));
            }
            query.push_str(" }");
        }
        query.push_str("\n}");
        query
    }
}

pub fn get_gateway_events_query(
    event_entities: &[GatewayEventEntity],
    block_range: Option<BlockRange>,
) -> String {
    let mut query_builder = QueryBuilder::new();
    for entity in event_entities {
        query_builder = entity.add_single_query(query_builder, block_range.clone());
    }
    query_builder.build()
}
// to merge get_gateway_events_query get_bridge_out_events_query later
pub fn get_bridge_out_events_query(
    event_entities: &[SwapEventEntity],
    block_range: Option<BlockRange>,
) -> String {
    let mut query_builder = QueryBuilder::new();
    for entity in event_entities {
        query_builder = entity.add_single_query(query_builder, block_range.clone());
    }
    query_builder.build()
}
