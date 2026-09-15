use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use indexmap::IndexMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use strum::{Display, EnumString};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerializableTxid(pub Txid);

impl From<Txid> for SerializableTxid {
    fn from(txid: Txid) -> Self {
        SerializableTxid(txid)
    }
}

impl From<SerializableTxid> for Txid {
    fn from(serializable_txid: SerializableTxid) -> Self {
        serializable_txid.0
    }
}

impl Default for SerializableTxid {
    fn default() -> Self {
        SerializableTxid(Txid::from_byte_array([0u8; 32]))
    }
}
impl Serialize for SerializableTxid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializableTxid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tx_str = String::deserialize(deserializer)?;
        Ok(SerializableTxid(Txid::from_str(&tx_str).map_err(serde::de::Error::custom)?))
    }
}
impl sqlx::Type<sqlx::Sqlite> for SerializableTxid {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Sqlite> for SerializableTxid {
    fn encode_by_ref(
        &self,
        args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let hex_string = self.0.to_string();
        <String as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&hex_string, args)
    }
}

impl sqlx::Decode<'_, sqlx::Sqlite> for SerializableTxid {
    fn decode(
        value: sqlx::sqlite::SqliteValueRef<'_>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let hex_string = <String as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let txid = Txid::from_str(&hex_string)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(SerializableTxid(txid))
    }
}

macro_rules! define_numeric_array {
    ($name:ident, $size:expr) => {
        define_numeric_array!($name, $size, u8);
    };
    ($name:ident, $size:expr, $type:ty) => {
        #[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
        pub struct $name(pub [$type; $size]);

        impl TryFrom<String> for $name {
            type Error = sqlx::Error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let bytes = hex::decode(value).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

                if bytes.len() != $size * std::mem::size_of::<$type>() {
                    return Err(sqlx::Error::Decode(
                        format!(
                            "Expected {} bytes, got {}",
                            $size * std::mem::size_of::<$type>(),
                            bytes.len()
                        )
                        .into(),
                    ));
                }

                let mut array = [0 as $type; $size];
                for (i, chunk) in bytes.chunks(std::mem::size_of::<$type>()).enumerate() {
                    if i < $size {
                        let mut bytes_array = [0u8; std::mem::size_of::<$type>()];
                        bytes_array.copy_from_slice(chunk);
                        array[i] = <$type>::from_le_bytes(bytes_array);
                    }
                }
                Ok($name(array))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                let mut bytes = Vec::new();
                for &val in &value.0 {
                    bytes.extend_from_slice(&val.to_le_bytes());
                }
                hex::encode(bytes)
            }
        }

        impl sqlx::Type<sqlx::Sqlite> for $name {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <String as sqlx::Type<sqlx::Sqlite>>::type_info()
            }
        }

        impl sqlx::Encode<'_, sqlx::Sqlite> for $name {
            fn encode_by_ref(
                &self,
                args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
            ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
                let hex_string = hex::encode(
                    self.0.iter().flat_map(|&val| val.to_le_bytes()).collect::<Vec<_>>(),
                );
                <String as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&hex_string, args)
            }
        }

        impl sqlx::Decode<'_, sqlx::Sqlite> for $name {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'_>,
            ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                let string = <String as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
                string
                    .try_into()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        }
    };
}

define_numeric_array!(ByteArray32, 32);
define_numeric_array!(UInt64Array3, 3, u64);

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Node {
    pub peer_id: String,
    pub actor: String,
    pub node_name: String,
    pub goat_addr: String,
    pub btc_pub_key: String,
    pub socket_addr: String,
    pub reward: String,
    pub service_fee_rate: f64,
    pub available_peg_btc: String,
    pub updated_at: i64,
    pub created_at: i64,
}

/// tem query data
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodesOverview {
    pub total: i64,
    pub online_operators: i64,
    pub offline_operators: i64,
    pub online_verifiers: i64,
    pub offline_verifiers: i64,
    pub online_committees: i64,
    pub offline_committees: i64,
    pub online_watchtowers: i64,
    pub offline_watchtowers: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommitteeSignatures {
    pub pubkey: Vec<u8>,
    pub l1_sig: Vec<u8>,
    pub l2_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Display, EnumString)]
pub enum InstanceBridgeInStatus {
    #[default]
    UserIniting, // front has call contract, but node not get event
    UserInited, // from contract event request
    // committee won't answer if userRequest is invalid(e.g. insufficient fee)
    CommitteesAnswered,        // enough committee responsed & window expired
    UserBroadcastPeginPrepare, // user pegin prepare
    Presigned,                 // enough graphs completed committee pre-signing
    PresignedFailed,           // required graph pre-signing did not finish in time
    RelayerL1Broadcasted,      // PeginConfirm broadcast by relayer
    RelayerL2Minted,           // success
    RelayerL2MintedFailed,
    Timeout,                    // time to cancle bridgein
    UserCanceled,               // user broadcast Pegin-cancel tx
    NoEnoughCommitteesAnswered, // no enough committee responsed & window expired
    UserDiscarded,              // pegin prepare tx input uxto been spent in other tx

    // for front end display
    Initiated,  // UserInited
    Verified,   // CommitteesAnswered
    Submitted,  // UserBroadcastPeginPrepare
    Failed,     // PresignedFailed, RelayerL2MintedFailed, NoEnoughCommitteesAnswered, UserDiscarded
    Processing, // Presigned, RelayerL1Broadcasted
    Success,    // RelayerL2Minted
    Canceled,   // UserCanceled
}

/// Lifecycle of a swap-based bridge-out escrow.
///
/// `Initialize`, `Claim`, and `Refund` mirror the swap contract events;
/// `Timeout` is derived locally when the refund deadline passes without an
/// observed claim. A later on-chain Claim/Refund event still overrides it.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Display, EnumString)]
pub enum SwapEscrowStatus {
    #[default]
    Initialize,
    Claim,
    Timeout,
    Refund,
}

/// Normalize an escrow hash to its canonical storage form:
/// lowercase, 0x-prefixed 32-byte hex.
pub fn normalize_escrow_hash(escrow_hash: &str) -> String {
    let stripped = escrow_hash
        .strip_prefix("0x")
        .or_else(|| escrow_hash.strip_prefix("0X"))
        .unwrap_or(escrow_hash);
    format!("0x{}", stripped.to_ascii_lowercase())
}

/// A swap-based bridge-out escrow, keyed by the on-chain escrow hash.
/// Fully independent of the BitVM `Instance`/`Graph` flow.
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct SwapEscrow {
    pub escrow_hash: String, // 0x-prefixed 32-byte hex, lowercase
    pub network: String,
    pub status: String,              // SwapEscrowStatus
    pub offerer_addr: String,        // goat account funding the escrow
    pub claimer_addr: String,        // goat account entitled to claim
    pub btc_addr: String,            // btc address receiving the payout
    pub token: String,               // escrow token contract address
    pub amount: String,              // escrow amount, U256 decimal string
    pub refund_deadline: i64,        // unix secs after which refund is possible
    pub escrow_data: Option<String>, // hex abi-encoded EscrowData from the Initialize tx
    pub init_tx_hash: String,        // swap Initialize goat tx
    pub init_tx_height: i64,
    pub claim_tx_hash: String,                    // swap Claim goat tx
    pub claim_btc_txid: Option<SerializableTxid>, // btc payout tx committed by the claim
    pub refund_tx_hash: String,                   // swap Refund goat tx
    pub status_updated_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    pub instance_id: Uuid,
    pub network: String,
    pub from_addr: String,
    pub to_addr: String, // goat deposit addr
    pub amount: i64,
    pub fees: UInt64Array3,
    pub input_utxos: String,  // init should been []
    pub status: String,       // InstanceBridgeInStatus
    pub goat_tx_hash: String, // pegin Request tx
    pub goat_tx_height: i64,
    pub user_xonly_pubkey: ByteArray32,
    pub user_change_addr: String,
    pub user_refund_addr: String,
    pub btc_txid: Option<SerializableTxid>, // Pegin Prepare Request tx
    pub btc_height: i64,
    pub pegin_confirm_txid: Option<SerializableTxid>, // btc txid
    pub pegin_cancel_txid: Option<SerializableTxid>,  // btc txid
    #[sqlx(json)]
    pub committees_answers: IndexMap<String, Vec<u8>>,
    pub pegin_data_tx_hash: String,
    pub parameters: Option<String>,
    pub post_pegin_txhash: Option<String>,
    pub status_updated_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct BridgeOutGlobalStats {
    pub id: i64,
    pub initial_txn: i64,
    pub initial_amount: String,
    pub claim_txn: i64,
    pub claim_amount: String,
    pub refund_txn: i64,
    pub refund_amount: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// graph status
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    OperatorDataPushed,
    PreKickoff,
    OperatorKickOff,
    Challenge,
    Disprove,
    Obsoleted, // reimbursement by other operators
    Skipped,
    OperatorTake1,
    OperatorTake2,

    /// frontend use only
    Created,
    Presigned,
    L2Recorded,
    OperatorKickOffing,
    Challenging,
    Disproving,
}

/// The evidence that authorizes a graph status transition.
///
/// Graph definitions, finalized Goat events, and chain reconciliation have
/// different authority. Keeping the source explicit prevents a generic
/// database update from accidentally becoming a state-transition bypass.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GraphStatusSource {
    Definition,
    GoatEvent,
    ChainReconcile,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GraphStatusTransitionOutcome {
    Applied,
    AlreadyCurrent,
    Rejected { current: GraphStatus },
    NotFound,
}

impl GraphStatus {
    pub fn get_closed_status() -> Vec<GraphStatus> {
        vec![
            GraphStatus::OperatorTake1,
            GraphStatus::OperatorTake2,
            GraphStatus::Skipped,
            GraphStatus::Disprove,
        ]
    }
    pub fn get_pegin_finalized_status() -> GraphStatus {
        GraphStatus::OperatorDataPushed
    }

    pub fn get_pegout_started_status() -> Vec<GraphStatus> {
        vec![GraphStatus::OperatorKickOff, GraphStatus::Challenge]
    }

    pub fn is_pegin_finalized(&self) -> bool {
        GraphStatus::get_pegin_finalized_status().eq(self)
    }
    pub fn is_pegout_started(&self) -> bool {
        GraphStatus::get_pegout_started_status().contains(self)
    }
    pub fn is_closed(&self) -> bool {
        GraphStatus::get_closed_status().contains(self)
    }
    pub fn is_obsoleted(&self) -> bool {
        self.eq(&GraphStatus::Obsoleted)
    }

    /// Whether this is a backend protocol state rather than a frontend-only
    /// display alias.
    pub fn is_protocol_status(self) -> bool {
        matches!(
            self,
            Self::OperatorPresigned
                | Self::CommitteePresigned
                | Self::OperatorDataPushed
                | Self::PreKickoff
                | Self::OperatorKickOff
                | Self::Challenge
                | Self::Disprove
                | Self::Obsoleted
                | Self::Skipped
                | Self::OperatorTake1
                | Self::OperatorTake2
        )
    }

    /// States from which `self` may be reached with the supplied evidence.
    ///
    /// These sets intentionally contain transitive predecessors. A chain scan
    /// can observe several confirmed transactions in one pass, so requiring a
    /// locally persisted intermediate state would make recovery after restart
    /// impossible. Closed states are deliberately absent from all sets.
    pub fn allowed_transition_from(self, source: GraphStatusSource) -> &'static [GraphStatus] {
        use GraphStatus::*;

        const EARLY: &[GraphStatus] = &[OperatorPresigned, CommitteePresigned];
        const EARLY_OR_OBSOLETED: &[GraphStatus] =
            &[OperatorPresigned, CommitteePresigned, Obsoleted];
        const PRE_KICKOFF: &[GraphStatus] =
            &[OperatorPresigned, CommitteePresigned, OperatorDataPushed, Obsoleted];
        const KICKOFF: &[GraphStatus] =
            &[OperatorPresigned, CommitteePresigned, OperatorDataPushed, PreKickoff, Obsoleted];
        const CHALLENGE: &[GraphStatus] = &[
            OperatorPresigned,
            CommitteePresigned,
            OperatorDataPushed,
            PreKickoff,
            Obsoleted,
            OperatorKickOff,
        ];
        const TAKE1: &[GraphStatus] = &[
            OperatorPresigned,
            CommitteePresigned,
            OperatorDataPushed,
            PreKickoff,
            Obsoleted,
            OperatorKickOff,
        ];
        const TAKE2_OR_DISPROVE: &[GraphStatus] = &[
            OperatorPresigned,
            CommitteePresigned,
            OperatorDataPushed,
            PreKickoff,
            Obsoleted,
            OperatorKickOff,
            Challenge,
        ];
        const SKIPPED: &[GraphStatus] =
            &[OperatorPresigned, CommitteePresigned, OperatorDataPushed, PreKickoff, Obsoleted];
        const OBSOLETED: &[GraphStatus] = &[
            OperatorPresigned,
            CommitteePresigned,
            OperatorDataPushed,
            PreKickoff,
            OperatorKickOff,
            Challenge,
        ];

        match source {
            GraphStatusSource::Definition => match self {
                CommitteePresigned => &[OperatorPresigned],
                _ => &[],
            },
            GraphStatusSource::GoatEvent => match self {
                OperatorDataPushed => EARLY,
                OperatorTake1 => TAKE1,
                OperatorTake2 | Disprove => TAKE2_OR_DISPROVE,
                _ => &[],
            },
            GraphStatusSource::ChainReconcile => match self {
                CommitteePresigned => &[OperatorPresigned],
                OperatorDataPushed => EARLY_OR_OBSOLETED,
                Obsoleted => OBSOLETED,
                PreKickoff => PRE_KICKOFF,
                OperatorKickOff => KICKOFF,
                Challenge => CHALLENGE,
                OperatorTake1 => TAKE1,
                OperatorTake2 | Disprove => TAKE2_OR_DISPROVE,
                Skipped => SKIPPED,
                OperatorPresigned | Created | Presigned | L2Recorded | OperatorKickOffing
                | Challenging | Disproving => &[],
            },
        }
    }
}

/// graph detail
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Graph {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub kickoff_index: i64,
    pub from_addr: String,
    pub to_addr: String, //operator_receive_address
    pub amount: i64,
    pub challenge_amount: i64,
    pub status: String,     // GraphStatus
    pub sub_status: String, // GraphStatus
    pub operator_pubkey: String,
    /// Canonical hash of the immutable graph parameters. This binds the
    /// runtime projection to exactly one transaction-graph definition.
    pub definition_hash: String,
    pub next_prekickoff: Option<SerializableTxid>,
    pub cur_prekickoff_txid: Option<SerializableTxid>,
    pub force_skip_kickoff_txid: Option<SerializableTxid>,
    pub quick_challenge_txid: Option<SerializableTxid>,
    pub challenge_incomplete_kickoff_txid: Option<SerializableTxid>,
    pub pegin_txid: Option<SerializableTxid>,
    pub kickoff_txid: Option<SerializableTxid>,
    pub take1_txid: Option<SerializableTxid>,
    pub challenge_txid: Option<SerializableTxid>,
    pub take2_txid: Option<SerializableTxid>,
    pub watchtower_challenge_init_txid: Option<SerializableTxid>,
    pub operator_assert_txid: Option<SerializableTxid>,
    #[sqlx(json)]
    pub verifier_assert_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub disprove_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub watchtower_challenge_timeout_txids: Vec<SerializableTxid>,
    #[sqlx(json)]
    pub operator_challenge_nack_txids: Vec<SerializableTxid>,
    pub operator_commit_timeout_txid: Option<SerializableTxid>,
    pub init_withdraw_tx_hash: Option<String>,
    pub bridge_out_start_at: i64,
    pub status_updated_at: i64,
    pub proceed_withdraw_height: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphBtcTxVoutMonitor {
    pub graph_id: Uuid,
    pub tx_name: String,
    pub txid: SerializableTxid,
    pub height: i64,
    pub vout_len: i64,
    pub monitor_data: String, // GraphStatus
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Display, EnumString)]
pub enum MessageState {
    Pending,
    Processed,
    Failed,
    Expired,
    Cancelled,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct Message {
    pub message_id: String,
    pub business_id: Uuid, // graph_id or instance_id
    pub actor: String,
    pub from_peer: String,
    pub msg_type: String,
    pub content: Vec<u8>,
    pub state: String,
    pub message_version: i64,
    pub weight: i64,
    pub lock_time_until: i64,
    pub created_at: i64,
}

/// A durable copy of a message received from the P2P network.
///
/// Unlike `Message`, which is used for locally generated compensation work,
/// this row retains the original sender and is consumed before dispatching the
/// external message. Processed content is cleared, while failed content is
/// retained for manual requeue and later TTL cleanup.
#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct P2pInboxMessage {
    pub message_id: String,
    pub business_id: Option<Uuid>,
    pub actor: String,
    pub from_peer: String,
    pub msg_type: String,
    pub content: Vec<u8>,
    pub content_size: i64,
    pub state: String,
    pub attempt_count: i64,
    pub next_retry_at: i64,
    pub lease_until: i64,
    pub lease_token: String,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct P2pOutboxMessage {
    pub message_id: String,
    pub msg_type: String,
    pub content: Vec<u8>,
    pub state: String,
    pub attempt_count: i64,
    pub next_retry_at: i64,
    pub lease_until: i64,
    pub last_error: Option<String>,
    pub retry_until: i64,
    pub retry_interval_secs: i64,
    pub ack_peer_id: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, FromRow)]
pub struct MessageDebugOverview {
    pub message_id: String,
    pub actor: String,
    pub msg_type: String,
    pub state: String,
    pub lock_time_until: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub reason_count: i64,
    pub last_reason_code: Option<String>,
    pub last_reason_detail: Option<String>,
    pub last_reason_seen_at: Option<i64>,
}

#[derive(Clone, Debug, FromRow)]
pub struct MessageDebugReason {
    pub reason_code: String,
    pub reason_detail: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub occurrences: i64,
}

#[derive(Clone, Debug, FromRow, PartialEq, Eq)]
pub struct MetricsStateCount {
    pub category: String,
    pub state: String,
    pub count: i64,
    pub oldest_created_at: Option<i64>,
    pub last_success_at: Option<i64>,
}

/// Aggregate, local-only values used for alerting. These values intentionally
/// contain no business identifiers so they can be exported as Prometheus gauges.
#[derive(Clone, FromRow, Debug, Default)]
pub struct NodeAlertMetricsSnapshot {
    pub pegin_oldest_active_status_updated_at: Option<i64>,
    pub pegin_oldest_committee_wait_status_updated_at: Option<i64>,
    pub pegout_oldest_active_status_updated_at: Option<i64>,
    pub operator_available_pegbtc: Option<String>,
}

/// Aggregate event watcher progress used to expose a bounded health state.
#[derive(Clone, FromRow, Debug, Default)]
pub struct EventWatchMetricsSnapshot {
    pub lag_blocks: i64,
    pub watcher_count: i64,
    pub syncing_count: i64,
    pub failed_count: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct PeginInstanceProcessData {
    pub instance_id: Uuid,
    pub process_data: String,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct PeginGraphProcessData {
    pub graph_id: Uuid,
    pub instance_id: Uuid,
    pub process_data: String,
    pub is_endorsed: bool,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct PendingGraphInit {
    pub instance_id: Uuid,
    pub operator_pubkey: String,
    pub graph_id: Uuid,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Display, EnumString)]
pub enum MessageType {
    None,
    PeginRequest,
    CreateGraph,
    ConfirmInstance,
    InitGraph,
    GenCircuits,
    CutCircuits,
    SolderingProof,
    VerifierGraphParamsEndorsement,
    NonceGeneration,
    AggNonceConsensus,
    CommitteePresign,
    GraphFinalize,
    EndorseGraph,
    PeginConfirmNonce,
    PeginConfirmNonceConsensus,
    PeginConfirmPartialSig,
    PostReady,
    KickoffReady,
    KickoffSent,
    PreKickoffSent,
    ChallengeSent,
    WatchtowerChallengeInitSent,
    WatchtowerChallengeSent,
    WatchtowerChallengeTimeout,
    NackReady,
    OperatorCommitPubinReady,
    OperatorCommitPubinTimeout,
    AssertReady,
    AssertSent,
    ChallengeAssertSent,
    WronglyChallengeTimeout,
    DisproveSent,
    Take1Ready,
    Take1Sent,
    Take2Ready,
    Take2Sent,
    RequestNodeInfo,
    ResponseNodeInfo,
    SyncGraphRequest,
    SyncGraph,
    InstanceDiscarded,
    Tick,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum WatchContractStatus {
    #[default]
    UnSync,
    Syncing,
    Synced,
    Failed,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct WatchContract {
    pub contract_addr: String,
    pub the_graph_url: String,
    pub gap: i64,
    pub from_height: i64,
    pub status: String,
    pub extra: Option<String>,
    pub updated_at: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum GoatTxType {
    #[default]
    Normal,
    BridgeInRequest,
    CommitteeAnswer,
    BridgeIn,
    PostPeginData,
    PostOperatorData,
    InitWithdraw,
    CancelWithdraw,
    ProceedWithdraw,
    WithdrawHappyPath,
    WithdrawUnhappyPath,
    WithdrawDisproved,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum GoatTxProcessingStatus {
    #[default]
    Skipped,
    Pending,
    Processed,
    Failed,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxRecord {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub tx_type: String,
    pub tx_hash: String,
    pub height: i64,
    pub is_local: bool,
    pub processing_status: String,
    pub extra: Option<String>,
    pub created_at: i64,
}
impl GoatTxRecord {
    pub fn new(graph_id: Uuid, tx_type: String) -> Self {
        Self {
            graph_id,
            instance_id: Uuid::nil(),
            tx_type,
            tx_hash: String::new(),
            height: 0,
            is_local: false,
            processing_status: GoatTxProcessingStatus::Skipped.to_string(),
            extra: None,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        }
    }

    pub fn with_instance_id(mut self, instance_id: Uuid) -> Self {
        self.instance_id = instance_id;
        self
    }

    pub fn with_tx_hash(mut self, tx_hash: String) -> Self {
        self.tx_hash = tx_hash;
        self
    }

    pub fn with_height(mut self, height: i64) -> Self {
        self.height = height;
        self
    }

    pub fn is_local(&self) -> bool {
        self.is_local
    }

    pub fn without_extra(mut self, extra: Option<String>) -> Self {
        self.extra = extra;
        self
    }

    pub fn with_is_local(mut self, is_local: bool) -> Self {
        self.is_local = is_local;
        self
    }

    pub fn with_processing_status(mut self, processing_status: String) -> Self {
        self.processing_status = processing_status;
        self
    }

    pub fn is_processed(&self) -> bool {
        self.processing_status == GoatTxProcessingStatus::Processed.to_string()
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct GraphRawData {
    pub graph_id: Uuid,
    pub raw_data: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GoatTxProceedWithdrawExtra {
    pub challenge_txid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, Display, EnumString)]
pub enum ProofState {
    #[default]
    New,
    Proving,
    Proven,
    Failed,
}
impl ProofState {
    pub fn to_i64(&self) -> i64 {
        match self {
            Self::New => 0,
            Self::Proving => 1,
            Self::Proven => 2,
            Self::Failed => 3,
        }
    }

    pub fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::New),
            1 => Some(Self::Proving),
            2 => Some(Self::Proven),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct WatchtowerProof {
    pub id: i64,
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub public_key: String,
    pub challenge_txid: SerializableTxid,
    pub challenge_init_txid: SerializableTxid,
    pub execution_layer_block_number: i64,
    pub path_to_proof: Option<String>,
    pub public_value_hex: Option<String>,
    pub proof_size: i64,
    pub cycles: i64,
    pub proof_state: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub zkm_version: String,
    pub node_index: i32,
    pub included: bool,
    pub extra: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct OperatorProof {
    pub id: i64,
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_committed_blockhash: String,
    pub execution_layer_block_number: i64,
    pub path_to_proof: Option<String>,
    pub public_value_hex: Option<String>,
    pub proof_size: i64,
    pub cycles: i64,
    pub proof_state: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub zkm_version: String,
    pub extra: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct LongRunningTaskProof {
    pub block_start: i64,
    pub block_end: i64,
    pub chain_name: String,
    pub path_to_proof: Option<String>,
    pub public_value_hex: Option<String>,
    pub proof_size: i64,
    pub cycles: i64,
    pub proof_state: i64,
    pub total_time_to_proof: i64,
    pub proving_time: i64,
    pub zkm_version: String,
    pub extra: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct SequencerSetHashChange {
    pub id: i64,
    pub cosmos_block_height: i64,
    pub goat_block_height: i64,
    pub validators_hash: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, FromRow, Debug, Serialize, Deserialize, Default)]
pub struct SequencerSetScanState {
    pub id: i64,
    pub next_cosmos_block_height: i64,
    pub latest_goat_block_height: i64,
    pub latest_validators_hash: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_status_from_str() {
        assert_eq!(GraphStatus::from_str("Created").unwrap(), GraphStatus::Created);
        assert_eq!(
            GraphStatus::from_str("OperatorPresigned").unwrap(),
            GraphStatus::OperatorPresigned
        );
        assert!(GraphStatus::from_str("Invalid").is_err());
    }

    #[test]
    fn test_graph_status_display() {
        assert_eq!(GraphStatus::Created.to_string(), "Created");
        assert_eq!(GraphStatus::OperatorPresigned.to_string(), "OperatorPresigned");
    }

    #[test]
    fn test_bridge_in_status_from_str() {
        assert_eq!(
            InstanceBridgeInStatus::from_str("RelayerL2Minted").unwrap(),
            InstanceBridgeInStatus::RelayerL2Minted
        );
        assert!(InstanceBridgeInStatus::from_str("Invalid").is_err());
    }

    #[test]
    fn test_message_type_from_str() {
        assert_eq!(MessageType::from_str("PeginRequest").unwrap(), MessageType::PeginRequest);
        assert_eq!(MessageType::from_str("CreateGraph").unwrap(), MessageType::CreateGraph);
        assert!(MessageType::from_str("Invalid").is_err());
    }

    #[test]
    fn test_byte_array_macro() {
        let bytes = ByteArray32([1u8; 32]);
        let hex_str: String = bytes.into();
        let parsed: ByteArray32 = hex_str.try_into().unwrap();
        assert_eq!(bytes.0, parsed.0);

        define_numeric_array!(U32Array2, 2, u32);
        let u32_array = U32Array2([123u32, 456u32]);
        let hex_str: String = u32_array.into();
        let parsed: U32Array2 = hex_str.try_into().unwrap();
        assert_eq!(u32_array.0, parsed.0);

        define_numeric_array!(I64Array1, 1, i64);
        let i64_array = I64Array1([-123i64]);
        let hex_str: String = i64_array.into();
        let parsed: I64Array1 = hex_str.try_into().unwrap();
        assert_eq!(i64_array.0, parsed.0);
    }
}
