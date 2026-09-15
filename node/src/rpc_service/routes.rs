pub(crate) const ROOT: &str = "/";

pub(crate) mod v1 {
    pub const NODES_BASE: &str = "/v1/nodes";
    pub const NODES_BY_ID: &str = "/v1/nodes/{:id}";
    pub const NODES_OVERVIEW: &str = "/v1/nodes/overview";

    pub const INSTANCES_BASE: &str = "/v1/instances";
    pub const INSTANCES_SETTINGS: &str = "/v1/instances/settings";
    pub const INSTANCES_BY_ID: &str = "/v1/instances/{:id}";
    pub const INSTANCES_OVERVIEW: &str = "/v1/instances/overview";
    // TODO(auth): Restrict access before returning locally constructed cancellation PSBTs.
    pub const INSTANCES_UNSIGNED_PEGIN_TXN: &str = "/v1/instances/{:id}/unsigned-pegin-txn";

    pub const SWAPS_BASE: &str = "/v1/swaps";
    pub const SWAPS_BY_ESCROW_HASH: &str = "/v1/swaps/{:escrow_hash}";
    pub const GRAPHS_BASE: &str = "/v1/graphs";
    pub const GRAPHS_BY_ID: &str = "/v1/graphs/{:id}";
    pub const GRAPHS_READY_TO_KICKOFF: &str = "/v1/graphs/ready-to-kickoff";
    pub const GRAPHS_TXN_BY_ID: &str = "/v1/graphs/{:id}/txn";
    pub const GRAPHS_NEIGHBOR_IDS: &str = "/v1/graphs/{:id}/neighbor-ids";
    pub const GRAPHS_TX_BY_ID: &str = "/v1/graphs/{:id}/tx";
    pub const GRAPHS_SEND_CHALLENGE: &str = "/v1/graphs/{:id}/send-challenge";
    #[cfg(feature = "rpc-debug-endpoints")]
    pub const GRAPHS_SEND_VERIFIER_CHALLENGE: &str = "/v1/graphs/{:id}/send-verifier-challenge";
    pub const PEGOUT: &str = "/v1/graphs/pegout";
    // TODO(auth): Restrict debug endpoints before exposing the RPC outside trusted operators.
    #[cfg(feature = "rpc-debug-endpoints")]
    pub const DEBUG_STATUS: &str = "/v1/debug/status";
    // TODO(auth): Restrict debug endpoints before exposing the RPC outside trusted operators.
    #[cfg(feature = "rpc-debug-endpoints")]
    pub const DEBUG_GRAPH_MESSAGES: &str = "/v1/debug/graphs/{:id}/messages";
    // TODO(auth): Restrict debug endpoints before exposing the RPC outside trusted operators.
    #[cfg(feature = "rpc-debug-endpoints")]
    pub const DEBUG_INSTANCE_MESSAGES: &str = "/v1/debug/instances/{:id}/messages";
    // TODO(auth): Restrict debug endpoints before exposing the RPC outside trusted operators.
    #[cfg(feature = "rpc-debug-endpoints")]
    pub const DEBUG_MESSAGE_DETAILS: &str = "/v1/debug/messages/{:id}";
    // pub const PROOFS_BASE: &str = "/v1/proofs";
    pub const PROOFS_CHAIN_PROOFS_DESC: &str = "/v1/proofs/chain_proofs_desc";
    pub const NODES_WATCHTOWER_BASE: &str = "/v1/proofs/watchtower_proofs";
    #[allow(dead_code)]
    pub const NODES_OPERATOR_BASE: &str = "/v1/proofs/operator_proofs";
    pub const PROOFS_OPERATOR_PROOF_DESC: &str = "/v1/proofs/operator_proofs_desc";
    pub const PROOFS_WATCHTOWER_PROOF_TIMEOUT: &str = "/v1/proofs/watchtower_proofs_timeout";
    #[allow(dead_code)]
    pub const PROOFS_OPERATOR_PROOF_TIMEOUT: &str = "/v1/proofs/operator_proofs_timeout";
}
