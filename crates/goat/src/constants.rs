use serde::{Deserialize, Serialize};

pub const N_SEQUENCE_FOR_LOCK_TIME: u32 = 0xFFFFFFFE; // The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid confilcts with relative timelocks.

/// Connector timelock values in bitcoin blocks.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockConfig {
    pub connector_z: u32,
    pub connector_a: u32,
    pub prover_connector: u32,
    pub connector_d: u32,
    pub watchtower_challenge: u32,
    pub operator_ack: u32,
    pub operator_commit: u32,
    pub connector_f: u32,
}

impl TimelockConfig {
    pub const fn new(
        connector_z: u32,
        connector_a: u32,
        prover_connector: u32,
        connector_d: u32,
        watchtower_challenge: u32,
        operator_ack: u32,
        operator_commit: u32,
        connector_f: u32,
    ) -> Self {
        TimelockConfig {
            connector_z,
            connector_a,
            prover_connector,
            connector_d,
            watchtower_challenge,
            operator_ack,
            operator_commit,
            connector_f,
        }
    }
}

// Commitment message parameters. Hardcoded number of bytes per message.
pub const BITCOIN_TXID_LENGTH: usize = 32;
