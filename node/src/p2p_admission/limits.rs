//! Message size limits and inbox quotas per sender class, from the
//! environment.

use crate::middleware::behaviour::MAX_GOSSIPSUB_TRANSMIT_SIZE;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quota {
    pub rows: i64,
    pub bytes: i64,
}

impl Quota {
    pub(super) fn admits(&self, rows: i64, bytes: i64) -> bool {
        rows <= self.rows && bytes <= self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundLimits {
    pub max_json_bytes: usize,
    pub max_binary_bytes: usize,
    /// Every stored network event, whatever its class.
    pub global: Quota,
    /// Part of the global budget only committee senders may fill.
    pub committee_reserve: Quota,
    /// Every stored network event of one registered sender, in whichever class.
    pub registered_peer: Quota,
}

impl InboundLimits {
    /// Derive byte quotas from the global ceiling; row limits remain fixed.
    pub fn with_inbox_bytes(max_json_bytes: usize, max_inbox_bytes: i64) -> Self {
        Self {
            max_json_bytes,
            max_binary_bytes: MAX_GOSSIPSUB_TRANSMIT_SIZE,
            global: Quota { rows: 16_384, bytes: max_inbox_bytes },
            committee_reserve: Quota { rows: 4_096, bytes: max_inbox_bytes / 4 },
            registered_peer: Quota { rows: 1_024, bytes: max_inbox_bytes / 8 },
        }
    }

    pub fn from_env() -> Self {
        Self::with_inbox_bytes(
            crate::env::get_p2p_max_json_message_bytes(),
            crate::env::get_p2p_inbox_max_bytes(),
        )
    }
}

static INBOUND_LIMITS: LazyLock<InboundLimits> = LazyLock::new(InboundLimits::from_env);

pub fn inbound_limits() -> &'static InboundLimits {
    &INBOUND_LIMITS
}
