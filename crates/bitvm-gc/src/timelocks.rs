use anyhow::{Result, bail};
use bitcoin::Network;
use goat::constants::TimelockConfig;

pub const NODE_BITCOIN_BLOCK_INTERVAL_SECS: i64 = 600;
pub const NODE_TESTNET_BLOCK_INTERVAL_SECS: i64 = 300;
pub const NODE_SIGNET_BLOCK_INTERVAL_SECS: i64 = 60;
pub const NODE_REGTEST_BLOCK_INTERVAL_SECS: i64 = 60;

pub const NODE_BITCOIN_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 144,
    connector_a: 144,
    prover_connector: 144,
    connector_d: 432,
    watchtower_challenge: 144,
    operator_ack: 288,
    operator_commit: 432,
    connector_f: 576,
};
pub const NODE_TESTNET_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 100,
    connector_a: 6,
    prover_connector: 16,
    connector_d: 32,
    watchtower_challenge: 20,
    operator_ack: 28,
    operator_commit: 42,
    connector_f: 56,
};
pub const NODE_SIGNET_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 6,
    connector_a: 6,
    prover_connector: 6,
    connector_d: 18,
    watchtower_challenge: 6,
    operator_ack: 12,
    operator_commit: 18,
    connector_f: 24,
};
pub const NODE_REGTEST_TIMELOCK_CONFIG: TimelockConfig = TimelockConfig {
    connector_z: 1,
    connector_a: 2,
    prover_connector: 1,
    connector_d: 3,
    watchtower_challenge: 1,
    operator_ack: 2,
    operator_commit: 3,
    connector_f: 4,
};

pub fn default_timelock_config(network: Network) -> TimelockConfig {
    match network {
        Network::Bitcoin => NODE_BITCOIN_TIMELOCK_CONFIG,
        Network::Testnet | Network::Testnet4 => NODE_TESTNET_TIMELOCK_CONFIG,
        Network::Signet => NODE_SIGNET_TIMELOCK_CONFIG,
        Network::Regtest => NODE_REGTEST_TIMELOCK_CONFIG,
    }
}

pub fn estimated_block_interval_secs(network: Network) -> i64 {
    match network {
        Network::Bitcoin => NODE_BITCOIN_BLOCK_INTERVAL_SECS,
        Network::Testnet | Network::Testnet4 => NODE_TESTNET_BLOCK_INTERVAL_SECS,
        Network::Signet => NODE_SIGNET_BLOCK_INTERVAL_SECS,
        Network::Regtest => NODE_REGTEST_BLOCK_INTERVAL_SECS,
    }
}

/// Non-serialized timing policy used to validate the on-chain timelock config.
///
/// A graph commits to the CSV values, while every node applies this local network
/// policy before accepting those values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolTimingBudget {
    /// Confirmation depth required before downstream Bitcoin evidence is used.
    pub evidence_confirmations: u32,
    /// Event discovery, P2P propagation, scheduling, and local signing.
    pub reaction_blocks: u32,
    /// P99 time for a watchtower to retrieve and prepare its proof commitment.
    pub watchtower_proof_blocks: u32,
    /// Target blocks for a transaction to be included, including fee bumping.
    pub inclusion_blocks: u32,
    /// Reorg and transient service failure allowance.
    pub safety_blocks: u32,
}

impl ProtocolTimingBudget {
    const fn action_window(self) -> u32 {
        self.reaction_blocks
            .saturating_add(self.inclusion_blocks)
            .saturating_add(self.safety_blocks)
    }

    const fn watchtower_proof_window(self) -> u32 {
        self.action_window().saturating_add(self.watchtower_proof_blocks)
    }

    const fn confirmed_action_window(self) -> u32 {
        self.evidence_confirmations
            .saturating_add(self.inclusion_blocks)
            .saturating_add(self.safety_blocks)
    }
}

const BITCOIN_TIMING_BUDGET: ProtocolTimingBudget = ProtocolTimingBudget {
    evidence_confirmations: 6,
    reaction_blocks: 6,
    watchtower_proof_blocks: 24,
    inclusion_blocks: 6,
    safety_blocks: 6,
};

const TESTNET_TIMING_BUDGET: ProtocolTimingBudget = ProtocolTimingBudget {
    evidence_confirmations: 10,
    reaction_blocks: 2,
    watchtower_proof_blocks: 12,
    inclusion_blocks: 2,
    safety_blocks: 2,
};

const SIGNET_TIMING_BUDGET: ProtocolTimingBudget = ProtocolTimingBudget {
    evidence_confirmations: 1,
    reaction_blocks: 1,
    watchtower_proof_blocks: 2,
    inclusion_blocks: 1,
    safety_blocks: 1,
};

const REGTEST_TIMING_BUDGET: ProtocolTimingBudget = ProtocolTimingBudget {
    evidence_confirmations: 0,
    reaction_blocks: 1,
    watchtower_proof_blocks: 0,
    inclusion_blocks: 0,
    safety_blocks: 0,
};

pub fn protocol_timing_budget(network: Network) -> ProtocolTimingBudget {
    match network {
        Network::Bitcoin => BITCOIN_TIMING_BUDGET,
        Network::Testnet | Network::Testnet4 => TESTNET_TIMING_BUDGET,
        Network::Signet => SIGNET_TIMING_BUDGET,
        Network::Regtest => REGTEST_TIMING_BUDGET,
    }
}

pub fn validate_timelock_config(network: Network, config: &TimelockConfig) -> Result<()> {
    let budget = protocol_timing_budget(network);
    for (name, value) in [
        ("connector_z", config.connector_z),
        ("connector_a", config.connector_a),
        ("prover_connector", config.prover_connector),
        ("connector_d", config.connector_d),
        ("watchtower_challenge", config.watchtower_challenge),
        ("operator_ack", config.operator_ack),
        ("operator_commit", config.operator_commit),
        ("connector_f", config.connector_f),
    ] {
        ensure_bip68_height_based_sequence(name, value)?;
        if value < budget.reaction_blocks {
            bail!(
                "timelock_config.{name} must be at least {} reaction blocks, got {value}",
                budget.reaction_blocks,
            );
        }
    }
    let default_connector_z = default_timelock_config(network).connector_z;
    if config.connector_z != default_connector_z {
        bail!(
            "timelock_config.connector_z must remain {} because connector-z is fixed before graph construction",
            default_connector_z
        );
    }

    let action_window = budget.action_window();
    ensure_at_least("connector_a", config.connector_a, action_window)?;
    ensure_at_least(
        "watchtower_challenge",
        config.watchtower_challenge,
        budget.watchtower_proof_window(),
    )?;
    ensure_gap_at_least(
        "watchtower_challenge",
        config.watchtower_challenge,
        "operator_ack",
        config.operator_ack,
        action_window,
    )?;
    ensure_gap_at_least(
        "max(watchtower_challenge, operator_ack)",
        config.watchtower_challenge.max(config.operator_ack),
        "operator_commit",
        config.operator_commit,
        budget.confirmed_action_window(),
    )?;
    ensure_at_least("prover_connector", config.prover_connector, action_window)?;
    ensure_gap_at_least(
        "prover_connector",
        config.prover_connector,
        "connector_d",
        config.connector_d,
        action_window,
    )?;
    ensure_gap_at_least(
        "operator_commit",
        config.operator_commit,
        "connector_f",
        config.connector_f,
        budget.confirmed_action_window(),
    )?;

    Ok(())
}

const BIP68_BLOCKS_MASK: u32 = 0x0000_ffff;

fn ensure_bip68_height_based_sequence(name: &str, value: u32) -> Result<()> {
    if value & !BIP68_BLOCKS_MASK != 0 {
        bail!(
            "timelock_config.{name} must use a BIP68 height-based sequence value, got {value:#010x}"
        );
    }
    Ok(())
}

fn ensure_gap_at_least(
    left_name: &str,
    left: u32,
    right_name: &str,
    right: u32,
    required_blocks: u32,
) -> Result<()> {
    let actual_blocks = right.saturating_sub(left);
    if actual_blocks < required_blocks {
        bail!(
            "timelock_config.{right_name} - timelock_config.{left_name} must be at least \
             {required_blocks} blocks, got {actual_blocks}"
        );
    }
    Ok(())
}

fn ensure_at_least(name: &str, value: u32, required_blocks: u32) -> Result<()> {
    if value < required_blocks {
        bail!("timelock_config.{name} must be at least {required_blocks} blocks, got {value}");
    }
    Ok(())
}

pub fn timelock_blocks(_network: Network, blocks: u32) -> u32 {
    blocks
}

pub fn connector_z_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_z)
}

pub fn default_connector_z_timelock_blocks(network: Network) -> u32 {
    connector_z_timelock_blocks(network, &default_timelock_config(network))
}

pub fn take1_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_a)
}

pub fn take2_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_d)
}

pub fn connector_f_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.connector_f)
}

pub fn disprove_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.prover_connector)
}

pub fn watchtower_challenge_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.watchtower_challenge)
}

pub fn operator_ack_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.operator_ack)
}

pub fn operator_commit_timelock_blocks(network: Network, config: &TimelockConfig) -> u32 {
    timelock_blocks(network, config.operator_commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_default_timelock_configs_validate() {
        for (network, config) in [
            (Network::Bitcoin, NODE_BITCOIN_TIMELOCK_CONFIG),
            (Network::Testnet, NODE_TESTNET_TIMELOCK_CONFIG),
            (Network::Testnet4, NODE_TESTNET_TIMELOCK_CONFIG),
            (Network::Signet, NODE_SIGNET_TIMELOCK_CONFIG),
            (Network::Regtest, NODE_REGTEST_TIMELOCK_CONFIG),
        ] {
            assert_eq!(default_timelock_config(network), config);
            validate_timelock_config(network, &config).unwrap();
        }
    }

    #[test]
    fn rejects_non_height_based_bip68_sequences() {
        assert!(ensure_bip68_height_based_sequence("test", BIP68_BLOCKS_MASK).is_ok());

        for invalid in [1 << 16, 1 << 22, 1 << 31] {
            let error = ensure_bip68_height_based_sequence("test", invalid).unwrap_err();
            assert!(error.to_string().contains("BIP68 height-based sequence"));
        }
    }
}
