use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::{chunk::api::type_conversion_utils::script_to_witness, treepp::*};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::{assert_scripts::LabelHash, constants::TimelockConfig};

use super::{
    super::{error::Error, scripts::*, transactions::base::Input},
    base::*,
};

pub type WatchtowerConnectors = (WatchtowerChallengeConnector, AckConnector);

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WatchtowerChallengeConnector {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub watchtower_taproot_public_key: XOnlyPublicKey,
    pub watchtower_challenge_blocks_timelock: u32,
}
impl WatchtowerChallengeConnector {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        watchtower_taproot_public_key: &XOnlyPublicKey,
        timelock_config: &TimelockConfig,
    ) -> Self {
        WatchtowerChallengeConnector {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            watchtower_taproot_public_key: *watchtower_taproot_public_key,
            watchtower_challenge_blocks_timelock: timelock_config.watchtower_challenge,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        // for Watchtower-Challenge tx
        generate_pay_to_pubkey_taproot_script(&self.watchtower_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        // for Watchtower-Challenge-Timeout tx
        generate_timelock_taproot_script(
            &self.operator_taproot_public_key,
            self.watchtower_challenge_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.watchtower_challenge_blocks_timelock)
    }
}
impl TaprootConnector for WatchtowerChallengeConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(SECP256K1, self.watchtower_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AckConnector {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub hashlock: LabelHash,
    pub ack_blocks_timelock: u32,
}

impl AckConnector {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        hashlock: LabelHash,
        timelock_config: &TimelockConfig,
    ) -> Self {
        AckConnector {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            ack_blocks_timelock: timelock_config.operator_ack,
            hashlock,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        // for Watchtower-Challenge-Timeout tx
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        // for Operator-Challenge-ACK tx
        script! {
            OP_HASH160
            { self.hashlock.to_vec() }
            OP_EQUALVERIFY
            OP_TRUE
        }
        .compile()
    }

    pub fn generate_leaf_1_unlock_data(&self, preimage: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let witness_script = script! {
            { preimage.to_vec() }
        };
        let witness = script_to_witness(witness_script.clone());
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_1_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => Ok(witness),
            false => Err(Error::Other("Invalid preimage for ACK connector.")),
        }
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_2_script(&self) -> ScriptBuf {
        // for Operator-Challenge-NACK tx
        generate_timelock_taproot_script(&self.n_of_n_taproot_public_key, self.ack_blocks_timelock)
    }

    fn generate_taproot_leaf_2_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.ack_blocks_timelock)
    }
}

impl TaprootConnector for AckConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            2 => self.generate_taproot_leaf_2_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            2 => self.generate_taproot_leaf_2_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(2, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(2, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .add_leaf(1, self.generate_taproot_leaf_2_script())
            .expect("Unable to add leaf 2")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
