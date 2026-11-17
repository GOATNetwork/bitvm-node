use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GuardianConnector {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
}

impl GuardianConnector {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey) -> Self {
        GuardianConnector { network, operator_taproot_public_key: *operator_taproot_public_key }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.operator_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for GuardianConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.operator_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.generate_taproot_spend_info().output_key(), self.network)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PrekickoffConnector {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
}

impl PrekickoffConnector {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey) -> Self {
        PrekickoffConnector { network, operator_taproot_public_key: *operator_taproot_public_key }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.operator_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for PrekickoffConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.operator_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.generate_taproot_spend_info().output_key(), self.network)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickoffConnector {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
}

impl KickoffConnector {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey) -> Self {
        KickoffConnector { network, operator_taproot_public_key: *operator_taproot_public_key }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.operator_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for KickoffConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.operator_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.generate_taproot_spend_info().output_key(), self.network)
    }
}

/// Output 0 of the next Pre-Kickoff, spent only by the committee-signed
/// Quick-Challenge or Force-Skip-Kickoff. The operator holds no key to it, so
/// it cannot sweep the output and make those penalties unspendable.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ForceSkipConnector {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl ForceSkipConnector {
    pub fn new(network: Network, n_of_n_taproot_public_key: &XOnlyPublicKey) -> Self {
        ForceSkipConnector { network, n_of_n_taproot_public_key: *n_of_n_taproot_public_key }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}

impl TaprootConnector for ForceSkipConnector {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.generate_taproot_spend_info().output_key(), self.network)
    }
}
