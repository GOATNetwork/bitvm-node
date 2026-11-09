use crate::{assert_scripts::*, constants::TimelockConfig};
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::{chunk::api::type_conversion_utils::RawWitness, treepp::*};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use super::{
    super::{error::Error, scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct VerifierConnector {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    #[serde(with = "BigArray")]
    pub operator_wots_public_key: OperatorAssertPublicKey,
    #[serde(with = "BigArray")]
    pub label_hashes: [WireHash; INPUT_WIRE_NUM],
}

impl VerifierConnector {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_wots_public_key: &OperatorAssertPublicKey,
        label_hashes: [WireHash; INPUT_WIRE_NUM],
    ) -> Self {
        VerifierConnector {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            operator_wots_public_key: *operator_wots_public_key,
            label_hashes,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        verify_verifier_assert_script_768_wire(&self.operator_wots_public_key, &self.label_hashes)
            .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    pub fn generate_leaf_0_unlock_data(
        &self,
        labels: [Label; INPUT_WIRE_NUM],
        operator_assertion: &RawWitness,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut witness = Vec::with_capacity(operator_assertion.len() + INPUT_WIRE_NUM);
        witness.extend(operator_assertion.iter().cloned());
        witness.extend(labels);
        let witness_script = script! {
            { witness.clone() }
        };
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_0_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => Ok(witness),
            false => Err(Error::Other("Invalid unlock data for VerifierConnector.")),
        }
    }
}

impl TaprootConnector for VerifierConnector {
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
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

pub struct ProverConnector {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub disprove_blocks_timelock: u32,
    pub hashlocks: Vec<LabelHash>,
}

impl ProverConnector {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: XOnlyPublicKey,
        hashlocks: Vec<LabelHash>,
        timelock_config: &TimelockConfig,
    ) -> Self {
        assert!(
            !hashlocks.is_empty(),
            "ProverConnector requires at least one hashlock"
        );
        ProverConnector {
            network,
            n_of_n_taproot_public_key,
            disprove_blocks_timelock: timelock_config.prover_connector,
            hashlocks,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        wrongly_challenged_hashlocks_script(&self.hashlocks).compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.disprove_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.disprove_blocks_timelock)
    }
}

impl TaprootConnector for ProverConnector {
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
