use crate::{
    assert_scripts::{
        verify_prover_pubin_script, OperatorCommitPubinPublicKey, OperatorCommitPubinSecretKey,
        PROVER_SIG_LEN,
    },
    constants::TimelockConfig,
    utils::remove_script_and_control_block_from_witness,
    wots::*,
};
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
pub struct ConnectorE {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    #[serde(with = "BigArray")]
    pub operator_commit_pubin_wots_public_key: OperatorCommitPubinPublicKey,
    pub operator_commit_blocks_timelock: u32,
}

impl ConnectorE {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_commit_pubin_wots_public_key: &OperatorCommitPubinPublicKey,
        timelock_config: &TimelockConfig,
    ) -> Self {
        ConnectorE {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            operator_commit_pubin_wots_public_key: *operator_commit_pubin_wots_public_key,
            operator_commit_blocks_timelock: timelock_config.operator_commit,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        verify_prover_pubin_script(&self.operator_commit_pubin_wots_public_key).compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.operator_commit_blocks_timelock,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.operator_commit_blocks_timelock)
    }

    pub fn generate_leaf_0_unlock_data(
        &self,
        sk: &OperatorCommitPubinSecretKey,
        pubin_commitment: &[u8; 96],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let witness = Wots96::sign_to_raw_witness(sk, pubin_commitment);
        let witness_script = script! {
            { witness.clone() }
        };
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_0_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => Ok(witness.to_vec()),
            false => Err(Error::Other(
                "Invalid operator-commit-pubin WOTS secret-key for Connector-E.",
            )),
        }
    }

    pub fn extract_leaf_0_raw_witness(&self, txin: &TxIn) -> Result<RawWitness, Error> {
        let witness = txin.witness.to_vec();
        if witness.len() != PROVER_SIG_LEN + 2 {
            return Err(Error::Other(
                "Invalid witness length for Connector-E leaf 0.",
            ));
        }
        Ok(remove_script_and_control_block_from_witness(witness))
    }
}

impl TaprootConnector for ConnectorE {
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
