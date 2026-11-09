use crate::{assert_scripts::*, utils::remove_script_and_control_block_from_witness};
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::{chunk::api::type_conversion_utils::RawWitness, treepp::*};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use super::{
    super::{error::Error, scripts::*, transactions::base::Input, wots::*},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    #[serde(with = "BigArray")]
    pub operator_wots_public_key: OperatorAssertPublicKey,
}

impl ConnectorC {
    pub fn new(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_wots_public_key: &OperatorAssertPublicKey,
    ) -> Self {
        ConnectorC {
            network,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            operator_wots_public_key: *operator_wots_public_key,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        verify_prover_assert_script_768_wire(&self.operator_wots_public_key).compile()
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    pub fn generate_leaf_1_unlock_data(
        &self,
        sk: &OperatorAssertSecretKey,
        proof: &[u8; 96],
        pi2: &[u8],
        pi3: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let witness = Wots96::sign_to_raw_witness(sk, proof);
        let witness_script = script! {
            { witness.clone() }
            { pi2.to_vec() }
            { pi3.to_vec() }
        };
        let verification_script = witness_script.push_script(self.generate_taproot_leaf_1_script());
        let exec_result = execute_script(verification_script);
        match exec_result.success {
            true => {
                let mut unlock_data = witness.to_vec();
                unlock_data.push(pi2.to_vec());
                unlock_data.push(pi3.to_vec());
                Ok(unlock_data)
            }
            false => Err(Error::Other("Invalid WOTS secret-key for Connector-C.")),
        }
    }

    pub fn extract_leaf_1_raw_witness(&self, txin: &TxIn) -> Result<RawWitness, Error> {
        let witness = txin.witness.to_vec();
        if witness.len() != PROVER_SIG_LEN + 4 {
            return Err(Error::Other(
                "Invalid witness length for Connector-C leaf 1.",
            ));
        }
        Ok(remove_script_and_control_block_from_witness(witness))
    }
}

impl TaprootConnector for ConnectorC {
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
