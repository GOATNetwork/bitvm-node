use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{
        base::*,
        connector_a::ConnectorA,
        connector_b::ConnectorB,
        connector_c::ConnectorC,
        kickoff_connectors::{GuardianConnector, KickoffConnector},
    },
    contexts::operator::OperatorContext,
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::p2a_output,
    transactions::{
        base::{
            max_pegout_cost, max_watchtower_challenge_cost, output_topology, tx_output_input,
            BaseTransaction, Input, DUST_AMOUNT, MIN_RELAY_FEE_KICKOFF,
        },
        pre_signed::{pre_sign_taproot_input_default, PreSignedTransaction},
    },
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickoffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for KickoffTransaction {
    fn tx(&self) -> &Transaction {
        &self.tx
    }

    fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    fn prev_outs(&self) -> &Vec<TxOut> {
        &self.prev_outs
    }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> {
        &self.prev_scripts
    }
}
impl KickoffTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_validation(
        kickoff_connector: &KickoffConnector,
        connector_a: &ConnectorA,
        connector_b: &ConnectorB,
        connector_c: &ConnectorC,
        guardian_connector: &GuardianConnector,
        input_0: &Input,
        watchtower_num: usize,
        verifier_num: usize,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = kickoff_connector.generate_taproot_leaf_tx_in(input_0_leaf, input_0);

        if input_0.amount < Amount::from_sat(max_pegout_cost(watchtower_num, verifier_num)) {
            return Err(Error::Transaction(InsufficientInputAmount));
        }
        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_KICKOFF);
        let output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };
        let output_1 = TxOut {
            value: Amount::from_sat(max_watchtower_challenge_cost(watchtower_num)),
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };
        let output_3 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: guardian_connector
                .generate_taproot_address()
                .script_pubkey(),
        };
        let anchor_output = p2a_output();
        let output_2 = TxOut {
            value: total_output_amount
                - output_0.value
                - output_1.value
                - output_3.value
                - anchor_output.value,
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        Ok(KickoffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![output_0, output_1, output_2, output_3, anchor_output],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: kickoff_connector.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![kickoff_connector.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        kickoff_connector: &KickoffConnector,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            kickoff_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn connector_a_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::kickoff::connector_a())
    }

    pub fn connector_b_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::kickoff::connector_b())
    }

    pub fn connector_c_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::kickoff::connector_c())
    }

    pub fn guardian_connector_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::kickoff::guardian_connector())
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::kickoff::anchor())
    }
}
impl BaseTransaction for KickoffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Kickoff"
    }
}
