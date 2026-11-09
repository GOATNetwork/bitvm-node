use bitcoin::{
    absolute, consensus, Address, Amount, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    contexts::base::BaseContext,
    transactions::signing_musig2::generate_taproot_aggregated_signature,
};

use super::{
    super::{
        connectors::{
            base::*, connector_0::Connector0, connector_d::ConnectorD, connector_f::ConnectorF,
            kickoff_connectors::GuardianConnector,
        },
        contexts::{committee::CommitteeContext, operator::OperatorContext},
        error::{Error, TransactionError::InsufficientInputAmount},
        scripts::*,
        transactions::signing_musig2::generate_taproot_partial_signature,
    },
    base::*,
    pre_signed::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Take2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for Take2Transaction {
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

impl Take2Transaction {
    pub fn new_for_validation(
        connector_0: &Connector0,
        connector_d: &ConnectorD,
        connector_f: &ConnectorF,
        guardian_connector: &GuardianConnector,
        input_0: Input,
        input_1: Input,
        input_2: Input,
        input_3: Input,
        operator_address: &Address,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = connector_0.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 = connector_d.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        let input_2_leaf = 0;
        let _input_2 = connector_f.generate_taproot_leaf_tx_in(input_2_leaf, &input_2);

        let input_3_leaf = 0;
        let _input_3 = guardian_connector.generate_taproot_leaf_tx_in(input_3_leaf, &input_3);

        let total_input_amount = input_0.amount + input_1.amount + input_2.amount + input_3.amount;

        if total_input_amount < Amount::from_sat(MIN_RELAY_FEE_TAKE_2 + DUST_AMOUNT + P2A_AMOUNT) {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let total_output_amount = total_input_amount - Amount::from_sat(MIN_RELAY_FEE_TAKE_2);

        let output_1 = p2a_output();

        let output_0 = TxOut {
            value: total_output_amount - output_1.value,
            script_pubkey: operator_address.script_pubkey(),
        };

        Ok(Take2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1, _input_2, _input_3],
                output: vec![output_0, output_1],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_2.amount,
                    script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_3.amount,
                    script_pubkey: guardian_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_taproot_leaf_script(input_0_leaf),
                connector_d.generate_taproot_leaf_script(input_1_leaf),
                connector_f.generate_taproot_leaf_script(input_2_leaf),
                guardian_connector.generate_taproot_leaf_script(input_3_leaf),
            ],
        })
    }

    fn sign_input_0_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 0;
        let sighash_type = TapSighashType::All;
        generate_taproot_partial_signature(
            context,
            self.tx(),
            sec_nonce,
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
        )
    }

    fn push_input_0_signature(
        &mut self,
        connector_0: &Connector0,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_0.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_0_sig.serialize());

        // Push script + control block
        push_taproot_leaf_script_and_control_block_to_witness(
            tx_mut,
            input_index,
            &spend_info,
            &script,
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &CommitteeContext,
        sec_nonces: &[SecNonce; 1],
        agg_nonces: &[AggNonce; 1],
    ) -> Result<[PartialSignature; 1], SigningError> {
        let input_0_sig = self.sign_input_0_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        match [input_0_sig]
            .into_iter()
            .collect::<Result<Vec<PartialSignature>, SigningError>>()
        {
            Ok(sigs) => Ok(sigs.try_into().unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn aggregate_pre_sigs(
        &self,
        context: &dyn BaseContext,
        partial_signatures: &[Vec<PartialSignature>; 1],
        agg_nonces: &[AggNonce; 1],
    ) -> Result<[bitcoin::taproot::Signature; 1], Error> {
        let input_index = 0;
        let sig_index = 0;
        let sighash_type = TapSighashType::All;
        let input_0_sig = match generate_taproot_aggregated_signature(
            context,
            self.tx(),
            &agg_nonces[sig_index],
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
            partial_signatures[sig_index].clone(),
        ) {
            Ok(sig) => bitcoin::taproot::Signature {
                signature: sig.into(),
                sighash_type,
            },
            Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
        };
        Ok([input_0_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_0: &Connector0,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_0_signature(connector_0, pre_sigs[0]);
    }

    pub fn sign_input_1(&mut self, context: &OperatorContext, connector_d: &ConnectorD) {
        let input_index = 1;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_d.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn sign_input_2(&mut self, context: &OperatorContext, connector_f: &ConnectorF) {
        let input_index = 2;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_f.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn sign_input_3(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
    ) {
        let input_index = 3;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            guardian_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for Take2Transaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Take2"
    }
}
