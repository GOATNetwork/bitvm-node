use bitcoin::{
    absolute,
    consensus::{self},
    Address, Amount, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::connector_0::Connector0,
    contexts::{base::BaseContext, committee::CommitteeContext},
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::generate_opreturn_script,
    transactions::{
        signing::populate_taproot_input_witness_with_signature,
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{
    super::connectors::{base::*, connector_z::ConnectorZ},
    base::*,
    pre_signed::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInDepositTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    fee_amount: Amount,
    pub input_amounts: Vec<Amount>,
}
impl PegInDepositTransaction {
    pub fn new_unsigned(
        connector_z: &ConnectorZ,
        inputs: Vec<Input>,
        deposit_amount: Amount,
        fee_amount: Amount,
        change_address: Address,
    ) -> Result<Self, Error> {
        let mut total_input_amount = Amount::ZERO;
        let input_amounts: Vec<Amount> = inputs.iter().map(|input| input.amount).collect();
        let txins: Vec<TxIn> = inputs
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect();
        if total_input_amount < deposit_amount + fee_amount {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let change_amount = total_input_amount - deposit_amount - fee_amount;
        let mut txouts = vec![];
        let output_0 = TxOut {
            value: deposit_amount,
            script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
        };
        txouts.push(output_0);
        let mut fee_amount = fee_amount;
        if change_amount > Amount::from_sat(DUST_AMOUNT) {
            let output_1 = TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            };
            txouts.push(output_1);
        } else {
            fee_amount += change_amount;
        }

        Ok(PegInDepositTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: txins,
                output: txouts,
            },
            fee_amount,
            input_amounts,
        })
    }

    pub fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn connector_z_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::pegin_deposit::connector_z())
    }

    pub fn change_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::pegin_deposit::change())
    }
}
impl BaseTransaction for PegInDepositTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInDeposit"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInRefundTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for PegInRefundTransaction {
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
impl PegInRefundTransaction {
    pub fn new_with_signature(
        connector_z: &ConnectorZ,
        input_0: Input,
        refund_address: &Address,
        fee_amount: Amount,
        signature: bitcoin::taproot::Signature,
    ) -> Result<Self, Error> {
        match Self::new_for_validation(connector_z, input_0, refund_address, fee_amount) {
            Ok(mut this) => {
                this.push_input_0_signature(connector_z, signature);
                Ok(this)
            }
            Err(e) => Err(e),
        }
    }

    pub fn new_for_validation(
        connector_z: &ConnectorZ,
        input_0: Input,
        refund_address: &Address,
        fee_amount: Amount,
    ) -> Result<Self, Error> {
        let input_0_leaf = 1;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount < fee_amount {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let total_output_amount = input_0.amount - fee_amount;
        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: refund_address.script_pubkey(),
        };

        Ok(PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    fn push_input_0_signature(
        &mut self,
        connector_z: &ConnectorZ,
        signature: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let taproot_spend_info = connector_z.generate_taproot_spend_info();

        populate_taproot_input_witness_with_signature(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            &[signature],
        );
    }

    pub fn refund_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::pegin_refund::refund())
    }
}
impl BaseTransaction for PegInRefundTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInRefund"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInConfirmTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for PegInConfirmTransaction {
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
impl PegInConfirmTransaction {
    pub fn new_for_validation(
        connector_0: &Connector0,
        connector_z: &ConnectorZ,
        input_0: Input,
        fee_amount: Amount,
        message: Vec<u8>,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount < fee_amount {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let total_output_amount = input_0.amount - fee_amount;
        let output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
        };
        let output_1 = TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(message),
        };

        Ok(PegInConfirmTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![output_0, output_1],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn sign_input_0_musig2(
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

    pub fn aggregate_input_0_musig2_signatures(
        &mut self,
        context: &dyn BaseContext,
        partial_sigs: Vec<PartialSignature>,
        agg_nonce: &AggNonce,
    ) -> Result<bitcoin::taproot::Signature, Error> {
        let input_index = 0;
        let sighash_type = TapSighashType::All;
        match generate_taproot_aggregated_signature(
            context,
            self.tx(),
            agg_nonce,
            input_index,
            self.prev_outs(),
            &self.prev_scripts()[input_index],
            sighash_type,
            partial_sigs,
        ) {
            Ok(sig) => Ok(bitcoin::taproot::Signature {
                signature: sig.into(),
                sighash_type,
            }),
            Err(_) => Err(Error::Other("Failed to aggregate signatures")),
        }
    }

    pub fn push_input_0_signature(
        &mut self,
        connector_z: &ConnectorZ,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_z.generate_taproot_spend_info();
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

    pub fn connector_0_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::pegin_confirm::connector_0())
    }

    pub fn op_return_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::pegin_confirm::op_return())
    }
}
impl BaseTransaction for PegInConfirmTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "PegInConfirm"
    }
}
