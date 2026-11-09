use bitcoin::{
    absolute, consensus, Address, Amount, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::base::TaprootConnector,
    contexts::{base::BaseContext, committee::CommitteeContext},
    error::Error,
    transactions::{
        signing::push_taproot_leaf_script_and_control_block_to_witness,
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{super::connectors::connector_a::ConnectorA, base::*, pre_signed::*};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ChallengeTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    pub challenge_amount: Amount,
}

impl PreSignedTransaction for ChallengeTransaction {
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

impl ChallengeTransaction {
    pub fn new_for_validation(
        connector_a: &ConnectorA,
        input_0: Input,
        challenge_amount: Amount,
        operator_address: &Address,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_a.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let _output_0 = TxOut {
            value: challenge_amount,
            script_pubkey: operator_address.script_pubkey(),
        };

        ChallengeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                // input 1 will be added later
            ],
            prev_scripts: vec![
                connector_a.generate_taproot_leaf_script(input_0_leaf),
                // input 1's script will be added later
            ],
            challenge_amount,
        }
    }

    fn sign_input_0_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 0;
        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay;
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
        connector_a: &ConnectorA,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_a.generate_taproot_spend_info();
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
        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay;
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
        connector_a: &ConnectorA,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_0_signature(connector_a, pre_sigs[0]);
    }
}

impl BaseTransaction for ChallengeTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.input.len() < 2 {
            panic!("Missing input. Call add_inputs_and_output before finalizing");
        }

        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Challenge"
    }
}
