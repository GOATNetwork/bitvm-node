use bitcoin::{
    absolute, consensus, Address, Amount, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::{
        base::{generate_default_tx_in, TaprootConnector},
        kickoff_connectors::{
            ForceSkipConnector, GuardianConnector, KickoffConnector, PrekickoffConnector,
        },
    },
    contexts::{base::BaseContext, committee::CommitteeContext, operator::OperatorContext},
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::p2a_output,
    transactions::{
        signing::{
            populate_taproot_input_witness_default,
            push_taproot_leaf_script_and_control_block_to_witness,
        },
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{base::*, pre_signed::*};

pub fn operator_skip_kickoff(
    context: &OperatorContext,
    kickoff_connector: &KickoffConnector,
    input_0: Input,
    fee_amount: Amount,
    receiver_address: Address,
) -> Result<Transaction, Error> {
    let input_0_leaf = 0;
    let _input_0 = kickoff_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

    if input_0.amount < fee_amount + Amount::from_sat(DUST_AMOUNT) {
        return Err(Error::Transaction(InsufficientInputAmount));
    }

    let output_0 = TxOut {
        value: input_0.amount - fee_amount,
        script_pubkey: receiver_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![_input_0],
        output: vec![output_0],
    };

    let prev_out = TxOut {
        value: input_0.amount,
        script_pubkey: kickoff_connector.generate_taproot_address().script_pubkey(),
    };
    let prev_script = kickoff_connector.generate_taproot_leaf_script(input_0_leaf);
    populate_taproot_input_witness_default(
        &mut tx,
        &[prev_out],
        0,
        TapSighashType::All,
        &kickoff_connector.generate_taproot_spend_info(),
        &prev_script,
        &vec![&context.operator_keypair],
    );

    Ok(tx)
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PrekickoffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    pub input_amounts: Vec<Amount>,
}
impl PreSignedTransaction for PrekickoffTransaction {
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
impl PrekickoffTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_validation(
        prev_prekickoff_connector: &PrekickoffConnector,
        force_skip_connector: &ForceSkipConnector,
        kickoff_connector: &KickoffConnector,
        prekickoff_connector: &PrekickoffConnector,
        input_0: Input,
        replenish_fee_inputs: Vec<Input>,
        replenish_fee_prev_outs: Vec<TxOut>,
        // replenish_fee_prev_scripts: Vec<ScriptBuf>,
        fee_amount: u64,
        watchtower_num: usize,
        verifier_num: usize,
    ) -> Result<Self, Error> {
        let mut input_amounts = vec![input_0.amount];
        let replenish_fee_input_amounts: Vec<Amount> = replenish_fee_inputs
            .iter()
            .map(|input| input.amount)
            .collect();
        input_amounts.extend(replenish_fee_input_amounts);

        let input_0_leaf = 0;
        let _input_0 =
            prev_prekickoff_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
        let mut txins = vec![_input_0];
        let mut total_input_amount = input_0.amount;
        txins.extend(
            replenish_fee_inputs
                .iter()
                .map(|input| {
                    total_input_amount += input.amount;
                    generate_default_tx_in(input)
                })
                .collect::<Vec<TxIn>>(),
        );

        if total_input_amount
            < Amount::from_sat(
                fee_amount
                    + 2 * DUST_AMOUNT
                    + P2A_AMOUNT
                    + max_pegout_cost(watchtower_num, verifier_num),
            )
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let total_output_amount = total_input_amount - Amount::from_sat(fee_amount);
        let output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: force_skip_connector
                .generate_taproot_address()
                .script_pubkey(),
        };
        let output_1 = TxOut {
            value: Amount::from_sat(max_pegout_cost(watchtower_num, verifier_num)),
            script_pubkey: kickoff_connector.generate_taproot_address().script_pubkey(),
        };
        let output_3 = p2a_output();
        let output_2 = TxOut {
            value: total_output_amount - output_0.value - output_1.value - output_3.value,
            script_pubkey: prekickoff_connector
                .generate_taproot_address()
                .script_pubkey(),
        };

        let mut prev_outs = vec![TxOut {
            value: input_0.amount,
            script_pubkey: prev_prekickoff_connector
                .generate_taproot_address()
                .script_pubkey(),
        }];
        prev_outs.extend(replenish_fee_prev_outs);

        let prev_scripts =
            vec![prev_prekickoff_connector.generate_taproot_leaf_script(input_0_leaf)];
        // prev_scripts.extend(replenish_fee_prev_scripts);

        Ok(PrekickoffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: txins,
                output: vec![output_0, output_1, output_2, output_3],
            },
            prev_outs,
            prev_scripts,
            input_amounts,
        })
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        prev_prekickoff_connector: &PrekickoffConnector,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            prev_prekickoff_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn force_skip_connector_input(&self) -> Result<Input, Error> {
        tx_output_input(
            &self.tx,
            output_topology::prekickoff::force_skip_connector(),
        )
    }

    pub fn kickoff_connector_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::prekickoff::kickoff_connector())
    }

    pub fn prekickoff_connector_input(&self) -> Result<Input, Error> {
        tx_output_input(
            &self.tx,
            output_topology::prekickoff::prekickoff_connector(),
        )
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::prekickoff::anchor())
    }
}
impl BaseTransaction for PrekickoffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "Prekickoff"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ForceSkipKickoffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for ForceSkipKickoffTransaction {
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
impl ForceSkipKickoffTransaction {
    pub fn new_presigned(
        context: &OperatorContext,
        kickoff_connector: &KickoffConnector,
        next_force_skip_connector: &ForceSkipConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            kickoff_connector,
            next_force_skip_connector,
            input_0,
            input_1,
        );

        this.pre_sign_and_push(context, kickoff_connector);

        this
    }

    pub fn new_for_validation(
        kickoff_connector: &KickoffConnector,
        next_force_skip_connector: &ForceSkipConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = kickoff_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 =
            next_force_skip_connector.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        ForceSkipKickoffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![], // output will be added later
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: kickoff_connector.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: next_force_skip_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                kickoff_connector.generate_taproot_leaf_script(input_0_leaf),
                next_force_skip_connector.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
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
            TapSighashType::None,
            kickoff_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    fn sign_input_1_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 1;
        let sighash_type = TapSighashType::None;
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

    fn push_input_1_signature(
        &mut self,
        next_force_skip_connector: &ForceSkipConnector,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = next_force_skip_connector.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());
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
        let input_1_sig = self.sign_input_1_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        match [input_1_sig]
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
        let input_index = 1;
        let sig_index = 0;
        let sighash_type = TapSighashType::None;
        let input_1_sig = match generate_taproot_aggregated_signature(
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
        Ok([input_1_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        next_force_skip_connector: &ForceSkipConnector,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_1_signature(next_force_skip_connector, pre_sigs[0]);
    }

    /// Signs input 0. Input 1 spends the force-skip connector and is signed
    /// by the committee through `pre_sign`.
    pub fn pre_sign_and_push(
        &mut self,
        context: &OperatorContext,
        kickoff_connector: &KickoffConnector,
    ) {
        self.sign_input_0(context, kickoff_connector);
    }
}
impl BaseTransaction for ForceSkipKickoffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "ForceSkipKickoff"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct QuickChallengeTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for QuickChallengeTransaction {
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
impl QuickChallengeTransaction {
    pub fn new_presigned(
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
        next_force_skip_connector: &ForceSkipConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            guardian_connector,
            next_force_skip_connector,
            input_0,
            input_1,
        );

        this.pre_sign_and_push(context, guardian_connector);

        this
    }

    pub fn new_for_validation(
        guardian_connector: &GuardianConnector,
        next_force_skip_connector: &ForceSkipConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = guardian_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 =
            next_force_skip_connector.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        QuickChallengeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![], // output will be added later
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: guardian_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: next_force_skip_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                guardian_connector.generate_taproot_leaf_script(input_0_leaf),
                next_force_skip_connector.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::None,
            guardian_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    fn sign_input_1_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
    ) -> Result<PartialSignature, SigningError> {
        let input_index = 1;
        let sighash_type = TapSighashType::None;
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

    fn push_input_1_signature(
        &mut self,
        next_force_skip_connector: &ForceSkipConnector,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = next_force_skip_connector.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());
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
        let input_1_sig = self.sign_input_1_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        match [input_1_sig]
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
        let input_index = 1;
        let sig_index = 0;
        let sighash_type = TapSighashType::None;
        let input_1_sig = match generate_taproot_aggregated_signature(
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
        Ok([input_1_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        next_force_skip_connector: &ForceSkipConnector,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_1_signature(next_force_skip_connector, pre_sigs[0]);
    }

    /// Signs input 0. Input 1 spends the force-skip connector and is signed
    /// by the committee through `pre_sign`.
    pub fn pre_sign_and_push(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
    ) {
        self.sign_input_0(context, guardian_connector);
    }
}
impl BaseTransaction for QuickChallengeTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "QuickChallenge"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ChallengeIncompleteKickoffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}
impl PreSignedTransaction for ChallengeIncompleteKickoffTransaction {
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
impl ChallengeIncompleteKickoffTransaction {
    pub fn new_presigned(
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
        next_prekickoff_connector: &PrekickoffConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            guardian_connector,
            next_prekickoff_connector,
            input_0,
            input_1,
        );

        this.pre_sign_and_push(context, guardian_connector, next_prekickoff_connector);

        this
    }

    pub fn new_for_validation(
        guardian_connector: &GuardianConnector,
        next_prekickoff_connector: &PrekickoffConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = guardian_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 =
            next_prekickoff_connector.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        ChallengeIncompleteKickoffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![], // output will be added later
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: guardian_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: next_prekickoff_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                guardian_connector.generate_taproot_leaf_script(input_0_leaf),
                next_prekickoff_connector.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::None,
            guardian_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn sign_input_1(
        &mut self,
        context: &OperatorContext,
        next_prekickoff_connector: &PrekickoffConnector,
    ) {
        let input_index = 1;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::None,
            next_prekickoff_connector.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn pre_sign_and_push(
        &mut self,
        context: &OperatorContext,
        guardian_connector: &GuardianConnector,
        next_prekickoff_connector: &PrekickoffConnector,
    ) {
        self.sign_input_0(context, guardian_connector);
        self.sign_input_1(context, next_prekickoff_connector);
    }
}
impl BaseTransaction for ChallengeIncompleteKickoffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
    fn name(&self) -> &'static str {
        "ChallengeIncompleteKickoff"
    }
}
