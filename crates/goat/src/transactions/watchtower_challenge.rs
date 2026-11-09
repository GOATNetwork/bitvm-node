use bitcoin::{
    absolute, consensus, key::Keypair, Address, Amount, ScriptBuf, TapSighashType, Transaction,
    TxIn, TxOut,
};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    assert_scripts::OperatorCommitPubinSecretKey,
    connectors::{
        base::{generate_default_tx_in, TaprootConnector},
        connector_b::ConnectorB,
        connector_e::ConnectorE,
        connector_f::ConnectorF,
        watchtower_connectors::{AckConnector, WatchtowerChallengeConnector},
    },
    contexts::{base::BaseContext, committee::CommitteeContext, operator::OperatorContext},
    error::{Error, TransactionError::InsufficientInputAmount},
    scripts::{generate_data_commitment_outputs, p2a_output},
    transactions::{
        signing::{
            populate_taproot_input_witness_default, populate_taproot_txin_witness,
            push_taproot_leaf_script_and_control_block_to_witness,
        },
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

use super::{base::*, pre_signed::*};

pub fn operator_commit_pubin(
    connector_e: &ConnectorE,
    pubin_commitment: &[u8; 96],
    wots_sk: &OperatorCommitPubinSecretKey,
    input_0: Input,
) -> Result<TxIn, Error> {
    let input_0_leaf = 0;
    let mut _input_0 = connector_e.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
    let unlock_data = connector_e.generate_leaf_0_unlock_data(wots_sk, pubin_commitment)?;
    populate_taproot_txin_witness(
        &mut _input_0,
        &connector_e.generate_taproot_spend_info(),
        &connector_e.generate_taproot_leaf_script(input_0_leaf),
        unlock_data,
    );
    Ok(_input_0)
}

pub fn operator_challenge_ack(
    ack_connector: &AckConnector,
    preimage: &[u8],
    input_0: Input,
) -> Result<TxIn, Error> {
    let input_0_leaf = 1;
    let mut _input_0 = ack_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);
    let unlock_data = ack_connector.generate_leaf_1_unlock_data(preimage)?;
    populate_taproot_txin_witness(
        &mut _input_0,
        &ack_connector.generate_taproot_spend_info(),
        &ack_connector.generate_taproot_leaf_script(input_0_leaf),
        unlock_data,
    );
    Ok(_input_0)
}

pub fn extract_operator_preimage_from_ack_txin(ack_txin: &TxIn) -> Result<Vec<u8>, Error> {
    ack_txin
        .witness
        .nth(0)
        .map(|w| w.to_vec())
        .ok_or(Error::Other(
            "Unable to extract preimage from ACK txin witness",
        ))
}

pub fn watchtower_challenge(
    watchtower_keypair: &Keypair,
    watchtower_challenge_connector: &WatchtowerChallengeConnector,
    commitment: &[u8],
    input_0: Input,
    payer_inputs: Vec<Input>,
    change_address: &Address,
    fee_amount: Amount,
) -> Result<Transaction, Error> {
    let input_0_leaf = 0;
    let _input_0 =
        watchtower_challenge_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

    let mut txins = vec![_input_0];
    let mut total_input_amount = input_0.amount;
    txins.extend(
        payer_inputs
            .iter()
            .map(|input| {
                total_input_amount += input.amount;
                generate_default_tx_in(input)
            })
            .collect::<Vec<TxIn>>(),
    );

    let commitment_outputs = generate_data_commitment_outputs(commitment);
    let commitment_amounts = commitment_outputs
        .iter()
        .map(|out| out.value)
        .sum::<Amount>();

    if total_input_amount < fee_amount + commitment_amounts {
        return Err(Error::Transaction(InsufficientInputAmount));
    }

    let total_output_amount = total_input_amount - fee_amount;
    let change_amount = total_output_amount - commitment_amounts;
    let mut txouts = commitment_outputs;
    if change_amount >= Amount::from_sat(DUST_AMOUNT) {
        txouts.push(TxOut {
            value: change_amount,
            script_pubkey: change_address.script_pubkey(),
        });
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };

    let input_index = 0;
    let prev_outs = vec![TxOut {
        value: input_0.amount,
        script_pubkey: watchtower_challenge_connector
            .generate_taproot_address()
            .script_pubkey(),
    }];
    let script = watchtower_challenge_connector.generate_taproot_leaf_script(input_0_leaf);
    populate_taproot_input_witness_default(
        &mut tx,
        &prev_outs,
        input_index,
        TapSighashType::AllPlusAnyoneCanPay,
        &watchtower_challenge_connector.generate_taproot_spend_info(),
        &script,
        &vec![watchtower_keypair],
    );

    Ok(tx)
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WatchtowerChallengeInitTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for WatchtowerChallengeInitTransaction {
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

impl WatchtowerChallengeInitTransaction {
    pub fn new_for_validation(
        connector_b: &ConnectorB,
        connector_e: &ConnectorE,
        connector_f: &ConnectorF,
        watchtower_challenge_connectors: &Vec<WatchtowerChallengeConnector>,
        ack_connectors: &Vec<AckConnector>,
        input_0: Input,
    ) -> Result<Self, Error> {
        if watchtower_challenge_connectors.len() != ack_connectors.len() {
            return Err(Error::Other(
                "watchtower challenge and ACK connector counts differ",
            ));
        }

        let input_0_leaf = 0;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount
            < Amount::from_sat(max_watchtower_challenge_cost(
                watchtower_challenge_connectors.len(),
            ))
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let mut total_output_amount = input_0.amount
            - Amount::from_sat(min_relay_fee_watchtower_challenge_init(
                watchtower_challenge_connectors.len(),
            ));
        let mut txouts = vec![];
        for (watchtower_challenge_connector, ack_connector) in watchtower_challenge_connectors
            .iter()
            .zip(ack_connectors.iter())
        {
            let challenge_output = TxOut {
                value: Amount::from_sat(watchtower_challenge_connector_output_amount()),
                script_pubkey: watchtower_challenge_connector
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            let ack_output = TxOut {
                value: Amount::from_sat(ack_connector_output_amount()),
                script_pubkey: ack_connector.generate_taproot_address().script_pubkey(),
            };
            total_output_amount = total_output_amount - challenge_output.value - ack_output.value;
            txouts.push(challenge_output);
            txouts.push(ack_output);
        }

        let connector_e_output = TxOut {
            value: Amount::from_sat(connector_e_output_amount()),
            script_pubkey: connector_e.generate_taproot_address().script_pubkey(),
        };
        let anchor_output = p2a_output();
        total_output_amount = total_output_amount - connector_e_output.value - anchor_output.value;
        let connector_f_output = TxOut {
            value: total_output_amount,
            script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
        };

        txouts.push(connector_e_output);
        txouts.push(connector_f_output);
        txouts.push(anchor_output);

        Ok(WatchtowerChallengeInitTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: txouts,
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn sign_input_0(&mut self, context: &OperatorContext, connector_b: &ConnectorB) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            connector_b.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn watchtower_connector_input(&self, index: usize) -> Result<Input, Error> {
        let watchtower_num =
            output_topology::watchtower_challenge_init::watchtower_num(self.tx.output.len());
        if index >= watchtower_num {
            return Err(Error::Other("watchtower connector index out of bounds"));
        }
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::watchtower_connector(index),
        )
    }

    pub fn ack_connector_input(&self, index: usize) -> Result<Input, Error> {
        let watchtower_num =
            output_topology::watchtower_challenge_init::watchtower_num(self.tx.output.len());
        if index >= watchtower_num {
            return Err(Error::Other("ACK connector index out of bounds"));
        }
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::ack_connector(index),
        )
    }

    pub fn connector_e_input(&self) -> Result<Input, Error> {
        let watchtower_num =
            output_topology::watchtower_challenge_init::watchtower_num(self.tx.output.len());
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::connector_e(watchtower_num),
        )
    }

    pub fn connector_f_input(&self) -> Result<Input, Error> {
        let watchtower_num =
            output_topology::watchtower_challenge_init::watchtower_num(self.tx.output.len());
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::connector_f(watchtower_num),
        )
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        let watchtower_num =
            output_topology::watchtower_challenge_init::watchtower_num(self.tx.output.len());
        tx_output_input(
            &self.tx,
            output_topology::watchtower_challenge_init::anchor(watchtower_num),
        )
    }
}

impl BaseTransaction for WatchtowerChallengeInitTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "WatchtowerChallengeInit"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct WatchtowerChallengeTimeoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for WatchtowerChallengeTimeoutTransaction {
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

impl WatchtowerChallengeTimeoutTransaction {
    pub fn new_for_validation(
        watchtower_challenge_connector: &WatchtowerChallengeConnector,
        ack_connector: &AckConnector,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 =
            watchtower_challenge_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 0;
        let _input_1 = ack_connector.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        WatchtowerChallengeTimeoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![p2a_output()],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: watchtower_challenge_connector
                        .generate_taproot_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: ack_connector.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                watchtower_challenge_connector.generate_taproot_leaf_script(input_0_leaf),
                ack_connector.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        watchtower_challenge_connector: &WatchtowerChallengeConnector,
    ) {
        let input_index = 0;
        pre_sign_taproot_input_default(
            self,
            input_index,
            TapSighashType::All,
            watchtower_challenge_connector.generate_taproot_spend_info(),
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
        ack_connector: &AckConnector,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = ack_connector.generate_taproot_spend_info();
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
        ack_connector: &AckConnector,
        pre_sigs: [bitcoin::taproot::Signature; 1],
    ) {
        self.push_input_1_signature(ack_connector, pre_sigs[0]);
    }
}

impl BaseTransaction for WatchtowerChallengeTimeoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "WatchtowerChallengeTimeout"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct OperatorChallengeNackTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for OperatorChallengeNackTransaction {
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

impl OperatorChallengeNackTransaction {
    pub fn new_for_validation(
        ack_connector: &AckConnector,
        connector_f: &ConnectorF,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 2;
        let _input_0 = ack_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_f.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        OperatorChallengeNackTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![p2a_output()],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: ack_connector.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                ack_connector.generate_taproot_leaf_script(input_0_leaf),
                connector_f.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    fn sign_input_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
        input_index: usize,
    ) -> Result<PartialSignature, SigningError> {
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

    fn push_input_signature(
        &mut self,
        input_index: usize,
        spend_info: bitcoin::taproot::TaprootSpendInfo,
        input_sig: bitcoin::taproot::Signature,
    ) {
        let script = self.prev_scripts()[input_index].clone();
        let tx_mut = self.tx_mut();
        tx_mut.input[input_index]
            .witness
            .push(input_sig.serialize());
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
        sec_nonces: &[SecNonce; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[PartialSignature; 2], SigningError> {
        let input_0_sig = self.sign_input_musig2(context, &sec_nonces[0], &agg_nonces[0], 0);
        let input_1_sig = self.sign_input_musig2(context, &sec_nonces[1], &agg_nonces[1], 1);
        match [input_0_sig, input_1_sig]
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
        partial_signatures: &[Vec<PartialSignature>; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[bitcoin::taproot::Signature; 2], Error> {
        let mut pre_sigs = Vec::with_capacity(2);
        for input_index in 0..2 {
            let sighash_type = TapSighashType::All;
            let sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[input_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[input_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
            pre_sigs.push(sig);
        }
        Ok(pre_sigs.try_into().unwrap())
    }

    pub fn push_pre_sigs(
        &mut self,
        ack_connector: &AckConnector,
        connector_f: &ConnectorF,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_signature(0, ack_connector.generate_taproot_spend_info(), pre_sigs[0]);
        self.push_input_signature(1, connector_f.generate_taproot_spend_info(), pre_sigs[1]);
    }
}

impl BaseTransaction for OperatorChallengeNackTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "OperatorChallengeNack"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct OperatorCommitTimeoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for OperatorCommitTimeoutTransaction {
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

impl OperatorCommitTimeoutTransaction {
    pub fn new_for_validation(
        connector_e: &ConnectorE,
        connector_f: &ConnectorF,
        input_0: Input,
        input_1: Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_e.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_f.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        OperatorCommitTimeoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![p2a_output()],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_e.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_f.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_e.generate_taproot_leaf_script(input_0_leaf),
                connector_f.generate_taproot_leaf_script(input_1_leaf),
            ],
        }
    }

    fn sign_input_musig2(
        &mut self,
        context: &CommitteeContext,
        sec_nonce: &SecNonce,
        agg_nonce: &AggNonce,
        input_index: usize,
    ) -> Result<PartialSignature, SigningError> {
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

    fn push_input_signature(
        &mut self,
        input_index: usize,
        spend_info: bitcoin::taproot::TaprootSpendInfo,
        input_sig: bitcoin::taproot::Signature,
    ) {
        let script = self.prev_scripts()[input_index].clone();
        let tx_mut = self.tx_mut();
        tx_mut.input[input_index]
            .witness
            .push(input_sig.serialize());
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
        sec_nonces: &[SecNonce; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[PartialSignature; 2], SigningError> {
        let input_0_sig = self.sign_input_musig2(context, &sec_nonces[0], &agg_nonces[0], 0);
        let input_1_sig = self.sign_input_musig2(context, &sec_nonces[1], &agg_nonces[1], 1);
        match [input_0_sig, input_1_sig]
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
        partial_signatures: &[Vec<PartialSignature>; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[bitcoin::taproot::Signature; 2], Error> {
        let mut pre_sigs = Vec::with_capacity(2);
        for input_index in 0..2 {
            let sighash_type = TapSighashType::All;
            let sig = match generate_taproot_aggregated_signature(
                context,
                self.tx(),
                &agg_nonces[input_index],
                input_index,
                self.prev_outs(),
                &self.prev_scripts()[input_index],
                sighash_type,
                partial_signatures[input_index].clone(),
            ) {
                Ok(sig) => bitcoin::taproot::Signature {
                    signature: sig.into(),
                    sighash_type,
                },
                Err(_) => return Err(Error::Other("Failed to aggregate signatures")),
            };
            pre_sigs.push(sig);
        }
        Ok(pre_sigs.try_into().unwrap())
    }

    pub fn push_pre_sigs(
        &mut self,
        connector_e: &ConnectorE,
        connector_f: &ConnectorF,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_signature(0, connector_e.generate_taproot_spend_info(), pre_sigs[0]);
        self.push_input_signature(1, connector_f.generate_taproot_spend_info(), pre_sigs[1]);
    }
}

impl BaseTransaction for OperatorCommitTimeoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "OperatorCommitTimeout"
    }
}
