use std::vec;

use bitcoin::{
    absolute, consensus, taproot::LeafVersion, Amount, ScriptBuf, TapSighashType, Transaction,
    TxIn, TxOut,
};
use bitvm::{chunk::api::type_conversion_utils::RawWitness, execute_script, treepp::*};
use musig2::{errors::SigningError, AggNonce, PartialSignature, SecNonce};
use serde::{Deserialize, Serialize};

use crate::{
    assert_scripts::{
        Label, LabelHash, OperatorAssertPublicKey, OperatorAssertSecretKey,
        OperatorCommitPubinPublicKey, INPUT_WIRE_NUM,
    },
    connectors::{
        assert_connectors::{ProverConnector, VerifierConnector},
        base::TaprootConnector,
        connector_c::ConnectorC,
        connector_d::{ConnectorD, CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX},
    },
    contexts::{base::BaseContext, committee::CommitteeContext},
    error::{Error, TransactionError::InsufficientInputAmount},
    pubin_disprove_scripts::verify_guest_pubin_commitment,
    scripts::p2a_output,
    transactions::{
        base::*,
        pre_signed::PreSignedTransaction,
        signing::{
            populate_taproot_input_witness, populate_taproot_txin_witness,
            push_taproot_leaf_script_and_control_block_to_witness,
        },
        signing_musig2::{
            generate_taproot_aggregated_signature, generate_taproot_partial_signature,
        },
    },
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct OperatorAssertTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for OperatorAssertTransaction {
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

impl OperatorAssertTransaction {
    pub fn new_for_validation(
        connector_c: &ConnectorC,
        verifier_connectors: &Vec<VerifierConnector>,
        connector_d: &ConnectorD,
        input_0: Input,
    ) -> Result<Self, Error> {
        let input_0_leaf = 1;
        let _input_0 = connector_c.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount
            < Amount::from_sat(operator_assert_input_amount(verifier_connectors.len()))
        {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let mut total_output_amount = input_0.amount
            - Amount::from_sat(min_relay_fee_operator_assert(verifier_connectors.len()));
        let mut txouts = vec![];
        for verifier_connector in verifier_connectors {
            let assert_output = TxOut {
                value: Amount::from_sat(verifier_assert_input_amount()),
                script_pubkey: verifier_connector
                    .generate_taproot_address()
                    .script_pubkey(),
            };
            total_output_amount -= assert_output.value;
            txouts.push(assert_output);
        }
        let anchor_output = p2a_output();
        total_output_amount -= anchor_output.value;
        let connector_d_output = TxOut {
            value: total_output_amount,
            script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
        };
        txouts.push(connector_d_output);
        txouts.push(anchor_output);

        Ok(OperatorAssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: txouts,
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_c.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn operator_commit_proof(
        &mut self,
        wots_sk: &OperatorAssertSecretKey,
        connector_c: &ConnectorC,
        proof: &[u8; 96],
        pi2: &[u8],
        pi3: &[u8],
    ) -> Result<(), Error> {
        let input_index = 0;
        let leaf_index = 1;
        match connector_c.generate_leaf_1_unlock_data(wots_sk, proof, pi2, pi3) {
            Ok(wit) => {
                populate_taproot_input_witness(
                    self.tx_mut(),
                    input_index,
                    &connector_c.generate_taproot_spend_info(),
                    &connector_c.generate_taproot_leaf_script(leaf_index),
                    wit,
                );
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn verifier_connector_input(&self, index: usize) -> Result<Input, Error> {
        let verifier_num = output_topology::operator_assert::verifier_num(self.tx.output.len());
        if index >= verifier_num {
            return Err(Error::Other("verifier connector index out of bounds"));
        }

        tx_output_input(
            &self.tx,
            output_topology::operator_assert::verifier_connector(index),
        )
    }

    pub fn connector_d_input(&self) -> Result<Input, Error> {
        let verifier_num = output_topology::operator_assert::verifier_num(self.tx.output.len());
        tx_output_input(
            &self.tx,
            output_topology::operator_assert::connector_d(verifier_num),
        )
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        let verifier_num = output_topology::operator_assert::verifier_num(self.tx.output.len());
        tx_output_input(
            &self.tx,
            output_topology::operator_assert::anchor(verifier_num),
        )
    }
}

impl BaseTransaction for OperatorAssertTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "OperatorAssert"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct VerifierAssertTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for VerifierAssertTransaction {
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

impl VerifierAssertTransaction {
    pub fn new_for_validation(
        verifier_connector: &VerifierConnector,
        prover_connector: &ProverConnector,
        input_0: Input,
    ) -> Result<Self, Error> {
        let input_0_leaf = 0;
        let _input_0 = verifier_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        if input_0.amount < Amount::from_sat(verifier_assert_input_amount()) {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        let output_0 = TxOut {
            value: Amount::from_sat(verifier_assert_prover_output_amount()),
            script_pubkey: prover_connector.generate_taproot_address().script_pubkey(),
        };

        let output_1 = p2a_output();

        Ok(VerifierAssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![output_0, output_1],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: verifier_connector
                    .generate_taproot_address()
                    .script_pubkey(),
            }],
            prev_scripts: vec![verifier_connector.generate_taproot_leaf_script(input_0_leaf)],
        })
    }

    pub fn verifier_publish_labels(
        &mut self,
        verifier_connector: &VerifierConnector,
        labels: [Label; INPUT_WIRE_NUM],
        operator_assertion: &RawWitness,
    ) -> Result<(), Error> {
        let input_index = 0;
        let leaf_index = 0;
        let wit = verifier_connector.generate_leaf_0_unlock_data(labels, operator_assertion)?;
        populate_taproot_input_witness(
            self.tx_mut(),
            input_index,
            &verifier_connector.generate_taproot_spend_info(),
            &verifier_connector.generate_taproot_leaf_script(leaf_index),
            wit,
        );
        Ok(())
    }

    pub fn prover_connector_input(&self) -> Result<Input, Error> {
        tx_output_input(
            &self.tx,
            output_topology::verifier_assert::prover_connector(),
        )
    }

    pub fn anchor_input(&self) -> Result<Input, Error> {
        tx_output_input(&self.tx, output_topology::verifier_assert::anchor())
    }
}

impl BaseTransaction for VerifierAssertTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "VerifierAssert"
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DisproveTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for DisproveTransaction {
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

impl DisproveTransaction {
    pub fn new_for_validation(
        prover_connector: &ProverConnector,
        connector_d: &ConnectorD,
        input_0: Input,
        input_1: Input,
        _final_msg: Vec<u8>,
    ) -> Result<Self, Error> {
        let input_0_leaf = 1;
        let _input_0 = prover_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let input_1_leaf = 1;
        let _input_1 = connector_d.generate_taproot_leaf_tx_in(input_1_leaf, &input_1);

        if input_0.amount + input_1.amount < Amount::from_sat(disprove_input_amount()) {
            return Err(Error::Transaction(InsufficientInputAmount));
        }

        Ok(DisproveTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1],
                output: vec![p2a_output()],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: prover_connector.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                prover_connector.generate_taproot_leaf_script(input_0_leaf),
                connector_d.generate_taproot_leaf_script(input_1_leaf),
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

    fn push_input_0_signature(
        &mut self,
        prover_connector: &ProverConnector,
        input_0_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = prover_connector.generate_taproot_spend_info();
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
        connector_d: &ConnectorD,
        input_1_sig: bitcoin::taproot::Signature,
    ) {
        let input_index = 1;
        let script = self.prev_scripts()[input_index].clone();
        let spend_info = connector_d.generate_taproot_spend_info();
        let tx_mut = self.tx_mut();
        // Push signature to witness
        tx_mut.input[input_index]
            .witness
            .push(input_1_sig.serialize());

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
        sec_nonces: &[SecNonce; 2],
        agg_nonces: &[AggNonce; 2],
    ) -> Result<[PartialSignature; 2], SigningError> {
        let input_0_sig = self.sign_input_0_musig2(context, &sec_nonces[0], &agg_nonces[0]);
        let input_1_sig = self.sign_input_1_musig2(context, &sec_nonces[1], &agg_nonces[1]);
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
        let (input_0_sig, input_1_sig);
        {
            let input_index = 0;
            let sig_index = 0;
            let sighash_type = TapSighashType::None;
            input_0_sig = match generate_taproot_aggregated_signature(
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
        }
        {
            let input_index = 1;
            let sig_index = 1;
            let sighash_type = TapSighashType::None;
            input_1_sig = match generate_taproot_aggregated_signature(
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
        }
        Ok([input_0_sig, input_1_sig])
    }

    pub fn push_pre_sigs(
        &mut self,
        prover_connector: &ProverConnector,
        connector_d: &ConnectorD,
        pre_sigs: [bitcoin::taproot::Signature; 2],
    ) {
        self.push_input_0_signature(prover_connector, pre_sigs[0]);
        self.push_input_1_signature(connector_d, pre_sigs[1]);
    }
}

impl BaseTransaction for DisproveTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }

    fn name(&self) -> &'static str {
        "Disprove"
    }
}

pub fn pubin_disprove_script(
    guest_pubin_wots_pubkey: &OperatorCommitPubinPublicKey,
    operator_assert_wots_pubkey: &OperatorAssertPublicKey,
    constant_value: &[u8; 32],
    watchtower_hashelocks: &Vec<LabelHash>,
) -> Script {
    verify_guest_pubin_commitment(
        guest_pubin_wots_pubkey,
        operator_assert_wots_pubkey,
        constant_value,
        watchtower_hashelocks,
    )
}

pub fn validate_pubin(
    operator_commit_pubin_witness: RawWitness,
    operator_assert_witness: RawWitness,
    ack_preimages: Vec<Vec<u8>>,
    input_lock_script: ScriptBuf,
) -> Option<(RawWitness, ScriptBuf)> {
    let mut unlock_data = operator_assert_witness;
    unlock_data.extend(ack_preimages);
    unlock_data.extend(operator_commit_pubin_witness);

    let witness_script = script! {
        { unlock_data.clone() }
    };
    let verification_script = witness_script.push_script(input_lock_script.clone());
    let exec_result = execute_script(verification_script);
    if exec_result.success {
        Some((unlock_data, input_lock_script))
    } else {
        None
    }
}

pub fn pubin_disprove(
    connector_d: &ConnectorD,
    connector_d_input: &Input,
    input_script_witness: RawWitness,
) -> Result<TxIn, Error> {
    let input_lock_script =
        connector_d.generate_taproot_leaf_script(CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX);
    let mut txin = connector_d
        .generate_taproot_leaf_tx_in(CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX, connector_d_input);
    input_script_witness
        .into_iter()
        .for_each(|witness_item| txin.witness.push(witness_item));

    let prevout_leaf = (input_lock_script, LeafVersion::TapScript);
    let control_block = match connector_d
        .generate_taproot_spend_info()
        .control_block(&prevout_leaf)
    {
        Some(control_block) => control_block,
        None => {
            return Err(Error::Other(
                "Unable to generate Connector-D control block for pubin-disprove txin.",
            ))
        }
    };
    txin.witness.push(prevout_leaf.0.to_bytes());
    txin.witness.push(control_block.serialize());
    Ok(txin)
}

pub fn wrongly_challenged(
    prover_connector: &ProverConnector,
    input_0: &Input,
    final_msg: &Label,
) -> Result<TxIn, Error> {
    let leaf_index = 0;
    let unlock_data = vec![final_msg.clone()];
    let witness_script = script! {
        { unlock_data.clone() }
    };
    let script = prover_connector.generate_taproot_leaf_script(leaf_index);
    let verification_script = witness_script.push_script(script.clone());
    let exec_result = execute_script(verification_script);
    if !exec_result.success {
        return Err(Error::Other(
            "Invalid hashlock preimage for ProverConnector.",
        ));
    }

    let mut txin = prover_connector.generate_taproot_leaf_tx_in(leaf_index, input_0);
    populate_taproot_txin_witness(
        &mut txin,
        &prover_connector.generate_taproot_spend_info(),
        &script,
        unlock_data,
    );
    Ok(txin)
}
