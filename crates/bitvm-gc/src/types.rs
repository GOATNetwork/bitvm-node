use std::collections::BTreeMap;

use anyhow::{Result, bail};
use bitcoin::{
    Address, Amount, Network, PrivateKey, PublicKey, TxOut, Witness, XOnlyPublicKey, key::Keypair,
    taproot::LeafVersion,
};
use goat::{
    assert_scripts::{
        INPUT_WIRE_NUM, LabelHash, OperatorAssertPublicKey, OperatorCommitPubinPublicKey, WireHash,
    },
    connectors::{
        assert_connectors::{ProverConnector, VerifierConnector},
        base::TaprootConnector,
        connector_0::Connector0,
        connector_a::ConnectorA,
        connector_b::ConnectorB,
        connector_c::ConnectorC,
        connector_d::ConnectorD,
        connector_e::ConnectorE,
        connector_f::ConnectorF,
        connector_z::ConnectorZ,
        kickoff_connectors::{
            ForceSkipConnector, GuardianConnector, KickoffConnector, PrekickoffConnector,
        },
        watchtower_connectors::{AckConnector, WatchtowerChallengeConnector},
    },
    constants::TimelockConfig,
    contexts::{base::BaseContext, committee::CommitteeContext, operator::OperatorContext},
    transactions::{
        assert::{DisproveTransaction, OperatorAssertTransaction, VerifierAssertTransaction},
        base::*,
        challenge::ChallengeTransaction,
        kickoff::KickoffTransaction,
        pegin::*,
        pre_signed::PreSignedTransaction,
        prekickoff::{
            ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction,
            PrekickoffTransaction, QuickChallengeTransaction,
        },
        take1::Take1Transaction,
        take2::Take2Transaction,
        watchtower_challenge::{
            OperatorChallengeNackTransaction, OperatorCommitTimeoutTransaction,
            WatchtowerChallengeInitTransaction, WatchtowerChallengeTimeoutTransaction,
        },
    },
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    committee::{CommitteeSignatures, push_committee_pre_signatures},
    operator::{generate_bitvm_graph, push_operator_pre_signature},
    timelocks::validate_timelock_config,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct UserInfo {
    pub depositor_evm_address: [u8; 20],
    pub txn_fees: [u64; 3],
    pub inputs: Vec<Input>,
    pub user_xonly_pubkey: XOnlyPublicKey,
    #[serde(with = "node_serializer::address")]
    pub user_change_address: Address,
    #[serde(with = "node_serializer::address")]
    pub user_refund_address: Address,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcInstanceParameters {
    pub network: Network,
    pub instance_id: Uuid,
    pub user_info: UserInfo,
    pub pegin_amount: Amount,
    pub committee_pubkeys: Vec<PublicKey>,
    pub committee_agg_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct PrekickoffParameters {
    pub cur_prekickoff_txn: PrekickoffTransaction,
    pub replenish_fee_inputs: Vec<Input>,
    pub replenish_fee_prev_outs: Vec<TxOut>,
    pub fee_amount: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcGraphParameters {
    pub instance_parameters: BitvmGcInstanceParameters,
    pub prekickoff_parameters: PrekickoffParameters,
    pub timelock_config: TimelockConfig,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub challenge_amount: Amount,
    pub operator_pubkey: PublicKey,
    #[serde(with = "BigArray")]
    pub operator_assert_wots_pubkey: OperatorAssertPublicKey,
    #[serde(with = "BigArray")]
    pub operator_commit_pubin_wots_pubkey: OperatorCommitPubinPublicKey,
    #[serde(with = "node_serializer::address")]
    pub operator_receive_address: Address,
    pub watchtower_pubkeys: Vec<XOnlyPublicKey>,
    pub watchtower_ack_hashlocks: Vec<LabelHash>,
    pub pubin_disprove_constant: [u8; 32],
    pub gc_data: Vec<BitvmGcCircuitData>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcCircuitData {
    pub verifier_pubkey: PublicKey,
    pub final_msg_hashlocks: Vec<LabelHash>,
    #[serde(with = "BigArray")]
    pub wire_hashes: [WireHash; INPUT_WIRE_NUM],
}

/// Fallible aggregation for untrusted committee lists. musig2 panics on an empty list.
pub fn checked_committee_key(pubkeys: &[PublicKey]) -> Result<PublicKey> {
    anyhow::ensure!(!pubkeys.is_empty(), "committee public keys are empty");
    let keys: Vec<musig2::secp::Point> = pubkeys.iter().map(|key| key.inner.into()).collect();
    let context = musig2::KeyAggContext::new(keys)
        .map_err(|error| anyhow::anyhow!("invalid committee keys: {error}"))?;
    let key: bitcoin::secp256k1::PublicKey = context.aggregated_pubkey();
    Ok(PublicKey::from(key))
}

fn checked_money_sum(amounts: impl IntoIterator<Item = Amount>) -> Result<Amount> {
    let mut total = Amount::ZERO;
    for amount in amounts {
        total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("Bitcoin amount sum overflows"))?;
        anyhow::ensure!(total <= Amount::MAX_MONEY, "Bitcoin amount exceeds MAX_MONEY");
    }
    Ok(total)
}

impl BitvmGcInstanceParameters {
    /// Cheap safety checks before constructing scripts or adding transaction amounts.
    pub fn validate_basic(&self) -> Result<()> {
        anyhow::ensure!(
            checked_committee_key(&self.committee_pubkeys)? == self.committee_agg_pubkey,
            "committee aggregate key mismatch"
        );
        let unique: std::collections::HashSet<_> =
            self.committee_pubkeys.iter().map(|key| key.inner).collect();
        anyhow::ensure!(
            unique.len() == self.committee_pubkeys.len(),
            "duplicate committee public key"
        );
        anyhow::ensure!(!self.user_info.inputs.is_empty(), "peg-in inputs are empty");
        checked_money_sum(self.user_info.inputs.iter().map(|input| input.amount))?;
        checked_money_sum([
            self.pegin_amount,
            Amount::from_sat(self.user_info.txn_fees[1]),
            Amount::from_sat(self.user_info.txn_fees[0]),
        ])?;
        anyhow::ensure!(
            self.user_info.txn_fees[2] <= Amount::MAX_MONEY.to_sat(),
            "refund fee exceeds MAX_MONEY"
        );
        Ok(())
    }

    pub fn n_of_n_taproot_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from(self.committee_agg_pubkey)
    }

    pub fn user_taproot_public_key(&self) -> XOnlyPublicKey {
        self.user_info.user_xonly_pubkey
    }

    pub fn connector_0(&self) -> Connector0 {
        Connector0::new(self.network, &self.n_of_n_taproot_public_key())
    }

    pub fn connector_z(&self) -> ConnectorZ {
        ConnectorZ::new(
            self.network,
            &self.n_of_n_taproot_public_key(),
            &self.user_taproot_public_key(),
            &crate::timelocks::default_timelock_config(self.network),
        )
    }

    pub fn build_pegin_tx(
        &self,
    ) -> Result<(PegInDepositTransaction, PegInConfirmTransaction, PegInRefundTransaction)> {
        self.validate_basic()?;
        let network = self.network;
        let connector_0 = self.connector_0();
        let connector_z = self.connector_z();
        let pegin_message = [
            get_magic_bytes(&network),
            self.instance_id.as_bytes().to_vec(),
            self.user_info.depositor_evm_address.to_vec(),
        ]
        .concat();

        let pegin_deposit = PegInDepositTransaction::new_unsigned(
            &connector_z,
            self.user_info.inputs.clone(),
            self.pegin_amount
                .checked_add(Amount::from_sat(self.user_info.txn_fees[1]))
                .ok_or_else(|| anyhow::anyhow!("peg-in amount plus confirm fee overflows"))?,
            Amount::from_sat(self.user_info.txn_fees[0]),
            self.user_info.user_change_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin deposit txn: {e}"))?;
        let deposit_outpoint = pegin_deposit
            .connector_z_input()
            .map_err(|e| anyhow::anyhow!("fail to get pegin deposit output: {e}"))?;
        let pegin_confirm = PegInConfirmTransaction::new_for_validation(
            &connector_0,
            &connector_z,
            deposit_outpoint.clone(),
            Amount::from_sat(self.user_info.txn_fees[1]),
            pegin_message,
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin confirm txn: {e}"))?;
        let pegin_refund = PegInRefundTransaction::new_for_validation(
            &connector_z,
            deposit_outpoint,
            &self.user_info.user_refund_address,
            Amount::from_sat(self.user_info.txn_fees[2]),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin refund txn: {e}"))?;

        Ok((pegin_deposit, pegin_confirm, pegin_refund))
    }

    pub fn build_pegin_cancel_psbt(&self) -> Result<bitcoin::psbt::Psbt> {
        self.validate_basic()?;
        let connector_z = self.connector_z();
        let n_of_n_taproot_public_key = self.n_of_n_taproot_public_key();

        let pegin_deposit = PegInDepositTransaction::new_unsigned(
            &connector_z,
            self.user_info.inputs.clone(),
            self.pegin_amount
                .checked_add(Amount::from_sat(self.user_info.txn_fees[1]))
                .ok_or_else(|| anyhow::anyhow!("peg-in amount plus confirm fee overflows"))?,
            Amount::from_sat(self.user_info.txn_fees[0]),
            self.user_info.user_change_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin deposit txn: {e}"))?;
        let deposit_outpoint = pegin_deposit
            .connector_z_input()
            .map_err(|e| anyhow::anyhow!("fail to get pegin deposit output: {e}"))?;
        let pegin_refund = PegInRefundTransaction::new_for_validation(
            &connector_z,
            deposit_outpoint.clone(),
            &self.user_info.user_refund_address,
            Amount::from_sat(self.user_info.txn_fees[2]),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin refund txn: {e}"))?;

        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(pegin_refund.tx().clone()).unwrap();
        let taproot_spend_info = connector_z.generate_taproot_spend_info();
        let mut tap_scripts = BTreeMap::new();
        let tap_script_1 = connector_z.generate_taproot_leaf_script(1);
        tap_scripts.insert(
            taproot_spend_info
                .control_block(&(tap_script_1.clone(), LeafVersion::TapScript))
                .unwrap(),
            (tap_script_1, LeafVersion::TapScript),
        );
        let psbt_input_0 = bitcoin::psbt::Input {
            witness_utxo: {
                Some(TxOut {
                    value: deposit_outpoint.amount,
                    script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
                })
            },
            tap_merkle_root: taproot_spend_info.merkle_root(),
            tap_internal_key: Some(n_of_n_taproot_public_key),
            tap_scripts,
            ..Default::default()
        };
        psbt.inputs[0] = psbt_input_0;

        Ok(psbt)
    }

    pub fn get_committee_context(
        &self,
        committee_member_keypair: Keypair,
    ) -> Result<CommitteeContext> {
        let network = self.network;
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        let private_key = PrivateKey::new(committee_member_keypair.secret_key(), network);
        let committee_member_public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        if !self.committee_pubkeys.contains(&committee_member_public_key) {
            bail!("The provided committee member keypair does not match any committee public key");
        }
        Ok(CommitteeContext {
            network,
            committee_keypair: committee_member_keypair,
            committee_public_key: committee_member_public_key,
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        let network = self.network;
        let n_of_n_public_keys = self.committee_pubkeys.clone();
        let n_of_n_public_key = self.committee_agg_pubkey;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);
        BaseBitvmContext {
            network,
            n_of_n_public_keys,
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}

impl BitvmGcGraphParameters {
    pub fn validate_basic(&self) -> Result<()> {
        self.instance_parameters.validate_basic()?;
        anyhow::ensure!(
            !self.watchtower_pubkeys.is_empty() && self.watchtower_pubkeys.len() <= 256,
            "invalid watchtower count"
        );
        anyhow::ensure!(
            self.watchtower_pubkeys.len() == self.watchtower_ack_hashlocks.len(),
            "watchtower hashlock count mismatch"
        );
        anyhow::ensure!(!self.gc_data.is_empty(), "verifier slots are empty");
        for data in &self.gc_data {
            anyhow::ensure!(
                data.final_msg_hashlocks.len() == crate::babe_adapter::BABE_M_CC,
                "verifier final message hashlock count mismatch"
            );
        }
        let prep = &self.prekickoff_parameters;
        anyhow::ensure!(
            prep.replenish_fee_inputs.len() == prep.replenish_fee_prev_outs.len(),
            "replenish input/output count mismatch"
        );
        let current = prep
            .cur_prekickoff_txn
            .prekickoff_connector_input()
            .map_err(|error| anyhow::anyhow!("invalid current prekickoff: {error}"))?;
        checked_money_sum(
            std::iter::once(current.amount)
                .chain(prep.replenish_fee_inputs.iter().map(|input| input.amount)),
        )?;
        anyhow::ensure!(
            prep.fee_amount <= Amount::MAX_MONEY.to_sat(),
            "prekickoff fee exceeds MAX_MONEY"
        );
        anyhow::ensure!(
            self.challenge_amount <= Amount::MAX_MONEY,
            "challenge amount exceeds MAX_MONEY"
        );
        Ok(())
    }

    pub fn network(&self) -> Network {
        self.instance_parameters.network
    }

    pub fn operator_taproot_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from(self.operator_pubkey)
    }

    pub fn n_of_n_taproot_public_key(&self) -> XOnlyPublicKey {
        self.instance_parameters.n_of_n_taproot_public_key()
    }

    pub fn connector_0(&self) -> Connector0 {
        self.instance_parameters.connector_0()
    }

    pub fn connector_z(&self) -> ConnectorZ {
        self.instance_parameters.connector_z()
    }

    pub fn prekickoff_connector(&self) -> PrekickoffConnector {
        PrekickoffConnector::new(self.network(), &self.operator_taproot_public_key())
    }

    /// Output 0 of the next Pre-Kickoff. It is locked to this graph's committee,
    /// which pre-signs its spend in Quick-Challenge and Force-Skip-Kickoff.
    pub fn force_skip_connector(&self) -> ForceSkipConnector {
        ForceSkipConnector::new(self.network(), &self.n_of_n_taproot_public_key())
    }

    pub fn kickoff_connector(&self) -> KickoffConnector {
        KickoffConnector::new(self.network(), &self.operator_taproot_public_key())
    }

    pub fn connector_a(&self) -> ConnectorA {
        ConnectorA::new(
            self.network(),
            &self.operator_taproot_public_key(),
            &self.n_of_n_taproot_public_key(),
            &self.timelock_config,
        )
    }

    pub fn connector_b(&self) -> ConnectorB {
        ConnectorB::new(self.network(), &self.operator_taproot_public_key())
    }

    pub fn connector_c(&self) -> ConnectorC {
        ConnectorC::new(
            self.network(),
            &self.n_of_n_taproot_public_key(),
            &self.operator_assert_wots_pubkey,
        )
    }

    pub fn connector_d(&self) -> ConnectorD {
        ConnectorD::new(
            self.network(),
            &self.operator_taproot_public_key(),
            &self.n_of_n_taproot_public_key(),
            &self.operator_commit_pubin_wots_pubkey,
            &self.operator_assert_wots_pubkey,
            &self.pubin_disprove_constant,
            &self.watchtower_ack_hashlocks,
            &self.timelock_config,
        )
    }

    pub fn connector_e(&self) -> ConnectorE {
        ConnectorE::new(
            self.network(),
            &self.n_of_n_taproot_public_key(),
            &self.operator_commit_pubin_wots_pubkey,
            &self.timelock_config,
        )
    }

    pub fn connector_f(&self) -> ConnectorF {
        ConnectorF::new(
            self.network(),
            &self.operator_taproot_public_key(),
            &self.n_of_n_taproot_public_key(),
            &self.timelock_config,
        )
    }

    pub fn guardian_connector(&self) -> GuardianConnector {
        GuardianConnector::new(self.network(), &self.operator_taproot_public_key())
    }

    pub fn watchtower_challenge_connector(
        &self,
        watchtower_index: usize,
    ) -> Result<WatchtowerChallengeConnector> {
        let watchtower_taproot_public_key = self
            .watchtower_pubkeys
            .get(watchtower_index)
            .ok_or_else(|| anyhow::anyhow!("invalid watchtower index {watchtower_index}"))?;
        Ok(WatchtowerChallengeConnector::new(
            self.network(),
            &self.operator_taproot_public_key(),
            watchtower_taproot_public_key,
            &self.timelock_config,
        ))
    }

    pub fn watchtower_challenge_connectors(&self) -> Vec<WatchtowerChallengeConnector> {
        self.watchtower_pubkeys
            .iter()
            .map(|pubkey| {
                WatchtowerChallengeConnector::new(
                    self.network(),
                    &self.operator_taproot_public_key(),
                    pubkey,
                    &self.timelock_config,
                )
            })
            .collect()
    }

    pub fn ack_connector(&self, watchtower_index: usize) -> Result<AckConnector> {
        let hashlock = self
            .watchtower_ack_hashlocks
            .get(watchtower_index)
            .ok_or_else(|| anyhow::anyhow!("invalid watchtower index {watchtower_index}"))?;
        Ok(AckConnector::new(
            self.network(),
            &self.n_of_n_taproot_public_key(),
            *hashlock,
            &self.timelock_config,
        ))
    }

    pub fn ack_connectors(&self) -> Vec<AckConnector> {
        self.watchtower_ack_hashlocks
            .iter()
            .map(|hashlock| {
                AckConnector::new(
                    self.network(),
                    &self.n_of_n_taproot_public_key(),
                    *hashlock,
                    &self.timelock_config,
                )
            })
            .collect()
    }

    pub fn verifier_connector(&self, verifier_index: usize) -> Result<VerifierConnector> {
        let gc_data = self
            .gc_data
            .get(verifier_index)
            .ok_or_else(|| anyhow::anyhow!("invalid verifier index {verifier_index}"))?;
        Ok(VerifierConnector::new(
            self.network(),
            &self.n_of_n_taproot_public_key(),
            &self.operator_assert_wots_pubkey,
            gc_data.wire_hashes.clone(),
        ))
    }

    pub fn verifier_connectors(&self) -> Vec<VerifierConnector> {
        self.gc_data
            .iter()
            .map(|data| {
                VerifierConnector::new(
                    self.network(),
                    &self.n_of_n_taproot_public_key(),
                    &self.operator_assert_wots_pubkey,
                    data.wire_hashes.clone(),
                )
            })
            .collect()
    }

    pub fn prover_connector(&self, verifier_index: usize) -> Result<ProverConnector> {
        let gc_data = self
            .gc_data
            .get(verifier_index)
            .ok_or_else(|| anyhow::anyhow!("invalid verifier index {verifier_index}"))?;
        Ok(ProverConnector::new(
            self.network(),
            self.n_of_n_taproot_public_key(),
            gc_data.final_msg_hashlocks.clone(),
            &self.timelock_config,
        ))
    }

    pub fn prover_connectors(&self) -> Vec<ProverConnector> {
        self.gc_data
            .iter()
            .map(|data| {
                ProverConnector::new(
                    self.network(),
                    self.n_of_n_taproot_public_key(),
                    data.final_msg_hashlocks.clone(),
                    &self.timelock_config,
                )
            })
            .collect()
    }

    pub fn validate_timelock_config(&self) -> Result<()> {
        validate_timelock_config(self.network(), &self.timelock_config)
    }

    pub fn get_operator_context(&self, operator_keypair: Keypair) -> Result<OperatorContext> {
        let network = self.instance_parameters.network;
        let operator_public_key = self.operator_pubkey;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_public_key);
        let committee_public_key = self.instance_parameters.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        if operator_public_key
            != PublicKey::from_private_key(
                SECP256K1,
                &PrivateKey::new(operator_keypair.secret_key(), network),
            )
        {
            bail!("The provided operator keypair does not match the operator public key");
        }
        Ok(OperatorContext {
            network,
            operator_keypair,
            operator_public_key,
            operator_taproot_public_key,

            n_of_n_public_keys: self.instance_parameters.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        self.instance_parameters.get_base_context()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcGraph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: BitvmGcGraphParameters,

    pub cur_prekickoff: PrekickoffTransaction,
    pub next_prekickoff: PrekickoffTransaction,
    pub force_skip_kickoff: ForceSkipKickoffTransaction,
    pub quick_challenge: QuickChallengeTransaction,
    pub challenge_incomplete_kickoff: ChallengeIncompleteKickoffTransaction,

    pub pegin: PegInConfirmTransaction,
    pub kickoff: KickoffTransaction,
    pub take1: Take1Transaction,
    pub challenge: ChallengeTransaction,
    pub watchtower_challenge_init: WatchtowerChallengeInitTransaction,
    pub watchtower_challenge_timeouts: Vec<WatchtowerChallengeTimeoutTransaction>,
    pub operator_challenge_nacks: Vec<OperatorChallengeNackTransaction>,
    pub operator_commit_timeout: OperatorCommitTimeoutTransaction,
    pub operator_assert: OperatorAssertTransaction,
    pub verifier_asserts: Vec<VerifierAssertTransaction>,
    pub disproves: Vec<DisproveTransaction>,
    pub take2: Take2Transaction,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct SimplifiedBitvmGcGraph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: BitvmGcGraphParameters,
    pub operator_pre_sigs: Option<Vec<Witness>>,
    pub committee_pre_sigs: Option<CommitteeSignatures>,
}

impl BitvmGcGraph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }
    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }
    pub fn connector_0(&self) -> Connector0 {
        self.parameters.connector_0()
    }
    pub fn connector_z(&self) -> ConnectorZ {
        self.parameters.connector_z()
    }
    pub fn prekickoff_connector(&self) -> PrekickoffConnector {
        self.parameters.prekickoff_connector()
    }
    pub fn force_skip_connector(&self) -> ForceSkipConnector {
        self.parameters.force_skip_connector()
    }
    pub fn kickoff_connector(&self) -> KickoffConnector {
        self.parameters.kickoff_connector()
    }
    pub fn connector_a(&self) -> ConnectorA {
        self.parameters.connector_a()
    }
    pub fn connector_b(&self) -> ConnectorB {
        self.parameters.connector_b()
    }
    pub fn connector_c(&self) -> ConnectorC {
        self.parameters.connector_c()
    }
    pub fn connector_d(&self) -> ConnectorD {
        self.parameters.connector_d()
    }
    pub fn connector_e(&self) -> ConnectorE {
        self.parameters.connector_e()
    }
    pub fn connector_f(&self) -> ConnectorF {
        self.parameters.connector_f()
    }
    pub fn guardian_connector(&self) -> GuardianConnector {
        self.parameters.guardian_connector()
    }
    pub fn ack_connector(&self, watchtower_index: usize) -> Result<AckConnector> {
        self.parameters.ack_connector(watchtower_index)
    }
    pub fn ack_connectors(&self) -> Vec<AckConnector> {
        self.parameters.ack_connectors()
    }
    pub fn watchtower_challenge_connector(
        &self,
        watchtower_index: usize,
    ) -> Result<WatchtowerChallengeConnector> {
        self.parameters.watchtower_challenge_connector(watchtower_index)
    }
    pub fn watchtower_challenge_connectors(&self) -> Vec<WatchtowerChallengeConnector> {
        self.parameters.watchtower_challenge_connectors()
    }
    pub fn verifier_connector(&self, verifier_index: usize) -> Result<VerifierConnector> {
        self.parameters.verifier_connector(verifier_index)
    }
    pub fn verifier_connectors(&self) -> Vec<VerifierConnector> {
        self.parameters.verifier_connectors()
    }
    pub fn prover_connector(&self, verifier_index: usize) -> Result<ProverConnector> {
        self.parameters.prover_connector(verifier_index)
    }
    pub fn prover_connectors(&self) -> Vec<ProverConnector> {
        self.parameters.prover_connectors()
    }
    pub fn to_simplified(&self) -> Result<SimplifiedBitvmGcGraph> {
        fn extract_sig_from_witness(witness: &Witness) -> Result<bitcoin::taproot::Signature> {
            witness
                .nth(0)
                .and_then(|data| bitcoin::taproot::Signature::from_slice(data).ok())
                .ok_or_else(|| anyhow::anyhow!("No valid signature found in witness"))
        }
        let operator_pre_sigs = if self.operator_pre_signed {
            Some(vec![
                self.force_skip_kickoff.tx().input[0].witness.clone(),
                self.quick_challenge.tx().input[0].witness.clone(),
                self.challenge_incomplete_kickoff.tx().input[0].witness.clone(),
                self.challenge_incomplete_kickoff.tx().input[1].witness.clone(),
            ])
        } else {
            None
        };
        let committee_pre_sigs = if self.committee_pre_signed {
            let take1 = vec![
                extract_sig_from_witness(&self.take1.tx().input[0].witness)?,
                extract_sig_from_witness(&self.take1.tx().input[3].witness)?,
            ];
            let take2 = vec![extract_sig_from_witness(&self.take2.tx().input[0].witness)?];
            let challenge = vec![extract_sig_from_witness(&self.challenge.tx().input[0].witness)?];
            let mut watchtower_challenge_timeout = Vec::new();
            for tx in &self.watchtower_challenge_timeouts {
                watchtower_challenge_timeout
                    .push(extract_sig_from_witness(&tx.tx().input[1].witness)?);
            }
            let mut operator_challenge_nack = Vec::new();
            for tx in &self.operator_challenge_nacks {
                operator_challenge_nack.push(extract_sig_from_witness(&tx.tx().input[0].witness)?);
                operator_challenge_nack.push(extract_sig_from_witness(&tx.tx().input[1].witness)?);
            }
            let operator_commit_timeout = vec![
                extract_sig_from_witness(&self.operator_commit_timeout.tx().input[0].witness)?,
                extract_sig_from_witness(&self.operator_commit_timeout.tx().input[1].witness)?,
            ];
            let mut disprove = Vec::new();
            for disprove_tx in &self.disproves {
                disprove.push(extract_sig_from_witness(&disprove_tx.tx().input[0].witness)?);
                disprove.push(extract_sig_from_witness(&disprove_tx.tx().input[1].witness)?);
            }
            let force_skip_kickoff =
                vec![extract_sig_from_witness(&self.force_skip_kickoff.tx().input[1].witness)?];
            let quick_challenge =
                vec![extract_sig_from_witness(&self.quick_challenge.tx().input[1].witness)?];
            Some(CommitteeSignatures {
                take1,
                take2,
                challenge,
                watchtower_challenge_timeout,
                operator_challenge_nack,
                operator_commit_timeout,
                disprove,
                force_skip_kickoff,
                quick_challenge,
            })
        } else {
            None
        };
        Ok(SimplifiedBitvmGcGraph {
            operator_pre_signed: self.operator_pre_signed,
            committee_pre_signed: self.committee_pre_signed,
            parameters: self.parameters.clone(),
            operator_pre_sigs,
            committee_pre_sigs,
        })
    }
    pub fn from_simplified(simplified: &SimplifiedBitvmGcGraph) -> Result<BitvmGcGraph> {
        let mut graph = generate_bitvm_graph(simplified.parameters.clone())?;
        if simplified.operator_pre_signed {
            let operator_pre_sigs = simplified
                .operator_pre_sigs
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing operator pre signatures"))?;
            push_operator_pre_signature(&mut graph, operator_pre_sigs)?;
            graph.operator_pre_signed = true;
        }
        if simplified.committee_pre_signed {
            let committee_pre_sigs = simplified
                .committee_pre_sigs
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing committee pre signatures"))?;
            push_committee_pre_signatures(&mut graph, committee_pre_sigs)?;
            graph.committee_pre_signed = true;
        }
        Ok(graph)
    }
}

impl SimplifiedBitvmGcGraph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }

    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }

    pub fn parameters_hash(&self) -> Result<[u8; 32]> {
        self.parameters.canonical_graph_params_hash()
    }
}

impl BitvmGcInstanceParameters {
    pub fn parameters_hash(&self) -> Result<[u8; 32]> {
        let encoded = serde_json::to_vec(self)?;
        Ok(Sha256::digest(encoded).into())
    }
}

impl BitvmGcGraphParameters {
    pub fn canonical_graph_params_hash(&self) -> Result<[u8; 32]> {
        let encoded = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"GOAT_BITVM_GC_GRAPH_PARAMS_V1");
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    pub fn parameters_hash(&self) -> Result<[u8; 32]> {
        self.canonical_graph_params_hash()
    }
}

impl SimplifiedBitvmGcGraph {
    pub fn canonical_graph_params_hash(&self) -> Result<[u8; 32]> {
        self.parameters.canonical_graph_params_hash()
    }
}

pub struct BaseBitvmContext {
    pub network: Network,
    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for BaseBitvmContext {
    fn network(&self) -> Network {
        self.network
    }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> {
        &self.n_of_n_public_keys
    }
    fn n_of_n_public_key(&self) -> &PublicKey {
        &self.n_of_n_public_key
    }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey {
        &self.n_of_n_taproot_public_key
    }
}

pub fn get_magic_bytes(net: &Network) -> Vec<u8> {
    match net {
        Network::Bitcoin => hex::encode(b"GTV6").as_bytes().to_vec(),
        _ => hex::encode(b"GTT6").as_bytes().to_vec(),
    }
}

pub mod node_serializer {
    use bitcoin::Address;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub mod address {
        use super::*;

        pub fn serialize<S>(addr: &Address, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&addr.to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s)
                .map(|addr| addr.assume_checked())
                .map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate as bitvm_lib;
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/admission.rs"));

    #[test]
    fn malformed_instances_return_errors_instead_of_panicking_in_both_builders() {
        let valid = admission_parameters(Network::Regtest, 1).instance_parameters;
        valid.validate_basic().unwrap();
        for case in 0..5 {
            let mut bad = valid.clone();
            match case {
                0 => bad.committee_pubkeys.clear(),
                1 => bad.pegin_amount = Amount::from_sat(u64::MAX),
                2 => bad.user_info.txn_fees[0] = u64::MAX,
                3 => bad.user_info.txn_fees[1] = u64::MAX,
                _ => bad.user_info.inputs[0].amount = Amount::from_sat(u64::MAX),
            }
            assert!(
                std::panic::catch_unwind(|| bad.build_pegin_tx()).expect("must not panic").is_err()
            );
            assert!(
                std::panic::catch_unwind(|| bad.build_pegin_cancel_psbt())
                    .expect("must not panic")
                    .is_err()
            );
        }
    }

    #[test]
    fn reconstruction_rejects_malformed_parameters_before_signatures() {
        let valid = admission_parameters(Network::Regtest, 1);
        for case in 0..4 {
            let mut bad = valid.clone();
            match case {
                0 => bad.instance_parameters.committee_pubkeys.clear(),
                1 => bad.instance_parameters.pegin_amount = Amount::from_sat(u64::MAX),
                2 => bad.watchtower_ack_hashlocks.clear(),
                _ => bad.gc_data.clear(),
            }
            let simplified = SimplifiedBitvmGcGraph {
                parameters: bad,
                operator_pre_signed: true,
                committee_pre_signed: true,
                operator_pre_sigs: None,
                committee_pre_sigs: None,
            };
            assert!(
                std::panic::catch_unwind(|| BitvmGcGraph::from_simplified(&simplified))
                    .expect("must not panic")
                    .is_err()
            );
        }
    }

    #[test]
    fn direct_committee_verification_rejects_empty_keys_without_panic() {
        let mut graph =
            crate::operator::generate_bitvm_graph(admission_parameters(Network::Regtest, 1))
                .unwrap();
        graph.committee_pre_signed = true;
        graph.parameters.instance_parameters.committee_pubkeys.clear();
        assert!(
            std::panic::catch_unwind(|| crate::committee::verify_graph_committee_pre_signatures(
                &graph
            ))
            .expect("must not panic")
            .is_err()
        );
    }
}
