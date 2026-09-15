use anyhow::{Result, bail, ensure};
use bitcoin::XOnlyPublicKey;
use bitcoin::{
    PublicKey, Script, TapLeafHash, TapSighash, TapSighashType, Transaction, TxOut,
    hashes::Hash,
    key::Keypair,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature},
};
use goat::contexts::base::generate_n_of_n_public_key;
use goat::transactions::base::BaseTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::{get_nonce_message, verify_public_nonce};
use goat::transactions::signing_musig2::generate_aggregated_nonce;
use musig2::secp::Point;
use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, verify_partial};
use secp256k1::{Message, SECP256K1, schnorr::Signature as SchnorrSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::hkdf_derive_bytes;
use crate::types::{BitvmGcGraph, BitvmGcInstanceParameters};

const COMMITTEE_NONCE_HKDF_SALT: &[u8] = b"bitvm-gc/committee-nonce/v1";
const COMMITTEE_PRESIGN_SIGHASH_DOMAIN: &[u8] = b"GOAT_BITVM_GC_COMMITTEE_PRESIGN_SIGHASHES_V1";
const COMMITTEE_NONCE_CONSENSUS_DOMAIN: &[u8] = b"GOAT_BITVM_GC_COMMITTEE_NONCE_CONSENSUS_V1";
const PEGIN_CONFIRM_NONCE_CONSENSUS_DOMAIN: &[u8] =
    b"GOAT_BITVM_GC_PEGIN_CONFIRM_NONCE_CONSENSUS_V1";

pub fn take1_pre_sign_num() -> usize {
    2
}
pub fn take2_pre_sign_num() -> usize {
    1
}
pub fn challenge_pre_sign_num() -> usize {
    1
}
pub fn watchtower_challenge_timeout_pre_sign_num(watchtower_num: usize) -> usize {
    watchtower_num
}
pub fn operator_challenge_nack_pre_sign_num(watchtower_num: usize) -> usize {
    watchtower_num * 2
}
pub fn operator_commit_timeout_pre_sign_num() -> usize {
    2
}
pub fn disprove_pre_sign_num(verifier_num: usize) -> usize {
    verifier_num * 2
}

pub fn sign_pegin_confirm(
    graph: &BitvmGcGraph,
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: SecNonce,
    committee_agg_nonce: AggNonce,
) -> Result<PartialSignature> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let committee_context =
        graph.parameters.instance_parameters.get_committee_context(committee_member_keypair)?;
    pegin_confirm
        .sign_input_0_musig2(&committee_context, &committee_member_sec_nonce, &committee_agg_nonce)
        .map_err(|e| anyhow::anyhow!("fail to sign pegin confirm {}: {e}", pegin_confirm.name()))
}

/// Return the exact MuSig2 message signed by PeginConfirm input 0.
pub fn pegin_confirm_sighash(instance_parameters: &BitvmGcInstanceParameters) -> Result<[u8; 32]> {
    let pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    let script = pegin_confirm
        .prev_scripts()
        .first()
        .ok_or_else(|| anyhow::anyhow!("{} input 0 script is missing", pegin_confirm.name()))?;
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    Ok(taproot_script_spend_sighash(
        pegin_confirm.tx(),
        0,
        pegin_confirm.prev_outs(),
        leaf_hash,
        TapSighashType::All,
    )?
    .to_byte_array())
}

/// Build the transcript committee members must agree on before PeginConfirm signing.
/// Aggregate nonce is derived internally from canonical public nonces.
pub fn pegin_confirm_nonce_consensus_hash(
    instance_parameters: &BitvmGcInstanceParameters,
    committee_pubkeys: &[PublicKey],
    ordered_pub_nonces: &[PubNonce],
) -> Result<[u8; 32]> {
    ensure!(
        committee_pubkeys.len() == ordered_pub_nonces.len(),
        "committee public key and nonce counts differ"
    );

    let agg_nonce = nonce_aggregation(&ordered_pub_nonces.to_vec());
    let mut hasher = Sha256::new();
    hasher.update(PEGIN_CONFIRM_NONCE_CONSENSUS_DOMAIN);
    hasher.update(instance_parameters.instance_id.as_bytes());
    hasher.update(instance_parameters.parameters_hash()?);
    hasher.update(pegin_confirm_sighash(instance_parameters)?);
    hasher.update((committee_pubkeys.len() as u32).to_be_bytes());
    for (committee_pubkey, pub_nonce) in committee_pubkeys.iter().zip(ordered_pub_nonces) {
        hasher.update(committee_pubkey.to_bytes());
        let encoded = serde_json::to_vec(pub_nonce)?;
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
    }
    let encoded_agg_nonce = serde_json::to_vec(&agg_nonce)?;
    hasher.update((encoded_agg_nonce.len() as u64).to_be_bytes());
    hasher.update(encoded_agg_nonce);
    Ok(hasher.finalize().into())
}

pub fn agg_and_push_pegin_confirm_sigs(
    graph: &BitvmGcGraph,
    partial_sigs: Vec<PartialSignature>,
    agg_nonce: &AggNonce,
) -> Result<Transaction> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let context = graph.parameters.instance_parameters.get_base_context();
    let agg_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, agg_nonce)
        .map_err(|e| {
            anyhow::anyhow!("fail to aggregate pegin confirm {}: {e}", pegin_confirm.name())
        })?;
    let connector_z = graph.parameters.instance_parameters.connector_z();
    pegin_confirm.push_input_0_signature(&connector_z, agg_sig);
    Ok(pegin_confirm.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMusig2Data<T> {
    pub take1: Vec<T>,
    pub take2: Vec<T>,
    pub challenge: Vec<T>,
    pub watchtower_challenge_timeout: Vec<T>,
    pub operator_challenge_nack: Vec<T>,
    pub operator_commit_timeout: Vec<T>,
    pub disprove: Vec<T>,
}

pub type CommitteeSecNonces = CommitteeMusig2Data<SecNonce>;
pub type CommitteePubNonces = CommitteeMusig2Data<PubNonce>;
pub type CommitteeNonceSignatures = CommitteeMusig2Data<SchnorrSignature>;
pub type CommitteeAggNonces = CommitteeMusig2Data<AggNonce>;
pub type CommitteePartialSignatures = CommitteeMusig2Data<PartialSignature>;
pub type CommitteeSignatures = CommitteeMusig2Data<TaprootSignature>;

impl<T> CommitteeMusig2Data<T> {
    pub fn validate_length(&self, watchtower_num: usize, verifier_num: usize) -> Result<()> {
        ensure!(self.take1.len() == take1_pre_sign_num(), "invalid number of take1");
        ensure!(self.take2.len() == take2_pre_sign_num(), "invalid number of take2");
        ensure!(self.challenge.len() == challenge_pre_sign_num(), "invalid number of challenge");
        ensure!(
            self.watchtower_challenge_timeout.len()
                == watchtower_challenge_timeout_pre_sign_num(watchtower_num),
            "invalid number of watchtower challenge timeout"
        );
        ensure!(
            self.operator_challenge_nack.len()
                == operator_challenge_nack_pre_sign_num(watchtower_num),
            "invalid number of operator challenge nack"
        );
        ensure!(
            self.operator_commit_timeout.len() == operator_commit_timeout_pre_sign_num(),
            "invalid number of operator commit timeout"
        );
        ensure!(
            self.disprove.len() == disprove_pre_sign_num(verifier_num),
            "invalid number of disprove"
        );
        Ok(())
    }

    pub fn new_empty() -> Self {
        CommitteeMusig2Data {
            take1: vec![],
            take2: vec![],
            challenge: vec![],
            watchtower_challenge_timeout: vec![],
            operator_challenge_nack: vec![],
            operator_commit_timeout: vec![],
            disprove: vec![],
        }
    }
}

pub fn key_aggregation(pubkeys: &[PublicKey]) -> PublicKey {
    generate_n_of_n_public_key(pubkeys).0
}

/// Hash every MuSig2 signing context used by committee pre-signing in nonce-slot order.
///
/// This is deliberately independent of witnesses and partial signatures. It commits to the
/// exact taproot sighashes that deterministic committee nonces will be used to sign.
pub fn committee_presign_sighash_digest(graph: &BitvmGcGraph) -> Result<[u8; 32]> {
    fn add_sighash<T: PreSignedTransaction + BaseTransaction>(
        hasher: &mut Sha256,
        slot: &[u8],
        tx: &T,
        input_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<()> {
        let script = tx.prev_scripts().get(input_index).ok_or_else(|| {
            anyhow::anyhow!("{} input {input_index} script is missing", tx.name())
        })?;
        let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
        let sighash = taproot_script_spend_sighash(
            tx.tx(),
            input_index,
            tx.prev_outs(),
            leaf_hash,
            sighash_type,
        )?;

        hasher.update((slot.len() as u32).to_be_bytes());
        hasher.update(slot);
        hasher.update(sighash.to_byte_array());
        Ok(())
    }

    let mut hasher = Sha256::new();
    hasher.update(COMMITTEE_PRESIGN_SIGHASH_DOMAIN);
    add_sighash(&mut hasher, b"take1/0/all", &graph.take1, 0, TapSighashType::All)?;
    add_sighash(&mut hasher, b"take1/3/all", &graph.take1, 3, TapSighashType::All)?;
    add_sighash(&mut hasher, b"take2/0/all", &graph.take2, 0, TapSighashType::All)?;
    add_sighash(
        &mut hasher,
        b"challenge/0/single_anyonecanpay",
        &graph.challenge,
        0,
        TapSighashType::SinglePlusAnyoneCanPay,
    )?;
    for (index, tx) in graph.watchtower_challenge_timeouts.iter().enumerate() {
        add_sighash(
            &mut hasher,
            format!("watchtower_challenge_timeout/{index}/1/none").as_bytes(),
            tx,
            1,
            TapSighashType::None,
        )?;
    }
    for (index, tx) in graph.operator_challenge_nacks.iter().enumerate() {
        add_sighash(
            &mut hasher,
            format!("operator_challenge_nack/{index}/0/all").as_bytes(),
            tx,
            0,
            TapSighashType::All,
        )?;
        add_sighash(
            &mut hasher,
            format!("operator_challenge_nack/{index}/1/all").as_bytes(),
            tx,
            1,
            TapSighashType::All,
        )?;
    }
    add_sighash(
        &mut hasher,
        b"operator_commit_timeout/0/all",
        &graph.operator_commit_timeout,
        0,
        TapSighashType::All,
    )?;
    add_sighash(
        &mut hasher,
        b"operator_commit_timeout/1/all",
        &graph.operator_commit_timeout,
        1,
        TapSighashType::All,
    )?;
    for (index, tx) in graph.disproves.iter().enumerate() {
        add_sighash(
            &mut hasher,
            format!("disprove/{index}/0/none").as_bytes(),
            tx,
            0,
            TapSighashType::None,
        )?;
        add_sighash(
            &mut hasher,
            format!("disprove/{index}/1/none").as_bytes(),
            tx,
            1,
            TapSighashType::None,
        )?;
    }
    Ok(hasher.finalize().into())
}

/// Build the transcript every committee member must confirm before generating a partial
/// signature. Aggregate nonces are derived from the ordered public nonces here so callers
/// cannot supply a different aggregation to the consensus transcript.
pub fn committee_nonce_consensus_hash(
    graph: &BitvmGcGraph,
    committee_pubkeys: &[PublicKey],
    ordered_pub_nonces: &[CommitteePubNonces],
) -> Result<[u8; 32]> {
    ensure!(
        committee_pubkeys.len() == ordered_pub_nonces.len(),
        "committee public key and nonce counts differ"
    );
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.parameters.gc_data.len();
    for pub_nonces in ordered_pub_nonces {
        pub_nonces.validate_length(watchtower_num, verifier_num)?;
    }
    let agg_nonces = nonces_aggregation(ordered_pub_nonces)?;
    agg_nonces.validate_length(watchtower_num, verifier_num)?;

    let mut hasher = Sha256::new();
    hasher.update(COMMITTEE_NONCE_CONSENSUS_DOMAIN);
    hasher.update(graph.parameters.instance_parameters.instance_id.as_bytes());
    hasher.update(graph.parameters.graph_id.as_bytes());
    hasher.update(graph.parameters.parameters_hash()?);
    hasher.update(committee_presign_sighash_digest(graph)?);
    hasher.update((committee_pubkeys.len() as u32).to_be_bytes());
    for (committee_pubkey, pub_nonces) in committee_pubkeys.iter().zip(ordered_pub_nonces) {
        hasher.update(committee_pubkey.to_bytes());
        let encoded = serde_json::to_vec(pub_nonces)?;
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
    }
    let encoded_agg_nonces = serde_json::to_vec(&agg_nonces)?;
    hasher.update((encoded_agg_nonces.len() as u64).to_be_bytes());
    hasher.update(encoded_agg_nonces);
    Ok(hasher.finalize().into())
}

pub fn committee_pre_sign(
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: CommitteeSecNonces,
    committee_agg_nonce: CommitteeAggNonces,
    graph: &mut BitvmGcGraph,
) -> Result<CommitteePartialSignatures> {
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    committee_member_sec_nonce.validate_length(watchtower_num, verifier_num)?;
    committee_agg_nonce.validate_length(watchtower_num, verifier_num)?;

    let committee_context =
        graph.parameters.instance_parameters.get_committee_context(committee_member_keypair)?;
    let mut res = CommitteePartialSignatures::new_empty();

    {
        // take-1
        let sec_nonces = committee_member_sec_nonce.take1.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take1.try_into().unwrap();
        match graph.take1.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take1 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take1.name()),
        };
    }

    {
        // take-2
        let sec_nonces = committee_member_sec_nonce.take2.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take2.try_into().unwrap();
        match graph.take2.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take2 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take2.name()),
        };
    }

    {
        // challenge
        let sec_nonces = committee_member_sec_nonce.challenge.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.challenge.try_into().unwrap();
        match graph.challenge.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.challenge = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.challenge.name()),
        };
    }

    {
        // watchtower challenge timeout
        let mut timeout_sigs = vec![];
        for (i, tx) in graph.watchtower_challenge_timeouts.iter_mut().enumerate() {
            let sec_nonces = [committee_member_sec_nonce.watchtower_challenge_timeout[i].clone()];
            let agg_nonces = [committee_agg_nonce.watchtower_challenge_timeout[i].clone()];
            let sigs = tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", tx.name()))?;
            timeout_sigs.extend(sigs);
        }
        res.watchtower_challenge_timeout = timeout_sigs;
    }

    {
        // operator challenge nack
        let mut nack_sigs = vec![];
        for (i, tx) in graph.operator_challenge_nacks.iter_mut().enumerate() {
            let sec_nonces = [
                committee_member_sec_nonce.operator_challenge_nack[i * 2].clone(),
                committee_member_sec_nonce.operator_challenge_nack[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.operator_challenge_nack[i * 2].clone(),
                committee_agg_nonce.operator_challenge_nack[i * 2 + 1].clone(),
            ];
            let sigs = tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", tx.name()))?;
            nack_sigs.extend(sigs);
        }
        res.operator_challenge_nack = nack_sigs;
    }

    {
        // operator commit timeout
        let sec_nonces = committee_member_sec_nonce.operator_commit_timeout.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.operator_commit_timeout.try_into().unwrap();
        match graph.operator_commit_timeout.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.operator_commit_timeout = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.operator_commit_timeout.name()),
        };
    }

    {
        // disprove
        let mut disprove_sigs = vec![];
        for (i, disprove_tx) in graph.disproves.iter_mut().enumerate() {
            let sec_nonces = [
                committee_member_sec_nonce.disprove[i * 2].clone(),
                committee_member_sec_nonce.disprove[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.disprove[i * 2].clone(),
                committee_agg_nonce.disprove[i * 2 + 1].clone(),
            ];
            let sigs = disprove_tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", disprove_tx.name()))?;
            disprove_sigs.extend(sigs);
        }
        res.disprove = disprove_sigs;
    }

    Ok(res)
}

pub fn nonce_aggregation(pub_nonces: &Vec<PubNonce>) -> AggNonce {
    generate_aggregated_nonce(pub_nonces)
}

pub fn nonces_aggregation(pub_nonces_vec: &[CommitteePubNonces]) -> Result<CommitteeAggNonces> {
    fn aggregate_field<F>(rows: &[CommitteePubNonces], get: F) -> Result<Vec<AggNonce>>
    where
        F: Fn(&CommitteePubNonces) -> &Vec<PubNonce>,
    {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let expected = get(&rows[0]).len();

        for (idx, r) in rows.iter().enumerate() {
            if get(r).len() != expected {
                bail!("length mismatch on row {}: expected {}, got {}", idx, expected, get(r).len())
            }
        }

        Ok((0..expected)
            .map(|i| {
                let column: Vec<PubNonce> = rows.iter().map(|r| get(r)[i].clone()).collect();
                nonce_aggregation(&column)
            })
            .collect())
    }

    Ok(CommitteeAggNonces {
        take1: aggregate_field(pub_nonces_vec, |c| &c.take1)?,
        take2: aggregate_field(pub_nonces_vec, |c| &c.take2)?,
        challenge: aggregate_field(pub_nonces_vec, |c| &c.challenge)?,
        watchtower_challenge_timeout: aggregate_field(pub_nonces_vec, |c| {
            &c.watchtower_challenge_timeout
        })?,
        operator_challenge_nack: aggregate_field(pub_nonces_vec, |c| &c.operator_challenge_nack)?,
        operator_commit_timeout: aggregate_field(pub_nonces_vec, |c| &c.operator_commit_timeout)?,
        disprove: aggregate_field(pub_nonces_vec, |c| &c.disprove)?,
    })
}

pub fn signature_aggregation(
    partial_sigs: &Vec<CommitteePartialSignatures>,
    agg_nonces: &CommitteeAggNonces,
    graph: &BitvmGcGraph,
) -> Result<CommitteeSignatures> {
    let context = graph.parameters.get_base_context();
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    agg_nonces.validate_length(watchtower_num, verifier_num)?;
    for r in partial_sigs {
        r.validate_length(watchtower_num, verifier_num)?;
    }

    let mut res: CommitteeSignatures = CommitteeSignatures::new_empty();

    // take1
    let take1_agg_nonces = agg_nonces.take1.clone().try_into().unwrap();
    let mut take1_partial_sigs = [vec![], vec![]];
    partial_sigs.iter().for_each(|r| {
        take1_partial_sigs[0].push(r.take1[0]);
        take1_partial_sigs[1].push(r.take1[1]);
    });
    match graph.take1.aggregate_pre_sigs(&context, &take1_partial_sigs, &take1_agg_nonces) {
        Ok(v) => res.take1 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take1.name()),
    };

    // take2
    let take2_agg_nonces = agg_nonces.take2.clone().try_into().unwrap();
    let take2_partial_sigs = [partial_sigs.iter().map(|r| r.take2[0]).collect()];
    match graph.take2.aggregate_pre_sigs(&context, &take2_partial_sigs, &take2_agg_nonces) {
        Ok(v) => res.take2 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take2.name()),
    };

    // challenge
    let challenge_agg_nonces = agg_nonces.challenge.clone().try_into().unwrap();
    let challenge_partial_sigs = [partial_sigs.iter().map(|r| r.challenge[0]).collect()];
    match graph.challenge.aggregate_pre_sigs(
        &context,
        &challenge_partial_sigs,
        &challenge_agg_nonces,
    ) {
        Ok(v) => res.challenge = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.challenge.name()),
    };

    // watchtower challenge timeout
    let mut timeout_sigs = vec![];
    for (i, tx) in graph.watchtower_challenge_timeouts.iter().enumerate() {
        let agg_nonces = [agg_nonces.watchtower_challenge_timeout[i].clone()];
        let partial_sigs =
            [partial_sigs.iter().map(|r| r.watchtower_challenge_timeout[i]).collect()];
        let sigs = tx
            .aggregate_pre_sigs(&context, &partial_sigs, &agg_nonces)
            .map_err(|e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", tx.name()))?;
        timeout_sigs.extend(sigs);
    }
    res.watchtower_challenge_timeout = timeout_sigs;

    // operator challenge nack
    let mut nack_sigs = vec![];
    for (i, tx) in graph.operator_challenge_nacks.iter().enumerate() {
        let agg_nonces = [
            agg_nonces.operator_challenge_nack[i * 2].clone(),
            agg_nonces.operator_challenge_nack[i * 2 + 1].clone(),
        ];
        let mut partial_sigs_by_input = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            partial_sigs_by_input[0].push(r.operator_challenge_nack[i * 2]);
            partial_sigs_by_input[1].push(r.operator_challenge_nack[i * 2 + 1]);
        });
        let sigs = tx
            .aggregate_pre_sigs(&context, &partial_sigs_by_input, &agg_nonces)
            .map_err(|e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", tx.name()))?;
        nack_sigs.extend(sigs);
    }
    res.operator_challenge_nack = nack_sigs;

    // operator commit timeout
    let operator_commit_timeout_agg_nonces =
        agg_nonces.operator_commit_timeout.clone().try_into().unwrap();
    let mut operator_commit_timeout_partial_sigs = [vec![], vec![]];
    partial_sigs.iter().for_each(|r| {
        operator_commit_timeout_partial_sigs[0].push(r.operator_commit_timeout[0]);
        operator_commit_timeout_partial_sigs[1].push(r.operator_commit_timeout[1]);
    });
    match graph.operator_commit_timeout.aggregate_pre_sigs(
        &context,
        &operator_commit_timeout_partial_sigs,
        &operator_commit_timeout_agg_nonces,
    ) {
        Ok(v) => res.operator_commit_timeout = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.operator_commit_timeout.name()),
    };

    // disprove
    let mut disprove_sigs = vec![];
    for (i, disprove_tx) in graph.disproves.iter().enumerate() {
        let _agg_nonces =
            [agg_nonces.disprove[i * 2].clone(), agg_nonces.disprove[i * 2 + 1].clone()];
        let mut _partial_sigs = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            _partial_sigs[0].push(r.disprove[i * 2]);
            _partial_sigs[1].push(r.disprove[i * 2 + 1]);
        });
        let sigs = disprove_tx.aggregate_pre_sigs(&context, &_partial_sigs, &_agg_nonces).map_err(
            |e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", disprove_tx.name()),
        )?;
        disprove_sigs.extend(sigs);
    }
    res.disprove = disprove_sigs;

    Ok(res)
}

fn taproot_script_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    sighash_type: TapSighashType,
) -> Result<TapSighash> {
    let prevout = prevouts
        .get(input_index)
        .ok_or_else(|| anyhow::anyhow!("missing prevout for input {input_index}"))?;
    if sighash_type == TapSighashType::AllPlusAnyoneCanPay
        || sighash_type == TapSighashType::SinglePlusAnyoneCanPay
        || sighash_type == TapSighashType::NonePlusAnyoneCanPay
    {
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::One(input_index, prevout),
                leaf_hash,
                sighash_type,
            )
            .map_err(|e| anyhow::anyhow!("failed to construct input {input_index} sighash: {e}"))
    } else {
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(prevouts),
                leaf_hash,
                sighash_type,
            )
            .map_err(|e| anyhow::anyhow!("failed to construct input {input_index} sighash: {e}"))
    }
}

fn key_agg_context(committee_pubkeys: &[PublicKey]) -> Result<KeyAggContext> {
    let pubkeys: Vec<Point> =
        committee_pubkeys.iter().map(|public_key| public_key.inner.into()).collect();
    KeyAggContext::new(pubkeys).map_err(|e| anyhow::anyhow!("invalid committee key set: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_taproot_partial_signature(
    committee_pubkeys: &[PublicKey],
    committee_pubkey: &PublicKey,
    pub_nonce: &PubNonce,
    partial_sig: PartialSignature,
    agg_nonce: &AggNonce,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    script: &Script,
    sighash_type: TapSighashType,
) -> Result<()> {
    let key_agg_ctx = key_agg_context(committee_pubkeys)?;
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = taproot_script_spend_sighash(tx, input_index, prevouts, leaf_hash, sighash_type)?;
    verify_partial(&key_agg_ctx, partial_sig, agg_nonce, committee_pubkey.inner, pub_nonce, sighash)
        .map_err(|e| anyhow::anyhow!("invalid partial signature from {committee_pubkey}: {e}"))
}

pub fn verify_taproot_pre_signed_input<T: PreSignedTransaction + BaseTransaction>(
    tx: &T,
    signing_pubkey: &XOnlyPublicKey,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<()> {
    let input = tx
        .tx()
        .input
        .get(input_index)
        .ok_or_else(|| anyhow::anyhow!("{} input {input_index} is missing", tx.name()))?;
    ensure!(
        input.witness.len() == 3,
        "{} input {input_index} must contain signature, script and control block",
        tx.name()
    );
    let signature_bytes = input
        .witness
        .nth(0)
        .ok_or_else(|| anyhow::anyhow!("{} input {input_index} signature is missing", tx.name()))?;
    let witness_script = input
        .witness
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("{} input {input_index} script is missing", tx.name()))?;
    let control_block_bytes = input.witness.nth(2).ok_or_else(|| {
        anyhow::anyhow!("{} input {input_index} control block is missing", tx.name())
    })?;
    let prevout = tx
        .prev_outs()
        .get(input_index)
        .ok_or_else(|| anyhow::anyhow!("{} input {input_index} prevout is missing", tx.name()))?;
    let script = tx
        .prev_scripts()
        .get(input_index)
        .ok_or_else(|| anyhow::anyhow!("{} input {input_index} script is missing", tx.name()))?;

    ensure!(
        witness_script == script.as_bytes(),
        "{} input {input_index} witness script mismatch",
        tx.name()
    );
    ensure!(
        prevout.script_pubkey.is_p2tr(),
        "{} input {input_index} prevout is not P2TR",
        tx.name()
    );
    let output_key =
        XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..]).map_err(|e| {
            anyhow::anyhow!("{} input {input_index} output key is invalid: {e}", tx.name())
        })?;
    let control_block = ControlBlock::decode(control_block_bytes).map_err(|e| {
        anyhow::anyhow!("{} input {input_index} control block is invalid: {e}", tx.name())
    })?;
    ensure!(
        control_block.verify_taproot_commitment(SECP256K1, output_key, script),
        "{} input {input_index} control block does not commit to the expected script",
        tx.name()
    );

    let signature = TaprootSignature::from_slice(signature_bytes).map_err(|e| {
        anyhow::anyhow!("{} input {input_index} signature is invalid: {e}", tx.name())
    })?;
    ensure!(
        signature.sighash_type == sighash_type,
        "{} input {input_index} sighash type mismatch",
        tx.name()
    );
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = taproot_script_spend_sighash(
        tx.tx(),
        input_index,
        tx.prev_outs(),
        leaf_hash,
        sighash_type,
    )?;
    SECP256K1.verify_schnorr(&signature.signature, &Message::from(sighash), signing_pubkey).map_err(
        |e| anyhow::anyhow!("{} input {input_index} signature verification failed: {e}", tx.name()),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_pre_signed_input<T: PreSignedTransaction + BaseTransaction>(
    tx: &T,
    committee_pubkeys: &[PublicKey],
    committee_pubkey: &PublicKey,
    pub_nonce: &PubNonce,
    partial_sig: PartialSignature,
    agg_nonce: &AggNonce,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<()> {
    verify_taproot_partial_signature(
        committee_pubkeys,
        committee_pubkey,
        pub_nonce,
        partial_sig,
        agg_nonce,
        tx.tx(),
        input_index,
        tx.prev_outs(),
        &tx.prev_scripts()[input_index],
        sighash_type,
    )
    .map_err(|e| anyhow::anyhow!("fail to verify pre-signature {}[{input_index}]: {e}", tx.name()))
}

pub fn verify_graph_committee_partial_sigs(
    graph: &BitvmGcGraph,
    committee_pubkeys: &[PublicKey],
    committee_pubkey: &PublicKey,
    pub_nonces: &CommitteePubNonces,
    agg_nonces: &CommitteeAggNonces,
    partial_sigs: &CommitteePartialSignatures,
) -> Result<()> {
    ensure!(
        committee_pubkeys.contains(committee_pubkey),
        "committee pubkey {committee_pubkey} is not in the committee set"
    );
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    pub_nonces.validate_length(watchtower_num, verifier_num)?;
    agg_nonces.validate_length(watchtower_num, verifier_num)?;
    partial_sigs.validate_length(watchtower_num, verifier_num)?;

    verify_pre_signed_input(
        &graph.take1,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.take1[0],
        partial_sigs.take1[0],
        &agg_nonces.take1[0],
        0,
        TapSighashType::All,
    )?;
    verify_pre_signed_input(
        &graph.take1,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.take1[1],
        partial_sigs.take1[1],
        &agg_nonces.take1[1],
        3,
        TapSighashType::All,
    )?;
    verify_pre_signed_input(
        &graph.take2,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.take2[0],
        partial_sigs.take2[0],
        &agg_nonces.take2[0],
        0,
        TapSighashType::All,
    )?;
    verify_pre_signed_input(
        &graph.challenge,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.challenge[0],
        partial_sigs.challenge[0],
        &agg_nonces.challenge[0],
        0,
        TapSighashType::SinglePlusAnyoneCanPay,
    )?;

    for (i, tx) in graph.watchtower_challenge_timeouts.iter().enumerate() {
        verify_pre_signed_input(
            tx,
            committee_pubkeys,
            committee_pubkey,
            &pub_nonces.watchtower_challenge_timeout[i],
            partial_sigs.watchtower_challenge_timeout[i],
            &agg_nonces.watchtower_challenge_timeout[i],
            1,
            TapSighashType::None,
        )?;
    }

    for (i, tx) in graph.operator_challenge_nacks.iter().enumerate() {
        verify_pre_signed_input(
            tx,
            committee_pubkeys,
            committee_pubkey,
            &pub_nonces.operator_challenge_nack[i * 2],
            partial_sigs.operator_challenge_nack[i * 2],
            &agg_nonces.operator_challenge_nack[i * 2],
            0,
            TapSighashType::All,
        )?;
        verify_pre_signed_input(
            tx,
            committee_pubkeys,
            committee_pubkey,
            &pub_nonces.operator_challenge_nack[i * 2 + 1],
            partial_sigs.operator_challenge_nack[i * 2 + 1],
            &agg_nonces.operator_challenge_nack[i * 2 + 1],
            1,
            TapSighashType::All,
        )?;
    }

    verify_pre_signed_input(
        &graph.operator_commit_timeout,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.operator_commit_timeout[0],
        partial_sigs.operator_commit_timeout[0],
        &agg_nonces.operator_commit_timeout[0],
        0,
        TapSighashType::All,
    )?;
    verify_pre_signed_input(
        &graph.operator_commit_timeout,
        committee_pubkeys,
        committee_pubkey,
        &pub_nonces.operator_commit_timeout[1],
        partial_sigs.operator_commit_timeout[1],
        &agg_nonces.operator_commit_timeout[1],
        1,
        TapSighashType::All,
    )?;

    for (i, tx) in graph.disproves.iter().enumerate() {
        verify_pre_signed_input(
            tx,
            committee_pubkeys,
            committee_pubkey,
            &pub_nonces.disprove[i * 2],
            partial_sigs.disprove[i * 2],
            &agg_nonces.disprove[i * 2],
            0,
            TapSighashType::None,
        )?;
        verify_pre_signed_input(
            tx,
            committee_pubkeys,
            committee_pubkey,
            &pub_nonces.disprove[i * 2 + 1],
            partial_sigs.disprove[i * 2 + 1],
            &agg_nonces.disprove[i * 2 + 1],
            1,
            TapSighashType::None,
        )?;
    }

    Ok(())
}

pub fn verify_graph_committee_pre_signatures(graph: &BitvmGcGraph) -> Result<()> {
    ensure!(graph.committee_pre_signed(), "graph is not pre-signed by the committee");
    let (_, committee_pubkey) =
        generate_n_of_n_public_key(&graph.parameters.instance_parameters.committee_pubkeys);
    ensure!(
        committee_pubkey == graph.parameters.instance_parameters.n_of_n_taproot_public_key(),
        "graph committee aggregate public key mismatch"
    );

    verify_taproot_pre_signed_input(&graph.take1, &committee_pubkey, 0, TapSighashType::All)?;
    verify_taproot_pre_signed_input(&graph.take1, &committee_pubkey, 3, TapSighashType::All)?;
    verify_taproot_pre_signed_input(&graph.take2, &committee_pubkey, 0, TapSighashType::All)?;
    verify_taproot_pre_signed_input(
        &graph.challenge,
        &committee_pubkey,
        0,
        TapSighashType::SinglePlusAnyoneCanPay,
    )?;
    for tx in &graph.watchtower_challenge_timeouts {
        verify_taproot_pre_signed_input(tx, &committee_pubkey, 1, TapSighashType::None)?;
    }
    for tx in &graph.operator_challenge_nacks {
        verify_taproot_pre_signed_input(tx, &committee_pubkey, 0, TapSighashType::All)?;
        verify_taproot_pre_signed_input(tx, &committee_pubkey, 1, TapSighashType::All)?;
    }
    verify_taproot_pre_signed_input(
        &graph.operator_commit_timeout,
        &committee_pubkey,
        0,
        TapSighashType::All,
    )?;
    verify_taproot_pre_signed_input(
        &graph.operator_commit_timeout,
        &committee_pubkey,
        1,
        TapSighashType::All,
    )?;
    for tx in &graph.disproves {
        verify_taproot_pre_signed_input(tx, &committee_pubkey, 0, TapSighashType::None)?;
        verify_taproot_pre_signed_input(tx, &committee_pubkey, 1, TapSighashType::None)?;
    }
    Ok(())
}

pub fn verify_pegin_confirm_partial_sig(
    instance_parameters: &BitvmGcInstanceParameters,
    committee_pubkeys: &[PublicKey],
    committee_pubkey: &PublicKey,
    pub_nonce: &PubNonce,
    agg_nonce: &AggNonce,
    partial_sig: PartialSignature,
) -> Result<()> {
    ensure!(
        committee_pubkeys.contains(committee_pubkey),
        "committee pubkey {committee_pubkey} is not in the committee set"
    );
    let pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    verify_pre_signed_input(
        &pegin_confirm,
        committee_pubkeys,
        committee_pubkey,
        pub_nonce,
        partial_sig,
        agg_nonce,
        0,
        TapSighashType::All,
    )
}

pub fn push_committee_pre_signatures(
    graph: &mut BitvmGcGraph,
    sigs: &CommitteeSignatures,
) -> Result<()> {
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if graph.committee_pre_signed {
        bail!("already pre-signed by committee".to_string())
    };
    sigs.validate_length(watchtower_num, verifier_num)?;

    let connector_0 = graph.parameters.connector_0();
    let connector_a = graph.connector_a();
    let connector_c = graph.connector_c();
    let connector_d = graph.connector_d();
    let connector_e = graph.connector_e();
    let connector_f = graph.connector_f();
    let ack_connectors = graph.ack_connectors();

    // take1
    graph.take1.push_pre_sigs(&connector_0, &connector_c, sigs.take1.clone().try_into().unwrap());

    // take2
    graph.take2.push_pre_sigs(&connector_0, sigs.take2.clone().try_into().unwrap());

    // challenge
    graph.challenge.push_pre_sigs(&connector_a, sigs.challenge.clone().try_into().unwrap());

    // watchtower challenge timeout
    for (i, tx) in graph.watchtower_challenge_timeouts.iter_mut().enumerate() {
        tx.push_pre_sigs(
            &ack_connectors[i],
            sigs.watchtower_challenge_timeout[i..(i + 1)].try_into().unwrap(),
        );
    }

    // operator challenge nack
    for (i, tx) in graph.operator_challenge_nacks.iter_mut().enumerate() {
        tx.push_pre_sigs(
            &ack_connectors[i],
            &connector_f,
            sigs.operator_challenge_nack[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    // operator commit timeout
    graph.operator_commit_timeout.push_pre_sigs(
        &connector_e,
        &connector_f,
        sigs.operator_commit_timeout.clone().try_into().unwrap(),
    );

    // disprove
    let prover_connectors = graph.parameters.prover_connectors();
    for (i, disprove_tx) in graph.disproves.iter_mut().enumerate() {
        disprove_tx.push_pre_sigs(
            &prover_connectors[i],
            &connector_d,
            sigs.disprove[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    graph.committee_pre_signed = true;
    Ok(())
}

pub fn generate_nonce_from_seed(
    seed: String,
    graph_index: usize,
    signer_keypair: Keypair,
    watchtower_num: usize,
    verifier_num: usize,
) -> (CommitteePubNonces, CommitteeSecNonces, CommitteeNonceSignatures) {
    let graph_seed = hkdf_derive_bytes(
        seed.as_bytes(),
        COMMITTEE_NONCE_HKDF_SALT,
        format!("graph/{graph_index}").as_bytes(),
        32,
    );
    let mut pub_nonces = CommitteePubNonces::new_empty();
    let mut sec_nonces = CommitteeSecNonces::new_empty();
    let mut nonce_sigs = CommitteeNonceSignatures::new_empty();
    let mut index = 0;
    {
        // take1
        for _ in 0..take1_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take1.push(pub_nonce);
            sec_nonces.take1.push(sec_nonce);
            nonce_sigs.take1.push(nonce_sig);
            index += 1;
        }
    }
    {
        // take2
        for _ in 0..take2_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take2.push(pub_nonce);
            sec_nonces.take2.push(sec_nonce);
            nonce_sigs.take2.push(nonce_sig);
            index += 1;
        }
    }
    {
        // challenge
        for _ in 0..challenge_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.challenge.push(pub_nonce);
            sec_nonces.challenge.push(sec_nonce);
            nonce_sigs.challenge.push(nonce_sig);
            index += 1;
        }
    }
    {
        // watchtower challenge timeout
        for _ in 0..watchtower_challenge_timeout_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.watchtower_challenge_timeout.push(pub_nonce);
            sec_nonces.watchtower_challenge_timeout.push(sec_nonce);
            nonce_sigs.watchtower_challenge_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // operator challenge nack
        for _ in 0..operator_challenge_nack_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.operator_challenge_nack.push(pub_nonce);
            sec_nonces.operator_challenge_nack.push(sec_nonce);
            nonce_sigs.operator_challenge_nack.push(nonce_sig);
            index += 1;
        }
    }
    {
        // operator commit timeout
        for _ in 0..operator_commit_timeout_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.operator_commit_timeout.push(pub_nonce);
            sec_nonces.operator_commit_timeout.push(sec_nonce);
            nonce_sigs.operator_commit_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // disprove
        for _ in 0..disprove_pre_sign_num(verifier_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.disprove.push(pub_nonce);
            sec_nonces.disprove.push(sec_nonce);
            nonce_sigs.disprove.push(nonce_sig);
            index += 1;
        }
    }
    (pub_nonces, sec_nonces, nonce_sigs)
}

pub fn verify_nonce_signatures(
    pubkey: &XOnlyPublicKey,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
    watchtower_num: usize,
    verifier_num: usize,
) -> Result<bool> {
    pub_nonces.validate_length(watchtower_num, verifier_num)?;
    nonce_sigs.validate_length(watchtower_num, verifier_num)?;

    fn verify_vec(pubkey: &XOnlyPublicKey, nonces: &[PubNonce], sigs: &[SchnorrSignature]) -> bool {
        if nonces.len() != sigs.len() {
            return false;
        }
        nonces.iter().zip(sigs.iter()).all(|(nonce, sig)| verify_public_nonce(sig, nonce, pubkey))
    }

    Ok(verify_vec(pubkey, &pub_nonces.take1, &nonce_sigs.take1)
        && verify_vec(pubkey, &pub_nonces.take2, &nonce_sigs.take2)
        && verify_vec(pubkey, &pub_nonces.challenge, &nonce_sigs.challenge)
        && verify_vec(
            pubkey,
            &pub_nonces.watchtower_challenge_timeout,
            &nonce_sigs.watchtower_challenge_timeout,
        )
        && verify_vec(
            pubkey,
            &pub_nonces.operator_challenge_nack,
            &nonce_sigs.operator_challenge_nack,
        )
        && verify_vec(
            pubkey,
            &pub_nonces.operator_commit_timeout,
            &nonce_sigs.operator_commit_timeout,
        )
        && verify_vec(pubkey, &pub_nonces.disprove, &nonce_sigs.disprove))
}

pub(crate) fn generate_nonce(
    signer_keypair: Keypair,
    seed: &[u8],
    index: usize,
) -> (SecNonce, PubNonce, SchnorrSignature) {
    let nonce_seed =
        hkdf_derive_bytes(seed, COMMITTEE_NONCE_HKDF_SALT, format!("nonce/{index}").as_bytes(), 32);
    let nonce_seed: [u8; 32] =
        nonce_seed.try_into().expect("hkdf output length is fixed to 32 bytes");
    let sec_nonce = SecNonce::build(nonce_seed).build();
    let pub_nonce = sec_nonce.public_nonce();
    let nonce_signature = signer_keypair.sign_schnorr(get_nonce_message(&pub_nonce));
    (sec_nonce, pub_nonce, nonce_signature)
}
