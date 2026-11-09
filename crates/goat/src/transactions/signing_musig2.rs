#![allow(clippy::too_many_arguments)]
use bitcoin::{
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Script, TapLeafHash, TapSighash, TapSighashType, Transaction, TxOut,
};
use musig2::{
    aggregate_partial_signatures,
    errors::{SigningError, VerifyError},
    secp::{MaybeScalar, Point},
    sign_partial, AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecNonce,
};

use super::super::contexts::{base::BaseContext, committee::CommitteeContext};

fn taproot_script_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    sighash_type: TapSighashType,
) -> TapSighash {
    if sighash_type == TapSighashType::AllPlusAnyoneCanPay
        || sighash_type == TapSighashType::SinglePlusAnyoneCanPay
        || sighash_type == TapSighashType::NonePlusAnyoneCanPay
    {
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::One(input_index, &prevouts[input_index]),
                leaf_hash,
                sighash_type,
            )
            .expect("Failed to construct sighash")
    } else {
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(prevouts),
                leaf_hash,
                sighash_type,
            )
            .expect("Failed to construct sighash")
    }
}

pub fn generate_nonce() -> SecNonce {
    SecNonce::build(&mut rand::rngs::OsRng).build()
}

pub fn generate_aggregated_nonce(nonces: &Vec<PubNonce>) -> AggNonce {
    AggNonce::sum(nonces)
}

pub fn generate_taproot_partial_signature(
    context: &CommitteeContext,
    tx: &Transaction,
    secret_nonce: &SecNonce,
    aggregated_nonce: &AggNonce,
    input_index: usize,
    prevouts: &[TxOut],
    script: &Script,
    sighash_type: TapSighashType,
) -> Result<MaybeScalar, SigningError> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        context
            .n_of_n_public_keys
            .iter()
            .map(|&public_key| public_key.inner.into()),
    ); // TODO: The tests will reveal whether this conversion works as expected.
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = taproot_script_spend_sighash(tx, input_index, prevouts, leaf_hash, sighash_type);

    sign_partial(
        &key_agg_ctx,
        context.committee_keypair.secret_key(),
        secret_nonce.clone(),
        aggregated_nonce,
        sighash,
    )
}

pub fn generate_taproot_aggregated_signature(
    context: &dyn BaseContext,
    tx: &Transaction,
    aggregated_nonce: &AggNonce,
    input_index: usize,
    prevouts: &[TxOut],
    script: &Script,
    sighash_type: TapSighashType,
    partial_signatures: Vec<PartialSignature>,
) -> Result<LiftedSignature, VerifyError> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        context
            .n_of_n_public_keys()
            .iter()
            .map(|&public_key| public_key.inner.into()),
    );
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash_cache =
        taproot_script_spend_sighash(tx, input_index, prevouts, leaf_hash, sighash_type);

    aggregate_partial_signatures(
        &key_agg_ctx,
        aggregated_nonce,
        partial_signatures,
        sighash_cache,
    )
}
