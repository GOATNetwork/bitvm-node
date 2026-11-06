use anyhow::{Result, bail};
use bitcoin::{Address, Amount, TapSighashType, Transaction, TxIn, key::Keypair};
use bitcoin::{Network, PublicKey, Witness, XOnlyPublicKey};
use goat::assert_scripts::{
    OperatorAssertPublicKey, OperatorAssertSecretKey, OperatorCommitPubinPublicKey,
    OperatorCommitPubinSecretKey,
};
use goat::constants::TimelockConfig;
use goat::transactions::assert::{
    DisproveTransaction, OperatorAssertTransaction, VerifierAssertTransaction, wrongly_challenged,
};
use goat::transactions::base::DUST_AMOUNT;
use goat::transactions::challenge::ChallengeTransaction;
use goat::transactions::kickoff::KickoffTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::{
    ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction, PrekickoffTransaction,
    QuickChallengeTransaction, operator_skip_kickoff,
};
use goat::transactions::take1::Take1Transaction;
use goat::transactions::take2::Take2Transaction;
use goat::transactions::watchtower_challenge::{
    OperatorChallengeNackTransaction, OperatorCommitTimeoutTransaction,
    WatchtowerChallengeInitTransaction, WatchtowerChallengeTimeoutTransaction,
    operator_challenge_ack, operator_commit_pubin,
};
use goat::wots::{Wots, Wots96};

use crate::committee::verify_taproot_pre_signed_input;
use crate::keys::hkdf_derive_bytes;
use crate::timelocks::{
    default_timelock_config, take1_timelock_blocks, take2_timelock_blocks, validate_timelock_config,
};
use crate::types::{BitvmGcGraph, BitvmGcGraphParameters};

const OPERATOR_ASSERT_WOTS_HKDF_SALT: &[u8] = b"bitvm-gc/operator-wots/v2";
const OPERATOR_COMMIT_PUBIN_WOTS_HKDF_SALT: &[u8] = b"bitvm-gc/operator-commit-pubin-wots/v2";

#[allow(deprecated)]
pub fn generate_assert_wots_key(seed: &str) -> (OperatorAssertSecretKey, OperatorAssertPublicKey) {
    let sec_str = hex::encode(hkdf_derive_bytes(
        seed.as_bytes(),
        OPERATOR_ASSERT_WOTS_HKDF_SALT,
        b"wots96/0",
        96,
    ));
    let secret = Wots96::secret_from_str(&sec_str);
    let public = Wots96::generate_public_key(&secret);
    (secret, public)
}

#[allow(deprecated)]
pub fn generate_commit_pubin_wots_key(
    seed: &str,
) -> (OperatorCommitPubinSecretKey, OperatorCommitPubinPublicKey) {
    let sec_str = hex::encode(hkdf_derive_bytes(
        seed.as_bytes(),
        OPERATOR_COMMIT_PUBIN_WOTS_HKDF_SALT,
        b"wots96/0",
        96,
    ));
    let secret = Wots96::secret_from_str(&sec_str);
    let public = Wots96::generate_public_key(&secret);
    (secret, public)
}

pub fn operator_presig_num() -> usize {
    6
}

pub fn generate_bitvm_graph(params: BitvmGcGraphParameters) -> Result<BitvmGcGraph> {
    params.validate_basic()?;
    validate_timelock_config(params.network(), &params.timelock_config)?;

    let watchtower_num = params.watchtower_pubkeys.len();
    let verifier_num = params.gc_data.len();
    if params.watchtower_ack_hashlocks.len() != watchtower_num {
        bail!(
            "watchtower ack hashlock count {} does not match watchtower count {watchtower_num}",
            params.watchtower_ack_hashlocks.len()
        );
    }

    let (_, pegin, _) = params.instance_parameters.build_pegin_tx()?;
    let connector_0_input = pegin
        .connector_0_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-0 input: {e}"))?;

    let cur_prekickoff_connector = params.prekickoff_connector();
    let next_force_skip_connector = params.force_skip_connector();
    let next_kickoff_connector = params.kickoff_connector();
    let next_prekickoff_connector = params.prekickoff_connector();
    let cur_prekickoff = params.prekickoff_parameters.cur_prekickoff_txn.clone();
    let cur_prekickoff_connector_input = cur_prekickoff
        .prekickoff_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get current pre-kickoff connector input: {e}"))?;
    let next_prekickoff = PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        params.prekickoff_parameters.replenish_fee_inputs.clone(),
        params.prekickoff_parameters.replenish_fee_prev_outs.clone(),
        params.prekickoff_parameters.fee_amount,
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))?;
    let next_force_skip_connector_input = next_prekickoff
        .force_skip_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get next force-skip connector input: {e}"))?;
    let next_prekickoff_connector_input = next_prekickoff
        .prekickoff_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get next pre-kickoff connector input: {e}"))?;

    // kickoff
    let kickoff_connector_input = cur_prekickoff
        .kickoff_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get kickoff connector input: {e}"))?;
    let kickoff_connector = params.kickoff_connector();
    let connector_a = params.connector_a();
    let connector_b = params.connector_b();
    let connector_c = params.connector_c();
    let guardian_connector = params.guardian_connector();
    let kickoff = KickoffTransaction::new_for_validation(
        &kickoff_connector,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        &kickoff_connector_input,
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create kickoff txn: {e}"))?;
    let connector_a_input = kickoff
        .connector_a_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-a input: {e}"))?;
    let connector_b_input = kickoff
        .connector_b_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-b input: {e}"))?;
    let connector_c_input = kickoff
        .connector_c_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-c input: {e}"))?;
    let guardian_connector_input = kickoff
        .guardian_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get guardian connector input: {e}"))?;

    // prekickoff challenge
    let force_skip_kickoff = ForceSkipKickoffTransaction::new_for_validation(
        &kickoff_connector,
        &next_force_skip_connector,
        kickoff_connector_input,
        next_force_skip_connector_input.clone(),
    );
    let quick_challenge = QuickChallengeTransaction::new_for_validation(
        &guardian_connector,
        &next_force_skip_connector,
        guardian_connector_input.clone(),
        next_force_skip_connector_input,
    );
    let challenge_incomplete_kickoff = ChallengeIncompleteKickoffTransaction::new_for_validation(
        &guardian_connector,
        &next_prekickoff_connector,
        guardian_connector_input.clone(),
        next_prekickoff_connector_input,
    );

    // take-1
    let connector_0 = params.connector_0();
    let take1 = Take1Transaction::new_for_validation(
        &connector_0,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        connector_0_input.clone(),
        connector_a_input.clone(),
        connector_b_input.clone(),
        connector_c_input.clone(),
        guardian_connector_input.clone(),
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-1 txn: {e}"))?;

    // challenge
    let challenge = ChallengeTransaction::new_for_validation(
        &connector_a,
        connector_a_input,
        params.challenge_amount,
        &params.operator_receive_address,
    );

    // watchtower-challenge
    let connector_e = params.connector_e();
    let connector_f = params.connector_f();
    let watchtower_challenge_connectors = params.watchtower_challenge_connectors();
    let ack_connectors = params.ack_connectors();
    let watchtower_challenge_init = WatchtowerChallengeInitTransaction::new_for_validation(
        &connector_b,
        &connector_e,
        &connector_f,
        &watchtower_challenge_connectors,
        &ack_connectors,
        connector_b_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create watchtower-challenge-init txn: {e}"))?;
    let connector_e_input = watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-e input: {e}"))?;
    let connector_f_input = watchtower_challenge_init
        .connector_f_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-f input: {e}"))?;
    let mut watchtower_challenge_timeouts = Vec::with_capacity(watchtower_num);
    let mut operator_challenge_nacks = Vec::with_capacity(watchtower_num);
    for (i, (watchtower_connector, ack_connector)) in
        watchtower_challenge_connectors.iter().zip(ack_connectors.iter()).enumerate()
    {
        let watchtower_input = watchtower_challenge_init
            .watchtower_connector_input(i)
            .map_err(|e| anyhow::anyhow!("failed to get watchtower connector input {i}: {e}"))?;
        let ack_input = watchtower_challenge_init
            .ack_connector_input(i)
            .map_err(|e| anyhow::anyhow!("failed to get ack connector input {i}: {e}"))?;
        watchtower_challenge_timeouts.push(
            WatchtowerChallengeTimeoutTransaction::new_for_validation(
                watchtower_connector,
                ack_connector,
                watchtower_input,
                ack_input.clone(),
            ),
        );
        operator_challenge_nacks.push(OperatorChallengeNackTransaction::new_for_validation(
            ack_connector,
            &connector_f,
            ack_input,
            connector_f_input.clone(),
        ));
    }
    let operator_commit_timeout = OperatorCommitTimeoutTransaction::new_for_validation(
        &connector_e,
        &connector_f,
        connector_e_input.clone(),
        connector_f_input.clone(),
    );

    // prover-assert
    let connector_d = params.connector_d();
    let verifier_connectors = params.verifier_connectors();
    let operator_assert = OperatorAssertTransaction::new_for_validation(
        &connector_c,
        &verifier_connectors,
        &connector_d,
        connector_c_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create operator assert txn: {e}"))?;
    let connector_d_input = operator_assert
        .connector_d_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-d input: {e}"))?;

    // verifier-asserts and disproves
    let mut verifier_asserts = Vec::with_capacity(verifier_num);
    let mut disproves = Vec::with_capacity(verifier_num);
    for (i, verifier_connector) in verifier_connectors.iter().enumerate() {
        let verifier_input = operator_assert
            .verifier_connector_input(i)
            .map_err(|e| anyhow::anyhow!("failed to get verifier connector input {i}: {e}"))?;
        let prover_connector = params.prover_connector(i)?;
        let verifier_assert = VerifierAssertTransaction::new_for_validation(
            verifier_connector,
            &prover_connector,
            verifier_input,
        )
        .map_err(|e| anyhow::anyhow!("failed to create verifier assert txn {i}: {e}"))?;
        let prover_input = verifier_assert
            .prover_connector_input()
            .map_err(|e| anyhow::anyhow!("failed to get prover connector input {i}: {e}"))?;
        let disprove = DisproveTransaction::new_for_validation(
            &prover_connector,
            &connector_d,
            prover_input,
            connector_d_input.clone(),
            Vec::new(),
        )
        .map_err(|e| anyhow::anyhow!("failed to create disprove txn {i}: {e}"))?;
        verifier_asserts.push(verifier_assert);
        disproves.push(disprove);
    }

    // take-2
    let take2 = Take2Transaction::new_for_validation(
        &connector_0,
        &connector_d,
        &connector_f,
        &guardian_connector,
        connector_0_input,
        connector_d_input,
        connector_f_input,
        guardian_connector_input,
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-2 txn: {e}"))?;

    Ok(BitvmGcGraph {
        operator_pre_signed: false,
        committee_pre_signed: false,
        parameters: params,
        cur_prekickoff,
        next_prekickoff,
        force_skip_kickoff,
        quick_challenge,
        challenge_incomplete_kickoff,
        pegin,
        kickoff,
        take1,
        challenge,
        watchtower_challenge_init,
        watchtower_challenge_timeouts,
        operator_challenge_nacks,
        operator_commit_timeout,
        operator_assert,
        verifier_asserts,
        disproves,
        take2,
    })
}

pub fn operator_pre_sign(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Vec<Witness>> {
    let keypair_pubkey = PublicKey::from(operator_keypair.public_key());
    if keypair_pubkey != graph.parameters.operator_pubkey {
        bail!("operator keypair does not match graph operator pubkey".to_string())
    };

    let mut wits = vec![];
    let context = graph.parameters.get_operator_context(operator_keypair)?;

    // presign force_skip_kickoff
    let kickoff_connector = graph.parameters.kickoff_connector();
    let next_force_skip_connector = graph.parameters.force_skip_connector();
    graph.force_skip_kickoff.pre_sign_and_push(
        &context,
        &kickoff_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.force_skip_kickoff.tx().input[0].witness.clone());
    wits.push(graph.force_skip_kickoff.tx().input[1].witness.clone());

    // presign quick_challenge
    let guardian_connector = graph.guardian_connector();
    graph.quick_challenge.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.quick_challenge.tx().input[0].witness.clone());
    wits.push(graph.quick_challenge.tx().input[1].witness.clone());

    // presign challenge_incomplete_kickoff
    let next_prekickoff_connector = graph.parameters.prekickoff_connector();
    graph.challenge_incomplete_kickoff.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_prekickoff_connector,
    );
    wits.push(graph.challenge_incomplete_kickoff.tx().input[0].witness.clone());
    wits.push(graph.challenge_incomplete_kickoff.tx().input[1].witness.clone());

    graph.operator_pre_signed = true;
    Ok(wits)
}

pub fn push_operator_pre_signature(
    graph: &mut BitvmGcGraph,
    signed_witness: &[Witness],
) -> Result<()> {
    if graph.operator_pre_signed {
        bail!("already pre-signed by operator".to_string())
    };
    if signed_witness.len() != operator_presig_num() {
        bail!("invalid number of pre-signatures".to_string())
    };

    graph.force_skip_kickoff.tx_mut().input[0].witness = signed_witness[0].clone();
    graph.force_skip_kickoff.tx_mut().input[1].witness = signed_witness[1].clone();
    graph.quick_challenge.tx_mut().input[0].witness = signed_witness[2].clone();
    graph.quick_challenge.tx_mut().input[1].witness = signed_witness[3].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[0].witness = signed_witness[4].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[1].witness = signed_witness[5].clone();

    graph.operator_pre_signed = true;
    Ok(())
}

pub fn verify_graph_operator_pre_signatures(graph: &BitvmGcGraph) -> Result<()> {
    if !graph.operator_pre_signed() {
        bail!("graph is not pre-signed by the operator");
    }
    let operator_pubkey = XOnlyPublicKey::from(graph.parameters.operator_pubkey);

    verify_taproot_pre_signed_input(
        &graph.force_skip_kickoff,
        &operator_pubkey,
        0,
        TapSighashType::None,
    )?;
    verify_taproot_pre_signed_input(
        &graph.force_skip_kickoff,
        &operator_pubkey,
        1,
        TapSighashType::None,
    )?;
    verify_taproot_pre_signed_input(
        &graph.quick_challenge,
        &operator_pubkey,
        0,
        TapSighashType::None,
    )?;
    verify_taproot_pre_signed_input(
        &graph.quick_challenge,
        &operator_pubkey,
        1,
        TapSighashType::None,
    )?;
    verify_taproot_pre_signed_input(
        &graph.challenge_incomplete_kickoff,
        &operator_pubkey,
        0,
        TapSighashType::None,
    )?;
    verify_taproot_pre_signed_input(
        &graph.challenge_incomplete_kickoff,
        &operator_pubkey,
        1,
        TapSighashType::None,
    )?;
    Ok(())
}

/// remember to sign replensish inputs (if any) after this
pub fn operator_sign_prekickoff_input_0(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let prev_prekickoff_connector = graph.parameters.prekickoff_connector();
    graph.cur_prekickoff.sign_input_0(&operator_context, &prev_prekickoff_connector);
    Ok(graph.cur_prekickoff.tx().clone())
}

pub fn operator_sign_skip_kickoff(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
    operator_receive_address: Address,
    fee_rate: f64,
) -> Result<Option<Transaction>> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = graph.parameters.kickoff_connector();
    let kickoff_connector_input = graph
        .cur_prekickoff
        .kickoff_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get kickoff connector input: {e}"))?;
    // create a sample tx to estimate fee
    let sample_tx = operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input.clone(),
        Amount::ZERO,
        operator_receive_address.clone(),
    )
    .map_err(|e| anyhow::anyhow!("failed to create sample skip-kickoff txn: {e}"))?;

    let fee_amount =
        Amount::from_sat((sample_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if fee_amount + Amount::from_sat(DUST_AMOUNT) >= kickoff_connector_input.amount {
        // if fee_amount > input_amount - dust_amount, skip-kickoff tx is meaningless
        return Ok(None);
    }
    match operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input,
        fee_amount,
        operator_receive_address,
    ) {
        Ok(tx) => Ok(Some(tx)),
        Err(e) => bail!("failed to create skip-kickoff txn: {e}"),
    }
}

pub fn operator_sign_kickoff(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = graph.parameters.kickoff_connector();
    graph.kickoff.sign_input_0(&operator_context, &kickoff_connector);
    Ok(graph.kickoff.tx().clone())
}

pub fn operator_sign_take1(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_a = graph.connector_a();
    let connector_b = graph.connector_b();
    let guardian_connector = graph.guardian_connector();
    graph.take1.sign_input_1(&operator_context, &connector_a);
    graph.take1.sign_input_2(&operator_context, &connector_b);
    graph.take1.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take1.tx().clone())
}

pub fn operator_sign_take2(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_d = graph.connector_d();
    let connector_f = graph.connector_f();
    let guardian_connector = graph.guardian_connector();
    graph.take2.sign_input_1(&operator_context, &connector_d);
    graph.take2.sign_input_2(&operator_context, &connector_f);
    graph.take2.sign_input_3(&operator_context, &guardian_connector);
    Ok(graph.take2.tx().clone())
}

pub fn operator_sign_watchtower_challenge_init(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_b = graph.connector_b();
    graph.watchtower_challenge_init.sign_input_0(&operator_context, &connector_b);
    Ok(graph.watchtower_challenge_init.tx().clone())
}

pub fn operator_sign_watchtower_challenge_timeout(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
    watchtower_index: usize,
) -> Result<Transaction> {
    if watchtower_index >= graph.watchtower_challenge_timeouts.len() {
        bail!("invalid watchtower index {watchtower_index}")
    };
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let watchtower_challenge_connector = graph.watchtower_challenge_connector(watchtower_index)?;
    graph.watchtower_challenge_timeouts[watchtower_index]
        .sign_input_0(&operator_context, &watchtower_challenge_connector);
    Ok(graph.watchtower_challenge_timeouts[watchtower_index].tx().clone())
}

pub fn operator_sign_challenge_ack(
    graph: &BitvmGcGraph,
    watchtower_index: usize,
    preimage: &[u8],
) -> Result<TxIn> {
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("invalid watchtower index {watchtower_index}")
    };
    let ack_connector = graph.ack_connector(watchtower_index)?;
    let input = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|e| anyhow::anyhow!("failed to get ack connector input: {e}"))?;
    operator_challenge_ack(&ack_connector, preimage, input)
        .map_err(|e| anyhow::anyhow!("failed to sign operator challenge ack: {e}"))
}

pub fn operator_sign_commit_pubin(
    graph: &BitvmGcGraph,
    wots_secret_key: &OperatorCommitPubinSecretKey,
    pubin_commitment: &[u8; 96],
) -> Result<TxIn> {
    if Wots96::generate_public_key(wots_secret_key)
        != graph.parameters.operator_commit_pubin_wots_pubkey
    {
        bail!("provided pubin WOTS secret key does not match expected public key")
    };

    let connector_e = graph.connector_e();
    let input = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-e input: {e}"))?;
    operator_commit_pubin(&connector_e, pubin_commitment, wots_secret_key, input)
        .map_err(|e| anyhow::anyhow!("failed to sign operator commit pubin: {e}"))
}

pub fn operator_sign_assert(
    graph: &mut BitvmGcGraph,
    wots_secret_key: &OperatorAssertSecretKey,
    proof: &[u8; 96],
    pi2: &[u8],
    pi3: &[u8],
) -> Result<Transaction> {
    if Wots96::generate_public_key(wots_secret_key) != graph.parameters.operator_assert_wots_pubkey
    {
        bail!("provided WOTS secret key does not match expected public key".to_string())
    };

    let connector_c = graph.connector_c();
    graph
        .operator_assert
        .operator_commit_proof(wots_secret_key, &connector_c, proof, pi2, pi3)
        .map_err(|e| anyhow::anyhow!("failed to sign operator assert: {e}"))?;
    Ok(graph.operator_assert.tx().clone())
}

pub fn operator_sign_wrongly_challenged(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    final_msg: &[u8],
) -> Result<(TxIn, Amount)> {
    if verifier_index >= graph.verifier_asserts.len() {
        bail!("invalid verifier index {verifier_index}".to_string())
    };

    let prover_connector = graph.prover_connector(verifier_index)?;
    let input = graph.verifier_asserts[verifier_index]
        .prover_connector_input()
        .map_err(|e| anyhow::anyhow!("failed to get prover connector input: {e}"))?;

    let final_msg = final_msg.to_vec();
    wrongly_challenged(&prover_connector, &input, &final_msg)
        .map(|txin| (txin, input.amount))
        .map_err(|e| anyhow::anyhow!("failed to sign wrongly challenged: {e}"))
}

pub fn take1_timelock(network: Network) -> u32 {
    take1_timelock_with_config(network, &default_timelock_config(network))
}

pub fn take1_timelock_with_config(network: Network, timelock_config: &TimelockConfig) -> u32 {
    take1_timelock_blocks(network, timelock_config)
}

pub fn take2_timelock(network: Network) -> u32 {
    take2_timelock_with_config(network, &default_timelock_config(network))
}

pub fn take2_timelock_with_config(network: Network, timelock_config: &TimelockConfig) -> u32 {
    take2_timelock_blocks(network, timelock_config)
}
