use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use crate::types::BitvmGcCircuitData;
use anyhow::{Result, bail};
use ark_bn254::g1::G1Affine;
use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof as Groth16Proof;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::bag::S;
use goat::assert_scripts::{INPUT_WIRE_NUM, OperatorAssertSecretKey, WireHash, label_hash};
use goat::wots::{Wots, Wots96};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soldering_host::BabeBundle;
pub use soldering_host::BabeBundleBuilder;
use verifiable_circuit_babe::babe::{
    GC_INPUT_WIRES, WitnessEncSetupCt,
    build_challenge_assert_witness as babe_build_challenge_assert_witness,
};
use verifiable_circuit_babe::cac::cac_finalize_indices;
pub use verifiable_circuit_babe::cac::{CACSetupPackage, FinalizedInstanceData};
use verifiable_circuit_babe::dre::N_PADDED;
use verifiable_circuit_babe::gc::{SGC_PART1_CONSTANT_SIZE, SparseAdaptorTable};
pub use verifiable_circuit_babe::instance::commit::CACInstanceCommit;
pub use verifiable_circuit_babe::instance::secret::Seed;
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{
    SolderedLabelsData, SolderingData as RealSolderingData, SolderingProof as RealSolderingProof,
};
pub use verifiable_circuit_babe::transactions::ChallengeAssertWitnessRaw;
pub use verifiable_circuit_babe::transactions::TxAssertWitness;
use verifiable_circuit_babe::utils::pi1_xd_to_wots96_msg;
use verifiable_circuit_babe::verifier::BABEVerifier;

/// Number of Wots96 digit signatures expected by the GOAT GC-V2 connector.
pub const WOTS_SIG_COUNT: usize = Wots96::TOTAL_DIGIT_LEN as usize;
pub const BABE_N_CC: usize = 181;
pub const BABE_M_CC: usize = 7;

pub type OpenedInstanceSeeds = Vec<(usize, Seed)>;
pub type FinalizedInstances = Vec<FinalizedInstanceData>;
pub type SetupAndSolderingData = (OpenedInstanceSeeds, FinalizedInstances, SolderingData);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingData {
    pub finalized_indices: Vec<usize>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactSolderingProofPayload {
    pub opened: OpenedInstanceSeeds,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: CompactSolderingData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolderingData {
    pub finalized_indices: Vec<usize>,
    pub soldered_output: SolderedLabelsData,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierPrivateState {
    pub instance_seeds: Vec<Seed>,
    pub statement_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierState {
    pub package: CACSetupPackage,
    pub finalized_indices: Vec<usize>,
    pub verifier_pubkey: bitcoin::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeProverState {
    pub package: CACSetupPackage,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: SolderingData,
    pub h_msgs: Vec<[u8; 20]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeAssertWitness {
    pub verifier_index: usize,
    pub witness: ChallengeAssertWitnessRaw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeWronglyChallengedWitness {
    pub verifier_index: usize,
    // just need to contain one valid msg
    pub final_msg: Vec<u8>,
}

/// Builds deterministic placeholder setup commitments for tests and wiring.
pub fn sample_cac_instance_commit(seed: u8) -> CACInstanceCommit {
    let epk = (0..GC_INPUT_WIRES)
        .map(|wire| {
            let w = (wire as u16).to_le_bytes();
            [hash20(&[seed, w[0], w[1], 0]), hash20(&[seed, w[0], w[1], 1])]
        })
        .collect();

    let constant_commit_sgc: Vec<_> = (0..SGC_PART1_CONSTANT_SIZE)
        .map(|_| [hash32(&[seed, 0xf0, 0]), hash32(&[seed, 0xf0, 1])])
        .collect();

    CACInstanceCommit {
        epk,
        constant_commits_fgc: [
            [hash32(&[seed, 0xf0, 0]), hash32(&[seed, 0xf0, 1])],
            [hash32(&[seed, 0xf1, 0]), hash32(&[seed, 0xf1, 1])],
        ],
        constant_commits_sgc: constant_commit_sgc,
        b_blind_commit: hash32(&[seed, 0xa0]),
        h_msg: hash20(&[seed, 0xa1]),
        h_ct_setup: hash32(&[seed, 0xa2]),
        com_adaptor: [hash32(&[seed, 0xa3]), hash32(&[seed, 0xa4])],
        com_gc: [hash32(&[seed, 0xa5]), hash32(&[seed, 0xa6]), hash32(&[seed, 0xa7])],
    }
}

pub fn sample_finalized_instance_data(index: usize) -> FinalizedInstanceData {
    let adaptor_tables =
        [SparseAdaptorTable { entries: vec![] }, SparseAdaptorTable { entries: vec![] }];
    let ct_setup = WitnessEncSetupCt { ct2_r_delta_g2: vec![], ct3_masked_msg: vec![] };

    FinalizedInstanceData {
        index,
        ciphertext_sets: [vec![], vec![], vec![]],
        adaptor_tables,
        ct_setup,
        constant_labels_0: [S([0; 16]), S([0; 16])],
        constant_labels_1: vec![],
        b: G1Affine::identity(),
        aes_salt: S([0; 16]),
    }
}

impl SolderingData {
    /// Builds deterministic placeholder soldering data for the selected finalized indices.
    pub fn sample(finalized_indices: Vec<usize>) -> Self {
        Self { finalized_indices, soldered_output: SolderedLabelsData::default(), proof: vec![] }
    }
}

/// Builds a deterministic placeholder CAC setup package with `n_cc` instances.
pub fn build_setup_package(n_cc: usize) -> Result<CACSetupPackage> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    Ok(CACSetupPackage {
        commits: (0..n_cc).map(|index| sample_cac_instance_commit(index as u8)).collect(),
    })
}

/// Builds a real random BABE/CAC setup package bound to the supplied Groth16 statement.
pub fn build_real_setup_package(
    n_cc: usize,
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<(CACSetupPackage, BabeVerifierPrivateState)> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    ensure_real_gc_assets_configured()?;
    let verifier = catch_unwind(AssertUnwindSafe(|| BABEVerifier::new(n_cc, vk, static_inputs)))
        .map_err(|_| anyhow::anyhow!("real BABE verifier setup panicked while loading GC assets"))?
        .map_err(anyhow::Error::msg)?;
    let package = verifier.commit();
    let private_state = BabeVerifierPrivateState {
        instance_seeds: verifier.get_seeds(),
        statement_digest: statement_digest(vk, static_inputs)?,
    };

    Ok((package, private_state))
}

/// Reconstructs the real Verifier instances and creates CAC opening/soldering output data.
pub fn open_real_setup_and_solder(
    soldering_builder: &BabeBundleBuilder,
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<SetupAndSolderingData> {
    ensure_real_gc_assets_configured()?;
    if private_state.statement_digest != statement_digest(vk, static_inputs)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    let verifier = restore_real_verifier(private_state, package, vk, static_inputs)?;
    if verifier.commit() != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let bundle = soldering_builder
        .babe_verifier_open_and_solder(&verifier, finalized_indices)
        .map_err(anyhow::Error::msg)?;
    Ok((bundle.opened, bundle.finalized, from_real_soldering(&bundle.soldering)?))
}

/// Verifies real CAC openings, commitments, and the native Ziren soldering proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_real_setup(
    soldering_builder: &BabeBundleBuilder,
    package: &CACSetupPackage,
    opened: &[(usize, Seed)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    vk: &Groth16VerifyingKey<Bn254>,
    claimed_finalized_indices: &[usize],
    static_public_inputs: Fr,
) -> Result<()> {
    let bundle = BabeBundle {
        opened: opened.to_vec(),
        finalized: finalized.to_vec(),
        soldering: to_real_soldering(soldering)?,
    };
    soldering_builder
        .babe_prover_verify_setup(
            package,
            &bundle,
            vk,
            static_public_inputs,
            claimed_finalized_indices,
        )
        .map_err(anyhow::Error::msg)
}

/// Removes setup-derived public fields from the Verifier-to-Operator soldering proof payload.
pub fn compact_soldering_proof_payload(
    opened: &[(usize, Seed)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<CompactSolderingProofPayload> {
    Ok(CompactSolderingProofPayload {
        opened: opened.to_vec(),
        finalized: finalized.to_vec(),
        soldering: CompactSolderingData {
            finalized_indices: soldering.finalized_indices.clone(),
            proof: soldering.proof.clone(),
        },
    })
}

/// Reconstructs the full BABE setup data using the locally trusted setup package.
pub fn expand_compact_soldering_proof_payload(
    payload: CompactSolderingProofPayload,
) -> Result<SetupAndSolderingData> {
    let finalized = payload.finalized.clone();
    Ok((payload.opened, finalized, expand_compact_soldering_data(payload.soldering)?))
}

/// Derives finalized circuit indices using the real BABE/CAC Fiat-Shamir selection.
pub fn derive_finalized_indices(package: &CACSetupPackage, m_cc: usize) -> Result<Vec<usize>> {
    let n_cc = package.commits.len();
    if m_cc == 0 || m_cc > n_cc {
        bail!("invalid m_cc {m_cc} for n_cc {n_cc}");
    }
    Ok(cac_finalize_indices(n_cc, m_cc))
}

/// Opens non-finalized placeholder instances and returns finalized data plus soldering data.
pub fn open_and_solder(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<SetupAndSolderingData> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    let opened = (0..package.commits.len())
        .filter(|index| !finalized_set.contains(index))
        .map(|index| (index, deterministic_seed(index)))
        .collect::<Vec<_>>();
    let finalized =
        finalized_indices.iter().map(|index| sample_finalized_instance_data(*index)).collect();
    let soldering = SolderingData::sample(finalized_indices.to_vec());
    Ok((opened, finalized, soldering))
}

/// Validates placeholder opened, finalized, and soldering data consistency.
pub fn verify_setup(
    package: &CACSetupPackage,
    opened: &[(usize, Seed)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<()> {
    let n_cc = package.commits.len();
    let finalized_set = finalized.iter().map(|data| data.index).collect::<HashSet<_>>();
    if finalized_set.len() != finalized.len() {
        bail!("duplicate finalized data");
    }
    for (index, seed) in opened {
        if *index >= n_cc {
            bail!("opened index {index} out of range");
        }
        if finalized_set.contains(index) {
            bail!("index {index} cannot be both opened and finalized");
        }
        if *seed != deterministic_seed(*index) {
            bail!("opened seed mismatch for index {index}");
        }
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    for data in finalized {
        if data.index >= n_cc {
            bail!("finalized index {} out of range", data.index);
        }
    }
    Ok(())
}

/// Extracts one graph slot owned by `verifier_pubkey` from finalized setup data.
///
/// `epk` must have exactly `GC_INPUT_WIRES` (768) entries
pub fn extract_gc_circuit_data(
    verifier_pubkey: bitcoin::PublicKey,
    epk: &[[[u8; 20]; 2]],
    h_msgs: &[[u8; 20]],
) -> Result<BitvmGcCircuitData> {
    if epk.len() != GC_INPUT_WIRES {
        bail!("BABE epk has {} entries; expected {GC_INPUT_WIRES}", epk.len());
    }
    let to_wire_hash =
        |pair: &[[u8; 20]; 2]| WireHash { false_label_hash: pair[0], true_label_hash: pair[1] };

    let wire_hashes: [WireHash; INPUT_WIRE_NUM] = epk
        .iter()
        .map(to_wire_hash)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|v: Vec<WireHash>| {
            anyhow::anyhow!("wire hash count {} does not match expected {INPUT_WIRE_NUM}", v.len())
        })?;
    Ok(BitvmGcCircuitData { verifier_pubkey, final_msg_hashlocks: h_msgs.to_vec(), wire_hashes })
}

/// Builds the native BABE assertion witness from the validated operator Groth16 proof.
pub fn build_assert_witness(
    proof: &ark_groth16::Proof<Bn254>,
    assert_secret_key: &OperatorAssertSecretKey,
    dynamic_input: ark_bn254::Fr,
) -> Result<TxAssertWitness> {
    if assert_secret_key.is_empty() {
        bail!("operator WOTS secret key must not be empty");
    }
    let msg = pi1_xd_to_wots96_msg(&proof.a, dynamic_input);
    let wots_sig = Wots96::sign(assert_secret_key, &msg);
    let mut pi2 = Vec::new();
    let mut pi3 = Vec::new();
    proof.b.serialize_compressed(&mut pi2)?;
    proof.c.serialize_compressed(&mut pi3)?;
    Ok(TxAssertWitness { wots_sig: wots_sig.to_vec(), pi2, pi3 })
}

pub fn assert_wots_message(assert_witness: &TxAssertWitness) -> Result<[u8; 96]> {
    let arr_sig: [[u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize] =
        assert_witness.wots_sig.clone().try_into().map_err(|_| {
            anyhow::anyhow!("WOTS signature has wrong length; expected {}", Wots96::TOTAL_DIGIT_LEN)
        })?;
    Ok(Wots96::signature_to_message(&arr_sig))
}

pub fn recover_operator_proof_from_assert_witness(
    assert_witness: &TxAssertWitness,
) -> Result<Groth16Proof<Bn254>> {
    let (pi1, _) = assert_witness
        .try_recover_pi1_xd()
        .ok_or_else(|| anyhow::anyhow!("Cannot recover pi1 and xd"))?;
    let (pi2, pi3) = assert_witness
        .recover_pi2_pi3()
        .ok_or_else(|| anyhow::anyhow!("Cannot recover pi2 and pi3"))?;
    Ok(Groth16Proof { a: pi1, b: pi2, c: pi3 })
}

/// Builds a placeholder verifier challenge witness from an assert witness.
pub fn build_challenge_assert_witness(
    verifier_state: &BabeVerifierState,
    assert_witness: &TxAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if verifier_state.finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let bytes = assert_wots_message(assert_witness)?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: ChallengeAssertWitnessRaw {
            input_labels: (0usize..INPUT_WIRE_NUM)
                .map(|index| hash16_with_index(&bytes, index))
                .collect(),
            wots_sig: assert_witness.wots_sig.clone(),
        },
    })
}

/// Verifies a native operator assertion and reveals the real base-instance labels.
pub fn build_real_challenge_assert_witness(
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
    assert_witness: &TxAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let verifier = restore_real_verifier(private_state, package, vk, static_inputs)?;
    if verifier.commit() != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }

    let base_idx = finalized_indices[0];
    let witness = babe_build_challenge_assert_witness(&verifier, assert_witness, base_idx);

    if witness.witness.input_labels.len() != GC_INPUT_WIRES {
        bail!(
            "real BABE challenge labels have {}; expected {GC_INPUT_WIRES}",
            witness.witness.input_labels.len()
        );
    }
    Ok(BabeChallengeAssertWitness { verifier_index, witness: witness.witness })
}

/// Builds a wrongly-challenged witness from a valid recovered finalized-message preimage.
pub fn build_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    final_msg: Vec<u8>,
) -> Result<BabeWronglyChallengedWitness> {
    build_wrongly_challenged_witness_from_preimages(
        &prover_state.h_msgs,
        challenge_witness,
        final_msg,
    )
}

/// Evaluates the native BABE garbled circuit and returns a finalized hashlock preimages.
pub fn recover_real_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    proof: &ark_groth16::Proof<Bn254>,
    vk: Groth16VerifyingKey<Bn254>,
    dyn_pubin: ark_bn254::Fr,
) -> Result<BabeWronglyChallengedWitness> {
    let mut prover = BABEProver::new(vk, proof.clone(), dyn_pubin);
    recover_a_valid_finalized_messages(prover_state, challenge_witness, &mut prover)
}

/// Builds a wrongly-challenged witness after validating all finalized preimages.
pub fn build_wrongly_challenged_witness_from_preimages(
    h_msgs: &[[u8; 20]],
    challenge_witness: &BabeChallengeAssertWitness,
    final_msg: Vec<u8>,
) -> Result<BabeWronglyChallengedWitness> {
    if h_msgs.len() != BABE_M_CC {
        bail!("wrongly challenged setup must contain exactly {BABE_M_CC} finalized hashlocks");
    }

    if !h_msgs.contains(&label_hash(&final_msg)) {
        bail!("message is not a valid preimage");
    }

    Ok(BabeWronglyChallengedWitness { verifier_index: challenge_witness.verifier_index, final_msg })
}

fn ensure_real_gc_assets_configured() -> Result<()> {
    for name in [
        "FGC_GATES_PATH",
        "FGC_OUT_INDICES_PATH",
        "SGC_GATES_PATH",
        "SGC_OUT_INDICES_PATH",
        "FGC_COMPACT_GATES_PATH",
        "FGC_COMPACT_OUT_INDICES_PATH",
        "SGC_COMPACT_GATES_PATH",
        "SGC_COMPACT_OUT_INDICES_PATH",
    ] {
        let path = PathBuf::from(
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for real CAC setup"))?,
        );
        if !path.is_file() {
            bail!("{name} does not point to a readable file: {}", path.display());
        }
    }
    Ok(())
}

fn statement_digest(vk: &Groth16VerifyingKey<Bn254>, static_inputs: Fr) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    static_inputs.serialize_compressed(&mut bytes)?;
    Ok(hash32(&bytes))
}

fn restore_real_verifier(
    state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: Fr,
) -> Result<BABEVerifier> {
    BABEVerifier::from_state(&state.instance_seeds, package, vk, static_inputs)
        .ok_or_else(|| anyhow::anyhow!("Cannot restore real verifier"))
}

fn validate_finalized_indices(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<()> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.is_empty() {
        bail!("at least one finalized index is required");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    Ok(())
}

fn from_real_soldering(soldering: &RealSolderingData) -> Result<SolderingData> {
    let output = soldering.soldering_proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: bincode::serialize(&soldering.soldering_proof.proof)?,
    })
}

fn expand_compact_soldering_data(soldering: CompactSolderingData) -> Result<SolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    let proof = RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? };
    let output = proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices,
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: soldering.proof,
    })
}

fn to_real_soldering(soldering: &SolderingData) -> Result<RealSolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    Ok(RealSolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldering_proof: RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? },
    })
}

fn recover_a_valid_finalized_messages(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    prover: &mut BABEProver,
) -> Result<BabeWronglyChallengedWitness> {
    if prover_state.finalized.len() != prover_state.h_msgs.len() {
        bail!("BABE prover state finalized data and hash count differ");
    }
    if prover_state.finalized.is_empty() {
        bail!("BABE prover state has no finalized instances");
    }

    let base_input_labels: Vec<S> =
        challenge_witness.witness.input_labels.iter().map(|&b| S(b)).collect();
    let pi1_full_labels = base_input_labels[..2 * N_PADDED].to_vec();
    let x_d_full_labels = base_input_labels[2 * N_PADDED..].to_vec();
    let real_soldering = to_real_soldering(&prover_state.soldering)?;

    let soldered_output = &prover_state.soldering.soldered_output;
    if soldered_output.base_commitment.len() != GC_INPUT_WIRES {
        bail!(
            "soldering base commitment count {} does not match expected GC input wire count {GC_INPUT_WIRES}",
            soldered_output.base_commitment.len()
        );
    }

    let found = prover.check_compute_msg(
        &prover_state.finalized,
        &pi1_full_labels,
        &x_d_full_labels,
        &real_soldering,
        &prover_state.h_msgs,
    );

    if !found {
        bail!("Cannot find any valid msg");
    }

    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        final_msg: prover
            .valid_msg
            .ok_or_else(|| {
                anyhow::anyhow!("check_compute_msg returned true but valid_msg is not set")
            })?
            .to_vec(),
    })
}

fn deterministic_seed(index: usize) -> Seed {
    hash32(&(index as u64).to_le_bytes())
}

fn hash20(data: &[u8]) -> [u8; 20] {
    let hash = hash32(data);
    hash[0..20].try_into().expect("20 bytes")
}

fn hash16(data: &[u8]) -> [u8; 16] {
    let hash = hash32(data);
    hash[0..16].try_into().expect("16 bytes")
}

fn hash16_with_index(data: &[u8], index: usize) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(data.len() + std::mem::size_of::<u64>());
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    hash16(&bytes)
}

fn hash32(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
