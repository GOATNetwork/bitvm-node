//! Deterministic, on-chain-valid mocks that stand in for the real BABE / garbled-circuit
//! machinery when the `mock-gc` cargo feature is enabled.
//!
//! Design goal: keep **all on-chain-relevant data real** (the `epk` label commitments, the
//! finalized-message hashlocks, the soldered wire deltas) so that the Operator's Assert, the
//! Verifier's ChallengeAssert and the Operator's WronglyChallenged transactions all satisfy the
//! real Bitcoin scripts, while faking only the parts that would otherwise require the 3.3 GB gate
//! files and a Ziren STARK/Groth16 prover (the garbling, the soldering STARK proof, and the
//! Groth16 pairing verdict).
//!
//! The mock label commitments are derived with the **real** light-secret derivation
//! (`InstanceLightSecrets::from_seed`, ChaCha20 only), so the untouched, still-real
//! `build_real_challenge_assert_witness` keeps producing 768 labels whose HASH160 match the
//! committed `epk` bit-by-bit. The soldered output is produced by the **real**
//! `soldering_guest_compute`, so `verify_soldering_output_match_commitment` still passes; it is
//! then wrapped in a structurally-real (but empty) `ZKMProofWithPublicValues` so the node's
//! payload plumbing survives with zero call-site changes.
//!
//! What is intentionally *not* sound (localnet only): the finalized message preimage is placed in
//! plaintext in `ct_setup.ct3_masked_msg`, and the Groth16 pairing check is replaced by a policy
//! verdict shared by convention with the mock proof builder. This is fine for a functional
//! testnet and useless as a security test.

use crate::babe_adapter::StaticInputs;

use std::collections::HashSet;

use anyhow::{Result, anyhow, bail};
use ark_bn254::{Bn254, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

use verifiable_circuit_babe::babe::{GC_INPUT_WIRES, WitnessEncSetupCt};
use verifiable_circuit_babe::cac::verify_finalized_indices_in_bundle;
use verifiable_circuit_babe::dre::N_PADDED;
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{build_soldered_wires_input, soldering_guest_compute};
use verifiable_circuit_babe::utils::derive_hashlock;
use verifiable_circuit_babe::verifier::{BABEVerifier, InstanceLightSecrets};
use zkm_sdk::{ZKMProof, ZKMProofWithPublicValues, ZKMPublicValues};

use crate::babe_adapter::{
    BABE_M_CC, BabeChallengeAssertWitness, BabeProverState, BabeVerifierPrivateState,
    BabeWronglyChallengedWitness, CACInstanceCommit, CACSetupPackage, FinalizedInstanceData,
    OpenedInstanceSeeds, Seed, SetupAndSolderingData, SolderingData, TxAssertWitness,
    assert_wots_message, sample_finalized_instance_data, statement_digest,
    validate_finalized_indices,
};

/// Version string stamped into the mocked soldering `ZKMProofWithPublicValues`. Not verified by
/// the node (only `SolderingProof::output()` / the public values are consumed for soldering).
const MOCK_ZKM_VERSION: &str = "mock-gc";

/// Domain tag for the deterministic per-instance finalized message preimage.
const MOCK_MSG_TAG: &[u8] = b"bitvm2-mock-gc/final-msg";

/// Drop-in replacement for `soldering_host::BabeBundleBuilder`. Under the real build that type runs
/// a Ziren `client.setup()` on the soldering guest ELF in `new()` (tens of seconds, the heaviest
/// startup item). The mock is a zero-cost unit struct.
#[derive(Debug, Default, Clone, Copy)]
pub struct BabeBundleBuilder;

impl BabeBundleBuilder {
    pub fn new() -> Self {
        tracing::info!(
            event = "mock_gc",
            stage = "builder_init",
            "mock-gc BabeBundleBuilder (no Ziren setup)"
        );
        Self
    }
}

/// The proof verdict policy, read from `MOCK_GC_PROOF_VERDICT` at call time. It stands in for the
/// real Groth16 pairing check (which no mocked proof can satisfy for the embedded IMM VK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Treat every structurally-valid operator proof as valid (happy path, no dispute). Default.
    AlwaysValid,
    /// Treat every operator proof as invalid (Verifier challenges; Operator cannot answer).
    AlwaysInvalid,
    /// Run the real pairing check (a genuinely valid Groth16 proof still passes).
    Real,
}

fn verdict() -> Verdict {
    match std::env::var("MOCK_GC_PROOF_VERDICT").ok().as_deref() {
        Some("always-invalid") => Verdict::AlwaysInvalid,
        Some("real") => Verdict::Real,
        _ => Verdict::AlwaysValid,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Deterministic per-instance filler commitment for fields the mock does not need to be real.
fn tag_commit(seed: &Seed, n: u8) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(seed.len() + 2);
    bytes.extend_from_slice(seed);
    bytes.extend_from_slice(&[0xf0, n]);
    sha256(&bytes)
}

/// Deterministic finalized-message preimage for an instance (kept in plaintext in the finalized
/// data so the Operator can recover it; its HASH160 is the on-chain finalized hashlock).
fn mock_msg(seed: &Seed) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(MOCK_MSG_TAG.len() + seed.len());
    bytes.extend_from_slice(MOCK_MSG_TAG);
    bytes.extend_from_slice(seed);
    sha256(&bytes)
}

/// Builds a CAC instance commitment whose `epk` (label hashlocks) and `h_msg` are derived exactly
/// as the real `CACInstanceCommit::from_instance`, but from the cheap light secrets and a mock
/// message. Only `epk` and `h_msg` are consumed on-chain / by the still-real challenge path; the
/// remaining commitment fields are deterministic filler.
fn mock_commit_from_seed(seed: Seed) -> CACInstanceCommit {
    let ls = InstanceLightSecrets::from_seed(seed);
    let mut epk = Vec::with_capacity(GC_INPUT_WIRES);
    for key in &ls.input_0labels[0] {
        epk.push([derive_hashlock(&key.0), derive_hashlock(&(*key ^ ls.delta[0]).0)]);
    }
    for key in &ls.input_0labels[1] {
        epk.push([derive_hashlock(&key.0), derive_hashlock(&(*key ^ ls.delta[1]).0)]);
    }
    debug_assert_eq!(epk.len(), GC_INPUT_WIRES);

    CACInstanceCommit {
        epk,
        constant_commits_fgc: [
            [tag_commit(&seed, 1), tag_commit(&seed, 2)],
            [tag_commit(&seed, 3), tag_commit(&seed, 4)],
        ],
        // The real path stores 510 SGC constant commits here; nothing in the node checks the
        // length, so keep the gossiped GenCircuits package small.
        constant_commits_sgc: vec![],
        b_blind_commit: tag_commit(&seed, 5),
        h_msg: derive_hashlock(&mock_msg(&seed)),
        h_ct_setup: tag_commit(&seed, 6),
        com_adaptor: [tag_commit(&seed, 7), tag_commit(&seed, 8)],
        com_gc: [tag_commit(&seed, 9), tag_commit(&seed, 10), tag_commit(&seed, 11)],
    }
}

fn serialize_static_input(static_inputs: StaticInputs) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    static_inputs.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

/// Bit `wire` of the 96-byte Wots assert message, using the same layout as
/// `InstanceLightSecrets::compute_labels_from_bytes` (π₁ wires `0..512` in bytes `0..64`, x_d wires
/// `512..768` in bytes `64..96`).
fn message_bit(msg: &[u8; 96], wire: usize) -> usize {
    let (byte, bit) = if wire < 2 * N_PADDED {
        (wire / 8, wire % 8)
    } else {
        let local = wire - 2 * N_PADDED;
        (64 + local / 8, local % 8)
    };
    ((msg[byte] >> bit) & 1) as usize
}

/// Mock of `build_real_setup_package`: sample fresh seeds (exactly like the real
/// `BABEVerifier::new`), derive the real label commitments cheaply, and bind the statement digest.
/// Skips the ~181-instance garbling entirely.
pub fn build_real_setup_package(
    n_cc: usize,
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: StaticInputs,
) -> Result<(CACSetupPackage, BabeVerifierPrivateState)> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    let seeds: Vec<Seed> = (0..n_cc).map(|_| rand::random()).collect();
    let commits = seeds.iter().map(|seed| mock_commit_from_seed(*seed)).collect();
    let package = CACSetupPackage { commits };
    let private_state = BabeVerifierPrivateState {
        instance_seeds: seeds,
        statement_digest: statement_digest(vk, static_inputs)?,
    };
    Ok((package, private_state))
}

/// Mock of `open_real_setup_and_solder`: reveal the real seeds for non-finalized instances, build
/// finalized data carrying the statement and the plaintext message preimage, and produce the real
/// soldered output wrapped in a structurally-real (empty) STARK proof.
pub fn open_real_setup_and_solder(
    _soldering_builder: &BabeBundleBuilder,
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    static_inputs: StaticInputs,
) -> Result<SetupAndSolderingData> {
    if private_state.statement_digest != statement_digest(vk, static_inputs)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    if private_state.instance_seeds.len() != package.commits.len() {
        bail!("persisted BABE verifier seeds do not match setup package size");
    }
    let verifier =
        BABEVerifier::from_state(&private_state.instance_seeds, package, vk, static_inputs)
            .ok_or_else(|| anyhow!("cannot restore mock verifier from persisted state"))?;

    let finalized_set: HashSet<usize> = finalized_indices.iter().copied().collect();
    let opened: OpenedInstanceSeeds = (0..package.commits.len())
        .filter(|index| !finalized_set.contains(index))
        .map(|index| (index, private_state.instance_seeds[index]))
        .collect();

    let static_bytes = serialize_static_input(static_inputs)?;
    let finalized: Vec<FinalizedInstanceData> = finalized_indices
        .iter()
        .map(|&index| {
            let mut data = sample_finalized_instance_data(index);
            data.ct_setup = WitnessEncSetupCt {
                ct2_r_delta_g2: static_bytes.clone(),
                ct3_masked_msg: mock_msg(&private_state.instance_seeds[index]).to_vec(),
            };
            data.b = G1Affine::generator();
            data
        })
        .collect();

    let soldered_input = build_soldered_wires_input(&verifier, finalized_indices);
    let soldered_output = soldering_guest_compute(&soldered_input);
    let public_values = bincode::serialize(&soldered_output)?;
    let proof = bincode::serialize(&ZKMProofWithPublicValues {
        proof: ZKMProof::Core(vec![]),
        public_values: ZKMPublicValues::from(&public_values),
        zkm_version: MOCK_ZKM_VERSION.to_string(),
    })?;

    Ok((
        opened,
        finalized,
        SolderingData { finalized_indices: finalized_indices.to_vec(), soldered_output, proof },
    ))
}

/// Mock of `verify_real_setup`: run the real shape/partition and soldering-commitment checks, plus
/// the mock-specific statement binding and message-preimage checks. Skips only the Ziren
/// `client.verify` and the 174-instance re-garbling.
#[allow(clippy::too_many_arguments)]
pub fn verify_real_setup(
    _soldering_builder: &BabeBundleBuilder,
    package: &CACSetupPackage,
    opened: &[(usize, Seed)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    _vk: &Groth16VerifyingKey<Bn254>,
    claimed_finalized_indices: &[usize],
    static_public_inputs: StaticInputs,
) -> Result<()> {
    verify_finalized_indices_in_bundle(
        package,
        opened,
        finalized,
        claimed_finalized_indices,
        &soldering.finalized_indices,
    )
    .map_err(anyhow::Error::msg)?;

    let static_bytes = serialize_static_input(static_public_inputs)?;
    for data in finalized {
        let commit = package
            .commits
            .get(data.index)
            .ok_or_else(|| anyhow!("finalized instance index {} out of range", data.index))?;
        if data.ct_setup.ct2_r_delta_g2 != static_bytes {
            bail!("finalized instance {} is not bound to the setup statement", data.index);
        }
        if derive_hashlock(&data.ct_setup.ct3_masked_msg) != commit.h_msg {
            bail!("finalized instance {} message preimage does not match its hashlock", data.index);
        }
    }

    if verify_openings_enabled() {
        for (index, seed) in opened {
            let commit = package
                .commits
                .get(*index)
                .ok_or_else(|| anyhow!("opened instance index {index} out of range"))?;
            if &mock_commit_from_seed(*seed) != commit {
                bail!("opened seed for instance {index} does not reproduce its commitment");
            }
        }
    }

    BABEProver::verify_soldering_output_match_commitment(
        &soldering.soldered_output,
        package,
        &soldering.finalized_indices,
    )
    .map_err(anyhow::Error::msg)?;

    Ok(())
}

/// Mock of `recover_real_wrongly_challenged_witness`: instead of evaluating the garbled circuit, it
/// (1) checks the on-chain-revealed ChallengeAssert labels really are the committed base-instance
/// labels for the asserted message (exactly what the ChallengeAssert Bitcoin script proves), (2)
/// applies the proof verdict, and (3) returns the plaintext finalized message preimage — whose
/// HASH160 is the on-chain WronglyChallenged hashlock.
pub fn recover_real_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    _proof: &ark_groth16::Proof<Bn254>,
    _vk: Groth16VerifyingKey<Bn254>,
    _dyn_pubin: Fr,
) -> Result<BabeWronglyChallengedWitness> {
    if prover_state.finalized.is_empty() {
        bail!("BABE prover state has no finalized instances");
    }
    if prover_state.finalized.len() != prover_state.h_msgs.len() {
        bail!("BABE prover state finalized data and hash count differ");
    }
    if prover_state.h_msgs.len() != BABE_M_CC {
        bail!("wrongly challenged setup must contain exactly {BABE_M_CC} finalized hashlocks");
    }

    let base = &prover_state.finalized[0];
    let base_commit = prover_state
        .package
        .commits
        .get(base.index)
        .ok_or_else(|| anyhow!("base finalized instance index {} out of range", base.index))?;
    let input_labels = &challenge_witness.witness.input_labels;
    if input_labels.len() != GC_INPUT_WIRES {
        bail!("challenge witness exposes {} labels; expected {GC_INPUT_WIRES}", input_labels.len());
    }

    // The published ChallengeAssert labels must be the committed base-instance labels selected by
    // the bits of the asserted 96-byte message. This is precisely the relation the on-chain
    // ChallengeAssert script enforces, so it cannot pass with junk labels.
    let msg = assert_wots_message(&TxAssertWitness {
        wots_sig: challenge_witness.witness.wots_sig.clone(),
        pi2: vec![],
        pi3: vec![],
    })?;
    for (wire, label) in input_labels.iter().enumerate() {
        let bit = message_bit(&msg, wire);
        if derive_hashlock(label) != base_commit.epk[wire][bit] {
            bail!("Cannot find any valid msg");
        }
    }

    match verdict() {
        Verdict::AlwaysInvalid => bail!("Cannot find any valid msg"),
        // No mocked proof can satisfy the real pairing equation, so `real` cannot let the Operator
        // legitimately answer; treat it as "cannot answer" to force the Disprove branch.
        Verdict::Real => bail!("Cannot find any valid msg"),
        Verdict::AlwaysValid => {}
    }

    let final_msg = base.ct_setup.ct3_masked_msg.clone();
    if derive_hashlock(&final_msg) != prover_state.h_msgs[0] {
        bail!("Cannot find any valid msg");
    }

    Ok(BabeWronglyChallengedWitness { verifier_index: challenge_witness.verifier_index, final_msg })
}

/// Replaces the Verifier's real `TxAssertWitness::verify_groth16_proof` pairing check. The witness
/// must be structurally recoverable (as the real assert path always produces), then the verdict
/// decides whether the Verifier accepts the proof (happy path) or challenges.
pub fn verify_operator_assert_proof(
    assert_witness: &TxAssertWitness,
    vk: &Groth16VerifyingKey<Bn254>,
    static_input: StaticInputs,
) -> bool {
    if assert_witness.try_recover_pi1_xd().is_none() || assert_witness.recover_pi2_pi3().is_none() {
        return false;
    }
    match verdict() {
        Verdict::AlwaysInvalid => false,
        Verdict::Real => assert_witness.verify_groth16_proof(vk, &static_input),
        Verdict::AlwaysValid => true,
    }
}

/// Whether `verify_real_setup` re-derives every opened commitment from its revealed seed.
/// Default on; set `MOCK_GC_VERIFY_OPENINGS=false`/`0` to skip (~174 instances) for speed.
fn verify_openings_enabled() -> bool {
    !matches!(
        std::env::var("MOCK_GC_VERIFY_OPENINGS").ok().as_deref(),
        Some("false") | Some("0") | Some("no")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babe_adapter::{
        BABE_M_CC, BabeProverState, build_assert_witness, build_real_challenge_assert_witness,
        compact_soldering_proof_payload, derive_finalized_indices,
        expand_compact_soldering_proof_payload, extract_gc_circuit_data,
    };
    use ark_bn254::G2Affine;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use goat::assert_scripts::label_hash;
    use goat::wots::{Wots, Wots96};
    use rand::SeedableRng;
    use verifiable_circuit_babe::babe::DummyMulCircuit;

    // Small n_cc keeps the test quick while still exercising opened (n_cc - M_CC) instances.
    const TEST_N_CC: usize = 12;

    fn test_vk() -> Groth16VerifyingKey<Bn254> {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (_, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(Fr::from(3u64)), b: Some(Fr::from(7u64)) },
            &mut rng,
        )
        .expect("groth16 setup");
        vk
    }

    fn test_verifier_pubkey() -> bitcoin::PublicKey {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        bitcoin::PublicKey::new(sk.public_key(&secp))
    }

    fn mock_operator_proof() -> ark_groth16::Proof<Bn254> {
        // Structurally valid, non-infinity subgroup points; the mock never checks the pairing.
        ark_groth16::Proof {
            a: G1Affine::generator(),
            b: G2Affine::generator(),
            c: G1Affine::generator(),
        }
    }

    struct Fixture {
        vk: Groth16VerifyingKey<Bn254>,
        static_input: StaticInputs,
        package: CACSetupPackage,
        private_state: BabeVerifierPrivateState,
        finalized_indices: Vec<usize>,
        opened: Vec<(usize, Seed)>,
        finalized: Vec<FinalizedInstanceData>,
        soldering: SolderingData,
    }

    fn build_fixture() -> Fixture {
        let vk = test_vk();
        let static_input = [Fr::from(2024u64); crate::babe_adapter::STATIC_SLOTS.len()];
        let (package, private_state) =
            build_real_setup_package(TEST_N_CC, &vk, static_input).expect("setup package");
        let finalized_indices =
            derive_finalized_indices(&package, BABE_M_CC).expect("finalized indices");
        let (opened, finalized, soldering) = open_real_setup_and_solder(
            &BabeBundleBuilder::new(),
            &private_state,
            &package,
            &finalized_indices,
            &vk,
            static_input,
        )
        .expect("open and solder");
        Fixture {
            vk,
            static_input,
            package,
            private_state,
            finalized_indices,
            opened,
            finalized,
            soldering,
        }
    }

    #[test]
    fn setup_verifies_and_payload_round_trips() {
        let f = build_fixture();
        // The verifier's setup verifies on the operator side.
        verify_real_setup(
            &BabeBundleBuilder::new(),
            &f.package,
            &f.opened,
            &f.finalized,
            &f.soldering,
            &f.vk,
            &f.finalized_indices,
            f.static_input,
        )
        .expect("verify_real_setup should accept an honest bundle");

        // The compact payload survives a bincode round-trip (the ZKMProofWithPublicValues wrapper
        // and finalized data are preserved), and still verifies.
        let compact = compact_soldering_proof_payload(&f.opened, &f.finalized, &f.soldering)
            .expect("compact payload");
        let bytes = bincode::serialize(&compact).expect("serialize compact payload");
        let restored: crate::babe_adapter::CompactSolderingProofPayload =
            bincode::deserialize(&bytes).expect("deserialize compact payload");
        let (opened2, finalized2, soldering2) =
            expand_compact_soldering_proof_payload(restored).expect("expand payload");
        verify_real_setup(
            &BabeBundleBuilder::new(),
            &f.package,
            &opened2,
            &finalized2,
            &soldering2,
            &f.vk,
            &f.finalized_indices,
            f.static_input,
        )
        .expect("verify_real_setup should accept the round-tripped bundle");
    }

    #[test]
    fn verify_rejects_tampered_statement_and_message() {
        let f = build_fixture();

        // Wrong statement: the finalized instances are no longer bound to it.
        let wrong = verify_real_setup(
            &BabeBundleBuilder::new(),
            &f.package,
            &f.opened,
            &f.finalized,
            &f.soldering,
            &f.vk,
            &f.finalized_indices,
            f.static_input.map(|input| input + Fr::from(1u64)),
        );
        assert!(wrong.is_err(), "a mismatched statement must be rejected");

        // Tampered message preimage: HASH160 no longer matches the committed hashlock.
        let mut finalized = f.finalized.clone();
        finalized[0].ct_setup.ct3_masked_msg = vec![0u8; 32];
        let tampered = verify_real_setup(
            &BabeBundleBuilder::new(),
            &f.package,
            &f.opened,
            &finalized,
            &f.soldering,
            &f.vk,
            &f.finalized_indices,
            f.static_input,
        );
        assert!(tampered.is_err(), "a tampered finalized message must be rejected");
    }

    #[test]
    fn challenge_labels_match_gc_data_and_wrongly_challenged_is_consistent() {
        // This test owns MOCK_GC_PROOF_VERDICT; no other test reads the verdict, so mutating the
        // process env here is race-free.
        unsafe { std::env::remove_var("MOCK_GC_PROOF_VERDICT") };

        let f = build_fixture();
        let base_idx = f.finalized_indices[0];
        let h_msgs: Vec<[u8; 20]> =
            f.finalized.iter().map(|d| f.package.commits[d.index].h_msg).collect();
        let gc_data = extract_gc_circuit_data(
            test_verifier_pubkey(),
            &f.package.commits[base_idx].epk,
            &h_msgs,
        )
        .expect("extract gc data");
        assert_eq!(gc_data.final_msg_hashlocks.len(), BABE_M_CC);

        // Operator asserts, Verifier reveals the base-instance labels.
        let proof = mock_operator_proof();
        let dynamic_input = Fr::from(9u64);
        let secret = Wots96::generate_secret_key();
        let assert_witness =
            build_assert_witness(&proof, &secret, dynamic_input).expect("assert witness");
        let msg = assert_wots_message(&assert_witness).expect("assert message");
        let challenge = build_real_challenge_assert_witness(
            &f.private_state,
            &f.package,
            &f.finalized_indices,
            &f.vk,
            f.static_input,
            &assert_witness,
            0,
        )
        .expect("challenge assert witness");

        // Every revealed label hashes to the gc_data wire hash selected by the asserted message bit
        // — exactly the relation the on-chain ChallengeAssert script enforces.
        assert_eq!(challenge.witness.input_labels.len(), GC_INPUT_WIRES);
        for (wire, label) in challenge.witness.input_labels.iter().enumerate() {
            let bit = message_bit(&msg, wire);
            let expected = if bit == 1 {
                gc_data.wire_hashes[wire].true_label_hash
            } else {
                gc_data.wire_hashes[wire].false_label_hash
            };
            assert_eq!(label_hash(&label.to_vec()), expected, "label mismatch at wire {wire}");
        }

        // Operator recovers a valid WronglyChallenged message whose HASH160 is an on-chain hashlock.
        let prover_state = BabeProverState {
            package: f.package.clone(),
            finalized: f.finalized.clone(),
            soldering: f.soldering.clone(),
            h_msgs: h_msgs.clone(),
        };
        assert!(verify_operator_assert_proof(&assert_witness, &f.vk, f.static_input));
        let recovered = recover_real_wrongly_challenged_witness(
            &prover_state,
            &challenge,
            &proof,
            f.vk.clone(),
            dynamic_input,
        )
        .expect("wrongly challenged witness");
        assert!(
            gc_data.final_msg_hashlocks.contains(&label_hash(&recovered.final_msg)),
            "recovered message must satisfy an on-chain finalized hashlock"
        );

        // Forcing an invalid verdict makes the Verifier challenge and blocks the Operator's answer.
        unsafe { std::env::set_var("MOCK_GC_PROOF_VERDICT", "always-invalid") };
        assert!(!verify_operator_assert_proof(&assert_witness, &f.vk, f.static_input));
        assert!(
            recover_real_wrongly_challenged_witness(
                &prover_state,
                &challenge,
                &proof,
                f.vk.clone(),
                dynamic_input,
            )
            .is_err(),
            "with an invalid verdict the operator cannot answer the challenge"
        );
        unsafe { std::env::remove_var("MOCK_GC_PROOF_VERDICT") };
    }
}
