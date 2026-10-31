use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_ec::AffineRepr;
use ark_groth16::Groth16;
use bitvm_gc::assert_scripts::{INPUT_WIRE_NUM, label_hash};
use bitvm_gc::babe_adapter::{
    BABE_M_CC, BabeBundleBuilder, BabeChallengeAssertWitness, BabeProverState, BabeVerifierState,
    CACSetupPackage, ChallengeAssertWitnessRaw, FinalizedInstanceData, SolderingData,
    WOTS_SIG_COUNT, build_assert_witness, build_challenge_assert_witness, build_real_setup_package,
    build_setup_package, build_wrongly_challenged_witness,
    build_wrongly_challenged_witness_from_preimages, derive_finalized_indices,
    extract_gc_circuit_data, open_and_solder, open_real_setup_and_solder,
    sample_cac_instance_commit, sample_finalized_instance_data, verify_real_setup, verify_setup,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::collections::HashSet;
use std::str::FromStr;
use verifiable_circuit_babe::babe::DummyMulCircuit;

fn verifier_pubkey() -> bitcoin::PublicKey {
    bitcoin::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .expect("public key")
}

#[test]
#[ignore = "requires FGC_GATES_PATH, FGC_OUT_INDICES_PATH, SGC_GATES_PATH, SGC_OUT_INDICES_PATH, FGC_COMPACT_GATES_PATH, FGC_COMPACT_OUT_INDICES_PATH, SGC_COMPACT_GATES_PATH, SGC_COMPACT_OUT_INDICES_PATH runtime assets"]
fn real_setup_restores_private_state_and_verifies_soldering_proof() {
    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let a = Fr::from(3_u64);
    let b = Fr::from(7_u64);
    let (_, vk) = Groth16::<ark_bn254::Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    )
    .expect("groth16 setup");
    let static_public_inputs = a * b;
    let _dynamic_public_inputs = a * a;

    let (package, private_state) =
        build_real_setup_package(BABE_M_CC, &vk, static_public_inputs).expect("real setup");
    let restored =
        serde_json::from_slice(&serde_json::to_vec(&private_state).expect("serialize state"))
            .expect("deserialize state");
    let soldering_builder = BabeBundleBuilder::new();
    let finalized_indices = (0..BABE_M_CC).collect::<Vec<_>>();
    let (opened, finalized, soldering) = open_real_setup_and_solder(
        &soldering_builder,
        &restored,
        &package,
        &finalized_indices,
        &vk,
        static_public_inputs,
    )
    .expect("open real setup");

    assert!(opened.is_empty());
    assert_eq!(finalized.len(), BABE_M_CC);
    verify_real_setup(
        &soldering_builder,
        &package,
        &opened,
        &finalized,
        &soldering,
        &vk,
        &finalized_indices,
        static_public_inputs,
    )
    .expect("verify soldering proof");
    let epk = &package.commits[finalized[0].index].epk;
    let h_msgs: Vec<[u8; 20]> = finalized.iter().map(|f| package.commits[f.index].h_msg).collect();
    extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs)
        .expect("extract native 768-wire graph data");
}

#[test]
fn babe_setup_payload_round_trips_and_derives_gc_data() {
    let package = CACSetupPackage {
        commits: (0..BABE_M_CC).map(|index| sample_cac_instance_commit(index as u8)).collect(),
    };

    let encoded = serde_json::to_vec(&package).expect("serialize package");
    let decoded: CACSetupPackage = serde_json::from_slice(&encoded).expect("deserialize package");
    assert_eq!(decoded, package);

    let finalized_indices =
        derive_finalized_indices(&decoded, BABE_M_CC).expect("derive finalized");
    assert_eq!(finalized_indices.len(), BABE_M_CC);

    let finalized = finalized_indices
        .iter()
        .map(|index| sample_finalized_instance_data(*index))
        .collect::<Vec<_>>();
    let epk = &package.commits[finalized[0].index].epk;
    let h_msgs: Vec<[u8; 20]> = finalized.iter().map(|f| package.commits[f.index].h_msg).collect();
    let gc_data =
        extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs).expect("extract gc data");

    assert_eq!(gc_data.verifier_pubkey, verifier_pubkey());
    assert_eq!(gc_data.final_msg_hashlocks.len(), BABE_M_CC);
}

#[test]
fn protocol_finalized_instances_contribute_one_base_wire_slot() {
    use verifiable_circuit_babe::babe::GC_INPUT_WIRES;
    let package = CACSetupPackage {
        commits: (0..BABE_M_CC).map(|i| sample_cac_instance_commit(i as u8)).collect(),
    };
    let finalized: Vec<FinalizedInstanceData> =
        (0..BABE_M_CC).map(sample_finalized_instance_data).collect();
    let h_msgs: Vec<[u8; 20]> = finalized.iter().map(|f| package.commits[f.index].h_msg).collect();
    let epk = &package.commits[finalized[0].index].epk;

    let gc_data =
        extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs).expect("one verifier graph slot");

    // M finalized instances each contribute one hashlock …
    assert_eq!(gc_data.final_msg_hashlocks, h_msgs);
    let n = GC_INPUT_WIRES / 3; // N_PADDED = 256 wires per group, no dummy positions
    // EPK maps 1:1 to wire_hashes: pi1_x[0..n], pi1_y[n..2n], x_d[2n..3n]
    assert_eq!(gc_data.wire_hashes[0].false_label_hash, epk[0][0]);
    assert_eq!(gc_data.wire_hashes[0].true_label_hash, epk[0][1]);
    assert_eq!(gc_data.wire_hashes[n - 1].false_label_hash, epk[n - 1][0]);
    assert_eq!(gc_data.wire_hashes[n].false_label_hash, epk[n][0]);
    assert_eq!(gc_data.wire_hashes[2 * n].false_label_hash, epk[2 * n][0]);
    assert_eq!(gc_data.wire_hashes[3 * n - 1].false_label_hash, epk[3 * n - 1][0]);
}

#[test]
fn gc_slot_rejects_invalid_epk_length() {
    use verifiable_circuit_babe::babe::GC_INPUT_WIRES;
    let h_msgs = vec![[0u8; 20]; BABE_M_CC];
    for bad_len in [0, 1, GC_INPUT_WIRES - 1, GC_INPUT_WIRES + 1] {
        let bad_epk = vec![[[0u8; 20]; 2]; bad_len];
        match extract_gc_circuit_data(verifier_pubkey(), &bad_epk, &h_msgs) {
            Ok(_) => panic!("epk length {bad_len} should be rejected"),
            Err(err) => assert!(
                err.to_string().contains("epk has"),
                "unexpected error for len {bad_len}: {err}"
            ),
        }
    }
}

#[test]
fn finalized_indices_reject_invalid_counts_and_cover_full_cut() {
    let package = build_setup_package(4).expect("setup package");

    assert!(derive_finalized_indices(&package, 0).is_err());
    assert!(derive_finalized_indices(&package, 5).is_err());

    let first = derive_finalized_indices(&package, 4).expect("derive full cut");
    assert_eq!(first.len(), 4);
    assert_eq!(first.iter().copied().collect::<HashSet<_>>().len(), 4);
    assert_eq!(first.iter().copied().collect::<HashSet<_>>(), HashSet::from([0, 1, 2, 3]));
}

#[test]
fn verify_setup_accepts_valid_opening_and_rejects_invalid_shapes() {
    let package = build_setup_package(4).expect("setup package");
    let finalized_indices = derive_finalized_indices(&package, 2).expect("derive finalized");
    let (opened, finalized, soldering) =
        open_and_solder(&package, &finalized_indices).expect("open and solder");

    verify_setup(&package, &opened, &finalized, &soldering).expect("valid setup");

    let mut duplicate_finalized = finalized.clone();
    duplicate_finalized.push(finalized[0].clone());
    assert!(verify_setup(&package, &opened, &duplicate_finalized, &soldering).is_err());

    let mut overlapping_opened = opened.clone();
    overlapping_opened.push((finalized[0].index, [0u8; 32]));
    assert!(verify_setup(&package, &overlapping_opened, &finalized, &soldering).is_err());

    let mut wrong_seed_opened = opened.clone();
    wrong_seed_opened[0].1[0] ^= 1;
    assert!(verify_setup(&package, &wrong_seed_opened, &finalized, &soldering).is_err());

    let mut mismatched_soldering = soldering.clone();
    mismatched_soldering.finalized_indices.reverse();
    if mismatched_soldering.finalized_indices == soldering.finalized_indices {
        mismatched_soldering.finalized_indices.push(usize::MAX);
    }
    assert!(verify_setup(&package, &opened, &finalized, &mismatched_soldering).is_err());
}

#[test]
fn witness_builders_validate_inputs_and_indices() {
    use bitvm_gc::operator::generate_assert_wots_key;
    let (assert_secret_key, _) = generate_assert_wots_key("test-graph-scoped-key");
    let proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: ark_bn254::G1Affine {
            x: ark_bn254::Fq::from(1u64),
            y: ark_bn254::Fq::from(2u64),
            infinity: false,
        },
        b: ark_bn254::G2Affine::generator(),
        c: ark_bn254::G1Affine::generator(),
    };
    let dynamic_input = Fr::from(0u64);

    let assert_witness =
        build_assert_witness(&proof, &assert_secret_key, dynamic_input).expect("assert witness");
    assert_eq!(assert_witness.wots_sig.len(), WOTS_SIG_COUNT);
    assert!(assert_witness.try_recover_pi1_xd().is_some());
    assert!(build_assert_witness(&proof, &Vec::new(), dynamic_input).is_err());

    let verifier_state = BabeVerifierState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized_indices: (0..BABE_M_CC).collect(),
        verifier_pubkey: verifier_pubkey(),
    };
    let challenge_witness = build_challenge_assert_witness(&verifier_state, &assert_witness, 12)
        .expect("challenge witness");
    assert_eq!(challenge_witness.verifier_index, 12);
    assert_eq!(challenge_witness.witness.input_labels.len(), INPUT_WIRE_NUM);

    let final_msg = b"finalized-preimage-0".to_vec();
    let h_msgs: Vec<[u8; 20]> = (0..BABE_M_CC)
        .map(|i| label_hash(&format!("finalized-preimage-{i}").into_bytes()))
        .collect();
    let prover_state = BabeProverState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized: (0..BABE_M_CC).map(sample_finalized_instance_data).collect(),
        soldering: SolderingData::sample((0..BABE_M_CC).collect()),
        h_msgs,
    };
    let wrongly_challenged =
        build_wrongly_challenged_witness(&prover_state, &challenge_witness, final_msg.clone())
            .expect("wrongly challenged witness");
    assert_eq!(wrongly_challenged.verifier_index, 12);
    assert_eq!(wrongly_challenged.final_msg, final_msg);
    assert!(
        build_wrongly_challenged_witness(
            &prover_state,
            &challenge_witness,
            b"missing-preimage".to_vec(),
        )
        .is_err()
    );
}

#[test]
fn wrongly_challenged_witness_accepts_valid_preimage_and_rejects_invalid() {
    let h_msgs: Vec<[u8; 20]> = (0..BABE_M_CC)
        .map(|i| label_hash(&format!("finalized-preimage-{i}").into_bytes()))
        .collect();
    let valid_msg = b"finalized-preimage-0".to_vec();
    let challenge_witness = BabeChallengeAssertWitness {
        verifier_index: 0,
        witness: ChallengeAssertWitnessRaw { input_labels: vec![], wots_sig: vec![] },
    };

    let from_preimages = build_wrongly_challenged_witness_from_preimages(
        &h_msgs,
        &challenge_witness,
        valid_msg.clone(),
    )
    .expect("wrongly challenged witness");
    assert_eq!(from_preimages.verifier_index, 0);
    assert_eq!(from_preimages.final_msg, valid_msg);

    let prover_state = BabeProverState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized: (0..BABE_M_CC).map(sample_finalized_instance_data).collect(),
        soldering: SolderingData::sample((0..BABE_M_CC).collect()),
        h_msgs,
    };
    let delegated = build_wrongly_challenged_witness(
        &prover_state,
        &challenge_witness,
        from_preimages.final_msg.clone(),
    )
    .expect("delegated wrongly challenged witness");
    assert_eq!(delegated, from_preimages);

    assert!(
        build_wrongly_challenged_witness_from_preimages(
            &prover_state.h_msgs,
            &challenge_witness,
            b"not-a-valid-preimage".to_vec(),
        )
        .is_err()
    );
}

#[test]
fn setup_package_and_open_reject_degenerate_inputs() {
    assert!(build_setup_package(0).is_err());

    let pkg = build_setup_package(4).expect("setup package");
    assert!(open_and_solder(&pkg, &[0, 0]).is_err()); // duplicate finalized index
    assert!(open_and_solder(&pkg, &[99]).is_err()); // out-of-range finalized index
}

#[test]
fn witness_builders_reject_wrong_finalized_count() {
    use bitvm_gc::babe_adapter::TxAssertWitness;

    // build_challenge_assert_witness rejects finalized_indices.len() != BABE_M_CC
    let bad_state = BabeVerifierState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized_indices: vec![0], // 1, not BABE_M_CC
        verifier_pubkey: verifier_pubkey(),
    };
    let dummy_assert = TxAssertWitness { wots_sig: vec![], pi2: vec![], pi3: vec![] };
    assert!(build_challenge_assert_witness(&bad_state, &dummy_assert, 0).is_err());

    // build_wrongly_challenged_witness_from_preimages rejects h_msgs.len() != BABE_M_CC
    let challenge = BabeChallengeAssertWitness {
        verifier_index: 0,
        witness: ChallengeAssertWitnessRaw { input_labels: vec![], wots_sig: vec![] },
    };
    assert!(
        build_wrongly_challenged_witness_from_preimages(&[], &challenge, b"msg".to_vec(),).is_err()
    );
    let too_many = vec![[0u8; 20]; BABE_M_CC + 1];
    assert!(
        build_wrongly_challenged_witness_from_preimages(&too_many, &challenge, b"msg".to_vec(),)
            .is_err()
    );
}

#[test]
fn assert_witness_preserves_pi1_and_dynamic_input() {
    use bitvm_gc::babe_adapter::assert_wots_message;
    use bitvm_gc::operator::generate_assert_wots_key;

    let (sk, _) = generate_assert_wots_key("round-trip-test");
    let dynamic_input = Fr::from(42u64);
    let proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: ark_bn254::G1Affine {
            x: ark_bn254::Fq::from(1u64),
            y: ark_bn254::Fq::from(2u64),
            infinity: false,
        },
        b: ark_bn254::G2Affine::generator(),
        c: ark_bn254::G1Affine::generator(),
    };

    let assert_witness = build_assert_witness(&proof, &sk, dynamic_input).expect("assert witness");

    let (recovered_pi1, recovered_xd) =
        assert_witness.try_recover_pi1_xd().expect("recover pi1 and xd");
    assert_eq!(recovered_pi1, proof.a);
    assert_eq!(recovered_xd, dynamic_input);

    // assert_wots_message must be deterministic
    let msg = assert_wots_message(&assert_witness).expect("wots message");
    let msg2 = assert_wots_message(&assert_witness).expect("wots message 2");
    assert_eq!(msg, msg2);
}

#[test]
fn assert_wots_message_works_for_invalid_field_elements() {
    use bitvm::signatures::Wots;
    use bitvm_gc::babe_adapter::{TxAssertWitness, assert_wots_message};
    use goat::wots::Wots96;

    // Construct a WOTS sig over bytes that are NOT valid Fq/Fr field elements (all 0xFF).
    let sk = Wots96::generate_secret_key();
    let raw_msg = [0xFFu8; 96];
    let sig = Wots96::sign(&sk, &raw_msg);
    let witness = TxAssertWitness { wots_sig: sig.to_vec(), pi2: vec![], pi3: vec![] };

    // try_recover_pi1_xd fails because 0xFF..FF > field modulus
    assert!(witness.try_recover_pi1_xd().is_none());
    // assert_wots_message succeeds regardless — it works on raw bytes only
    let msg = assert_wots_message(&witness).expect("raw message extraction must succeed");
    assert_eq!(msg, raw_msg);
}
