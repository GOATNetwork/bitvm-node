use ark_bn254::Bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use bitvm::chunk::api::type_conversion_utils::RawProof;

// TODO
pub fn get_proof() -> RawProof {
    RawProof::default()
}

pub fn serialize_proof(proof: ark_groth16::Proof<Bn254>) -> Vec<u8> {
    let mut proof_sered = vec![0; proof.serialized_size(Compress::Yes)];
    proof
        .serialize_with_mode(&mut proof_sered[..], Compress::Yes)
        .expect("fail to serialize proof");
    proof_sered
}
pub fn serialize_vk(vk: ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let mut vk_sered = vec![0; vk.serialized_size(Compress::Yes)];
    vk.serialize_with_mode(&mut vk_sered[..], Compress::Yes)
        .expect("fail to serialize vk");
    vk_sered
}
pub fn serialize_pubin(pubin: Vec<ark_bn254::Fr>) -> Vec<u8> {
    fn tmp_fr_serialization(f: ark_bn254::Fr) -> Vec<u8> {
        use ark_ff::BigInt;
        use ark_ff::PrimeField;

        let BigInt(f_big) = f.into_bigint();
        let mut res = Vec::with_capacity(f_big.len() * 8);
        for &num in f_big.iter() {
            res.extend_from_slice(&num.to_le_bytes());
        }
        res
    }

    let mut public_inputs_sered = Vec::new();
    for f in pubin {
        let f_sered = tmp_fr_serialization(f);
        public_inputs_sered.push(f_sered);
    }

    bincode::serialize(&public_inputs_sered).unwrap()
}
pub fn deserialize_proof(buffer: Vec<u8>) -> ark_groth16::Proof<Bn254> {
    ark_groth16::Proof::<Bn254>::deserialize_with_mode(
        buffer.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .unwrap()
}
pub fn deserialize_vk(buffer: Vec<u8>) -> ark_groth16::VerifyingKey<Bn254> {
    ark_groth16::VerifyingKey::<Bn254>::deserialize_with_mode(
        buffer.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .unwrap()
}
pub fn deserialize_pubin(buffer: Vec<u8>) -> Vec<ark_bn254::Fr> {
    fn tmp_fr_deserialization(v: &[u8]) -> ark_bn254::Fr {
        use ark_ff::BigInt;
        use ark_ff::PrimeField;

        let mut arr = [0u64; 4];
        for (i, chunk) in v.chunks(8).enumerate() {
            arr[i] = u64::from_le_bytes(chunk.try_into().expect("Invalid fr length"));
        }
        ark_bn254::Fr::from_bigint(BigInt(arr)).unwrap()
    }

    let buffer: Vec<Vec<u8>> = bincode::deserialize(&buffer).unwrap();
    let mut pubin = vec![];
    for item in &buffer {
        let f = tmp_fr_deserialization(item);
        pubin.push(f);
    }
    pubin
}

#[test]
#[ignore]
#[allow(deprecated)]
fn verify_zkm2_proof() {
    use crate::wots::{Wots, Wots16, Wots32};
    /// TODO: Update NUM_PUBS, NUM_256, NUM_160, mock_proof
    /// NUM_PUBS = 2
    /// NUM_256 = 14
    /// NUM_160 = 367
    use bitvm::chunk::api::{
        api_generate_full_tapscripts, api_generate_partial_script, generate_signatures,
        validate_assertions, PublicKeys, NUM_HASH, NUM_PUBS, NUM_U256,
    };
    fn get_pubkeys(secret_key: Vec<String>) -> PublicKeys {
        let mut pubins = vec![];
        for secret in secret_key.iter().take(NUM_PUBS) {
            pubins.push(Wots32::generate_public_key(&Wots32::secret_from_str(
                secret.as_str(),
            )));
        }
        let mut fq_arr = vec![];
        for i in 0..NUM_U256 {
            let p256 = Wots32::generate_public_key(&Wots32::secret_from_str(
                secret_key[i + NUM_PUBS].as_str(),
            ));
            fq_arr.push(p256);
        }
        let mut h_arr = vec![];
        for i in 0..NUM_HASH {
            let p160 = Wots16::generate_public_key(&Wots16::secret_from_str(
                secret_key[i + NUM_PUBS + NUM_U256].as_str(),
            ));
            h_arr.push(p160);
        }
        let wotspubkey: PublicKeys = (
            pubins.try_into().unwrap(),
            fq_arr.try_into().unwrap(),
            h_arr.try_into().unwrap(),
        );
        wotspubkey
    }

    let proof_file = "ark-bin/proof.bin";
    let vk_file = "ark-bin/vkey.bin";
    let pubin_file = "ark-bin/pubin.bin";

    let proof_bin = std::fs::read(proof_file).unwrap();
    let vk_bin = std::fs::read(vk_file).unwrap();
    let pubin_bin = std::fs::read(pubin_file).unwrap();

    let ark_proof = deserialize_proof(proof_bin);
    let ark_vkey = deserialize_vk(vk_bin);
    let ark_public_inputs = deserialize_pubin(pubin_bin);

    println!("STEP 1 GENERATE TAPSCRIPTS");
    let secret_key: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
    let secrets = (0..NUM_PUBS + NUM_U256 + NUM_HASH)
        .map(|idx| format!("{secret_key}{:04x}", idx))
        .collect::<Vec<String>>();
    let pubkeys = get_pubkeys(secrets.clone());

    let partial_scripts = api_generate_partial_script(&ark_vkey);
    let disprove_scripts = api_generate_full_tapscripts(pubkeys, &partial_scripts);

    println!("STEP 2 GENERATE SIGNED ASSERTIONS");
    let proof_sigs = generate_signatures(
        ark_proof,
        ark_public_inputs.to_vec(),
        &ark_vkey,
        secrets.clone(),
    )
    .unwrap();
    println!("num assertion; 256-bit numbers {}", NUM_PUBS + NUM_U256);
    println!("num assertion; 160-bit numbers {}", NUM_HASH);

    println!("STEP 3 VALIDATE SIGNED ASSERTIONS");
    let validate_res = validate_assertions(
        &ark_vkey,
        proof_sigs,
        pubkeys,
        &disprove_scripts.try_into().unwrap(),
    );
    assert!(validate_res.is_none());
}

#[test]
#[ignore]
fn read_bin() {
    use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};

    let proof_file = "ark-bin/proof.bin";
    let vk_file = "ark-bin/vkey.bin";
    let pubin_file = "ark-bin/pubin.bin";

    let proof_bin = std::fs::read(proof_file).unwrap();
    let vk_bin = std::fs::read(vk_file).unwrap();
    let pubin_bin = std::fs::read(pubin_file).unwrap();

    let ark_proof = deserialize_proof(proof_bin);
    let ark_vkey = deserialize_vk(vk_bin);
    let ark_public_inputs = deserialize_pubin(pubin_bin);

    dbg!(&ark_proof);
    dbg!(&ark_vkey);
    dbg!(&ark_public_inputs);

    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
        &ark_vkey.into(),
        &ark_proof,
        &ark_public_inputs,
    )
    .unwrap();
    assert!(ok);
}

#[test]
#[ignore]
fn genearte_test_proof() {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};

    #[derive(Copy)]
    pub struct DummyCircuit<F: PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: PrimeField> Clone for DummyCircuit<F> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let proof_bin = serialize_proof(proof);
    let vk_bin = serialize_vk(vk);
    let pubin_bin = serialize_pubin(vec![c]);

    std::fs::write("test-groth16/proof.bin", &proof_bin).unwrap();
    std::fs::write("test-groth16/vkey.bin", &vk_bin).unwrap();
    std::fs::write("test-groth16/pubin.bin", &pubin_bin).unwrap();
}
