mod signature;
mod utils;
use alloy_primitives::U32;
pub use signature::*;
pub use utils::*;

use alloy_primitives::U256;
use bitcoin::Block;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use commit_chain::{
    AuthorizedProgramIds, CommitChainCircuitInput, CommitChainCircuitOutput,
    commit_chain_commitment_digest, decode_commit_chain_circuit_output,
    extract_commit_chain_commitment, extract_data_from_commitment_outputs, sequencer_hash,
};
use header_chain::{
    BitcoinMerkleTree, BlockHeaderCircuitOutput, CircuitBlockHeader, CircuitTransaction,
    HeaderChainCircuitInput, MMRHost, SPV, verify_merkle_proof,
};
use state_chain::{StateChainCircuitInput, StateChainCircuitOutput, verify_sequencer_commit};
use zkm_primitives::io::ZKMPublicValues;

use bitcoin::{Transaction, secp256k1::XOnlyPublicKey};
pub use guest_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};
use verifier::verify_groth16_proof;

pub const GRAPH_ID_SIZE: usize = 16;
pub const PROOF_SIZE: usize = 260;
pub const PUBLIC_INPUTS_SIZE: usize = 36;
pub const ZKM_VERSION_LEN_SIZE: usize = 4;
pub const VK_HASH_SIZE: usize = 66;

pub const TOTAL_WORK_SIZE: usize = 32;
pub const CONSENSUS_BLOCK_HEIGHT_SIZE: usize = 4;

// 0xc3d8382a8efed79d564f8ec6da4dd00a4e77572d1e02f5f81dda441a36fdc9d8
pub const ROOT_COMMIT_PROGRAM_ID: verifier::ProgramId = [
    195, 216, 56, 42, 142, 254, 215, 157, 86, 79, 142, 198, 218, 77, 208, 10, 78, 119, 87, 45, 30,
    2, 245, 248, 29, 218, 68, 26, 54, 253, 201, 216,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerPublicOutputs {
    pub total_work: [u8; TOTAL_WORK_SIZE],
    pub consensus_block_height: [u8; CONSENSUS_BLOCK_HEIGHT_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPublicOutputs {
    pub btc_best_block_hash: [u8; 32],
    pub constant: [u8; 32],
    pub included_watchtowers: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedWatchtowerChallenge {
    pub node_index: u16,
    pub spv: SPV,
}

/// Verifies that a proof identity matches both its output and Publisher authorization.
fn check_program_id(
    actual_program_id: verifier::ProgramId,
    output_program_id: verifier::ProgramId,
    authorized_program_id: verifier::ProgramId,
) {
    assert_eq!(actual_program_id, authorized_program_id, "unauthorized proof program id");
    assert_eq!(output_program_id, actual_program_id, "proof output program id mismatch");
}

fn checked_history_root(
    program_type: verifier::ProgramType,
    actual_program_id: verifier::ProgramId,
    output_program_id: verifier::ProgramId,
    authorized_program_id: verifier::ProgramId,
    history: [u8; 32],
) -> [u8; 32] {
    check_program_id(actual_program_id, output_program_id, authorized_program_id);
    verifier::finalize_history(program_type, history, actual_program_id)
}

/// Verifies that the latest Bitcoin commitment authorizes every supplied circuit proof.
///
/// `root_commit_program_id` is the pinned anchor; it is the only identity here that does not
/// come from the proofs being checked, so it is asserted before anything reads the
/// Commit-chain output. See [`ROOT_COMMIT_PROGRAM_ID`].
#[allow(clippy::too_many_arguments)]
fn verify_commitment_authorization(
    commit_chain_output: &CommitChainCircuitOutput,
    header_chain_output: &BlockHeaderCircuitOutput,
    state_chain_output: &StateChainCircuitOutput,
    header_program_id: verifier::ProgramId,
    state_program_id: verifier::ProgramId,
    commit_program_id: verifier::ProgramId,
    root_commit_program_id: verifier::ProgramId,
    sequencer_set_hash: [u8; 32],
) -> AuthorizedProgramIds {
    assert_eq!(
        commit_program_id, root_commit_program_id,
        "commit proof program id does not match the pinned root anchor"
    );
    let authorized = commit_chain_output.chain_state.authorized_program_ids;
    authorized.validate().expect("invalid authorized ProgramIds");
    check_program_id(commit_program_id, commit_chain_output.self_program_id, authorized.commit);
    let program_history_root = verifier::program_history_root(
        checked_history_root(
            verifier::ProgramType::Header,
            header_program_id,
            header_chain_output.self_program_id,
            authorized.header,
            header_chain_output.program_history_hash,
        ),
        checked_history_root(
            verifier::ProgramType::State,
            state_program_id,
            state_chain_output.self_program_id,
            authorized.state,
            state_chain_output.program_history_hash,
        ),
    );
    let checkpoint_root = verifier::proof_checkpoint_root(
        header_chain_output.upgrade_checkpoint_hash,
        state_chain_output.upgrade_checkpoint_hash,
    );
    assert_eq!(
        checkpoint_root, commit_chain_output.chain_state.proof_checkpoint_root,
        "proof checkpoint root mismatch"
    );
    let commitment =
        extract_commit_chain_commitment(&commit_chain_output.chain_state.commit_txn.output)
            .expect("invalid commit-chain commitment output");
    assert_eq!(
        commitment,
        commit_chain_commitment_digest(
            sequencer_set_hash,
            state_chain_output.chain_state.genesis_evm_block_hash,
            program_history_root,
            checkpoint_root,
            authorized,
        )
    );
    authorized
}

pub fn decode_operator_public_outputs(
    public_values: &[u8],
) -> Result<OperatorPublicOutputs, String> {
    if public_values.len() != 96 {
        return Err(format!(
            "operator public values must be 96 bytes, got {}",
            public_values.len()
        ));
    }
    bincode::deserialize(public_values)
        .map_err(|err| format!("failed to decode operator public values: {err}"))
}

pub fn watch_longest_chain(
    genesis_sequencer_commit_txid: [u8; 32],
    header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    state_chain: StateChainCircuitInput,
    spv: SPV,
) -> ([u8; 32], u32) {
    println!("commit header, size: {}", commit_chain.commits.len());
    // verify latest_sequencer_commit is valid:
    //   * Check both latest_sequencer_commit_txid and genesis_sequencer_commit_txid are in all_sequencer_commit_txids (which is a private input)
    //   * Check latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    // verify the commit chain proof
    let commit_program_id = verify_groth16_proof(
        &commit_chain.zkm_proof,
        &commit_chain.zkm_public_values,
        &commit_chain.zkm_vk_hash,
        &commit_chain.zkm_version,
    )
    .expect("Failed to verify commit chain proof");

    let commit_chain_output = decode_commit_chain_circuit_output(&commit_chain.zkm_public_values);
    assert_eq!(
        commit_chain_output.chain_state.commit_txn.compute_txid(),
        spv.transaction.0.compute_txid()
    );
    assert_eq!(genesis_sequencer_commit_txid, commit_chain_output.chain_state.genesis_txid);

    println!("header chain: applying: {}", header_chain.block_headers.len());
    // verify header_chain is valid
    let header_program_id = verify_groth16_proof(
        &header_chain.zkm_proof,
        &header_chain.zkm_public_values,
        &header_chain.zkm_vk_hash,
        &header_chain.zkm_version,
    )
    .expect("Failed to verify header chain proof");

    let btc_header_chain_output: BlockHeaderCircuitOutput =
        ZKMPublicValues::from(&header_chain.zkm_public_values).read();
    assert_eq!(
        btc_header_chain_output.chain_state.block_hashes_mmr.size,
        btc_header_chain_output.chain_state.block_height + 1,
        "header MMR size mismatch"
    );
    let commitment_block_height = spv
        .verify(&btc_header_chain_output.chain_state.block_hashes_mmr)
        .expect("sequencer commitment SPV verification failed");

    let state_program_id = verify_groth16_proof(
        &state_chain.zkm_proof,
        &state_chain.zkm_public_values,
        &state_chain.zkm_vk_hash,
        &state_chain.zkm_version,
    )
    .expect("Failed to verify state chain proof");
    let state_chain_output: StateChainCircuitOutput =
        ZKMPublicValues::from(&state_chain.zkm_public_values).read();
    // check the signature.
    let cosmos_block_bytes = &state_chain_output.chain_state.latest_cosmos_block;
    let cosmos_block: LightBlock =
        serde_json::from_slice(cosmos_block_bytes).expect("failed to deserialize light block");
    verify_sequencer_commit(&cosmos_block);

    // check the equivalence of sequencer set
    let commit_sequencer_set_hash = sequencer_hash(&commit_chain_output.chain_state.sequencers);
    let expected_seqeuencer_set_hash = cosmos_block.signed_header.header.validators_hash;
    assert_eq!(commit_sequencer_set_hash, expected_seqeuencer_set_hash);

    if let tendermint::Hash::Sha256(sequencer_set_hash) = expected_seqeuencer_set_hash {
        verify_commitment_authorization(
            &commit_chain_output,
            &btc_header_chain_output,
            &state_chain_output,
            header_program_id,
            state_program_id,
            commit_program_id,
            ROOT_COMMIT_PROGRAM_ID,
            sequencer_set_hash,
        );
    } else {
        panic!("Invalid commitment: inconsistent sequencer set hash");
    };

    println!("commit public inputs");
    // commit public inputs
    (btc_header_chain_output.chain_state.total_work, commitment_block_height)
}

pub fn u256_to_le_bits(u: U256) -> [bool; 256] {
    let mut bits = [false; 256];
    for (i, item) in bits.iter_mut().enumerate() {
        *item = u.bit(i); // U256 provides `.bit(n)` method
    }
    bits
}

pub fn le_bits_to_u256(bits: &[bool]) -> U256 {
    let mut u = U256::ZERO;
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            u += U256::ONE << i; // Set the i-th bit if it's true
        }
    }
    u
}

/// Validates challenge indices against the graph-sized public inclusion bitmap.
pub fn validate_watchtower_challenge_indices(
    included_watchtowers: &[bool; 256],
    graph_watchtower_count: usize,
    challenge_indices: &[u16],
) -> Result<(), String> {
    if graph_watchtower_count == 0 || graph_watchtower_count > 256 {
        return Err(format!("invalid graph watchtower count {graph_watchtower_count}"));
    }

    let mut seen = [false; 256];
    for index in challenge_indices {
        let index = *index as usize;
        if index >= graph_watchtower_count {
            return Err(format!("watchtower challenge index {index} out of bounds"));
        }
        if seen[index] {
            return Err(format!("duplicate watchtower challenge index {index}"));
        }
        seen[index] = true;
    }
    if included_watchtowers != &seen {
        return Err("watchtower challenge indices do not match included bitmap".to_string());
    }
    Ok(())
}

/// Checks an optional challenge-init transaction against its graph txid.
/// A transaction is required when `challenges_present` is true.
fn checked_challenge_init_transaction(
    expected_txid: [u8; 32],
    transaction: Option<&Transaction>,
    challenges_present: bool,
) -> Option<&Transaction> {
    if let Some(transaction) = transaction {
        assert_eq!(
            transaction.compute_txid().to_byte_array(),
            expected_txid,
            "watchtower challenge init transaction txid mismatch"
        );
    }
    assert!(
        !challenges_present || transaction.is_some(),
        "watchtower challenge init transaction is required when challenges exist"
    );

    transaction
}

// calculate operator public input:  https://github.com/ProjectZKM/Ziren/blob/main/crates/sdk/src/utils.rs#L42
#[allow(clippy::too_many_arguments)]
pub fn propose_longest_chain(
    included_watchtowers: U256,                       //pis
    graph_id: [u8; GRAPH_ID_SIZE],                    // pis
    operator_genesis_sequencer_commit_txid: [u8; 32], // pis

    watchtower_challenge_init_txid: [u8; 32],
    watchtower_challenge_init_txn: Option<Transaction>,
    watchtower_challenges: Vec<IndexedWatchtowerChallenge>,
    graph_watchtower_xonly_public_keys: &[[u8; 32]],

    operator_header_chain: HeaderChainCircuitInput,
    commit_chain: CommitChainCircuitInput,
    state_chain: StateChainCircuitInput,
    spv_ss_commit: SPV,
    operator_committed_blockhash: [u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // verify operator_latest_sequencer_commit_txid is valid, and on operator head chain
    //   * Check operator_latest_sequencer_commit_txid is derived from genesis_sequencer_commit_txid
    let commit_program_id = verify_groth16_proof(
        &commit_chain.zkm_proof,
        &commit_chain.zkm_public_values,
        &commit_chain.zkm_vk_hash,
        &commit_chain.zkm_version,
    )
    .expect("Failed to verify commit chain proof");
    let commit_chain_output = decode_commit_chain_circuit_output(&commit_chain.zkm_public_values);
    assert_eq!(
        commit_chain_output.chain_state.commit_txn.compute_txid(),
        spv_ss_commit.transaction.0.compute_txid()
    );
    assert_eq!(
        operator_genesis_sequencer_commit_txid,
        commit_chain_output.chain_state.genesis_txid
    );

    // https://github.com/KSlashh/BitVM/blob/v2/goat/src/transactions/watchtower_challenge.rs#L128
    // verify operator_header_chain is valid
    let header_program_id = verify_groth16_proof(
        &operator_header_chain.zkm_proof,
        &operator_header_chain.zkm_public_values,
        &operator_header_chain.zkm_vk_hash,
        &operator_header_chain.zkm_version,
    )
    .expect("Failed to verify header chain proof");
    let btc_header_chain_output: BlockHeaderCircuitOutput =
        ZKMPublicValues::from(&operator_header_chain.zkm_public_values).read();
    let operator_total_work = btc_header_chain_output.chain_state.total_work;
    let btc_best_block_hash = btc_header_chain_output.chain_state.best_block_hash;
    assert_eq!(
        btc_header_chain_output.chain_state.block_hashes_mmr.size,
        btc_header_chain_output.chain_state.block_height + 1,
        "header MMR size mismatch"
    );
    let operator_consensus_block_height = spv_ss_commit
        .verify(&btc_header_chain_output.chain_state.block_hashes_mmr)
        .expect("sequencer commitment SPV verification failed");

    println!("verify el block");
    let state_program_id = verify_groth16_proof(
        &state_chain.zkm_proof,
        &state_chain.zkm_public_values,
        &state_chain.zkm_vk_hash,
        &state_chain.zkm_version,
    )
    .expect("Failed to verify state chain proof");

    let state_chain_output: StateChainCircuitOutput =
        ZKMPublicValues::from(&state_chain.zkm_public_values).read();

    // check the signature.
    let cosmos_block_bytes = &state_chain_output.chain_state.latest_cosmos_block;
    let cosmos_block: LightBlock =
        serde_json::from_slice(cosmos_block_bytes).expect("failed to deserialize light block");
    verify_sequencer_commit(&cosmos_block);
    // check the equivalence of sequencer set
    let commit_sequencer_set_hash = sequencer_hash(&commit_chain_output.chain_state.sequencers);
    let expected_seqeuencer_set_hash = cosmos_block.signed_header.header.validators_hash;

    let authorized =
        if let tendermint::Hash::Sha256(sequencer_set_hash) = expected_seqeuencer_set_hash {
            verify_commitment_authorization(
                &commit_chain_output,
                &btc_header_chain_output,
                &state_chain_output,
                header_program_id,
                state_program_id,
                commit_program_id,
                ROOT_COMMIT_PROGRAM_ID,
                sequencer_set_hash,
            )
        } else {
            panic!("Invalid commitment: inconsistent sequencer set hash");
        };
    assert_eq!(commit_sequencer_set_hash, expected_seqeuencer_set_hash);

    let included_watchtowers_bits = u256_to_le_bits(included_watchtowers);
    let challenge_indices =
        watchtower_challenges.iter().map(|challenge| challenge.node_index).collect::<Vec<_>>();
    validate_watchtower_challenge_indices(
        &included_watchtowers_bits,
        graph_watchtower_xonly_public_keys.len(),
        &challenge_indices,
    )
    .expect("invalid indexed watchtower challenges");

    let watchtower_challenge_init_txn = checked_challenge_init_transaction(
        watchtower_challenge_init_txid,
        watchtower_challenge_init_txn.as_ref(),
        !watchtower_challenges.is_empty(),
    );
    for challenge in &watchtower_challenges {
        let i = challenge.node_index as usize;
        let challenge_height = challenge
            .spv
            .verify(&btc_header_chain_output.chain_state.block_hashes_mmr)
            .expect("watchtower challenge SPV verification failed");
        assert!(
            challenge_height <= btc_header_chain_output.chain_state.block_height,
            "challenge height exceeds authenticated header chain"
        );

        let tx = &challenge.spv.transaction.0;
        let input = tx.input.first().expect("watchtower challenge must have input 0");
        let expected_vout = u32::from(challenge.node_index) * 2;
        assert_eq!(input.previous_output.txid.to_byte_array(), watchtower_challenge_init_txid);
        assert_eq!(input.previous_output.vout, expected_vout);

        let prev_out = watchtower_challenge_init_txn
            .expect("watchtower challenge init transaction is required")
            .output
            .get(expected_vout as usize)
            .expect("watchtower challenge prevout is missing");
        let xonly = XOnlyPublicKey::from_slice(&graph_watchtower_xonly_public_keys[i])
            .expect("invalid graph watchtower x-only key");
        let script = bitcoin::blockdata::script::Builder::new()
            .push_x_only_key(&xonly)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        verify_taproot_leaf_schnorr_signature(&script, tx, 0, prev_out, &xonly)
            .expect("watchtower challenge signature verification failed");

        let Ok(commitment) = extract_data_from_commitment_outputs(&tx.output) else {
            continue;
        };
        let Ok((
            parsed_graph_id,
            proof,
            public_values,
            vk,
            watchtower_total_work,
            watchtower_consensus_block_height,
            zkm_version,
        )) = parse_watchtower_commitment(&commitment)
        else {
            continue;
        };
        let Ok(program_id) = verify_groth16_proof(&proof, &public_values, &vk, &zkm_version) else {
            continue;
        };
        if program_id != authorized.watchtower || parsed_graph_id != graph_id {
            continue;
        }
        assert!(
            U256::from_be_bytes(watchtower_total_work) <= U256::from_be_bytes(operator_total_work),
            "valid watchtower challenge has more work than operator"
        );
        assert!(
            u32::from_le_bytes(watchtower_consensus_block_height)
                <= operator_consensus_block_height,
            "valid watchtower challenge has a later commitment than operator"
        );
    }

    let mut is_found = false;
    for withdrawal in &state_chain_output.chain_state.withdrawals {
        if withdrawal.2.contains(&graph_id) {
            is_found = true;
            break;
        }
    }
    assert!(is_found, "Graph id {graph_id:?} is not included in current state chain");

    // (operator_total_work, included_watchtowers, graph_id, operator_genesis_sequencer_commit_txid, btc_best_block_hash)
    //(hash_operator_inputs(graph_id, operator_genesis_sequencer_commit_txid), btc_best_block_hash)
    println!("graph_id hex: {:?}", hex::encode(graph_id));
    println!(
        "operator_genesis_sequencer_commit_txid hex: {:?}",
        hex::encode(operator_genesis_sequencer_commit_txid)
    );
    let constant = hash_operator_constant(
        graph_id,
        operator_genesis_sequencer_commit_txid,
        watchtower_challenge_init_txid,
        graph_watchtower_xonly_public_keys,
    );
    println!("constant hex: {:?}", hex::encode(constant));

    println!("btc_best_block_hash hex: {:?}", hex::encode(btc_best_block_hash));
    println!("included_watchtowers: {:?}", hex::encode(included_watchtowers.to_le_bytes::<32>()));
    //let included = operator_header_chain
    //    .block_headers
    //    .iter()
    //    .position(|header| header.compute_block_hash() == operator_committed_blockhash);
    //assert!(included.is_some(), "operator committed blockhash is not included in header chain");
    assert_eq!(
        operator_committed_blockhash, btc_best_block_hash,
        "operator committed blockhash is not included in header chain"
    );

    //operator_public_input
    (operator_committed_blockhash, constant, included_watchtowers.to_le_bytes::<32>())
}

pub fn hash_operator_constant(
    graph_id: [u8; GRAPH_ID_SIZE],
    operator_genesis_sequencer_commit_txid: [u8; 32],
    watchtower_challenge_init_txid: [u8; 32],
    watchtower_xonly_public_keys: &[[u8; 32]],
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"bitvm/operator-constant/v3");
    engine.input(&graph_id);
    engine.input(&operator_genesis_sequencer_commit_txid);
    engine.input(&watchtower_challenge_init_txid);
    engine.input(&(watchtower_xonly_public_keys.len() as u16).to_be_bytes());
    for key in watchtower_xonly_public_keys {
        engine.input(key);
    }
    let hash = sha256::Hash::from_engine(engine);
    *hash.as_byte_array()
}

pub fn hash_partial_binding_witness(
    constant: [u8; 32],
    btc_best_block_hash: [u8; 32],
    included_watchtowers: [u8; 32],
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(&constant);
    engine.input(&btc_best_block_hash);
    engine.input(&included_watchtowers);
    let hash = sha256::Hash::from_engine(engine);
    *hash.as_byte_array()
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// Utility method for converting u32 words from bytes in big endian.
pub fn words_from_bytes_be(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4].try_into().unwrap();
        words[i] = u32::from_be_bytes(chunk);
    }
    words
}

pub fn build_spv(
    raw_txn: &Transaction,
    target_block_pos: u32,
    target_block: Block,
    block_headers: &[CircuitBlockHeader],
) -> SPV {
    let tx: CircuitTransaction = CircuitTransaction(raw_txn.clone());
    let latest_sequencer_commit_txid = tx.0.compute_txid();

    let mut mmr_native = MMRHost::new();
    for block_header in block_headers {
        mmr_native.append(block_header.compute_block_hash());
    }

    let target_block_header: CircuitBlockHeader = block_headers[target_block_pos as usize].clone();

    // find the target block
    let tx_pos =
        target_block.txdata.iter().position(|x| x.compute_txid() == latest_sequencer_commit_txid);
    assert!(tx_pos.is_some());
    let txid_list = target_block.txdata.iter().map(|x| x.compute_txid().to_byte_array()).collect();

    let bitcoin_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new(txid_list);
    let bitcoin_inclusion_proof = bitcoin_merkle_tree.generate_proof(tx_pos.unwrap() as u32);

    println!("verify merkle proof");
    if !(verify_merkle_proof(
        latest_sequencer_commit_txid.to_byte_array(),
        &bitcoin_inclusion_proof,
        bitcoin_merkle_tree.root(),
    )) {
        panic!("Can not verify merkle proof")
    }

    println!("generate proof from mmr native");

    let (_, mmr_inclusion_proof) = mmr_native.generate_proof(target_block_pos);

    println!("constuct spv");
    SPV::new(tx, bitcoin_inclusion_proof, target_block_header, mmr_inclusion_proof)
}

pub fn build_watchtower_commitment(
    graph_id: &[u8; GRAPH_ID_SIZE],
    proof: &[u8; PROOF_SIZE],
    public_inputs: &[u8; PUBLIC_INPUTS_SIZE],
    vk_hash: &str,
    zkm_version: &str,
) -> Vec<u8> {
    let mut comm = graph_id.to_vec();
    comm.extend_from_slice(proof);
    comm.extend_from_slice(public_inputs);
    assert_eq!(vk_hash.len(), VK_HASH_SIZE);
    comm.extend_from_slice(vk_hash.as_bytes());
    comm.extend_from_slice(&(zkm_version.len() as u32).to_le_bytes());
    comm.extend_from_slice(zkm_version.as_bytes());

    comm
}

pub type WatchtowerCommitmentResult = (
    [u8; GRAPH_ID_SIZE],
    [u8; PROOF_SIZE],
    [u8; PUBLIC_INPUTS_SIZE],
    [u8; VK_HASH_SIZE],
    [u8; TOTAL_WORK_SIZE],
    [u8; CONSENSUS_BLOCK_HEIGHT_SIZE],
    String,
);

pub fn parse_watchtower_commitment(
    commitment: &[u8],
) -> Result<WatchtowerCommitmentResult, String> {
    let min_commitment_size =
        GRAPH_ID_SIZE + PROOF_SIZE + PUBLIC_INPUTS_SIZE + VK_HASH_SIZE + ZKM_VERSION_LEN_SIZE;
    if commitment.len() < min_commitment_size {
        return Err(format!(
            "invalid commitment size: {}, expected at least {}",
            commitment.len(),
            min_commitment_size
        ));
    }
    let mut end = GRAPH_ID_SIZE;
    let mut graph_id = [0u8; GRAPH_ID_SIZE];
    graph_id.copy_from_slice(&commitment[..end]);

    let mut proof = [0u8; PROOF_SIZE];
    proof.copy_from_slice(&commitment[end..end + PROOF_SIZE]);
    end += PROOF_SIZE;

    let mut zkm_public_values = [0u8; PUBLIC_INPUTS_SIZE];
    zkm_public_values.copy_from_slice(&commitment[end..end + PUBLIC_INPUTS_SIZE]);
    end += PUBLIC_INPUTS_SIZE;

    let mut zkm_vk_hash_bytes = [0u8; VK_HASH_SIZE];
    zkm_vk_hash_bytes.copy_from_slice(&commitment[end..end + VK_HASH_SIZE]);
    end += VK_HASH_SIZE;

    let zkm_version_len =
        u32::from_le_bytes(commitment[end..end + ZKM_VERSION_LEN_SIZE].try_into().unwrap())
            as usize;
    if zkm_version_len == 0 {
        return Err("zkm_version must not be empty".to_string());
    }
    end += ZKM_VERSION_LEN_SIZE;

    let expected_size = min_commitment_size + zkm_version_len;
    if commitment.len() != expected_size {
        return Err(format!(
            "invalid commitment size: {}, expected {}",
            commitment.len(),
            expected_size
        ));
    }
    let zkm_version = String::from_utf8(commitment[end..end + zkm_version_len].to_vec())
        .map_err(|err| format!("invalid zkm_version UTF-8: {err}"))?;

    // extract ChainState
    let mut watchtower_total_work = [0u8; TOTAL_WORK_SIZE];
    watchtower_total_work.copy_from_slice(&zkm_public_values[0..TOTAL_WORK_SIZE]);
    let mut watchtower_consensus_block_height = [0u8; CONSENSUS_BLOCK_HEIGHT_SIZE];
    watchtower_consensus_block_height.copy_from_slice(
        &zkm_public_values[TOTAL_WORK_SIZE..TOTAL_WORK_SIZE + CONSENSUS_BLOCK_HEIGHT_SIZE],
    );

    println!("watchtower total work: {watchtower_total_work:?}");
    println!("watchtower total work: {:?}", U256::from_be_bytes(watchtower_total_work));
    println!("watchtower consensus block height: {watchtower_consensus_block_height:?}");
    println!(
        "watchtower consensus block height: {:?}",
        U32::from_le_bytes(watchtower_consensus_block_height)
    );

    Ok((
        graph_id,
        proof,
        zkm_public_values,
        zkm_vk_hash_bytes,
        watchtower_total_work,
        watchtower_consensus_block_height,
        zkm_version,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::Transaction;
    const PROOF: &[u8] = include_bytes!("../../../circuits/data/watchtower/output3.bin.proof.bin");
    const PUBLIC_INPUTS: &[u8] =
        include_bytes!("../../../circuits/data/watchtower/output3.bin.public_inputs.bin");
    const VK_HASH: &str = include_str!("../../../circuits/data/watchtower/output3.bin.vk_hash.bin");
    const ZKM_VERSION: &str = "v1.2.4";

    #[test]
    fn checked_history_root_binds_actual_output_and_expected_program_ids() {
        let program_id = [1u8; 32];
        let history = [2u8; 32];
        assert_eq!(
            checked_history_root(
                verifier::ProgramType::Header,
                program_id,
                program_id,
                program_id,
                history,
            ),
            verifier::finalize_history(verifier::ProgramType::Header, history, program_id)
        );

        let wrong_expected = std::panic::catch_unwind(|| {
            checked_history_root(
                verifier::ProgramType::Header,
                program_id,
                program_id,
                [3u8; 32],
                history,
            )
        });
        assert!(wrong_expected.is_err());

        let wrong_output = std::panic::catch_unwind(|| {
            checked_history_root(
                verifier::ProgramType::Header,
                program_id,
                [3u8; 32],
                program_id,
                history,
            )
        });
        assert!(wrong_output.is_err());
    }

    #[test]
    fn check_program_id_rejects_unauthorized_or_mismatched_outputs() {
        let program_id = [1u8; 32];
        check_program_id(program_id, program_id, program_id);

        assert!(
            std::panic::catch_unwind(|| check_program_id(program_id, program_id, [2u8; 32]))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| check_program_id(program_id, [2u8; 32], program_id))
                .is_err()
        );
    }

    #[test]
    fn test_build_watchtower_commitment() {
        let graph_id = hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();

        let total_work = 1006120;
        let block_height = 503043;
        println!("public inputs: {:?}", PUBLIC_INPUTS.len());
        println!("vk hash: {:?}", VK_HASH.len());
        let comm = build_watchtower_commitment(
            &graph_id,
            &PROOF.try_into().unwrap(),
            &PUBLIC_INPUTS.try_into().unwrap(),
            VK_HASH,
            ZKM_VERSION,
        );

        println!("comm: {:?}", comm.len());
        println!("comm hex: {:?}", hex::encode(&comm));
        let expected = parse_watchtower_commitment(&comm).unwrap();
        println!("expected: {:?}", expected);

        assert_eq!(expected.0, graph_id);
        assert_eq!(expected.1, PROOF);
        assert_eq!(expected.2, PUBLIC_INPUTS);
        assert_eq!(expected.3, VK_HASH.as_bytes());
        assert_eq!(expected.4, U256::from(total_work).to_be_bytes());
        assert_eq!(expected.5, U32::from(block_height).to_le_bytes());
        assert_eq!(expected.6, ZKM_VERSION.to_string());
    }

    #[test]
    fn test_words_bytes_conversion() {
        let words: [u32; 8] = [
            0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00, 0x01020304, 0xa1b2c3d4, 0xdeadbeef,
            0xabcdef01,
        ];
        let bytes = words_to_bytes_be(&words);
        let recovered = words_from_bytes_be(&bytes);
        assert_eq!(words, recovered);
    }

    #[test]
    fn test_hash_partial_binding_witness() {
        use bitcoin::hashes::Hash as _;

        let constant = [1u8; 32];
        let btc_best_block_hash = [2u8; 32];
        let included_watchtowers = [3u8; 32];
        let mut input = Vec::new();
        input.extend_from_slice(&constant);
        input.extend_from_slice(&btc_best_block_hash);
        input.extend_from_slice(&included_watchtowers);
        let expected = bitcoin::hashes::sha256::Hash::hash(&input);

        assert_eq!(
            hash_partial_binding_witness(constant, btc_best_block_hash, included_watchtowers),
            *expected.as_byte_array()
        );
    }

    #[test]
    fn test_hash_operator_constant_binds_ordered_watchtower_keys() {
        use bitcoin::hashes::Hash as _;

        let graph_id = [1u8; GRAPH_ID_SIZE];
        let genesis_txid = [2u8; 32];
        let watchtower_keys = [[3u8; 32], [4u8; 32]];
        let challenge_init_txid = [5u8; 32];
        let mut input = b"bitvm/operator-constant/v3".to_vec();
        input.extend_from_slice(&graph_id);
        input.extend_from_slice(&genesis_txid);
        input.extend_from_slice(&challenge_init_txid);
        input.extend_from_slice(&(watchtower_keys.len() as u16).to_be_bytes());
        for key in &watchtower_keys {
            input.extend_from_slice(key);
        }
        let expected = bitcoin::hashes::sha256::Hash::hash(&input);

        assert_eq!(
            hash_operator_constant(graph_id, genesis_txid, challenge_init_txid, &watchtower_keys),
            *expected.as_byte_array()
        );
        assert_ne!(
            hash_operator_constant(
                graph_id,
                genesis_txid,
                challenge_init_txid,
                &[watchtower_keys[1], watchtower_keys[0]],
            ),
            *expected.as_byte_array()
        );
    }

    #[test]
    fn optional_challenge_init_transaction_is_fail_closed() {
        let transaction = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let txid = transaction.compute_txid().to_byte_array();

        assert!(checked_challenge_init_transaction(txid, None, false).is_none());
        assert!(checked_challenge_init_transaction(txid, Some(&transaction), true).is_some());
        assert!(
            std::panic::catch_unwind(|| {
                checked_challenge_init_transaction([1u8; 32], Some(&transaction), false)
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| { checked_challenge_init_transaction(txid, None, true) })
                .is_err()
        );
    }

    #[test]
    fn watchtower_challenge_indices_preserve_sparse_bitmap_positions() {
        let mut included = [false; 256];
        included[1] = true;
        included[4] = true;

        validate_watchtower_challenge_indices(&included, 5, &[1, 4]).unwrap();
        assert!(validate_watchtower_challenge_indices(&included, 5, &[0, 1]).is_err());
        assert!(validate_watchtower_challenge_indices(&included, 5, &[1, 1]).is_err());
    }

    #[test]
    fn test_u256_to_le_bits() {
        use std::str::FromStr;
        // generate random u256
        let u = U256::from(rand::random::<u128>());
        let bits = u256_to_le_bits(u);
        let reconstructed = le_bits_to_u256(&bits);
        assert_eq!(u, reconstructed);

        let u_str = u.to_string();
        let u = U256::from_str(&u_str).unwrap();
        let bits = u256_to_le_bits(u);
        let reconstructed2 = le_bits_to_u256(&bits);
        assert_eq!(u, reconstructed);
        assert_eq!(u, reconstructed2);
        let reconstructed_str = reconstructed2.to_string();
        assert_eq!(u_str, reconstructed_str);
    }

    #[test]
    fn test_extract_data_from_commitment_outputs() {
        use bitcoin::consensus::encode::deserialize;
        // Testnet4 tx: 14b586e2e64e7b4b12aca96832d0703b9d218fa81e0ea84c1155a5749b28924b
        let bytes = hex::decode(
            "02000000000102c1eeed57e622af0fbb57e863a3b6284dc5ce6249804d0b6ce923bf81004188b00000000000fffffffff0679cdb8b16eebfbcd7fb4d582a20247857db4927f0f79388ba6735bdcd98f60b00000000ffffffff0c4a010000000000002200209bf28a9ccba44a0cbdd17ce6bb8262a136a08ac0088b0ec3f5ae484951f590dd4a01000000000000220020f65f87063cd8c00f539cb877d19a672b241066780a185357072e7da517286a1d4a0100000000000022002056dde473377f215234cf46258af2e2a5007a8e34206ecb438cef18906035c7384a01000000000000220020e77df8511565180c187f61ecdaf15fdc0bcd6076084a3a6823eb1e7fbb4e5af74a01000000000000220020ee98e7229e9a7ac2269cf2c493ff09f1c8b64f5116f5c3662be80640f8a11e144a01000000000000220020a2703885ba63f87d5bde5c3f085a7343e09eaef408074390d2081ff325cc6e894a0100000000000022002038e7a277db470a65c1075e58053075fe83944c621e43601f2b77e18e597c1cbe4a01000000000000220020ad89f2340414b9209003047abdf53716103ff6e71bd1f04c17055c33859124e84a010000000000002200207024bc980d3fa0d5715d859f2e036164414bbdcf0000000000000000000000004a01000000000000220020000000000000000000000938e7e6f31c23766897f6d40100307830306562643200000000000000003c6a3a353862363863396134373432343339653636393834306432306265626665346562643236393366636138323463386430623065346531366233368726980000000000220020082778653debae3a77067cc2c165ae2294c4c6984515aabe977dde1d8e39365103412853f869fd7d8a3e97fd095e6dce63be7e13b172f70e6c92b4ad968af671b3b1f72113b8d2a2a3749c02fc1241110081d8b8ba3686fc6e9b157530ba2fc41bef81222076c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954ac41c076c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954d391bf91c2d0eb83acda477b90f5efbfa4e4d1388e31690a6de57ff01c93f2e202473044022006feb2824f0d733e11c98ea52b0c2aaa1e6bc4c4223287959addbe2e33ebb71202203a1d4613db8eadf3e8d65e46b94e4027d3e6435a2abffd8aeefbc8bd4858f7a50123210376c09522e2614dadf1471e456abf567b1756465a4133cedc7a0780b277f7e954ac00000000"
        ).unwrap();
        let tx: Transaction = deserialize(&bytes).unwrap();

        let commitment = extract_data_from_commitment_outputs(&tx.output).unwrap();
        let parse_result = parse_watchtower_commitment(&commitment);
        assert!(parse_result.is_err(), "legacy commitment with trailing zkm_version should fail");
    }

    #[test]
    fn test_parse_watchtower_commitment_rejects_missing_zkm_version_len() {
        let graph_id: [u8; GRAPH_ID_SIZE] =
            hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        let mut commitment = graph_id.to_vec();
        commitment.extend_from_slice(PROOF);
        commitment.extend_from_slice(PUBLIC_INPUTS);
        commitment.extend_from_slice(VK_HASH.as_bytes());
        assert!(parse_watchtower_commitment(&commitment).is_err());
    }

    #[test]
    fn test_parse_watchtower_commitment_rejects_empty_zkm_version() {
        let graph_id: [u8; GRAPH_ID_SIZE] =
            hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        let mut commitment = graph_id.to_vec();
        commitment.extend_from_slice(PROOF);
        commitment.extend_from_slice(PUBLIC_INPUTS);
        commitment.extend_from_slice(VK_HASH.as_bytes());
        commitment.extend_from_slice(&0u32.to_le_bytes());

        assert!(parse_watchtower_commitment(&commitment).is_err());
    }

    #[test]
    fn test_parse_watchtower_commitment_rejects_invalid_zkm_version_utf8() {
        let graph_id: [u8; GRAPH_ID_SIZE] =
            hex::decode("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        let mut commitment = graph_id.to_vec();
        commitment.extend_from_slice(PROOF);
        commitment.extend_from_slice(PUBLIC_INPUTS);
        commitment.extend_from_slice(VK_HASH.as_bytes());
        commitment.extend_from_slice(&2u32.to_le_bytes());
        commitment.extend_from_slice(&[0xff, 0xff]);

        assert!(parse_watchtower_commitment(&commitment).is_err());
    }
}
