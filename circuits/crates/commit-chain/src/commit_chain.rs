use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use serde::{Deserialize, Serialize};
use tendermint::validator::{Info, ProposerPriority};
use tendermint::{PublicKey as TPublicKey, account};
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Hash, ValidatorSet},
};

use bincode::Options as BincodeOptions;
use bitcoin::{Transaction, TxOut, Witness, hashes::Hash as _, secp256k1::PublicKey};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct AuthorizedProgramIds {
    pub header: verifier::ProgramId,
    pub state: verifier::ProgramId,
    pub commit: verifier::ProgramId,
    pub watchtower: verifier::ProgramId,
}

impl AuthorizedProgramIds {
    /// Rejects an authorization set containing an unconfigured ProgramId.
    pub fn validate(&self) -> Result<(), String> {
        if [self.header, self.state, self.commit, self.watchtower].contains(&[0u8; 32]) {
            return Err("authorized ProgramIds must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitInfo {
    pub threshold: u16,
    pub publisher_public_keys: Vec<String>,
    #[serde(default)]
    pub next_threshold: Option<u16>,
    #[serde(default)]
    pub next_publisher_public_keys: Option<Vec<String>>,
    pub txid: String,
    pub genesis_txid: String,
    pub sequencers: Vec<SequencerInfo>,
    pub genesis_evm_block_hash: [u8; 32],
    pub program_history_root: [u8; 32],
    pub proof_checkpoint_root: [u8; 32],
    pub authorized_program_ids: AuthorizedProgramIds,
}

/// Selects a Genesis replay or a same-Program recursive predecessor.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum CommitChainPrevProofType {
    GenesisBlock,
    PrevProof,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CircuitCommit {
    pub commit_txn: Transaction,
    pub genesis_txid: [u8; 32],
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
    #[serde(default)]
    pub next_publisher_public_keys: Option<Vec<PublicKey>>,
    #[serde(default)]
    pub next_threshold: Option<u16>,
    pub sequencers: Vec<SequencerInfo>,
    pub genesis_evm_block_hash: [u8; 32],
    pub program_history_root: [u8; 32],
    pub block_height: u32, // Bitcoin block height of current commitment
    pub proof_checkpoint_root: [u8; 32],
    pub authorized_program_ids: AuthorizedProgramIds,
}

impl CommitInfo {
    /// Return the publisher set that becomes active after this commit is mined.
    pub fn active_publisher_set(&self) -> (&[String], u16) {
        match (self.next_publisher_public_keys.as_deref(), self.next_threshold) {
            (Some(next_keys), Some(next_threshold)) => (next_keys, next_threshold),
            _ => (&self.publisher_public_keys, self.threshold),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SequencerInfo {
    /// Validator account address
    pub address: String,
    /// Validator public key
    pub pub_key: Vec<u8>,
    pub power: u64,
    /// Validator name
    pub name: Option<String>,
}

impl From<SequencerInfo> for Info {
    fn from(val: SequencerInfo) -> Self {
        Info {
            address: account::Id::try_from(hex::decode(&val.address).unwrap()).unwrap(),
            pub_key: TPublicKey::from_raw_secp256k1(&val.pub_key).unwrap(),
            power: val.power.try_into().unwrap(),
            name: val.name,
            proposer_priority: ProposerPriority::default(),
        }
    }
}

impl From<Info> for SequencerInfo {
    fn from(info: Info) -> Self {
        SequencerInfo {
            address: hex::encode(info.address.as_bytes()),
            pub_key: info.pub_key.to_bytes(),
            power: info.power.value(),
            name: info.name,
        }
    }
}

/// The latest seqeuncer set
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainState {
    pub block_height: u32,
    pub commit_txn: Transaction,
    pub genesis_txid: [u8; 32],
    pub sequencers: Vec<SequencerInfo>,
    pub publisher_public_keys: Vec<PublicKey>,
    pub threshold: u16,
    pub proof_checkpoint_root: [u8; 32],
    pub authorized_program_ids: AuthorizedProgramIds,
}

impl CircuitCommit {
    /// Return the publisher set that is committed into this tx's next update connector.
    pub fn active_publisher_set(&self) -> (&[PublicKey], u16) {
        match (self.next_publisher_public_keys.as_deref(), self.next_threshold) {
            (Some(next_keys), Some(next_threshold)) => (next_keys, next_threshold),
            _ => (&self.publisher_public_keys, self.threshold),
        }
    }
}

pub const PROOF_SIZE: usize = 260;
pub const PUBLIC_INPUTS_SIZE: usize = 36;
pub const VK_HASH_SIZE: usize = 66;
pub const COMMIT_CHAIN_COMMITMENT_SIZE: usize = 32;
const COMMIT_CHAIN_COMMITMENT_DOMAIN: &[u8] = b"bitvm/commit-chain/v2";

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainCircuitOutput {
    pub chain_state: CommitChainState,
    pub self_program_id: verifier::ProgramId,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CommitChainCircuitInput {
    pub prev_proof: CommitChainPrevProofType,
    pub zkm_proof: Vec<u8>,
    pub zkm_public_values: Vec<u8>,
    pub zkm_vk_hash: Vec<u8>,
    pub zkm_version: String,
    pub self_program_id: verifier::ProgramId,
    pub commits: Vec<CircuitCommit>,
}

pub fn classify_commit_chain_output(
    public_values: &[u8],
) -> Result<CommitChainPrevProofType, String> {
    if deserialize_commit_chain_output(public_values).is_ok() {
        return Ok(CommitChainPrevProofType::PrevProof);
    }
    Err("unknown commit-chain public output format".to_string())
}

fn deserialize_commit_chain_output(
    public_values: &[u8],
) -> Result<CommitChainCircuitOutput, Box<bincode::ErrorKind>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(public_values)
}

pub fn sequencer_hash(sequencers: &[SequencerInfo]) -> Hash {
    let sequencer_set =
        ValidatorSet::without_proposer(sequencers.iter().cloned().map(|s| s.into()).collect());
    sequencer_set.hash()
}

/// Hashes the Publisher commitment, proof checkpoints, and authorized circuit identities.
pub fn commit_chain_commitment_digest(
    sequencer_set_hash: [u8; 32],
    genesis_evm_block_hash: [u8; 32],
    program_history_root: [u8; 32],
    proof_checkpoint_root: [u8; 32],
    authorized_program_ids: AuthorizedProgramIds,
) -> [u8; 32] {
    assert_ne!(program_history_root, [0u8; 32], "program history root must be non-zero");
    assert_ne!(proof_checkpoint_root, [0u8; 32], "proof checkpoint root must be non-zero");
    authorized_program_ids.validate().expect("invalid authorized ProgramIds");

    let mut hasher = Sha256::new();
    hasher.update(COMMIT_CHAIN_COMMITMENT_DOMAIN);
    hasher.update(sequencer_set_hash);
    hasher.update(genesis_evm_block_hash);
    hasher.update(program_history_root);
    hasher.update(proof_checkpoint_root);
    hasher.update(authorized_program_ids.header);
    hasher.update(authorized_program_ids.state);
    hasher.update(authorized_program_ids.commit);
    hasher.update(authorized_program_ids.watchtower);
    hasher.finalize().into()
}

pub fn extract_commit_chain_commitment(tx_output: &[TxOut]) -> Result<[u8; 32], String> {
    if tx_output.len() != 2 {
        return Err(format!("commit transaction must have 2 outputs, got {}", tx_output.len()));
    }
    let output = &tx_output[1];
    if output.value != bitcoin::Amount::ZERO {
        return Err("commitment output must have zero value".to_string());
    }
    let instructions = output
        .script_pubkey
        .instructions_minimal()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("invalid commitment script: {err}"))?;
    if instructions.len() != 2 {
        return Err("commitment script must be OP_RETURN followed by one push".to_string());
    }
    if !matches!(
        instructions[0],
        bitcoin::script::Instruction::Op(op) if op == bitcoin::opcodes::all::OP_RETURN
    ) {
        return Err("commitment output must start with OP_RETURN".to_string());
    }
    let bitcoin::script::Instruction::PushBytes(bytes) = &instructions[1] else {
        return Err("commitment must be pushed bytes".to_string());
    };
    bytes
        .as_bytes()
        .try_into()
        .map_err(|_| format!("commitment must be {COMMIT_CHAIN_COMMITMENT_SIZE} bytes"))
}

/// Decode current commit-chain public values.
pub fn decode_commit_chain_circuit_output(public_values: &[u8]) -> CommitChainCircuitOutput {
    deserialize_commit_chain_output(public_values)
        .expect("failed to decode current commit chain circuit output")
}

impl CommitChainState {
    pub fn new(genesis_txid: [u8; 32]) -> Self {
        CommitChainState {
            block_height: u32::MAX,
            commit_txn: Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            genesis_txid,
            sequencers: Vec::new(),
            publisher_public_keys: vec![],
            threshold: u16::MAX,
            proof_checkpoint_root: [0u8; 32],
            authorized_program_ids: AuthorizedProgramIds::default(),
        }
    }

    pub fn apply_commit(&mut self, commits: Vec<CircuitCommit>) {
        for commit in &commits {
            let mut latest_commit_txn_with_wtns = commit.commit_txn.clone();
            let latest_sequencers = &commit.sequencers;
            let (next_publisher_public_keys, next_threshold) = commit.active_publisher_set();
            let has_prev_commit = !self.commit_txn.output.is_empty();

            assert_eq!(commit.genesis_txid, self.genesis_txid);
            if !has_prev_commit {
                assert_eq!(
                    latest_commit_txn_with_wtns.compute_txid().as_raw_hash().to_byte_array(),
                    self.genesis_txid
                );
            }

            // calculate the commitment of latest sequencer set and check the equivalent
            let actual_commitment =
                extract_commit_chain_commitment(&latest_commit_txn_with_wtns.output).unwrap();
            if let Hash::Sha256(latest_sequencer_set_hash) = sequencer_hash(latest_sequencers) {
                let expected_commitment = commit_chain_commitment_digest(
                    latest_sequencer_set_hash,
                    commit.genesis_evm_block_hash,
                    commit.program_history_root,
                    commit.proof_checkpoint_root,
                    commit.authorized_program_ids,
                );
                assert_eq!(actual_commitment, expected_commitment);
            } else {
                panic!("Invalid latest sequencer set hash");
            }

            // check the latest txn's prev out is equals to the output of prev_txn
            let prev_commit_txn_value = &self.commit_txn;
            if has_prev_commit {
                // The recursive proof or an earlier batch item already authenticated the previous
                // commitment.
                let update_connector = &latest_commit_txn_with_wtns.input[0];
                let prev_commit_txid = prev_commit_txn_value.compute_txid();
                assert_eq!(update_connector.previous_output.txid, prev_commit_txid);
                assert_eq!(update_connector.previous_output.vout, 0);
                // Verify that the spending witness matches the publisher set committed by the
                // previous update connector.
                let prevout = &prev_commit_txn_value.output[0];
                let redeem_script = crate::create_sequencer_update_script(
                    &self.publisher_public_keys[..],
                    self.threshold as usize,
                );
                let publisher_witness_valid = crate::publisher::verify_p2wsh_multisig_witness(
                    &latest_commit_txn_with_wtns,
                    0,
                    prevout,
                    &redeem_script,
                    &self.publisher_public_keys,
                    self.threshold as usize,
                )
                .expect("Failed to verify Publisher multisig witness");
                assert!(
                    publisher_witness_valid,
                    "Publisher multisig witness does not meet threshold"
                );
            }

            let expected_next_connector_script = crate::create_sequencer_update_script(
                next_publisher_public_keys,
                next_threshold as usize,
            );
            let expected_next_connector_script_pubkey =
                bitcoin::ScriptBuf::new_p2wsh(&expected_next_connector_script.wscript_hash());
            assert_eq!(
                latest_commit_txn_with_wtns.output[0].script_pubkey,
                expected_next_connector_script_pubkey
            );

            // remove witness
            latest_commit_txn_with_wtns.input.iter_mut().for_each(|input| {
                input.witness = Witness::new();
            });

            self.sequencers = latest_sequencers.clone();
            self.commit_txn = latest_commit_txn_with_wtns.clone();
            self.publisher_public_keys = next_publisher_public_keys.to_vec();
            self.threshold = next_threshold;
            self.block_height = commit.block_height;
            self.proof_checkpoint_root = commit.proof_checkpoint_root;
            self.authorized_program_ids = commit.authorized_program_ids;
        }
    }
}

/// Reassembles pushed commitment chunks through the terminating OP_RETURN output.
pub fn extract_data_from_commitment_outputs(txouts: &[TxOut]) -> Result<Vec<u8>, String> {
    let mut data = vec![];
    for txout in txouts {
        let script = &txout.script_pubkey;
        let instructions = script
            .instructions_minimal()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("invalid challenge commitment script: {err}"))?;
        let Some(bitcoin::blockdata::script::Instruction::PushBytes(bytes)) = instructions.get(1)
        else {
            return Err("challenge commitment output must contain pushed bytes".to_string());
        };
        data.extend_from_slice(bytes.as_bytes());
        if matches!(
            instructions.first(),
            Some(bitcoin::script::Instruction::Op(op))
                if *op == bitcoin::opcodes::all::OP_RETURN
        ) {
            return Ok(data);
        }
    }
    Err("challenge commitment is missing OP_RETURN terminator".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_dummy_publisher_keys, create_sequencer_update_script, finalize, sign_partial,
    };
    use bitcoin::{Amount, ScriptBuf, script::PushBytesBuf};
    use bitcoin::{
        EcdsaSighashType, OutPoint, Sequence, TxIn, Witness, absolute::LockTime,
        transaction::Version,
    };
    #[test]
    fn test_extract_op_return() {
        let expected_op_data = [12; 32];
        let script =
            ScriptBuf::new_op_return(PushBytesBuf::try_from(expected_op_data.to_vec()).unwrap());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut { value: Amount::from_sat(500), script_pubkey: ScriptBuf::new() },
                bitcoin::TxOut { value: Amount::ZERO, script_pubkey: script },
            ],
        };

        assert_eq!(expected_op_data, extract_commit_chain_commitment(&tx.output).unwrap());
    }

    fn commitment_payload(
        sequencers: &[SequencerInfo],
        genesis_evm_block_hash: [u8; 32],
        program_history_root: [u8; 32],
        proof_checkpoint_root: [u8; 32],
        authorized_program_ids: AuthorizedProgramIds,
    ) -> PushBytesBuf {
        let Hash::Sha256(sequencer_set_hash) = sequencer_hash(sequencers) else {
            panic!("expected sha256 sequencer hash");
        };
        PushBytesBuf::try_from(
            commit_chain_commitment_digest(
                sequencer_set_hash,
                genesis_evm_block_hash,
                program_history_root,
                proof_checkpoint_root,
                authorized_program_ids,
            )
            .to_vec(),
        )
        .expect("commitment payload is pushable")
    }

    fn authorized_program_ids() -> AuthorizedProgramIds {
        AuthorizedProgramIds {
            header: [1; 32],
            state: [2; 32],
            commit: [3; 32],
            watchtower: [4; 32],
        }
    }

    #[test]
    fn test_commit_chain_commitment_digest_known_vector() {
        assert_eq!(
            hex::encode(commit_chain_commitment_digest(
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0x44; 32],
                authorized_program_ids(),
            )),
            "ca5b93b9c16288dd057cfb6c6123d14d2c7a608971724239dc0714c2f5774e36"
        );
    }

    #[test]
    fn commitment_binds_checkpoints_and_all_program_ids() {
        let ids = authorized_program_ids();
        let digest = commit_chain_commitment_digest([6; 32], [7; 32], [8; 32], [9; 32], ids);

        assert_ne!(
            digest,
            commit_chain_commitment_digest([6; 32], [7; 32], [8; 32], [10; 32], ids)
        );
        assert_ne!(
            digest,
            commit_chain_commitment_digest(
                [6; 32],
                [7; 32],
                [8; 32],
                [9; 32],
                AuthorizedProgramIds { watchtower: [11; 32], ..ids },
            )
        );
    }

    #[test]
    fn test_extract_commit_chain_commitment_requires_canonical_push32() {
        let digest = [0x11; 32];
        let valid = vec![
            TxOut { value: Amount::from_sat(500), script_pubkey: ScriptBuf::new() },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(
                    PushBytesBuf::try_from(digest.to_vec()).unwrap(),
                ),
            },
        ];
        assert_eq!(extract_commit_chain_commitment(&valid).unwrap(), digest);

        for size in [31, 33, 64, 96, 128] {
            let mut outputs = valid.clone();
            outputs[1].script_pubkey =
                ScriptBuf::new_op_return(PushBytesBuf::try_from(vec![0x11; size]).unwrap());
            assert!(extract_commit_chain_commitment(&outputs).is_err(), "{size} bytes");
        }
        assert!(extract_commit_chain_commitment(&valid[..1]).is_err());
        let mut extra = valid.clone();
        extra.push(valid[1].clone());
        assert!(extract_commit_chain_commitment(&extra).is_err());
    }

    #[test]
    #[should_panic(expected = "program history root must be non-zero")]
    fn test_commit_chain_commitment_digest_rejects_zero_program_history_root() {
        commit_chain_commitment_digest(
            [0x11; 32],
            [0x22; 32],
            [0; 32],
            [0x44; 32],
            authorized_program_ids(),
        );
    }

    #[test]
    fn test_commit_info_requires_commitment_preimage_fields() {
        let legacy = serde_json::json!({
            "threshold": 2,
            "publisher_public_keys": [],
            "txid": "00",
            "genesis_txid": "00",
            "sequencers": []
        });
        assert!(serde_json::from_value::<CommitInfo>(legacy).is_err());
    }

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    struct OldCommitChainState {
        block_height: u32,
        commit_txn: Transaction,
        genesis_txid: [u8; 32],
        sequencers: Vec<SequencerInfo>,
        publisher_public_keys: Vec<PublicKey>,
        threshold: u16,
        operator_vk_hash: [u8; 32],
    }

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    struct OldCommitChainCircuitOutput {
        chain_state: OldCommitChainState,
        self_program_id: verifier::ProgramId,
        program_history_hash: [u8; 32],
    }

    #[test]
    fn test_classify_commit_chain_output_rejects_old_operator_vk_hash_schema() {
        let old_output = OldCommitChainCircuitOutput {
            chain_state: OldCommitChainState {
                block_height: 7,
                commit_txn: Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                genesis_txid: [0x22u8; 32],
                sequencers: vec![],
                publisher_public_keys: vec![],
                threshold: 0,
                operator_vk_hash: [0x33; 32],
            },
            self_program_id: [0x44; 32],
            program_history_hash: [0x55; 32],
        };
        let public_values = bincode::serialize(&old_output).unwrap();

        assert!(classify_commit_chain_output(&public_values).is_err());
        assert!(
            std::panic::catch_unwind(|| decode_commit_chain_circuit_output(&public_values))
                .is_err()
        );
    }

    // todo: use new commit file
    #[test]
    fn test_apply_commit() {
        // let commit_info: Vec<CircuitCommit> = serde_json::from_slice(include_bytes!(
        //     "../../../data/commit-chain/0-1.bin.commits"
        // ))
        // .unwrap();
        //
        // let mut chain_state = CommitChainState::new(commit_info[0].genesis_txid);
        // chain_state.apply_commit(commit_info.clone());
        // assert_eq!(commit_info[0].genesis_txid, chain_state.genesis_txid);
        // assert_eq!(commit_info[0].sequencers.clone(), chain_state.sequencers.clone());
        // assert_eq!(commit_info[0].commit_txn.compute_txid(), chain_state.commit_txn.compute_txid());
        //
        // let commit_info2: Vec<CircuitCommit> = serde_json::from_slice(include_bytes!(
        //     "../../../data/commit-chain/1-1.bin.commits"
        // ))
        // .unwrap();
        // chain_state.apply_commit(commit_info2.clone());
        // assert_eq!(commit_info[0].genesis_txid, chain_state.genesis_txid);
        // assert_eq!(commit_info2[0].sequencers.clone(), chain_state.sequencers.clone());
        // assert_eq!(
        //     commit_info2[0].commit_txn.compute_txid(),
        //     chain_state.commit_txn.compute_txid()
        // );
    }

    #[test]
    fn test_apply_commit_tracks_next_publisher_set_as_active_state() {
        let current_keys = create_dummy_publisher_keys(3, bitcoin::Network::Regtest);
        let current_pubkeys: Vec<PublicKey> = current_keys.iter().map(|(_, pk)| *pk).collect();
        let next_keys = create_dummy_publisher_keys(4, bitcoin::Network::Regtest);
        let next_pubkeys: Vec<PublicKey> = next_keys.iter().map(|(_, pk)| *pk).collect();
        let final_keys = create_dummy_publisher_keys(5, bitcoin::Network::Regtest);
        let final_pubkeys: Vec<PublicKey> = final_keys.iter().map(|(_, pk)| *pk).collect();

        let current_threshold = 2u16;
        let next_threshold = 3u16;
        let final_threshold = 4u16;
        let empty_sequencers = vec![];
        let genesis_evm_block_hash = [0x11u8; 32];
        let program_history_root = [0x22u8; 32];
        let proof_checkpoint_root = [0x55u8; 32];
        let authorized_program_ids = authorized_program_ids();
        let commit0_op_return = ScriptBuf::new_op_return(commitment_payload(
            &empty_sequencers,
            genesis_evm_block_hash,
            program_history_root,
            proof_checkpoint_root,
            authorized_program_ids,
        ));
        let commit0 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new_p2wsh(
                        &create_sequencer_update_script(
                            &current_pubkeys,
                            current_threshold as usize,
                        )
                        .wscript_hash(),
                    ),
                },
                TxOut { value: Amount::ZERO, script_pubkey: commit0_op_return },
            ],
        };
        let mut genesis_txid = [0u8; 32];
        genesis_txid.copy_from_slice(commit0.compute_txid().as_raw_hash().as_ref());

        let commit0_info = CircuitCommit {
            commit_txn: commit0.clone(),
            genesis_txid,
            publisher_public_keys: vec![],
            threshold: 0,
            next_publisher_public_keys: Some(current_pubkeys.clone()),
            next_threshold: Some(current_threshold),
            sequencers: empty_sequencers.clone(),
            genesis_evm_block_hash,
            program_history_root,
            block_height: 1,
            proof_checkpoint_root,
            authorized_program_ids,
        };

        let commit1_redeem_script =
            create_sequencer_update_script(&current_pubkeys, current_threshold as usize);
        let commit1_program_history_root = [0x33u8; 32];
        let commit1_op_return = ScriptBuf::new_op_return(commitment_payload(
            &empty_sequencers,
            genesis_evm_block_hash,
            commit1_program_history_root,
            proof_checkpoint_root,
            authorized_program_ids,
        ));
        let mut commit1 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(commit0.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: ScriptBuf::new_p2wsh(
                        &create_sequencer_update_script(&next_pubkeys, next_threshold as usize)
                            .wscript_hash(),
                    ),
                },
                TxOut { value: Amount::ZERO, script_pubkey: commit1_op_return },
            ],
        };
        let (sig1, _) = sign_partial(
            &mut commit1,
            &current_keys[0].0,
            &commit1_redeem_script,
            Amount::from_sat(100_000),
            EcdsaSighashType::All,
        )
        .unwrap();
        let (sig2, _) = sign_partial(
            &mut commit1,
            &current_keys[1].0,
            &commit1_redeem_script,
            Amount::from_sat(100_000),
            EcdsaSighashType::All,
        )
        .unwrap();
        finalize(&mut commit1, vec![sig1, sig2], &commit1_redeem_script).unwrap();
        let commit1_info = CircuitCommit {
            commit_txn: commit1.clone(),
            genesis_txid,
            publisher_public_keys: current_pubkeys.clone(),
            threshold: current_threshold,
            next_publisher_public_keys: Some(next_pubkeys.clone()),
            next_threshold: Some(next_threshold),
            sequencers: empty_sequencers.clone(),
            genesis_evm_block_hash,
            program_history_root: commit1_program_history_root,
            block_height: 2,
            proof_checkpoint_root,
            authorized_program_ids,
        };

        let commit2_redeem_script =
            create_sequencer_update_script(&next_pubkeys, next_threshold as usize);
        let commit2_program_history_root = [0x44u8; 32];
        let commit2_op_return = ScriptBuf::new_op_return(commitment_payload(
            &empty_sequencers,
            genesis_evm_block_hash,
            commit2_program_history_root,
            proof_checkpoint_root,
            authorized_program_ids,
        ));
        let mut commit2 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(commit1.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(80_000),
                    script_pubkey: ScriptBuf::new_p2wsh(
                        &create_sequencer_update_script(&final_pubkeys, final_threshold as usize)
                            .wscript_hash(),
                    ),
                },
                TxOut { value: Amount::ZERO, script_pubkey: commit2_op_return },
            ],
        };
        let (sig3, _) = sign_partial(
            &mut commit2,
            &next_keys[0].0,
            &commit2_redeem_script,
            Amount::from_sat(90_000),
            EcdsaSighashType::All,
        )
        .unwrap();
        let (sig4, _) = sign_partial(
            &mut commit2,
            &next_keys[1].0,
            &commit2_redeem_script,
            Amount::from_sat(90_000),
            EcdsaSighashType::All,
        )
        .unwrap();
        let (sig5, _) = sign_partial(
            &mut commit2,
            &next_keys[2].0,
            &commit2_redeem_script,
            Amount::from_sat(90_000),
            EcdsaSighashType::All,
        )
        .unwrap();
        finalize(&mut commit2, vec![sig3, sig4, sig5], &commit2_redeem_script).unwrap();
        let commit2_info = CircuitCommit {
            commit_txn: commit2.clone(),
            genesis_txid,
            publisher_public_keys: next_pubkeys.clone(),
            threshold: next_threshold,
            next_publisher_public_keys: Some(final_pubkeys.clone()),
            next_threshold: Some(final_threshold),
            sequencers: empty_sequencers,
            genesis_evm_block_hash,
            program_history_root: commit2_program_history_root,
            block_height: 3,
            proof_checkpoint_root,
            authorized_program_ids,
        };

        let mut chain_state = CommitChainState::new(genesis_txid);
        chain_state.apply_commit(vec![commit0_info]);
        assert_eq!(chain_state.publisher_public_keys, current_pubkeys);
        assert_eq!(chain_state.threshold, current_threshold);

        chain_state.apply_commit(vec![commit1_info, commit2_info]);
        assert_eq!(chain_state.publisher_public_keys, final_pubkeys);
        assert_eq!(chain_state.threshold, final_threshold);
        assert_eq!(chain_state.block_height, 3);
    }

    #[test]
    fn test_apply_commit_enforces_new_genesis() {
        let next_keys = create_dummy_publisher_keys(3, bitcoin::Network::Regtest);
        let next_pubkeys: Vec<PublicKey> = next_keys.iter().map(|(_, pk)| *pk).collect();
        let empty_sequencers = vec![];
        let genesis_evm_block_hash = [0x55u8; 32];
        let program_history_root = [0x66u8; 32];
        let proof_checkpoint_root = [0x77u8; 32];
        let authorized_program_ids = authorized_program_ids();
        let commit_txn = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new_p2wsh(
                        &create_sequencer_update_script(&next_pubkeys, 2).wscript_hash(),
                    ),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(commitment_payload(
                        &empty_sequencers,
                        genesis_evm_block_hash,
                        program_history_root,
                        proof_checkpoint_root,
                        authorized_program_ids,
                    )),
                },
            ],
        };
        let genesis_txid = *commit_txn.compute_txid().as_byte_array();
        let commit = CircuitCommit {
            commit_txn,
            genesis_txid,
            publisher_public_keys: vec![],
            threshold: 0,
            next_publisher_public_keys: Some(next_pubkeys),
            next_threshold: Some(2),
            sequencers: empty_sequencers,
            genesis_evm_block_hash,
            program_history_root,
            block_height: 1,
            proof_checkpoint_root,
            authorized_program_ids,
        };

        let old_chain_commit = CircuitCommit { genesis_txid: [0x77; 32], ..commit.clone() };
        let result = std::panic::catch_unwind(|| {
            CommitChainState::new(genesis_txid).apply_commit(vec![old_chain_commit]);
        });
        assert!(result.is_err());

        let mismatched_preimage =
            CircuitCommit { program_history_root: [0x77; 32], ..commit.clone() };
        let result = std::panic::catch_unwind(|| {
            CommitChainState::new(genesis_txid).apply_commit(vec![mismatched_preimage]);
        });
        assert!(result.is_err());

        let mut chain_state = CommitChainState::new(genesis_txid);
        chain_state.apply_commit(vec![commit]);

        assert_eq!(chain_state.block_height, 1);
    }
}
