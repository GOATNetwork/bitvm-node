use crate::committee::{
    CommitteeNonceSignatures, CommitteePubNonces, CommitteeSecNonces,
    committee_presign_sighash_digest, generate_nonce, generate_nonce_from_seed,
    pegin_confirm_sighash,
};
use crate::operator::{generate_assert_wots_key, generate_commit_pubin_wots_key};
use crate::types::{BitvmGcGraph, BitvmGcInstanceParameters};
use anyhow::{Context, bail};
use bitcoin::{
    Network, PublicKey,
    bip32::{ChildNumber, DerivationPath, Xpriv},
    key::Keypair,
    secp256k1::{SECP256K1, SecretKey},
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use goat::assert_scripts::{
    OperatorAssertPublicKey, OperatorAssertSecretKey, OperatorCommitPubinPublicKey,
    OperatorCommitPubinSecretKey,
};
use hex::{decode as hex_decode, encode as hex_encode};
use hkdf::Hkdf;
use musig2::{PubNonce, SecNonce};
use rand::{RngCore, rngs::OsRng};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io::Write, path::Path};
use uuid::Uuid;

pub type OperatorAssertWotsSecretKey = OperatorAssertSecretKey;
pub type OperatorAssertWotsPublicKey = OperatorAssertPublicKey;
pub type OperatorAssertWotsKeypair = (OperatorAssertWotsSecretKey, OperatorAssertWotsPublicKey);
pub type OperatorCommitPubinWotsSecretKey = OperatorCommitPubinSecretKey;
pub type OperatorCommitPubinWotsPublicKey = OperatorCommitPubinPublicKey;
pub type OperatorCommitPubinWotsKeypair =
    (OperatorCommitPubinWotsSecretKey, OperatorCommitPubinWotsPublicKey);

const HKDF_SALT: &[u8] = b"bitvm-gc/keys/v1";
const BITVM_BIP32_ROOT_DOMAIN: &[u8] = b"bitvm_bip32_root";
const PURPOSE_BITVM_GC_DERIVATION: u32 = 2345;

const ROLE_COMMITTEE: u32 = 0;
const ROLE_OPERATOR: u32 = 1;
// const ROLE_VERIFIER: u32 = 2;

const KEY_KIND_COMMITTEE_ENVELOPE: u32 = 0;
const KEY_KIND_OPERATOR_NONCE: u32 = 1;

const COMMITTEE_ENVELOPE_VERSION: u8 = 1;

pub fn hkdf_derive_bytes(
    seed_material: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), seed_material);
    let mut out = vec![0u8; out_len];
    hkdf.expand(info, &mut out).expect("hkdf expand with valid output length should not fail");
    out
}

fn hkdf_expand(master_key: &Keypair, salt: &[u8], domain: &[u8], out_len: usize) -> Vec<u8> {
    let secret_key = master_key.secret_key();
    hkdf_derive_bytes(&secret_key.secret_bytes(), salt, domain, out_len)
}

fn derive_secret(master_key: &Keypair, domain: &[u8]) -> String {
    hex_encode(hkdf_expand(master_key, HKDF_SALT, domain, 32))
}

fn derive_bip32_root(master_key: &Keypair) -> Xpriv {
    let seed = hkdf_expand(master_key, HKDF_SALT, BITVM_BIP32_ROOT_DOMAIN, 64);
    let network = std::env::var("BITCOIN_NETWORK").unwrap_or("testnet4".to_string());
    let network = match network.as_str() {
        "bitcoin" => Network::Bitcoin,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => {
            tracing::warn!(
                "Unknown BTC network: {network}, expect bitcoin, testnet4, signet or regtest, return testnet by default"
            );
            Network::Testnet4
        }
    };
    Xpriv::new_master(network, &seed)
        .expect("32-byte secp256k1 key with valid seed should derive xpriv")
}

// Path layout: m / purpose' / role' / key_kind' / nonce_hi16' / ... / nonce_lo16'
fn operator_nonce_derivation_path(nonce: u64) -> DerivationPath {
    // Split u64 nonce into four 16-bit segments
    let segments = [
        ((nonce >> 48) & 0xffff) as u32,
        ((nonce >> 32) & 0xffff) as u32,
        ((nonce >> 16) & 0xffff) as u32,
        (nonce & 0xffff) as u32,
    ];

    let mut path = vec![
        ChildNumber::from_hardened_idx(PURPOSE_BITVM_GC_DERIVATION)
            .expect("constant index is valid"),
        ChildNumber::from_hardened_idx(ROLE_OPERATOR).expect("constant index is valid"),
        ChildNumber::from_hardened_idx(KEY_KIND_OPERATOR_NONCE).expect("constant index is valid"),
    ];
    path.extend(
        segments
            .into_iter()
            .map(|seg| ChildNumber::from_hardened_idx(seg).expect("16-bit index is always valid")),
    );
    DerivationPath::from(path)
}

// Path layout: m / purpose' / role_committee' / key_kind' / iid_0' / ... / iid_7'
fn committee_kek_derivation_path(instance_id: Uuid) -> DerivationPath {
    let instance = instance_id.as_u128();
    let segments = [
        ((instance >> 112) & 0xffff) as u32,
        ((instance >> 96) & 0xffff) as u32,
        ((instance >> 80) & 0xffff) as u32,
        ((instance >> 64) & 0xffff) as u32,
        ((instance >> 48) & 0xffff) as u32,
        ((instance >> 32) & 0xffff) as u32,
        ((instance >> 16) & 0xffff) as u32,
        (instance & 0xffff) as u32,
    ];

    let mut path = vec![
        ChildNumber::from_hardened_idx(PURPOSE_BITVM_GC_DERIVATION)
            .expect("constant index is valid"),
        ChildNumber::from_hardened_idx(ROLE_COMMITTEE).expect("constant index is valid"),
        ChildNumber::from_hardened_idx(KEY_KIND_COMMITTEE_ENVELOPE)
            .expect("constant index is valid"),
    ];
    path.extend(
        segments
            .into_iter()
            .map(|seg| ChildNumber::from_hardened_idx(seg).expect("16-bit index is always valid")),
    );
    DerivationPath::from(path)
}

fn derive_committee_instance_kek(master_key: &Keypair, instance_id: Uuid) -> ([u8; 32], String) {
    let root = derive_bip32_root(master_key);
    let path = committee_kek_derivation_path(instance_id);
    let child =
        root.derive_priv(SECP256K1, &path).expect("valid derivation path should derive child key");
    (child.private_key.secret_bytes(), path.to_string())
}

fn current_unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs() as i64
}

fn envelope_aad(instance_id: Uuid, committee_pubkey: &PublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 33);
    aad.extend_from_slice(instance_id.as_bytes());
    aad.extend_from_slice(&committee_pubkey.to_bytes());
    aad
}

pub struct NodeMasterKey(Keypair);
impl NodeMasterKey {
    pub fn new(inner: Keypair) -> Self {
        NodeMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeInstanceKeyEnvelope {
    pub version: u8,
    pub instance_id: Uuid,
    pub committee_pubkey_hex: String,
    pub kek_path: String,
    pub aead_nonce_hex: String,
    pub ciphertext_hex: String,
    pub created_at: i64,
}

pub struct CommitteeMasterKey(Keypair);

struct CommitteeGraphNonceContext {
    instance_id: Uuid,
    graph_id: Uuid,
    graph_parameters_hash: [u8; 32],
    presign_sighash_digest: [u8; 32],
    watchtower_num: usize,
    verifier_num: usize,
}

struct CommitteeInstanceNonceContext {
    instance_id: Uuid,
    instance_parameters_hash: [u8; 32],
    pegin_confirm_sighash: [u8; 32],
}

impl CommitteeMasterKey {
    pub fn new(inner: Keypair) -> Self {
        CommitteeMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }

    pub fn create_instance_keypair_envelope(
        &self,
        instance_id: Uuid,
        envelope_path: &Path,
    ) -> anyhow::Result<bitcoin::PublicKey> {
        let secret_key = SecretKey::new(&mut OsRng);
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let committee_pubkey: PublicKey = keypair.public_key().into();

        let (kek, kek_path) = derive_committee_instance_kek(&self.0, instance_id);
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .expect("32-byte kek should always create chacha20poly1305 key");
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let aad = envelope_aad(instance_id, &committee_pubkey);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &secret_key.secret_bytes(), aad: &aad },
            )
            .map_err(|e| anyhow::anyhow!("encrypt committee instance key failed: {e}"))?;

        let envelope = CommitteeInstanceKeyEnvelope {
            version: COMMITTEE_ENVELOPE_VERSION,
            instance_id,
            committee_pubkey_hex: committee_pubkey.to_string(),
            kek_path,
            aead_nonce_hex: hex_encode(nonce),
            ciphertext_hex: hex_encode(ciphertext),
            created_at: current_unix_time_secs(),
        };

        let serialized = serde_json::to_vec_pretty(&envelope)
            .context("serialize committee instance key envelope")?;
        if let Some(parent) = envelope_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create envelope directory failed: {}", parent.display())
            })?;
        }
        let mut file = fs::File::create(envelope_path)
            .with_context(|| format!("create envelope file failed: {}", envelope_path.display()))?;
        file.write_all(&serialized)
            .with_context(|| format!("write envelope failed: {}", envelope_path.display()))?;
        fs::set_permissions(envelope_path, fs::Permissions::from_mode(0o600)).with_context(
            || format!("set envelope permissions failed: {}", envelope_path.display()),
        )?;
        Ok(committee_pubkey)
    }

    pub fn load_instance_keypair(
        &self,
        instance_id: Uuid,
        envelope_path: &Path,
    ) -> anyhow::Result<Keypair> {
        let serialized = fs::read(envelope_path)
            .with_context(|| format!("read envelope failed: {}", envelope_path.display()))?;
        let envelope: CommitteeInstanceKeyEnvelope =
            serde_json::from_slice(&serialized).context("parse envelope json failed")?;
        if envelope.version != COMMITTEE_ENVELOPE_VERSION {
            bail!(
                "unsupported envelope version: {}, expected {}",
                envelope.version,
                COMMITTEE_ENVELOPE_VERSION
            );
        }
        if envelope.instance_id != instance_id {
            bail!(
                "envelope instance_id mismatch: expected {}, got {}",
                instance_id,
                envelope.instance_id
            );
        }

        let committee_pubkey = envelope
            .committee_pubkey_hex
            .parse::<PublicKey>()
            .context("invalid envelope committee_pubkey_hex")?;
        let nonce_bytes =
            hex_decode(&envelope.aead_nonce_hex).context("invalid envelope nonce hex")?;
        if nonce_bytes.len() != 12 {
            bail!("invalid envelope nonce length: {}", nonce_bytes.len());
        }
        let ciphertext =
            hex_decode(&envelope.ciphertext_hex).context("invalid envelope ciphertext hex")?;

        let (kek, expected_kek_path) = derive_committee_instance_kek(&self.0, instance_id);
        if envelope.kek_path != expected_kek_path {
            bail!(
                "envelope kek_path mismatch: expected {}, got {}",
                expected_kek_path,
                envelope.kek_path
            );
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .expect("32-byte kek should always create chacha20poly1305 key");
        let aad = envelope_aad(instance_id, &committee_pubkey);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &ciphertext, aad: &aad })
            .map_err(|e| anyhow::anyhow!("decrypt committee instance key failed: {e}"))?;

        if plaintext.len() != 32 {
            bail!("invalid plaintext secret key length: {}", plaintext.len());
        }
        let secret_key =
            SecretKey::from_slice(&plaintext).context("invalid decrypted committee secret key")?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let loaded_pubkey: PublicKey = keypair.public_key().into();
        if loaded_pubkey != committee_pubkey {
            bail!(
                "envelope committee pubkey mismatch: expected {committee_pubkey}, got {loaded_pubkey}"
            );
        }
        Ok(keypair)
    }

    pub fn delete_instance_keypair_envelope(
        &self,
        instance_id: Uuid,
        envelope_path: &Path,
    ) -> anyhow::Result<()> {
        if !envelope_path.exists() {
            return Ok(());
        }

        // Refuse deletion if caller instance id does not match envelope content.
        let serialized = fs::read(envelope_path)
            .with_context(|| format!("read envelope failed: {}", envelope_path.display()))?;
        let envelope: CommitteeInstanceKeyEnvelope =
            serde_json::from_slice(&serialized).context("parse envelope json failed")?;
        if envelope.instance_id != instance_id {
            bail!(
                "envelope instance_id mismatch: expected {}, got {}",
                instance_id,
                envelope.instance_id
            );
        }

        fs::remove_file(envelope_path)
            .with_context(|| format!("remove envelope failed: {}", envelope_path.display()))?;
        Ok(())
    }

    pub fn nonces_for_graph_job_with_keypair(
        &self,
        graph: &BitvmGcGraph,
        signer_keypair: Keypair,
    ) -> anyhow::Result<(CommitteePubNonces, CommitteeSecNonces, CommitteeNonceSignatures)> {
        let context = CommitteeGraphNonceContext {
            instance_id: graph.parameters.instance_parameters.instance_id,
            graph_id: graph.parameters.graph_id,
            graph_parameters_hash: graph.parameters.parameters_hash()?,
            presign_sighash_digest: committee_presign_sighash_digest(graph)?,
            watchtower_num: graph.parameters.watchtower_pubkeys.len(),
            verifier_num: graph.parameters.gc_data.len(),
        };
        Ok(self.nonces_for_graph_context_with_keypair(context, signer_keypair))
    }

    fn nonces_for_graph_context_with_keypair(
        &self,
        context: CommitteeGraphNonceContext,
        signer_keypair: Keypair,
    ) -> (CommitteePubNonces, CommitteeSecNonces, CommitteeNonceSignatures) {
        let domain = [
            b"committee_bitvm_graph_nonces_v3".to_vec(),
            context.instance_id.as_bytes().to_vec(),
            context.graph_id.as_bytes().to_vec(),
            context.graph_parameters_hash.to_vec(),
            context.presign_sighash_digest.to_vec(),
        ]
        .concat();
        let nonce_seed = derive_secret(&signer_keypair, &domain);
        generate_nonce_from_seed(
            nonce_seed,
            context.graph_id.as_u128() as usize,
            signer_keypair,
            context.watchtower_num,
            context.verifier_num,
        )
    }

    pub fn nonce_for_instance_job_with_keypair(
        &self,
        instance_parameters: &BitvmGcInstanceParameters,
        signer_keypair: Keypair,
    ) -> anyhow::Result<(SecNonce, PubNonce, SchnorrSignature)> {
        let context = CommitteeInstanceNonceContext {
            instance_id: instance_parameters.instance_id,
            instance_parameters_hash: instance_parameters.parameters_hash()?,
            pegin_confirm_sighash: pegin_confirm_sighash(instance_parameters)?,
        };
        Ok(self.nonce_for_instance_context_with_keypair(context, signer_keypair))
    }

    fn nonce_for_instance_context_with_keypair(
        &self,
        context: CommitteeInstanceNonceContext,
        signer_keypair: Keypair,
    ) -> (SecNonce, PubNonce, SchnorrSignature) {
        let domain = [
            b"committee_bitvm_instance_nonce_v3".to_vec(),
            context.instance_id.as_bytes().to_vec(),
            context.instance_parameters_hash.to_vec(),
            context.pegin_confirm_sighash.to_vec(),
        ]
        .concat();
        let nonce_seed = derive_secret(&signer_keypair, &domain);
        generate_nonce(signer_keypair, nonce_seed.as_bytes(), 0)
    }
}

pub struct OperatorMasterKey(Keypair);
impl OperatorMasterKey {
    pub fn new(inner: Keypair) -> Self {
        OperatorMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
    pub fn keypair_for_nonce(&self, nonce: u64) -> Keypair {
        let root = derive_bip32_root(&self.0);
        let path = operator_nonce_derivation_path(nonce);
        let child = root
            .derive_priv(SECP256K1, &path)
            .expect("valid derivation path should derive child key");
        Keypair::from_secret_key(SECP256K1, &child.private_key)
    }
    pub fn assert_wots_keypair_for_graph(&self, graph_id: Uuid) -> OperatorAssertWotsKeypair {
        let domain = [b"operator_bitvm_wots_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
        let key_seed = derive_secret(&self.0, &domain);
        generate_assert_wots_key(&key_seed)
    }
    pub fn commit_pubin_wots_keypair_for_graph(
        &self,
        graph_id: Uuid,
    ) -> OperatorCommitPubinWotsKeypair {
        let domain =
            [b"operator_bitvm_pubin_wots_key".to_vec(), graph_id.as_bytes().to_vec()].concat();
        let key_seed = derive_secret(&self.0, &domain);
        generate_commit_pubin_wots_key(&key_seed)
    }
    pub fn preimage_for_graph(&self, graph_id: Uuid, index: usize) -> Vec<u8> {
        let domain = [
            b"operator_bitvm_preimage".to_vec(),
            graph_id.as_bytes().to_vec(),
            index.to_be_bytes().to_vec(),
        ]
        .concat();
        hkdf_expand(&self.0, HKDF_SALT, &domain, 32)
    }
}

pub struct VerifierMasterKey(Keypair);
impl VerifierMasterKey {
    pub fn new(inner: Keypair) -> Self {
        VerifierMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
}

pub struct WatchtowerMasterKey(Keypair);
impl WatchtowerMasterKey {
    pub fn new(inner: Keypair) -> Self {
        WatchtowerMasterKey(inner)
    }
    pub fn master_keypair(&self) -> Keypair {
        NodeMasterKey(self.0).master_keypair()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::path::PathBuf;

    fn test_master_keypair(seed: &str) -> Keypair {
        let hashed = Sha256::digest(seed.as_bytes());
        let sk = SecretKey::from_slice(&hashed).expect("seeded hash should build secret key");
        Keypair::from_secret_key(SECP256K1, &sk)
    }

    fn test_envelope_path(instance_id: Uuid) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitvm-gc-committee-key-{instance_id}.json"));
        path
    }

    #[test]
    fn committee_instance_key_envelope_create_load_delete() {
        let instance_id = Uuid::new_v4();
        let master = CommitteeMasterKey::new(test_master_keypair("seed:test-committee-master"));
        let envelope_path = test_envelope_path(instance_id);

        if envelope_path.exists() {
            fs::remove_file(&envelope_path).expect("cleanup stale envelope");
        }

        let created_pubkey = master
            .create_instance_keypair_envelope(instance_id, &envelope_path)
            .expect("create envelope should succeed");
        assert!(envelope_path.exists(), "envelope file should exist after create");

        let loaded = master
            .load_instance_keypair(instance_id, &envelope_path)
            .expect("load envelope should succeed");
        let loaded_pubkey: PublicKey = loaded.public_key().into();
        assert_eq!(created_pubkey, loaded_pubkey, "loaded keypair must match created pubkey");

        master
            .delete_instance_keypair_envelope(instance_id, &envelope_path)
            .expect("delete envelope should succeed");
        assert!(!envelope_path.exists(), "envelope file should be removed");
    }

    #[test]
    fn committee_instance_key_envelope_load_mismatch_instance_id_should_fail() {
        let instance_id = Uuid::new_v4();
        let wrong_instance_id = Uuid::new_v4();
        let master = CommitteeMasterKey::new(test_master_keypair("seed:test-committee-master"));
        let envelope_path = test_envelope_path(instance_id);

        if envelope_path.exists() {
            fs::remove_file(&envelope_path).expect("cleanup stale envelope");
        }

        master
            .create_instance_keypair_envelope(instance_id, &envelope_path)
            .expect("create envelope should succeed");

        let err = master
            .load_instance_keypair(wrong_instance_id, &envelope_path)
            .expect_err("load with mismatched instance_id should fail");
        assert!(
            err.to_string().contains("instance_id mismatch"),
            "error should include mismatch hint"
        );

        fs::remove_file(&envelope_path).expect("cleanup envelope after test");
    }

    #[test]
    fn committee_instance_key_envelope_delete_mismatch_instance_id_should_fail() {
        let instance_id = Uuid::new_v4();
        let wrong_instance_id = Uuid::new_v4();
        let master = CommitteeMasterKey::new(test_master_keypair("seed:test-committee-master"));
        let envelope_path = test_envelope_path(instance_id);

        if envelope_path.exists() {
            fs::remove_file(&envelope_path).expect("cleanup stale envelope");
        }

        master
            .create_instance_keypair_envelope(instance_id, &envelope_path)
            .expect("create envelope should succeed");

        let err = master
            .delete_instance_keypair_envelope(wrong_instance_id, &envelope_path)
            .expect_err("delete with mismatched instance_id should fail");
        assert!(
            err.to_string().contains("instance_id mismatch"),
            "error should include mismatch hint"
        );
        assert!(envelope_path.exists(), "envelope file must remain when delete is rejected");

        fs::remove_file(&envelope_path).expect("cleanup envelope after test");
    }

    #[test]
    fn committee_instance_key_envelope_delete_nonexistent_is_ok() {
        let instance_id = Uuid::new_v4();
        let master = CommitteeMasterKey::new(test_master_keypair("seed:test-committee-master"));
        let envelope_path = test_envelope_path(instance_id);

        if envelope_path.exists() {
            fs::remove_file(&envelope_path).expect("cleanup stale envelope");
        }

        master
            .delete_instance_keypair_envelope(instance_id, &envelope_path)
            .expect("delete should be idempotent when file does not exist");
    }

    #[test]
    fn hkdf_derive_bytes_is_deterministic_and_respects_output_length() {
        let seed = b"seed-material";
        let salt = b"salt-material";
        let info = b"derive/test";

        let out1 = hkdf_derive_bytes(seed, salt, info, 32);
        let out2 = hkdf_derive_bytes(seed, salt, info, 32);
        let out3 = hkdf_derive_bytes(seed, salt, b"derive/other", 32);

        assert_eq!(out1.len(), 32);
        assert_eq!(out1, out2, "same inputs must derive identical output");
        assert_ne!(out1, out3, "different info should derive different output");
    }

    #[test]
    fn operator_keypair_for_nonce_is_deterministic_and_nonce_scoped() {
        let master = OperatorMasterKey::new(test_master_keypair("seed:test-operator-master"));

        let keypair_a1 = master.keypair_for_nonce(42);
        let keypair_a2 = master.keypair_for_nonce(42);
        let keypair_b = master.keypair_for_nonce(43);

        let pub_a1: PublicKey = keypair_a1.public_key().into();
        let pub_a2: PublicKey = keypair_a2.public_key().into();
        let pub_b: PublicKey = keypair_b.public_key().into();

        assert_eq!(pub_a1, pub_a2, "same nonce should derive same keypair");
        assert_ne!(pub_a1, pub_b, "different nonce should derive different keypairs");
    }

    #[test]
    fn operator_assert_wots_keypair_for_graph_is_deterministic_and_graph_scoped() {
        let master = OperatorMasterKey::new(test_master_keypair("seed:test-operator-master"));
        let graph_a = Uuid::new_v4();
        let graph_b = Uuid::new_v4();

        let keypair_a1 = master.assert_wots_keypair_for_graph(graph_a);
        let keypair_a2 = master.assert_wots_keypair_for_graph(graph_a);
        let keypair_b = master.assert_wots_keypair_for_graph(graph_b);

        assert_eq!(keypair_a1.1, keypair_a2.1, "same graph should derive same WOTS pubkey");
        assert_ne!(
            keypair_a1.1, keypair_b.1,
            "different graphs should derive different WOTS pubkeys"
        );
    }

    #[test]
    fn operator_nonce_derivation_path_has_expected_bip32_layout() {
        let nonce: u64 = 0x1122_3344_5566_7788;
        let path = operator_nonce_derivation_path(nonce);
        let children: Vec<ChildNumber> = path.into_iter().cloned().collect();

        assert_eq!(children.len(), 7, "path should be purpose/role/key_kind + 4 segments");
        assert_eq!(
            children[0],
            ChildNumber::from_hardened_idx(PURPOSE_BITVM_GC_DERIVATION).unwrap()
        );
        assert_eq!(children[1], ChildNumber::from_hardened_idx(ROLE_OPERATOR).unwrap());
        assert_eq!(children[2], ChildNumber::from_hardened_idx(KEY_KIND_OPERATOR_NONCE).unwrap());
        assert_eq!(children[3], ChildNumber::from_hardened_idx(0x1122).unwrap());
        assert_eq!(children[4], ChildNumber::from_hardened_idx(0x3344).unwrap());
        assert_eq!(children[5], ChildNumber::from_hardened_idx(0x5566).unwrap());
        assert_eq!(children[6], ChildNumber::from_hardened_idx(0x7788).unwrap());
    }

    #[test]
    fn committee_kek_derivation_is_deterministic_and_instance_scoped() {
        let master = test_master_keypair("seed:test-committee-master");
        let instance_a = Uuid::new_v4();
        let instance_b = Uuid::new_v4();

        let (kek_a1, path_a1) = derive_committee_instance_kek(&master, instance_a);
        let (kek_a2, path_a2) = derive_committee_instance_kek(&master, instance_a);
        let (kek_b, path_b) = derive_committee_instance_kek(&master, instance_b);

        assert_eq!(kek_a1, kek_a2, "same instance should derive same kek bytes");
        assert_eq!(path_a1, path_a2, "same instance should derive same path");
        assert_ne!(kek_a1, kek_b, "different instances should derive different kek");
        assert_ne!(path_a1, path_b, "different instances should derive different path");
    }
}
