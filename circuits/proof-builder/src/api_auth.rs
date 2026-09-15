use anyhow::{Context, bail};
use rand::{RngCore, rngs::OsRng};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, PublicKey, SECP256K1, XOnlyPublicKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::mem;
use std::str::FromStr;

pub const AUTH_TIMESTAMP_HEADER: &str = "x-proof-auth-timestamp";
pub const AUTH_NONCE_HEADER: &str = "x-proof-auth-nonce";
pub const AUTH_PUBLIC_KEY_HEADER: &str = "x-proof-auth-public-key";
pub const AUTH_SIGNATURE_HEADER: &str = "x-proof-auth-signature";
pub const AUTH_WINDOW_SECS: i64 = 300;

const AUTH_DOMAIN: &str = "bitvm-proof-builder-auth-v1";
const AUTH_NONCE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofBuilderAuthRole {
    Operator,
    Watchtower,
}

impl ProofBuilderAuthRole {
    /// Returns the stable role label included in the signed payload.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBuilderAuthHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub public_key: String,
    pub signature: String,
}

impl ProofBuilderAuthHeaders {
    /// Converts the signed values into HTTP header name/value pairs.
    pub fn to_header_pairs(&self) -> Vec<(String, String)> {
        vec![
            (AUTH_TIMESTAMP_HEADER.to_string(), self.timestamp.clone()),
            (AUTH_NONCE_HEADER.to_string(), self.nonce.clone()),
            (AUTH_PUBLIC_KEY_HEADER.to_string(), self.public_key.clone()),
            (AUTH_SIGNATURE_HEADER.to_string(), self.signature.clone()),
        ]
    }
}

/// Normalizes a compressed or x-only secp256k1 public key to x-only form.
pub fn normalize_public_key(value: &str) -> anyhow::Result<XOnlyPublicKey> {
    if let Ok(public_key) = XOnlyPublicKey::from_str(value) {
        return Ok(public_key);
    }
    let public_key = PublicKey::from_str(value).context("invalid secp256k1 public key")?;
    Ok(public_key.x_only_public_key().0)
}

/// Signs one Proof Builder request with a fresh nonce and the caller's node key.
#[allow(clippy::too_many_arguments)]
pub fn sign_proof_builder_request<B: Serialize>(
    keypair: &Keypair,
    role: ProofBuilderAuthRole,
    method: &str,
    path: &str,
    body: &B,
) -> anyhow::Result<ProofBuilderAuthHeaders> {
    let timestamp = current_time_secs().to_string();
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let public_key = keypair.x_only_public_key().0.to_string();
    let digest = request_digest(role, method, path, &timestamp, &nonce, &public_key, body)?;
    let mut auxiliary_randomness = [0u8; 32];
    OsRng.fill_bytes(&mut auxiliary_randomness);
    let signature = SECP256K1.sign_schnorr_with_aux_rand(
        &Message::from_digest(digest),
        keypair,
        &auxiliary_randomness,
    );

    Ok(ProofBuilderAuthHeaders {
        timestamp,
        nonce,
        public_key,
        signature: hex::encode(signature.as_ref()),
    })
}

/// Verifies the cryptographic binding of one Proof Builder request.
#[allow(clippy::too_many_arguments)]
pub fn verify_proof_builder_request_signature<B: Serialize>(
    role: ProofBuilderAuthRole,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    public_key: &XOnlyPublicKey,
    signature: &str,
    body: &B,
) -> anyhow::Result<()> {
    validate_timestamp(timestamp)?;
    let nonce_bytes = hex::decode(nonce).context("invalid auth nonce encoding")?;
    if nonce_bytes.len() != AUTH_NONCE_LEN {
        bail!("invalid auth nonce length");
    }
    let signature_bytes = hex::decode(signature).context("invalid auth signature encoding")?;
    let signature = Signature::from_slice(&signature_bytes).context("invalid auth signature")?;
    let canonical_public_key = public_key.to_string();
    let digest = request_digest(role, method, path, timestamp, nonce, &canonical_public_key, body)?;
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(digest), public_key)
        .context("auth signature verification failed")
}

/// Validates that an authentication timestamp is canonical and within the accepted window.
pub fn validate_timestamp(timestamp: &str) -> anyhow::Result<i64> {
    let timestamp_value: i64 = timestamp.parse().context("invalid auth timestamp")?;
    if timestamp_value.to_string() != timestamp {
        bail!("auth timestamp is not canonical");
    }
    let now = current_time_secs();
    if (now - timestamp_value).abs() > AUTH_WINDOW_SECS {
        bail!("auth timestamp expired");
    }
    Ok(timestamp_value)
}

/// Hashes length-prefixed request fields and canonical JSON body bytes into the signed digest.
fn request_digest<B: Serialize>(
    role: ProofBuilderAuthRole,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    public_key: &str,
    body: &B,
) -> anyhow::Result<[u8; 32]> {
    let body_hash = Sha256::digest(canonical_json_bytes(body)?);
    let mut hasher = Sha256::new();
    for field in [AUTH_DOMAIN, role.as_str(), method, path, timestamp, nonce, public_key] {
        hash_field(&mut hasher, field.as_bytes());
    }
    hash_field(&mut hasher, &body_hash);
    Ok(hasher.finalize().into())
}

/// Serializes JSON objects with recursively sorted keys for cross-client digest stability.
fn canonical_json_bytes<B: Serialize>(body: &B) -> anyhow::Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(body).context("failed to serialize authenticated request body")?;
    sort_json_value(&mut value);
    serde_json::to_vec(&value).context("failed to encode canonical authenticated request body")
}

/// Recursively sorts JSON object keys while preserving array order.
fn sort_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut entries = mem::take(map).into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            for (key, mut value) in entries {
                sort_json_value(&mut value);
                map.insert(key, value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sort_json_value),
        _ => {}
    }
}

/// Adds one length-prefixed field to the authentication digest.
pub fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Returns the current Unix time used by the authentication freshness check.
fn current_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestBody {
        graph_id: &'static str,
        value: u64,
    }

    #[derive(Serialize)]
    struct ReorderedTestBody {
        value: u64,
        graph_id: &'static str,
    }

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
    }

    #[test]
    fn signed_request_verifies_and_is_bound_to_request() {
        let keypair = keypair(7);
        let body = TestBody { graph_id: "graph-1", value: 1 };
        let headers = sign_proof_builder_request(
            &keypair,
            ProofBuilderAuthRole::Operator,
            "POST",
            "/v1/proofs/operator_proofs",
            &body,
        )
        .unwrap();
        let public_key = normalize_public_key(&headers.public_key).unwrap();

        assert!(
            verify_proof_builder_request_signature(
                ProofBuilderAuthRole::Operator,
                "POST",
                "/v1/proofs/operator_proofs",
                &headers.timestamp,
                &headers.nonce,
                &public_key,
                &headers.signature,
                &body,
            )
            .is_ok()
        );
        assert!(
            verify_proof_builder_request_signature(
                ProofBuilderAuthRole::Operator,
                "POST",
                "/v1/proofs/operator_proofs_timeout",
                &headers.timestamp,
                &headers.nonce,
                &public_key,
                &headers.signature,
                &body,
            )
            .is_err()
        );
        assert!(
            verify_proof_builder_request_signature(
                ProofBuilderAuthRole::Watchtower,
                "POST",
                "/v1/proofs/operator_proofs",
                &headers.timestamp,
                &headers.nonce,
                &public_key,
                &headers.signature,
                &body,
            )
            .is_err()
        );
        assert!(
            verify_proof_builder_request_signature(
                ProofBuilderAuthRole::Operator,
                "POST",
                "/v1/proofs/operator_proofs",
                &headers.timestamp,
                &headers.nonce,
                &public_key,
                &headers.signature,
                &TestBody { graph_id: "graph-2", value: 1 },
            )
            .is_err()
        );
        assert!(
            verify_proof_builder_request_signature(
                ProofBuilderAuthRole::Operator,
                "POST",
                "/v1/proofs/operator_proofs",
                &headers.timestamp,
                &headers.nonce,
                &public_key,
                &headers.signature,
                &ReorderedTestBody { value: 1, graph_id: "graph-1" },
            )
            .is_ok()
        );
    }

    #[test]
    fn public_key_normalization_accepts_compressed_and_x_only_keys() {
        let keypair = keypair(9);
        let expected = keypair.x_only_public_key().0;
        assert_eq!(normalize_public_key(&expected.to_string()).unwrap(), expected);
        assert_eq!(normalize_public_key(&keypair.public_key().to_string()).unwrap(), expected);
    }
}
