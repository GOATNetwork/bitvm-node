use crate::env::get_bitvm_key;
use crate::rpc_service::response::ErrorResponse;
use crate::rpc_service::{AppState, current_time_secs};
use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode};
use proof_builder::api_auth::hash_field;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, SECP256K1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const AUTH_TIMESTAMP_HEADER: &str = "x-auth-timestamp";
pub const AUTH_NONCE_HEADER: &str = "x-auth-nonce";
pub const AUTH_SIGNATURE_HEADER: &str = "x-auth-signature";
const AUTH_WINDOW_SECS: i64 = 300;
const AUTH_DOMAIN: &[u8] = b"bitvm-rpc-auth-v2";
const MAX_AUTH_BODY_BYTES: usize = 2 * 1024 * 1024;

struct ParsedAuth {
    timestamp_str: String,
    timestamp: i64,
    nonce: String,
    signature: Signature,
}

/// Require a fresh, request-bound Schnorr signature and atomically consume its nonce.
pub async fn require_request_auth(
    State(app_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let now = current_time_secs();
    let parsed_auth = match parse_auth_headers(&parts.headers, now) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };

    let body = match to_bytes(body, MAX_AUTH_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return auth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                "request body exceeds 2 MiB limit",
            )
            .into_response();
        }
    };
    let request_target =
        parts.uri.path_and_query().map(|value| value.as_str()).unwrap_or_else(|| parts.uri.path());

    let keypair = match get_bitvm_key() {
        Ok(keypair) => keypair,
        Err(_) => {
            return auth_error(
                StatusCode::UNAUTHORIZED,
                "AUTH_ERROR",
                "server key configuration error (BITVM_SECRET)",
            )
            .into_response();
        }
    };
    let (x_only_pubkey, _) = keypair.x_only_public_key();
    if let Err(error) =
        verify_auth_signature(&parsed_auth, &parts.method, request_target, &body, &x_only_pubkey)
    {
        return error.into_response();
    }

    let expires_at = parsed_auth.timestamp + AUTH_WINDOW_SECS;
    match consume_auth_nonce(&app_state.rpc_auth_nonces, &parsed_auth.nonce, expires_at, now) {
        Ok(true) => next.run(Request::from_parts(parts, Body::from(body))).await,
        Ok(false) => auth_error(
            StatusCode::CONFLICT,
            "AUTH_REPLAY",
            "authentication nonce has already been used",
        )
        .into_response(),
        Err(()) => {
            tracing::error!(
                event = "rpc_auth_nonce_cache_failed",
                "RPC authentication nonce cache lock is poisoned"
            );
            auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_SERVICE_UNAVAILABLE",
                "authentication service unavailable",
            )
            .into_response()
        }
    }
}

/// Build the authentication headers for one exact HTTP request.
///
/// The caller must send the same method, request target, and body bytes that are
/// supplied here. Returns `(timestamp, nonce, hex_signature)`.
pub fn sign_request_auth(
    keypair: &Keypair,
    method: &Method,
    request_target: &str,
    body: &[u8],
) -> (String, String, String) {
    let timestamp = current_time_secs().to_string();
    let nonce = Uuid::new_v4().to_string();
    let signature =
        sign_request_auth_values(keypair, &timestamp, &nonce, method, request_target, body);
    (timestamp, nonce, signature)
}

fn parse_auth_headers(
    headers: &HeaderMap,
    now: i64,
) -> Result<ParsedAuth, (StatusCode, Json<ErrorResponse>)> {
    let timestamp_str = header_value(headers, AUTH_TIMESTAMP_HEADER)?.to_string();
    let timestamp = timestamp_str
        .parse()
        .map_err(|_| auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "invalid timestamp"))?;
    if now.abs_diff(timestamp) > AUTH_WINDOW_SECS as u64 {
        return Err(auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "timestamp expired"));
    }

    let nonce = header_value(headers, AUTH_NONCE_HEADER)?.to_string();
    let parsed_nonce = Uuid::parse_str(&nonce)
        .map_err(|_| auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "invalid nonce"))?;
    if parsed_nonce.to_string() != nonce {
        return Err(auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "invalid nonce"));
    }

    let signature_hex = header_value(headers, AUTH_SIGNATURE_HEADER)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| {
        auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "invalid signature hex encoding")
    })?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
        auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "invalid signature format")
    })?;

    Ok(ParsedAuth { timestamp_str, timestamp, nonce, signature })
}

fn header_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<&'a str, (StatusCode, Json<ErrorResponse>)> {
    headers.get(name).and_then(|value| value.to_str().ok()).ok_or_else(|| {
        auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", &format!("missing {name} header"))
    })
}

fn verify_auth_signature(
    auth: &ParsedAuth,
    method: &Method,
    request_target: &str,
    body: &[u8],
    x_only_pubkey: &XOnlyPublicKey,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let digest =
        request_auth_digest(&auth.timestamp_str, &auth.nonce, method, request_target, body);
    let message = Message::from_digest(digest);
    SECP256K1.verify_schnorr(&auth.signature, &message, x_only_pubkey).map_err(|_| {
        auth_error(StatusCode::UNAUTHORIZED, "AUTH_ERROR", "signature verification failed")
    })
}

fn sign_request_auth_values(
    keypair: &Keypair,
    timestamp: &str,
    nonce: &str,
    method: &Method,
    request_target: &str,
    body: &[u8],
) -> String {
    let message =
        Message::from_digest(request_auth_digest(timestamp, nonce, method, request_target, body));
    hex::encode(SECP256K1.sign_schnorr(&message, keypair).as_ref())
}

fn request_auth_digest(
    timestamp: &str,
    nonce: &str,
    method: &Method,
    request_target: &str,
    body: &[u8],
) -> [u8; 32] {
    let body_digest = Sha256::digest(body);
    let mut hasher = Sha256::new();
    for field in [
        AUTH_DOMAIN,
        timestamp.as_bytes(),
        nonce.as_bytes(),
        method.as_str().as_bytes(),
        request_target.as_bytes(),
    ] {
        hash_field(&mut hasher, field);
    }
    hash_field(&mut hasher, &body_digest);
    hasher.finalize().into()
}

fn consume_auth_nonce(
    nonces: &Mutex<HashMap<String, i64>>,
    nonce: &str,
    expires_at: i64,
    now: i64,
) -> Result<bool, ()> {
    let mut nonces = nonces.lock().map_err(|_| ())?;
    nonces.retain(|_, expires_at| *expires_at >= now);
    Ok(nonces.insert(nonce.to_string(), expires_at).is_none())
}

fn auth_error(status: StatusCode, error: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: error.to_string(), message: message.to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMESTAMP: &str = "2000000000";
    const NONCE: &str = "01234567-89ab-4def-8123-456789abcdef";
    const OTHER_NONCE: &str = "fedcba98-7654-4abc-8123-456789abcdef";
    const TARGET: &str = "/v1/graphs/pegout";
    const BODY: &[u8] = br#"{"graph_id":null,"dry_run":false,"skip_locked":false}"#;

    fn test_keypair() -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[0x42; 32]).unwrap()
    }

    fn signed_headers(
        keypair: &Keypair,
        timestamp: &str,
        nonce: &str,
        method: &Method,
        target: &str,
        body: &[u8],
    ) -> HeaderMap {
        let signature = sign_request_auth_values(keypair, timestamp, nonce, method, target, body);
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_TIMESTAMP_HEADER, timestamp.parse().unwrap());
        headers.insert(AUTH_NONCE_HEADER, nonce.parse().unwrap());
        headers.insert(AUTH_SIGNATURE_HEADER, signature.parse().unwrap());
        headers
    }

    fn verify(
        headers: &HeaderMap,
        method: &Method,
        target: &str,
        body: &[u8],
        now: i64,
    ) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
        let auth = parse_auth_headers(headers, now)?;
        let (x_only_pubkey, _) = test_keypair().x_only_public_key();
        verify_auth_signature(&auth, method, target, body, &x_only_pubkey)
    }

    #[test]
    fn sign_then_verify_ok() {
        let keypair = test_keypair();
        let headers = signed_headers(&keypair, TIMESTAMP, NONCE, &Method::POST, TARGET, BODY);
        let non_v4_headers = signed_headers(
            &keypair,
            TIMESTAMP,
            "01234567-89ab-7def-8123-456789abcdef",
            &Method::POST,
            TARGET,
            BODY,
        );

        assert!(verify(&headers, &Method::POST, TARGET, BODY, 2_000_000_000).is_ok());
        assert!(verify(&non_v4_headers, &Method::POST, TARGET, BODY, 2_000_000_000).is_ok());
    }

    #[test]
    fn signature_is_bound_to_the_entire_request() {
        let keypair = test_keypair();
        let headers = signed_headers(&keypair, TIMESTAMP, NONCE, &Method::POST, TARGET, BODY);

        assert!(verify(&headers, &Method::PUT, TARGET, BODY, 2_000_000_000).is_err());
        assert!(
            verify(&headers, &Method::POST, "/v1/graphs/not-pegout", BODY, 2_000_000_000,).is_err()
        );
        assert!(
            verify(&headers, &Method::POST, "/v1/graphs/pegout?dry_run=true", BODY, 2_000_000_000,)
                .is_err()
        );
        assert!(
            verify(
                &headers,
                &Method::POST,
                TARGET,
                br#"{"graph_id":null,"dry_run":true,"skip_locked":false}"#,
                2_000_000_000,
            )
            .is_err()
        );

        let mut changed_nonce = headers.clone();
        changed_nonce.insert(AUTH_NONCE_HEADER, OTHER_NONCE.parse().unwrap());
        assert!(verify(&changed_nonce, &Method::POST, TARGET, BODY, 2_000_000_000).is_err());

        let mut changed_timestamp = headers;
        changed_timestamp.insert(AUTH_TIMESTAMP_HEADER, "2000000001".parse().unwrap());
        assert!(verify(&changed_timestamp, &Method::POST, TARGET, BODY, 2_000_000_001).is_err());
    }

    #[test]
    fn missing_or_invalid_headers_fail() {
        let keypair = test_keypair();
        let headers = signed_headers(&keypair, TIMESTAMP, NONCE, &Method::POST, TARGET, BODY);

        for missing in [AUTH_TIMESTAMP_HEADER, AUTH_NONCE_HEADER, AUTH_SIGNATURE_HEADER] {
            let mut incomplete = headers.clone();
            incomplete.remove(missing);
            assert_eq!(
                verify(&incomplete, &Method::POST, TARGET, BODY, 2_000_000_000).unwrap_err().0,
                StatusCode::UNAUTHORIZED
            );
        }

        for nonce in [
            "not-a-uuid".to_string(),
            NONCE.replace('-', ""),
            format!("{{{NONCE}}}"),
            NONCE.to_uppercase(),
        ] {
            let mut invalid_headers = headers.clone();
            invalid_headers.insert(AUTH_NONCE_HEADER, nonce.parse().unwrap());
            assert!(verify(&invalid_headers, &Method::POST, TARGET, BODY, 2_000_000_000).is_err());
        }
    }

    #[test]
    fn nonce_cache_rejects_replay_and_removes_expired_entries() {
        let nonces = Mutex::new(HashMap::new());

        assert!(consume_auth_nonce(&nonces, NONCE, 400, 100).unwrap());
        assert!(!consume_auth_nonce(&nonces, NONCE, 400, 100).unwrap());
        assert!(consume_auth_nonce(&nonces, OTHER_NONCE, 800, 401).unwrap());
        assert!(!nonces.lock().unwrap().contains_key(NONCE));
    }

    #[test]
    fn nonce_cache_consumption_is_atomic() {
        let nonces = Mutex::new(HashMap::new());
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| consume_auth_nonce(&nonces, NONCE, 400, 100).unwrap());
            let second = scope.spawn(|| consume_auth_nonce(&nonces, NONCE, 400, 100).unwrap());
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_ne!(first, second);
    }

    #[test]
    fn expired_timestamp_fails() {
        let keypair = test_keypair();
        let headers = signed_headers(&keypair, TIMESTAMP, NONCE, &Method::POST, TARGET, BODY);

        assert_eq!(
            verify(&headers, &Method::POST, TARGET, BODY, 2_000_000_301).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn wrong_signature_fails() {
        let keypair = test_keypair();
        let mut headers = signed_headers(&keypair, TIMESTAMP, NONCE, &Method::POST, TARGET, BODY);
        headers.insert(AUTH_SIGNATURE_HEADER, "ff".repeat(64).parse().unwrap());

        assert!(verify(&headers, &Method::POST, TARGET, BODY, 2_000_000_000).is_err());
    }

    #[test]
    fn legacy_signature_fails() {
        let keypair = test_keypair();
        let mut hasher = Sha256::new();
        hasher.update(b"bitvm-auth");
        hasher.update(TIMESTAMP.as_bytes());
        let message = Message::from_digest(hasher.finalize().into());
        let signature = hex::encode(SECP256K1.sign_schnorr(&message, &keypair).as_ref());
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_TIMESTAMP_HEADER, TIMESTAMP.parse().unwrap());
        headers.insert(AUTH_NONCE_HEADER, NONCE.parse().unwrap());
        headers.insert(AUTH_SIGNATURE_HEADER, signature.parse().unwrap());

        assert!(verify(&headers, &Method::POST, TARGET, BODY, 2_000_000_000).is_err());
    }
}
