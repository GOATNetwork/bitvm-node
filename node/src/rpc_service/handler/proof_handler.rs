use crate::env::get_proof_build_rpc_host;
use crate::rpc_service::AppState;
use crate::rpc_service::response::{ApiResult, ok_response, to_api_error};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, Uri};
use proof_builder::{ChainProofDescRequest, OperatorProofDescRequest, ProofDescResponse};
use reqwest::Url;
use std::sync::Arc;

/// Checks if the request host matches the configured proof builder host to prevent forwarding loops.
fn is_loop_detected(env_url: &Url, request_host: Option<&str>) -> bool {
    let Some(req_host_str) = request_host else {
        return false;
    };

    let Some(env_hostname) = env_url.host_str() else {
        return false;
    };

    // Parse Request Host (String split)
    let (req_hostname, req_port_opt) = parse_simple_host_port(req_host_str);

    // Compare Hostnames (case-insensitive)
    if !env_hostname.eq_ignore_ascii_case(&req_hostname) {
        return false;
    }

    let env_port = env_url.port_or_known_default().unwrap_or(0);
    // Compare Ports
    match req_port_opt {
        Some(req_port) => env_port == req_port,
        None => {
            // Request has no explicit port.
            // If Env is using standard ports (80/443), we assume collision is possible/likely.
            // If Env is using a non-standard port (e.g. 8080), and request has NO port (implying 80/443),
            // then they are different.
            env_port == 80 || env_port == 443
        }
    }
}

/// Parses a simple "host" or "host:port" string.
fn parse_simple_host_port(input: &str) -> (String, Option<u16>) {
    let input = input.trim();
    if let Some((host, port_str)) = input.split_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host.to_string(), Some(port));
    }

    (input.to_string(), None)
}

async fn handle_proof_desc_forwarding(
    uri: &Uri,
    headers: &HeaderMap,
    app_state: Arc<AppState>,
    error_code: &str,
) -> ApiResult<ProofDescResponse> {
    match get_proof_build_rpc_host() {
        Some(host) => {
            // Strict check: parse as URL and validate scheme
            let Some(env_url) =
                Url::parse(&host).ok().filter(|u| u.scheme() == "http" || u.scheme() == "https")
            else {
                tracing::warn!("GOAT_PROOF_BUILD_URL is invalid (must be valid http/https URL)");
                return ok_response(ProofDescResponse {
                    proof_desc: None,
                    error: Some("proof builder URL is misconfigured".to_string()),
                });
            };

            let request_host = headers.get("host").and_then(|h| h.to_str().ok());
            if is_loop_detected(&env_url, request_host) {
                tracing::warn!("GOAT_PROOF_BUILD_URL points to this node; not forwarding");
                return ok_response(ProofDescResponse {
                    proof_desc: None,
                    error: Some("Request host matches self, loop detected".to_string()),
                });
            }

            let base_url = env_url.as_str().trim_end_matches('/');
            let url = format!("{base_url}{uri}");

            let resp =
                app_state.http_client.get_response_json::<ProofDescResponse>(&url).await.map_err(
                    |e| {
                        // The URL and the upstream error stay in the log: the URL can
                        // carry credentials and this endpoint is public.
                        tracing::warn!(error = %e, "proof builder request failed");
                        to_api_error(error_code, "proof builder unavailable".to_string())
                    },
                )?;
            ok_response(resp)
        }
        None => ok_response(ProofDescResponse {
            proof_desc: None,
            error: Some("env GOAT_PROOF_BUILD_URL needs to be set".to_string()),
        }),
    }
}

/// Get chain proof description
///
/// Retrieves proof description information for a specific chain proof type. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `proof_type`: Proof type (required) - one of `header_chain`, `commit_chain`, or `state_chain`
/// - `height`: Block height (optional) - specific block height to query proof for
///
/// # Returns
///
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_CHAIN_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for different chain proof types
/// in the BitVM network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/chain_proofs_desc?proof_type=header_chain&height=100000&is_start_height=false
/// ```
///
/// Success response example (200 OK):
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "header_chain",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_CHAIN_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_chain_proof_desc(
    Query(_params): Query<ChainProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        "GET_CHAIN_PROOF_ERROR",
    )
    .await
}

/// Get operator proof description
///
/// Retrieves proof description information for operator proofs. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `instance_id`: Instance ID (required) - the identifier of the BitVM instance
/// - `graph_id`: Graph ID (required) - the identifier of the graph within the instance
///
/// # Returns
///
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_OPERATOR_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for operator proofs
/// in the BitVM network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/operator_proofs_desc?instance_id=instance123&graph_id=graph456
/// ```
///
/// Success response example (200 OK):
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "OperatorProof",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_OPERATOR_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_operator_proof_desc(
    Query(_params): Query<OperatorProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        "GET_OPERATOR_PROOF_ERROR",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_host_port() {
        assert_eq!(parse_simple_host_port("example.com"), ("example.com".to_string(), None));
        assert_eq!(
            parse_simple_host_port("example.com:8080"),
            ("example.com".to_string(), Some(8080))
        );
        assert_eq!(
            parse_simple_host_port("192.168.1.1:3000"),
            ("192.168.1.1".to_string(), Some(3000))
        );
    }

    #[test]
    fn test_is_loop_detected_standard_ports() {
        // Same host, standard ports
        let u1 = Url::parse("http://example.com").unwrap();
        assert!(is_loop_detected(&u1, Some("example.com")));

        let u2 = Url::parse("https://example.com").unwrap();
        assert!(is_loop_detected(&u2, Some("example.com")));

        // Explicit ports matching defaults
        let u3 = Url::parse("http://example.com:80").unwrap();
        assert!(is_loop_detected(&u3, Some("example.com:80")));

        let u4 = Url::parse("https://example.com:443").unwrap();
        assert!(is_loop_detected(&u4, Some("example.com:443")));

        // Mixing implicit and explicit standard ports
        assert!(is_loop_detected(&u1, Some("example.com:80")));
        assert!(is_loop_detected(&u3, Some("example.com")));
    }

    #[test]
    fn test_is_loop_detected_non_standard_ports() {
        let u = Url::parse("http://example.com:8080").unwrap();

        // Same host, same non-standard port -> Loop
        assert!(is_loop_detected(&u, Some("example.com:8080")));

        // Same host, different ports -> No Loop
        assert!(!is_loop_detected(&u, Some("example.com:9090")));

        // Env uses non-standard, Req uses implicit (std) -> No Loop
        assert!(!is_loop_detected(&u, Some("example.com")));
    }

    #[test]
    fn test_is_loop_detected_mismatch_host() {
        let u = Url::parse("http://example.com").unwrap();
        assert!(!is_loop_detected(&u, Some("other.com")));
        assert!(!is_loop_detected(&u, Some("sub.example.com")));
    }

    #[test]
    fn test_is_loop_detected_case_insensitive() {
        let u1 = Url::parse("HTTP://EXAMPLE.COM").unwrap();
        assert!(is_loop_detected(&u1, Some("example.com")));

        let u2 = Url::parse("http://example.com").unwrap();
        assert!(is_loop_detected(&u2, Some("EXAMPLE.COM")));
    }
}
