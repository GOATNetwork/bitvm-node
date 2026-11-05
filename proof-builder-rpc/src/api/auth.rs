use crate::api::response::ErrorResponse;
use alloy_primitives::Address;
use async_trait::async_trait;
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use client::goat_chain::{GOATClient, GraphData};
use proof_builder::api_auth::{
    AUTH_NONCE_HEADER, AUTH_PUBLIC_KEY_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER,
    AUTH_WINDOW_SECS, ProofBuilderAuthRole, normalize_public_key,
    verify_proof_builder_request_signature,
};
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) type AuthResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;
pub(crate) type AuthorizationChains = HashMap<Address, Arc<dyn AuthorizationChain>>;

#[async_trait]
pub(crate) trait AuthorizationChain: Send + Sync {
    /// Returns the Gateway data registered for one graph.
    async fn graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData>;
    /// Returns all graph IDs registered under one instance.
    async fn graph_ids(&self, instance_id: &Uuid) -> anyhow::Result<Vec<Uuid>>;
    /// Returns the current global Watchtower registry.
    async fn watchtowers(&self) -> anyhow::Result<Vec<XOnlyPublicKey>>;
}

#[async_trait]
impl AuthorizationChain for GOATClient {
    async fn graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
        self.gateway_get_graph_data(graph_id).await
    }

    async fn graph_ids(&self, instance_id: &Uuid) -> anyhow::Result<Vec<Uuid>> {
        self.gateway_get_graph_ids_by_instance_id(instance_id).await
    }

    async fn watchtowers(&self) -> anyhow::Result<Vec<XOnlyPublicKey>> {
        self.committee_mana_get_watchtowers().await
    }
}

pub(crate) struct RequestAuthorizer {
    chains: AuthorizationChains,
    accepted_nonces: Mutex<HashMap<(String, String), i64>>,
}

impl RequestAuthorizer {
    /// Creates an authorizer backed by live GOAT contract queries.
    pub(crate) fn new(chains: AuthorizationChains) -> Self {
        Self { chains, accepted_nonces: Mutex::new(HashMap::new()) }
    }

    /// Verifies request credentials locally and returns the authenticated signer.
    pub(crate) fn authenticate<B: Serialize>(
        &self,
        headers: &HeaderMap,
        role: ProofBuilderAuthRole,
        method: &str,
        path: &str,
        body: &B,
        claimed_watchtower_public_key: Option<&str>,
    ) -> AuthResult<XOnlyPublicKey> {
        let timestamp = required_header(headers, AUTH_TIMESTAMP_HEADER)?;
        let nonce = required_header(headers, AUTH_NONCE_HEADER)?;
        let signer_value = required_header(headers, AUTH_PUBLIC_KEY_HEADER)?;
        let signature = required_header(headers, AUTH_SIGNATURE_HEADER)?;
        let signer = normalize_public_key(signer_value)
            .map_err(|_| unauthorized("invalid signer public key"))?;

        if let Some(claimed_public_key) = claimed_watchtower_public_key {
            let claimed = normalize_public_key(claimed_public_key)
                .map_err(|_| forbidden("invalid watchtower public key"))?;
            if claimed != signer {
                return Err(forbidden("watchtower signer does not match request public key"));
            }
        }

        verify_proof_builder_request_signature(
            role, method, path, timestamp, nonce, &signer, signature, body,
        )
        .map_err(|_| unauthorized("invalid request signature"))?;
        self.record_nonce(&signer.to_string(), nonce)?;
        Ok(signer)
    }

    /// Checks current graph ownership and instance membership for an Operator
    /// and returns the registered graph data.
    pub(crate) async fn authorize_operator(
        &self,
        signer: &XOnlyPublicKey,
        gateway_address: Option<&str>,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> AuthResult<GraphData> {
        let chain = self.chain_for_gateway(gateway_address)?;
        let signer_bytes = signer.serialize();
        let graph_data = chain.graph_data(graph_id).await.map_err(contract_unavailable)?;
        if graph_data.operator_pubkey == [0; 32] {
            return Err(forbidden("graph is not registered"));
        }
        if graph_data.operator_pubkey != signer_bytes {
            return Err(forbidden("operator signer does not own graph"));
        }

        let graph_ids = chain.graph_ids(instance_id).await.map_err(contract_unavailable)?;
        if !graph_ids.contains(graph_id) {
            return Err(forbidden("graph does not belong to instance"));
        }
        Ok(graph_data)
    }

    /// Checks that the signer is in the current global Watchtower registry and
    /// that the graph is registered under the instance; returns the graph data.
    ///
    /// The graph's own Watchtower list is not on chain, so slot membership is
    /// enforced when the Operator task fixes the list.
    pub(crate) async fn authorize_watchtower(
        &self,
        signer: &XOnlyPublicKey,
        gateway_address: Option<&str>,
        instance_id: &Uuid,
        graph_id: &Uuid,
    ) -> AuthResult<GraphData> {
        let chain = self.chain_for_gateway(gateway_address)?;
        let watchtowers = chain.watchtowers().await.map_err(contract_unavailable)?;
        if !watchtowers.contains(signer) {
            return Err(forbidden("watchtower signer is not registered"));
        }
        let graph_data = chain.graph_data(graph_id).await.map_err(contract_unavailable)?;
        if graph_data.operator_pubkey == [0; 32] {
            return Err(forbidden("graph is not registered"));
        }
        let graph_ids = chain.graph_ids(instance_id).await.map_err(contract_unavailable)?;
        if !graph_ids.contains(graph_id) {
            return Err(forbidden("graph does not belong to instance"));
        }
        Ok(graph_data)
    }

    /// Selects the configured contract set identified by the signed request body.
    fn chain_for_gateway(
        &self,
        gateway_address: Option<&str>,
    ) -> AuthResult<Arc<dyn AuthorizationChain>> {
        let gateway_address = match gateway_address {
            Some(value) => {
                let address = value
                    .parse::<Address>()
                    .map_err(|_| bad_request("gateway_address is not a valid EVM address"))?;
                if address == Address::ZERO {
                    return Err(bad_request("gateway_address must not be the zero address"));
                }
                address
            }
            None if self.chains.len() == 1 => {
                return Ok(self.chains.values().next().expect("one chain is configured").clone());
            }
            None => {
                return Err(bad_request(
                    "gateway_address is required when multiple Gateways are configured",
                ));
            }
        };

        self.chains
            .get(&gateway_address)
            .cloned()
            .ok_or_else(|| forbidden("gateway_address is not configured"))
    }

    /// Atomically rejects a nonce already accepted from the same signer.
    fn record_nonce(&self, signer: &str, nonce: &str) -> AuthResult<()> {
        let now = current_time_secs();
        let mut accepted_nonces = self
            .accepted_nonces
            .lock()
            .map_err(|_| internal_error("authentication replay cache is unavailable"))?;
        accepted_nonces.retain(|_, accepted_at| now - *accepted_at <= AUTH_WINDOW_SECS);
        if accepted_nonces.insert((signer.to_string(), nonce.to_string()), now).is_some() {
            return Err(unauthorized("request nonce has already been used"));
        }
        Ok(())
    }
}

/// Builds a 400 response for an invalid or ambiguous Gateway selection.
fn bad_request(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::BAD_REQUEST, message)
}

/// Reads one required UTF-8 authentication header.
fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> AuthResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| unauthorized(&format!("missing or invalid {name} header")))
}

/// Builds a 401 response for missing or invalid authentication credentials.
fn unauthorized(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::UNAUTHORIZED, message)
}

/// Builds a 403 response for an authenticated identity without the required role or ownership.
pub(crate) fn forbidden(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::FORBIDDEN, message)
}

/// Converts a failed authorization contract query into a fail-closed response.
fn contract_unavailable(error: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    tracing::warn!(error = %error, "GOAT authorization query failed");
    auth_error(StatusCode::SERVICE_UNAVAILABLE, "authorization contract is unavailable")
}

/// Builds a 500 response when the local authentication state cannot be used safely.
fn internal_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    auth_error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// Builds the common JSON error returned by the Proof Builder authentication boundary.
fn auth_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: "PROOF_BUILDER_AUTH_ERROR".to_string(),
            message: message.into(),
        }),
    )
}

/// Returns the current Unix time used to expire replay-cache entries.
fn current_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct TestAuthorizationState {
        graphs: HashMap<Uuid, GraphData>,
        instance_graphs: HashMap<Uuid, Vec<Uuid>>,
        watchtowers: HashSet<XOnlyPublicKey>,
        fail_queries: bool,
    }

    #[derive(Default)]
    pub(crate) struct TestAuthorizationChain {
        state: Mutex<TestAuthorizationState>,
    }

    impl TestAuthorizationChain {
        pub(crate) fn set_graph(&self, instance_id: Uuid, graph_id: Uuid, owner: XOnlyPublicKey) {
            let mut state = self.state.lock().unwrap();
            state.graphs.insert(graph_id, graph_data(owner));
            state.instance_graphs.entry(instance_id).or_default().push(graph_id);
        }

        /// Sets the registered Watchtower-Challenge-Init txid and Watchtower count.
        pub(crate) fn set_graph_watchtowers(
            &self,
            graph_id: Uuid,
            challenge_init_txid: [u8; 32],
            watchtowers: usize,
        ) {
            let mut state = self.state.lock().unwrap();
            let graph = state.graphs.get_mut(&graph_id).expect("graph is set");
            graph.watchtower_challenge_init_txid = challenge_init_txid;
            graph.watchtower_challenge_timeout_txids = vec![[0; 32]; watchtowers];
        }

        pub(crate) fn set_graph_owner(&self, graph_id: Uuid, owner: XOnlyPublicKey) {
            self.state.lock().unwrap().graphs.insert(graph_id, graph_data(owner));
        }

        pub(crate) fn add_watchtower(&self, public_key: XOnlyPublicKey) {
            self.state.lock().unwrap().watchtowers.insert(public_key);
        }

        pub(crate) fn remove_watchtower(&self, public_key: &XOnlyPublicKey) {
            self.state.lock().unwrap().watchtowers.remove(public_key);
        }

        pub(crate) fn set_fail_queries(&self, fail_queries: bool) {
            self.state.lock().unwrap().fail_queries = fail_queries;
        }
    }

    #[async_trait]
    impl AuthorizationChain for TestAuthorizationChain {
        async fn graph_data(&self, graph_id: &Uuid) -> anyhow::Result<GraphData> {
            let state = self.state.lock().unwrap();
            ensure_available(&state)?;
            Ok(state.graphs.get(graph_id).cloned().unwrap_or_else(empty_graph_data))
        }

        async fn graph_ids(&self, instance_id: &Uuid) -> anyhow::Result<Vec<Uuid>> {
            let state = self.state.lock().unwrap();
            ensure_available(&state)?;
            Ok(state.instance_graphs.get(instance_id).cloned().unwrap_or_default())
        }

        async fn watchtowers(&self) -> anyhow::Result<Vec<XOnlyPublicKey>> {
            let state = self.state.lock().unwrap();
            ensure_available(&state)?;
            Ok(state.watchtowers.iter().copied().collect())
        }
    }

    fn ensure_available(state: &TestAuthorizationState) -> anyhow::Result<()> {
        anyhow::ensure!(!state.fail_queries, "authorization query failed");
        Ok(())
    }

    fn graph_data(owner: XOnlyPublicKey) -> GraphData {
        GraphData { operator_pubkey: owner.serialize(), ..empty_graph_data() }
    }

    fn empty_graph_data() -> GraphData {
        GraphData {
            operator_pubkey_prefix: 0,
            operator_pubkey: [0; 32],
            pegin_txid: [0; 32],
            kickoff_txid: [0; 32],
            take1_txid: [0; 32],
            take2_txid: [0; 32],
            watchtower_challenge_init_txid: [0; 32],
            prover_assert_txid: [0; 32],
            disprove_txids: vec![],
            watchtower_challenge_timeout_txids: vec![],
            operator_challenge_nack_txids: vec![],
            operator_commit_timeout_txid: [0; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestAuthorizationChain;
    use super::*;
    use proof_builder::api_auth::{ProofBuilderAuthHeaders, sign_proof_builder_request};
    use secp256k1::{Keypair, SECP256K1};

    #[derive(Serialize)]
    struct TestBody {
        public_key: String,
        value: u64,
    }

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).unwrap()
    }

    fn gateway(seed: u8) -> Address {
        Address::from_slice(&[seed; 20])
    }

    fn chains(gateway: Address, chain: Arc<TestAuthorizationChain>) -> AuthorizationChains {
        let chain: Arc<dyn AuthorizationChain> = chain;
        HashMap::from([(gateway, chain)])
    }

    fn headers(values: &ProofBuilderAuthHeaders) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values.to_header_pairs() {
            headers.insert(name.parse::<axum::http::HeaderName>().unwrap(), value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn authenticates_valid_signer_once_and_rejects_replay() {
        let operator = keypair(7);
        let authorizer =
            RequestAuthorizer::new(chains(gateway(1), Arc::new(TestAuthorizationChain::default())));
        let body = TestBody { public_key: operator.public_key().to_string(), value: 1 };
        let signed = sign_proof_builder_request(
            &operator,
            ProofBuilderAuthRole::Operator,
            "POST",
            "/v1/proofs/operator_proofs",
            &body,
        )
        .unwrap();
        let headers = headers(&signed);

        assert!(
            authorizer
                .authenticate(
                    &headers,
                    ProofBuilderAuthRole::Operator,
                    "POST",
                    "/v1/proofs/operator_proofs",
                    &body,
                    None,
                )
                .is_ok()
        );
        assert_eq!(
            authorizer
                .authenticate(
                    &headers,
                    ProofBuilderAuthRole::Operator,
                    "POST",
                    "/v1/proofs/operator_proofs",
                    &body,
                    None,
                )
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn operator_authorization_checks_graph_owner() {
        let operator = keypair(7).x_only_public_key().0;
        let other_operator = keypair(8).x_only_public_key().0;
        let instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();
        let chain = Arc::new(TestAuthorizationChain::default());
        let authorizer = RequestAuthorizer::new(chains(gateway(1), chain.clone()));

        assert_eq!(
            authorizer
                .authorize_operator(&operator, None, &instance_id, &graph_id)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );

        chain.set_graph_owner(graph_id, other_operator);
        assert_eq!(
            authorizer
                .authorize_operator(&operator, None, &instance_id, &graph_id)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );

        chain.set_graph(instance_id, graph_id, operator);
        assert!(
            authorizer.authorize_operator(&operator, None, &instance_id, &graph_id).await.is_ok()
        );
    }

    #[tokio::test]
    async fn operator_authorization_rejects_instance_mismatch() {
        let operator = keypair(7).x_only_public_key().0;
        let instance_id = Uuid::new_v4();
        let other_instance_id = Uuid::new_v4();
        let graph_id = Uuid::new_v4();
        let chain = Arc::new(TestAuthorizationChain::default());
        chain.set_graph(other_instance_id, graph_id, operator);
        let authorizer = RequestAuthorizer::new(chains(gateway(1), chain.clone()));

        assert_eq!(
            authorizer
                .authorize_operator(&operator, None, &instance_id, &graph_id)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn watchtower_authorization_tracks_registry_and_binds_request_identity() {
        let watchtower_keypair = keypair(9);
        let watchtower = watchtower_keypair.x_only_public_key().0;
        let other_watchtower = keypair(11);
        let (instance_id, graph_id) = (Uuid::new_v4(), Uuid::new_v4());
        let chain = Arc::new(TestAuthorizationChain::default());
        chain.add_watchtower(watchtower);
        chain.set_graph(instance_id, graph_id, keypair(7).x_only_public_key().0);
        let authorizer = RequestAuthorizer::new(chains(gateway(1), chain.clone()));

        assert!(
            authorizer
                .authorize_watchtower(&watchtower, None, &instance_id, &graph_id)
                .await
                .is_ok()
        );
        // A graph that is unregistered or belongs to another instance is refused.
        for (instance, graph) in [(instance_id, Uuid::new_v4()), (Uuid::new_v4(), graph_id)] {
            assert_eq!(
                authorizer
                    .authorize_watchtower(&watchtower, None, &instance, &graph)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
        }
        chain.remove_watchtower(&watchtower);
        assert_eq!(
            authorizer
                .authorize_watchtower(&watchtower, None, &instance_id, &graph_id)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );

        let body = TestBody { public_key: other_watchtower.public_key().to_string(), value: 1 };
        let signed = sign_proof_builder_request(
            &watchtower_keypair,
            ProofBuilderAuthRole::Watchtower,
            "POST",
            "/v1/proofs/watchtower_proofs",
            &body,
        )
        .unwrap();
        assert_eq!(
            authorizer
                .authenticate(
                    &headers(&signed),
                    ProofBuilderAuthRole::Watchtower,
                    "POST",
                    "/v1/proofs/watchtower_proofs",
                    &body,
                    Some(&body.public_key),
                )
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
}
