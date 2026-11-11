use crate::api::ApiState;
use crate::task::current_time_secs;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text;charset=utf-8;version=1.0.0";
pub(crate) const HEADER_CHAIN_PROOF: &str = "header_chain";
pub(crate) const COMMIT_CHAIN_PROOF: &str = "commit_chain";
pub(crate) const STATE_CHAIN_PROOF: &str = "state_chain";
pub(crate) const OPERATOR_PROOF: &str = "operator";
pub(crate) const WATCHTOWER_PROOF: &str = "watchtower";

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    route: String,
    status: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct HttpDurationLabels {
    method: String,
    route: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct AttemptLabels {
    proof_type: String,
    outcome: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct ProofTypeLabels {
    proof_type: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct ProofStateLabels {
    proof_type: String,
    state: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct ApiResultLabels {
    operation: String,
    result: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ApiMetricsState {
    registry: Arc<Mutex<Registry>>,
    http_requests: Family<HttpRequestLabels, Counter>,
    http_request_duration_seconds: Family<HttpDurationLabels, Histogram>,
    http_requests_in_flight: Gauge,
    proof_attempts: Family<AttemptLabels, Counter>,
    proof_attempt_duration_seconds: Family<AttemptLabels, Histogram>,
    proof_last_success_timestamp_seconds: Family<ProofTypeLabels, Gauge>,
    proof_tasks: Family<ProofStateLabels, Gauge>,
    proof_oldest_task_age_seconds: Family<ProofStateLabels, Gauge>,
    api_results: Family<ApiResultLabels, Counter>,
}

struct InFlightGuard(Gauge);

impl Drop for InFlightGuard {
    /// Decrements the in-flight request gauge when request processing ends or is cancelled.
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl ApiMetricsState {
    /// Creates and registers the complete Proof Builder metric set.
    pub(crate) fn new() -> Self {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let http_requests = Family::default();
        let http_request_duration_seconds =
            Family::<HttpDurationLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.005, 2.0, 15))
            });
        let http_requests_in_flight = Gauge::default();
        let proof_attempts = Family::default();
        let proof_attempt_duration_seconds =
            Family::<AttemptLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(1.0, 2.0, 18))
            });
        let proof_last_success_timestamp_seconds = Family::default();
        let proof_tasks = Family::default();
        let proof_oldest_task_age_seconds = Family::default();
        let api_results = Family::default();

        let mut registry_guard = registry.lock().unwrap();
        registry_guard.register(
            "http_requests",
            "Total number of HTTP requests",
            http_requests.clone(),
        );
        registry_guard.register(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            http_request_duration_seconds.clone(),
        );
        registry_guard.register(
            "http_requests_in_flight",
            "Number of HTTP requests currently being processed",
            http_requests_in_flight.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_attempts",
            "Total number of proof build attempts",
            proof_attempts.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_attempt_duration_seconds",
            "Proof attempt duration in seconds",
            proof_attempt_duration_seconds.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_last_success_timestamp_seconds",
            "Unix timestamp of the latest successful proof",
            proof_last_success_timestamp_seconds.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_tasks",
            "Number of persisted proof tasks by state",
            proof_tasks.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_oldest_task_age_seconds",
            "Age of the oldest persisted proof task by state",
            proof_oldest_task_age_seconds.clone(),
        );
        registry_guard.register(
            "bitvm_proof_builder_api_results",
            "Total number of Proof Builder API business results",
            api_results.clone(),
        );
        drop(registry_guard);

        Self {
            registry,
            http_requests,
            http_request_duration_seconds,
            http_requests_in_flight,
            proof_attempts,
            proof_attempt_duration_seconds,
            proof_last_success_timestamp_seconds,
            proof_tasks,
            proof_oldest_task_age_seconds,
            api_results,
        }
    }

    /// Records one proof attempt with its proof type, outcome, and end-to-end duration.
    pub(crate) fn record_attempt(&self, proof_type: &str, outcome: &str, duration: Duration) {
        let labels =
            AttemptLabels { proof_type: proof_type.to_owned(), outcome: outcome.to_owned() };
        self.proof_attempts.get_or_create(&labels).inc();
        self.proof_attempt_duration_seconds.get_or_create(&labels).observe(duration.as_secs_f64());
    }

    /// Creates a guard that records a failed API business result unless explicitly updated.
    pub(crate) fn api_result(&self, operation: &'static str) -> ApiResultGuard {
        ApiResultGuard { metrics: self.clone(), operation, result: "failed" }
    }

    /// Rebuilds proof task counts, ages, and success timestamps from persisted state rows.
    fn refresh_proof_snapshot(&self, rows: &[store::MetricsStateCount], now: i64) {
        self.proof_last_success_timestamp_seconds.clear();
        self.proof_tasks.clear();
        self.proof_oldest_task_age_seconds.clear();
        for row in rows {
            let Some(proof_type) = proof_type_label(&row.category) else {
                continue;
            };
            let state = proof_state_label(&row.state);
            let labels =
                ProofStateLabels { proof_type: proof_type.to_owned(), state: state.to_owned() };
            self.proof_tasks.get_or_create(&labels).inc_by(row.count);
            if matches!(state, "new" | "proving") {
                let age = row
                    .oldest_created_at
                    .map_or(0, |created_at| now.saturating_sub(created_at).max(0));
                let oldest_age = self.proof_oldest_task_age_seconds.get_or_create(&labels);
                oldest_age.set(oldest_age.get().max(age));
            }
            if let Some(last_success_at) = row.last_success_at {
                let gauge = self
                    .proof_last_success_timestamp_seconds
                    .get_or_create(&ProofTypeLabels { proof_type: proof_type.to_owned() });
                gauge.set(gauge.get().max(last_success_at));
            }
        }
    }

    /// Refreshes persisted proof metrics and encodes the complete registry.
    fn scrape(
        &self,
        rows: &[store::MetricsStateCount],
        now: i64,
    ) -> Result<String, std::fmt::Error> {
        let mut buffer = String::new();
        let registry = self.registry.lock().unwrap();
        self.refresh_proof_snapshot(rows, now);
        encode(&mut buffer, &registry)?;
        Ok(buffer)
    }
}

pub(crate) struct ApiResultGuard {
    metrics: ApiMetricsState,
    operation: &'static str,
    result: &'static str,
}

impl ApiResultGuard {
    /// Sets the business result that the guard records when dropped.
    pub(crate) fn set(&mut self, result: &'static str) {
        self.result = result;
    }
}

impl Drop for ApiResultGuard {
    /// Records the final API business result when handler execution leaves the scope.
    fn drop(&mut self) {
        self.metrics
            .api_results
            .get_or_create(&ApiResultLabels {
                operation: self.operation.to_owned(),
                result: self.result.to_owned(),
            })
            .inc();
    }
}

pub(super) async fn metrics_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let method = request.method().to_string();
    state.metrics_state.http_requests_in_flight.inc();
    let in_flight = InFlightGuard(state.metrics_state.http_requests_in_flight.clone());
    let response = next.run(request).await;
    drop(in_flight);
    let status = response.status().as_u16();
    state
        .metrics_state
        .http_requests
        .get_or_create(&HttpRequestLabels { method: method.clone(), route: route.clone(), status })
        .inc();
    state
        .metrics_state
        .http_request_duration_seconds
        .get_or_create(&HttpDurationLabels { method, route })
        .observe(start.elapsed().as_secs_f64());
    response
}

/// Refreshes database-backed proof metrics and returns the encoded metrics response.
pub(super) async fn metrics_handler(State(app_state): State<Arc<ApiState>>) -> Response {
    let rows = match app_state.local_db.acquire().await {
        Ok(mut storage_processor) => match storage_processor.proof_metrics_state_counts().await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!("Failed to query proof metrics: {error}");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        },
        Err(error) => {
            tracing::warn!("Failed to acquire database for proof metrics: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, METRICS_CONTENT_TYPE.parse().unwrap());
    match app_state.metrics_state.scrape(&rows, current_time_secs()) {
        Ok(buffer) => (headers, buffer).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "failed to encode proof builder metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Maps a persisted proof category to its bounded Prometheus proof-type label.
fn proof_type_label(category: &str) -> Option<&'static str> {
    match category {
        "header-chain" => Some("header_chain"),
        "commit-chain" => Some("commit_chain"),
        "state-chain" => Some("state_chain"),
        "operator" => Some("operator"),
        "watchtower" => Some("watchtower"),
        _ => None,
    }
}

/// Maps a persisted numeric proof state to its bounded Prometheus state label.
fn proof_state_label(state: &str) -> &'static str {
    match state {
        "0" => "new",
        "1" => "proving",
        "2" => "proven",
        "3" => "failed",
        "4" => "cancelled",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_bounded_http_and_business_metrics() {
        let metrics = ApiMetricsState::new();
        metrics
            .http_requests
            .get_or_create(&HttpRequestLabels {
                method: "GET".to_owned(),
                route: "/v1/proofs/:id".to_owned(),
                status: 200,
            })
            .inc();
        metrics
            .http_request_duration_seconds
            .get_or_create(&HttpDurationLabels {
                method: "GET".to_owned(),
                route: "/v1/proofs/:id".to_owned(),
            })
            .observe(0.01);
        metrics.http_requests_in_flight.inc();
        {
            let _in_flight = InFlightGuard(metrics.http_requests_in_flight.clone());
            assert_eq!(metrics.http_requests_in_flight.get(), 1);
        }
        assert_eq!(metrics.http_requests_in_flight.get(), 0);
        metrics.record_attempt("operator", "failed", Duration::from_secs(1));
        metrics.record_attempt("watchtower", "success", Duration::from_secs(2));
        {
            let mut result = metrics.api_result("operator_submit");
            result.set("pending");
        }

        let output = metrics.scrape(&[], 0).unwrap();
        assert!(output.contains("http_requests_total"));
        assert!(!output.contains("http_requests_total_total"));
        assert!(output.contains("route=\"/v1/proofs/:id\""));
        assert!(output.contains("bitvm_proof_builder_attempts_total"));
        assert!(output.contains("proof_type=\"watchtower\",outcome=\"success\""));
        assert!(output.contains("http_requests_in_flight 0"));
        assert!(output.contains("bitvm_proof_builder_api_results_total"));
    }

    #[test]
    fn refreshes_observed_proof_state_series() {
        let metrics = ApiMetricsState::new();
        let output = metrics
            .scrape(
                &[
                    store::MetricsStateCount {
                        category: "header-chain".to_owned(),
                        state: "0".to_owned(),
                        count: 2,
                        oldest_created_at: Some(90),
                        last_success_at: None,
                    },
                    store::MetricsStateCount {
                        category: "operator".to_owned(),
                        state: "unexpected".to_owned(),
                        count: 1,
                        oldest_created_at: Some(80),
                        last_success_at: None,
                    },
                    store::MetricsStateCount {
                        category: "operator".to_owned(),
                        state: "5".to_owned(),
                        count: 2,
                        oldest_created_at: Some(70),
                        last_success_at: None,
                    },
                    store::MetricsStateCount {
                        category: "operator".to_owned(),
                        state: "2".to_owned(),
                        count: 1,
                        oldest_created_at: Some(90),
                        last_success_at: Some(95),
                    },
                    store::MetricsStateCount {
                        category: "arbitrary-user-value".to_owned(),
                        state: "0".to_owned(),
                        count: 99,
                        oldest_created_at: Some(1),
                        last_success_at: None,
                    },
                ],
                100,
            )
            .unwrap();
        assert!(
            output
                .contains("bitvm_proof_builder_tasks{proof_type=\"header_chain\",state=\"new\"} 2")
        );
        assert!(
            output.contains(
                "bitvm_proof_builder_oldest_task_age_seconds{proof_type=\"header_chain\",state=\"new\"} 10"
            )
        );
        assert!(
            output
                .contains("bitvm_proof_builder_tasks{proof_type=\"operator\",state=\"unknown\"} 3")
        );
        assert!(output.contains(
            "bitvm_proof_builder_last_success_timestamp_seconds{proof_type=\"operator\"} 95"
        ));
        assert!(
            !output.contains("bitvm_proof_builder_oldest_task_age_seconds{proof_type=\"operator\"")
        );
        assert!(
            !output
                .contains("bitvm_proof_builder_tasks{proof_type=\"header_chain\",state=\"failed\"")
        );
        assert!(!output.contains("arbitrary-user-value"));
    }
}
