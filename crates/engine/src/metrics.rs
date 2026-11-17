//! Engine metrics: counts by kind and outcome, apply latency, and row counts by
//! state for the four tables.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindOutcomeLabels {
    kind: String,
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindLabels {
    kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TableStateLabels {
    table: String,
    state: String,
}

#[derive(Clone, Debug)]
pub struct EngineMetrics {
    events_total: Family<KindOutcomeLabels, Counter>,
    apply_duration_seconds: Family<KindLabels, Histogram>,
    outbox_publish_total: Family<OutcomeLabels, Counter>,
    job_runs_total: Family<KindOutcomeLabels, Counter>,
    rows: Family<TableStateLabels, Gauge>,
    /// Every table/state the row gauge has reported, so a state that empties
    /// is set back to zero.
    known_rows: Arc<Mutex<HashSet<TableStateLabels>>>,
    acks_dropped_total: Counter,
    poisoned_total: Counter,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self {
            events_total: Family::default(),
            apply_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.005, 2.0, 15))
            }),
            outbox_publish_total: Family::default(),
            job_runs_total: Family::default(),
            rows: Family::default(),
            known_rows: Arc::default(),
            acks_dropped_total: Counter::default(),
            poisoned_total: Counter::default(),
        }
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "bitvm_node_engine_events",
            "Engine inbox events by kind and apply outcome",
            self.events_total.clone(),
        );
        registry.register(
            "bitvm_node_engine_apply_duration_seconds",
            "Engine apply duration by event kind",
            self.apply_duration_seconds.clone(),
        );
        registry.register(
            "bitvm_node_engine_outbox_publish",
            "Engine outbox publish attempts by outcome",
            self.outbox_publish_total.clone(),
        );
        registry.register(
            "bitvm_node_engine_job_runs",
            "Engine job runs by action and outcome",
            self.job_runs_total.clone(),
        );
        registry.register(
            "bitvm_node_engine_rows",
            "Engine table rows by state",
            self.rows.clone(),
        );
        registry.register(
            "bitvm_node_engine_acks_dropped",
            "ACKs dropped because the return channel was full",
            self.acks_dropped_total.clone(),
        );
        registry.register(
            "bitvm_node_engine_poisoned",
            "Events and jobs poisoned by a panic or invariant violation",
            self.poisoned_total.clone(),
        );
    }

    pub fn record_event(&self, kind: &str, outcome: &str) {
        self.events_total
            .get_or_create(&KindOutcomeLabels {
                kind: kind.to_string(),
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub fn record_apply_duration(&self, kind: &str, elapsed: Duration) {
        self.apply_duration_seconds
            .get_or_create(&KindLabels { kind: kind.to_string() })
            .observe(elapsed.as_secs_f64());
    }

    pub fn record_publish(&self, success: bool) {
        let outcome = if success { "success" } else { "failed" };
        self.outbox_publish_total
            .get_or_create(&OutcomeLabels { outcome: outcome.to_string() })
            .inc();
    }

    pub fn record_job_run(&self, action: &str, outcome: &str) {
        self.job_runs_total
            .get_or_create(&KindOutcomeLabels {
                kind: action.to_string(),
                outcome: outcome.to_string(),
            })
            .inc();
    }

    /// Publish one refresh of the row counts. The count query only returns
    /// states that have rows: a state it no longer returns goes to zero
    /// instead of keeping its last value.
    pub fn set_row_counts<'a>(&self, counts: impl IntoIterator<Item = (&'a str, &'a str, i64)>) {
        let mut known = self.known_rows.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut seen = HashSet::new();
        for (table, state, count) in counts {
            let labels = TableStateLabels { table: table.to_string(), state: state.to_string() };
            self.rows.get_or_create(&labels).set(count);
            known.insert(labels.clone());
            seen.insert(labels);
        }
        for labels in known.iter().filter(|labels| !seen.contains(*labels)) {
            self.rows.get_or_create(labels).set(0);
        }
    }

    pub fn record_ack_dropped(&self) {
        self.acks_dropped_total.inc();
    }

    pub fn record_poisoned(&self) {
        self.poisoned_total.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(metrics: &EngineMetrics, table: &str, state: &str) -> i64 {
        metrics
            .rows
            .get_or_create(&TableStateLabels { table: table.to_string(), state: state.to_string() })
            .get()
    }

    #[test]
    fn a_state_that_empties_goes_back_to_zero() {
        let metrics = EngineMetrics::new();
        metrics.set_row_counts([("job", "pending", 3), ("job", "running", 1)]);
        metrics.set_row_counts([("job", "pending", 2)]);
        assert_eq!(rows(&metrics, "job", "pending"), 2);
        assert_eq!(rows(&metrics, "job", "running"), 0);
        metrics.set_row_counts([]);
        assert_eq!(rows(&metrics, "job", "pending"), 0);
    }
}
