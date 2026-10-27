//! Artificial, env-configurable delays for the mocked GC operations (only compiled under the
//! `mock-gc` feature).
//!
//! Each mocked GC operation is fast in reality, so to make the localnet behave like the real
//! protocol (minutes of setup, seconds of dispute work) every mocked operation `await`s a delay
//! read from the environment **at call time**. The delay is always an async sleep placed in async
//! context, *before* the `spawn_blocking` that runs the (now trivial) mock, so it never holds a
//! blocking-pool thread and is cancel-safe at shutdown.
//!
//! Per-operation env var (seconds, integer or fractional), else `MOCK_GC_DELAY_SECS`, else 0:
//!
//! | operation      | env var                          | real work being simulated                     |
//! |----------------|----------------------------------|-----------------------------------------------|
//! | `BuilderInit`  | `MOCK_GC_BUILDER_INIT_DELAY_SECS`| Ziren `client.setup` on the soldering guest   |
//! | `Setup`        | `MOCK_GC_SETUP_DELAY_SECS`       | `BABEVerifier::new` garbling 181 instances    |
//! | `Solder`       | `MOCK_GC_SOLDER_DELAY_SECS`      | opening 7 instances + Ziren STARK proof       |
//! | `Verify`       | `MOCK_GC_VERIFY_DELAY_SECS`      | re-garble 174 opened instances + STARK verify |
//! | `Challenge`    | `MOCK_GC_CHALLENGE_DELAY_SECS`   | base-instance label derivation                |
//! | `Eval`         | `MOCK_GC_EVAL_DELAY_SECS`        | GC evaluation + message decryption            |
//!
//! Note: `Challenge` and `Eval` run inside the peg-out jobs (`verifier_assert`,
//! `wrongly_challenged`), which compete with the honest Operator on 1-3 block regtest
//! timelocks (WronglyChallenged / Disprove). A long delay there makes the Operator lose that
//! race and, past the engine job lease, lets a second holder re-run the job and double-broadcast
//! a dispute tx with a second, conflicting fee input. So `Challenge` and `Eval` are
//! **hard-capped** at [`LATENCY_CRITICAL_MAX_DELAY`]; a larger env value is clamped with a
//! warning. The three heavy setup ops carry no such cap and may be set to minutes. In practice
//! keep `Challenge`/`Eval` to a few seconds (below the block-mining cadence).

use std::time::Duration;

/// A mocked GC operation whose artificial delay can be configured independently.
#[derive(Debug, Clone, Copy)]
pub enum GcOp {
    BuilderInit,
    Setup,
    Solder,
    Verify,
    Challenge,
    Eval,
}

impl GcOp {
    const fn env_var(self) -> &'static str {
        match self {
            GcOp::BuilderInit => "MOCK_GC_BUILDER_INIT_DELAY_SECS",
            GcOp::Setup => "MOCK_GC_SETUP_DELAY_SECS",
            GcOp::Solder => "MOCK_GC_SOLDER_DELAY_SECS",
            GcOp::Verify => "MOCK_GC_VERIFY_DELAY_SECS",
            GcOp::Challenge => "MOCK_GC_CHALLENGE_DELAY_SECS",
            GcOp::Eval => "MOCK_GC_EVAL_DELAY_SECS",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            GcOp::BuilderInit => "builder_init",
            GcOp::Setup => "setup",
            GcOp::Solder => "solder",
            GcOp::Verify => "verify",
            GcOp::Challenge => "challenge",
            GcOp::Eval => "eval",
        }
    }

    /// The maximum artificial delay this op may impose, or `None` for an unbounded op.
    ///
    /// `Challenge` and `Eval` run inline on the sequential P2P-inbox dispatch worker with no
    /// lease renewal, so their delay is capped well under the inbox lease (see the module docs).
    /// The heavy ops (`BuilderInit`/`Setup`/`Solder`/`Verify`) are spawned with lease renewal and
    /// serialized by the heavy-task permit, so they may run for minutes and are left unbounded.
    const fn max_delay(self) -> Option<Duration> {
        match self {
            GcOp::Challenge | GcOp::Eval => Some(LATENCY_CRITICAL_MAX_DELAY),
            GcOp::BuilderInit | GcOp::Setup | GcOp::Solder | GcOp::Verify => None,
        }
    }
}

const DEFAULT_DELAY_VAR: &str = "MOCK_GC_DELAY_SECS";

/// Hard cap for the `Challenge`/`Eval` delays of the dispute jobs: well under the engine's
/// 5-minute job lease, so a misconfigured value can never let a second holder re-run the job
/// and double-broadcast a dispute transaction.
const LATENCY_CRITICAL_MAX_DELAY: Duration = Duration::from_secs(60);

fn parse_secs(name: &str) -> Option<Duration> {
    let raw = std::env::var(name).ok()?;
    let secs = raw.trim().parse::<f64>().ok()?;
    if secs.is_finite() && secs > 0.0 { Some(Duration::from_secs_f64(secs)) } else { None }
}

/// The env-configured delay for `op`, before clamping.
fn configured_delay_for(op: GcOp) -> Duration {
    parse_secs(op.env_var()).or_else(|| parse_secs(DEFAULT_DELAY_VAR)).unwrap_or(Duration::ZERO)
}

/// Clamp a configured delay to the op's safe maximum, warning once per call when it is truncated.
fn clamp_delay(op: GcOp, configured: Duration) -> Duration {
    match op.max_delay() {
        Some(max) if configured > max => {
            tracing::warn!(
                event = "mock_gc_delay",
                op = op.label(),
                stage = "clamped",
                configured_secs = configured.as_secs_f64(),
                max_secs = max.as_secs_f64(),
                "mock GC delay exceeds the safe maximum for an inline dispatch op; clamping so it \
                 cannot stall the inbox worker past the lease or race the dispute timelock"
            );
            max
        }
        _ => configured,
    }
}

fn delay_for(op: GcOp) -> Duration {
    clamp_delay(op, configured_delay_for(op))
}

/// Await the configured artificial delay for `op`, logging one structured line at start and end.
pub async fn simulate(op: GcOp) {
    let delay = delay_for(op);
    if delay.is_zero() {
        return;
    }
    let delay_secs = delay.as_secs_f64();
    tracing::info!(
        event = "mock_gc_delay",
        op = op.label(),
        stage = "started",
        delay_secs,
        "simulating mocked GC work"
    );
    tokio::time::sleep(delay).await;
    tracing::info!(
        event = "mock_gc_delay",
        op = op.label(),
        stage = "finished",
        delay_secs,
        "mocked GC work complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three heavy ops are spawned with lease renewal, so their delay is unbounded.
    const HEAVY_OPS: [GcOp; 4] = [GcOp::BuilderInit, GcOp::Setup, GcOp::Solder, GcOp::Verify];
    // These two run inline on the dispatch worker with no lease renewal, so they are capped.
    const INLINE_OPS: [GcOp; 2] = [GcOp::Challenge, GcOp::Eval];

    #[test]
    fn inline_dispatch_ops_are_capped() {
        for op in INLINE_OPS {
            assert_eq!(op.max_delay(), Some(LATENCY_CRITICAL_MAX_DELAY));
        }
        for op in HEAVY_OPS {
            assert_eq!(op.max_delay(), None);
        }
    }

    #[test]
    fn clamp_truncates_only_inline_ops_over_the_cap() {
        let over = LATENCY_CRITICAL_MAX_DELAY + Duration::from_secs(600);
        // An oversized inline delay is clamped to the safe maximum (well under the inbox lease).
        for op in INLINE_OPS {
            assert_eq!(clamp_delay(op, over), LATENCY_CRITICAL_MAX_DELAY);
        }
        // Heavy ops keep whatever was configured, even minutes.
        for op in HEAVY_OPS {
            assert_eq!(clamp_delay(op, over), over);
        }
    }

    #[test]
    fn clamp_preserves_values_within_the_cap() {
        let within = Duration::from_secs(3);
        for op in INLINE_OPS.into_iter().chain(HEAVY_OPS) {
            assert_eq!(clamp_delay(op, within), within);
        }
        // Exactly the cap is not truncated.
        for op in INLINE_OPS {
            assert_eq!(clamp_delay(op, LATENCY_CRITICAL_MAX_DELAY), LATENCY_CRITICAL_MAX_DELAY);
        }
    }

    #[test]
    fn cap_is_well_under_the_p2p_inbox_lease() {
        // P2P_INBOX_LEASE_SECS is 5 minutes (node/src/action.rs); the cap must leave ample margin
        // so a clamped inline op cannot outlive the (never-renewed) lease and get re-dispatched.
        assert!(LATENCY_CRITICAL_MAX_DELAY <= Duration::from_secs(60));
        assert!(LATENCY_CRITICAL_MAX_DELAY * 4 < Duration::from_secs(5 * 60));
    }
}
