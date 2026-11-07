# Localnet

Localnet runs two Committee nodes, an Operator, a Verifier and a Watchtower on
Bitcoin Regtest and a GOAT chain. Proof generation and verification use
deterministic mocks, while Bitcoin transactions follow the real
[transaction graph](../transaction-graph.svg).

The default GOAT backend is a private Anvil chain. The testnet3 backend uses GOAT
testnet3 with a separately deployed bridge. The test environment binds its
services to loopback.

## Quick start

Run from the repository root:

```bash
make localnet-reset
make localnet-status
make e2e-smoke
make localnet-down
```

`localnet-reset` rebuilds the test environment and clears its chain and node
state. `localnet-up` restarts an initialized environment without resetting it.

## Test scenarios

The [end-to-end suite](e2e/README.md) covers peg-in, peg-out, challenges,
disproofs, restarts, and backend outages. Run the smoke suite for a small change
and the full suite for broader protocol or scheduling changes:

```bash
make e2e
```

Mock proof verdicts exercise protocol branches; they do not test cryptographic
soundness. Keep proof and challenge processing fast enough to complete before
the simulated Bitcoin deadlines. Mock builds are not for live deployments.

## Diagnosis

Check readiness and chain progress before starting a scenario. Use the
[operator tools](../scripts/ops/README.md) to inspect stalled instances or graphs.
Clear fault injection and restore mining before rerunning a failed scenario.

## CI

The [Localnet e2e workflow](../.github/workflows/e2e_localnet.yml) runs on pushes
to `main` and `dev`, and on manual dispatch. It builds the mock nodes, resets a
private test environment, runs the suite, and reports results. Runs are queued
to avoid concurrent changes to the same test environment.
