# End-to-end checks

The suite exercises bridge protocol and recovery behavior on the
[localnet](../README.md). It runs manually and through the
[Localnet e2e workflow](../../.github/workflows/e2e_localnet.yml).

## Run

From the repository root:

```bash
make localnet-status
make e2e-smoke
make e2e
```

List scenarios or run a subset:

```bash
localnet/e2e/run.sh --list
localnet/e2e/run.sh pegout_happy challenge_take2
localnet/e2e/run.sh --stop-on-fail
```

## Coverage

| Scenario | Expected behavior |
|----------|-------------------|
| Peg-in | Committee signing completes and the graph is posted |
| Peg-out | An unchallenged claim completes through Take-1 |
| Valid challenged claim | The Operator completes through Take-2 |
| Invalid assertion | Verifier-Assert and Disprove prevent the claim |
| Back-to-back peg-ins | Setup work queues without losing either instance |
| Node restart | Interrupted work resumes without duplicate graph creation |
| Slow or unavailable backends | Pending work recovers after the outage |
| P2P isolation | Peers reconnect and the protocol resumes |

The [transaction graph](../../transaction-graph.svg) shows the Bitcoin paths.
Proof verdicts are mocked; these scenarios do not establish cryptographic
soundness.

## Results

Each scenario checks readiness and failed work before it runs, then checks for
new failures, stuck work, and leftover fault injection afterward. The suite
reports individual results and exits unsuccessfully if any scenario fails.
The P2P isolation scenario is skipped when the host cannot apply its network
isolation rules.
