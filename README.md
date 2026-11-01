# GOAT BitVM Node

GOAT Network's BitVM bridge implementation. See [GOAT BitVM Whitepaper](https://www.goat.network/bitvm2-whitepaper) for more details.

## Layout

- `node/`: Main node implementation, including P2P, RPC, and scheduled tasks
- `circuits/`: Circuits and proof generation logic
- `proof-builder-rpc/`: RPC server for offloading proof generation to a separate process
- `crates/`: Shared Rust crates for common types and utilities
- `deployment`: Deployment scripts and documentation
- `scripts/ops/`: Read-only operator helpers for a running node (health triage, log queries, instance / graph traces)
- `localnet/`: clone-and-run mock testnet (five `mock-gc` nodes on regtest + anvil + graph-node) and the on-demand e2e suite, see [localnet/README.md](localnet/README.md); `make localnet-reset`, `make e2e-smoke`


## Formal verification (TLA+)

`audit/tla/` contains TLA+ specs that model the bridge protocol as the Rust
code implements it: the graph/instance status state machines, the Bitcoin
transaction graph and its timelocks, the node's challenge/dispute reactions,
the job engine, and the GOAT Gateway contracts. **Only the current code is
checked**: every config models the code as it is now (or a proposed fix for a
bug still in it); none models old, pre-fix code. A fixed bug is covered by a
config of the current code that must verify, so CI fails if the bug returns;
an unfixed bug is a config of the current code that reproduces, so CI fails
until it is fixed.

- **Round 1** (`audit/TLAPlus-20260710.md`): 8 findings, **all fixed** in
  [`991faaa`](https://github.com/GOATNetwork/bitvm-node/commit/991faaabdb56c747103e8f1c6d6477c638ccfc4c);
  plus issues #429 and #431, fixed by #455, #451 and #476.
- **Round 2** (2026-10-31, protocol review of dev @ `60562f8`): the dispute
  defences, the assert scripts, the kickoff challenge gate, the Gateway
  withdraw lifecycle, the job engine and the peg-in. These findings are **not
  fixed yet**: their configs are `live`, so the `tla-plus` job **stays red until
  the code is fixed** - by design.

**Layout** - specs and configs live in separate trees that mirror the code they model:

```
audit/tla/
  checks.txt        every TLC run: tier | config | description
  check.sh          runs checks.txt (make tla, CI job tla-plus)
  specs/<area>/<Spec>.tla              modules; <area> = crates/bitvm-gc, crates/engine,
                                       node/aggregates/{graph,instance}, node/scheduled_tasks, contracts
  configs/<area>/<Spec>/<Name>.cfg     configs of <Spec>; runs specs/<area>/<Spec>.tla
```

The specs follow the [TLA+ agent skills](https://github.com/tlaplus/AgentSkills)
conventions: each action carries `\* Action:` and `\* Source:` comments pointing
at the current code, every config checks `TypeOk`, and properties are grouped
into safety invariants, safety properties and liveness.

**Timing parameters are swept, not fixed.** Every timelock, timing-budget value,
delay, reorg depth or capacity a verdict depends on is a frozen variable chosen
in `Init` from a range that covers every ordering class (equal, margin 0,
margin 1), so one run covers all combinations. Honest actors react within
explicit reaction/inclusion/evaluation delays, never "before the next block".
A fix states the margin it needs as `ParamsOK` (exact unless its header says
otherwise). `*Shipped.cfg` configs take the real per-network values from
`specs/crates/bitvm-gc/ShippedTimelockValues.tla`, which is **generated** from
`crates/bitvm-gc/src/timelocks.rs` by `crates/bitvm-gc/tests/tla_shipped_values.rs`;
that test fails in CI when the two drift (`make tla-values` regenerates it).

**Tiers** (`checks.txt`, judged by `check.sh`):

- **pass** - models the current code; must verify. This is where a fixed
  bug's regression check lives.
- **live** - models the current code with a known, unfixed bug; while it
  reproduces the counterexample it fails the run and blocks merge. When the
  code is fixed, change the config to model the fix (usually: take the
  `design` row's settings) and make it `pass`. A `live` row that stops
  reproducing without that also fails: the model drifted from the code.
- **design** - a proposed fix for a `live` bug, not in the code yet; must
  verify. It becomes the `pass` row once the fix lands.
- **boundary** - a fix design outside its `ParamsOK`, or an insufficient
  fix; must find a counterexample, which shows the condition is necessary.

The outcome is taken from TLC's exit status, so a config on which TLC does
not finish (parse error, missing file) fails in every tier, and every config
file must be listed in `checks.txt`.

**Specs** (row counts per tier; `checks.txt` has one line per config):

| Spec (`audit/tla/specs/...`) | Models | Findings | pass | live | design | boundary |
|---|---|---|---|---|---|---|
| `crates/bitvm-gc/AssertFrontRun.tla` | assert connectors, `graph_scan.rs`, `graph_pegout_jobs.rs` | C3, C4, pi2/pi3 malleability; validator gap (live) | 1 | 7 | 4 | 2 |
| `crates/bitvm-gc/DefenderTxPinning.tla` | presigned NACK/Commit-Timeout/Disprove policy | M3 |  | 2 | 2 | 2 |
| `crates/bitvm-gc/MultiActorRace.tla` | `timelocks.rs`, `graph_scan.rs` | Findings 5/10 | 1 |  |  |  |
| `crates/bitvm-gc/RoundPenalty.tla` | `utils/graph_tx.rs`, `operator/api.rs` | M5 |  | 2 | 2 | 1 |
| `crates/bitvm-gc/ShippedTimelockValues.tla` | generated from `timelocks.rs` | shared module |  |  |  |  |
| `crates/bitvm-gc/ShippedTimelocks.tla` | `timelocks.rs` `action_window` | shared module |  |  |  |  |
| `crates/bitvm-gc/Take1ChallengeRace.tla` | `timelocks.rs` | Finding 9 | 1 |  |  |  |
| `crates/bitvm-gc/Take2DisproveRace.tla` | `timelocks.rs` `validate_timelock_config`, goat connectors | Finding 4; validator floor (live) | 1 | 1 |  |  |
| `crates/engine/JobObligationPersistence.tla` | `crates/engine`, graph jobs | H3 |  | 3 | 2 | 1 |
| `crates/engine/MessageStateRace.tla` | `engine_job` (`crates/store/src/engine`, `crates/engine`) | Finding 7 | 1 |  |  |  |
| `crates/engine/PegoutPoolCapacity.tla` | `crates/engine` pools, `graph_pegout_jobs.rs` | H5 |  | 2 | 2 | 2 |
| `node/aggregates/graph/ChallengeKickoffGate.tla` | `challenge_kickoff`, SPV maintenance, `Gateway.sol` | C5, C6, H4 | 2 | 5 | 4 | 4 |
| `node/aggregates/graph/DisputeObligations.tla` | `graph_scan.rs`, `graph_pegout.rs`, `graph_pegout_jobs.rs` | C1, C2; validator gap (live) |  | 6 | 2 | 2 |
| `node/aggregates/graph/GraphLifecycle.tla` | `transition_graph_status`, `graph_pegout.rs`, `event_watch/gateway.rs` | Finding 1 | 2 |  |  |  |
| `node/aggregates/graph/GraphLifecycleFineGrainedFixed.tla` | `localdb/graph.rs` `transition_graph_status` | Finding 1b | 1 |  |  |  |
| `node/aggregates/graph/GraphTopology.tla` | `schema.rs` `allowed_transition_from` | shared module |  |  |  |  |
| `node/aggregates/graph/KickoffScanCoverage.tla` | `graph_scan.rs` `scan_graphs_on_chain` | #431 | 1 |  |  | 1 |
| `node/aggregates/graph/VerifierKickoffFailOpen.tla` | `graph_pegout_jobs.rs` `challenge_kickoff` | #429 | 1 |  |  |  |
| `node/aggregates/instance/CommitteeKeyDeletion.tla` | `instance_jobs.rs` key deletion, `env.rs` | H2 |  | 4 | 2 | 1 |
| `node/aggregates/instance/InstanceLifecycle.tla` | `instance.rs`, `instance_scan.rs`, `pegin_confirm_sign` | baseline; sign-gate race | 1 | 1 | 1 |  |
| `node/aggregates/instance/InstancePresigned.tla` | `instance.rs` `decide_graph_endorsed` | Finding 2 | 1 |  |  |  |
| `node/aggregates/instance/PeginConfirmCancelReorg.tla` | SPV writer, `post_pegin_data` | H6 |  | 3 | 2 | 4 |
| `node/aggregates/instance/PeginPostRetry.tla` | `instance_jobs.rs` `post_pegin_data` | M4 |  | 1 | 1 |  |
| `node/aggregates/instance/PeginRequestLiveness.tla` | `instance_scan.rs`, pegin requests | F1, F6, F7 |  | 5 | 4 | 1 |
| `node/aggregates/instance/PeginTimeoutAgreement.tla` | `instance_scan.rs` Timeout, relayer | M2 | 1 | 3 | 3 |  |
| `node/scheduled_tasks/InstanceBridgeOutRace.tla` | `event_watch/bridge_out.rs`, `swap_maintenance_tasks.rs` | Finding 6 | 1 |  |  |  |
| `contracts/GatewayWithdrawLifecycle.tla` | `Gateway.sol`, `graph_pegout_jobs.rs`, `event_watch/gateway.rs` | H1, M1, C5, F4, econ |  | 8 | 6 |  |
| `contracts/MultiSigReplay.tla` | `MultiSigVerifier.sol` | multisig replay |  | 1 | 1 |  |
| **total** | | | **16** | **54** | **38** | **21** |

**What the parameter sweeps found** (beyond the round-2 findings themselves):

- `validate_timelock_config` accepts unsafe timelocks (all `live`): `connector_d - prover_connector`
  counts one action window where ChallengeAssert + Disprove need `2(reaction+inclusion)+1`, and
  `>= action_window` only lets a late verifier tie Take2; `watchtower_challenge >= wtp + action_window`
  leaves the watchtower 2 blocks short; with a zero `confirmed_action_window` (Regtest) the
  `saturating_sub` gap checks admit any order of `operator_ack`, `operator_commit`, `connector_f`.
- The shipped Regtest timelocks are too short for the fix designs (C3/C4, M3, C6, C1/C2), and
  Signet's `watchtower_challenge` is one block short for the C1/C2 fix.
- C6 reproduces with a healthy SPV on Testnet4, Signet and Regtest (`connector_a` <= SPV lag);
  on Bitcoin only after ~118 blocks of SPV lag. The C6 fix would also challenge every honest
  peg-out on those three networks unless `connector_a >= BTC_BLOCK_CONFIRMS + lag + 2r + incl + 3`.
- H5 reproduces on Testnet4, Signet and Regtest, not on Bitcoin; its per-graph fix is insufficient
  when several graphs are challenged at once. GC evaluation time is not part of the timing budget.
- H6: the header relay feeds the GOAT SPV at the tip and the contract does not enforce depth, so a
  1-deep reorg after the 1-conf post mints unbacked pegBTC; via the node's own writer
  (`BTC_BLOCK_CONFIRMS` behind the tip) it takes a reorg of depth `BTC_BLOCK_CONFIRMS + 1`.
- `pegin_confirm_sign` reads the tip at the signing gate, then signs; a block in between yields a
  Peg-In-Confirm signature at `tip >= H_p + T0`, when the user's Cancel is already valid. Fix design:
  close the gate one block early.

**Setup** (once): install a JRE (11+), then download the official TLA+ tools jar:

```bash
sudo apt-get install -y openjdk-21-jre-headless   # or any JRE 11+
make tla-setup                                    # -> ~/.local/share/tlaplus/tla2tools.jar
```

**Run**:

```bash
make tla                                          # the whole table; exit 1 while any live bug reproduces
make tla SPEC=node/aggregates/graph               # every config under a code area
make tla SPEC=ChallengeKickoffGate                # every config of one spec
make tla SPEC=ChallengeKickoffGate/C6Shipped.cfg  # one config
make tla TLC_OPTS="-workers auto"                 # extra TLC flags
make tla-values                                   # regenerate ShippedTimelockValues.tla after a timelocks.rs change
```

TLC only resolves `EXTENDS` in the spec's own directory, so `check.sh` copies
every module into `audit/tla/states/lib` and runs from there. To run TLC by
hand, do the same: `java -jar tla2tools.jar -config <path to cfg> states/lib/<Spec>.tla`
(keep the spec path relative; TLC 2.19 does not find the config when it is absolute).
SANY (parser) is `java -cp tla2tools.jar tla2sany.SANY <Spec>.tla`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.