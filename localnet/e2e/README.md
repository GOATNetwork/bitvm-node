# e2e — on-demand end-to-end regression of the node

Not CI: run it by hand after a change, on the localnet of [../README.md](../README.md) (five mocked nodes on
regtest + anvil + local graph). Honours `LOCALNET_DATA` / `PORT_BASE` / `COMPOSE_PROJECT` like every other script.

```
localnet/scripts/status.sh                       # infra, chains, nodes all up
localnet/e2e/run.sh --list                       # the cases, in run order
localnet/e2e/run.sh                              # all of them (95–110 min), report in $LOCALNET_DATA/results/latest/report.md
localnet/e2e/run.sh pegout_happy challenge_take2 # a subset;  make e2e-smoke = pegin_happy pegout_happy challenge_take2
localnet/e2e/run.sh --stop-on-fail               # stop at the first failing case
```

Knobs: `E2E_CASE_TIMEOUT` (seconds per case, default 1200; an expired case is killed with its whole process tree,
chaos is reset and every node restarted before the post-check), `E2E_DELAY_TIER=fast|default` (default `fast`: the run
writes 2 s GC / 5 s proof delays to `$LOCALNET_DATA/run/tuning.env`, restarts nodes + proof builder, and restores the
`localnet.env` values (15/30 s, the manual-debugging tier) at the end), `E2E_POLL_SECS` (default 2).
Per run `$LOCALNET_DATA/results/<run>/` holds `<case>.log`, `report.md`, `report.json` (same table as structured
data: result, duration, rc, post-check rc, notes) and `logs.tar.gz` (every node / miner / proof-builder / fault-proxy
log written during the run). Exit code 0 only when nothing failed; `p2p_isolate_operator` is reported as SKIP (not a
failure) when the host has no passwordless `sudo` for iptables.

To test a new node commit: `localnet/build.sh`, `localnet/scripts/install-bins.sh`, `localnet/scripts/nodes.sh restart`, then `localnet/e2e/run.sh`.

| case | what it drives | pass = |
|---|---|---|
| `pegin_happy` | request → answers → Prepare → ceremony → Peg-In-Confirm → L2 mint → graph posted | instance RelayerL2Minted, graph L2Recorded on all nodes |
| `pegout_happy` | initWithdraw → kickoff → proceedWithdraw → Take-1 → finishWithdrawHappyPath | OperatorTake1 on all nodes, finish sent |
| `challenge_take2` | peg-out challenged by the verifier, assert found valid → Take-2 | OperatorTake2, finishWithdrawUnhappyPath |
| `dispute_disprove` | same with `MOCK_GC_PROOF_VERDICT=always-invalid` on operator + verifier → ChallengeAssert → Disprove | Disprove on all nodes, finishWithdrawDisproved; verdict restored to `valid` afterwards |
| `backtoback` | two peg-ins with a 120 s verifier solder delay; B is prepared while A's ceremony runs, and the verifier queues B's setup behind A's solder (one GC job per node at a time, `ENGINE_CPU_POOL_SLOTS` default 1) | A still in its ceremony on every node when B's Prepare confirms; B's setup job created before A's solder finished; both L2Recorded; consecutive slots |
| `pegin_restart_*` | peg-in with committee_0 / operator_0 / verifier_0 restarted the moment one of the instance's jobs is Running on it (verifier: 20 s solder for the case) | a job was caught running (verifier: its solder); it ends Done, re-run by the new process or finished during the old one's graceful shutdown; peg-in completes; one graph and one Peg-In-Confirm txid |
| `goat_timeout_at_kickoff` | Goat RPC answers 25 s slower than the 20 s timeout for 60 s at the kickoff block | peg-out completes after the window |
| `subgraph_latency` | 8 s on every subgraph query for a whole peg-in | this case's peg-in completes |
| `proof_builder_blackhole` | proof-builder requests accepted but never answered for 240 s during Prover-Assert | at least one operator request hit the black hole; Assert then Take-2 |
| `p2p_isolate_operator` | operator_0's p2p links cut for 90 s during the ceremony (iptables, needs sudo; SKIP without) | 0 peers half way through; both committee peers back within 60 s of the heal; peg-in completes |
| `boot_with_goat_down` | watchtower_0 restarted with its Goat / esplora / subgraph proxy down | the same process survives each outage and is ready within 240 s after it; a death fails the case (the node is started again for the later cases) |

Every case starts with an empty scratch dir (`$LOCALNET_DATA/run/e2e`, nothing carries over from an earlier case)
and a pre-check: a snapshot of every node's Failed job ids, nodes ready, no chaos injection left, and the operator's
locked stake at or above the gateway minimum (a Disprove slashes it; an operator under the minimum is silently
ignored by every peer, so the pre-check tops it up with the mock WGBTC faucet). Every case ends with a post-check:
`/v1/debug/engine` has no Failed / Poisoned inbox rows, no waiting / poisoned aggregates and no Running / Poisoned
jobs on any node, no Failed job exists that was not in the snapshot (and the debug endpoint reports no more Failed
jobs than the snapshot holds; a failed snapshot or DB query fails the check instead of counting as "none"), `scripts/chaos.sh status` is empty, the miner is
restarted. `run/tuning.env` is saved before each case and restored after it whatever happened (pass, fail, timeout,
Ctrl-C); when the restore had to change something the nodes are restarted and the report notes it. Scenario
scripts exit with their own verdict and the runner uses it; an unknown case name is an error (exit 2). The fault cases attach every node to `tools/faultproxy.py` the first time they run
(`scripts/chaos.sh attach all`, a restart of every node) and leave them attached; `scripts/chaos.sh detach all` undoes it.

Layout: `lib.sh` helpers (status polling, log waits, DB queries, chaos helpers), `flows/` the protocol drives,
`scenarios/` the fault injections around a flow; `$LOCALNET_DATA/results/<run>/` one log per case plus `report.md`,
`results/latest`. CLI identities come from `$LOCALNET_DATA/state/cli/{user,operator,verifier}.env` (test-only keys,
generated by `scripts/gen-node-envs.sh`); peg-ins consume one wallet UTXO each. Cases that flip a mock knob
(`dispute_disprove`, `backtoback`) do it through `$LOCALNET_DATA/run/tuning.env` and restore it afterwards.
