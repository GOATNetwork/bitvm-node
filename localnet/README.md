# localnet — a clone-and-run mock testnet for the node

Five `mock-gc` nodes (committee_0, committee_1, operator_0, verifier_0, watchtower_0) on bitcoin
regtest + a local anvil + a local graph-node, every endpoint on 127.0.0.1. The garbled circuits,
soldering and proofs are deterministic mocks with configurable delays; everything on chain is
real, so peg-in, peg-out, challenge/assert/take-2 and disprove run the genuine transaction graph
(see `node/README.md`, "Mock build for local testnets"). The on-demand regression suite lives in
[e2e/](e2e/README.md).

## Host requirements

docker (with compose v2), jq, sqlite3, python3, curl, and the Rust/zkm toolchain to build the
node (`source ~/.zkm-toolchain/env`). forge runs in the pinned foundry container
(`tools/forge.sh`), graph-cli in the pinned node container (`subgraph/deploy-local.sh`); a host
`cast` is used when present and otherwise the container one (`tools/cast.sh`, slower per call).
The p2p-isolation e2e case additionally needs passwordless `sudo iptables`.

## Quick start

```bash
git clone --recurse-submodules <repo> && cd bitvm-node     # or: git submodule update --init --recursive
make localnet-reset          # builds the binaries if needed, then wipes+creates the whole localnet (2 min; 7 min when keys are generated; + the build)
make localnet-status
make e2e-smoke               # pegin_happy pegout_happy challenge_take2 (~23 min)
make localnet-down           # stop nodes/miner/proof builder; `localnet/scripts/down.sh infra` also stops the containers
```

`make localnet-up` adopts an already created localnet (containers, chains, contracts, node DBs)
without rebuilding anything; it refuses if the data dir has no keys/contracts yet (run the reset).

## Layout: code vs state

| | where | what |
|---|---|---|
| code | `localnet/` (this directory) | `scripts/` lifecycle + ops, `tools/` fault proxy / key generation / container wrappers, `e2e/` the suite, `infra/docker-compose.yml`, `contracts/` (git submodule, upstream contracts), `contracts-local/` (GatewayLocal + mocks + deploy), `subgraph/` (gateway subgraph sources + deploy) |
| state | `$LOCALNET_DATA` (default `localnet/.local`, git-ignored) | `bin/` installed binaries, `state/` keys, contracts.json, subgraph.json, cli envs, `nodes/<role>/` .env + sqlite DB, `data/` chain data of the containers, `logs/`, `run/` pids/overrides/tuning, `results/` e2e reports, `forge/` + `subgraph/` build artifacts |

`scripts/localnet.env` is the only config file. Everything that must differ between two localnets
on one host derives from three variables, all taken from the environment:

| variable | default | effect |
|---|---|---|
| `LOCALNET_DATA` | `localnet/.local` | state directory |
| `PORT_BASE` | `22000` | every port is `PORT_BASE + offset`: esplora +2, bitcoind RPC +443, ipfs +501, anvil +545, graph query/admin/index/metrics +800/+820/+830/+840, node rpc/p2p/metrics +900/+910/+920 (+ role index), proof builder +950, fault proxies +960..+979, chaos control +989 |
| `COMPOSE_PROJECT` | `bvlocal` | docker project, container names `<project>-<service>`, network `<project>-net`, iptables chain `<PROJECT>_CHAOS` |

So a second localnet next to the first one is
`LOCALNET_DATA=/srv/bv2 PORT_BASE=23000 COMPOSE_PROJECT=bvlocal2 make localnet-reset`.
Per-data-dir overrides go in `$LOCALNET_DATA/localnet.override.env` (sourced last), e.g.
`export ANVIL_CHAIN_ID=48815` to adopt a localnet whose anvil was created before the default
moved to 48816. Runtime knobs the e2e suite flips (proof verdict, solder delay) are written to
`$LOCALNET_DATA/run/tuning.env` and picked up by `scripts/nodes.sh` at (re)start; the tracked
`localnet.env` is never edited by a script.

## Scripts

```
scripts/reset.sh --yes       DESTRUCTIVE: build if needed, wipe, recreate infra, keys, 101 blocks, contracts, subgraph, fund, start
scripts/up.sh                adopt + start (idempotent); fails with a hint when a node DB does not fit the binary
scripts/down.sh [infra]      stop nodes, proof builder, miner, fault proxy [+ docker compose stop]
scripts/status.sh            containers, chain heights, subgraph sync, support processes, per-node readiness
scripts/nodes.sh start|stop|restart|status [role...]
scripts/miner.sh start|stop|status|once [n]      regtest miner, 1 block / MINE_INTERVAL_SECS
scripts/proof-builder.sh start|stop|status        mock-proof-builder
scripts/fund.sh                                   BTC + gas top-ups (idempotent)
scripts/gen-node-envs.sh                          nodes/<role>/.env + state/cli/{user,operator,verifier}.env from state/*.json
scripts/install-bins.sh                           copy the release binaries into $LOCALNET_DATA/bin
scripts/chaos.sh                                  fault injection (proxy faults, p2p cuts, freeze, container pause); `status`, `reset`
scripts/triage.sh [role]  scripts/logq.sh ...  scripts/trace.sh <id>    read-only diagnosis helpers (JSON logs under logs/nodes/<role>/)
build.sh                                          cargo build -r -p bitvm-noded --features "rpc-debug-endpoints mock-gc" --bins (repo target)
```

Tuning: edit `scripts/localnet.env` (MOCK_GC_*_DELAY_SECS, MOCK_PROOF_*, MINE_INTERVAL_SECS, ...),
then `scripts/nodes.sh restart` (GC knobs) or `scripts/proof-builder.sh stop && start` (proof knobs).
The e2e runner applies its own faster tier (2 s GC / 5 s proof) through `run/tuning.env` for the duration of a run.
Keep challenge/eval and proof delays far below the block cadence or the honest operator loses the
WronglyChallenged race.

## Contracts

`contracts/` is a git submodule of the L2 contracts. It is pinned to PR #26 of
GOATNetwork/bitvm-L2-contracts ("fix GUARDIAN_CONNECTOR_VOUT & remove debug contracts", head
`3a679bf`, fetched from the fork `KSlashh/bitvm-L2-contracts`); once that PR is merged, point
`.gitmodules` back at `GOATNetwork/bitvm-L2-contracts` and bump the pin. The PR sets
`GUARDIAN_CONNECTOR_VOUT = 3`, which is what the node's kickoff topology uses (`goat`
`output_topology::kickoff::guardian_connector()`); older contract revisions parse peg-outs wrong.
No upstream source is patched. The localnet runs anvil at chain id 48816 (= the contracts'
testnet id, so `Constants.magicBytes()` accepts the regtest OP_RETURN magic the node emits).

`contracts-local/` is a second foundry project that imports the submodule (`bitvm-l2/` remapping):

- `GatewayLocal.sol` = upstream `GatewayUpgradeable` + two committee-only knobs: `debugMintPegBTC`
  (pegBTC faucet for the peg-out cases) and `debugSetResponseWindowBlocks` (the initializer fixes
  200 goat blocks; the deploy lowers it to `RESPONSE_WINDOW_BLOCKS`, default 50). Runtime size
  23,930 B, ~650 B under the EIP-170 limit: keep additions tiny.
- `MockBitcoinSPV.sol`, `MockWGBTC.sol`: the SPV relay and the stake token that do not exist on anvil.
- `script/DeployLocal.sol`: one broadcast deploys mocks + GatewayLocal/CommitteeManagement/
  StakeManagement proxies (same order and console labels as upstream `DeployGateway.sol`).
- `deploy-local.sh`: gas funding, the script, the committee/verifier/operator registrations and
  the operator stake, then writes `state/contracts.json`.

## Subgraph

`subgraph/gateway/` holds only sources (schema, manifest with a zero placeholder address, mapping,
ABI regenerated from the submodule build, `package-lock.json`). `subgraph/deploy-local.sh` stages
them under `$LOCALNET_DATA/subgraph/gateway`, patches address + start block from
`state/contracts.json`, and runs `npm ci` / `graph codegen` / `graph build` / `graph create` /
`graph deploy` inside the node container (node_modules is cached per data dir).

## Images

bitcoin/bitcoin:29, ipfs/kubo:v0.17.0, postgres:16 by tag; mempool/electrs, graph-node, foundry
(anvil + forge + cast) and node:22-alpine by digest, see `scripts/localnet.env`. To move a digest,
change it there and `scripts/reset.sh --yes`.

## Observability

- RPC per node (`rpc-debug-endpoints` on): `GET /v1/debug/status`, `/v1/debug/engine`, `/v1/instances`, `/v1/graphs`.
- Metrics `http://127.0.0.1:<METRICS_PORT_BASE+i>/metrics`: `bitvm_node_ready`, p2p peers/topics, `bitvm_node_engine_rows{table,state}`.
- Logs: one JSON file per boot under `logs/nodes/<role>/`, `current` points at the newest; `scripts/logq.sh`, `scripts/trace.sh`.
- DBs: `nodes/<role>/bitvm-node.db` (`sqlite3 -readonly`; UUIDs are 16-byte BLOBs, use `hex(col)`).

## Measured (2026-10-16, fresh clone on a loaded 16-core host)

| step | time |
|---|---|
| first `cargo build -r` of the mock-gc binaries (crates.io registry already cached) | 14 min |
| `make localnet-reset`, first time (includes gen-keys: ~1 min per role for the peer-id check) | 7 min |
| `make localnet-reset`, keys kept | 2 min |
| `make e2e-smoke` (pegin 6.5 min, pegout 3 min, challenge_take2 13 min incl. its own peg-in) | 23 min |
| `make e2e`, all 13 cases, fast delay tier (2 s GC / 5 s proof); three full passes on 2026-10-16 | 95–110 min |

Nodes report `ready=1` two to three minutes after a reset; the suite's pre-check waits for it.

## Known limits

- Mocked verdicts: proof-validity branches test the mock policy (`MOCK_GC_PROOF_VERDICT`), not cryptography.
- A node whose DB predates a migration the binary cannot apply dies at start; `up.sh` reports it, the fix is a reset.
- All ports bind loopback; the p2p listener too (`P2P_LISTEN_IP=127.0.0.1`).
