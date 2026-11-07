# localnet — a clone-and-run mock testnet for the node

Five `mock-gc` nodes (committee_0, committee_1, operator_0, verifier_0, watchtower_0) on bitcoin
regtest + a GOAT chain (a local anvil, or the public GOAT testnet3, see "GOAT backend") + a local
graph-node, every endpoint on 127.0.0.1. The garbled circuits,
soldering and proofs are deterministic mocks with configurable delays; everything on chain is
real, so peg-in, peg-out, challenge/assert/take-2 and disprove run the genuine transaction graph
(see the [node guide](../node/README.md#local-testnets) and [transaction graph](../transaction-graph.svg)). The on-demand regression suite lives in
[e2e/](e2e/README.md). CI runs the whole suite after pushes to main / dev, see "CI" below.

## Host requirements

docker (with compose v2), jq, sqlite3, python3, curl, and the Rust/zkm toolchain to build the
node (`source ~/.zkm-toolchain/env`). forge runs in the pinned foundry container
(`tools/forge.sh`), graph-cli in the pinned node container (`subgraph/deploy-local.sh`); a host
`cast` is used when present and otherwise the container one (`tools/cast.sh`, slower per call).
The p2p-isolation e2e case additionally needs passwordless `sudo iptables`.

## Quick start

```bash
git clone --recurse-submodules https://github.com/GOATNetwork/bitvm-node.git && cd bitvm-node     # or: git submodule update --init --recursive
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
| `PORT_BASE` | `22000` | every port is `PORT_BASE + offset`: esplora +2, bitcoind RPC +443, ipfs +501, GOAT RPC (anvil or the testnet3 forwarder) +545, graph query/admin/index/metrics +800/+820/+830/+840, node rpc/p2p/metrics +900/+910/+920 (+ role index), proof builder +950, fault proxies +960..+979, chaos control +989 |
| `COMPOSE_PROJECT` | `bvlocal` | docker project, container names `<project>-<service>`, network `<project>-net`, iptables chain `<PROJECT>_CHAOS` |

So a second localnet next to the first one is
`LOCALNET_DATA=/srv/bv2 PORT_BASE=23000 COMPOSE_PROJECT=bvlocal2 make localnet-reset`.
Per-data-dir overrides go in `$LOCALNET_DATA/localnet.override.env` (sourced last), e.g.
`export ANVIL_CHAIN_ID=48815` to adopt a localnet whose anvil was created before the default
moved to 48816. Runtime knobs the e2e suite flips (proof verdict, solder delay) are written to
`$LOCALNET_DATA/run/tuning.env` and picked up by `scripts/nodes.sh` at (re)start; the tracked
`localnet.env` is never edited by a script.

### GOAT backend

`GOAT_BACKEND=anvil` (default) runs a private anvil. `GOAT_BACKEND=testnet3` runs no chain at all:
the `goat-rpc` container (nginx, ~20 MiB) forwards plain HTTP on port +545 to
`GOAT_UPSTREAM_RPC` (default `https://rpc.testnet3.goat.network`, chain id 48816 like the anvil), so
nodes, the fault proxy and graph-node are unchanged. Every reset still deploys a fresh contract stack
of our own there and the subgraph starts at its creation block. Gas comes from `GOAT_FUNDER_KEY`, or
from the file `GOAT_FUNDER_KEY_FILE` (default `$LOCALNET_DATA/secrets/goat-funder.key`, chmod 600,
never in the repo): a funded testnet3 account, one per data dir, since two localnets sharing a funder
race on its nonce. The role top-ups default to 0.0005 below 0.0002 (anvil: 100 below 10); the reset
keeps `state/keys.json`, so the roles keep their balances between runs. Set the backend per data dir
in `localnet.override.env`, then reset; `chaos.sh infra pause goat` pauses whichever GOAT container
runs. The public chain brings its limits: an RPC outage fails the run, and anyone can call the
deployed contracts.

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

`contracts/` contains the L2 contracts used by the local deployment. The
Gateway must recognize Guardian output index 3 in Kickoff. The local GOAT chain
uses chain ID 48816 so it accepts the node's Regtest transaction metadata.

`contracts-local/` is a second foundry project that imports the submodule (`bitvm-l2/` remapping):

- `GatewayLocal.sol` = upstream `GatewayUpgradeable` + two committee-only knobs: `debugMintPegBTC`
  (pegBTC faucet for the peg-out cases) and `debugSetResponseWindowBlocks` (the initializer fixes
  200 goat blocks; the deploy lowers it to `RESPONSE_WINDOW_BLOCKS`, default 50). Runtime size
  23,930 B, ~650 B under the EIP-170 limit: keep additions tiny.
- `MockBitcoinSPV.sol`, `MockWGBTC.sol`: the SPV relay and the stake token, our own instances on either backend.
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

## CI

`.github/workflows/e2e_localnet.yml` runs on the self-hosted `bitvm2-node` runner on every push to
`main` / `dev` and on manual dispatch, with `GOAT_BACKEND=testnet3` (Actions → "Localnet e2e" → Run workflow); the same triggers
as `ci_time_consuming.yml`. It is informational, not a required check. One run is build →
`make localnet-reset` → `make e2e` → stop, about two hours; runs queue (`concurrency:
localnet-e2e`) and a running one is never cancelled.

The CI localnet is a third, private one: `LOCALNET_DATA=/data/actions-runner-bitvm2-node/cache/localnet-e2e/data`,
`PORT_BASE=25000`, `COMPOSE_PROJECT=bvci`, `CARGO_TARGET_DIR=.../localnet-e2e/target`, and the
funder key in `.../localnet-e2e/goat-funder.key` on the runner host (outside the data dir). The data dir
is kept between runs (keys, solc and node_modules caches; the reset wipes chains and node DBs), and
the last 10 result dirs stay in it. The job summary shows `report.md`; the run's result dir
(`report.json`, per-case logs, `logs.tar.gz`) is uploaded as the `localnet-e2e-<run id>` artifact for
14 days. The runner user needs docker, passwordless `sudo` for the p2p case (otherwise it is
reported as SKIP), the zkm toolchain and a free 25000–25999 port range. To reproduce a CI failure
locally, run the same three make targets with the same variables (any free `PORT_BASE`, and a
funder key of your own).

## Known limits

- Mocked verdicts: proof-validity branches test the mock policy (`MOCK_GC_PROOF_VERDICT`), not cryptography.
- A node whose DB predates a migration the binary cannot apply dies at start; `up.sh` reports it, the fix is a reset.
- All ports bind loopback; the p2p listener too (`P2P_LISTEN_IP=127.0.0.1`).
