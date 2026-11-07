# Deployment Guide

Deploy Committee, Operator, Verifier and Watchtower nodes with `bitvm-noded`.
Relayer is a Committee mode, enabled with `ENABLE_RELAYER=true`. See the
[node guide](../node/README.md) for configuration and RPC details, and the
[transaction graph](../transaction-graph.svg) for Bitcoin claim and dispute paths.
For a local test environment, use the [localnet guide](../localnet/README.md).

## Build

Run from the repository root:

```bash
source ~/.zkm-toolchain/env
cargo build -r -p bitvm-noded --bin bitvm-noded
```

The binary is `target/release/bitvm-noded`.

## Configure a node

The node loads `.env` from its working directory. Use a separate directory and
SQLite database for each node.

```dotenv
RUST_LOG=info
ACTOR=Verifier
BITCOIN_NETWORK=testnet4
GOAT_NETWORK=test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_GATEWAY_CONTRACT_ADDRESS=<deployed-gateway-address>
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=<gateway-subgraph-query-url>
GOAT_GATEWAY_EVENT_FILTER_FROM=<gateway-deployment-block>
GOAT_PROOF_BUILD_URL=http://127.0.0.1:7777
PEER_KEY=<base64-peer-key>
BITVM_SECRET=<bitcoin-private-key-or-seed>
GOAT_ADDRESS=<registered-goat-address>
```

Replace the placeholders with values for your deployment. Contract addresses,
subgraph URLs and starting blocks must describe the same deployment.
Generate peer and funding keys with the commands in the
[node guide](../node/README.md#generate-node-keys).

| Role | Configuration |
|------|---------------|
| Committee | `ACTOR=Committee`; set `GOAT_PRIVATE_KEY` |
| Operator | `ACTOR=Operator`; set `GOAT_ADDRESS` or `GOAT_PRIVATE_KEY`, and fund the Bitcoin signing key |
| Verifier | `ACTOR=Verifier`; set `GOAT_ADDRESS` or `GOAT_PRIVATE_KEY`, and fund the Bitcoin signing key |
| Watchtower | `ACTOR=Watchtower`; configure its registered Bitcoin signing key |
| Relayer | `ACTOR=Committee`, `ENABLE_RELAYER=true`; set `GOAT_PRIVATE_KEY` |

Optional settings include:

| Variable | Purpose |
|----------|---------|
| `BTC_CHAIN_URL` | Bitcoin Esplora endpoint |
| `PROTO_NAME` | P2P protocol namespace; use the same value for participating nodes |
| `NODE_NAME` | Display name |
| `EXTERNAL_SOCKET_ADDR` | Advertised node RPC socket address; bypasses automatic discovery |
| `GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS` | Sequencer-set publisher contract |
| `ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS` | Sequencer-set multisignature verifier contract |
| `GOAT_SWAP_CONTRACT_ADDRESS` | Swap contract for swap-enabled services |
| `GOAT_SWAP_EVENT_THE_GRAPH_URL` / `GOAT_SWAP_EVENT_FILTER_FROM` | Swap subgraph and starting block |
| `MIN_REQUIRED_VERIFIER` | Verifier slots for new graphs; default `1` |

Set the same positive `MIN_REQUIRED_VERIFIER` on all participating nodes before
creating graphs. Existing finalized graphs retain their original Verifier slots.
The [configuration reference](../node/README.md#configuration) covers engine,
network limits, timeouts and key-retention settings.

## Run

```bash
./target/release/bitvm-noded \
  --rpc-addr 0.0.0.0:9100 \
  --metrics-addr 127.0.0.1:9108 \
  --p2p-port 8443 \
  --db-path 'sqlite:./node.db?mode=rwc'
```

Use `--bootnodes '<multiaddr>'` to join existing peers. The Docker entrypoint
also accepts `BOOTNODES` and passes it to this CLI option. Give each process
its own database and listening ports.

## Health and metrics

`GET /v1/health` on the business RPC listener returns `200` when ready and `503`
otherwise, with readiness and backend status. The node retries an unavailable
GOAT RPC during startup before exiting if initialization still cannot complete.

Prometheus uses the dedicated `--metrics-addr` listener and `/metrics` path.
`GET /metrics` on the business RPC listener returns `404`. Bind metrics to a
private interface and use a distinct port per process.

The [Docker Compose configuration](docker-compose.yml) publishes metrics on
host loopback:

| Service | Host metrics endpoint |
|---------|-----------------------|
| `committee_0` | `http://127.0.0.1:9900/metrics` |
| `committee_1` | `http://127.0.0.1:9901/metrics` |
| `verifier_0` | `http://127.0.0.1:9902/metrics` |
| `operator_0` | `http://127.0.0.1:9903/metrics` |
| `watchtower_0` | `http://127.0.0.1:9904/metrics` |

Use the [operator tools](../scripts/ops/README.md) for health triage, log queries
and instance or graph timelines. Proof service configuration and recovery are
covered in the [Proof Builder RPC guide](../proof-builder-rpc/README.md).
