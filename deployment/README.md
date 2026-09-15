# Deployment Guide

This document describes how to deploy the different roles in the BitVM system: Committee, Operator, Challenger, Watchtower, and Relayer, by manually compiling and running the [node](../node/README.md).

## Prerequisites

Before building and running the node, ensure you have the following installed:

- **Rust Toolchain**: Latest stable version.
- **ZKM Toolchain**: Required for compiling the circuits.
  - Ensure the toolchain is installed in `~/.zkm-toolchain`.
  - You need to source the environment before building: `source ~/.zkm-toolchain/env`.

## Build

1.  **Source the ZKM Toolchain environment:**

    ```bash
    source ~/.zkm-toolchain/env
    ```

2.  **Build the project in release mode:**

    ```bash
    cargo build -r --all-targets
    ```

    The compiled binary will be located at `target/release/bitvm-noded`.

## Configuration

The node loads environment variables from a `.env` file in the current working directory.

### Common Environment Variables

Create a `.env` file and include necessary environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `ACTOR` | The role of the node (`Committee`, `Operator`, `Challenger`, `Watchtower`) | Yes |
| `BITCOIN_NETWORK` | Bitcoin network (`bitcoin`, `testnet`, `regtest`) | Yes |
| `GOAT_NETWORK` | Goat network (`main`, `test`) | Yes |
| `GOAT_CHAIN_URL` | RPC URL for the Goat chain | Yes |
| `GOAT_PROOF_BUILD_URL` | URL for the proof builder service | Yes |
| `PROOF_SEVER_URL` | URL for the proof server | Yes |
| `PEER_KEY` | The private key for the P2P node identity (libp2p) | Yes |
| `GOAT_GATEWAY_CONTRACT_ADDRESS` | Address of the Gateway contract on Goat | Yes |
| `GOAT_GATEWAY_EVENT_FILTER_FROM` | The block number to start filtering Gateway events from | Yes |
| `GOAT_GATEWAY_EVENT_THE_GRAPH_URL` | The Graph URL for querying Gateway events | Yes |
| `BITVM_SECRET` | Secret key or seed  for BTC interaction | Yes |
| `GOAT_ADDRESS` | The Goat chain address of the operator/node | Yes |
| `PROTO_NAME` | The P2P protocol name (default: `bitvm`) | Yes |
| `GOAT_PRIVATE_KEY` | Private key for the Goat chain interaction | Optional |
| `GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS` | Address of the Sequencer Set Publisher contract | Optional |
| `GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS` | Address of the MultiSig Verifier contract | Optional |
| `GOAT_SWAP_CONTRACT_ADDRESS` | Address of the Swap contract on Goat | Optional |
| `GOAT_SWAP_EVENT_FILTER_FROM` | The block number to start filtering Swap events from | Optional |
| `GOAT_SWAP_EVENT_THE_GRAPH_URL` | The Graph URL for querying Swap events | Optional |
| `BOOTNODES` | Multiaddr of bootnodes for P2P discovery | Optional |
| `NODE_NAME` | The name of the node | Optional |
| `MIN_REQUIRED_VERIFIER` | Positive verifier-slot count for newly created graphs (default: `1`); must be identical on all participating nodes | Optional |

`MIN_REQUIRED_VERIFIER` changes the transaction topology of newly created graphs. It does not add Verifier slots to existing finalized graphs, which continue to use the slots embedded when they were created. Configure the same value on every Operator, Verifier, Committee, Watchtower, and Relayer node before creating new graphs.

## Roles Deployment

Configure the `.env` file for the specific role and run the node.

**Common Arguments:**

- `--rpc-addr <ADDR>`: Address for the RPC server (default: `0.0.0.0:8080`)
- `--metrics-addr <ADDR>`: Address for the dedicated Prometheus listener (disabled when omitted)
- `--metrics-path <PATH>`: Path served by the metrics listener (default: `/metrics`)
- `--db-path <PATH>`: Path to the SQLite database (default: `sqlite:/tmp/bitvm-node.db`)
- `--p2p-port <PORT>`: Port for P2P communication (default: `0`)
- `--bootnodes <MULTIADDR>`: Bootnodes to connect to 

Bind metrics to a private interface and use a unique port for every node running
on the same host. The business RPC listener does not serve metrics, so
`GET /metrics` on `--rpc-addr` returns `404`. For remote Prometheus servers,
expose the dedicated listener through a private network, proxy, or access-control
layer instead of binding it directly to a public interface.

The provided Docker Compose deployment enables the listener on port `9108`
inside each container and publishes it only on the host loopback interface:

| Service | Host metrics endpoint |
|---------|-----------------------|
| `committee_0` | `http://127.0.0.1:9900/metrics` |
| `committee_1` | `http://127.0.0.1:9901/metrics` |
| `verifier_0` | `http://127.0.0.1:9902/metrics` |
| `operator_0` | `http://127.0.0.1:9903/metrics` |
| `watchtower_0` | `http://127.0.0.1:9904/metrics` |

### Committee

The Committee is responsible for signing presign transactions.

**example `.env`:**

```env
RUST_LOG=info

# required
ACTOR=Committee
BITCOIN_NETWORK=testnet # bitcoin / testnet / regtest
GOAT_NETWORK=test # main / test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_PROOF_BUILD_URL=...
PROOF_SEVER_URL=...
PEER_KEY=...
BITVM_SECRET=...  # committee can setup a seed string
GOAT_ADDRESS=...
GOAT_GATEWAY_CONTRACT_ADDRESS=0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=https://api.goat.0xgraph.xyz/api/public/1030419e-065f-45e9-8cf5-69c42207cbc7/subgraphs/bitvm2_gateway_ga_dev_0/0.0.3/gn
GOAT_GATEWAY_EVENT_FILTER_FROM=9689342
PROTO_NAME=bitvmt3
BOOTNODES=... # empty if this is the first node

# optional, relayer only
ENABLE_RELAYER=true
GOAT_PRIVATE_KEY=...

# optional, RPC server only
GOAT_SWAP_CONTRACT_ADDRESS=0xe510D5781C6C849284Fb25Dc20b1684cEC445C8B
GOAT_SWAP_EVENT_THE_GRAPH_URL=https://api.goat.0xgraph.xyz/api/public/1030419e-065f-45e9-8cf5-69c42207cbc7/subgraphs/escrow_manager_ga_dev_0/0.0.1/gn
GOAT_SWAP_EVENT_FILTER_FROM=9368978
```

**Run Command:**

```bash
./target/release/bitvm-noded \
  --rpc-addr 0.0.0.0:9100 \
  --metrics-addr 127.0.0.1:9108 \
  --p2p-port 8443 \
  --db-path ./committee.db
```

### Operator

The Operator manages the bridge operations.

**Add to `.env`:**

```env
RUST_LOG=info

# required
ACTOR=Operator
BITCOIN_NETWORK=testnet # bitcoin / testnet / regtest
GOAT_NETWORK=test # main / test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_PROOF_BUILD_URL=...
PROOF_SEVER_URL=...
PEER_KEY=...
BITVM_SECRET=...  # operator should setup its BTC private key
GOAT_ADDRESS=...
GOAT_GATEWAY_CONTRACT_ADDRESS=0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=https://api.goat.0xgraph.xyz/api/public/1030419e-065f-45e9-8cf5-69c42207cbc7/subgraphs/bitvm2_gateway_ga_dev_0/0.0.3/gn
GOAT_GATEWAY_EVENT_FILTER_FROM=9689342
PROTO_NAME=bitvmt3
BOOTNODES=... # empty if this is the first node
```

**Run Command:**

```bash
./target/release/bitvm-noded \
  --rpc-addr 0.0.0.0:9100 \
  --metrics-addr 127.0.0.1:9108 \
  --p2p-port 8443 \
  --db-path ./operator.db
```

### Challenger

The Challenger verifies the operations and submits challenges if necessary.

**Add to `.env`:**

```env
RUST_LOG=info

# required
ACTOR=Challenger
BITCOIN_NETWORK=testnet # bitcoin / testnet / regtest
GOAT_NETWORK=test # main / test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_PROOF_BUILD_URL=...
PROOF_SEVER_URL=...
PEER_KEY=...
BITVM_SECRET=...  # operator should setup its BTC private key
GOAT_ADDRESS=...
GOAT_GATEWAY_CONTRACT_ADDRESS=0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=https://api.goat.0xgraph.xyz/api/public/1030419e-065f-45e9-8cf5-69c42207cbc7/subgraphs/bitvm2_gateway_ga_dev_0/0.0.3/gn
GOAT_GATEWAY_EVENT_FILTER_FROM=9689342
PROTO_NAME=bitvmt3
BOOTNODES=... # empty if this is the first node
```

**Run Command:**

```bash
./target/release/bitvm-noded \
  --rpc-addr 0.0.0.0:9100 \
  --metrics-addr 127.0.0.1:9108 \
  --p2p-port 8443 \
  --db-path ./challenger.db
```

### Watchtower

The Watchtower submit the btc-chain-proof when needed.

**Add to `.env`:**

```env
RUST_LOG=info

# required
ACTOR=Watchtower
BITCOIN_NETWORK=testnet # bitcoin / testnet / regtest
GOAT_NETWORK=test # main / test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_PROOF_BUILD_URL=...
PROOF_SEVER_URL=...
PEER_KEY=...
BITVM_SECRET=...  # operator should setup its BTC private key
GOAT_GATEWAY_CONTRACT_ADDRESS=0x21f619040AC2eAcacEF8Fe17Ae8bDF53ec69C66f
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=https://api.goat.0xgraph.xyz/api/public/1030419e-065f-45e9-8cf5-69c42207cbc7/subgraphs/bitvm2_gateway_ga_dev_0/0.0.3/gn
GOAT_GATEWAY_EVENT_FILTER_FROM=9689342
PROTO_NAME=bitvmt3
BOOTNODES=... # empty if this is the first node
```

**Run Command:**

```bash
./target/release/bitvm-noded \
  --rpc-addr 0.0.0.0:9100 \
  --metrics-addr 127.0.0.1:9108 \
  --p2p-port 8443 \
  --db-path ./watchtower.db
```

For `sequencer-set-publish` and `proof-builder-rpc` deployment and failure recovery, please refer to the [Proof Builder RPC README](../proof-builder-rpc/README.md) for detailed instructions.
