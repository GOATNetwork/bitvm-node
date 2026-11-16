# Deployment Guide

A deployment consists of Committee, Operator, Verifier and Watchtower nodes,
with Committee nodes optionally acting as Relayers. The [node guide](../node/README.md)
describes their roles, and the [transaction graph](../transaction-graph.svg)
shows their Bitcoin claim and dispute paths.

## Build

Run from the repository root:

```bash
source ~/.zkm-toolchain/env
cargo build -r -p bitvm-noded --bin bitvm-noded
./target/release/bitvm-noded --help
```

## Prepare participants

1. Select the intended Bitcoin and GOAT networks and deployed bridge contracts.
2. Register each participant's identity for its role and fund the required
   Bitcoin and GOAT accounts.
3. Choose the proof service and peer network shared by the participants.
4. Give each node isolated persistent state and distinct listening addresses.
   A Committee node keeps its instance keys in `cache/committee-instance-keys`
   next to its database file, or in `COMMITTEE_INSTANCE_KEYS_DIR`. Keep that
   directory on the same persistent storage as the database, and never restore
   either from an older snapshot.
5. Start the nodes and confirm they are ready before initiating bridge activity.

All participants must agree on the graph parameters, Verifier slot count, and
proof programs used for new graphs. Existing finalized graphs retain the values
committed when they were created.

## Operate

Run nodes under a supervisor so interrupted processes restart. Retain their
persistent state across restarts. Monitor readiness, chain progress, peers, and
failed work with the [operator tools](../scripts/ops/README.md).

Keep operational monitoring on a private network. Follow the
[Proof Builder guide](../proof-builder-rpc/README.md) for proof coordination and
recovery. Use the [localnet](../localnet/README.md) to test changes before a live
deployment.
