# Proof Builder

The Proof Builder coordinates header, commit and state-chain proofs, then
produces Operator and Watchtower proofs on demand. See the
[circuits guide](../circuits/README.md) for proof composition and the
[transaction graph](../transaction-graph.svg) for their role in claims and disputes.

## Build and inspect

Run from the repository root:

```bash
cargo build -r -p proof-builder-rpc
cargo run -r -p proof-builder-rpc -- --help
```

## Authorization

Nodes authenticate proof requests with their bridge signing identities. The
service checks Operator ownership of a graph or current Watchtower membership
before accepting work. It supports multiple Gateway deployments on the same
GOAT network, with each request selecting its intended deployment.

The service does not need the nodes' private keys. Replay protection, bounded
concurrency, and request deadlines limit repeated or stalled work.

## Scheduling and recovery

Long-running chain proofs persist their progress. Operator and Watchtower tasks
with unavailable inputs stay pending while later work is checked. Independent
forward and bounded retry scans revisit older tasks under continuing load.

A timeout prevents a subsequently completed proof from overwriting a task that
is no longer pending. Restarting resumes from saved progress; restore proof
artifacts together with the matching service state.

## Fleet workers

Fleet can run the service beside a dedicated GPU server. Proving is serialized
through a shared gate, and completed artifacts are published before progress is
committed. The worker checks program identities and verification keys at startup.

Transient proving failures leave work pending. Invalid inputs have a bounded
attempt count. On shutdown, the worker stops accepting new proving work and
allows in-flight work a bounded time to finish; unfinished work can resume after
restart.

## Operations

Monitor chain-proof progress and pending on-demand tasks alongside node health.
Sequencer-set publication is a separate operation from proof generation. For
bridge deployment and local regression scenarios, see the
[deployment guide](../deployment/README.md) and [localnet](../localnet/README.md).
