# BitVM Node

`bitvm-noded` coordinates bridge participants on Bitcoin and GOAT L2. It monitors
both chains, builds and signs transaction graphs, exchanges protocol messages,
and coordinates proof generation and disputes.

## Bitcoin transaction graph

[![BitVM Bitcoin transaction graph with per-input sighash labels](../transaction-graph.svg)](../transaction-graph.svg)

Open the [full-size SVG](../transaction-graph.svg) for connector wiring, CSV
paths, competing spends, PreKickoff slots, and per-input authorization types.
The legend explains the signature notation.

- **Peg-in:** the deposit funds Z; confirmation creates C0, while refund is the
  competing path.
- **Claims:** Take-1 reimburses the Operator after A's CSV delay. Take-2 requires
  C0, D, F and G and must satisfy both D's and F's CSV delays.
- **Disputes:** Watchtower and Verifier branches prevent claims by spending
  required outputs. Verifier-Assert is also called ChallengeAssert;
  Pubin-Disprove spends D directly.

## Roles

| Role | Responsibility |
|------|----------------|
| Committee | Presign transactions and endorse peg-ins and graphs |
| Operator | Build graphs, publish assertions, and execute claims |
| Verifier | Prepare circuits, verify assertions, and submit disproofs |
| Watchtower | Monitor Bitcoin and submit Watchtower challenges |
| Relayer | Committee mode that posts data to GOAT and serves graph requests |

## Execution

Chain observations, admitted messages, and job results enter a durable inbox.
Instance and Graph aggregates apply events and schedule work. Heavy setup,
signing, proof generation, and network calls run as jobs; results return through
the inbox. Persistent state lets interrupted work resume after restart.

The Instance aggregate handles peg-in validation and signing. The Graph
aggregate handles setup, presigning, claims, and disputes. Missing graph
definitions are retrieved from peers and authenticated before use.

## Build and run

Run from the repository root:

```bash
cargo build -r -p bitvm-noded --bin bitvm-noded
./target/release/bitvm-noded --help
```

See the [deployment guide](../deployment/README.md) for running participants and
the [operator tools](../scripts/ops/README.md) for diagnosis.

### Local testnets

Use the [localnet guide](../localnet/README.md) to run the bridge with mocked
proof machinery. Mock builds are for local testing only.

## Related documentation

- [Project overview and graph checks](../README.md)
- [Circuits](../circuits/README.md)
- [Proof Builder](../proof-builder-rpc/README.md)
- [Incentives](../docs/incentives.md)
