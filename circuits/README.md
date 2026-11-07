# BitVM Circuits

The proof system connects Bitcoin chain evidence, sequencer commitments, and
GOAT execution to the bridge's claims and disputes. The initial trust anchor is
a GOAT snapshot containing a sequencer set and an EVM block hash.

See the [transaction graph](../transaction-graph.svg) for where proofs and
public-input commitments enter the Bitcoin protocol.

## Proof composition

| Proof | Purpose |
|-------|---------|
| Header chain | Establish Bitcoin headers and accumulated work |
| Commit chain | Establish sequencer-set commitments and publisher transitions |
| State chain | Verify GOAT execution, withdrawal state, and sequencer agreement |
| Watchtower | Authenticate a chain claim using the three chain proofs |
| Operator | Verify the withdrawal claim and evaluate indexed Watchtower evidence |

A Watchtower proof binds its sequencer commitment to Bitcoin inclusion and the
corresponding sequencer and state history. The Operator proof checks the graph's
Watchtower evidence and withdrawal state. For a valid claim from the same
genesis, the Operator's chain must have at least the claimed work and commitment
inclusion height.

The Operator proof is used by the assertion flow. Its static public input is
bound during graph setup; its dynamic public input is committed after the
Watchtower challenge set is known.

## Build and inspect

Run from the repository root:

```bash
cargo build -r -p header-chain-proof -p commit-chain-proof -p state-chain-proof \
  -p watchtower-proof -p operator-proof
cargo run -r -p operator-proof --bin operator-proof -- --help
```

For continuous proof generation and task recovery, use the
[Proof Builder](../proof-builder-rpc/README.md). For complete local bridge
scenarios, use the [end-to-end suite](../localnet/e2e/README.md).

## Proof compatibility

Program changes and proof-system upgrades can change verification keys. Nodes
and proof workers must agree on the programs, network, and verification keys
used for a graph. Rebuild chain proofs when an upgrade cannot verify the previous
proof artifacts.

A graph's committed public inputs and presignatures cannot be changed by updating
its stored parameters. Treat compatibility of existing graphs separately from
admission of newly created graphs.
