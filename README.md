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


## Transaction graph checks

The checks cover critical connector relationships in constructed transactions and
basic maturity relations for the default Bitcoin, Testnet4, Signet and Regtest
parameters:

- Rust tests construct the real transaction graph and check parent outpoints,
  competing spends, and the CSV values in transaction inputs and scripts.
- `audit/tla/TransactionGraph.tla` checks the Take-1 budget, ACK budget,
  timeout order, conditional Disprove maturity, and Take-2's two CSV clocks.
- `tests/tla_shipped_values.rs` checks that the TLA values match Rust. A timing
  change requires regenerating the values and rerunning the checks.

The TLA model is finite, init-only arithmetic. It assumes VerifierAssert confirms
within `action_window` of OperatorAssert for the Disprove comparison. Earlier
maturity does not guarantee earlier confirmation. These checks do not establish
end-to-end bridge safety or liveness, and do not model signatures, proof
validity, fees, relay policy, reorgs, job scheduling, or contract settlement.
Implementation changes outside the tested structure and generated values require
manual review of the model's assumptions.

```bash
# JRE 11+ is needed for TLC.
make tla-setup
cargo test -p bitvm-gc --test transaction_graph_invariants --test tla_shipped_values
make tla
# After changing Rust's timing constants:
make tla-values
make tla
```

Every TLC failure fails CI. There are no expected-failure configurations or
stored traces. Temporary TLC files are removed on exit. `TLA2TOOLS` overrides
the tool jar path; `TLC_OPTS` supplies optional whitespace-separated TLC flags.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.