# GOAT BitVM Node

GOAT Network's BitVM bridge implementation. See [GOAT BitVM Whitepaper](https://www.goat.network/bitvm2-whitepaper) for more details.

## Layout

- `node/`: Main node implementation, including P2P, RPC, and scheduled tasks
- `circuits/`: Circuits and proof generation logic
- `proof-builder-rpc/`: RPC server for offloading proof generation to a separate process
- `crates/`: Shared Rust crates for common types and utilities
- `deployment`: Deployment scripts and documentation


## Formal verification (TLA+)

`node/tla/` contains TLA+ specs that formally verify the graph/instance status
state machines and the peg-out timelock configuration against real races and
boundary conditions found in the Rust implementation. This started as an
**audit pass**: the specs proved several real bugs existed and proved a
correct fix design for each. **As of commit
[`991faaa`](https://github.com/GOATNetwork/bitvm-node/commit/991faaabdb56c747103e8f1c6d6477c638ccfc4c),
all 8 of those findings have been fixed and verified in the shipped Rust
code** - see `audit/TLAPlus-20260630.md` for the full report, including what
each real applied fix looks like.

**CI runs every spec on every pull request** (the `tla-plus` job, in
parallel with fmt/clippy/test). Each config is listed in the job with a tier
that says what TLC's result must be:

- **pass** - a fix or baseline design; must verify clean, otherwise the
  design regressed.
- **historical** - a bug already fixed in the code. The config deliberately
  still models the pre-fix code and is kept as a **permanent regression
  record**: it must still reproduce its counterexample. An unexpected pass
  means the spec stopped demonstrating the bug, or the fix was reverted.
- **live** - a known, still-unfixed bug; while its config reproduces the
  counterexample it blocks merge. Fix the code, then move the row to
  `historical`.

The outcome is taken from TLC's exit status, so a config on which TLC does
not finish (parse error, missing file) fails the job in every tier. Each
finding therefore has a **pair** of configs - one modeling the pre-fix code
(**expected to fail**) and one modeling the fix design (**expected to
pass**) - and the table below gives both.

**Setup** (once): install a JRE (11+) and download the official TLA+ tools jar:

```bash
sudo apt-get install -y openjdk-21-jre-headless   # or any JRE 11+
mkdir -p ~/.local/share/tlaplus
curl -sL -o ~/.local/share/tlaplus/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```

**Run a spec**:

```bash
cd node/tla
java -jar ~/.local/share/tlaplus/tla2tools.jar -config <Spec>.cfg <Spec>.tla
```

| Spec | Config | Models | Result |
|---|---|---|---|
| `GraphLifecycle.tla` | `GraphLifecycleCoreOnly.cfg` | code baseline | pass - chain-scan state machine alone is sound |
| `GraphLifecycle.tla` | `GraphLifecycle.cfg` | **pre-fix code (historical)** | **fails, by design**: unguarded race between the Bitcoin-chain-scan and GoatChain-event writers of `Graph.status` - fixed in `991faaa`, kept failing as a permanent regression check |
| `GraphLifecycle.tla` | `GraphLifecycleFixed.cfg` | fix design (**applied in `991faaa`**) | pass - atomic guard design closes the race |
| `GraphLifecycleFineGrained.tla` | `GraphLifecycleFineGrained.cfg` | pre-fix code (historical) | **fails, by design**: the read/write gap a naive (non-atomic) guard would still have - fixed in `991faaa` |
| `GraphLifecycleFineGrainedFixed.tla` | `GraphLifecycleFineGrainedFixed.cfg` | fix design (**applied in `991faaa`**) | pass - single-statement atomic CAS design closes the gap |
| `InstancePresigned.tla` | `InstancePresignedBug.cfg` | **pre-fix code (historical)** | **fails, by design**: `Instance.status` can regress past `Presigned` - fixed in `991faaa` |
| `InstancePresigned.tla` | `InstancePresignedFixed.cfg` | fix design (**applied in `991faaa`**) | pass - guard design closes the regression |
| `Take2DisproveRace.tla` | `Take2DisproveRace.cfg` | fix design (**applied in `991faaa`**, values updated to match) | pass - Take2 vs. Disprove UTXO race has strict margin on all networks with the real shipped `crates/bitvm-gc/src/timelocks.rs` values (Testnet4 `connector_d` now 40, shipped with more margin than originally proposed); the pre-fix shipped value (34) did **not** have this margin - that boundary case is how this spec found the bug in the first place |
| `MultiActorRace.tla` | `MultiActorRace.cfg` | fix design (**applied in `991faaa`**, values updated to match) | pass - the 1-of-N watchtower/verifier security property holds under the real shipped timelock values, checked against 2 independent actors per role rather than 1 |
| `InstanceBridgeOutRace.tla` | `InstanceBridgeOutRace.cfg` | **pre-fix code (historical)** | **fails, by design**: `InstanceBridgeOutStatus` can be resurrected to `Initialize` after reaching `Claim`/`Timeout`/`Refund` by a stale RPC upsert or maintenance-task write - fixed in `991faaa` |
| `InstanceBridgeOutRace.tla` | `InstanceBridgeOutRaceFixed.cfg` | fix design (**applied in `991faaa`**) | pass - atomic guard design (write only if not already terminal) closes the resurrection |
| `MessageStateRace.tla` | `MessageStateRace.cfg` | **pre-fix code (historical)** | **fails, by design**: `MessageState::Cancelled` could be resurrected to `Pending` by `upsert_message`'s unconditional `ON CONFLICT DO UPDATE` - fixed in `991faaa` |
| `MessageStateRace.tla` | `MessageStateRaceFixed.cfg` | fix design (**applied in `991faaa`**) | pass - guarding the resurrect-to-Pending write against terminal status closes the race |
| `Take1ChallengeRace.tla` | `Take1ChallengeRace.cfg` | **pre-fix code (historical)** | **fails, by design**: `connector_a` (Take1 vs. Challenge) had *no* margin check anywhere in `validate_timelock_config`; on Regtest the pre-fix shipped value gave a challenger exactly zero reaction margin - fixed in `991faaa` |
| `Take1ChallengeRace.tla` | `Take1ChallengeRaceFixed.cfg` | fix design (**applied in `991faaa`**) | pass - the missing margin check (mirroring Finding 4's floor) was added, closing the gap |
| `VerifierKickoffFailOpen.tla` | `VerifierKickoffFailOpen.cfg` | **pre-fix code (historical)** | **fails, by design**: issue #429 - the verifier consumed `KickoffSent` while GOAT SPV lagged the kickoff and never retried, so no Challenge was sent - fixed in #455 |
| `VerifierKickoffFailOpen.tla` | `VerifierKickoffFailOpenFixed.cfg` | fix design (**applied in #455**) | pass - deferring the message until SPV catches up guarantees the Challenge fires before Take1 |
| `KickoffScanCoverage.tla` | `KickoffScanCoverage.cfg` | **pre-fix code (historical)** | **fails, by design**: issue #431 - `detect_kickoff` watched only the lowest-nonce graph per operator, so a kickoff on a later graph was never observed - fixed in #451 |
| `KickoffScanCoverage.tla` | `KickoffScanCoverageResidual.cfg` | **pre-fix code (historical)** | **fails, by design**: #451's chain walk was capped at 32 successors, so a kickoff deeper than that escaped a single round - fixed by removing the cap and running the scan as its own task |
| `KickoffScanCoverage.tla` | `KickoffScanCoverageFixed.cfg` | fix design (**current code**) | pass - the uncapped walk from the root reaches every graph on the confirmed pre-kickoff chain |
| `MultiActorRace.tla` | `MultiActorRace.cfg` | verification (no bug; still holds under real shipped values) | pass - also confirms `operator_commit`'s margin against the shared `ConnectorF` UTXO (the `OperatorCommitTimeoutTransaction` path, `ConnectorF` leaf 1's second spender) holds, closing a gap where only a scalar Rust check existed |

Additional standalone tools available in the jar if needed: SANY (parser/type-checker)
via `java -cp tla2tools.jar tla2sany.SANY <Spec>.tla`, and the PlusCal translator
(used to generate `GraphLifecycleFineGrained*.tla`'s TLA+ body from its PlusCal
algorithm block) via `java -cp tla2tools.jar pcal.trans <Spec>.tla`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.