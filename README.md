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


## Formal verification (TLA+)

`audit/tla/` contains TLA+ specs that model the bridge protocol as the Rust
code implements it: the graph/instance status state machines, the Bitcoin
transaction graph and its timelocks, the node's challenge/dispute reactions,
the job engine, and the GOAT Gateway contract. Each finding has a **pair** of
configs - one modeling the current (or pre-fix) code, **expected to fail** with
a TLC counterexample, and one modeling a fix design, **expected to pass**.

- **Round 1** (`audit/TLAPlus-20260710.md`): 8 findings, **all fixed** in
  [`991faaa`](https://github.com/GOATNetwork/bitvm-node/commit/991faaabdb56c747103e8f1c6d6477c638ccfc4c);
  plus issues #429 and #431, fixed by #455, #451 and #476.
- **Round 2** (2026-10-31, protocol review of dev @ `60562f8`): the dispute
  defences, the assert scripts, the kickoff challenge gate, the Gateway
  withdraw lifecycle, the job engine and the peg-in. These findings are **not
  fixed yet**: their configs are `live`, so the `tla-plus` job **stays red until
  the code is fixed** - by design.

`audit/tla/specs.txt` is the single list of what runs and what each result
must be (`tier | config | spec | description`). CI (`tla-plus` job, every pull
request, in parallel with fmt/clippy/test) and `make tla` run the same list
through `audit/tla/check.sh`:

- **pass** - a fix or baseline design; must verify clean, otherwise the
  design regressed.
- **historical** - a bug already fixed in the code. The config deliberately
  still models the pre-fix code and is kept as a **permanent regression
  record**: it must still reproduce its counterexample. An unexpected pass
  means the spec stopped demonstrating the bug, or the fix was reverted.
- **live** - a known, still-unfixed bug; while its config reproduces the
  counterexample it fails the run and blocks merge. Fix the code, then move
  the row to `historical` (a frozen spec cannot see the code fix by itself).

The outcome is taken from TLC's exit status, so a config on which TLC does
not finish (parse error, missing file) fails in every tier.

**Setup** (once): install a JRE (11+), then download the official TLA+ tools jar:

```bash
sudo apt-get install -y openjdk-21-jre-headless   # or any JRE 11+
make tla-setup                                    # -> ~/.local/share/tlaplus/tla2tools.jar
```

**Run**:

```bash
make tla                                  # the whole table; exit 1 while any live bug reproduces
make tla SPEC=ChallengeKickoffGateC6.cfg  # one config
make tla SPEC=ChallengeKickoffGate.tla    # every config of one spec
make tla TLC_OPTS="-workers auto"         # extra TLC flags

# or TLC directly
cd audit/tla && java -jar ~/.local/share/tlaplus/tla2tools.jar -config <Config>.cfg <Spec>.tla
```

### Round 1 and issues #429 / #431

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
| `VerifierKickoffFailOpen.tla` | `VerifierKickoffFailOpenFixed.cfg` | fix design (**applied in #455**) | pass - deferring the message until SPV catches up makes the Challenge fire before Take1, provided SPV catches up before `connector_a` expires (a fairness assumption of the model; a SPV lag longer than `connector_a` is not modeled) |
| `KickoffScanCoverage.tla` | `KickoffScanCoverage.cfg` | **pre-fix code (historical)** | **fails, by design**: issue #431 - `detect_kickoff` watched only the lowest-nonce graph per operator, so a kickoff on a later graph was never observed - fixed in #451 |
| `KickoffScanCoverage.tla` | `KickoffScanCoverageResidual.cfg` | **pre-fix code (historical)** | **fails, by design**: #451's chain walk was capped at 32 successors, so a kickoff deeper than that escaped a single round - fixed by #476, whose `scan_graphs_on_chain` visits every monitored graph |
| `KickoffScanCoverage.tla` | `KickoffScanCoverageFixed.cfg` | fix design (**current code**) | pass - every graph on the confirmed pre-kickoff chain is reached, with no depth cap (since #476: a round-robin over all monitored graphs, `node/src/aggregates/graph_scan.rs`) |
| `MultiActorRace.tla` | `MultiActorRace.cfg` | verification (no bug; still holds under real shipped values) | pass - also confirms `operator_commit`'s margin against the shared `ConnectorF` UTXO (the `OperatorCommitTimeoutTransaction` path, `ConnectorF` leaf 1's second spender) holds, closing a gap where only a scalar Rust check existed |

### Round 2: protocol review (live until fixed)

C/H/M/F are the review's severity labels (critical, high, medium, low). Each spec's header quotes the code it
models with file:line.

| Spec | Config | Models | Result |
|---|---|---|---|
| `DisputeObligations.tla` | `DisputeObligationsC1.cfg` | **current code (live)** | **fails** `NoTake2WithInvalidProof`: C1 - one watchtower never challenged nor timed out keeps `all_resolved` false (`graph_scan.rs`): no NACK, no Commit-Timeout, and `verifier_assert` waits for connector-E -> Take-2 with an invalid proof |
| `DisputeObligations.tla` | `DisputeObligationsC1LateCommit.cfg` | **current code (live)** | **fails** `NoTake2WithInvalidProof`: all branches resolved, commit-pubin just before Commit-Timeout; ChallengeAssert only starts then and `operator_commit + prover_connector >= connector_f` on every network |
| `DisputeObligations.tla` | `DisputeObligationsC1NoPubin.cfg` | **current code (live)** | **fails** `NoTake2WithoutPubin`: Commit-Timeout gated on `all_resolved`; ACK via the hashlock leaf without a challenge -> Take-2 never bound to watchtower evidence |
| `DisputeObligations.tla` | `DisputeObligationsC2.cfg` | **current code (live)** | **fails** `NoTake2WithInvalidProof`: C2 - an early Assert cancels every `JOB_WATCHTOWER_CHALLENGE` (`graph_pegout.rs`, terminal) although the challenge is still valid on chain |
| `DisputeObligations.tla` | `DisputeObligationsC2Silenced.cfg` | **current code (live)** | **fails** `OnlineWatchtowerChallengeLands`: with C1 fixed, an early Assert still keeps every honest watchtower's challenge off chain |
| `DisputeObligations.tla` | `DisputeObligationsFixed.cfg` | fix design | pass - Commit-Timeout at `operator_commit` regardless of branches, NACK every unspent Ack, invalid proof challenged without waiting for commit-pubin, no cancel on Assert |
| `AssertFrontRun.tla` | `AssertFrontRun.cfg` | **current code (live)** | **fails** `NoTake2AfterValidChallenge`: C3 - VerifierConnector leaf 0 has no CHECKSIG; the operator copies the ChallengeAssert witness, `ProverConn_j` never exists, the presigned Disprove is invalid |
| `AssertFrontRun.tla` | `AssertFrontRunC4.cfg` | **current code (live)** | **fails** `HonestOperatorCanSettle`: C4 - ConnectorC leaf 1 is OP_2DROP + WOTS only; any watcher redirects the OperatorAssert, ConnectorD never exists, Take1 and Take2 both dead |
| `AssertFrontRun.tla` | `AssertFrontRunPiMalleable.cfg` | **current code (live)** | **fails** `HonestOperatorCanSettle`: pi2/pi3 sit under OP_2DROP, so a swap keeps the txid; verifier and operator both read them from the chain -> honest operator Disproved, even with both CHECKSIGs |
| `AssertFrontRun.tla` | `AssertFrontRunFixed.cfg` | fix design | pass - n-of-n SIGHASH_ALL presignature binds the VerifierAssert |
| `AssertFrontRun.tla` | `AssertFrontRunC4Fixed.cfg` | fix design | pass - operator CHECKSIG ALL on C leaf 1 + n-of-n CHECKSIG on VerifierConnector + pi2/pi3 in signed data |
| `DefenderTxPinning.tla` | `DefenderTxPinning.cfg` | **current code (live)** | **fails** `DefenderConfirmsBeforeDeadline`: M3 - v2 NACK/CommitTimeout/Disprove at ~1.2 sat/vB with a keyless P2A; a large sub-market child forces a BIP125 rule-3 overpay beyond the defender's budget |
| `DefenderTxPinning.tla` | `DefenderTxPinningFixed.cfg` | fix design | pass - v3/TRUC bounds the pin (VerifierAssert, ~60 kvB, stays a residual) |
| `RoundPenalty.tla` | `RoundPenalty.cfg` | **current code (live)** | **fails** `LateKickoffPenalized`: M5 - operator-key ForceSkipConn_{i+1} is burned at round i+1; a late Kickoff_i reaches Take with no penalty |
| `RoundPenalty.tla` | `RoundPenaltyFixed.cfg` | fix design | pass - n-of-n ForceSkipConnector keeps QuickChallenge_i valid |
| `ChallengeKickoffGate.tla` | `ChallengeKickoffGateC5.cfg` | **current code (live)** | **fails** `NoDoublePayment`: C5 - kickoff first, `initWithdraw` once SPV covers it -> `proceedWithdraw` reverts `KickoffHeightLow` forever; `challenge_kickoff` waits on `Initialized` forever; Take1 + a manual cancel pays twice |
| `ChallengeKickoffGate.tla` | `ChallengeKickoffGateC6.cfg` | **current code (live)** | **fails** `NoUnauthorizedTake1`: C6 - the gate waits for GOAT SPV with no `connector_a` deadline; drops the SPV-catches-up fairness assumption of `VerifierKickoffFailOpenFixed.cfg` |
| `ChallengeKickoffGate.tla` | `ChallengeKickoffGateC6Testnet4.cfg` | **current code (live)** | **fails** `NoUnauthorizedTake1`: shipped Testnet4 values - SPV posts up to tip - `BTC_BLOCK_CONFIRMS` (10) while `connector_a` is 6, so the gate can never fire before Take1, even with a healthy SPV (Signet and Regtest likewise) |
| `ChallengeKickoffGate.tla` | `ChallengeKickoffGateH4.cfg` | **current code (live)** | **fails** `NoUnauthorizedTake1`: H4 - maintenance skips `scan_graphs_on_chain` during the Goat history sync, so `challenge_kickoff` is never queued |
| `ChallengeKickoffGate.tla` | `ChallengeKickoffGateFixed.cfg` | fix design | pass - challenge a poisoned `Initialized`, contest at the `connector_a` deadline unless `Processing`, scan not gated on history sync, cancel rejected once the kickoff is provable |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleH1.cfg` | **current code (live)** | **fails** `DisprovedOperatorSlashed`: H1 - kickoff without `initWithdraw`, disproved; the relayer gives up on withdraw status None |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleH1Node.cfg` | **current code (live)** | **fails** `NodeTracksDisprove`: the event carries instanceId 0 and the watcher drops it |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleH1Fixed.cfg` | fix design | pass - relay None, key `WithdrawDisproved` by graph |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleM1.cfg` | **current code (live)** | **fails** `PegInRecoverable`: M1 - `finishWithdrawDisproved` never resets the pegin, the instance stays Locked |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleM1Escrow.cfg` | **current code (live)** | **fails** `EscrowAccounted`: a disprove while Initialized strands `lockAmount` |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleM1Fixed.cfg` | fix design | pass - disprove of the lock holder reopens the pegin and releases the escrow |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleC5.cfg` | **current code (live)** | **fails** `NoDoublePayment`: `committeeCancelWithdraw` after kickoff + Take1 refunds the pegBTC |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleC5Stale.cfg` | **current code (live)** | **fails** `CancelBoundToAttempt`: an attempt-1 cancel signature cancels attempt 2 |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleC5Fixed.cfg` | fix design | pass - cancel needs a kickoff-impossible proof and an attempt-bound digest |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleF4.cfg` | **current code (live)** | **fails** `OnlyGraphOperatorLocks`: F4 - permissionless `initWithdraw` |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleF4Fixed.cfg` | fix design | pass - `msg.sender` must be the graph operator |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleEcon.cfg` | **current code (live)** | **fails** `RewardsCoveredBySlash`: one stake backs every graph; a disprove that slashes 0 still pays the reward from the pool |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleEconFixed.cfg` | fix design | pass - per-graph stake reservation, rewards capped by the slash |
| `GatewayWithdrawLifecycle.tla` | `GatewayWithdrawLifecycleAllFixed.cfg` | fix design | pass - every Gateway fix together, all invariants and both liveness properties |
| `MultiSigReplay.tla` | `MultiSigReplay.cfg` | **current code (live)** | **fails** `NoCrossDeploymentReplay`: the `updateOwners` digest has no contract address or chain id |
| `MultiSigReplay.tla` | `MultiSigReplayFixed.cfg` | fix design | pass - domain-separated digest |
| `JobObligationPersistence.tla` | `JobObligationPersistence.cfg` | **current code (live)** | **fails** `DefenceEventuallyRuns`: H3 - a defence job that panics once is Poisoned; scans re-request the same stable job id and `INSERT OR IGNORE` never re-runs it |
| `JobObligationPersistence.tla` | `JobObligationPersistenceRejected.cfg` | **current code (live)** | **fails** `DefenceEventuallyRuns`: any error containing "revert" is Permanent, so a Goat-calling peg-out job ends `Done("rejected")` for good |
| `JobObligationPersistence.tla` | `JobObligationPersistenceReorg.cfg` | **current code (live)** | **fails** `NoFalseClosure`: Take1/Take2/Disprove/Skipped are decided at 1 confirmation, absorbing and never rescanned; a 1-block reorg leaves the graph falsely closed |
| `JobObligationPersistence.tla` | `JobObligationPersistenceFixed.cfg` | fix design | pass - obligations re-derived each scan, unbroadcast terminal jobs re-armed under a new generation, closure only at depth > max reorg |
| `PeginPostRetry.tla` | `PeginPostRetry.cfg` | **current code (live)** | **fails** `PostTerminates`: M4 - "cannot cover fee" is not a permanent post rejection, so the post retries forever with no alert while the BTC is locked |
| `PeginPostRetry.tla` | `PeginPostRetryFixed.cfg` | fix design | pass - a typed FeeTooHigh rejection fails the job and raises the alert |
| `PegoutPoolCapacity.tla` | `PegoutPoolCapacity.cfg` | **current code (live)** | **fails** `HonestOperatorAnswersAll`: H5 - one Pegout slot and one running job per graph serialize N Wrongly-Challenged evaluations; with N=5, E=3 the last misses Testnet4 `prover_connector` (16) |
| `PegoutPoolCapacity.tla` | `PegoutPoolCapacitySlotsOnly.cfg` | **current code (live)** | **fails** `HonestOperatorAnswersAll`: raising `pegout_pool_slots` alone does not help (per-aggregate claim gate) |
| `PegoutPoolCapacity.tla` | `PegoutPoolCapacityFixed.cfg` | fix design | pass - graph validation requires `prover_connector >= Reaction + N*E_max + Incl` |
| `PeginConfirmCancelReorg.tla` | `PeginConfirmCancelReorg.cfg` | **current code (live)** | **fails** `NoUnbackedMint`: H6 - the post mints at 1 confirmation and the Gateway checks only `blockHash(height)`; a reorg swapping the Confirm for the user's Cancel pays refund **and** pegBTC (SPV at the tip: depth 1) |
| `PeginConfirmCancelReorg.tla` | `PeginConfirmCancelReorgNodeSpv.cfg` | **current code (live)** | **fails** `NoUnbackedMint`: with the node's append-only SPV writer a reorg of `BTC_BLOCK_CONFIRMS` + 1 suffices (mainnet 7) |
| `PeginConfirmCancelReorg.tla` | `PeginConfirmCancelReorgGateOnly.cfg` | insufficient fix (not in `specs.txt`) | **fails**: closing signing one block earlier does not stop an adversarial reorg |
| `PeginConfirmCancelReorg.tla` | `PeginConfirmCancelReorgPostWaitOnly.cfg` | insufficient fix (not in `specs.txt`) | **fails**: waiting k confirmations in the node is not enough - a colluding committee member posts with the stale SPV header |
| `PeginConfirmCancelReorg.tla` | `PeginConfirmCancelReorgFixed.cfg` | fix design | pass - the SPV records only headers at least max-reorg deep |
| `PeginTimeoutAgreement.tla` | `PeginTimeoutAgreement.cfg` | **current code (live)** | **fails** `Agreement`: M2 - Timeout is decided from each node's own mempool and B; a later-confirmed Confirm leaves nodes in different terminal states |
| `PeginTimeoutAgreement.tla` | `PeginTimeoutAgreementMint.cfg` | **current code (live)** | **fails** `MintAfterConfirm`: the timed-out relayer's post job is cancelled and never re-queued; the BTC sits in C0 with no pegBTC |
| `PeginTimeoutAgreement.tla` | `PeginTimeoutAgreementFixed.cfg` | fix design | pass - a confirmed Confirm takes Timeout back to `RelayerL1Broadcasted` |
| `PeginTimeoutAgreement.tla` | `PeginTimeoutAgreementRelayerPosts.cfg` | partial fix | pass `MintAfterConfirm` only - the relayer posting regardless of Timeout makes the mint live, agreement still fails |
| `CommitteeKeyDeletion.tla` | `CommitteeKeyDeletion.cfg` | **current code (live)** | **fails** `NoSweepAfterSettlement`: H2 - `ENABLE_COMMITTEE_INSTANCE_KEY_DELETE` defaults to false; a later compromise of all keys sweeps settled C0 |
| `CommitteeKeyDeletion.tla` | `CommitteeKeyDeletionTimeout.cfg` | **current code (live)** | **fails** `NoSweepAfterSettlement`: with deletion on, Timeout never deletes |
| `CommitteeKeyDeletion.tla` | `CommitteeKeyDeletionFixed.cfg` | fix design | pass - deletion on by default and on every terminal state including Timeout |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessSpam.cfg` | **current code (live)** | **fails** `GenuinePeginProgresses`: F1 - free requests stay `CommitteesAnswered` forever; batch-paged scans find a genuine Prepare after the operator's graph cutoff |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessSpamFixed.cfg` | fix design | pass - request fee or minimum amount + `CommitteesAnswered` expiry |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessBadKey.cfg` | **current code (live)** | **fails** `NoStuckInstance`: F6 - one answer with an off-curve x (only parity checked) stalls the instance in `CommitteesAnswered` |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessBadKeyFixed.cfg` | fix design | pass - on-curve check on answers |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessNoHeight.cfg` | **current code (live)**, latent | **fails** `NoStuckInstance`: F7 - a confirmed Prepare without `block_height` stores height 0 and Timeout never fires (Esplora always returns a height) |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessNoHeightGate.cfg` | **current code (live)**, latent | **fails** `NoSignatureAtOrAfterT0`: same - the T0 gate never closes |
| `PeginRequestLiveness.tla` | `PeginRequestLivenessNoHeightFixed.cfg` | fix design | pass - a confirmed Prepare is acted on only with its height |

Additional standalone tools available in the jar if needed: SANY (parser/type-checker)
via `java -cp tla2tools.jar tla2sany.SANY <Spec>.tla`, and the PlusCal translator
(used to generate `GraphLifecycleFineGrained*.tla`'s TLA+ body from its PlusCal
algorithm block) via `java -cp tla2tools.jar pcal.trans <Spec>.tla`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.