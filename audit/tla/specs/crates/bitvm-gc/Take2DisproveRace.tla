---- MODULE Take2DisproveRace ----
(***************************************************************************)
(* Purpose: can Take2's two-clock readiness condition be used to preempt   *)
(* the Disprove fallback on the same ConnectorD output? Finding 4 of the   *)
(* timelock-reasonableness audit ("gap 3"). Init-only arithmetic: there    *)
(* are no transitions, TLC enumerates every initial state and checks the   *)
(* invariants on each.                                                     *)
(*                                                                         *)
(* Code scope (current tree):                                              *)
(*   goat crate bab46c2 (Cargo.lock), goat/src:                            *)
(*     transactions/take2.rs:67-77  Take2 spends connector_0 leaf 0,       *)
(*       ConnectorD leaf 0 and ConnectorF leaf 0 (+ guardian) together.     *)
(*     connectors/connector_d.rs:61-70  leaf 0 = operator + CSV(connector_d),*)
(*       clock = OperatorAssert's confirmation (D is an OperatorAssert      *)
(*       output, transactions/assert.rs:97-101).                           *)
(*     connectors/connector_f.rs:38-47  leaf 0 = operator + CSV(connector_f),*)
(*       clock = WatchtowerChallengeInit's confirmation                    *)
(*       (transactions/watchtower_challenge.rs:234-237).                   *)
(*     transactions/assert.rs:316-327  Disprove spends ProverConnector     *)
(*       leaf 1 and ConnectorD leaf 1 (n-of-n, no CSV, connector_d.rs:72-78).*)
(*     connectors/assert_connectors.rs:135-144  ProverConnector leaf 1 =    *)
(*       n-of-n + CSV(prover_connector), clock = VerifierAssert's           *)
(*       confirmation (VerifierAssert output, assert.rs:222-226).          *)
(*     ConnectorD leaf 2 (connector_d.rs:80-92, spent by pubin_disprove,   *)
(*       assert.rs:569-599) has no CSV at all, so it is never slower than  *)
(*       the leaf-1 Disprove modeled here and cannot open a new margin.    *)
(*   node:                                                                 *)
(*     node/src/aggregates/graph_scan.rs:792-843 take2_ready: both clocks  *)
(*       (assert.height + connector_d, wci.height + connector_f).          *)
(*     node/src/aggregates/graph_scan.rs:742-790 wrongly_challenge_timeout:*)
(*       VerifierAssert.height + prover_connector -> JOB_DISPROVE.          *)
(*   crates/bitvm-gc/src/timelocks.rs:173-239 validate_timelock_config,     *)
(*     which every graph's own timelock_config must pass (operator/api.rs: *)
(*     72 generate_bitvm_graph, node/src/aggregates/graph_scan.rs:466-472). *)
(*     The comparisons it enforces on this race:                           *)
(*       :186 every value >= reaction_blocks                               *)
(*       :222 prover_connector >= action_window                            *)
(*       :223-229 connector_d - prover_connector >= action_window          *)
(*     where action_window = reaction + inclusion + safety blocks (:91-95).*)
(*                                                                         *)
(* `delta` is the gap between OperatorAssert's and VerifierAssert's        *)
(* confirmations (VerifierAssert spends an OperatorAssert output, so it is *)
(* >= 0). Nothing on-chain bounds it; the spec assumes it is at most one   *)
(* action window (MinReactionBlocks == ActionWindow, ShippedTimelocks.tla),*)
(* the same budget the validator uses. Bitcoin UTXO semantics decide the   *)
(* race: whichever spend becomes valid first wins (modeled as strict <).   *)
(*                                                                         *)
(* Configs / tiers:                                                        *)
(*   Take2DisproveRace/Shipped.cfg (pass): TimelockSource = "Shipped", the         *)
(*     generated default_timelock_config values on every network.          *)
(*   Take2DisproveRace/Validated.cfg (live): TimelockSource = "Validated",  *)
(*     every (prover_connector, connector_d) validate_timelock_config      *)
(*     accepts near its floor. The gap check (:223-229) is ">=            *)
(*     action_window", which only gives delta + prover_connector <=        *)
(*     connector_d: at the floor, a verifier that confirms its assert a    *)
(*     full action window late only TIES Take2. FAILS                      *)
(*     DisproveWinsConnectorDRace. The shipped configs have slack          *)
(*     (gap 288/16/12/2 vs window 18/6/3/1) and pass.                      *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

CONSTANTS
    TimelockSource  \* "Shipped": default_timelock_config; "Validated": any config the validator accepts near its floor

\* How far above each validator floor the "Validated" sweep goes, in blocks.
ValidatedSlack == 0..2

\* Range of WatchtowerChallengeInit confirmation heights relative to OperatorAssert.
WciHeights == -300..300

ASSUME TimelockSource \in {"Shipped", "Validated"}

Max(a, b) == IF a >= b THEN a ELSE b

\* ensure_gap_at_least(left, right, required) of timelocks.rs:252-266
\* (right.saturating_sub(left) >= required).
GapAtLeast(left, right, required) == Max(right - left, 0) >= required

VARIABLES
    net,              \* Bitcoin network whose timelocks and timing budget apply
    delta,            \* VerifierAssert confirmation height - OperatorAssert confirmation height
    wci,              \* WatchtowerChallengeInit confirmation height relative to OperatorAssert (operator-chosen)
    proverConnector,  \* timelock_config.prover_connector of the graph
    connectorD        \* timelock_config.connector_d of the graph

vars == <<net, delta, wci, proverConnector, connectorD>>

TypeOk ==
    /\ net \in Networks
    /\ delta \in 0..MinReactionBlocks[net]
    /\ wci \in WciHeights
    /\ proverConnector \in Nat
    /\ connectorD \in Nat

\* Action: the only "step": pick a network, a graph timelock config, the
\* verifier's assert delay within one action window, and any operator choice
\* of when WatchtowerChallengeInit confirms. OperatorAssert is at height 0.
\* Source: default_timelock_config()/validate_timelock_config() in
\*   crates/bitvm-gc/src/timelocks.rs:54-61,173-239 (config);
\*   environment (delta, wci): the operator broadcasts WatchtowerChallengeInit
\*   (spends ConnectorB, watchtower_challenge.rs:193-194) independently of
\*   OperatorAssert (spends ConnectorC, assert.rs:73-74).
Init ==
    /\ net \in Networks
    /\ IF TimelockSource = "Shipped"
         THEN /\ proverConnector = ProverConnector[net]
              /\ connectorD = ConnectorD[net]
         ELSE /\ proverConnector \in {ActionWindow[net] + s : s \in ValidatedSlack}
              /\ connectorD \in {proverConnector + ActionWindow[net] + s : s \in ValidatedSlack}
    /\ delta \in 0..MinReactionBlocks[net]
    /\ wci \in WciHeights

\* No transitions: an exhaustive check over Init, not a process model.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
DisproveDeadline        == delta + proverConnector   \* ProverConnector leaf 1 CSV elapsed
Take2ConnectorDDeadline == connectorD                \* ConnectorD leaf 0 CSV elapsed
Take2ConnectorFDeadline == wci + ConnectorF[net]     \* ConnectorF leaf 0 CSV elapsed
Take2Deadline           == Max(Take2ConnectorDDeadline, Take2ConnectorFDeadline)

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* The graph's config passes the validator comparisons on this race
\* (timelocks.rs:186,222,223-229); holds by construction in "Validated".
ConfigMeetsValidatorFloors ==
    /\ proverConnector >= ReactionBlocks[net]
    /\ connectorD >= ReactionBlocks[net]
    /\ proverConnector >= ActionWindow[net]
    /\ GapAtLeast(proverConnector, connectorD, ActionWindow[net])

\* Within the assumed verifier delay, Disprove becomes valid strictly before
\* Take2's ConnectorD leaf, whatever the operator does with wci.
DisproveWinsConnectorDRace == DisproveDeadline < Take2ConnectorDDeadline

\* ConnectorF can only delay Take2, never let it beat the ConnectorD race.
ConnectorFNeverShortcutsConnectorD == Take2Deadline >= Take2ConnectorDDeadline

====
