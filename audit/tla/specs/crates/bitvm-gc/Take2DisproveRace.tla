---- MODULE Take2DisproveRace ----
(***************************************************************************)
(* Take2 vs Disprove on ConnectorD (Finding 4). Init-only arithmetic.      *)
(* Code (goat bab46c2, goat/src): Take2 spends ConnectorD leaf 0 =         *)
(*   operator + CSV(connector_d), clock = OperatorAssert, and ConnectorF   *)
(*   leaf 0 = operator + CSV(connector_f), clock = WatchtowerChallengeInit *)
(*   (transactions/take2.rs:67-77, connectors/connector_d.rs:61-70,        *)
(*   assert.rs:97-101, connector_f.rs:38-47,                               *)
(*   watchtower_challenge.rs:234-237). Disprove spends ProverConnector     *)
(*   leaf 1 = n-of-n + CSV(prover_connector), clock = VerifierAssert, and  *)
(*   ConnectorD leaf 1 (assert.rs:316-327, assert_connectors.rs:135-144,   *)
(*   connector_d.rs:72-78). ConnectorD leaf 2 (pubin_disprove) has no CSV: *)
(*   no new margin. Node: take2_ready and wrongly_challenge_timeout        *)
(*   (node/src/aggregates/graph_scan.rs:792-843, :742-788).                *)
(*   validate_timelock_config (crates/bitvm-gc/src/timelocks.rs:173-239,   *)
(*   applied per graph at graph_scan.rs:466-472) checks :186, :222 and     *)
(*   :223-229 on this race.                                                *)
(* Finding 4: :223-229 only requires connector_d - prover_connector >=     *)
(*   action_window, so at the floor a verifier one full window late only   *)
(*   ties Take2 (a tie counts as lost: strict <). Fix: gap >=              *)
(*   action_window + 1 (exact for delta <= action_window). The shipped     *)
(*   values have slack.                                                    *)
(* Parameters: TimelockSource ("Shipped" or "Validated", see CONSTANTS);   *)
(*   delta = VerifierAssert - OperatorAssert height, assumed               *)
(*   0..action_window (nothing on-chain bounds it); wci =                  *)
(*   WatchtowerChallengeInit height, -300..300 (operator-chosen).          *)
(* Exhaustive: each invariant is linear; delta covers its whole range,     *)
(*   "Validated" covers each floor and 2 blocks of slack, and wci only     *)
(*   enters ConnectorF's deadline, which Max keeps >= ConnectorD's.        *)
(* Configs: configs/crates/bitvm-gc/Take2DisproveRace/, tiers in           *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

CONSTANTS
    TimelockSource  \* "Shipped": default_timelock_config; "Validated": any config the validator accepts near its floor

\* Blocks above each validator floor swept by "Validated".
ValidatedSlack == 0..2

\* WatchtowerChallengeInit heights swept, relative to OperatorAssert.
WciHeights == -300..300

ASSUME TimelockSource \in {"Shipped", "Validated"}

Max(a, b) == IF a >= b THEN a ELSE b

\* ensure_gap_at_least (timelocks.rs:252-266): right.saturating_sub(left) >= required.
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

\* Action: pick a network, the graph's timelock config, the verifier's delay
\* and the operator's WatchtowerChallengeInit height; OperatorAssert is at 0.
\* Source: crates/bitvm-gc/src/timelocks.rs:54-61, :173-239; environment (delta, wci).
Init ==
    /\ net \in Networks
    /\ IF TimelockSource = "Shipped"
         THEN /\ proverConnector = ProverConnector[net]
              /\ connectorD = ConnectorD[net]
         ELSE /\ proverConnector \in {ActionWindow[net] + s : s \in ValidatedSlack}
              /\ connectorD \in {proverConnector + ActionWindow[net] + s : s \in ValidatedSlack}
    /\ delta \in 0..MinReactionBlocks[net]
    /\ wci \in WciHeights

\* No steps: TLC checks the invariants on every initial state.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
DisproveDeadline        == delta + proverConnector   \* ProverConnector leaf 1 CSV elapsed
Take2ConnectorDDeadline == connectorD                \* ConnectorD leaf 0 CSV elapsed
Take2ConnectorFDeadline == wci + ConnectorF[net]     \* ConnectorF leaf 0 CSV elapsed
Take2Deadline           == Max(Take2ConnectorDDeadline, Take2ConnectorFDeadline)

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* The config passes the validator's checks on this race (timelocks.rs:186, :222, :223-229).
ConfigMeetsValidatorFloors ==
    /\ proverConnector >= ReactionBlocks[net]
    /\ connectorD >= ReactionBlocks[net]
    /\ proverConnector >= ActionWindow[net]
    /\ GapAtLeast(proverConnector, connectorD, ActionWindow[net])

\* Disprove becomes valid strictly before Take2's ConnectorD leaf.
DisproveWinsConnectorDRace == DisproveDeadline < Take2ConnectorDDeadline

\* ConnectorF can only delay Take2, never let it beat the ConnectorD race.
ConnectorFNeverShortcutsConnectorD == Take2Deadline >= Take2ConnectorDDeadline

====
