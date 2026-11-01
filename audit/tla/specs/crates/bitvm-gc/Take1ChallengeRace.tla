---- MODULE Take1ChallengeRace ----
(***************************************************************************)
(* Take1 vs Challenge on Kickoff connector A (Finding 9). Init-only        *)
(* arithmetic over the shipped values of every network.                    *)
(* Code (goat bab46c2, goat/src): Kickoff output 0 is ConnectorA           *)
(*   (transactions/kickoff.rs:68-71). Leaf 0 = operator +                  *)
(*   CSV(connector_a), spent by Take1 (connectors/connector_a.rs:38-47,    *)
(*   take1.rs:73-74). Leaf 1 = n-of-n, no CSV, spent by Challenge          *)
(*   (connector_a.rs:49-55, challenge.rs:56-57, SinglePlusAnyoneCanPay     *)
(*   :93). Both clocks start at the Kickoff's confirmation; the first      *)
(*   confirmed spend wins. Node: take1_ready                               *)
(*   (node/src/aggregates/graph_scan.rs:520-551) and challenge_kickoff     *)
(*   (node/src/aggregates/graph_pegout_jobs.rs:595-647).                   *)
(* Finding 9: a challenger's whole margin is connector_a. The code's floor *)
(*   is connector_a >= action_window (validate_timelock_config,            *)
(*   crates/bitvm-gc/src/timelocks.rs:202); the invariant is that exact    *)
(*   comparison, checked on the shipped values. Whether challenge_kickoff  *)
(*   fits that window is ChallengeKickoffGate.tla's subject.               *)
(* Parameters: none besides the network.                                   *)
(* Exhaustive: Init enumerates all four networks; there are no steps.      *)
(* Configs: configs/crates/bitvm-gc/Take1ChallengeRace/, tiers in          *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

VARIABLES
    net   \* Bitcoin network whose connector_a and timing budget apply

vars == <<net>>

TypeOk == net \in Networks

\* Action: pick a network; the Kickoff confirms at height 0.
\* Source: default_timelock_config(), crates/bitvm-gc/src/timelocks.rs:54-61.
Init == net \in Networks

\* No steps: TLC checks the invariants on every initial state.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* Challenge has at least one action window after the Kickoff confirms
\* before Take1's CSV elapses.
ChallengeHasSufficientReactionMarginFixed ==
    ConnectorA[net] >= MinReactionBlocks[net]

====
