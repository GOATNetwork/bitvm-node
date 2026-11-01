---- MODULE Take1ChallengeRace ----
(***************************************************************************)
(* Purpose: Take1 vs Challenge on kickoff connector A (Finding 9). Both    *)
(* leaves of ConnectorA have their clock at the Kickoff's confirmation:    *)
(* Challenge is spendable at once, Take1 after CSV(connector_a). The whole *)
(* margin a challenger has to notice a bad kickoff and get Challenge       *)
(* confirmed is therefore connector_a itself. Init-only arithmetic over    *)
(* the shipped per-network values (ShippedTimelocks).                      *)
(*                                                                         *)
(* Code scope (current tree):                                              *)
(*   goat crate bab46c2 (Cargo.lock), goat/src:                            *)
(*     transactions/kickoff.rs:68-71  Kickoff output 0 = ConnectorA.       *)
(*     connectors/connector_a.rs:38-47  leaf 0 = operator +                *)
(*       CSV(connector_a), spent by Take1 (transactions/take1.rs:73-74).   *)
(*     connectors/connector_a.rs:49-55  leaf 1 = n-of-n, no CSV, spent by  *)
(*       Challenge (transactions/challenge.rs:56-57) signed                *)
(*       SinglePlusAnyoneCanPay (:93), so any challenger adds its own fee  *)
(*       input. First confirmed spend wins the output.                     *)
(*   node: node/src/aggregates/graph_scan.rs:520-551 take1_ready (kickoff  *)
(*     height + connector_a); node/src/aggregates/graph_pegout_jobs.rs:    *)
(*     594-647 challenge_kickoff (the verifier's Challenge).               *)
(*   crates/bitvm-gc/src/timelocks.rs:202 validate_timelock_config:        *)
(*     ensure_at_least("connector_a", connector_a, action_window), with    *)
(*     action_window = reaction + inclusion + safety blocks (:91-95). The  *)
(*     property below is exactly that comparison, so it holds for every    *)
(*     config the validator accepts; this spec checks the shipped values   *)
(*     against it (the validator itself is unit-tested on them,            *)
(*     timelocks.rs:320-332). Whether the node's challenge_kickoff fits    *)
(*     into that window is ChallengeKickoffGate.tla's subject (C6).        *)
(*                                                                         *)
(* Config / tier: Take1ChallengeRaceFixed.cfg (pass). The name is kept     *)
(* from when connector_a had no floor (fixed in 991faaa).                  *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

VARIABLES
    net   \* Bitcoin network whose connector_a and timing budget apply

vars == <<net>>

TypeOk == net \in Networks

\* Action: the only "step": pick a network; the Kickoff confirms at height 0.
\* Source: default_timelock_config() in crates/bitvm-gc/src/timelocks.rs:54-61
\*   via ShippedTimelockValues.tla (generated).
Init == net \in Networks

\* No transitions: an exhaustive check over Init, not a process model.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* A challenger has the code's full action window (reaction + inclusion +
\* safety), from the Kickoff's confirmation, to get Challenge confirmed
\* before Take1's CSV elapses (timelocks.rs:202).
ChallengeHasSufficientReactionMarginFixed ==
    ConnectorA[net] >= MinReactionBlocks[net]

====
