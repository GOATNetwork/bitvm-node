---- MODULE ShippedTimelocks ----
(***************************************************************************)
(* Per-network timing values for Take2DisproveRace, MultiActorRace and     *)
(* Take1ChallengeRace. Every number comes from ShippedTimelockValues.tla,  *)
(* generated from crates/bitvm-gc/src/timelocks.rs (`make tla-values`,     *)
(* drift-checked in CI).                                                   *)
(***************************************************************************)
EXTENDS ShippedTimelockValues

\* Floor the margin specs check against: the code's action_window
\* (reaction + inclusion + safety blocks, timelocks.rs:91-95).
MinReactionBlocks == ActionWindow

====
