---- MODULE ShippedTimelocks ----
(***************************************************************************)
(* Per-network timing values for the round-1 margin-arithmetic specs       *)
(* (Take2DisproveRace.tla, MultiActorRace.tla, Take1ChallengeRace.tla).    *)
(*                                                                         *)
(* Every number comes from ShippedTimelockValues.tla, which is GENERATED   *)
(* from crates/bitvm-gc/src/timelocks.rs by                                *)
(* crates/bitvm-gc/tests/tla_shipped_values.rs and checked for drift in    *)
(* CI (`make tla-values` regenerates it). This module used to carry a      *)
(* hand-transcribed copy, which went stale (testnet4 prover_connector,     *)
(* connector_d, operator_ack, operator_commit and connector_f all changed  *)
(* after it was written).                                                  *)
(*                                                                         *)
(* MinReactionBlocks used to be a policy floor invented by these specs     *)
(* (6/12/1/1). The code now has its own: validate_timelock_config          *)
(* requires connector_a and prover_connector >= action_window and          *)
(* connector_d - prover_connector >= action_window, where action_window =  *)
(* reaction_blocks + inclusion_blocks + safety_blocks                      *)
(* (ProtocolTimingBudget). The specs check against that floor, so a        *)
(* budget change in Rust changes what they check.                          *)
(***************************************************************************)
EXTENDS ShippedTimelockValues

MinReactionBlocks == ActionWindow

====
