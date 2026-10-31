---- MODULE ShippedTimelocks ----
(***************************************************************************)
(* Real per-network timelock values, transcribed from                      *)
(* crates/bitvm-gc/src/timelocks.rs, shared by every margin-arithmetic     *)
(* spec in this directory (Take2DisproveRace.tla, MultiActorRace.tla,      *)
(* Take1ChallengeRace.tla) - single source of truth instead of each spec   *)
(* re-transcribing its own copy.                                          *)
(*                                                                         *)
(* As of commit 991faaa ("Dev fix #418"), Finding 4's fix has actually been *)
(* applied to crates/bitvm-gc/src/timelocks.rs - these are now the REAL     *)
(* shipped values (re-verified via TLC against these exact numbers, not     *)
(* just the originally-proposed 35/testnet4 figure this file used to hold  *)
(* before the real fix landed with a wider margin than proposed).          *)
(* connector_a is NOT here - Take1ChallengeRace.tla defines its own        *)
(* ConnectorA/ConnectorAFixed locally, since that value pair is the        *)
(* historical subject under test in that spec, not a settled shared        *)
(* constant.                                                               *)
(***************************************************************************)

Networks == {"Bitcoin", "Testnet4", "Signet", "Regtest"}

ProverConnector     == [Bitcoin |-> 144, Testnet4 |-> 20, Signet |-> 6, Regtest |-> 1]
ConnectorD          == [Bitcoin |-> 432, Testnet4 |-> 40, Signet |-> 18, Regtest |-> 3]
WatchtowerChallenge == [Bitcoin |-> 144, Testnet4 |-> 20, Signet |-> 6, Regtest |-> 1]
OperatorAck         == [Bitcoin |-> 288, Testnet4 |-> 32, Signet |-> 12, Regtest |-> 2]
OperatorCommit      == [Bitcoin |-> 432, Testnet4 |-> 40, Signet |-> 18, Regtest |-> 3]
ConnectorF          == [Bitcoin |-> 576, Testnet4 |-> 52, Signet |-> 24, Regtest |-> 4]

\* Policy floor, not itself a timelocks.rs field: the assumed real-world
\* reaction-time bound (~1 hour) used across every margin-race spec.
MinReactionBlocks == [Bitcoin |-> 6, Testnet4 |-> 12, Signet |-> 1, Regtest |-> 1]

====
