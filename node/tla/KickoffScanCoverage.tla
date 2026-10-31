---- MODULE KickoffScanCoverage ----
(************************************************************************** *)
(* Model of GOATNetwork/bitvm-node issue #431:                              *)
(*   "detect_kickoff watches only the lowest-nonce graph per operator, so   *)
(*    a kickoff on a later graph is never Challenged (unauthorized Take1)". *)
(*                                                                          *)
(* THE ORIGINAL BUG (gc-v2 @ f2f0285e): detect_kickoff sourced its graphs   *)
(* from fetch_on_turn_graph_by_status, which keeps ONE row per              *)
(* operator_pubkey - the lowest kickoff_index still at OperatorDataPushed   *)
(* (SQL: ORDER BY operator_pubkey, kickoff_index; Rust keeps the first per  *)
(* operator). An operator with two posted graphs leaves nonce 0 idle and    *)
(* kicks nonce >= 1; the kicked graph is never in the watched set, so no    *)
(* KickoffSent / Challenge is ever created for it, and after the ConnectorA *)
(* CSV the operator Take1s with pegBTC never burned. Distinct from #429     *)
(* (there the message exists but the verifier skips it on SPV lag).         *)
(*                                                                          *)
(* THE FIX (commit 2bce25d, "Fix graph maintenance logic" #451, on current  *)
(* dev): detect_kickoff now runs scan_kickoff_chain from each root, which   *)
(* walks confirmed_prekickoff_successor forward - following each graph's    *)
(* on-chain-confirmed next_prekickoff to the successor (validated           *)
(* kickoff_index == prev+1) - so the idle lowest-nonce decoy no longer      *)
(* hides a kicked successor. This closes the filed 2-graph attack.          *)
(*                                                                          *)
(* THE RESIDUAL (of #451): the walk is capped at                            *)
(* MAX_PREKICKOFF_SUCCESSORS_PER_SCAN = 32 (graph_maintenance_tasks.rs).    *)
(* With a single fixed root per operator, a chain of > 32 idle decoys with  *)
(* the kicked graph beyond depth 32 is not reached WITHIN ONE TICK. In the  *)
(* real node the window does slide across ticks - each PreKickoffSent the   *)
(* walk enqueues moves its graph to PreKickoff (already an entry) and       *)
(* force-skips the one before it - but only if verifiers keep handling      *)
(* those messages; single-tick coverage depended on that liveness.          *)
(*                                                                          *)
(* STATUS: FIXED - the walk from the root no longer has a depth cap: it     *)
(* follows confirmed next_prekickoff links until the first unconfirmed one, *)
(* so every graph on the confirmed chain is reached in the round that its   *)
(* kickoff confirms, whatever its depth. Every step costs the operator a    *)
(* confirmed Bitcoin transaction, and detect_kickoff runs as its own task   *)
(* (run_kickoff_scan_task) so an unbounded walk cannot starve the other     *)
(* maintenance checks. Modeled by ScanDepth >= NumGraphs - 1.               *)
(*                                                                          *)
(* This spec is a COVERAGE abstraction (same static-Init idiom as           *)
(* Take2DisproveRace.tla): the operator kicks graph `kicked`, keeping the   *)
(* root idle; detect_kickoff covers exactly the confirmed chain reachable   *)
(* from the root within ScanDepth. Property: the kicked graph is covered    *)
(* (hence Challenged). ScanDepth=0 models the original no-walk selection;   *)
(* 0<ScanDepth<NumGraphs-1 models the capped walk of #451 (the residual);   *)
(* ScanDepth>=NumGraphs-1 models the uncapped walk shipped now.             *)
(************************************************************************** *)
EXTENDS Naturals

CONSTANTS
    NumGraphs,     \* graphs this operator has posted (all OperatorDataPushed, nonce 0..NumGraphs-1)
    ScanDepth      \* how many confirmed prekickoff successors the walk follows from the root
                   \*   0                    = no chain walk (original bug)
                   \*   0 < d < NumGraphs-1   = capped walk (#451, cap was 32)
                   \*   >= NumGraphs-1        = uncapped walk (current code)

Graphs == 0 .. (NumGraphs - 1)

\* The operator keeps the lowest-nonce graph idle as the decoy. It is the
\* single root detect_kickoff selects per operator
\* (fetch_first_graph_per_operator_by_status); because it is never kicked it
\* never leaves OperatorDataPushed within the modeled round.
Root == 0

VARIABLE kicked          \* the graph whose kickoff the operator broadcasts (no L2 initWithdraw)
vars == <<kicked>>

TypeOK == kicked \in Graphs

\* To broadcast graph `kicked`'s kickoff the operator must have confirmed the
\* prekickoff chain Root..kicked on Bitcoin (each successor's prekickoff spends
\* the prior next_prekickoff). scan_kickoff_chain therefore CAN follow that
\* confirmed chain from the root - but only up to ScanDepth successors deep.
\* A graph g is covered (its kickoff observed -> KickoffSent -> Challenge) iff
\* the walk reaches it: it lies on the confirmed chain (g <= kicked) and is
\* within the depth budget of the root, i.e. g <= ScanDepth.
WalkedSet == { g \in Graphs : g <= kicked /\ g - Root <= ScanDepth }

Init == kicked \in Graphs
Next == UNCHANGED vars   \* exhaustive over the Init choice of `kicked`
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Safety: every unauthorized kickoff is covered by detect_kickoff (so a
\* Challenge can fire before the operator's uncontested Take1).
\* kicked \in WalkedSet  <=>  kicked <= ScanDepth.
KickoffAlwaysCovered == kicked \in WalkedSet

====
