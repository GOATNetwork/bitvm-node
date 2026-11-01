---- MODULE KickoffScanCoverage ----
(***************************************************************************)
(* Issue #431: "detect_kickoff watches only the lowest-nonce graph per     *)
(* operator, so a kickoff on a later graph is never Challenged             *)
(* (unauthorized Take1)". An operator kept its lowest-nonce graph idle as  *)
(* a decoy and kicked a later one, which no scan ever looked at. #451      *)
(* added a capped successor walk; #476 removed per-operator root selection *)
(* altogether.                                                             *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476): node/src/aggregates/           *)
(* graph_scan.rs scan_graphs_on_chain (131-155), run from every            *)
(* maintenance tick (node/src/scheduled_tasks/mod.rs 286-291):             *)
(*   - selects EVERY graph in a monitored status - all but the closed      *)
(*     ones (monitored_statuses 113-127), ordered by (operator_pubkey,     *)
(*     kickoff_index); no root, no chain walk, no depth cap. A kicked      *)
(*     graph whose Take1 is not yet on chain is never closed (Skipped /    *)
(*     Disprove / Take1 / Take2 exclude a pending kickoff), so it is       *)
(*     always selected;                                                    *)
(*   - scans at most SCAN_BATCH = 64 of them per tick (41-44), resuming    *)
(*     after the slot the previous tick stopped at and wrapping around     *)
(*     (ScanPass::rows 169-240, resume_index 86-92); Obsoleted graphs run  *)
(*     the same rotation with OBSOLETED_SCAN_BATCH = 16 and a pre-kickoff  *)
(*     probe that passes once the pre-kickoff confirms (243-251), which a  *)
(*     kickoff requires;                                                   *)
(*   - a scanned graph whose chain stage is OperatorKickOff or later       *)
(*     yields the KickoffSent signal (stage_signals 435-464), which the    *)
(*     Graph aggregate turns into the verifier's JOB_CHALLENGE_KICKOFF     *)
(*     (graph_pegout.rs apply_chain_scan 551-625, route_signal 264).       *)
(*                                                                         *)
(* The question is now CAPACITY, not reachability: is the kicked graph     *)
(* scanned within the ticks that fit before Take1 becomes spendable? It    *)
(* is iff NumGraphs <= ScanBatch * Take1Ticks (ParamsOK below).            *)
(*                                                                         *)
(* Abstractions: one rotation (active or Obsoleted, they are identical in  *)
(* shape); the slot list is fixed during the window; every tick is at a    *)
(* fresh Bitcoin height (SCAN_MARKS empty), the worst case - a graph       *)
(* already marked at this height is skipped without using the batch, which *)
(* only speeds the rotation up; scans succeed (a failed RPC leaves the     *)
(* graph for the next lap); the tick is not skipped by the gateway         *)
(* history-sync gate (mod.rs 229-253; modeled in ChallengeKickoffGate).    *)
(*                                                                         *)
(* CONFIGS: KickoffScanCoverage/Fixed.cfg (tier pass) - the current code,   *)
(* with SCAN_BATCH scaled down so the rotation wraps within the window.    *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    NumGraphs,     \* monitored graphs in the rotation, slots 0..NumGraphs-1 in (operator, nonce) order
    ScanBatch,     \* graphs scanned per tick (SCAN_BATCH = 64, OBSOLETED_SCAN_BATCH = 16)
    Take1Ticks     \* maintenance ticks between the kickoff confirming and Take1 being spendable

ASSUME /\ NumGraphs \in Nat \ {0}
       /\ ScanBatch \in Nat \ {0}
       /\ Take1Ticks \in Nat

Graphs == 0 .. (NumGraphs - 1)

NoCursor == -1   \* SCAN_CURSOR unset (fresh process)

\* Coverage is guaranteed exactly when one lap of the rotation fits in the window.
ParamsOK == NumGraphs <= ScanBatch * Take1Ticks

VARIABLES
    kicked,     \* the graph whose kickoff the operator broadcast (no L2 initWithdraw); frozen
    cursor,     \* SCAN_CURSOR: the slot the previous tick stopped at, or NoCursor
    covered,    \* graphs scanned since the kickoff confirmed (each yields KickoffSent if kicked)
    ticks       \* maintenance ticks since the kickoff confirmed

vars == <<kicked, cursor, covered, ticks>>

TypeOk ==
    /\ kicked \in Graphs
    /\ cursor \in Graphs \cup {NoCursor}
    /\ covered \subseteq Graphs
    /\ ticks \in 0 .. Take1Ticks

\* Any graph may be the kicked one; the rotation may stand anywhere when the
\* kickoff confirms.
Init ==
    /\ kicked \in Graphs
    /\ cursor \in Graphs \cup {NoCursor}
    /\ covered = {}
    /\ ticks = 0

\* resume_index: the first slot after the cursor, or the start when the
\* cursor is unset or past the last slot.
ResumeIndex == IF cursor = NoCursor \/ cursor = NumGraphs - 1 THEN 0 ELSE cursor + 1

BatchSize == IF ScanBatch < NumGraphs THEN ScanBatch ELSE NumGraphs

ThisTickBatch == { (ResumeIndex + k) % NumGraphs : k \in 0 .. (BatchSize - 1) }

--------------------------------------------------------------------------
\* Action: one maintenance tick scans the next BatchSize graphs after the
\* cursor (wrapping), submits a chain_scan for each, and leaves the cursor
\* on the last one scanned. Ticks after Take1 is spendable are irrelevant.
\* Source: scan_graphs_on_chain() in node/src/aggregates/graph_scan.rs:131-155;
\*         ScanPass::rows() in node/src/aggregates/graph_scan.rs:169-240;
\*         resume_index() in node/src/aggregates/graph_scan.rs:86-92
ScanTick ==
    /\ ticks < Take1Ticks
    /\ covered' = covered \cup ThisTickBatch
    /\ cursor' = (ResumeIndex + BatchSize - 1) % NumGraphs
    /\ ticks' = ticks + 1
    /\ UNCHANGED kicked

Next == ScanTick

\* No fairness: the property is a bounded-window invariant.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* ---- Safety invariants ----

\* By the time Take1 is spendable the kicked graph has been scanned, so the
\* KickoffSent signal (hence the verifier's Challenge job) exists.
KickoffAlwaysCovered == ticks = Take1Ticks => kicked \in covered

\* ---- Safety properties ----
\* None beyond the invariants.

\* ---- Liveness ----
\* None: coverage is checked as the bounded invariant above.

====
