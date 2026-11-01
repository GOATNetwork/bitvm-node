---- MODULE KickoffScanCoverage ----
(***************************************************************************)
(* Issue #431: a kickoff on a graph that no chain scan reaches is never    *)
(*   Challenged, so the operator's Take1 is unauthorized.                  *)
(* Code: scan_graphs_on_chain (node/src/aggregates/graph_scan.rs:131-155), *)
(*   run every maintenance tick (node/src/scheduled_tasks/mod.rs:290-296). *)
(*   It takes every graph in a monitored status (all but closed, 113-127;  *)
(*   a kicked graph without Take1 is never closed) in (operator,           *)
(*   kickoff_index) order and scans at most SCAN_BATCH = 64 per tick (44), *)
(*   resuming after the previous tick's last slot and wrapping             *)
(*   (ScanPass::rows 169-240, resume_index 89-92). Obsoleted graphs use    *)
(*   the same rotation with OBSOLETED_SCAN_BATCH = 16 (47) and a           *)
(*   Pre-Kickoff probe that a kicked graph passes (243-251). A scan at     *)
(*   OperatorKickOff or later yields KickoffSent (stage_signals 436-464),  *)
(*   which queues JOB_CHALLENGE_KICKOFF (graph_pegout.rs:264).             *)
(* Parameters: NumGraphs = graphs in the rotation; ScanBatch = graphs per  *)
(*   tick; Take1Ticks = ticks from the kickoff confirming to Take1 being   *)
(*   spendable.                                                            *)
(* ParamsOK == NumGraphs <= ScanBatch * Take1Ticks (exact): Take1Ticks     *)
(*   ticks scan min(NumGraphs, ScanBatch * Take1Ticks) consecutive slots   *)
(*   from any cursor, so the kicked graph, at any slot, is covered iff one *)
(*   lap fits. In Fixed.cfg one lap takes all Take1Ticks; in Boundary.cfg  *)
(*   one tick more.                                                        *)
(* Abstractions: one rotation; slots fixed during the window; every tick   *)
(*   at a fresh height (no SCAN_MARKS skip, the slowest rotation); scans   *)
(*   succeed; the history-sync gate (mod.rs:229-255) is in                 *)
(*   ChallengeKickoffGate (H4).                                            *)
(* Configs: configs/node/aggregates/graph/KickoffScanCoverage/, tiers in   *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    NumGraphs,     \* monitored graphs, slots 0..NumGraphs-1 in (operator, nonce) order
    ScanBatch,     \* graphs scanned per tick (SCAN_BATCH = 64, OBSOLETED_SCAN_BATCH = 16)
    Take1Ticks     \* maintenance ticks from the kickoff confirming to Take1 being spendable

ASSUME /\ NumGraphs \in Nat \ {0}
       /\ ScanBatch \in Nat \ {0}
       /\ Take1Ticks \in Nat

Graphs == 0 .. (NumGraphs - 1)

NoCursor == -1   \* SCAN_CURSOR unset (fresh process)

\* One lap of the rotation fits in the Take1 window (exact, see header).
ParamsOK == NumGraphs <= ScanBatch * Take1Ticks

VARIABLES
    kicked,     \* the graph kicked off without an L2 initWithdraw; frozen
    cursor,     \* SCAN_CURSOR: the slot the previous tick stopped at, or NoCursor
    covered,    \* graphs scanned since the kickoff confirmed (each yields KickoffSent if kicked)
    ticks       \* maintenance ticks since the kickoff confirmed

vars == <<kicked, cursor, covered, ticks>>

TypeOk ==
    /\ kicked \in Graphs
    /\ cursor \in Graphs \cup {NoCursor}
    /\ covered \subseteq Graphs
    /\ ticks \in 0 .. Take1Ticks

\* Any graph may be kicked; the cursor may stand anywhere when the kickoff confirms.
Init ==
    /\ kicked \in Graphs
    /\ cursor \in Graphs \cup {NoCursor}
    /\ covered = {}
    /\ ticks = 0

\* First slot after the cursor, or 0 if unset or past the end (resume_index, graph_scan.rs:89-92).
ResumeIndex == IF cursor = NoCursor \/ cursor = NumGraphs - 1 THEN 0 ELSE cursor + 1

BatchSize == IF ScanBatch < NumGraphs THEN ScanBatch ELSE NumGraphs

\* Slots this tick scans.
ThisTickBatch == { (ResumeIndex + k) % NumGraphs : k \in 0 .. (BatchSize - 1) }

--------------------------------------------------------------------------
\* Action: one maintenance tick scans the next BatchSize slots after the cursor (wrapping) and leaves the cursor on the last.
\* Source: node/src/aggregates/graph_scan.rs:131-155 (scan_graphs_on_chain), 169-240 (ScanPass::rows)
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

\* When Take1 becomes spendable the kicked graph has been scanned (so the Challenge job exists).
KickoffAlwaysCovered == ticks = Take1Ticks => kicked \in covered

\* ---- Safety properties ----
\* None beyond the invariants.

\* ---- Liveness ----
\* None: coverage is checked as the bounded invariant above.

====
