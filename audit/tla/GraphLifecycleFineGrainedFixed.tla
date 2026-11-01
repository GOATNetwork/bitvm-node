---- MODULE GraphLifecycleFineGrainedFixed ----
(***************************************************************************)
(* Finding 1b (fixed in 991faaa): a guard checked by one statement and a   *)
(* write by a later one (SELECT, then UPDATE) leaves a gap in which another *)
(* writer's statement lands, even with correct guard logic on both sides.   *)
(* The fix moved the guard into the UPDATE itself.                          *)
(*                                                                         *)
(* Code scope (dev after #476): StorageProcessor::transition_graph_status, *)
(* crates/store/src/localdb/graph.rs:450-529, statement by statement:      *)
(*   1. UPDATE graph SET status = target [, sub_status] ... WHERE status IN *)
(*      allowed_transition_from(target, source)            -> Applied      *)
(*   2. if no row changed: read the row to tell AlreadyCurrent (status =    *)
(*      target) from Rejected; this read never authorizes a write           *)
(*   3. AlreadyCurrent with a sub_status: UPDATE graph SET sub_status ...    *)
(*      WHERE status = target                                               *)
(*   4. if that changed no row: read the row again to report the outcome.   *)
(* Each statement is one atomic step here; two writers, one per source that *)
(* races in production, interleave between any two statements:            *)
(*   ChainReconcile - apply_chain_scan / refresh_graph / obsolete_graph,     *)
(*                    always with a sub_status here (the chain scan's       *)
(*                    ChallengeSubStatus), node/src/aggregates/             *)
(*                    graph_pegout.rs:572, node/src/utils/graph_store.rs:626 *)
(*   GoatEvent      - apply_gateway_graph_status, no sub_status,            *)
(*                    node/src/scheduled_tasks/event_watch/gateway.rs:305   *)
(* Each writer picks any target its source can write, at any time: stale   *)
(* and replayed events included, so the check covers every interleaving    *)
(* the guard must survive, independent of the chain facts that              *)
(* GraphLifecycle.tla models.                                               *)
(*                                                                         *)
(* Config (audit/tla/specs.txt): GraphLifecycleFineGrainedFixed.cfg - pass. *)
(***************************************************************************)
EXTENDS GraphTopology

\* The two racing writers.
WriterChainReconcile == "ChainReconcile"
WriterGoatEvent      == "GoatEvent"
Writers == {WriterChainReconcile, WriterGoatEvent}

\* The evidence source each writer passes to transition_graph_status.
SourceOf(w) == IF w = WriterChainReconcile THEN SourceChainReconcile ELSE SourceGoatEvent

\* Whether the writer passes a sub_status.
HasSubStatus(w) == w = WriterChainReconcile

\* Program counter of one transition_graph_status call.
PcIdle            == "Idle"             \* between calls; statement 1 is next
PcReadOutcome     == "ReadOutcome"      \* statement 2
PcUpdateSubStatus == "UpdateSubStatus"  \* statement 3
PcReReadOutcome   == "ReReadOutcome"    \* statement 4
PcStates == {PcIdle, PcReadOutcome, PcUpdateSubStatus, PcReReadOutcome}

\* No target / no sub_status written yet.
None == "None"

VARIABLES
    status,     \* Graph.status
    subFor,     \* the status whose writer last set Graph.sub_status, or None
    pc,         \* per writer: the next statement of its current call
    target      \* per writer: the target of its current call, or None

vars == <<status, subFor, pc, target>>

TypeOk ==
    /\ status \in AllStatuses
    /\ subFor \in AllStatuses \cup {None}
    /\ pc \in [Writers -> PcStates]
    /\ target \in [Writers -> AllStatuses \cup {None}]

Init ==
    /\ status = OperatorPresigned
    /\ subFor = None
    /\ pc = [w \in Writers |-> PcIdle]
    /\ target = [w \in Writers |-> None]

--------------------------------------------------------------------------
(* Actions *)

\* Action: statement 1, the conditional UPDATE. Writes the target (and the
\* sub_status) iff the current status is in the allowed set; the call then
\* returns Applied. Otherwise no row changes and the call goes on to read the
\* outcome. A target with an empty allowed set (ChainReconcile observing
\* OperatorPresigned) only reads the outcome and writes nothing, so it is a
\* stuttering step and is left out.
\* Source: transition_graph_status() in crates/store/src/localdb/graph.rs:462-495
ConditionalUpdate(w) ==
    /\ pc[w] = PcIdle
    /\ \E t \in TargetsOf(SourceOf(w)) :
         IF status \in AllowedFrom(t, SourceOf(w))
           THEN /\ status' = t
                /\ subFor' = IF HasSubStatus(w) THEN t ELSE subFor
                /\ UNCHANGED <<pc, target>>
           ELSE /\ pc' = [pc EXCEPT ![w] = PcReadOutcome]
                /\ target' = [target EXCEPT ![w] = t]
                /\ UNCHANGED <<status, subFor>>

\* Action: statement 2, the outcome read. Rejected, or AlreadyCurrent without
\* a sub_status, ends the call; AlreadyCurrent with a sub_status goes on to
\* the guarded sub_status update. Writes nothing.
\* Source: transition_graph_status() in crates/store/src/localdb/graph.rs:496-508
ReadOutcome(w) ==
    /\ pc[w] = PcReadOutcome
    /\ IF status = target[w] /\ HasSubStatus(w)
         THEN /\ pc' = [pc EXCEPT ![w] = PcUpdateSubStatus]
              /\ UNCHANGED target
         ELSE /\ pc' = [pc EXCEPT ![w] = PcIdle]
              /\ target' = [target EXCEPT ![w] = None]
    /\ UNCHANGED <<status, subFor>>

\* Action: statement 3, UPDATE graph SET sub_status ... WHERE status = target.
\* If another writer moved the row since statement 2, no row changes and the
\* call re-reads the outcome.
\* Source: transition_graph_status() in crates/store/src/localdb/graph.rs:510-524
UpdateSubStatus(w) ==
    /\ pc[w] = PcUpdateSubStatus
    /\ IF status = target[w]
         THEN /\ subFor' = target[w]
              /\ pc' = [pc EXCEPT ![w] = PcIdle]
              /\ target' = [target EXCEPT ![w] = None]
         ELSE /\ pc' = [pc EXCEPT ![w] = PcReReadOutcome]
              /\ UNCHANGED <<subFor, target>>
    /\ UNCHANGED status

\* Action: statement 4, the final outcome read after a lost sub_status race.
\* Writes nothing.
\* Source: transition_graph_status() in crates/store/src/localdb/graph.rs:525-528
ReReadOutcome(w) ==
    /\ pc[w] = PcReReadOutcome
    /\ pc' = [pc EXCEPT ![w] = PcIdle]
    /\ target' = [target EXCEPT ![w] = None]
    /\ UNCHANGED <<status, subFor>>

Next ==
    \E w \in Writers :
        \/ ConditionalUpdate(w)
        \/ ReadOutcome(w)
        \/ UpdateSubStatus(w)
        \/ ReReadOutcome(w)

\* No fairness: only safety is checked.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* (none beyond TypeOk)

--------------------------------------------------------------------------
(* Safety properties *)

\* A closed status is never left, whatever the interleaving of statements.
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

\* The two payout paths are never both recorded for one graph.
NoConflictingWithdrawal ==
    /\ [][(status = OperatorTake1 => status' # OperatorTake2)]_status
    /\ [][(status = OperatorTake2 => status' # OperatorTake1)]_status

\* A sub_status is only ever written onto the status it describes: the
\* second UPDATE's `WHERE status = target` closes the read/write gap after
\* statement 2.
SubStatusWrittenWithItsStatus == [][(subFor' # subFor => subFor' = status')]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* (none)

====
