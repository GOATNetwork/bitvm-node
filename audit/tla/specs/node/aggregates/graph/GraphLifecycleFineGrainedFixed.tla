---- MODULE GraphLifecycleFineGrainedFixed ----
(***************************************************************************)
(* transition_graph_status (crates/store/src/localdb/graph.rs:450-529),    *)
(*   one SQL statement per step:                                           *)
(*    1. UPDATE status [, sub_status] WHERE status IN                      *)
(*       allowed_transition_from -> Applied (462-494; an empty allowed set *)
(*       writes nothing and is left out);                                  *)
(*    2. no row changed: read the row, AlreadyCurrent or Rejected          *)
(*       (500-507);                                                        *)
(*    3. AlreadyCurrent with a sub_status: UPDATE sub_status WHERE status  *)
(*       = target (509-523);                                               *)
(*    4. that changed no row: read the row again (528).                    *)
(* Two writers interleave between any two statements: ChainReconcile,      *)
(*   always with a sub_status (node/src/aggregates/graph_pegout.rs:572),   *)
(*   and GoatEvent, without                                                *)
(*   (node/src/scheduled_tasks/event_watch/gateway.rs:312).                *)
(* Finding 1b: a guard read by one statement and a write by a later one    *)
(*   leave a gap in which another writer lands. Checked: the guard is part *)
(*   of the UPDATE and the sub_status write is status-guarded.             *)
(* Each writer picks any target its source can write, at any time, so      *)
(*   stale and replayed events are covered without modelling the chains.   *)
(* Configs: configs/node/aggregates/graph/GraphLifecycleFineGrainedFixed/, *)
(*   tiers in audit/tla/checks.txt.                                        *)
(***************************************************************************)
EXTENDS GraphTopology

\* The two racing writers.
WriterChainReconcile == "ChainReconcile"
WriterGoatEvent      == "GoatEvent"
Writers == {WriterChainReconcile, WriterGoatEvent}

\* The source each writer passes to transition_graph_status.
SourceOf(w) == IF w = WriterChainReconcile THEN SourceChainReconcile ELSE SourceGoatEvent

\* The writer passes a sub_status.
HasSubStatus(w) == w = WriterChainReconcile

\* Next statement of a transition_graph_status call.
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

\* Action: statement 1, writes target (and sub_status) iff the status is in the allowed set; else goes on to read the outcome.
\* Source: crates/store/src/localdb/graph.rs:462-494
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

\* Action: statement 2, reads the row; ends the call unless AlreadyCurrent with a sub_status. Writes nothing.
\* Source: crates/store/src/localdb/graph.rs:500-507
ReadOutcome(w) ==
    /\ pc[w] = PcReadOutcome
    /\ IF status = target[w] /\ HasSubStatus(w)
         THEN /\ pc' = [pc EXCEPT ![w] = PcUpdateSubStatus]
              /\ UNCHANGED target
         ELSE /\ pc' = [pc EXCEPT ![w] = PcIdle]
              /\ target' = [target EXCEPT ![w] = None]
    /\ UNCHANGED <<status, subFor>>

\* Action: statement 3, writes sub_status iff the status is still the target; else goes on to re-read.
\* Source: crates/store/src/localdb/graph.rs:509-523
UpdateSubStatus(w) ==
    /\ pc[w] = PcUpdateSubStatus
    /\ IF status = target[w]
         THEN /\ subFor' = target[w]
              /\ pc' = [pc EXCEPT ![w] = PcIdle]
              /\ target' = [target EXCEPT ![w] = None]
         ELSE /\ pc' = [pc EXCEPT ![w] = PcReReadOutcome]
              /\ UNCHANGED <<subFor, target>>
    /\ UNCHANGED status

\* Action: statement 4, re-reads the row after a lost sub_status race. Writes nothing.
\* Source: crates/store/src/localdb/graph.rs:528
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

\* None beyond TypeOk.

--------------------------------------------------------------------------
(* Safety properties *)

\* A closed status is never left, under any interleaving of statements.
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

\* Take-1 and Take-2 are never both recorded for one graph.
NoConflictingWithdrawal ==
    /\ [][(status = OperatorTake1 => status' # OperatorTake2)]_status
    /\ [][(status = OperatorTake2 => status' # OperatorTake1)]_status

\* A sub_status is only written onto the status it describes.
SubStatusWrittenWithItsStatus == [][(subFor' # subFor => subFor' = status')]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* None.

====
