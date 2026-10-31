---- MODULE MessageStateRace ----
(***************************************************************************)
(* Model the local-message cancellation race, including a worker which has *)
(* already claimed a Pending row. The current Rust implementation uses     *)
(* state/version CAS operations for claim completion and owner defer, and  *)
(* cancel_messages_by_business_id reaches both Pending and Processing.     *)
(*                                                                         *)
(* FairSpec retains the pre-fix unconditional upsert as a historical bug   *)
(* reproduction. FairSpecFixed models the guarded upsert now implemented   *)
(* by crates/store/src/localdb.rs.                                         *)
(***************************************************************************)

Statuses == {"Pending", "Processing", "Processed", "Cancelled"}
TerminalStatuses == {"Cancelled"}

VARIABLES status, workerActive
vars == <<status, workerActive>>

TypeOK ==
    /\ status \in Statuses
    /\ workerActive \in BOOLEAN

Init ==
    /\ status = "Pending"
    /\ workerActive = FALSE

-----------------------------------------------------------------------------
\* claim_local_messages: only an available Pending row can be claimed.
Claim ==
    /\ status = "Pending"
    /\ ~workerActive
    /\ status' = "Processing"
    /\ workerActive' = TRUE

\* Terminal graph/instance handling cancels queued and already-claimed work.
BulkCancelOnGraphClose ==
    /\ status \in {"Pending", "Processing"}
    /\ status' = "Cancelled"
    /\ UNCHANGED workerActive

\* A live owner may complete or defer only the Processing row it claimed.
WorkerComplete ==
    /\ workerActive
    /\ status = "Processing"
    /\ status' = "Processed"
    /\ workerActive' = FALSE

OwnerDefer ==
    /\ workerActive
    /\ status = "Processing"
    /\ status' = "Pending"
    /\ workerActive' = FALSE

\* After cancellation, the old worker's guarded write affects zero rows.
StaleWorkerReturns ==
    /\ workerActive
    /\ status # "Processing"
    /\ UNCHANGED status
    /\ workerActive' = FALSE

\* Historical behavior: a periodic producer could resurrect any state.
UnconditionalUpsert ==
    /\ status' = "Pending"
    /\ UNCHANGED workerActive

\* Current behavior: Processing and terminal rows reject fallback upserts.
GuardedUpsert ==
    /\ status \notin {"Processing", "Cancelled"}
    /\ status' = "Pending"
    /\ UNCHANGED workerActive

Next ==
    \/ Claim
    \/ BulkCancelOnGraphClose
    \/ WorkerComplete
    \/ OwnerDefer
    \/ StaleWorkerReturns
    \/ UnconditionalUpsert

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Next)

NextFixed ==
    \/ Claim
    \/ BulkCancelOnGraphClose
    \/ WorkerComplete
    \/ OwnerDefer
    \/ StaleWorkerReturns
    \/ GuardedUpsert

SpecFixed == Init /\ [][NextFixed]_vars
FairSpecFixed == SpecFixed /\ WF_vars(NextFixed)

-----------------------------------------------------------------------------
\* Once administratively cancelled, neither an old worker nor a producer may
\* make the message dispatchable again.
TerminalStatusesAreAbsorbing ==
    [][(status \in TerminalStatuses => status' = status)]_status

====
