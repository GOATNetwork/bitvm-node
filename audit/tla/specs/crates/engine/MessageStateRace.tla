---- MODULE MessageStateRace ----
(***************************************************************************)
(* Finding 7 (round 1): a cancelled unit of work must never become         *)
(* dispatchable again, and a worker holding a stale claim must not         *)
(* overwrite a cancel.                                                     *)
(*                                                                         *)
(* Models one row of the engine job table engine_job (EngineJobState,      *)
(* crates/store/src/engine/mod.rs:30-37) and its writers, each one SQL     *)
(* statement or transaction: enqueue (INSERT OR IGNORE under a stable job  *)
(* id) and cancel from commit_apply (crates/engine/src/worker.rs); claim,  *)
(* lease renewal, generation-fenced finish and lapsed-cancel sweep from    *)
(* the executor (crates/engine/src/jobs.rs); terminal-row purge from       *)
(* housekeeping (crates/engine/src/runtime.rs).                            *)
(* Environment assumptions:                                                *)
(*   A1 once an aggregate cancels a job it never asks for it again (every  *)
(*      cancel site leaves the phase or retires the withdraw that derived  *)
(*      the job id; graph_pegout.rs:598-621 enqueues and cancels in one    *)
(*      commit, insert first).                                             *)
(*   A2 a row is purged only after terminal_retention_secs (15 days), far  *)
(*      beyond the 300 s lease, so no executor still holds a generation of *)
(*      it (otherwise a re-inserted row restarting at generation 0 is      *)
(*      ABA).                                                              *)
(* Parameters: Executors (concurrent executor tasks); MaxGeneration        *)
(* (claims per row incarnation, a model bound). No ParamsOK: the           *)
(* properties do not depend on timing.                                     *)
(* Configs: configs/crates/engine/MessageStateRace/, tiers in              *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Executors,      \* executor tasks that may hold a claim (jobs.rs spawn_job)
    MaxGeneration   \* model bound on claims per row incarnation

ASSUME MaxGeneration \in Nat \ {0}

\* engine_job.state, plus JobAbsent = no row (not inserted yet, or purged).
JobAbsent    == "Absent"
JobPending   == "Pending"
JobRunning   == "Running"
JobDone      == "Done"
JobFailed    == "Failed"
JobCancelled == "Cancelled"
JobPoisoned  == "Poisoned"

JobStates == {JobAbsent, JobPending, JobRunning, JobDone, JobFailed, JobCancelled, JobPoisoned}

\* Terminal states: never claimed again, only purged.
TerminalStatuses == {JobDone, JobFailed, JobCancelled, JobPoisoned}

\* What an executor reports (EngineJobFinish, crates/store/src/engine/mod.rs:389-398).
FinishDone     == "Done"
FinishRetry    == "Retry"
FinishFailed   == "Failed"
FinishPoisoned == "Poisoned"
FinishOutcomes == {FinishDone, FinishRetry, FinishFailed, FinishPoisoned}

NoClaim == 0   \* heldGeneration value of an executor that holds nothing

VARIABLES
    jobState,         \* engine_job.state of the modelled job id
    generation,       \* engine_job.generation (0 = never claimed in this incarnation)
    leaseLive,        \* engine_job.lease_until > now
    cancelRequested,  \* engine_job.cancel_requested
    heldGeneration,   \* [Executors -> generation the executor claimed, or NoClaim]
    wanted            \* the owning aggregate still asks for this job id (A1)

vars == <<jobState, generation, leaseLive, cancelRequested, heldGeneration, wanted>>

Generations == 0 .. MaxGeneration

TypeOk ==
    /\ jobState \in JobStates
    /\ generation \in Generations
    /\ leaseLive \in BOOLEAN
    /\ cancelRequested \in BOOLEAN
    /\ heldGeneration \in [Executors -> Generations]
    /\ wanted \in BOOLEAN

Init ==
    /\ jobState = JobAbsent
    /\ generation = 0
    /\ leaseLive = FALSE
    /\ cancelRequested = FALSE
    /\ heldGeneration = [e \in Executors |-> NoClaim]
    /\ wanted = TRUE

\* Executor e holds the row's current generation.
HoldsCurrent(e) == heldGeneration[e] = generation /\ generation # 0

-----------------------------------------------------------------------------
\* Action: aggregate apply creates the absent row Pending at generation 0
\* (asking for an existing id is ignored, so not a step).
\* Source: crates/engine/src/worker.rs:313-350; crates/store/src/engine/mod.rs:1276-1315
EnqueueJob ==
    /\ wanted
    /\ jobState = JobAbsent
    /\ jobState' = JobPending
    /\ generation' = 0
    /\ cancelRequested' = FALSE
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<heldGeneration, wanted>>

\* Action: executor e claims a Pending row, or a Running row with a lapsed
\* lease and no cancel request: new generation, fresh lease.
\* Source: crates/engine/src/jobs.rs:133-168; crates/store/src/engine/mod.rs:1336-1393
ClaimJob(e) ==
    /\ heldGeneration[e] = NoClaim
    /\ generation < MaxGeneration
    /\ \/ jobState = JobPending
       \/ jobState = JobRunning /\ ~leaseLive /\ ~cancelRequested
    /\ jobState' = JobRunning
    /\ generation' = generation + 1
    /\ leaseLive' = TRUE
    /\ heldGeneration' = [heldGeneration EXCEPT ![e] = generation + 1]
    /\ UNCHANGED <<cancelRequested, wanted>>

\* Action: e's renewal task restores a lapsed lease while e still holds the
\* current generation (the UPDATE matches generation and Running only).
\* Source: crates/engine/src/jobs.rs:306-364; crates/store/src/engine/mod.rs:1417-1436
RenewLease(e) ==
    /\ HoldsCurrent(e)
    /\ jobState = JobRunning
    /\ ~leaseLive
    /\ leaseLive' = TRUE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: executor e reports outcome; only the current generation of a
\* Running row writes (Done/Retry -> Cancelled if cancel requested, else
\* Done/Pending; Failed/Poisoned as is); any other holder writes nothing.
\* Source: crates/engine/src/jobs.rs:188-301,366-516 (immediate tx at 375-376);
\*         crates/store/src/engine/mod.rs:1440-1504
FinishJob(e, outcome) ==
    /\ heldGeneration[e] # NoClaim
    /\ IF HoldsCurrent(e) /\ jobState = JobRunning
          THEN /\ jobState' =
                    CASE outcome = FinishDone     -> IF cancelRequested THEN JobCancelled ELSE JobDone
                      [] outcome = FinishRetry    -> IF cancelRequested THEN JobCancelled ELSE JobPending
                      [] outcome = FinishFailed   -> JobFailed
                      [] outcome = FinishPoisoned -> JobPoisoned
               /\ leaseLive' = FALSE
          ELSE UNCHANGED <<jobState, leaseLive>>
    /\ heldGeneration' = [heldGeneration EXCEPT ![e] = NoClaim]
    /\ UNCHANGED <<generation, cancelRequested, wanted>>

\* Action: executor e drops its claim without recording a result (finish
\* retries exhausted after lease loss, or process restart).
\* Source: crates/engine/src/jobs.rs:252-301; crates/engine/src/runtime.rs:392
ExecutorAbandons(e) ==
    /\ heldGeneration[e] # NoClaim
    /\ heldGeneration' = [heldGeneration EXCEPT ![e] = NoClaim]
    /\ UNCHANGED <<jobState, generation, leaseLive, cancelRequested, wanted>>

\* Action: with no holder renewing, the lease (job_lease_secs = 300) lapses.
\* Source: environment (clock vs. lease_until; crates/engine/src/config.rs:92)
LeaseExpires ==
    /\ jobState = JobRunning
    /\ leaseLive
    /\ \A e \in Executors : ~HoldsCurrent(e)
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: the lease lapses while its holder is alive (stall, DB contention,
\* or restart).
\* Source: environment; crates/store/src/engine/mod.rs:1631-1638
HolderLeaseLapses ==
    /\ jobState = JobRunning
    /\ leaseLive
    /\ \E e \in Executors : HoldsCurrent(e)
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: executor loop marks a cancel-requested Running row with a lapsed
\* lease Cancelled.
\* Source: crates/engine/src/jobs.rs:94-131 (called at 75); crates/store/src/engine/mod.rs:1398-1414
FinishLapsedCancelled ==
    /\ jobState = JobRunning
    /\ ~leaseLive
    /\ cancelRequested
    /\ jobState' = JobCancelled
    /\ UNCHANGED <<generation, leaseLive, cancelRequested, heldGeneration, wanted>>

\* Action: aggregate cancels the job and stops asking for it (A1): Pending ->
\* Cancelled, Running -> cancel_requested, other states unchanged.
\* Source: crates/engine/src/worker.rs:351-366;
\*         crates/store/src/engine/mod.rs:1508-1532,1536-1564,1587-1612
CancelJob ==
    /\ wanted
    /\ wanted' = FALSE
    /\ CASE jobState = JobPending ->
                /\ jobState' = JobCancelled
                /\ UNCHANGED cancelRequested
         [] jobState = JobRunning ->
                /\ cancelRequested' = TRUE
                /\ UNCHANGED jobState
         [] OTHER ->
                UNCHANGED <<jobState, cancelRequested>>
    /\ UNCHANGED <<generation, leaseLive, heldGeneration>>

\* Action: housekeeping deletes a terminal row past retention (A2: no holder left).
\* Source: crates/engine/src/runtime.rs:441-464 (purge at 450-452); crates/store/src/engine/mod.rs:754-778
PurgeTerminalRow ==
    /\ jobState \in TerminalStatuses
    /\ \A e \in Executors : heldGeneration[e] = NoClaim
    /\ jobState' = JobAbsent
    /\ generation' = 0
    /\ leaseLive' = FALSE
    /\ cancelRequested' = FALSE
    /\ UNCHANGED <<heldGeneration, wanted>>

Next ==
    \/ EnqueueJob
    \/ \E e \in Executors : ClaimJob(e)
    \/ \E e \in Executors : RenewLease(e)
    \/ \E e \in Executors, o \in FinishOutcomes : FinishJob(e, o)
    \/ \E e \in Executors : ExecutorAbandons(e)
    \/ LeaseExpires
    \/ HolderLeaseLapses
    \/ FinishLapsedCancelled
    \/ CancelJob
    \/ PurgeTerminalRow

\* Fairness: FinishJob(e) - execute_job always reaches record_job_finish
\* (a panic becomes Poisoned, jobs.rs:223-246); LeaseExpires - time passes;
\* FinishLapsedCancelled - run_executor calls it every loop (jobs.rs:75).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A e \in Executors : WF_vars(\E o \in FinishOutcomes : FinishJob(e, o))
    /\ WF_vars(LeaseExpires)
    /\ WF_vars(FinishLapsedCancelled)

-----------------------------------------------------------------------------
\* At most one executor holds the current generation (can write the row).
SingleCurrentHolder ==
    Cardinality({e \in Executors : HoldsCurrent(e)}) <= 1

\* A terminal row is never rewritten, only purged.
TerminalStatusesAreAbsorbing ==
    [][(jobState \in TerminalStatuses => jobState' \in {jobState, JobAbsent})]_jobState

\* Finding 7: once Cancelled, the job is never Pending or Running again, even after purge.
CancelledNeverDispatchable ==
    [](jobState = JobCancelled => [](jobState \notin {JobPending, JobRunning}))

\* A cancel request is honoured: the row leaves Pending/Running.
CancelRequestHonoured ==
    cancelRequested ~> (jobState \notin {JobPending, JobRunning})

====
