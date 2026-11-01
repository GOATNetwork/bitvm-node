---- MODULE MessageStateRace ----
(***************************************************************************)
(* Round-1 Finding 7 (audit/TLAPlus-20260710.md): a cancelled unit of work *)
(* must never become dispatchable again - originally a periodic producer's *)
(* unconditional upsert resurrected a Cancelled local message to Pending,  *)
(* and a worker that had already claimed a row could overwrite the cancel. *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476). The local_message table and its *)
(* claim/defer/cancel_messages_by_business_id helpers are gone. Their      *)
(* successor is the engine's leased job table `engine_job`                 *)
(* (crates/store/src/engine/mod.rs, EngineJobState 30-37:                  *)
(* Pending, Running, Done, Failed, Cancelled, Poisoned), driven by         *)
(*   - aggregate applies (crates/engine/src/worker.rs commit_apply         *)
(*     283-365): enqueue = insert_engine_job (INSERT OR IGNORE, 1276-1315) *)
(*     under a stable job id (crates/engine/src/effects.rs 29-43); cancel  *)
(*     = cancel_engine_job / _for_phase / _for_aggregate (1508-1612);      *)
(*   - executors (crates/engine/src/jobs.rs): claim_due_engine_jobs        *)
(*     (1336-1395, new generation + lease), lease renewal (306-363 ->      *)
(*     renew_engine_job_lease 1417-1437), finish_engine_job (1440-1505,    *)
(*     generation-fenced, inside an immediate transaction, jobs.rs 366-    *)
(*     376), finish_lapsed_cancelled_engine_jobs (1398-1415);              *)
(*   - housekeeping (crates/engine/src/runtime.rs run_housekeeping         *)
(*     441-463): purge_engine_terminal_rows (754-777) deletes terminal     *)
(*     rows older than terminal_retention_secs (15 days, config.rs 101).   *)
(* Each of those is one SQL statement or one transaction: one action here. *)
(*                                                                         *)
(* Mapping from the old model: Claim -> ClaimJob, BulkCancelOnGraphClose   *)
(* -> CancelJob, WorkerComplete/OwnerDefer -> FinishJob(Done/Retry),       *)
(* StaleWorkerReturns -> FinishJob's fenced branch, GuardedUpsert ->       *)
(* EnqueueJob (INSERT OR IGNORE: an existing row is never rewritten).      *)
(*                                                                         *)
(* ENVIRONMENT ASSUMPTIONS (documented, not code):                         *)
(*   A1 The aggregate stops asking for a job once it cancels it: every     *)
(*      cancel site in node/src/aggregates (graph.rs 916-924, 1127;        *)
(*      graph_pegout.rs 509, 520, 544; instance.rs 783-858) leaves the     *)
(*      phase or retires the withdraw that derived the job id. The one     *)
(*      re-request (graph_pegout.rs 600-618, a watchtower challenge job    *)
(*      asked for and cancelled in the same scan) is applied in one        *)
(*      commit, insert before cancel, so it never runs either.             *)
(*   A2 A purge happens only after terminal_retention_secs (15 days), far  *)
(*      beyond any job lease (300 s) and the bounded finish retries        *)
(*      (jobs.rs 252-301), so no executor still holds a generation of the  *)
(*      purged row. Without A2 a re-inserted row restarts at generation 0  *)
(*      and a 15-day-old holder could match a new generation (ABA).        *)
(*                                                                         *)
(* CONFIGS: MessageStateRace/Fixed.cfg (tier pass) - the current code.      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Executors,      \* job execution tasks that may hold a claim (jobs.rs spawn_job)
    MaxGeneration   \* bound on claims per row incarnation (model-checking bound)

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

\* Terminal rows: never claimed again, only purged (purge_engine_terminal_rows).
TerminalStatuses == {JobDone, JobFailed, JobCancelled, JobPoisoned}

\* What an executor reports (EngineJobFinish, mod.rs 389-398).
FinishDone     == "Done"
FinishRetry    == "Retry"
FinishFailed   == "Failed"
FinishPoisoned == "Poisoned"
FinishOutcomes == {FinishDone, FinishRetry, FinishFailed, FinishPoisoned}

NoClaim == 0   \* heldGeneration value of an executor that holds nothing

VARIABLES
    jobState,         \* engine_job.state of the modeled job id
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
\* Action: an aggregate apply asks for the job and the row does not exist:
\* INSERT OR IGNORE creates it Pending at generation 0. Asking again for an
\* existing id (any state) is ignored - the old "guarded upsert", now a no-op
\* on every state, so it is not a separate step.
\* Source: commit_apply() in crates/engine/src/worker.rs:314-350;
\*         insert_engine_job() in crates/store/src/engine/mod.rs:1276-1315
EnqueueJob ==
    /\ wanted
    /\ jobState = JobAbsent
    /\ jobState' = JobPending
    /\ generation' = 0
    /\ cancelRequested' = FALSE
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<heldGeneration, wanted>>

\* Action: executor e claims the job - a due Pending row, or a Running row
\* whose lease lapsed without a cancel request - bumping the generation (the
\* fence against the previous holder) and taking a fresh lease.
\* Source: claim_and_spawn() in crates/engine/src/jobs.rs:133-168;
\*         claim_due_engine_jobs() in crates/store/src/engine/mod.rs:1336-1395
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

\* Action: e's renewal task extends a lapsed lease. The UPDATE matches on
\* generation and state = 'Running' only, so a holder whose lease lapsed but
\* was not re-claimed gets it back.
\* Source: spawn_lease_renewal() in crates/engine/src/jobs.rs:306-363;
\*         renew_engine_job_lease() in crates/store/src/engine/mod.rs:1417-1437
RenewLease(e) ==
    /\ HoldsCurrent(e)
    /\ jobState = JobRunning
    /\ ~leaseLive
    /\ leaseLive' = TRUE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: executor e reports `outcome`. Only the current generation of a
\* Running row writes: Done/Retry become Cancelled when a cancel was
\* requested, else Done/Pending; Failed/Poisoned are recorded as is. Any
\* other holder (lease lost and re-claimed, row cancelled or finished, row
\* purged) gets Stale/Missing and writes nothing - the old StaleWorkerReturns.
\* Source: execute_job()/record_job_finish() in crates/engine/src/jobs.rs:188-301,366-376;
\*         finish_engine_job() in crates/store/src/engine/mod.rs:1440-1505
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

\* Action: executor e goes away without recording its result (finish
\* retries exhausted after lease loss, or the process stopped).
\* Source: execute_job() in crates/engine/src/jobs.rs:252-301 ("finish_failed");
\*         reset_engine_job_leases() at startup, crates/engine/src/runtime.rs:392
ExecutorAbandons(e) ==
    /\ heldGeneration[e] # NoClaim
    /\ heldGeneration' = [heldGeneration EXCEPT ![e] = NoClaim]
    /\ UNCHANGED <<jobState, generation, leaseLive, cancelRequested, wanted>>

\* Action: time passes with nobody renewing the current generation, so its
\* lease (job_lease_secs = 300) lapses.
\* Source: environment (clock vs. lease_until; crates/engine/src/config.rs:92)
LeaseExpires ==
    /\ jobState = JobRunning
    /\ leaseLive
    /\ \A e \in Executors : ~HoldsCurrent(e)
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: the holder is alive but its renewal did not land in time (stall,
\* DB contention, restart via reset_engine_job_leases).
\* Source: environment; reset_engine_job_leases() in crates/store/src/engine/mod.rs:1631-1638
HolderLeaseLapses ==
    /\ jobState = JobRunning
    /\ leaseLive
    /\ \E e \in Executors : HoldsCurrent(e)
    /\ leaseLive' = FALSE
    /\ UNCHANGED <<jobState, generation, cancelRequested, heldGeneration, wanted>>

\* Action: the executor loop finishes a Running row that was asked to cancel
\* and whose lease lapsed as Cancelled, instead of running it again.
\* Source: finish_lapsed_cancelled() in crates/engine/src/jobs.rs:94-131 (called from run_executor, 75);
\*         finish_lapsed_cancelled_engine_jobs() in crates/store/src/engine/mod.rs:1398-1415
FinishLapsedCancelled ==
    /\ jobState = JobRunning
    /\ ~leaseLive
    /\ cancelRequested
    /\ jobState' = JobCancelled
    /\ UNCHANGED <<generation, leaseLive, cancelRequested, heldGeneration, wanted>>

\* Action: the aggregate cancels the job (its graph/instance closed, the
\* phase ended, the withdraw was retired) and stops asking for it (A1). A
\* Pending row becomes Cancelled at once; a Running row is flagged and
\* finishes Cancelled when its holder reports or its lease lapses; any other
\* row is left as is. The old BulkCancelOnGraphClose.
\* Source: commit_apply() in crates/engine/src/worker.rs:351-365;
\*         cancel_engine_job() / cancel_engine_jobs_for_aggregate() / cancel_engine_jobs_for_phase()
\*         in crates/store/src/engine/mod.rs:1508-1534,1536-1568,1587-1612
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

\* Action: housekeeping deletes a terminal row past the retention period
\* (A2: no executor still holds one of its generations).
\* Source: run_housekeeping() in crates/engine/src/runtime.rs:441-463;
\*         purge_engine_terminal_rows() in crates/store/src/engine/mod.rs:754-777
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

\* Fairness, each justified by the code:
\*  - FinishJob(e): execute_job always ends in record_job_finish (panics are
\*    caught as Poisoned, jobs.rs 222-248); ExecutorAbandons is the
\*    unfair alternative.
\*  - LeaseExpires: with no holder renewing, lease_until is passed in time.
\*  - FinishLapsedCancelled: run_executor calls it on every loop (jobs.rs 75).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A e \in Executors : WF_vars(\E o \in FinishOutcomes : FinishJob(e, o))
    /\ WF_vars(LeaseExpires)
    /\ WF_vars(FinishLapsedCancelled)

-----------------------------------------------------------------------------
\* ---- Safety invariants ----

\* Generation fencing: at most one executor can write the row.
SingleCurrentHolder ==
    Cardinality({e \in Executors : HoldsCurrent(e)}) <= 1

\* ---- Safety properties ----

\* A terminal row (Cancelled in particular) is never rewritten - not by a
\* stale holder, a re-enqueue or a cancel; it can only be purged.
TerminalStatusesAreAbsorbing ==
    [][(jobState \in TerminalStatuses => jobState' \in {jobState, JobAbsent})]_jobState

\* Finding 7: once cancelled, the job is never dispatchable again, even
\* after its row is purged.
CancelledNeverDispatchable ==
    [](jobState = JobCancelled => [](jobState \notin {JobPending, JobRunning}))

\* ---- Liveness ----

\* A cancel request on a running job is honoured: the row leaves
\* Pending/Running (Cancelled, or Failed/Poisoned if the holder reports so).
CancelRequestHonoured ==
    cancelRequested ~> (jobState \notin {JobPending, JobRunning})

====
