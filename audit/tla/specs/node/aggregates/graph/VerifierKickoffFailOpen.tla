---- MODULE VerifierKickoffFailOpen ----
(***************************************************************************)
(* Issue #429: the verifier must answer a kickoff without an L2            *)
(*   initWithdraw with a Challenge. A challenge job that finishes while    *)
(*   GOAT SPV lags or its Challenge is unconfirmed (fail-open) lets Take1  *)
(*   through unchallenged.                                                 *)
(* Code: JOB_CHALLENGE_KICKOFF, queued by every chain scan that reports    *)
(*   KickoffSent (node/src/aggregates/graph_pegout.rs:264; scan coverage   *)
(*   is KickoffScanCoverage). A retry (after_blocks / broadcast_pending,   *)
(*   graph_pegout_jobs.rs:171-173, 230-232) is JobOutcome::Transient       *)
(*   (node/src/aggregates/jobs.rs:70-77). A closed graph ends the job      *)
(*   (settlement_step 95-97); a kicked graph is not closed before Take1.   *)
(*   challenge_kickoff (node/src/aggregates/graph_pegout_jobs.rs:595-647): *)
(*    599-601 kickoff unconfirmed -> retry;                                *)
(*    605-621 connector spent: unconfirmed -> retry, confirmed -> done;    *)
(*    622-634 status None/Canceled -> on, Initialized -> retry, else done; *)
(*    635-642 kickoff_height >= spv_height -> retry;                       *)
(*    644-646 send the Challenge, retry next block (resent if evicted).    *)
(* Scope: withdraw None, an open graph, one job run = one step. Assumed:   *)
(*   the connector_a margin is adequate (Take1 only after the job's final  *)
(*   decision) and GOAT SPV catches up (fairness); ChallengeKickoffGate    *)
(*   drops both. Not modelled: a Goat read classified Permanent            *)
(*   (node/src/error.rs:33) ends the job; these public getters do not      *)
(*   revert.                                                               *)
(* No parameters.                                                          *)
(* Configs: configs/node/aggregates/graph/VerifierKickoffFailOpen/, tiers  *)
(*   in audit/tla/checks.txt.                                              *)
(***************************************************************************)

\* engine_job states of the challenge job (Running is inside the atomic run step).
JobPending == "Pending"
JobDone    == "Done"
JobStates  == {JobPending, JobDone}

\* Where the verifier's Challenge transaction is.
ChallengeNone      == "None"
ChallengeMempool   == "Mempool"
ChallengeConfirmed == "Confirmed"
ChallengeStates    == {ChallengeNone, ChallengeMempool, ChallengeConfirmed}

VARIABLES
    job,         \* engine_job.state of JOB_CHALLENGE_KICKOFF for this graph
    spvLags,     \* kickoff_height >= btc_spv_latest_height (GOAT SPV not strictly past the kickoff)
    challenge,   \* ChallengeNone, ChallengeMempool or ChallengeConfirmed
    take1        \* the operator's Take1 confirmed (spent the challenge connector)

vars == <<job, spvLags, challenge, take1>>

TypeOk ==
    /\ job \in JobStates
    /\ spvLags \in BOOLEAN
    /\ challenge \in ChallengeStates
    /\ take1 \in BOOLEAN

\* The kickoff is confirmed and the job queued; GOAT SPV still lags the kickoff.
Init ==
    /\ job = JobPending
    /\ spvLags = TRUE
    /\ challenge = ChallengeNone
    /\ take1 = FALSE

\* A confirmed transaction (Challenge or Take1) spent the challenge connector.
ConnectorSpentConfirmed == challenge = ChallengeConfirmed \/ take1

--------------------------------------------------------------------------
\* Action: GOAT's SPV light client passes the kickoff height.
\* Source: node/src/scheduled_tasks/spv_maintenance_tasks.rs:9-39 (spv_header_hash_update)
SpvCatchesUp ==
    /\ spvLags
    /\ spvLags' = FALSE
    /\ UNCHANGED <<job, challenge, take1>>

\* Action: one run of challenge_kickoff: done on a confirmed spend, retry while SPV lags or the Challenge is pending, else broadcast and retry.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:595-647 (challenge_kickoff), 171-173, 230-232 (after_blocks, broadcast_pending)
\* Source: node/src/aggregates/jobs.rs:70-77 (Step::into_outcome)
ChallengeKickoffRun ==
    /\ job = JobPending
    /\ CASE ConnectorSpentConfirmed ->
                /\ job' = JobDone
                /\ UNCHANGED challenge
         [] challenge = ChallengeMempool \/ spvLags ->
                UNCHANGED <<job, challenge>>
         [] OTHER ->
                /\ challenge' = ChallengeMempool
                /\ UNCHANGED job
    /\ UNCHANGED <<spvLags, take1>>

\* Action: the broadcast Challenge is mined.
\* Source: Bitcoin consensus
ChallengeConfirms ==
    /\ challenge = ChallengeMempool
    /\ ~take1
    /\ challenge' = ChallengeConfirmed
    /\ UNCHANGED <<job, spvLags, take1>>

\* Action: the Challenge drops out of the mempool; the next run sends it again.
\* Source: environment (Bitcoin mempool)
ChallengeEvicted ==
    /\ challenge = ChallengeMempool
    /\ challenge' = ChallengeNone
    /\ UNCHANGED <<job, spvLags, take1>>

\* Action: the operator's Take1 spends the connector, possible only after the job's final decision (adequate connector_a margin).
\* Source: Bitcoin consensus (Take1 connector_a CSV leaf)
OperatorTake1 ==
    /\ job = JobDone
    /\ challenge # ChallengeConfirmed
    /\ ~take1
    /\ take1' = TRUE
    /\ UNCHANGED <<job, spvLags, challenge>>

Next ==
    \/ SpvCatchesUp
    \/ ChallengeKickoffRun
    \/ ChallengeConfirms
    \/ ChallengeEvicted
    \/ OperatorTake1

\* WF on SpvCatchesUp (assumed: the SPV updater keeps posting) and on
\* ChallengeKickoffRun (a Pending job is retried every block). SF on
\* ChallengeConfirms: re-enabled after every eviction, an honest fee gets it
\* mined (pinning is DefenderTxPinning).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(SpvCatchesUp)
    /\ WF_vars(ChallengeKickoffRun)
    /\ SF_vars(ChallengeConfirms)

--------------------------------------------------------------------------
\* ---- Safety invariants ----

\* No fail-open: the job finishes only once the connector is spent by a confirmed transaction.
JobDoneOnlyWhenConnectorSpent == job = JobDone => ConnectorSpentConfirmed

\* When Take1 lands, the verifier's Challenge is broadcast or confirmed (#429).
NoUnauthorizedTake1 == take1 => challenge # ChallengeNone

\* ---- Safety properties ----
\* None beyond the invariants.

\* ---- Liveness ----

\* The verifier's Challenge eventually confirms.
ChallengeEventuallyConfirmed == <>(challenge = ChallengeConfirmed)

====
