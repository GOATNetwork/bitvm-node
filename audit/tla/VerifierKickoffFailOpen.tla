---- MODULE VerifierKickoffFailOpen ----
(***************************************************************************)
(* Issue #429: "[Security] Verifier KickoffSent challenge is one-shot and  *)
(* fail-open (unauthorized Take1)". An operator broadcasts a kickoff with  *)
(* NO L2 initWithdraw (no pegBTC burned); the verifier must answer with a  *)
(* Challenge. The bug: while GOAT SPV had not passed the kickoff height,   *)
(* handle_kickoff_sent_verifier returned Ok(()) without deferring, the     *)
(* KickoffSent message was marked Processed and never retried, so no       *)
(* Challenge was ever sent and the operator's Take1 went through. Fixed by *)
(* #455 (defer), and #476 replaced the message handler by an engine job.   *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8): the verifier's JOB_CHALLENGE_KICKOFF,       *)
(* queued by the Graph aggregate for every chain scan that reports         *)
(* KickoffSent (route_signal, node/src/aggregates/graph_pegout.rs 264;     *)
(* coverage of that scan: KickoffScanCoverage.tla) and run by              *)
(* challenge_kickoff, node/src/aggregates/graph_pegout_jobs.rs 595-647:    *)
(*   599-601  kickoff not confirmed          -> after_blocks(1)  (retry)   *)
(*   605-621  challenge connector spent: unconfirmed -> retry; confirmed   *)
(*            (by Take-1 or a Challenge)     -> Step::ignore     (done)    *)
(*   622-634  withdraw None/Canceled -> go on; Initialized -> retry;       *)
(*            other (Processing, ...)        -> Step::ignore     (done)    *)
(*   635-642  kickoff_height >= spv_height   -> after_blocks     (retry)   *)
(*   644-646  send_challenge_tx, broadcast_pending -> retry next block,    *)
(*            so an evicted Challenge is sent again and a confirmed one    *)
(*            ends the job.                                                *)
(* after_blocks / broadcast_pending (171-173, 230-232) are Step::retry ->  *)
(* JobOutcome::Transient -> engine_job back to Pending (MessageStateRace). *)
(* A closed graph ends the job (settlement_step 84-97), but a graph with a *)
(* pending kickoff and no Take1 is not closed.                             *)
(*                                                                         *)
(* SCOPE OF THIS MODEL: withdraw status None (the unauthorized case) and   *)
(* an open graph; the job's lease/claim mechanics are abstracted (one run  *)
(* = one atomic step). The ConnectorA CSV margin is ASSUMED adequate: Take1 *)
(* becomes spendable only after the verifier's job has reached its final  *)
(* decision (OperatorTake1 guard), and GOAT SPV catches up (fairness).     *)
(* ChallengeKickoffGate.tla drops both assumptions and models heights (C6).*)
(* Not modeled: a Goat read error classified Permanent (contains "revert", *)
(* node/src/error.rs 45-77) would end the job as "rejected" (graph_jobs.rs *)
(* 130-135) - the reads here are public getters, which do not revert.      *)
(*                                                                         *)
(* CONFIGS: VerifierKickoffFailOpenFixed.cfg (tier pass) - the current     *)
(* code.                                                                   *)
(***************************************************************************)

\* engine_job state of the verifier's challenge_kickoff job (Running is
\* folded into the atomic run step).
JobPending == "Pending"
JobDone    == "Done"
JobStates  == {JobPending, JobDone}

\* The verifier's Challenge transaction on Bitcoin.
ChallengeNone      == "None"
ChallengeMempool   == "Mempool"
ChallengeConfirmed == "Confirmed"
ChallengeStates    == {ChallengeNone, ChallengeMempool, ChallengeConfirmed}

VARIABLES
    job,         \* engine_job.state of JOB_CHALLENGE_KICKOFF for this graph
    spvLags,     \* kickoff_height >= btc_spv_latest_height (GOAT SPV not strictly past the kickoff)
    challenge,   \* where the verifier's Challenge transaction is
    take1        \* the operator's Take1 confirmed (spent the challenge connector)

vars == <<job, spvLags, challenge, take1>>

TypeOk ==
    /\ job \in JobStates
    /\ spvLags \in BOOLEAN
    /\ challenge \in ChallengeStates
    /\ take1 \in BOOLEAN

\* The kickoff is confirmed and the scan queued the job; at first
\* confirmation GOAT SPV lags the Bitcoin tip (the common case).
Init ==
    /\ job = JobPending
    /\ spvLags = TRUE
    /\ challenge = ChallengeNone
    /\ take1 = FALSE

\* The challenge connector is spent by a confirmed transaction.
ConnectorSpentConfirmed == challenge = ChallengeConfirmed \/ take1

--------------------------------------------------------------------------
\* Action: GOAT's SPV light client is updated past the kickoff height.
\* Source: spv_header_hash_update() in node/src/scheduled_tasks/spv_maintenance_tasks.rs:9
\*         (called from run() in node/src/scheduled_tasks/mod.rs:220-227); environment (GOAT)
SpvCatchesUp ==
    /\ spvLags
    /\ spvLags' = FALSE
    /\ UNCHANGED <<job, challenge, take1>>

\* Action: one run of the verifier's challenge_kickoff job. A confirmed spend
\* of the connector ends it (Done); a Challenge still in the mempool, or SPV
\* not past the kickoff, is a retry (the job stays Pending - the #429 fix);
\* otherwise the Challenge is broadcast and the job retries next block.
\* Source: challenge_kickoff() in node/src/aggregates/graph_pegout_jobs.rs:595-647;
\*         after_blocks()/broadcast_pending() in node/src/aggregates/graph_pegout_jobs.rs:171-173,230-232;
\*         Step::into_outcome() in node/src/aggregates/jobs.rs:70-77
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

\* Action: the Challenge drops out of the mempool (fee pressure, restart);
\* the next run sees the connector unspent and sends it again.
\* Source: environment (Bitcoin mempool)
ChallengeEvicted ==
    /\ challenge = ChallengeMempool
    /\ challenge' = ChallengeNone
    /\ UNCHANGED <<job, spvLags, take1>>

\* Action: after the ConnectorA CSV the operator spends the connector with
\* Take1. Under the adequate-margin assumption that is only possible once
\* the verifier's job has reached its final decision; it is an unauthorized
\* withdrawal unless a Challenge confirmed first (which would spend the
\* same connector).
\* Source: Bitcoin consensus (Take1, n-of-n pre-signed, connector_a CSV)
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

\* Fairness:
\*  - SpvCatchesUp (WF): assumption - the SPV updater keeps posting headers
\*    (ChallengeKickoffGate C6 is what happens without a deadline on it).
\*  - ChallengeKickoffRun (WF): a Pending job is retried every block
\*    (after_blocks waits at least one block, jobs.rs claim loop).
\*  - ChallengeConfirms (SF): a re-broadcast Challenge is enabled again
\*    after every eviction; an honest fee eventually gets it mined (pinning
\*    is DefenderTxPinning.tla).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(SpvCatchesUp)
    /\ WF_vars(ChallengeKickoffRun)
    /\ SF_vars(ChallengeConfirms)

--------------------------------------------------------------------------
\* ---- Safety invariants ----

\* No fail-open: the job is never finished while the connector is unspent.
JobDoneOnlyWhenConnectorSpent == job = JobDone => ConnectorSpentConfirmed

\* An unauthorized kickoff never reaches Take1 without the verifier's
\* Challenge (the #429 property).
NoUnauthorizedTake1 == take1 => challenge # ChallengeNone

\* ---- Safety properties ----
\* None beyond the invariants.

\* ---- Liveness ----

\* The verifier's Challenge eventually confirms.
ChallengeEventuallyConfirmed == <>(challenge = ChallengeConfirmed)

====
