---- MODULE PeginPostRetry ----
(***************************************************************************)
(* The relayer's post_pegin_data job (node/src/aggregates/instance_jobs.rs *)
(* 984-1048, PostPeginDataRunner 1056-1073) and its retry by the engine    *)
(* (crates/engine/src/jobs.rs:225-244, backoff up to 600 s, config.rs:94). *)
(* Finding M4: gateway_post_pegin_data's "cannot cover fee" bail           *)
(*   (crates/client/src/goat_chain/mod.rs:478-485) is not one of the three *)
(*   permanent substrings (is_permanent_post_rejection, :975-980), so it   *)
(*   is Transient and retried forever; PostPeginDataRejected is raised     *)
(*   only on Failed (instance.rs:1126-1127). BTC sits in the Confirm,      *)
(*   nothing mints, nobody is alerted (PostTerminates).                    *)
(* Parameter: FeeMayDrop (governance may lower the Gateway fee).           *)
(* Fix (RunFixed): a typed FeeTooHigh rejection, classified like the other *)
(*   three: Rejected -> Failed -> PostPeginDataRejected. No ParamsOK.      *)
(* No timing parameters: the verdict depends only on how the error is      *)
(*   classified, not on the backoff or the fee values.                     *)
(* Configs: configs/node/aggregates/instance/PeginPostRetry/, tiers in     *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    FeeMayDrop   \* governance may lower the Gateway fee (not forced by fairness)

\* What gateway_post_pegin_data would answer now.
AnswerOk             == "Ok"              \* postPeginData lands
AnswerFeeTooHigh     == "FeeTooHigh"      \* "cannot cover fee" bail
AnswerAmountMismatch == "AmountMismatch"  \* one of the three permanent substrings
Answers == {AnswerOk, AnswerFeeTooHigh, AnswerAmountMismatch}

\* engine_job row states of the post job.
JobPending == "Pending"
JobDone    == "Done"
JobFailed  == "Failed"

VARIABLES
    gatewayAnswer,  \* what gateway_post_pegin_data would answer now (Answers)
    job,            \* engine_job row of post_pegin_data
    retryPhase,     \* the row's attempts, modulo 2 (makes a retry a visible step)
    minted,         \* postPeginData landed (BridgeIn -> RelayerL2Minted)
    alerted         \* InstanceAlert::PostPeginDataRejected raised

vars == <<gatewayAnswer, job, retryPhase, minted, alerted>>

TypeOk ==
    /\ gatewayAnswer \in Answers
    /\ job \in {JobPending, JobDone, JobFailed}
    /\ retryPhase \in {0, 1}
    /\ minted \in BOOLEAN
    /\ alerted \in BOOLEAN

Init ==
    /\ gatewayAnswer \in Answers
    /\ job = JobPending
    /\ retryPhase = 0
    /\ minted = FALSE
    /\ alerted = FALSE

-----------------------------------------------------------------------------
\* Outcomes of one run of the post job.

\* postPeginData lands: Done, the BridgeIn event mints.
PostSucceeds ==
    /\ gatewayAnswer = AnswerOk
    /\ job' = JobDone /\ minted' = TRUE
    /\ UNCHANGED <<gatewayAnswer, retryPhase, alerted>>

\* Rejected -> JobOutcome::Failed -> PostPeginDataRejected alert.
PostRejectedAlerted ==
    /\ job' = JobFailed /\ alerted' = TRUE
    /\ UNCHANGED <<gatewayAnswer, retryPhase, minted>>

\* Err -> JobOutcome::Transient -> Pending again after the backoff.
PostRetried ==
    /\ retryPhase' = 1 - retryPhase
    /\ UNCHANGED <<gatewayAnswer, job, minted, alerted>>

\* Action: the relayer's post job runs (current code): success mints; a
\* permanent substring fails and alerts; "cannot cover fee" is retried.
\* Source: PostPeginDataRunner::run() in node/src/aggregates/instance_jobs.rs:1056-1073
\* Source: post_pegin_data() in instance_jobs.rs:1032-1040; is_permanent_post_rejection() :975-980
\* Source: gateway_post_pegin_data() in crates/client/src/goat_chain/mod.rs:478-485
\* Source: execute_job() in crates/engine/src/jobs.rs:225-244
\* Source: apply_job_result() in node/src/aggregates/instance.rs:1122-1135
RunCurrent ==
    /\ job = JobPending
    /\ \/ PostSucceeds
       \/ gatewayAnswer = AnswerAmountMismatch /\ PostRejectedAlerted
       \/ gatewayAnswer = AnswerFeeTooHigh /\ PostRetried

\* Action: the post job runs (fix): FeeTooHigh is a typed rejection, so it
\* fails and alerts.
\* Source: fix design for post_pegin_data() in node/src/aggregates/instance_jobs.rs:1036-1040
RunFixed ==
    /\ job = JobPending
    /\ \/ PostSucceeds
       \/ gatewayAnswer \in {AnswerAmountMismatch, AnswerFeeTooHigh} /\ PostRejectedAlerted

\* Action: governance lowers the Gateway fee; the post would now succeed.
\* Source: environment (governance, Gateway.sol fee setters)
LowerFee ==
    /\ FeeMayDrop
    /\ gatewayAnswer = AnswerFeeTooHigh
    /\ gatewayAnswer' = AnswerOk
    /\ UNCHANGED <<job, retryPhase, minted, alerted>>

Next ==
    \/ RunCurrent
    \/ LowerFee

NextFixed ==
    \/ RunFixed
    \/ LowerFee

\* Weak fairness for the job executor only: claim_and_spawn()
\* (crates/engine/src/jobs.rs:133) claims a due Pending row on every tick.
\* Governance is not fair.
FairSpec      == Init /\ [][Next]_vars      /\ WF_vars(RunCurrent)
FairSpecFixed == Init /\ [][NextFixed]_vars /\ WF_vars(RunFixed)

-----------------------------------------------------------------------------
(* Liveness *)

\* Every post job ends in a mint or in an alerted rejection.
PostTerminates == <>(minted \/ alerted)

====
