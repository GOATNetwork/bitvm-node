---- MODULE PeginPostRetry ----
(***************************************************************************)
(* PURPOSE. Finding M4: the relayer's post_pegin_data job retries a fee    *)
(* rejection forever, silently, while the user's BTC sits in Peg-In-       *)
(* Confirm and nothing is minted. The dual of JobObligationPersistence     *)
(* (b): there ANY revert text is Permanent; here only three substrings are.*)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476):                                 *)
(*  crates/client/src/goat_chain/mod.rs:474-485 (gateway_post_pegin_data, *)
(*  :424):                                                                 *)
(*      let pegin_fee_sats = min_pegin_fee_sats                            *)
(*                + pegin_amount_sats * pegin_fee_rate / GATEWAY_RATE_..;  *)
(*      if pegin_fee_sats >= pegin_amount_sats {                           *)
(*          bail!("instance_id:{..} pegin amount:{..} cannot cover fee:..")*)
(*      }                                                                  *)
(*  node/src/aggregates/instance_jobs.rs:975-980:                          *)
(*      fn is_permanent_post_rejection(error) -> bool {                    *)
(*          ["not a pending pegin request", "pegin amount mismatch",       *)
(*           "only committee member can call"].iter().any(..contains..)    *)
(*      }                                                                  *)
(*  post_pegin_data (instance_jobs.rs:984-1048): a non-matching error is   *)
(*  `return Err(error)` (:1036-1040). PostPeginDataRunner (:1051-1073):    *)
(*      Ok(PostOutcome::Rejected(reason)) => JobOutcome::Failed(reason),   *)
(*      Err(error) => JobOutcome::Transient { .., retry_after_secs: None } *)
(*  (no classify_failure, no attempt cap). execute_job                     *)
(*  (crates/engine/src/jobs.rs:225-244) then retries with                  *)
(*  job_retry_backoff Steps[10,30,60,120,300,600] (engine config.rs:94):   *)
(*  every 10 minutes, forever. The instance's job-result hook              *)
(*  (node/src/aggregates/instance.rs:1122-1127) raises                     *)
(*  InstanceAlert::PostPeginDataRejected only on JobResultOutcome::Failed, *)
(*  so the fee case never alerts; the only traces are a per-attempt WARN   *)
(*  log and the pegin_post_total{outcome="failure"} counter                *)
(*  (metrics_service.rs:872 record_pegin_post). The job is enqueued once   *)
(*  on RelayerL1Broadcasted (instance.rs:792-796) and cancelled only on    *)
(*  RelayerL2Minted (instance.rs:798-801).                                 *)
(*                                                                         *)
(* "cannot cover fee" depends on the Gateway's min_pegin_fee_sats /        *)
(* pegin_fee_rate, which governance can change, so it is not strictly     *)
(* permanent - but nothing alerts anyone that it needs a change.          *)
(*                                                                         *)
(* FIX DESIGN (NextFixed): a typed FeeTooHigh rejection, classified like   *)
(* the other three: PostOutcome::Rejected => JobOutcome::Failed =>         *)
(* raise_alert(PostPeginDataRejected). (A re-arm on a Gateway fee-change   *)
(* event can be layered on top; the property only needs the alert.)       *)
(*                                                                         *)
(* NO TIMING PARAMETERS: the verdict depends on the classification of the  *)
(* error only - the retry backoff length and the fee values do not change  *)
(* whether the job ever terminates or alerts.                              *)
(*                                                                         *)
(* CONFIGS AND TIERS (specs.txt):                                          *)
(*   live    PeginPostRetry.cfg       current code (FairSpec)              *)
(*   design  PeginPostRetryFixed.cfg  fix design (FairSpecFixed)           *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    FeeMayDrop   \* governance may lower the Gateway fee (environment, not forced by fairness)

\* What gateway_post_pegin_data would answer right now.
AnswerOk             == "Ok"              \* postPeginData lands
AnswerFeeTooHigh     == "FeeTooHigh"      \* "cannot cover fee" bail
AnswerAmountMismatch == "AmountMismatch"  \* one of the three permanent substrings
Answers == {AnswerOk, AnswerFeeTooHigh, AnswerAmountMismatch}

\* engine_job row states of the post job.
JobPending == "Pending"
JobDone    == "Done"
JobFailed  == "Failed"

VARIABLES
    gatewayAnswer,  \* what gateway_post_pegin_data would answer right now
    job,            \* engine_job row of post_pegin_data
    retryPhase,     \* the row's `attempts` column, abstracted modulo 2 (makes a retry a visible step)
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
\* Outcomes of one run of the post job (building blocks of RunCurrent/RunFixed).

\* postPeginData lands: Done, the BridgeIn event mints.
PostSucceeds ==
    /\ gatewayAnswer = AnswerOk
    /\ job' = JobDone /\ minted' = TRUE
    /\ UNCHANGED <<gatewayAnswer, retryPhase, alerted>>

\* Rejected -> JobOutcome::Failed -> raise_alert(PostPeginDataRejected).
PostRejectedAlerted ==
    /\ job' = JobFailed /\ alerted' = TRUE
    /\ UNCHANGED <<gatewayAnswer, retryPhase, minted>>

\* Err -> JobOutcome::Transient -> Pending again after the backoff.
PostRetried ==
    /\ retryPhase' = 1 - retryPhase
    /\ UNCHANGED <<gatewayAnswer, job, minted, alerted>>

\* Action: the relayer's post_pegin_data job runs (current code): success
\*   mints; a matching permanent substring fails and alerts; "cannot cover
\*   fee" is an unclassified Err, so the row is retried with backoff forever.
\* Source: PostPeginDataRunner::run() in node/src/aggregates/instance_jobs.rs:1056-1073;
\*         post_pegin_data() instance_jobs.rs:984-1048 (:1036-1040), is_permanent_post_rejection() :975-980;
\*         gateway_post_pegin_data() in crates/client/src/goat_chain/mod.rs:474-485;
\*         execute_job() in crates/engine/src/jobs.rs:225-244; alert hook node/src/aggregates/instance.rs:1122-1127
RunCurrent ==
    /\ job = JobPending
    /\ \/ PostSucceeds
       \/ gatewayAnswer = AnswerAmountMismatch /\ PostRejectedAlerted
       \/ gatewayAnswer = AnswerFeeTooHigh /\ PostRetried

\* Action: the post job runs (fix design): FeeTooHigh is a typed rejection
\*   classified like the other three, so it fails and alerts.
\* Source: proposed change to is_permanent_post_rejection() / post_pegin_data() in
\*         node/src/aggregates/instance_jobs.rs:975-1040 (fix design, not in the code)
RunFixed ==
    /\ job = JobPending
    /\ \/ PostSucceeds
       \/ gatewayAnswer \in {AnswerAmountMismatch, AnswerFeeTooHigh} /\ PostRejectedAlerted

\* Action: governance lowers the Gateway fee, so the post would now succeed.
\* Source: environment (Gateway.sol fee setters, governance; localnet/contracts submodule)
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

\* Weak fairness only for the node's job executor: a Pending row with
\* next_at in the past is claimed again by claim_and_spawn()
\* (crates/engine/src/jobs.rs:133) on every executor tick, so a continuously
\* enabled run eventually happens. The environment (governance) is free.
FairSpec      == Init /\ [][Next]_vars      /\ WF_vars(RunCurrent)
FairSpecFixed == Init /\ [][NextFixed]_vars /\ WF_vars(RunFixed)

-----------------------------------------------------------------------------
\* ---- Safety invariants
\* None beyond TypeOk: M4 is a liveness failure (no wrong state is reached,
\* the job just never ends).

\* ---- Safety properties
\* None.

\* ---- Liveness

\* Every post job ends in a mint or in an alerted rejection.
PostTerminates == <>(minted \/ alerted)

====
