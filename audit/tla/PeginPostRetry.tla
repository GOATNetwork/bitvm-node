---- MODULE PeginPostRetry ----
(***************************************************************************)
(* M4: the relayer's post_pegin_data job retries a fee rejection forever,  *)
(* silently, while the user's BTC is locked in Peg-In-Confirm and nothing  *)
(* is minted. The dual of JobObligationPersistence (b): there ANY revert   *)
(* text is Permanent; here only three substrings are. Checked against dev  *)
(* @ 60562f8.                                                             *)
(*                                                                         *)
(* THE CODE:                                                               *)
(*  crates/client/src/goat_chain/mod.rs:474-485 (gateway_post_pegin_data): *)
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
(*  instance_jobs.rs:1036-1040: a non-matching error is `return Err(error)`*)
(*  instance_jobs.rs:1062-1071 PostPeginDataRunner:                        *)
(*      Ok(PostOutcome::Rejected(reason)) => JobOutcome::Failed(reason),   *)
(*      Err(error) => JobOutcome::Transient { .., retry_after_secs: None } *)
(*  (no classify_failure, no attempt cap, no alert). engine jobs.rs:241    *)
(*  then retries with job_retry_backoff Steps[10,30,60,120,300,600]        *)
(*  (config.rs:94): every 10 minutes, forever. instance.rs:1126-1127 raises*)
(*  InstanceAlert::PostPeginDataRejected only on JobResultOutcome::Failed, *)
(*  so the fee case never alerts; the only trace is the                   *)
(*  pegin_post_total{outcome="failure"} counter (metrics_service.rs:872).  *)
(*  The job was enqueued once on RelayerL1Broadcasted (instance.rs:792-   *)
(*  796) and is cancelled only on RelayerL2Minted (instance.rs:798-801).   *)
(*                                                                         *)
(* "cannot cover fee" depends on the Gateway's min_pegin_fee_sats /        *)
(* pegin_fee_rate, which governance can change, so it is not strictly     *)
(* permanent - but nothing alerts anyone that it needs a change.          *)
(*                                                                         *)
(* FIXED DESIGN: a typed FeeTooHigh rejection, classified like the other   *)
(* three: PostOutcome::Rejected => JobOutcome::Failed => raise_alert(      *)
(* PostPeginDataRejected). (A re-arm on a Gateway fee-change event can be  *)
(* layered on top; the property only needs the alert.)                     *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    FeeMayDrop   \* governance may lower the Gateway fee (not forced by fairness)

Reasons == {"Ok", "FeeTooHigh", "AmountMismatch"}

VARIABLES
    reason,      \* what gateway_post_pegin_data would answer right now
    job,         \* engine_job row of post_pegin_data
    retryPhase,  \* the row's `attempts` column, abstracted modulo 2
    minted,      \* postPeginData landed (BridgeIn -> RelayerL2Minted)
    alerted      \* InstanceAlert::PostPeginDataRejected raised

vars == <<reason, job, retryPhase, minted, alerted>>

TypeOK ==
    /\ reason \in Reasons
    /\ job \in {"Pending", "Done", "Failed"}
    /\ retryPhase \in {0, 1}
    /\ minted \in BOOLEAN
    /\ alerted \in BOOLEAN

Init ==
    /\ reason \in Reasons
    /\ job = "Pending"
    /\ retryPhase = 0
    /\ minted = FALSE
    /\ alerted = FALSE

-----------------------------------------------------------------------------
PostSucceeds ==
    /\ reason = "Ok"
    /\ job' = "Done" /\ minted' = TRUE
    /\ UNCHANGED <<reason, retryPhase, alerted>>

\* is_permanent_post_rejection matches: Rejected -> Failed -> alert.
PostRejectedAlerted ==
    /\ job' = "Failed" /\ alerted' = TRUE
    /\ UNCHANGED <<reason, retryPhase, minted>>

\* Err -> JobOutcome::Transient -> Pending again after the backoff.
PostRetried ==
    /\ retryPhase' = 1 - retryPhase
    /\ UNCHANGED <<reason, job, minted, alerted>>

RunCurrent ==
    /\ job = "Pending"
    /\ \/ PostSucceeds
       \/ reason = "AmountMismatch" /\ PostRejectedAlerted
       \/ reason = "FeeTooHigh" /\ PostRetried

RunFixed ==
    /\ job = "Pending"
    /\ \/ PostSucceeds
       \/ reason \in {"AmountMismatch", "FeeTooHigh"} /\ PostRejectedAlerted

\* Governance lowers the Gateway fee.
LowerFee ==
    /\ FeeMayDrop
    /\ reason = "FeeTooHigh"
    /\ reason' = "Ok"
    /\ UNCHANGED <<job, retryPhase, minted, alerted>>

Next      == RunCurrent \/ LowerFee
NextFixed == RunFixed \/ LowerFee

\* Fairness only for the node's job executor; the environment is free.
FairSpec      == Init /\ [][Next]_vars      /\ WF_vars(RunCurrent)
FairSpecFixed == Init /\ [][NextFixed]_vars /\ WF_vars(RunFixed)

-----------------------------------------------------------------------------
\* Every post job ends in a mint or in an alerted rejection.
PostTerminates == <>(minted \/ alerted)

====
