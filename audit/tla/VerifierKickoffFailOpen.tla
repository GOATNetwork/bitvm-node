---- MODULE VerifierKickoffFailOpen ----
(***************************************************************************)
(* Model of GOATNetwork/bitvm-node issue #429:                             *)
(*   "[Security] Verifier KickoffSent challenge is one-shot and fail-open  *)
(*    (unauthorized Take1)"  - checked on gc-v2 @ f2f0285e.                 *)
(*                                                                         *)
(* STATUS: FIXED on dev by #455 (978f4201) - handle_kickoff_sent_verifier  *)
(* now defers the SPV-lag case via push_local_unhandled_messages_with_     *)
(* reason(GoatSpvPending), mirroring the committee handler (the design     *)
(* checked by VerifierKickoffFailOpenFixed.cfg). This module is frozen as  *)
(* the regression record of the ORIGINAL bug, described below as it stood  *)
(* at c15f1714.                                                            *)
(*                                                                         *)
(* Threat: an operator broadcasts a kickoff with NO L2 initWithdraw (no    *)
(* pegBTC burned). The automated defense is the verifier's                 *)
(* handle_kickoff_sent_verifier (node/src/handle.rs): if the L2 withdraw   *)
(* status for the graph is None/Canceled, it must broadcast a Challenge,   *)
(* forcing the operator off the uncontested Take1 fast-exit.               *)
(*                                                                         *)
(* THE BUG (node/src/handle.rs handle_kickoff_sent_verifier):              *)
(*                                                                         *)
(*   if [None, Canceled].contains(&withdraw_status) {                      *)
(*       if kickoff_height >= goat_confirmed_btc_height {                  *)
(*           tracing::warn!(...); return Ok(());  // <-- NO defer/retry    *)
(*       } else { send_challenge_tx(...); }                                *)
(*   }                                                                     *)
(*                                                                         *)
(* At first confirmation GOAT's SPV view lags the Bitcoin tip, so          *)
(* `kickoff_height >= goat_confirmed_btc_height` is the COMMON case (and,  *)
(* because the check is a strict `>` on the send side, it also skips when  *)
(* SPV == kickoff_height). On that branch the handler returns Ok(())       *)
(* WITHOUT push_local_unhandled_messages_with_reason, so node/src/action.rs*)
(* marks the KickoffSent message `Processed`. Nothing re-enqueues it:      *)
(* detect_kickoff (graph_maintenance_tasks.rs) only scans OperatorDataPushed*)
(* graphs, and upsert_message(is_update=false) will not recreate           *)
(* `{graph_id}_KickoffSent`. So every online honest verifier processes     *)
(* once, skips, and is done. After the ConnectorA CSV the operator signs   *)
(* Take1 (n-of-n pre-signed on connector_0) and exits - pegBTC never       *)
(* burned. handle_kickoff_sent_committee DOES defer the same SPV lag; the  *)
(* verifier does not.                                                      *)
(*                                                                         *)
(* This is the classic "consume-without-retry on a transient guard" fail-  *)
(* open, the same shape as MessageStateRace but on the Challenge defense.   *)
(* NOT #418 (the Take1/Challenge CSV margin) - per the issue, the scripts   *)
(* are fine IF a Challenge is actually sent; the defect is that it is       *)
(* never sent. So this spec abstracts the CSV margin as adequate and       *)
(* checks only the control-flow question: does the Challenge ever fire      *)
(* before the operator's uncontested Take1?                                *)
(***************************************************************************)

MsgStates == {"Pending", "Processed"}

VARIABLES
    msg,            \* local-queue state of the {graph_id}_KickoffSent message
    spvLags,        \* kickoff_height >= goat_confirmed_btc_height (GOAT SPV not strictly past the kickoff)
    challengeSent,  \* verifier broadcast send_challenge_tx for this unauthorized kickoff
    take1           \* operator completed the uncontested Take1 (unauthorized withdrawal)

vars == <<msg, spvLags, challengeSent, take1>>

TypeOK ==
    /\ msg \in MsgStates
    /\ spvLags \in BOOLEAN
    /\ challengeSent \in BOOLEAN
    /\ take1 \in BOOLEAN

\* detect_kickoff enqueued KickoffSent to Actor::All; at first confirm GOAT
\* SPV lags the Bitcoin tip (the common case, and the == case the strict `>`
\* also skips); withdraw status for this graph is the unauthorized None.
Init ==
    /\ msg = "Pending"
    /\ spvLags = TRUE
    /\ challengeSent = FALSE
    /\ take1 = FALSE

--------------------------------------------------------------------------
\* GOAT SPV eventually catches up to the already-confirmed kickoff (the lag
\* always closes with time).
SpvCatchesUp ==
    /\ spvLags
    /\ spvLags' = FALSE
    /\ UNCHANGED <<msg, challengeSent, take1>>

\* BUGGY handle_kickoff_sent_verifier: consumes the message either way. When
\* SPV still lags it returns Ok(()) with no defer -> Processed, NO challenge;
\* only when SPV is strictly past does it send the Challenge.
VerifierProcessBuggy ==
    /\ msg = "Pending"
    /\ msg' = "Processed"
    /\ challengeSent' = (IF spvLags THEN challengeSent ELSE TRUE)
    /\ UNCHANGED <<spvLags, take1>>

\* FIXED (issue's suggested fix): on None/Canceled while SPV is not strictly
\* past the kickoff, push_local_unhandled_messages_with_reason - i.e. DEFER,
\* leaving the message Pending to be retried - so the verifier only finalises
\* the message once SPV has caught up and the Challenge is actually sent.
VerifierProcessFixed ==
    /\ msg = "Pending"
    /\ ~spvLags
    /\ msg' = "Processed"
    /\ challengeSent' = TRUE
    /\ UNCHANGED <<spvLags, take1>>

\* After the ConnectorA CSV the operator broadcasts Take1. It is an
\* unauthorized withdrawal only if no Challenge was ever sent (a sent
\* Challenge forces the long dispute path; per the issue the CSV margin is
\* adequate once the Challenge fires). The verifier's one-shot handling has
\* run to a final decision by the time Take1 is spendable (msg = Processed).
OperatorTake1 ==
    /\ msg = "Processed"
    /\ ~challengeSent
    /\ ~take1
    /\ take1' = TRUE
    /\ UNCHANGED <<msg, spvLags, challengeSent>>

Next        == SpvCatchesUp \/ VerifierProcessBuggy \/ OperatorTake1
NextFixed   == SpvCatchesUp \/ VerifierProcessFixed \/ OperatorTake1

Spec        == Init /\ [][Next]_vars
FairSpec    == Spec /\ WF_vars(Next)
SpecFixed   == Init /\ [][NextFixed]_vars
FairSpecFixed == SpecFixed /\ WF_vars(NextFixed)

--------------------------------------------------------------------------
\* Safety (fail-open check): an unauthorized kickoff must never reach a
\* completed Take1 without the verifier's Challenge defense having fired.
\* Buggy: violated - process while SPV lags -> Processed, no Challenge,
\* never retried -> Take1. Fixed: holds - the message is deferred until the
\* Challenge is sent, so Take1's guard (Processed /\ ~challengeSent) is
\* never reachable.
NoUnauthorizedTake1 == take1 => challengeSent

====
