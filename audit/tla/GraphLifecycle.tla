---- MODULE GraphLifecycle ----
(***************************************************************************)
(* Formal model of a single BitVM graph's `status` column, built from the *)
(* ACTUAL Rust implementation (not the README, which was found to be      *)
(* stale in several ways - see git history / PR description for details). *)
(* Every action below cites the exact code it models.                     *)
(*                                                                         *)
(* Ground truth was established by fully reading:                        *)
(*   - scan_graph_chain_state, node/src/utils.rs:1328-1681 (Bitcoin-poll   *)
(*     status derivation, the "official" state machine)                   *)
(*   - handle_withdraw_paths_events / handle_withdraw_disproved_events,   *)
(*     node/src/scheduled_tasks/event_watch_task.rs:392-502 (GoatChain    *)
(*     L2-event-driven status writes - a SEPARATE, independently          *)
(*     scheduled writer to the same column)                               *)
(*   - StorageProcessor::update_graph / update_graph_status,              *)
(*     crates/store/src/localdb.rs:1290-1297 and node/src/utils.rs:       *)
(*     5185-5223 (both perform a raw `UPDATE graph SET status=?` with NO  *)
(*     guard against the new status being older/inconsistent with the     *)
(*     current one - confirmed by reading both implementations)          *)
(*                                                                         *)
(* Known deliberate simplifications (do not affect the properties below): *)
(*  - OperatorPresigned -> CommitteePresigned is modeled as one atomic    *)
(*    action. In reality it fires once an N-of-N committee-signature      *)
(*    quorum completes (node/src/action.rs:488-540, try_finalize_graph);  *)
(*    quorum counting across individual committee members is out of      *)
(*    scope for a single-graph spec.                                      *)
(*  - The four distinct Challenge-state disprove detectors (guardian,     *)
(*    watchtower-flow, per-verifier, connector-d/PubinDisprove - all in   *)
(*    utils.rs:1490-1670) are collapsed into one `Disprove` action, since  *)
(*    they differ only in `disprove_type`/`disprove_index` bookkeeping,   *)
(*    which never gates any further `status` transition (confirmed: the   *)
(*    ChallengeSubStatus fields and its is_watchtower_challenge_success   *)
(*    method have zero call sites anywhere in the repo - dead code).      *)
(***************************************************************************)
EXTENDS GraphTopology

VARIABLE status

vars == <<status>>

TypeOK == status \in AllStatuses

Init == status = "OperatorPresigned"

--------------------------------------------------------------------------
(* ChainScan actions: the Bitcoin/GoatChain-poll state machine,           *)
(* scan_graph_chain_state, utils.rs:1328-1681. This is the ONLY writer    *)
(* considered by the CORE-ONLY config.                                    *)

CommitteePresign ==
    /\ status = "OperatorPresigned"
    /\ status' = "CommitteePresigned"

OperatorPushL2Data ==
    /\ status = "CommitteePresigned"
    /\ status' = "OperatorDataPushed"                          \* utils.rs:1368-1373

BecomeObsoletedBeforeData ==                                    \* utils.rs:1386-1414
    /\ status \in {"OperatorPresigned", "CommitteePresigned"}
    /\ status' = "Obsoleted"

BecomeObsoletedAfterData ==                                     \* utils.rs:1375-1384
    /\ status = "OperatorDataPushed"
    /\ status' = "Obsoleted"

ConfirmPreKickoff ==                                             \* utils.rs:1386-1405
    /\ status = "OperatorDataPushed"
    /\ status' = "PreKickoff"

\* utils.rs:1418-1434 - fires from PreKickoff OR Obsoleted (resurrection).
BroadcastKickoff ==
    /\ status \in {"PreKickoff", "Obsoleted"}
    /\ status' = "OperatorKickOff"

ForceSkip ==                                                     \* utils.rs:1418-1434
    /\ status \in {"PreKickoff", "Obsoleted"}
    /\ status' = "Skipped"

Take1 ==                                                         \* utils.rs:1462-1489
    /\ status = "OperatorKickOff"
    /\ status' = "OperatorTake1"

OpenChallenge ==                                                 \* utils.rs:1462-1489
    /\ status = "OperatorKickOff"
    /\ status' = "Challenge"

\* utils.rs:1448-1461 - guardian disprove bypasses Challenge entirely; this
\* edge is absent from the README's Fig-04-1/4-2 diagram.
GuardianDisproveFromKickoff ==
    /\ status = "OperatorKickOff"
    /\ status' = "Disprove"

Take2 ==                                                         \* utils.rs:1661-1670
    /\ status = "Challenge"
    /\ status' = "OperatorTake2"

\* Collapses all 4 real disprove detectors - see header comment.
Disprove ==                                                      \* utils.rs:1490-1660
    /\ status = "Challenge"
    /\ status' = "Disprove"

ChainScanNext ==
    \/ CommitteePresign
    \/ OperatorPushL2Data
    \/ BecomeObsoletedBeforeData
    \/ BecomeObsoletedAfterData
    \/ ConfirmPreKickoff
    \/ BroadcastKickoff
    \/ ForceSkip
    \/ Take1
    \/ OpenChallenge
    \/ GuardianDisproveFromKickoff
    \/ Take2
    \/ Disprove

--------------------------------------------------------------------------
(* GoatRace actions: node/src/scheduled_tasks/event_watch_task.rs, a      *)
(* SEPARATE scheduled task that reacts to GoatChain (L2) events and       *)
(* writes `status` via StorageProcessor::update_graph - a raw SQL UPDATE  *)
(* with no WHERE-clause guard on the current status                      *)
(* (crates/store/src/localdb.rs:1290-1297) and no coordination with       *)
(* ChainScanNext above. Modeled exactly as read: no precondition on the   *)
(* current status at all, matching "any -> X" in the real code.           *)

GoatPostGraphData ==     status' = "OperatorDataPushed"  \* event_watch_task.rs:930-947
GoatWithdrawHappy ==     status' = "OperatorTake1"        \* event_watch_task.rs:392-449, WithdrawHappyEvent
GoatWithdrawUnhappy ==   status' = "OperatorTake2"        \* event_watch_task.rs:392-449, WithdrawUnhappyEvent
GoatWithdrawDisproved == status' = "Disprove"             \* event_watch_task.rs:451-502

GoatRaceNext ==
    \/ GoatPostGraphData
    \/ GoatWithdrawHappy
    \/ GoatWithdrawUnhappy
    \/ GoatWithdrawDisproved

\* The actual fix (update_graph_status_guarded, node/src/utils.rs) has TWO
\* guards, not one - a first draft with only guard (1) still let TLC find a
\* liveness bug: GoatPostGraphData could still knock an OperatorKickOff graph
\* back to OperatorDataPushed, which combined with Obsoleted's resurrection
\* edges cycles forever and never reaches a terminal status.
\*   (1) refuse to write OFF a closed/terminal status onto something else.
\*   (2) refuse OperatorDataPushed specifically unless the graph hasn't yet
\*       progressed past it (OperatorDataPushed only causally precedes
\*       PreKickoff in the real system - a correctly functioning node never
\*       needs to "re-push" data after kickoff has already happened).
GoatRaceNextGuarded ==
    \/ (status \notin TerminalStatuses
        /\ status \in {"OperatorPresigned", "CommitteePresigned", "OperatorDataPushed"}
        /\ GoatPostGraphData)
    \/ (status \notin TerminalStatuses /\ GoatWithdrawHappy)
    \/ (status \notin TerminalStatuses /\ GoatWithdrawUnhappy)
    \/ (status \notin TerminalStatuses /\ GoatWithdrawDisproved)

--------------------------------------------------------------------------
Next == ChainScanNext \/ GoatRaceNext
NextFixed == ChainScanNext \/ GoatRaceNextGuarded

CoreSpec == Init /\ [][ChainScanNext]_vars
FairCoreSpec == CoreSpec /\ WF_vars(ChainScanNext)

FullSpec == Init /\ [][Next]_vars
FairFullSpec == FullSpec /\ WF_vars(Next)

FullSpecFixed == Init /\ [][NextFixed]_vars
FairFullSpecFixed == FullSpecFixed /\ WF_vars(NextFixed)

--------------------------------------------------------------------------
(* Properties. Checked against FairCoreSpec (GraphLifecycleCoreOnly.cfg,  *)
(* expected to hold - the chain-scan state machine alone is sound) and    *)
(* against FairFullSpec (GraphLifecycle.cfg, expected to VIOLATE - that   *)
(* is the actual bug this spec was built to demonstrate).                 *)

NoStatusSkipping == [][(status # status' => <<status, status'>> \in AllowedTransitions)]_vars

TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_vars

\* The sharpest statement of the real risk: the two payout paths (happy-path
\* Take1 vs challenge-path Take2) must never both be recorded for one graph,
\* and a recorded Disprove (evidence an operator cheated) must never be lost.
NoConflictingWithdrawal ==
    /\ [][(status = "OperatorTake1" => status' # "OperatorTake2")]_vars
    /\ [][(status = "OperatorTake2" => status' # "OperatorTake1")]_vars

DisproveIsSticky == [][(status = "Disprove" => status' = "Disprove")]_vars

EventuallyTerminal == <>(status \in TerminalStatuses)

====
