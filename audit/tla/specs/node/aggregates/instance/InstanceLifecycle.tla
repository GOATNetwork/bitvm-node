---- MODULE InstanceLifecycle ----
(***************************************************************************)
(* Bridge-in lifecycle of one instance as decided by the Instance          *)
(* aggregate, against the chain facts it reads: Bitcoin height, the Goat    *)
(* committee-answer window, Peg-In-Prepare / Confirm / Cancel visibility,   *)
(* graph endorsement and the Goat mint. Checks the T0 signing gate, when    *)
(* the committee instance key may be deleted, and that failure states are   *)
(* terminal except Timeout -> UserCanceled.                                *)
(*                                                                         *)
(* Code scope (dev after #476):                                            *)
(*   - Instance aggregate decisions, node/src/aggregates/instance.rs:       *)
(*     decide_btc_snapshot (442), decide_answer_window (526),               *)
(*     decide_graph_endorsed (550), decide_l2_minted (561),                 *)
(*     signing_gate_for (602), PeginDeadlines (156-192), commit (696).      *)
(*   - Scans feeding them, node/src/aggregates/instance_scan.rs:            *)
(*     scanned_statuses (182), scan_instances_on_bitcoin (193),             *)
(*     gather_snapshot (270).                                               *)
(*   - Committee signing steps behind the T0 gate,                          *)
(*     node/src/aggregates/instance_jobs.rs: pegin_confirm_sign (659).      *)
(* Each aggregate apply is one atomic step (BEGIN IMMEDIATE,                *)
(* crates/engine/src/worker.rs:177).                                        *)
(*                                                                         *)
(* Deliberate simplifications:                                             *)
(*   - A snapshot is gathered and applied in one step (ScanBitcoin). In the *)
(*     code it is an engine event applied later, so its facts can be stale; *)
(*     that only widens the window of the Peg-In-Confirm-after-Timeout      *)
(*     alert, which this model already reaches.                             *)
(*   - The T0 gate is evaluated in the same step that signs (Sign). In the  *)
(*     code the job reads the tip height, then signs; a block arriving in   *)
(*     between is not modeled.                                              *)
(*   - No Bitcoin reorg (the "Prepare reorged out" UserDiscarded branch of  *)
(*     decide_btc_snapshot is not reachable).                               *)
(*   - decide_btc_snapshot's UserInited branch is unreachable: UserInited   *)
(*     is never scanned (gather_snapshot returns None).                     *)
(*                                                                         *)
(* Config (audit/tla/checks.txt): InstanceLifecycle/Baseline.cfg - pass.             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    T0Blocks,         \* PeginDeadlines.t0_blocks: Connector-Z timelock; Peg-In-Cancel is minable from H_p + T0
    BufferBlocks,     \* PeginDeadlines.buffer_blocks: B, abandon height is H_p + T0 + B
    KeyDeleteBlocks,  \* PeginDeadlines.key_delete_blocks: success-side key deletion depth
    MaxHeight         \* bound on the Bitcoin height for model checking

\* Instance.status values (InstanceBridgeInStatus, crates/store/src/schema.rs:205).
UserInited                 == "UserInited"
CommitteesAnswered         == "CommitteesAnswered"
UserBroadcastPeginPrepare  == "UserBroadcastPeginPrepare"
Presigned                  == "Presigned"
RelayerL1Broadcasted       == "RelayerL1Broadcasted"
RelayerL2Minted            == "RelayerL2Minted"
NoEnoughCommitteesAnswered == "NoEnoughCommitteesAnswered"
UserDiscarded              == "UserDiscarded"
UserCanceled               == "UserCanceled"
Timeout                    == "Timeout"

Statuses == {UserInited, CommitteesAnswered, UserBroadcastPeginPrepare,
             Presigned, RelayerL1Broadcasted, RelayerL2Minted,
             NoEnoughCommitteesAnswered, UserDiscarded, UserCanceled, Timeout}

\* InstanceBridgeInStatus::FAILED (schema.rs:225).
Failed == {NoEnoughCommitteesAnswered, UserDiscarded, UserCanceled, Timeout}

\* deletes_key_on_entry (schema.rs:242): Timeout keeps the key.
DeletesKey == {NoEnoughCommitteesAnswered, UserDiscarded, UserCanceled}

\* scanned_statuses (instance_scan.rs:182), with committee key deletion on.
ScannedStatuses == {CommitteesAnswered, UserBroadcastPeginPrepare, Presigned, Timeout,
                    RelayerL1Broadcasted, RelayerL2Minted}

\* Goat committee-answer window outcome.
AnswersNone   == "none"     \* window still open
AnswersShort  == "short"    \* closed without a quorum
AnswersQuorum == "quorum"   \* closed with a quorum

\* Peg-In-Confirm visibility.
ConfirmNone      == "none"
ConfirmMempool   == "mempool"
ConfirmConfirmed == "confirmed"

VARIABLES
    status,          \* Instance.status of the local row
    keyDeleted,      \* Instance.key_deleted: the committee instance key is gone
    h,               \* Bitcoin tip height
    answered,        \* the Goat response window: AnswersNone, AnswersShort or AnswersQuorum
    prepareH,        \* H_p, the Peg-In-Prepare confirmation height; 0 while unconfirmed
    inputsSpent,     \* an input of Peg-In-Prepare was spent elsewhere
    endorsed,        \* enough graphs of the instance are finalized and endorsed
    signed,          \* a committee member produced a Peg-In-Confirm signature
    signedAt,        \* heights at which signatures were produced
    confirm,         \* Peg-In-Confirm: ConfirmNone, ConfirmMempool or ConfirmConfirmed
    confirmH,        \* confirmation height of Peg-In-Confirm
    cancelConfirmed, \* Peg-In-Cancel confirmed
    minted           \* Goat BridgeIn emitted

vars == <<status, keyDeleted, h, answered, prepareH, inputsSpent, endorsed,
          signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* The variables only the environment changes.
env == <<h, answered, prepareH, inputsSpent, endorsed, signed, signedAt,
         confirm, confirmH, cancelConfirmed, minted>>

TypeOk ==
    /\ status \in Statuses
    /\ keyDeleted \in BOOLEAN
    /\ h \in 0..MaxHeight
    /\ answered \in {AnswersNone, AnswersShort, AnswersQuorum}
    /\ prepareH \in 0..MaxHeight
    /\ inputsSpent \in BOOLEAN
    /\ endorsed \in BOOLEAN
    /\ signed \in BOOLEAN
    /\ signedAt \subseteq 0..MaxHeight
    /\ confirm \in {ConfirmNone, ConfirmMempool, ConfirmConfirmed}
    /\ confirmH \in 0..MaxHeight
    /\ cancelConfirmed \in BOOLEAN
    /\ minted \in BOOLEAN

\* PeginDeadlines::cancel_from_height (instance.rs:177): H_p + T0.
CancelFromHeight == prepareH + T0Blocks

\* PeginDeadlines::abandon_height (instance.rs:183): H_p + T0 + B.
AbandonHeight == prepareH + T0Blocks + BufferBlocks

\* signing_gate_for (instance.rs:602): closed for a failed instance and from
\* H_p + T0; open while H_p is unknown.
SigningOpen == status \notin Failed /\ (prepareH = 0 \/ h < CancelFromHeight)

Init ==
    /\ status = UserInited
    /\ keyDeleted = FALSE
    /\ h = 0
    /\ answered = AnswersNone
    /\ prepareH = 0
    /\ inputsSpent = FALSE
    /\ endorsed = FALSE
    /\ signed = FALSE
    /\ signedAt = {}
    /\ confirm = ConfirmNone
    /\ confirmH = 0
    /\ cancelConfirmed = FALSE
    /\ minted = FALSE

--------------------------------------------------------------------------
(* Environment *)

\* Action: a new Bitcoin block.
\* Source: Bitcoin consensus
Tick ==
    /\ h < MaxHeight
    /\ h' = h + 1
    /\ UNCHANGED <<status, keyDeleted, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirm, confirmH,
                   cancelConfirmed, minted>>

\* Action: the Goat committee-answer window closes, with or without a quorum.
\* Source: Gateway.sol answerPeginRequest (response window)
WindowCloses ==
    /\ answered = AnswersNone
    /\ answered' \in {AnswersShort, AnswersQuorum}
    /\ UNCHANGED <<status, keyDeleted, h, prepareH, inputsSpent, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Prepare confirms; the user can only build it from a quorum
\* of answers.
\* Source: Bitcoin consensus
PrepareConfirms ==
    /\ answered = AnswersQuorum /\ prepareH = 0 /\ ~inputsSpent /\ h > 0
    /\ prepareH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, inputsSpent, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: an input of Peg-In-Prepare is spent by another transaction.
\* Source: Bitcoin consensus
InputSpentElsewhere ==
    /\ prepareH = 0 /\ ~inputsSpent
    /\ inputsSpent' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: enough graphs of the instance are finalized and endorsed.
\* Source: environment (operators and committee finishing graph setup)
GraphEndorsed ==
    /\ prepareH > 0 /\ ~endorsed
    /\ endorsed' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: a committee member signs Peg-In-Confirm: only in the Confirm phase
\* (the round starts on entering Presigned and stops once the round is over)
\* and only through the T0 gate.
\* Source: pegin_confirm_sign() in node/src/aggregates/instance_jobs.rs:659,711
\* Source: on_entered() Presigned arm in node/src/aggregates/instance.rs:785
Sign ==
    /\ status = Presigned /\ SigningOpen /\ ~signed
    /\ signed' = TRUE
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, confirm, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Confirm enters the mempool. Anyone holding the signed
\* transaction may broadcast it at any time, including after this node
\* abandoned the instance.
\* Source: environment
ConfirmEntersMempool ==
    /\ signed /\ confirm = ConfirmNone /\ ~cancelConfirmed
    /\ confirm' = ConfirmMempool
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Confirm confirms.
\* Source: Bitcoin consensus
ConfirmConfirms ==
    /\ confirm = ConfirmMempool /\ ~cancelConfirmed
    /\ confirm' = ConfirmConfirmed /\ confirmH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, cancelConfirmed, minted>>

\* Action: Peg-In-Cancel confirms. BIP68 makes it minable from H_p + T0; it
\* conflicts with an unconfirmed Peg-In-Confirm, which is then evicted.
\* Source: Bitcoin consensus
CancelConfirms ==
    /\ prepareH > 0 /\ h >= CancelFromHeight /\ confirm # ConfirmConfirmed /\ ~cancelConfirmed
    /\ cancelConfirmed' = TRUE /\ confirm' = ConfirmNone
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirmH, minted>>

\* Action: Goat mints for the confirmed Peg-In-Confirm and emits BridgeIn.
\* Source: Gateway.sol postPeginData
Mint ==
    /\ confirm = ConfirmConfirmed /\ ~minted
    /\ minted' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirm, confirmH, cancelConfirmed>>

Environment ==
    \/ Tick \/ WindowCloses \/ PrepareConfirms \/ InputSpentElsewhere
    \/ GraphEndorsed \/ Sign \/ ConfirmEntersMempool \/ ConfirmConfirms
    \/ CancelConfirms \/ Mint

--------------------------------------------------------------------------
(* The Instance aggregate *)

\* Action: the answer window closed: CommitteesAnswered with a quorum,
\* otherwise NoEnoughCommitteesAnswered, which deletes the key on entry.
\* Source: scan_answer_windows() in node/src/aggregates/instance_scan.rs:113
\* Source: decide_answer_window() in node/src/aggregates/instance.rs:526
ScanAnswers ==
    /\ status = UserInited /\ answered # AnswersNone
    /\ status' = IF answered = AnswersQuorum THEN CommitteesAnswered
                                             ELSE NoEnoughCommitteesAnswered
    /\ keyDeleted' = (keyDeleted \/ answered = AnswersShort)
    /\ UNCHANGED env

\* Action: a Bitcoin snapshot of a scanned instance is decided on the facts
\* as they are now: Prepare confirmed or a conflicting spend; then Confirm
\* confirmed, Cancel confirmed or Timeout past the abandon height while the
\* Confirm is invisible; Timeout -> UserCanceled on a confirmed Cancel; and
\* success-side key deletion once the Confirm is KeyDeleteBlocks deep.
\* Entering a key-deleting failure status deletes the key.
\* Source: scan_instances_on_bitcoin() / gather_snapshot() in node/src/aggregates/instance_scan.rs:193,270
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442
\* Source: commit() / enter_failure() in node/src/aggregates/instance.rs:696,826
ScanBitcoin ==
    /\ status \in ScannedStatuses
    /\ LET s1 == IF status = CommitteesAnswered
                   THEN IF prepareH > 0 THEN UserBroadcastPeginPrepare
                        ELSE IF inputsSpent THEN UserDiscarded
                        ELSE status
                   ELSE status
           s2 == IF s1 \in {UserBroadcastPeginPrepare, Presigned}
                   THEN IF confirm = ConfirmConfirmed THEN RelayerL1Broadcasted
                        ELSE IF cancelConfirmed THEN UserCanceled
                        ELSE IF prepareH > 0 /\ h >= AbandonHeight /\ confirm = ConfirmNone
                             THEN Timeout
                        ELSE s1
                   ELSE IF s1 = Timeout /\ cancelConfirmed THEN UserCanceled
                   ELSE s1
           failureDelete == s2 \in DeletesKey /\ s2 # status
           successDelete == s2 \in {RelayerL1Broadcasted, RelayerL2Minted}
                            /\ confirm = ConfirmConfirmed /\ confirmH + KeyDeleteBlocks <= h
       IN /\ status' = s2
          /\ keyDeleted' = (keyDeleted \/ failureDelete \/ successDelete)
    /\ UNCHANGED env

\* Action: enough graphs are endorsed: UserBroadcastPeginPrepare -> Presigned.
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550
ScanEndorsed ==
    /\ status = UserBroadcastPeginPrepare /\ endorsed
    /\ status' = Presigned
    /\ UNCHANGED keyDeleted
    /\ UNCHANGED env

\* Action: the Goat mint: RelayerL2Minted from any live status; for a failed
\* instance only an alert.
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
ScanMint ==
    /\ minted /\ status \notin Failed /\ status # RelayerL2Minted
    /\ status' = RelayerL2Minted
    /\ UNCHANGED keyDeleted
    /\ UNCHANGED env

Node == ScanAnswers \/ ScanBitcoin \/ ScanEndorsed \/ ScanMint

--------------------------------------------------------------------------
Next == Environment \/ Node

\* No fairness: only safety is checked.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* The T0 gate: no protocol signature at or after H_p + T0.
NoSignatureAtOrAfterT0 ==
    \A x \in signedAt : prepareH > 0 /\ x < CancelFromHeight

\* The key is deleted only in the three failure states that delete it, or on
\* the success side once the Peg-In-Confirm is KeyDeleteBlocks deep.
KeyDeletedOnlyWhenSafe ==
    keyDeleted =>
        \/ status \in DeletesKey
        \/ (status \in {RelayerL1Broadcasted, RelayerL2Minted}
            /\ confirm = ConfirmConfirmed /\ confirmH + KeyDeleteBlocks <= h)

\* Timeout keeps the committee key for manual handling.
TimeoutKeepsKey == status = Timeout => ~keyDeleted

\* The success statuses are only recorded for a confirmed Peg-In-Confirm.
BroadcastedMeansConfirmed ==
    status \in {RelayerL1Broadcasted, RelayerL2Minted} => confirm = ConfirmConfirmed

--------------------------------------------------------------------------
(* Safety properties *)

\* Failure states are terminal except Timeout -> UserCanceled.
FailureAbsorbing ==
    [][(status \in Failed =>
        status' \in (IF status = Timeout THEN {Timeout, UserCanceled} ELSE {status}))]_vars

\* Timeout is only entered past the abandon height while the Peg-In-Confirm
\* is neither confirmed nor in the mempool.
NoTimeoutWhileVisible ==
    [][((status' = Timeout /\ status # Timeout) =>
        (prepareH > 0 /\ h >= AbandonHeight /\ confirm = ConfirmNone))]_vars

\* A minted instance stays minted.
MintedIsFinal == [][(status = RelayerL2Minted => status' = RelayerL2Minted)]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* (none)

====
