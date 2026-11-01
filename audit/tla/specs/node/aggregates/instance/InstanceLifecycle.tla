---- MODULE InstanceLifecycle ----
(***************************************************************************)
(* One instance's bridge-in lifecycle as the Instance aggregate decides it *)
(* (node/src/aggregates/instance.rs decide_* and commit, fed by the scans  *)
(* in instance_scan.rs), against the chain facts it reads. Each apply is   *)
(* one atomic step (BEGIN IMMEDIATE, crates/engine/src/worker.rs:177). The *)
(* Peg-In-Confirm signing job (instance_jobs.rs pegin_confirm_sign) is two *)
(* steps: GateCheck reads the tip through the T0 gate, Sign signs.         *)
(* Also checks: key deletion only when safe, failure states terminal       *)
(* except Timeout -> UserCanceled, Timeout only on an invisible Confirm.   *)
(*                                                                         *)
(* Finding (sign-gate race): a block can arrive between GateCheck and      *)
(*   Sign, so a signature is made at tip >= H_p + T0                       *)
(*   (NoSignatureAtOrAfterT0).                                             *)
(*                                                                         *)
(* Parameters: T0Blocks, BufferBlocks, KeyDeleteBlocks (PeginDeadlines);   *)
(*   GateMargin: the gate closes at H_p + T0 - GateMargin (0 = the code);  *)
(*   MaxSignLag: most blocks between GateCheck and Sign (>= MaxHeight = no *)
(*   bound, as in the code); MaxHeight: bound on the tip.                  *)
(* Fix (close the gate GateMargin blocks early): ParamsOK, exact while     *)
(*   GateMargin < T0Blocks.                                                *)
(* Exhaustiveness: the race compares only the GateCheck tip plus the lag   *)
(*   with H_p + T0; T0, B and the key-delete depth translate heights. So   *)
(*   margin 0 with no lag bound (race) and margin = lag = 1 (fix) are the  *)
(*   two classes; T0 = 4 > GateMargin keeps the gate reachable.            *)
(* Not modeled: stale snapshots (gather and apply are one step), reorgs.   *)
(* Configs: configs/node/aggregates/instance/InstanceLifecycle/, tiers in  *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    T0Blocks,         \* PeginDeadlines.t0_blocks: Peg-In-Cancel is minable from H_p + T0
    BufferBlocks,     \* PeginDeadlines.buffer_blocks: B, abandon height is H_p + T0 + B
    KeyDeleteBlocks,  \* PeginDeadlines.key_delete_blocks: success-side key deletion depth
    GateMargin,       \* the gate closes this many blocks before H_p + T0 (0 = current code)
    MaxSignLag,       \* most blocks between GateCheck and Sign (>= MaxHeight: unbounded)
    MaxHeight         \* bound on the Bitcoin tip

\* The fix holds iff no more blocks arrive during the job than the margin.
ParamsOK == MaxSignLag <= GateMargin

\* InstanceBridgeInStatus (crates/store/src/schema.rs:205).
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

\* scanned_statuses (instance_scan.rs:182) with committee key deletion on.
ScannedStatuses == {CommitteesAnswered, UserBroadcastPeginPrepare, Presigned, Timeout,
                    RelayerL1Broadcasted, RelayerL2Minted}

\* Goat committee-answer window.
AnswersNone   == "none"     \* window still open
AnswersShort  == "short"    \* closed without a quorum
AnswersQuorum == "quorum"   \* closed with a quorum

\* Peg-In-Confirm visibility.
ConfirmNone      == "none"
ConfirmMempool   == "mempool"
ConfirmConfirmed == "confirmed"

\* Steps of the committee member's pegin_confirm_sign job.
SignIdle  == "idle"    \* not past the gate yet
SignGated == "gated"   \* gate passed at tip gateH; the signature is not made yet
SignDone  == "done"    \* signature produced
SignSteps == {SignIdle, SignGated, SignDone}

VARIABLES
    status,          \* Instance.status of the local row
    keyDeleted,      \* Instance.key_deleted
    h,               \* Bitcoin tip
    answered,        \* Goat answer window: AnswersNone, AnswersShort or AnswersQuorum
    prepareH,        \* H_p, the Peg-In-Prepare confirmation height; 0 while unconfirmed
    inputsSpent,     \* an input of Peg-In-Prepare was spent elsewhere
    endorsed,        \* enough graphs of the instance are finalized and endorsed
    signPc,          \* step of the signing job (SignSteps)
    gateH,           \* tip the signing job read at GateCheck
    signed,          \* a committee member produced a Peg-In-Confirm signature
    signedAt,        \* tips at which signatures were produced
    confirm,         \* Peg-In-Confirm: ConfirmNone, ConfirmMempool or ConfirmConfirmed
    confirmH,        \* confirmation height of Peg-In-Confirm
    cancelConfirmed, \* Peg-In-Cancel confirmed
    minted           \* Goat BridgeIn emitted

vars == <<status, keyDeleted, h, answered, prepareH, inputsSpent, endorsed,
          signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* The variables the Instance aggregate does not write.
env == <<h, answered, prepareH, inputsSpent, endorsed, signPc, gateH, signed, signedAt,
         confirm, confirmH, cancelConfirmed, minted>>

TypeOk ==
    /\ status \in Statuses
    /\ keyDeleted \in BOOLEAN
    /\ h \in 0..MaxHeight
    /\ answered \in {AnswersNone, AnswersShort, AnswersQuorum}
    /\ prepareH \in 0..MaxHeight
    /\ inputsSpent \in BOOLEAN
    /\ endorsed \in BOOLEAN
    /\ signPc \in SignSteps
    /\ gateH \in 0..MaxHeight
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
\* H_p + T0 - GateMargin; open while H_p is unknown.
SigningOpen == status \notin Failed /\ (prepareH = 0 \/ h + GateMargin < CancelFromHeight)

Init ==
    /\ status = UserInited
    /\ keyDeleted = FALSE
    /\ h = 0
    /\ answered = AnswersNone
    /\ prepareH = 0
    /\ inputsSpent = FALSE
    /\ endorsed = FALSE
    /\ signPc = SignIdle
    /\ gateH = 0
    /\ signed = FALSE
    /\ signedAt = {}
    /\ confirm = ConfirmNone
    /\ confirmH = 0
    /\ cancelConfirmed = FALSE
    /\ minted = FALSE

--------------------------------------------------------------------------
(* Environment and committee signing job *)

\* Action: a new Bitcoin block; at most MaxSignLag of them while the signing
\* job is between GateCheck and Sign.
\* Source: Bitcoin consensus
Tick ==
    /\ h < MaxHeight
    /\ signPc = SignGated => h + 1 - gateH <= MaxSignLag
    /\ h' = h + 1
    /\ UNCHANGED <<status, keyDeleted, answered, prepareH, inputsSpent,
                   endorsed, signPc, gateH, signed, signedAt, confirm, confirmH,
                   cancelConfirmed, minted>>

\* Action: the Goat answer window closes, with or without a quorum.
\* Source: Gateway.sol answerPeginRequest
WindowCloses ==
    /\ answered = AnswersNone
    /\ answered' \in {AnswersShort, AnswersQuorum}
    /\ UNCHANGED <<status, keyDeleted, h, prepareH, inputsSpent, endorsed,
                   signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Prepare confirms (the user builds it from a quorum of answers).
\* Source: Bitcoin consensus
PrepareConfirms ==
    /\ answered = AnswersQuorum /\ prepareH = 0 /\ ~inputsSpent /\ h > 0
    /\ prepareH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, inputsSpent, endorsed,
                   signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: an input of Peg-In-Prepare is spent by another transaction.
\* Source: Bitcoin consensus
InputSpentElsewhere ==
    /\ prepareH = 0 /\ ~inputsSpent
    /\ inputsSpent' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, endorsed,
                   signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: enough graphs of the instance are finalized and endorsed.
\* Source: environment (operators and committee finishing graph setup)
GraphEndorsed ==
    /\ prepareH > 0 /\ ~endorsed
    /\ endorsed' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: the committee member's signing job, in the Confirm phase, reads the
\* instance row and the tip and passes the T0 gate.
\* Source: pegin_confirm_sign() in node/src/aggregates/instance_jobs.rs:659-713
\* Source: signing_gate() in node/src/aggregates/instance.rs:620-640
GateCheck ==
    /\ signPc = SignIdle /\ status = Presigned /\ SigningOpen
    /\ signPc' = SignGated /\ gateH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* Action: the job signs Peg-In-Confirm without reading the tip again.
\* Source: pegin_confirm_sign() in node/src/aggregates/instance_jobs.rs:714-776
Sign ==
    /\ signPc = SignGated
    /\ signPc' = SignDone
    /\ signed' = TRUE
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, gateH, confirm, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Confirm enters the mempool; anyone holding the signed tx may
\* broadcast it at any time, also after this node abandoned the instance.
\* Source: environment
ConfirmEntersMempool ==
    /\ signed /\ confirm = ConfirmNone /\ ~cancelConfirmed
    /\ confirm' = ConfirmMempool
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signPc, gateH, signed, signedAt, confirmH, cancelConfirmed, minted>>

\* Action: Peg-In-Confirm confirms.
\* Source: Bitcoin consensus
ConfirmConfirms ==
    /\ confirm = ConfirmMempool /\ ~cancelConfirmed
    /\ confirm' = ConfirmConfirmed /\ confirmH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signPc, gateH, signed, signedAt, cancelConfirmed, minted>>

\* Action: Peg-In-Cancel confirms (BIP68: from H_p + T0) and evicts an
\* unconfirmed Peg-In-Confirm.
\* Source: Bitcoin consensus
CancelConfirms ==
    /\ prepareH > 0 /\ h >= CancelFromHeight /\ confirm # ConfirmConfirmed /\ ~cancelConfirmed
    /\ cancelConfirmed' = TRUE /\ confirm' = ConfirmNone
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signPc, gateH, signed, signedAt, confirmH, minted>>

\* Action: Goat mints for the confirmed Peg-In-Confirm and emits BridgeIn.
\* Source: Gateway.sol postPeginData
Mint ==
    /\ confirm = ConfirmConfirmed /\ ~minted
    /\ minted' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signPc, gateH, signed, signedAt, confirm, confirmH, cancelConfirmed>>

Environment ==
    \/ Tick \/ WindowCloses \/ PrepareConfirms \/ InputSpentElsewhere
    \/ GraphEndorsed \/ GateCheck \/ Sign \/ ConfirmEntersMempool
    \/ ConfirmConfirms \/ CancelConfirms \/ Mint

--------------------------------------------------------------------------
(* The Instance aggregate *)

\* Action: the answer window closed: CommitteesAnswered with a quorum, else
\* NoEnoughCommitteesAnswered, which deletes the key on entry.
\* Source: scan_answer_windows() in node/src/aggregates/instance_scan.rs:113
\* Source: decide_answer_window() in node/src/aggregates/instance.rs:526
ScanAnswers ==
    /\ status = UserInited /\ answered # AnswersNone
    /\ status' = IF answered = AnswersQuorum THEN CommitteesAnswered
                                             ELSE NoEnoughCommitteesAnswered
    /\ keyDeleted' = (keyDeleted \/ answered = AnswersShort)
    /\ UNCHANGED env

\* Action: a Bitcoin snapshot decided on the current facts: Prepare confirmed
\* or a conflicting spend; then Confirm confirmed, Cancel confirmed, or Timeout
\* past the abandon height with the Confirm invisible; Timeout -> UserCanceled
\* on a confirmed Cancel; key deletion on entering a deleting failure status
\* or once the Confirm is KeyDeleteBlocks deep.
\* Source: scan_instances_on_bitcoin() / gather_snapshot() in node/src/aggregates/instance_scan.rs:193,270
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442-521
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

\* Action: enough graphs endorsed: UserBroadcastPeginPrepare -> Presigned.
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550
ScanEndorsed ==
    /\ status = UserBroadcastPeginPrepare /\ endorsed
    /\ status' = Presigned
    /\ UNCHANGED keyDeleted
    /\ UNCHANGED env

\* Action: the Goat mint: RelayerL2Minted from any live status; a failed
\* instance only alerts.
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
ScanMint ==
    /\ minted /\ status \notin Failed /\ status # RelayerL2Minted
    /\ status' = RelayerL2Minted
    /\ UNCHANGED keyDeleted
    /\ UNCHANGED env

Node == ScanAnswers \/ ScanBitcoin \/ ScanEndorsed \/ ScanMint

--------------------------------------------------------------------------
Next == Environment \/ Node

\* Safety only: no fairness.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* The T0 gate: no Peg-In-Confirm signature at or after H_p + T0.
NoSignatureAtOrAfterT0 ==
    \A x \in signedAt : prepareH > 0 /\ x < CancelFromHeight

\* The key is deleted only in a deleting failure status, or on the success
\* side once the Peg-In-Confirm is KeyDeleteBlocks deep.
KeyDeletedOnlyWhenSafe ==
    keyDeleted =>
        \/ status \in DeletesKey
        \/ (status \in {RelayerL1Broadcasted, RelayerL2Minted}
            /\ confirm = ConfirmConfirmed /\ confirmH + KeyDeleteBlocks <= h)

\* Timeout keeps the committee key for manual handling.
TimeoutKeepsKey == status = Timeout => ~keyDeleted

\* The success statuses imply a confirmed Peg-In-Confirm.
BroadcastedMeansConfirmed ==
    status \in {RelayerL1Broadcasted, RelayerL2Minted} => confirm = ConfirmConfirmed

--------------------------------------------------------------------------
(* Safety properties *)

\* Failure states are terminal except Timeout -> UserCanceled.
FailureAbsorbing ==
    [][(status \in Failed =>
        status' \in (IF status = Timeout THEN {Timeout, UserCanceled} ELSE {status}))]_vars

\* Timeout is entered only past the abandon height with the Confirm neither
\* confirmed nor in the mempool.
NoTimeoutWhileVisible ==
    [][((status' = Timeout /\ status # Timeout) =>
        (prepareH > 0 /\ h >= AbandonHeight /\ confirm = ConfirmNone))]_vars

\* A minted instance stays minted.
MintedIsFinal == [][(status = RelayerL2Minted => status' = RelayerL2Minted)]_vars

====
