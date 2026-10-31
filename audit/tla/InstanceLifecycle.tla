---- MODULE InstanceLifecycle ----
(***************************************************************************)
(* Bridge-in lifecycle model for Instance aggregate decisions.              *)
(* Models chain heights, committee answers, transaction visibility,         *)
(* cancellation, signing eligibility and committee key deletion.            *)
(* Failure states are terminal except Timeout -> UserCanceled.               *)
(* Signing closes at the cancellation height; Timeout keeps the key.         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS T0, B, KD, MaxHeight

Statuses == {"UserInited", "CommitteesAnswered", "UserBroadcastPeginPrepare",
             "Presigned", "RelayerL1Broadcasted", "RelayerL2Minted",
             "NoEnoughCommitteesAnswered", "UserDiscarded", "UserCanceled",
             "Timeout"}
Failed == {"NoEnoughCommitteesAnswered", "UserDiscarded", "UserCanceled", "Timeout"}
DeletesKey == {"NoEnoughCommitteesAnswered", "UserDiscarded", "UserCanceled"}

VARIABLES
    status,          \* the instance row
    keyDeleted,      \* instance.key_deleted
    h,               \* Bitcoin tip height
    answered,        \* "none" | "short" | "quorum": the Goat response window
    prepareH,        \* H_p, 0 while Peg-In-Prepare is unconfirmed
    inputsSpent,     \* an input of Peg-In-Prepare was spent elsewhere
    endorsed,        \* a graph of the instance is finalized and endorsed
    signed,          \* a committee member produced a Peg-In-Confirm signature
    signedAt,        \* heights at which signatures were produced
    confirm,         \* Peg-In-Confirm: "none" | "mempool" | "confirmed"
    confirmH,        \* confirmation height of Peg-In-Confirm
    cancelConfirmed, \* Peg-In-Cancel confirmed
    minted           \* Goat BridgeIn emitted

vars == <<status, keyDeleted, h, answered, prepareH, inputsSpent, endorsed,
          signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>
env == <<h, answered, prepareH, inputsSpent, endorsed, signed, signedAt,
         confirm, confirmH, cancelConfirmed, minted>>
node == <<status, keyDeleted>>

TypeOK ==
    /\ status \in Statuses
    /\ keyDeleted \in BOOLEAN
    /\ h \in 0..MaxHeight
    /\ answered \in {"none", "short", "quorum"}
    /\ prepareH \in 0..MaxHeight
    /\ inputsSpent \in BOOLEAN
    /\ endorsed \in BOOLEAN
    /\ signed \in BOOLEAN
    /\ signedAt \subseteq 0..MaxHeight
    /\ confirm \in {"none", "mempool", "confirmed"}
    /\ confirmH \in 0..MaxHeight
    /\ cancelConfirmed \in BOOLEAN
    /\ minted \in BOOLEAN

Init ==
    /\ status = "UserInited"
    /\ keyDeleted = FALSE
    /\ h = 0
    /\ answered = "none"
    /\ prepareH = 0
    /\ inputsSpent = FALSE
    /\ endorsed = FALSE
    /\ signed = FALSE
    /\ signedAt = {}
    /\ confirm = "none"
    /\ confirmH = 0
    /\ cancelConfirmed = FALSE
    /\ minted = FALSE

CancelFromHeight == prepareH + T0
AbandonHeight == prepareH + T0 + B
SigningOpen == status \notin Failed /\ (prepareH = 0 \/ h < CancelFromHeight)

--------------------------------------------------------------------------
(* Environment *)

Tick ==
    /\ h < MaxHeight
    /\ h' = h + 1
    /\ UNCHANGED <<status, keyDeleted, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirm, confirmH,
                   cancelConfirmed, minted>>

WindowCloses ==
    /\ answered = "none"
    /\ answered' \in {"short", "quorum"}
    /\ UNCHANGED <<status, keyDeleted, h, prepareH, inputsSpent, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* The user can only build Peg-In-Prepare from a quorum of answers.
PrepareConfirms ==
    /\ answered = "quorum" /\ prepareH = 0 /\ ~inputsSpent /\ h > 0
    /\ prepareH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, inputsSpent, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

InputSpentElsewhere ==
    /\ prepareH = 0 /\ ~inputsSpent
    /\ inputsSpent' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, endorsed,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

GraphEndorsed ==
    /\ prepareH > 0 /\ ~endorsed
    /\ endorsed' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   signed, signedAt, confirm, confirmH, cancelConfirmed, minted>>

\* A committee member signs Peg-In-Confirm: only in the Confirm phase and
\* only through the T0 gate (instance not failed, h < H_p + T0).
Sign ==
    /\ status = "Presigned" /\ SigningOpen /\ ~signed
    /\ signed' = TRUE
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, confirm, confirmH, cancelConfirmed, minted>>

\* Anyone holding the signed transaction may broadcast it at any time,
\* including after this node abandoned the instance.
ConfirmEntersMempool ==
    /\ signed /\ confirm = "none" /\ ~cancelConfirmed
    /\ confirm' = "mempool"
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirmH, cancelConfirmed, minted>>

ConfirmConfirms ==
    /\ confirm = "mempool" /\ ~cancelConfirmed
    /\ confirm' = "confirmed" /\ confirmH' = h
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, cancelConfirmed, minted>>

\* BIP68: Peg-In-Cancel is minable from H_p + T0; it conflicts with an
\* unconfirmed Peg-In-Confirm, which is then evicted.
CancelConfirms ==
    /\ prepareH > 0 /\ h >= CancelFromHeight /\ confirm # "confirmed" /\ ~cancelConfirmed
    /\ cancelConfirmed' = TRUE /\ confirm' = "none"
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirmH, minted>>

Mint ==
    /\ confirm = "confirmed" /\ ~minted
    /\ minted' = TRUE
    /\ UNCHANGED <<status, keyDeleted, h, answered, prepareH, inputsSpent,
                   endorsed, signed, signedAt, confirm, confirmH, cancelConfirmed>>

Environment ==
    \/ Tick \/ WindowCloses \/ PrepareConfirms \/ InputSpentElsewhere
    \/ GraphEndorsed \/ Sign \/ ConfirmEntersMempool \/ ConfirmConfirms
    \/ CancelConfirms \/ Mint

--------------------------------------------------------------------------
(* The Instance aggregate *)

\* decide_answer_window
ScanAnswers ==
    /\ status = "UserInited" /\ answered # "none"
    /\ status' = IF answered = "quorum" THEN "CommitteesAnswered"
                                        ELSE "NoEnoughCommitteesAnswered"
    /\ keyDeleted' = (keyDeleted \/ answered = "short")
    /\ UNCHANGED env

\* decide_btc_snapshot on the facts as they are now
ScanBitcoin ==
    /\ status \notin {"UserCanceled", "UserDiscarded", "NoEnoughCommitteesAnswered"}
    /\ LET s1 == IF status = "CommitteesAnswered"
                   THEN IF prepareH > 0 THEN "UserBroadcastPeginPrepare"
                        ELSE IF inputsSpent THEN "UserDiscarded"
                        ELSE status
                   ELSE status
           s2 == IF s1 \in {"UserBroadcastPeginPrepare", "Presigned"}
                   THEN IF confirm = "confirmed" THEN "RelayerL1Broadcasted"
                        ELSE IF cancelConfirmed THEN "UserCanceled"
                        ELSE IF prepareH > 0 /\ h >= AbandonHeight /\ confirm = "none"
                             THEN "Timeout"
                        ELSE s1
                   ELSE IF s1 = "Timeout" /\ cancelConfirmed THEN "UserCanceled"
                   ELSE s1
           failureDelete == s2 \in DeletesKey /\ s2 # status
           successDelete == s2 \in {"RelayerL1Broadcasted", "RelayerL2Minted"}
                            /\ confirm = "confirmed" /\ confirmH + KD <= h
       IN /\ status' = s2
          /\ keyDeleted' = (keyDeleted \/ failureDelete \/ successDelete)
    /\ UNCHANGED env

\* decide_graph_endorsed
ScanEndorsed ==
    /\ status = "UserBroadcastPeginPrepare" /\ endorsed
    /\ status' = "Presigned"
    /\ UNCHANGED <<keyDeleted>> /\ UNCHANGED env

\* decide_l2_minted: success from any live state, only an alert for failed instances
ScanMint ==
    /\ minted /\ status \notin Failed /\ status # "RelayerL2Minted"
    /\ status' = "RelayerL2Minted"
    /\ UNCHANGED <<keyDeleted>> /\ UNCHANGED env

Node == ScanAnswers \/ ScanBitcoin \/ ScanEndorsed \/ ScanMint

Next == Environment \/ Node
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Properties *)

\* The T0 gate: no protocol signature at or after H_p + T0.
NoSignatureAtOrAfterT0 ==
    \A x \in signedAt : prepareH > 0 /\ x < CancelFromHeight

\* The key is deleted only in the three failure states that delete it, or
\* on the success side once the Peg-In-Confirm is KD blocks deep.
KeyDeletedOnlyWhenSafe ==
    keyDeleted =>
        \/ status \in DeletesKey
        \/ (status \in {"RelayerL1Broadcasted", "RelayerL2Minted"}
            /\ confirm = "confirmed" /\ confirmH + KD <= h)

TimeoutKeepsKey == status = "Timeout" => ~keyDeleted

BroadcastedMeansConfirmed ==
    status \in {"RelayerL1Broadcasted", "RelayerL2Minted"} => confirm = "confirmed"

\* Failure states are terminal except Timeout -> UserCanceled.
FailureAbsorbing ==
    [][(status \in Failed =>
        status' \in (IF status = "Timeout" THEN {"Timeout", "UserCanceled"} ELSE {status}))]_vars

\* Timeout is only entered past the abandon height while the Peg-In-Confirm
\* is neither confirmed nor in the mempool.
NoTimeoutWhileVisible ==
    [][((status' = "Timeout" /\ status # "Timeout") =>
        (prepareH > 0 /\ h >= AbandonHeight /\ confirm = "none"))]_vars

MintedIsFinal == [][(status = "RelayerL2Minted" => status' = "RelayerL2Minted")]_vars

====
