---- MODULE DisproveSettlement ----
(***************************************************************************)
(* How a node recognises that a graph was disproved on Bitcoin, and how   *)
(* the relayer then settles that disprove on Goat.                         *)
(*                                                                         *)
(* Part 1 - recognition (node/src/utils/graph_chain_state.rs:              *)
(* confirmed_connector_spend, matches_presigned_inputs,                    *)
(* classify_connector_spend, detect_guardian_disprove,                     *)
(* detect_connector_d_disprove). The graph's outcome is read from the      *)
(* transaction that actually spent the guardian connector or Connector-D,  *)
(* not from the txid of a prebuilt template:                               *)
(*   - Quick-Challenge, Challenge-Incomplete-Kickoff and Disprove-X are    *)
(*     presigned with SIGHASH_NONE, so the broadcaster picks the outputs   *)
(*     (reward OP_RETURN, change, anchor) and the txid changes. They are   *)
(*     identified by version, locktime and input structure.                *)
(*   - Take-1 and Take-2 are SIGHASH_ALL: their txid is fixed and they are *)
(*     excluded by txid.                                                   *)
(*   - On Connector-D the tapleaf decides: the Pubin-Disprove leaf (2) is  *)
(*     a Pubin-Disprove whatever the other inputs are; the N-of-N leaf (1) *)
(*     plus the inputs of Disprove-X i (input 0 = verifier i's assert      *)
(*     output) is Disprove-X i; the operator's timelock leaf (0) is Take-2 *)
(*     or an arbitrary operator spend.                                     *)
(*   - The guardian key path and Connector-D leaf 0 let the operator spend *)
(*     those connectors with arbitrary transactions: not a disprove, and   *)
(*     the scan keeps going (commit 5ef78f1).                              *)
(*   - An unconfirmed spend is nothing yet; a confirmed spend whose        *)
(*     transaction is missing, hashes to another txid, or does not spend   *)
(*     the connector is an error: the scan retries, the graph stays open.  *)
(* A txid is modelled as <<input structure, outputs>> (witnesses are not   *)
(* part of it); "Modified" stands for any non-template output set.         *)
(*                                                                         *)
(* Part 2 - settlement (node/src/aggregates/graph_pegout_jobs.rs:          *)
(* finish_disproved, routed only to relayers by graph_pegout.rs).          *)
(* finishWithdrawDisproved no longer requires initWithdraw/proceedWithdraw:*)
(* WithdrawStatus None is a valid settlement state and is never given up   *)
(* on after a retry budget; Disproved is the idempotent exit; every other  *)
(* status takes the same path: Take-1 exclusion on Connector-A, the        *)
(* challenge-finish tx (by the actual txid) must be readable, and the GOAT *)
(* SPV client must cover its block. Goat RPC errors retry.                 *)
(*                                                                         *)
(* Assumed, not modelled: Goat accepts a correct finishWithdrawDisproved   *)
(* for any non-Disproved status, including a Disprove-X with changed      *)
(* outputs (contract-side CT1/CT2 in docs/contract-followups.md), and a    *)
(* Goat revert ends the job. The liveness result therefore only says the   *)
(* node keeps trying until the call lands; it is not a general guarantee  *)
(* that every peg-out job retries forever.                                 *)
(*                                                                         *)
(* Pre-fix switches (each makes TLC fail):                                 *)
(*   IdentifyByTemplateTxid  - the old detection: a guardian challenge     *)
(*     only if its template txid confirmed; on Connector-D, Take-2 txid -> *)
(*     nothing, a Disprove-X template txid -> Disprove-X, anything else -> *)
(*     Pubin-Disprove.                                                     *)
(*   GiveUpOnMissingWithdraw - the old finish_disproved: WithdrawStatus    *)
(*     None went through withdraw_missing and was ignored for good after   *)
(*     WITHDRAW_LAG_RETRIES runs (LagRetries here).                        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    VerifierNum,             \* Disprove-X templates, one per verifier
    LagRetries,              \* stands for WITHDRAW_LAG_RETRIES (30)
    IdentifyByTemplateTxid,  \* pre-fix recognition
    GiveUpOnMissingWithdraw  \* pre-fix settlement gate

ASSUME VerifierNum \in Nat \ {0} /\ LagRetries \in Nat \ {0}
ASSUME IdentifyByTemplateTxid \in BOOLEAN /\ GiveUpOnMissingWithdraw \in BOOLEAN

Verifiers == 1..VerifierNum

\* Input structures (version, locktime, outpoints, sequences, scriptSigs).
In(k) == <<k, 0>>
DisX(i) == <<"DisX", i>>
QC == In("QC")
CIK == In("CIK")
Take1 == In("Take1")
Take2 == In("Take2")
OtherIn == In("Other")
DisXIns == {DisX(i) : i \in Verifiers}

Outputs == {"Template", "Modified"}
\* Connector-D tapleaf in the witness; "NA" for the guardian connector,
\* whose spends are told apart by input structure only.
Leaves == {"Timelock", "NofN", "Pubin", "NA"}

Spend(c, i, o, l) == [conn |-> c, inputs |-> i, outputs |-> o, leaf |-> l]

\* Every confirmed spend Bitcoin allows. SIGHASH_NONE templates take any
\* outputs, SIGHASH_ALL Takes only their own; the N-of-N leaf is only signed
\* inside Disprove-X templates; the Pubin-Disprove leaf and the operator's
\* paths accept any transaction. A Pubin-Disprove whose other inputs equal a
\* Disprove-X's is kept although input 0 of a Disprove-X needs the committee
\* (an over-approximation, as in the Rust unit test); the timelock leaf's
\* CSV sequence never matches a Disprove-X input structure.
ValidSpends ==
    {Spend("G", i, o, "NA") : i \in {QC, CIK, OtherIn}, o \in Outputs}
    \cup {Spend("G", i, "Template", "NA") : i \in {Take1, Take2}}
    \cup {Spend("D", i, o, "NofN") : i \in DisXIns, o \in Outputs}
    \cup {Spend("D", i, o, "Pubin") : i \in DisXIns \cup {OtherIn}, o \in Outputs}
    \cup {Spend("D", Take2, "Template", "Timelock")}
    \cup {Spend("D", OtherIn, o, "Timelock") : o \in Outputs}

Txid(s) == <<s.inputs, s.outputs>>
TemplateTxid(i) == <<i, "Template">>

Det(k, x, t) == [kind |-> k, index |-> x, txid |-> t]
NoDet == Det("None", 0, TemplateTxid(OtherIn))
DisproveKinds == {"QuickChallenge", "ChallengeIncompleteKickoff", "Disprove", "PubinDisprove"}

\* What the spend is, by protocol semantics.
TrueKind(s) ==
    IF s.conn = "G" THEN
        CASE s.inputs = QC -> "QuickChallenge"
          [] s.inputs = CIK -> "ChallengeIncompleteKickoff"
          [] s.inputs \in {Take1, Take2} -> "Take"
          [] OTHER -> "NotDisprove"
    ELSE
        CASE s.leaf = "Pubin" -> "PubinDisprove"
          [] s.leaf = "NofN" -> "Disprove"
          [] s.inputs = Take2 -> "Take"
          [] OTHER -> "NotDisprove"
TrueIndex(s) == IF TrueKind(s) = "Disprove" THEN s.inputs[2] ELSE 0
IsDisprove(s) == TrueKind(s) \in DisproveKinds

\* classify_connector_spend after the fix.
Candidates(c) ==
    IF c = "G" THEN {<<QC, "QuickChallenge", 0>>, <<CIK, "ChallengeIncompleteKickoff", 0>>}
    ELSE {<<DisX(i), "Disprove", i>> : i \in Verifiers}
Takes(c) == IF c = "G" THEN {TemplateTxid(Take1), TemplateTxid(Take2)} ELSE {TemplateTxid(Take2)}

ClassifyFixed(s) ==
    LET leafOk == s.conn = "G" \/ s.leaf = "NofN"
        hits == {c \in Candidates(s.conn) : leafOk /\ c[1] = s.inputs}
    IN  IF Txid(s) \in Takes(s.conn) THEN NoDet
        ELSE IF s.conn = "D" /\ s.leaf = "Pubin" THEN Det("PubinDisprove", 0, Txid(s))
        ELSE IF hits = {} THEN NoDet
        ELSE LET c == CHOOSE h \in hits : TRUE IN Det(c[2], c[3], Txid(s))

\* The pre-fix detect_guardian_disprove / detect_connector_d_disprove.
ClassifyTemplateTxid(s) ==
    IF s.conn = "G" THEN
        CASE Txid(s) = TemplateTxid(QC) -> Det("QuickChallenge", 0, Txid(s))
          [] Txid(s) = TemplateTxid(CIK) -> Det("ChallengeIncompleteKickoff", 0, Txid(s))
          [] OTHER -> NoDet
    ELSE IF Txid(s) = TemplateTxid(Take2) THEN NoDet
    ELSE IF \E i \in Verifiers : Txid(s) = TemplateTxid(DisX(i))
        THEN Det("Disprove", CHOOSE i \in Verifiers : Txid(s) = TemplateTxid(DisX(i)), Txid(s))
    ELSE Det("PubinDisprove", 0, Txid(s))

Classify(s) == IF IdentifyByTemplateTxid THEN ClassifyTemplateTxid(s) ELSE ClassifyFixed(s)

\* What confirmed_connector_spend can get back from the Bitcoin backend.
Backend == {"Ok", "TxMissing", "HashMismatch", "NotSpendingConnector"}
WithdrawStatuses == {"None", "Initialized", "Processing", "Canceled", "Complete", "Disproved"}
Min(a, b) == IF a <= b THEN a ELSE b

VARIABLES
    spend,      \* the transaction that spends the watched connector (fixed)
    confirmed,  \* that spend is confirmed
    connA,      \* Kickoff Connector-A: "Unspent", "Challenge" or "Take1"
    graph,      \* local graph: "Open" while scanning, "Disprove" once detected
    det,        \* the DetectedDisprove handed to the DisproveSent signal
    scanResult, \* outcome of the last scan: "Pending", "None", "Retry", "Disprove"
    relayer,    \* this node is a committee relayer
    withdraw,   \* WithdrawStatus of the graph on Goat
    spv,        \* the GOAT SPV client covers the spend's block
    job,        \* finish_disproved job: "Absent", "Pending", "Done", "Ignored", "GaveUp", "Rejected"
    attempts    \* runs of that job (capped at LagRetries)

vars == <<spend, confirmed, connA, graph, det, scanResult, relayer, withdraw, spv, job, attempts>>

TypeOK ==
    /\ spend \in ValidSpends
    /\ confirmed \in BOOLEAN /\ spv \in BOOLEAN /\ relayer \in BOOLEAN
    /\ connA \in {"Unspent", "Challenge", "Take1"}
    /\ graph \in {"Open", "Disprove"}
    /\ det.kind \in DisproveKinds \cup {"None"}
    /\ scanResult \in {"Pending", "None", "Retry", "Disprove"}
    /\ withdraw \in WithdrawStatuses
    /\ job \in {"Absent", "Pending", "Done", "Ignored", "GaveUp", "Rejected"}
    /\ attempts \in 0..LagRetries

\* Connector-A as Bitcoin allows it next to the spend: Take-1 also spends the
\* guardian connector and Connector-A, so it excludes every disprove; a
\* Connector-D disprove needs a Challenge on Connector-A.
ConnAFits(s, a) ==
    /\ (s.inputs = Take1) => a = "Take1"
    /\ IsDisprove(s) => a # "Take1"
    /\ (IsDisprove(s) /\ s.conn = "D") => a = "Challenge"

Init ==
    /\ spend \in ValidSpends
    /\ connA \in {a \in {"Unspent", "Challenge", "Take1"} : ConnAFits(spend, a)}
    /\ confirmed = FALSE
    /\ graph = "Open"
    /\ det = NoDet
    /\ scanResult = "Pending"
    /\ relayer \in BOOLEAN
    /\ withdraw \in WithdrawStatuses
    /\ spv = FALSE
    /\ job = "Absent"
    /\ attempts = 0

------------------------------------------------------------------------------
\* Bitcoin and Goat environment.

Confirm == ~confirmed /\ confirmed' = TRUE /\ UNCHANGED <<spend, connA, graph, det, scanResult, relayer, withdraw, spv, job, attempts>>

SpvCatchUp == confirmed /\ ~spv /\ spv' = TRUE /\ UNCHANGED <<spend, confirmed, connA, graph, det, scanResult, relayer, withdraw, job, attempts>>

\* A malicious operator may or may not call initWithdraw at any time.
OperatorInitWithdraw ==
    /\ withdraw = "None" /\ withdraw' = "Initialized"
    /\ UNCHANGED <<spend, confirmed, connA, graph, det, scanResult, relayer, spv, job, attempts>>

\* Another relayer's finishWithdrawDisproved lands first.
OtherRelayerSettles ==
    /\ confirmed /\ spv /\ IsDisprove(spend) /\ withdraw # "Disproved"
    /\ withdraw' = "Disproved"
    /\ UNCHANGED <<spend, confirmed, connA, graph, det, scanResult, relayer, spv, job, attempts>>

------------------------------------------------------------------------------
\* Graph scan (scan_graph_chain_state) for this graph's connector.

Scan(b) ==
    /\ graph = "Open"
    /\ UNCHANGED <<spend, confirmed, connA, relayer, withdraw, spv, attempts>>
    /\ IF ~confirmed THEN
           /\ scanResult' = "Pending" /\ UNCHANGED <<graph, det, job>>
       ELSE IF b # "Ok" THEN
           /\ scanResult' = "Retry" /\ UNCHANGED <<graph, det, job>>
       ELSE LET r == Classify(spend) IN
           IF r.kind = "None" THEN
               /\ scanResult' = "None" /\ UNCHANGED <<graph, det, job>>
           ELSE
               /\ scanResult' = "Disprove" /\ graph' = "Disprove" /\ det' = r
               \* DisproveSent is routed to JOB_FINISH_DISPROVED for relayers only.
               /\ job' = IF relayer THEN "Pending" ELSE "Absent"

------------------------------------------------------------------------------
\* finish_disproved. rpcOk = FALSE: a Goat or Bitcoin RPC failed (transient).

SettlementAccepted ==
    det.kind = TrueKind(spend) /\ det.index = TrueIndex(spend) /\ det.txid = Txid(spend)

JobRun(rpcOk) ==
    /\ job = "Pending"
    /\ attempts' = Min(attempts + 1, LagRetries)
    /\ UNCHANGED <<spend, confirmed, connA, graph, det, scanResult, relayer, spv>>
    /\ IF ~rpcOk THEN UNCHANGED <<withdraw, job>>
       ELSE IF ~relayer THEN job' = "Ignored" /\ UNCHANGED withdraw
       ELSE IF withdraw = "Disproved" THEN job' = "Ignored" /\ UNCHANGED withdraw
       ELSE IF GiveUpOnMissingWithdraw /\ withdraw = "None" THEN
           \* withdraw_missing: wait, then give up for good.
           /\ job' = IF attempts < LagRetries THEN "Pending" ELSE "GaveUp"
           /\ UNCHANGED withdraw
       ELSE IF connA = "Take1" THEN job' = "Ignored" /\ UNCHANGED withdraw
       \* btc.get_tx(challenge_finish_txid): only the txid that is on chain.
       ELSE IF ~(confirmed /\ det.txid = Txid(spend)) THEN UNCHANGED <<withdraw, job>>
       ELSE IF ~spv THEN UNCHANGED <<withdraw, job>>
       ELSE IF SettlementAccepted THEN withdraw' = "Disproved" /\ job' = "Done"
       ELSE job' = "Rejected" /\ UNCHANGED withdraw

Next ==
    \/ Confirm \/ SpvCatchUp \/ OperatorInitWithdraw \/ OtherRelayerSettles
    \/ \E b \in Backend : Scan(b)
    \/ \E ok \in BOOLEAN : JobRun(ok)

\* Fairness: the spend confirms, SPV catches up, and the backend and Goat
\* RPC answer correctly infinitely often. Nothing forces the operator to
\* call initWithdraw or another relayer to act.
Fairness ==
    /\ WF_vars(Confirm) /\ WF_vars(SpvCatchUp)
    /\ WF_vars(Scan("Ok")) /\ WF_vars(JobRun(TRUE))

Spec == Init /\ [][Next]_vars /\ Fairness

------------------------------------------------------------------------------
\* Part 1 properties.

\* A graph only becomes Disprove from a confirmed spend that really is a
\* disprove, with its kind, verifier index and actual on-chain txid.
DisproveMatchesActualSpend ==
    graph = "Disprove" =>
        /\ confirmed
        /\ IsDisprove(spend)
        /\ det.kind = TrueKind(spend)
        /\ det.index = TrueIndex(spend)
        /\ det.txid = Txid(spend)

\* Takes and arbitrary operator spends never make a disprove.
NonDisproveSpendsKeepGraphOpen == ~IsDisprove(spend) => graph = "Open"

\* An unconfirmed spend or a backend error is retried, never terminal.
RetryIsNotTerminal == scanResult \in {"Pending", "Retry"} => graph = "Open"

\* Reward, change and anchor outputs do not change the classification:
\* the spend classifies like every valid spend that differs only in outputs.
OutputsDoNotChangeClassification ==
    \A t \in ValidSpends :
        (t.conn = spend.conn /\ t.inputs = spend.inputs /\ t.leaf = spend.leaf)
            => /\ Classify(t).kind = Classify(spend).kind
               /\ Classify(t).index = Classify(spend).index

\* Every confirmed disprove is eventually recognised.
DisproveEventuallyDetected == IsDisprove(spend) => <>(graph = "Disprove")

------------------------------------------------------------------------------
\* Part 2 properties.

\* Our finishWithdrawDisproved is only sent by a relayer, after a disprove
\* was detected, not over a Take-1, for the confirmed actual txid once SPV
\* covers it, and never when Goat already shows Disproved.
SubmitGuarded ==
    [][(job' = "Done" /\ job # "Done") =>
        /\ relayer /\ graph = "Disprove" /\ connA # "Take1"
        /\ confirmed /\ det.txid = Txid(spend) /\ spv
        /\ withdraw # "Disproved"]_vars

\* Disproved is final on Goat.
DisprovedIsAbsorbing == [][withdraw = "Disproved" => withdraw' = "Disproved"]_withdraw

\* WithdrawStatus None is never given up on.
NoneNeverGivenUp == job # "GaveUp"

\* H7: an operator whose Kickoff is disproved on Bitcoin without any
\* initWithdraw is slashed on Goat, given a relayer, proof availability and
\* fair scheduling.
RogueKickoffSlashed ==
    (relayer /\ IsDisprove(spend) /\ withdraw = "None") => <>(withdraw = "Disproved")

\* The same for every starting WithdrawStatus.
DisproveEventuallySettled ==
    (relayer /\ IsDisprove(spend)) => <>(withdraw = "Disproved")

====
