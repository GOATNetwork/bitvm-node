---- MODULE PeginRequestLiveness ----
(***************************************************************************)
(* Low-severity liveness of a genuine peg-in (one module, one cfg pair per *)
(* finding). Code at dev 60562f8 (after #476).                             *)
(*                                                                         *)
(* F1 - free spam requests starve the Bitcoin scan.                         *)
(*   Gateway.sol:262-299 postPeginRequest: "TODO: check peginAmount,       *)
(*   feeRate,userInputs / TODO: charge fee". utils/goat_chain.rs:179-188    *)
(*   read_pegin_request only checks each input is UNSPENT (not owned, not  *)
(*   unique), so committee nodes answer requests built on anyone's UTXOs   *)
(*   (instance_jobs.rs:245-272). instance.rs:478-487 + instance_scan.rs:   *)
(*   287-310: CommitteesAnswered has no deadline - it only leaves on a     *)
(*   confirmed Prepare or a spent input. instance_scan.rs:65-107,182-218:  *)
(*   the Bitcoin scan pages INSTANCE_MAINTENANCE_BATCH_SIZE (env.rs:128-129,*)
(*   50) rows per maintenance tick (env.rs:126, every 20 s + run time), in  *)
(*   created_at order, over every CommitteesAnswered/UserBroadcastPeginPrepare/ *)
(*   Presigned/Timeout row. instance_jobs.rs:278-296: an operator starts no *)
(*   graph once tip > H_p + OPERATOR_GRAPH_START_CUTOFF_BLOCKS (env.rs:     *)
(*   192-200, 2/3 T0). Enough live spam rows delay the scan's detection of  *)
(*   the genuine Prepare past that cutoff: no graph, no Presigned, Timeout. *)
(*                                                                         *)
(* F6 - one off-curve committee answer wedges the instance.                *)
(*   Gateway.sol:301-327 answerPeginRequest checks length 33 and the parity *)
(*   byte only; the 32-byte x is stored unchecked and counts toward quorum. *)
(*   instance.rs:714-731: pegin_txids -> utils/instance_store.rs:186-197    *)
(*   PublicKey::from_slice fails -> warn!, no Prepare/Confirm/Cancel txids. *)
(*   instance_scan.rs:287-310: without the Prepare txid nothing is queried  *)
(*   -> CommitteesAnswered forever (the user cannot build the n-of-n        *)
(*   either). Refusing to answer would NOT block (quorum < committee); a    *)
(*   malformed answer does.                                                 *)
(*                                                                         *)
(* F7 - Prepare confirmed without a block height.                           *)
(*   instance.rs:481: prepare_height = prepare.block_height.unwrap_or(     *)
(*   prepare_height); prepare_height is instance.btc_height, created as 0   *)
(*   (utils/instance_store.rs:92) and never set before this step, so a      *)
(*   fact {confirmed: true, block_height: None} stores btc_height = 0, and  *)
(*   step 1 never runs again (only UserInited | CommitteesAnswered).        *)
(*   cancel_from_height(0) = None (instance.rs:177-179): the T0 gate never  *)
(*   closes and Timeout never fires; graph_start_blocked skips the cutoff   *)
(*   (instance_jobs.rs:288). REACHABILITY: tx_fact (instance_scan.rs:257-266)*)
(*   maps esplora's TxStatus, the only real adaptor                         *)
(*   (btc_chain/esplora_bitcoin_adaptor.rs:94-96); Esplora returns          *)
(*   block_height whenever confirmed = true, so F7 needs a non-conforming   *)
(*   backend/proxy - a latent hardening issue, not a live bug.              *)
(*                                                                         *)
(* Time is counted in maintenance ticks, TicksPerBlock per block. Honest   *)
(* protocol steps (graph endorsement when OperatorsHonest, Confirm, mint)  *)
(* complete before the next tick.                                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Spam, Batch, TicksPerBlock,   \* F1
    Hp, Cutoff, T0, B, MaxHeight,
    BadKey, OnCurveCheck,         \* F6 and its fix
    NoHeight, HeightRequired,     \* F7 and its fix
    OperatorsHonest

Rows == Spam + 1            \* the genuine row is the newest, index Spam
Terminal == {"RelayerL2Minted", "Timeout", "NoEnoughCommitteesAnswered",
             "UserDiscarded", "UserCanceled"}

VARIABLES
    h, t, cursor,
    status,         \* the genuine instance
    txidsKnown,     \* pegin_txids succeeded at CommitteesAnswered
    btcHeight,      \* instance.btc_height
    graphsStarted,  \* operators opened setup sessions
    signedAt,       \* heights at which the committee signed Peg-In-Confirm
    minted

vars == <<h, t, cursor, status, txidsKnown, btcHeight, graphsStarted, signedAt, minted>>

TypeOK ==
    /\ h \in 0..MaxHeight /\ t \in 0..(TicksPerBlock - 1) /\ cursor \in 0..Rows
    /\ status \in {"CommitteesAnswered", "UserBroadcastPeginPrepare", "Presigned",
                   "RelayerL1Broadcasted"} \cup Terminal
    /\ txidsKnown \in BOOLEAN /\ btcHeight \in 0..MaxHeight
    /\ graphsStarted \in BOOLEAN /\ signedAt \subseteq 0..MaxHeight
    /\ minted \in BOOLEAN

\* The answer window closed with a quorum. With the on-curve check the
\* malformed answer is refused and the honest answers still make quorum.
Init ==
    /\ h = 0 /\ t = 0
    /\ cursor \in 0..Rows          \* the scan's phase is arbitrary
    /\ status = "CommitteesAnswered"
    /\ txidsKnown = (~BadKey \/ OnCurveCheck)
    /\ btcHeight = 0 /\ graphsStarted = FALSE
    /\ signedAt = {} /\ minted = FALSE

PrepareOnChain == txidsKnown /\ h >= Hp
GateOpen == btcHeight = 0 \/ h < btcHeight + T0

--------------------------------------------------------------------------
(* One maintenance tick: find_one_instance_page + gather_snapshot + decide *)

Covered == cursor <= Spam /\ Spam < cursor + Batch
NextCursor ==
    IF Rows - cursor >= Batch THEN cursor + Batch   \* full page: advance
    ELSE 0                                          \* short/empty page: reset
Clock ==
    /\ t' = (t + 1) % TicksPerBlock
    /\ h' = IF t = TicksPerBlock - 1 /\ h < MaxHeight THEN h + 1 ELSE h
    /\ cursor' = NextCursor

Detect(height) ==
    /\ status' = "UserBroadcastPeginPrepare"
    /\ btcHeight' = height
    \* graph_start_blocked: cutoff only when btc_height > 0
    /\ graphsStarted' = (height = 0 \/ h <= height + Cutoff)

TimesOut ==
    status \in {"UserBroadcastPeginPrepare", "Presigned"}
    /\ btcHeight > 0 /\ h >= btcHeight + T0 + B

Prompt ==
    \/ OperatorsHonest /\ graphsStarted /\ status = "UserBroadcastPeginPrepare"
    \/ status = "Presigned" /\ GateOpen
    \/ status = "RelayerL1Broadcasted"

\* The scan reads the Prepare WITH its block height.
StepH ==
    /\ ~Prompt /\ Clock
    /\ IF Covered /\ status = "CommitteesAnswered" /\ PrepareOnChain
          THEN Detect(Hp)
       ELSE IF Covered /\ TimesOut
          THEN /\ status' = "Timeout" /\ UNCHANGED <<btcHeight, graphsStarted>>
       ELSE UNCHANGED <<status, btcHeight, graphsStarted>>
    /\ UNCHANGED <<txidsKnown, signedAt, minted>>

\* F7: the backend says confirmed but omits block_height on this query.
StepN ==
    /\ NoHeight /\ ~Prompt /\ Clock
    /\ Covered /\ status = "CommitteesAnswered" /\ PrepareOnChain
    /\ IF HeightRequired
          THEN UNCHANGED <<status, btcHeight, graphsStarted>>   \* retry next scan
          ELSE Detect(0)                                        \* unwrap_or(0)
    /\ UNCHANGED <<txidsKnown, signedAt, minted>>

GraphEndorsed ==
    /\ graphsStarted /\ status = "UserBroadcastPeginPrepare"
    /\ status' = "Presigned"
    /\ UNCHANGED <<h, t, cursor, txidsKnown, btcHeight, graphsStarted, signedAt, minted>>

\* PeginConfirm round through the T0 gate, broadcast, confirmed.
ConfirmDone ==
    /\ status = "Presigned" /\ GateOpen
    /\ status' = "RelayerL1Broadcasted"
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<h, t, cursor, txidsKnown, btcHeight, graphsStarted, minted>>

Mint ==
    /\ status = "RelayerL1Broadcasted"
    /\ status' = "RelayerL2Minted" /\ minted' = TRUE
    /\ UNCHANGED <<h, t, cursor, txidsKnown, btcHeight, graphsStarted, signedAt>>

Next == StepH \/ StepN \/ GraphEndorsed \/ ConfirmDone \/ Mint

\* A scan that reaches the confirmed Prepare with its height: the backend
\* does not omit the height forever (strong fairness over the scan pass).
DetectWithHeight ==
    StepH /\ Covered /\ status = "CommitteesAnswered" /\ PrepareOnChain

Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(StepH) /\ SF_vars(DetectWithHeight)
    /\ WF_vars(ConfirmDone) /\ WF_vars(Mint)
    /\ (OperatorsHonest => WF_vars(GraphEndorsed))

--------------------------------------------------------------------------
(* Properties *)

\* An honest user's peg-in, with honest operators, ends minted.
GenuinePeginProgresses == <>(status = "RelayerL2Minted")

\* Every instance reaches a terminal status.
NoStuckInstance == <>(status \in Terminal)

\* The T0 gate (as in InstanceLifecycle.tla), against the TRUE Prepare height.
NoSignatureAtOrAfterT0 == \A x \in signedAt : x < Hp + T0

====
