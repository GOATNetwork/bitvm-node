---- MODULE PeginRequestLiveness ----
(***************************************************************************)
(* Liveness of one genuine peg-in from CommitteesAnswered: the paged       *)
(* Bitcoin scan (instance_scan.rs:193, find_one_instance_page :67, 50 rows *)
(* per 20 s tick, env.rs:126-129), decide_btc_snapshot (instance.rs:442),  *)
(* the operators' graph cutoff (instance_jobs.rs:278 graph_start_blocked,  *)
(* default 2*T0/3, env.rs:194-200), the T0 gate and Timeout.               *)
(* F1: free requests on anyone's unspent UTXOs (Gateway.sol                *)
(*   postPeginRequest charges nothing; utils/goat_chain.rs:142 checks      *)
(*   only that inputs are unspent) stay CommitteesAnswered forever and     *)
(*   delay the scan's detection of the genuine Prepare past the cutoff:    *)
(*   no graph, Timeout (GenuinePeginProgresses).                           *)
(* F6: one off-curve committee answer (Gateway.sol checks only length and  *)
(*   parity) makes pegin_txids fail (instance.rs:716-729,                  *)
(*   instance_store.rs:190): no Prepare txid, CommitteesAnswered forever   *)
(*   (NoStuckInstance).                                                    *)
(* F7 (latent, needs a backend that omits block_height): btc_height stays  *)
(*   0 (instance.rs:481), so the T0 gate and Timeout never fire            *)
(*   (NoStuckInstance, NoSignatureAtOrAfterT0).                            *)
(* Parameters (frozen variables): spam, batch, tpb (live spam rows, page   *)
(*   size, ticks per block); t0, b; gd, cd (most blocks the honest graph   *)
(*   endorsement / Confirm round take, scheduled by the adversary). NetSet *)
(*   = {}: sweep the *Range constants, else shipped (ShippedSpam).         *)
(* F1 fix (bounded live spam): ParamsOK, exact.                            *)
(* Exhaustiveness: the guards compare ScanLag with the cutoff and          *)
(*   ScanLag + gd + cd with t0 - 1. spam 0..4, batch, tpb 1..2 give        *)
(*   ScanLag 0..5; with t0 1..6, gd, cd 0..1 every order occurs with       *)
(*   margins 0 and 1; any B >= 1 is one class. F6, F7: every value.        *)
(* Configs: configs/node/aggregates/instance/PeginRequestLiveness/, tiers  *)
(*   in audit/tla/checks.txt.                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, ShippedTimelockValues

CONSTANTS
    NetSet,             \* {} = generic sweep, else the networks whose shipped values to use
    SpamRange,          \* generic sweep: live spam rows ahead of the genuine instance
    BatchRange,         \* generic sweep: scan page sizes
    TPBRange,           \* generic sweep: maintenance ticks per block
    T0Range,            \* generic sweep: connector_z CSV values
    BRange,             \* generic sweep: abandon buffer values
    GraphDelayRange,    \* generic sweep: honest graph-endorsement delay bounds (blocks)
    ConfirmDelayRange,  \* generic sweep: honest Confirm-round delay bounds (blocks)
    ShippedSpam,        \* shipped: "attack" (spam past the cutoff) | "bounded" (F1 fix)
    PhaseFixed,         \* TRUE: the scan starts a pass at the Prepare block (else any phase)
    ParamFilter,        \* "all" | "ok" (ParamsOK) | "notok"
    BadKey,             \* F6: one committee answer has an off-curve x
    OnCurveCheck,       \* F6 fix: off-curve answers are refused
    NoHeight,           \* F7: the backend may report a confirmed Prepare without a height
    HeightRequired,     \* F7 fix: a confirmed Prepare without a height is not acted on
    OperatorsHonest     \* operators endorse graphs (fairness on GraphEndorsed)

ASSUME /\ NetSet \subseteq Networks
       /\ ShippedSpam \in {"attack", "bounded"} /\ PhaseFixed \in BOOLEAN
       /\ ParamFilter \in {"all", "ok", "notok"}

\* InstanceBridgeInStatus values the genuine instance can take.
CommitteesAnswered        == "CommitteesAnswered"
UserBroadcastPeginPrepare == "UserBroadcastPeginPrepare"
Presigned                 == "Presigned"
RelayerL1Broadcasted      == "RelayerL1Broadcasted"
RelayerL2Minted           == "RelayerL2Minted"
Timeout                   == "Timeout"
Terminal == {RelayerL2Minted, Timeout, "NoEnoughCommitteesAnswered",
             "UserDiscarded", "UserCanceled"}
Statuses == {CommitteesAnswered, UserBroadcastPeginPrepare, Presigned,
             RelayerL1Broadcasted} \cup Terminal
\* No time-dependent behaviour is left, so the clock stops.
Settled == Terminal \cup {RelayerL1Broadcasted}

Hp == 1                  \* Peg-In-Prepare height
Generic == "generic"     \* net value of a generic-sweep run
BatchShipped == 50       \* DEFAULT_INSTANCE_MAINTENANCE_BATCH_SIZE (env.rs:129)
TaskIntervalSecs == 20   \* REGULAR_TASK_INTERVAL_SECOND (env.rs:126)

VARIABLES
    net,            \* frozen: network whose shipped values are used (Generic in a sweep)
    spam,           \* frozen: live spam rows ahead of the genuine instance
    batch,          \* frozen: scan page size
    tpb,            \* frozen: maintenance ticks per block
    t0,             \* frozen: connector_z CSV
    b,              \* frozen: abandon buffer
    gd,             \* frozen: honest graph-endorsement delay bound (blocks)
    cd,             \* frozen: honest Confirm-round delay bound (blocks)
    h,              \* Bitcoin tip
    t,              \* maintenance ticks done in block h (0..tpb)
    cursor,         \* the scan's page start (row index)
    status,         \* the genuine instance's status
    txidsKnown,     \* pegin_txids succeeded at CommitteesAnswered
    btcHeight,      \* instance.btc_height (0 = unset)
    graphsStarted,  \* operators opened setup sessions
    stepH,          \* height of the last honest step (detection / Presigned)
    signedAt,       \* heights at which the committee signed Peg-In-Confirm
    minted          \* Goat BridgeIn

params == <<net, spam, batch, tpb, t0, b, gd, cd>>
vars == <<params, h, t, cursor, status, txidsKnown, btcHeight, graphsStarted,
          stepH, signedAt, minted>>

Cutoff == (2 * t0) \div 3     \* default OPERATOR_GRAPH_START_CUTOFF_BLOCKS (env.rs:199)
Rows == spam + 1              \* the genuine row is the newest, index spam
MaxHeight == Hp + t0 + b      \* the Timeout height
PassTicks == Rows \div batch + 1   \* ticks per scan pass: full pages, then a short page
ScanLag == (PassTicks - 1) \div tpb \* most blocks from the Prepare to its detection (reachable)
\* F1 fix: graphs start, and the Confirm is signed before T0.
ParamsOK == ScanLag <= Cutoff /\ ScanLag + gd + cd <= t0 - 1

InitParams ==
    /\ IF NetSet = {}
          THEN /\ net = Generic
               /\ spam \in SpamRange /\ batch \in BatchRange /\ tpb \in TPBRange
               /\ t0 \in T0Range /\ b \in BRange
               /\ gd \in GraphDelayRange /\ cd \in ConfirmDelayRange
          ELSE /\ net \in NetSet
               /\ t0 = ConnectorZ[net] /\ b = PeginAbandonBufferBlocks[net]
               /\ tpb = BlockIntervalSecs[net] \div TaskIntervalSecs
               /\ batch = BatchShipped
               /\ IF ShippedSpam = "attack"
                     THEN /\ spam = batch * (Cutoff + 1) * tpb
                          /\ gd = 0 /\ cd = 0
                     ELSE /\ spam = batch * tpb - 1
                          /\ gd = ReactionBlocks[net] /\ cd = ReactionBlocks[net]
    /\ CASE ParamFilter = "all" -> TRUE
         [] ParamFilter = "ok"  -> ParamsOK
         [] OTHER               -> ~ParamsOK

TypeOk ==
    /\ net \in NetSet \cup {Generic}
    /\ spam \in Nat /\ batch \in Nat \ {0} /\ tpb \in Nat \ {0}
    /\ t0 \in Nat \ {0} /\ b \in Nat \ {0} /\ gd \in Nat /\ cd \in Nat
    /\ h \in 0..MaxHeight /\ t \in 0..tpb /\ cursor \in 0..Rows
    /\ status \in Statuses
    /\ txidsKnown \in BOOLEAN /\ btcHeight \in 0..MaxHeight
    /\ graphsStarted \in BOOLEAN /\ stepH \in 0..MaxHeight
    /\ signedAt \subseteq 0..MaxHeight
    /\ minted \in BOOLEAN

\* The answer window closed with a quorum and the Prepare is in block Hp, the
\* tip. With the on-curve check the malformed answer is refused and the honest
\* answers still make quorum.
Init ==
    /\ InitParams
    /\ h = Hp /\ t = 0
    /\ IF PhaseFixed THEN cursor = 0
       ELSE cursor \in {c \in 0..Rows : c % batch = 0}   \* the scan's phase is arbitrary
    /\ status = CommitteesAnswered
    /\ txidsKnown = (~BadKey \/ OnCurveCheck)
    /\ btcHeight = 0 /\ graphsStarted = FALSE /\ stepH = 0
    /\ signedAt = {} /\ minted = FALSE

PrepareOnChain == txidsKnown /\ h >= Hp            \* the scan can query the Prepare
GateOpen == btcHeight = 0 \/ h < btcHeight + t0    \* signing_gate_for (instance.rs:602)

Covered == cursor <= spam /\ spam < cursor + batch  \* this page holds the genuine row
NextCursor ==
    IF Rows - cursor >= batch THEN cursor + batch   \* full page: advance
    ELSE 0                                          \* short/empty page: reset

\* An honest step is due in this block: the tip may not move on.
Due ==
    \/ OperatorsHonest /\ graphsStarted /\ status = UserBroadcastPeginPrepare
       /\ h >= stepH + gd
    \/ status = Presigned /\ GateOpen /\ h >= stepH + cd

\* One maintenance tick of block h (ticks 0..tpb-1): the page moves on.
Clock ==
    /\ status \notin Settled
    /\ t < tpb /\ t' = t + 1 /\ h' = h
    /\ cursor' = NextCursor

\* The confirmed Prepare is detected; btc_height := height.
Detect(height) ==
    /\ status' = UserBroadcastPeginPrepare
    /\ btcHeight' = height
    /\ stepH' = h
    \* graph_start_blocked: cutoff only when btc_height > 0
    /\ graphsStarted' = (height = 0 \/ h <= height + Cutoff)

\* decide_btc_snapshot's Timeout (the Confirm stays invisible until ConfirmDone).
TimesOut ==
    status \in {UserBroadcastPeginPrepare, Presigned}
    /\ btcHeight > 0 /\ h >= btcHeight + t0 + b

--------------------------------------------------------------------------
(* Actions *)

\* Action: one tick of the Bitcoin scan reads the current page; if it holds
\* the genuine row, the Prepare is detected with its height (graphs start
\* within the cutoff), or past H_p + T0 + B the instance times out.
\* Source: scan_instances_on_bitcoin() in node/src/aggregates/instance_scan.rs:193
\* Source: find_one_instance_page() in node/src/aggregates/instance_scan.rs:67-107
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:478-506
\* Source: graph_start_blocked() in node/src/aggregates/instance_jobs.rs:278-296
ScanTick ==
    /\ Clock
    /\ IF Covered /\ status = CommitteesAnswered /\ PrepareOnChain
          THEN Detect(Hp)
       ELSE IF Covered /\ TimesOut
          THEN /\ status' = Timeout /\ UNCHANGED <<btcHeight, graphsStarted, stepH>>
       ELSE UNCHANGED <<status, btcHeight, graphsStarted, stepH>>
    /\ UNCHANGED <<params, txidsKnown, signedAt, minted>>

\* Action: F7, a scan tick where the backend reports the Prepare confirmed
\* without a height: the code stores btc_height 0; the fix retries.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:481
\* Source: tx_fact() in node/src/aggregates/instance_scan.rs:257-266
\* Source: environment (non-conforming backend)
ScanTickNoHeight ==
    /\ NoHeight /\ Clock
    /\ Covered /\ status = CommitteesAnswered /\ PrepareOnChain
    /\ IF HeightRequired
          THEN UNCHANGED <<status, btcHeight, graphsStarted, stepH>>   \* retry next scan
          ELSE Detect(0)                                               \* unwrap_or(0)
    /\ UNCHANGED <<params, txidsKnown, signedAt, minted>>

\* Action: after tpb ticks the next block arrives, unless an honest step is due.
\* Source: Bitcoin consensus
NewBlock ==
    /\ status \notin Settled /\ t = tpb /\ ~Due
    /\ t' = 0 /\ h' = IF h < MaxHeight THEN h + 1 ELSE h
    /\ UNCHANGED <<params, cursor, status, txidsKnown, btcHeight, graphsStarted,
                   stepH, signedAt, minted>>

\* Action: operators finish graph setup and the committee presigns: enough
\* endorsed graphs move the instance to Presigned.
\* Source: confirm_instance() in node/src/aggregates/instance_jobs.rs:300
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550
GraphEndorsed ==
    /\ graphsStarted /\ status = UserBroadcastPeginPrepare /\ t = tpb
    /\ status' = Presigned /\ stepH' = h
    /\ UNCHANGED <<params, h, t, cursor, txidsKnown, btcHeight, graphsStarted, signedAt, minted>>

\* Action: the committee's Confirm round signs through the T0 gate and the
\* Confirm is broadcast and confirmed. Gate and signature are one step here
\* (the race between them: InstanceLifecycle.tla).
\* Source: pegin_confirm_sign() in node/src/aggregates/instance_jobs.rs:659
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900
\* Source: signing_gate_for() in node/src/aggregates/instance.rs:602
ConfirmDone ==
    /\ status = Presigned /\ GateOpen /\ t = tpb
    /\ status' = RelayerL1Broadcasted
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<params, h, t, cursor, txidsKnown, btcHeight, graphsStarted, stepH, minted>>

\* Action: the relayer posts the peg-in data and Goat mints.
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:984
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
Mint ==
    /\ status = RelayerL1Broadcasted
    /\ status' = RelayerL2Minted /\ minted' = TRUE
    /\ UNCHANGED <<params, h, t, cursor, txidsKnown, btcHeight, graphsStarted, stepH, signedAt>>

Next ==
    \/ ScanTick
    \/ ScanTickNoHeight
    \/ NewBlock
    \/ GraphEndorsed
    \/ ConfirmDone
    \/ Mint

\* A scan tick that reaches the confirmed Prepare with its height.
DetectWithHeight ==
    ScanTick /\ Covered /\ status = CommitteesAnswered /\ PrepareOnChain

\* Fairness: the scan keeps ticking and blocks keep coming; the backend does
\* not omit the height forever (SF); the engine retries the Confirm round and
\* the post job until done; graphs are endorsed only by honest operators.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(ScanTick) /\ WF_vars(NewBlock) /\ SF_vars(DetectWithHeight)
    /\ WF_vars(ConfirmDone) /\ WF_vars(Mint)
    /\ (OperatorsHonest => WF_vars(GraphEndorsed))

--------------------------------------------------------------------------
(* Safety invariants *)

\* No Peg-In-Confirm signature at or after the true H_p + T0.
NoSignatureAtOrAfterT0 == \A x \in signedAt : x < Hp + t0

(* Liveness *)

\* The genuine peg-in ends minted.
GenuinePeginProgresses == <>(status = RelayerL2Minted)

\* Every instance reaches a terminal status.
NoStuckInstance == <>(status \in Terminal)

====
