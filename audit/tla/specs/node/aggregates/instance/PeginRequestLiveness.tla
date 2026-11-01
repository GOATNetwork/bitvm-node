---- MODULE PeginRequestLiveness ----
(***************************************************************************)
(* PURPOSE. Low-severity liveness of a genuine peg-in (one module, one cfg *)
(* pair per finding). Code at dev 60562f8 (after #476).                    *)
(*                                                                         *)
(* F1 - free spam requests starve the Bitcoin scan.                         *)
(*   Gateway.sol postPeginRequest: "TODO: check peginAmount, feeRate,      *)
(*   userInputs / TODO: charge fee". node/src/utils/goat_chain.rs:142-188  *)
(*   read_pegin_request only checks each input is UNSPENT (not owned, not  *)
(*   unique), so committee nodes answer requests built on anyone's UTXOs   *)
(*   (node/src/aggregates/instance_jobs.rs:245-272 answer_pegin_request).  *)
(*   node/src/aggregates/instance.rs:478-487 + instance_scan.rs:285-310:   *)
(*   CommitteesAnswered has no deadline - it only leaves on a confirmed    *)
(*   Prepare or a spent input. node/src/aggregates/instance_scan.rs:67-107 *)
(*   find_one_instance_page + 192-218 scan_instances_on_bitcoin: the       *)
(*   Bitcoin scan pages INSTANCE_MAINTENANCE_BATCH_SIZE (node/src/env.rs:  *)
(*   128-129, 50) rows per maintenance tick (env.rs:126, every 20 s + run  *)
(*   time), in created_at order (keyset cursor; a short or empty page      *)
(*   resets), over every CommitteesAnswered/UserBroadcastPeginPrepare/     *)
(*   Presigned/Timeout row. instance_jobs.rs:278-296 graph_start_blocked:  *)
(*   no graph once tip > H_p + OPERATOR_GRAPH_START_CUTOFF_BLOCKS (env.rs: *)
(*   194-200, default 2/3 T0). Enough live spam rows delay the scan's      *)
(*   detection of the genuine Prepare past that cutoff: no graph, no       *)
(*   Presigned, Timeout.                                                   *)
(*                                                                         *)
(* F6 - one off-curve committee answer wedges the instance.                *)
(*   Gateway.sol answerPeginRequest checks length 33 and the parity byte   *)
(*   only; the 32-byte x is stored unchecked and counts toward quorum.     *)
(*   instance.rs:714-731 -> pegin_txids (instance.rs:1337) ->              *)
(*   node/src/utils/instance_store.rs:186-197 PublicKey::from_slice fails  *)
(*   -> warn!, no Prepare/Confirm/Cancel txids. instance_scan.rs:285-310:  *)
(*   without the Prepare txid nothing is queried -> CommitteesAnswered     *)
(*   forever (the user cannot build the n-of-n either). Refusing to answer *)
(*   would NOT block (quorum < committee); a malformed answer does.        *)
(*                                                                         *)
(* F7 - Prepare confirmed without a block height.                           *)
(*   instance.rs:481: prepare_height = prepare.block_height.unwrap_or(     *)
(*   prepare_height); prepare_height is instance.btc_height, created as 0   *)
(*   (instance_store.rs:92) and never set before this step, so a fact      *)
(*   {confirmed: true, block_height: None} stores btc_height = 0, and step *)
(*   1 never runs again (only UserInited | CommitteesAnswered).            *)
(*   cancel_from_height(0) = None (instance.rs:177-179): the T0 gate never *)
(*   closes and Timeout never fires; graph_start_blocked skips the cutoff  *)
(*   (instance_jobs.rs:288). REACHABILITY: tx_fact (instance_scan.rs:      *)
(*   257-266) maps esplora's TxStatus, the only real adaptor (crates/      *)
(*   client/src/btc_chain/esplora_bitcoin_adaptor.rs:94-96); Esplora       *)
(*   returns block_height whenever confirmed = true, so F7 needs a non-    *)
(*   conforming backend/proxy - a latent hardening issue, not a live bug.  *)
(*                                                                         *)
(* TIME is counted in maintenance ticks, tpb per block (tpb <=             *)
(* BlockIntervalSecs / 20). No hidden timing: the honest graph endorsement *)
(* (operators' setup + committee presign) completes within gd blocks of    *)
(* detection, the Peg-In-Confirm round within cd blocks of Presigned (if   *)
(* the T0 gate is still open); within those bounds the adversary schedules *)
(* them (at block boundaries: a step earlier in the same block changes no  *)
(* outcome, since the gate and the deadlines are per block and a Timeout   *)
(* needs tip >= H_p+T0+B where the gate is closed anyway). The mint has no *)
(* deadline (weak fairness); once the instance is RelayerL1Broadcasted or  *)
(* terminal the clock stops (no time-dependent behaviour is left).         *)
(*                                                                         *)
(* PARAMETERS (frozen variables): spam, batch, tpb (F1: live spam rows,    *)
(* page size, ticks per block); t0, b (CSV, abandon buffer; cutoff =       *)
(* 2*t0 \div 3, the env.rs:194-200 default); gd, cd (honest graph /        *)
(* Confirm-round delay bounds). Generic sweep (NetSet = {}): from the      *)
(* *Range constants. Shipped: t0 = ConnectorZ[net], b =                    *)
(* PeginAbandonBufferBlocks[net], tpb = BlockIntervalSecs[net] \div 20,    *)
(* batch = 50, and ShippedSpam = "attack": spam = batch*(cutoff+1)*tpb,    *)
(* gd = cd = 0 (the most favourable honest timing); "bounded": spam =      *)
(* batch*tpb - 1 (a fix bounding live spam to one block of scanning), gd = *)
(* cd = ReactionBlocks[net].                                               *)
(*                                                                         *)
(* F1 ARITHMETIC. A scan pass is P = (spam+1) \div batch + 1 ticks (full   *)
(* pages, then one short/empty page that resets); the genuine row is       *)
(* covered once per pass at an arbitrary phase, so it is detected at most  *)
(* D = (P-1) \div tpb blocks after the Prepare, and D is reachable. The     *)
(* genuine peg-in then succeeds iff D <= cutoff (graphs start) and          *)
(* D + gd + cd <= t0 - 1 (Confirm signed before T0): ParamsOK. EXACT       *)
(* (checked point by point, 480 points; the Boundary cfg fails).           *)
(* EXHAUSTIVENESS: the guards compare the detection tick with cutoff*tpb   *)
(* and the deadline heights with H_p+T0. spam 0..4, batch 1..2, tpb 1..2   *)
(* give P 1..6 and D 0..5; with t0 1..6 (cutoff 0..4) and gd, cd 0..1 every*)
(* class of D vs cutoff and of D+gd+cd vs t0-1 occurs, margins 0 and 1. B  *)
(* only delays the Timeout (any B >= 1 is one class).                      *)
(* F6 and F7 are NOT timing findings: an off-curve answer wedges the       *)
(* instance, and btc_height 0 disables the gate and Timeout, for EVERY     *)
(* value of these parameters; their configs sweep a small set to show it.  *)
(*                                                                         *)
(* CONFIGS -> TIERS (audit/tla/checks.txt):                                *)
(*   live     PeginRequestLiveness/Spam.cfg, ...SpamShipped.cfg (F1),       *)
(*            ...BadKey.cfg (F6), ...NoHeight.cfg, ...NoHeightGate.cfg (F7, *)
(*            latent: needs a non-conforming backend)                      *)
(*   design   ...SpamFixed.cfg, ...SpamFixedShipped.cfg, ...BadKeyFixed.cfg,*)
(*            ...NoHeightFixed.cfg                                         *)
(*   boundary ...SpamBoundary.cfg                                          *)
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
    ShippedSpam,        \* shipped: "attack" | "bounded"
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

\* Instance statuses (InstanceBridgeInStatus).
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
\* No time-dependent behaviour is left: the clock stops (a state-space cut
\* that changes no verdict).
Settled == Terminal \cup {RelayerL1Broadcasted}

Hp == 1                  \* Peg-In-Prepare height
Generic == "generic"     \* net value of a generic-sweep run
BatchShipped == 50       \* env.rs:129 DEFAULT_INSTANCE_MAINTENANCE_BATCH_SIZE
TaskIntervalSecs == 20   \* env.rs:126 REGULAR_TASK_INTERVAL_SECOND

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

Cutoff == (2 * t0) \div 3
Rows == spam + 1            \* the genuine row is the newest, index spam
MaxHeight == Hp + t0 + b
PassTicks == Rows \div batch + 1
ScanLag == (PassTicks - 1) \div tpb
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

\* The answer window closed with a quorum and the Prepare is in block Hp,
\* the current tip. With the on-curve check the malformed answer is
\* refused and the honest answers still make quorum.
Init ==
    /\ InitParams
    /\ h = Hp /\ t = 0
    /\ IF PhaseFixed THEN cursor = 0
       ELSE cursor \in {c \in 0..Rows : c % batch = 0}   \* the scan's phase is arbitrary
    /\ status = CommitteesAnswered
    /\ txidsKnown = (~BadKey \/ OnCurveCheck)
    /\ btcHeight = 0 /\ graphsStarted = FALSE /\ stepH = 0
    /\ signedAt = {} /\ minted = FALSE

PrepareOnChain == txidsKnown /\ h >= Hp
GateOpen == btcHeight = 0 \/ h < btcHeight + t0

Covered == cursor <= spam /\ spam < cursor + batch
NextCursor ==
    IF Rows - cursor >= batch THEN cursor + batch   \* full page: advance
    ELSE 0                                          \* short/empty page: reset

\* An honest step whose deadline is this block: the tip may not move on.
Due ==
    \/ OperatorsHonest /\ graphsStarted /\ status = UserBroadcastPeginPrepare
       /\ h >= stepH + gd
    \/ status = Presigned /\ GateOpen /\ h >= stepH + cd

\* One maintenance tick of block h (ticks 0..tpb-1): the page moves on.
Clock ==
    /\ status \notin Settled
    /\ t < tpb /\ t' = t + 1 /\ h' = h
    /\ cursor' = NextCursor

Detect(height) ==
    /\ status' = UserBroadcastPeginPrepare
    /\ btcHeight' = height
    /\ stepH' = h
    \* graph_start_blocked: cutoff only when btc_height > 0
    /\ graphsStarted' = (height = 0 \/ h <= height + Cutoff)

TimesOut ==
    status \in {UserBroadcastPeginPrepare, Presigned}
    /\ btcHeight > 0 /\ h >= btcHeight + t0 + b

--------------------------------------------------------------------------
(* Actions *)

\* Action: one maintenance tick of the Bitcoin scan: the current page; if it
\*   covers the genuine row, the confirmed Prepare is detected WITH its
\*   height (UserBroadcastPeginPrepare; operators start graphs if within the
\*   cutoff) or, past H_p+T0+B, the instance times out.
\* Source: scan_instances_on_bitcoin() in node/src/aggregates/instance_scan.rs:192;
\*   find_one_instance_page() instance_scan.rs:67; decide_btc_snapshot()
\*   node/src/aggregates/instance.rs:442 (478-503); graph_start_blocked()
\*   node/src/aggregates/instance_jobs.rs:278
ScanTick ==
    /\ Clock
    /\ IF Covered /\ status = CommitteesAnswered /\ PrepareOnChain
          THEN Detect(Hp)
       ELSE IF Covered /\ TimesOut
          THEN /\ status' = Timeout /\ UNCHANGED <<btcHeight, graphsStarted, stepH>>
       ELSE UNCHANGED <<status, btcHeight, graphsStarted, stepH>>
    /\ UNCHANGED <<params, txidsKnown, signedAt, minted>>

\* Action: F7 - a scan tick on which the backend reports the Prepare
\*   confirmed without a block height: current code stores btc_height 0
\*   (unwrap_or); the fix retries on the next pass.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:481;
\*   tx_fact() node/src/aggregates/instance_scan.rs:257; environment (non-conforming backend)
ScanTickNoHeight ==
    /\ NoHeight /\ Clock
    /\ Covered /\ status = CommitteesAnswered /\ PrepareOnChain
    /\ IF HeightRequired
          THEN UNCHANGED <<status, btcHeight, graphsStarted, stepH>>   \* retry next scan
          ELSE Detect(0)                                               \* unwrap_or(0)
    /\ UNCHANGED <<params, txidsKnown, signedAt, minted>>

\* Action: after the block's tpb ticks the next block arrives - unless an
\*   honest step is due in this block (then the step comes first).
\* Source: Bitcoin consensus
NewBlock ==
    /\ status \notin Settled /\ t = tpb /\ ~Due
    /\ t' = 0 /\ h' = IF h < MaxHeight THEN h + 1 ELSE h
    /\ UNCHANGED <<params, cursor, status, txidsKnown, btcHeight, graphsStarted,
                   stepH, signedAt, minted>>

\* Action: operators finish graph setup and the committee presigns:
\*   enough endorsed graphs move the instance to Presigned.
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550;
\*   confirm_instance() node/src/aggregates/instance_jobs.rs:300
GraphEndorsed ==
    /\ graphsStarted /\ status = UserBroadcastPeginPrepare /\ t = tpb
    /\ status' = Presigned /\ stepH' = h
    /\ UNCHANGED <<params, h, t, cursor, txidsKnown, btcHeight, graphsStarted, signedAt, minted>>

\* Action: the committee's Peg-In-Confirm round signs through the T0 gate;
\*   the Confirm is broadcast and confirmed.
\* Source: pegin_confirm_sign() in node/src/aggregates/instance_jobs.rs:659;
\*   broadcast_pegin_confirm() instance_jobs.rs:900; signing_open() instance.rs:189
ConfirmDone ==
    /\ status = Presigned /\ GateOpen /\ t = tpb
    /\ status' = RelayerL1Broadcasted
    /\ signedAt' = signedAt \cup {h}
    /\ UNCHANGED <<params, h, t, cursor, txidsKnown, btcHeight, graphsStarted, stepH, minted>>

\* Action: the relayer posts the peg-in data and Goat mints.
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:984;
\*   decide_l2_minted() instance.rs:561
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

\* Fairness: the maintenance loop keeps ticking (REGULAR_TASK_INTERVAL_SECOND)
\* and blocks keep coming (WF ScanTick, NewBlock); the backend does not omit
\* the height forever (SF over the passes that cover the row); the
\* committee's Confirm round and the relayer's post job are retried by the
\* engine until done (WF ConfirmDone, Mint); graphs are endorsed only if
\* the operators are honest (they may refuse).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(ScanTick) /\ WF_vars(NewBlock) /\ SF_vars(DetectWithHeight)
    /\ WF_vars(ConfirmDone) /\ WF_vars(Mint)
    /\ (OperatorsHonest => WF_vars(GraphEndorsed))

--------------------------------------------------------------------------
(* Safety invariants *)

\* The committee never signs Peg-In-Confirm at or after the TRUE H_p + T0
\* (where the user's Cancel is valid) - the T0 gate, as in InstanceLifecycle.tla.
NoSignatureAtOrAfterT0 == \A x \in signedAt : x < Hp + t0

(* Safety properties: none. *)

(* Liveness *)

\* An honest user's peg-in, with honest operators, ends minted.
GenuinePeginProgresses == <>(status = RelayerL2Minted)

\* Every instance reaches a terminal status.
NoStuckInstance == <>(status \in Terminal)

====
