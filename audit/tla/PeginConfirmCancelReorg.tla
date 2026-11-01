---- MODULE PeginConfirmCancelReorg ----
(***************************************************************************)
(* PURPOSE. H6: Peg-In-Confirm vs Peg-In-Cancel across a Bitcoin reorg -   *)
(* the user gets the BTC refund AND pegBTC ("unbacked mint").              *)
(*                                                                         *)
(* CODE SCOPE (dev 60562f8, after #476):                                   *)
(*  connector_z (goat bab46c2, src/connectors/connector_z.rs:38-52): leaf  *)
(*    0 = n-of-n (Peg-In-Confirm), leaf 1 = user key + CSV T0 (Peg-In-     *)
(*    Cancel). Both spend the Peg-In-Prepare output, so they conflict.     *)
(*    BIP68: the Cancel is valid in a block of height >= H_p + T0 and      *)
(*    enters mempools at tip H_p + T0 - 1. T0 = ConnectorZ (crates/bitvm-  *)
(*    gc/src/timelocks.rs default_timelock_config).                        *)
(*  node/src/aggregates/instance.rs:189-191 signing_open: open while tip   *)
(*    < H_p + T0. node/src/aggregates/instance_jobs.rs:875-893             *)
(*    pegin_confirm_broadcast_blocked: the relayer broadcasts while tip <  *)
(*    H_p + T0 and no Cancel is CONFIRMED - a Confirm broadcast at tip     *)
(*    H_p+T0-1 competes with the Cancel for block H_p+T0 (the one-block    *)
(*    overlap, constant GateOverlap).                                      *)
(*  instance.rs:442-527 decide_btc_snapshot: a confirmed Confirm moves     *)
(*    UserBroadcastPeginPrepare | Presigned to RelayerL1Broadcasted        *)
(*    (490-493); nothing moves it back. instance.rs:773-797 on_entered     *)
(*    enqueues JOB_POST_PEGIN_DATA on the relayer.                         *)
(*  instance_jobs.rs:984-1040 post_pegin_data: posts once                  *)
(*    get_tx_status(..).block_height is Some (ONE confirmation) and        *)
(*    spv_height >= pegin_height - no depth of its own (postConf = 1; the  *)
(*    SPV check alone makes it wait spvLag + 1 confirmations).             *)
(*  crates/client/src/goat_chain/mod.rs:424-471 gateway_post_pegin_data:   *)
(*    bails if the SPV hash at the proof height differs (or, with          *)
(*    ENABLE_UPDATE_SPV_CONTRACT, overwrites it with the posting node's    *)
(*    own view - not modeled).                                             *)
(*  Gateway.sol postPeginData -> _verifyMerkleInclusion: only              *)
(*    bitcoinSPV.blockHash(proof.height) == blockHash; no depth, no PoW,   *)
(*    no latestHeight check. onlyCommittee: ANY committee member holding   *)
(*    the gossiped endorsements (PeginConfirmPartialSig carries            *)
(*    endorse_sig, instance_jobs.rs:765-776) may post.                     *)
(*  node/src/scheduled_tasks/spv_maintenance_tasks.rs:9-40                 *)
(*    spv_header_hash_update (ENABLE_UPDATE_SPV_CONTRACT): records heights *)
(*    last+1..tip-k, k = BTC_BLOCK_CONFIRMS (crates/util/src/lib.rs:13-21  *)
(*    = BtcBlockConfirms: 6/10/6/1; env override node/src/env.rs:277-282). *)
(*    It only appends: a hash recorded before a reorg is never rewritten.  *)
(*    The production GOAT BitcoinSPV may be fed by another writer with a   *)
(*    different lag; spvLag = 0 models a feeder that records the tip.      *)
(*                                                                         *)
(* MODEL. One instance past Presigned; Prepare fixed at height Hp (never   *)
(* reorged). The chain holds at most one of Confirm/Cancel. One reorg of   *)
(* depth 1..maxReorg replaces the top blocks by a one-block-longer branch  *)
(* that may carry the Cancel instead of the Confirm (user + one miner).    *)
(* SPV records a height once it is spvLag blocks below the tip (or later); *)
(* entries above a later fork point turn stale and stay. Relayer, user,    *)
(* miners and the SPV writer act in any order with any delay - no "acts    *)
(* before the next block" assumption.                                      *)
(*                                                                         *)
(* PARAMETERS (frozen variables, chosen once in Init): t0 (connector_z     *)
(* CSV), spvLag, postConf (honest post depth), maxReorg (deepest reorg).   *)
(* Generic sweep (NetSet = {}): each from its *Range constant. Shipped     *)
(* (NetSet # {}): net \in NetSet, t0 = ConnectorZ[net], postConf = 1 (the  *)
(* code), spvLag = BtcBlockConfirms[net] (SpvFeeder = "node") or 0         *)
(* ("tip"); maxReorg = max(1, EvidenceConfirmations[net]) (ReorgBound =    *)
(* "evidence": the protocol's own depth before Bitcoin evidence is used)   *)
(* or BtcBlockConfirms[net] + 1 ("spv+1").                                 *)
(*                                                                         *)
(* EXHAUSTIVENESS. The guards compare d (1..maxReorg) with spvLag+1 (a     *)
(* recorded block is spvLag+1 deep) and with postConf, and the tip with    *)
(* H_p+T0. With spvLag \in 0..3, postConf \in 1..4, maxReorg \in 1..4     *)
(* every weak ordering of {spvLag+1, postConf, maxReorg} occurs, with ties *)
(* and margins 0 and 1. T0 only matters through the window clip below:     *)
(* every T0 >= 2*maxReorg + 3 gives a translate, so T0 \in 1..11 covers    *)
(* every class.                                                            *)
(*                                                                         *)
(* WINDOW (time abstracted by events, so a real T0 = 144 stays small). The *)
(* model starts at tip h0 = max(Hp, H_p+T0-maxReorg-2), SPV caught up,     *)
(* nothing broadcast, and stops at H_p+T0+maxReorg+3. A violation needs a  *)
(* Confirm mined at some x that a reorg at tip r removes (r-d < x <= r)    *)
(* and a Cancel at a height >= H_p+T0. Blocks before x and after the       *)
(* broadcast are idle (the Confirm waits in a mempool), so idle blocks can *)
(* be inserted or removed there until r >= H_p+T0-1 (then x >= H_p+T0-     *)
(* maxReorg > h0, and the broadcast moves to h0, where the gate is still   *)
(* open since h0 <= H_p+T0-2) and r <= H_p+T0+maxReorg (the Cancel then    *)
(* lands by H_p+T0+maxReorg+2). SPV entries below x - maxReorg are never   *)
(* stale and hold no Confirm, so the SPV start value only shifts when the  *)
(* writer may first record x.                                              *)
(*                                                                         *)
(* FIX DESIGN. The depth of any header the mint can use must exceed every  *)
(* reorg: ParamsOK. With a colluding poster (ByzPoster) only the SPV depth *)
(* counts (ByzOk); for the honest relayer alone its own wait counts too    *)
(* (HonestOk). Both EXACT: checked point by point (336 points), and the    *)
(* Boundary cfg fails.                                                     *)
(*                                                                         *)
(* CONFIGS -> TIERS (audit/tla/specs.txt):                                 *)
(*   live     PeginConfirmCancelReorg.cfg (tip feeder sweep),              *)
(*            PeginConfirmCancelReorgNodeSpv.cfg (node writer k 1..3),     *)
(*            PeginConfirmCancelReorgShipped.cfg (tip feeder, shipped)     *)
(*   design   PeginConfirmCancelReorgFixed.cfg (ParamsOK sweep),           *)
(*            PeginConfirmCancelReorgFixedShipped.cfg (node writer at the  *)
(*            shipped k, reorgs <= evidence depth)                         *)
(*   boundary PeginConfirmCancelReorgFixedBoundary.cfg (~ParamsOK sweep),  *)
(*            PeginConfirmCancelReorgNodeSpvShipped.cfg (shipped k, d=k+1) *)
(*   not in specs.txt (insufficient fixes, must fail):                     *)
(*            PeginConfirmCancelReorgGateOnly.cfg, ...PostWaitOnly.cfg     *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    NetSet,          \* {} = generic sweep, else the networks whose shipped values to use
    T0Range,         \* generic sweep: connector_z CSV values
    SpvLagRange,     \* generic sweep: SPV writer lag values
    PostConfRange,   \* generic sweep: honest post depth values
    MaxReorgRange,   \* generic sweep: reorg depth bounds
    SpvFeeder,       \* shipped: "node" (spvLag = BtcBlockConfirms) | "tip" (spvLag = 0)
    ReorgBound,      \* shipped: "evidence" (max(1, EvidenceConfirmations)) | "spv+1"
    ParamFilter,     \* "all" | "ok" (ParamsOK) | "notok" | "honestOnly" (HonestOk /\ ~ByzOk)
    GateOverlap,     \* 1 = current gate (broadcast while tip < Hp+T0); 0 = closes one block earlier
    ByzPoster        \* a colluding committee member may post with any header SPV holds

ASSUME /\ NetSet \subseteq Networks
       /\ GateOverlap \in {0, 1}
       /\ SpvFeeder \in {"node", "tip"} /\ ReorgBound \in {"evidence", "spv+1"}
       /\ ParamFilter \in {"all", "ok", "notok", "honestOnly"}
       /\ SpvLagRange \subseteq Nat
       /\ T0Range \cup PostConfRange \cup MaxReorgRange \subseteq Nat \ {0}

\* Relayer-node instance statuses (InstanceBridgeInStatus).
Presigned            == "Presigned"
RelayerL1Broadcasted == "RelayerL1Broadcasted"
UserCanceled         == "UserCanceled"
Statuses == {Presigned, RelayerL1Broadcasted, UserCanceled}

Hp == 1                  \* Peg-In-Prepare height (only differences matter)
Generic == "generic"     \* net value of a generic-sweep run
Max(a, b) == IF a >= b THEN a ELSE b

VARIABLES
    net,           \* frozen: network whose shipped values are used (Generic in a sweep)
    t0,            \* frozen: connector_z CSV
    spvLag,        \* frozen: SPV records height x only once tip >= x + spvLag
    postConf,      \* frozen: confirmations the honest relayer's post waits
    maxReorg,      \* frozen: deepest reorg the adversary can produce
    h,             \* Bitcoin tip
    confirmAt,     \* height of Peg-In-Confirm in the current chain, 0 if none
    cancelAt,      \* height of Peg-In-Cancel in the current chain, 0 if none
    memConfirm,    \* Confirm in some mempool
    memCancel,     \* Cancel in some mempool
    spvTop,        \* highest height recorded by the SPV contract
    spvStaleFrom,  \* lowest stale SPV height (NoStale if none)
    spvHasConfirm, \* SPV recorded (current or stale) a header whose block holds the Confirm
    status,        \* the relayer node's instance status
    minted,        \* Gateway.postPeginData minted pegBTC
    reorged        \* the one reorg happened

params == <<net, t0, spvLag, postConf, maxReorg>>
vars == <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
          spvStaleFrom, spvHasConfirm, status, minted, reorged>>

CancelFrom == Hp + t0                        \* first block that may hold the Cancel
GateOpen == h < Hp + t0 - (1 - GateOverlap)  \* signing_open / broadcast gate
H0 == Max(Hp, CancelFrom - maxReorg - 2)     \* window start (see header)
MaxH == CancelFrom + maxReorg + 3            \* window end (see header)
NoStale == MaxH + 1

\* The fix designs' margins.
ByzOk == spvLag >= maxReorg                       \* SPV depth alone beats every reorg
HonestOk == Max(spvLag, postConf - 1) >= maxReorg \* honest relayer: SPV or its own wait
ParamsOK == IF ByzPoster THEN ByzOk ELSE HonestOk

ShippedParams(n) ==
    /\ t0 = ConnectorZ[n]
    /\ postConf = 1
    /\ spvLag = IF SpvFeeder = "node" THEN BtcBlockConfirms[n] ELSE 0
    /\ maxReorg = IF ReorgBound = "evidence" THEN Max(1, EvidenceConfirmations[n])
                  ELSE BtcBlockConfirms[n] + 1

InitParams ==
    /\ IF NetSet = {}
          THEN /\ net = Generic
               /\ t0 \in T0Range /\ spvLag \in SpvLagRange
               /\ postConf \in PostConfRange /\ maxReorg \in MaxReorgRange
          ELSE /\ net \in NetSet /\ ShippedParams(net)
    /\ CASE ParamFilter = "all"   -> TRUE
         [] ParamFilter = "ok"    -> ParamsOK
         [] ParamFilter = "notok" -> ~ParamsOK
         [] OTHER                 -> HonestOk /\ ~ByzOk

TypeOk ==
    /\ net \in NetSet \cup {Generic}
    /\ t0 \in Nat \ {0} /\ spvLag \in Nat /\ postConf \in Nat \ {0} /\ maxReorg \in Nat \ {0}
    /\ h \in H0..MaxH
    /\ confirmAt \in 0..MaxH /\ cancelAt \in 0..MaxH
    /\ ~(confirmAt > 0 /\ cancelAt > 0)
    /\ memConfirm \in BOOLEAN /\ memCancel \in BOOLEAN
    /\ spvTop \in Hp..MaxH /\ spvStaleFrom \in 1..NoStale
    /\ spvHasConfirm \in BOOLEAN
    /\ status \in Statuses
    /\ minted \in BOOLEAN /\ reorged \in BOOLEAN

Init ==
    /\ InitParams
    /\ h = H0
    /\ confirmAt = 0 /\ cancelAt = 0
    /\ memConfirm = FALSE /\ memCancel = FALSE
    /\ spvTop = Max(Hp, H0 - spvLag) /\ spvStaleFrom = NoStale /\ spvHasConfirm = FALSE
    /\ status = Presigned
    /\ minted = FALSE /\ reorged = FALSE

--------------------------------------------------------------------------
(* Actions *)

\* Action: the relayer aggregates the committee's partial signatures and
\*   broadcasts the Peg-In-Confirm while the T0 gate is open and neither tx is
\*   on chain; the tx then sits in mempools until mined.
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900;
\*   pegin_confirm_broadcast_blocked() instance_jobs.rs:875;
\*   signing_open() node/src/aggregates/instance.rs:189
Broadcast ==
    /\ status = Presigned /\ GateOpen
    /\ confirmAt = 0 /\ cancelAt = 0 /\ ~memConfirm
    /\ memConfirm' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memCancel, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

\* Action: the user broadcasts the Peg-In-Cancel; mempools accept it once the
\*   NEXT block satisfies the CSV (BIP68).
\* Source: environment (user); connector_z leaf 1 (goat src/connectors/connector_z.rs:38-52);
\*   Bitcoin consensus (BIP68)
UserCancel ==
    /\ h + 1 >= CancelFrom /\ cancelAt = 0 /\ confirmAt = 0 /\ ~memCancel
    /\ memCancel' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

\* Action: a new block extends the chain, carrying the Confirm, the Cancel
\*   (if CSV-valid), or neither; the two conflict.
\* Source: Bitcoin consensus
Mine ==
    /\ h < MaxH
    /\ h' = h + 1
    /\ \/ /\ memConfirm /\ confirmAt = 0 /\ cancelAt = 0
          /\ confirmAt' = h + 1 /\ memConfirm' = FALSE /\ memCancel' = FALSE
          /\ UNCHANGED cancelAt
       \/ /\ memCancel /\ cancelAt = 0 /\ confirmAt = 0 /\ h + 1 >= CancelFrom
          /\ cancelAt' = h + 1 /\ memCancel' = FALSE /\ memConfirm' = FALSE
          /\ UNCHANGED confirmAt
       \/ UNCHANGED <<confirmAt, cancelAt, memConfirm, memCancel>>
    /\ UNCHANGED <<params, spvTop, spvStaleFrom, spvHasConfirm, status, minted, reorged>>

\* Action: the SPV writer appends height spvTop+1 (the hash of the current
\*   chain) once it is spvLag blocks below the tip; never rewrites.
\* Source: spv_header_hash_update() in node/src/scheduled_tasks/spv_maintenance_tasks.rs:9-40
SpvRecord ==
    /\ spvTop + 1 + spvLag <= h
    /\ spvTop' = spvTop + 1
    /\ spvHasConfirm' = (spvHasConfirm \/ (confirmAt > 0 /\ confirmAt = spvTop + 1))
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvStaleFrom,
                   status, minted, reorged>>

\* Action: one reorg of depth d replaces the blocks above f = h - d by
\*   f+1..h+1; the new branch may carry the Cancel at a CSV-valid height, the
\*   Confirm again, or neither. SPV entries above f stay, now stale.
\* Source: environment (Bitcoin reorg by a miner, possibly colluding with the user)
Reorg ==
    /\ ~reorged /\ h < MaxH
    /\ \E d \in 1..maxReorg :
        LET f == h - d IN
        /\ f >= Hp
        /\ LET cf == IF confirmAt > f THEN 0 ELSE confirmAt
               cc == IF cancelAt > f THEN 0 ELSE cancelAt
           IN \/ /\ cf = 0 /\ cc = 0
                 /\ \E y \in (f + 1)..(h + 1) :
                        y >= CancelFrom /\ cancelAt' = y /\ confirmAt' = 0
                 /\ memConfirm' = FALSE /\ memCancel' = FALSE
              \/ /\ cf = 0 /\ cc = 0
                 /\ \E y \in (f + 1)..(h + 1) : confirmAt' = y /\ cancelAt' = 0
                 /\ memConfirm' = FALSE /\ memCancel' = FALSE
              \/ /\ confirmAt' = cf /\ cancelAt' = cc
                 /\ memConfirm' = (memConfirm \/ (confirmAt > f))
                 /\ memCancel' = (memCancel \/ (cancelAt > f))
        /\ spvStaleFrom' = IF spvTop > f /\ f + 1 < spvStaleFrom THEN f + 1 ELSE spvStaleFrom
    /\ h' = h + 1
    /\ reorged' = TRUE
    /\ UNCHANGED <<params, spvTop, spvHasConfirm, status, minted>>

\* Action: the relayer's Bitcoin scan moves the instance on a confirmed
\*   Confirm (RelayerL1Broadcasted) or Cancel (UserCanceled); L1 never regresses.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442 (step 2, 490-496)
Scan ==
    /\ status = Presigned
    /\ \/ confirmAt > 0 /\ status' = RelayerL1Broadcasted
       \/ confirmAt = 0 /\ cancelAt > 0 /\ status' = UserCanceled
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, minted, reorged>>

SpvCurrent(x) == x <= spvTop /\ x < spvStaleFrom

\* Action: the honest relayer posts the Confirm: confirmed in its backend
\*   (current chain), SPV covers the block and holds ITS hash, postConf deep.
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:984 (1020-1031);
\*   gateway_post_pegin_data() crates/client/src/goat_chain/mod.rs:424-471;
\*   Gateway.sol postPeginData
HonestPost ==
    /\ status = RelayerL1Broadcasted /\ ~minted
    /\ confirmAt > 0 /\ SpvCurrent(confirmAt)
    /\ h - confirmAt + 1 >= postConf
    /\ minted' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, status, reorged>>

\* Action: a colluding committee member posts the Confirm with any header
\*   the SPV holds - possibly stale; the contract checks nothing else.
\* Source: environment (Byzantine committee member); Gateway.sol postPeginData /
\*   _verifyMerkleInclusion (onlyCommittee, blockHash match only)
ByzPost ==
    /\ ByzPoster /\ ~minted /\ spvHasConfirm
    /\ minted' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, status, reorged>>

Next ==
    \/ Broadcast
    \/ UserCancel
    \/ Mine
    \/ SpvRecord
    \/ Reorg
    \/ Scan
    \/ HonestPost
    \/ ByzPost

\* Safety only: no fairness needed.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* The user never holds both the refund (Cancel on chain) and pegBTC.
NoUnbackedMint == ~(minted /\ cancelAt > 0)

(* Safety properties *)

\* The relayer's instance never leaves RelayerL1Broadcasted.
RelayerL1NeverRegresses ==
    [][status = RelayerL1Broadcasted => status' = RelayerL1Broadcasted]_vars

(* Liveness: none (the finding is a safety violation). *)

====
