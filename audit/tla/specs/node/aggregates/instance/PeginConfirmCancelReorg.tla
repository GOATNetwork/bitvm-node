---- MODULE PeginConfirmCancelReorg ----
(***************************************************************************)
(* H6: Peg-In-Confirm vs Peg-In-Cancel across a Bitcoin reorg. Both spend  *)
(* the Prepare output (connector_z leaf 0 n-of-n, leaf 1 user + CSV T0).   *)
(* The relayer posts once the Confirm has one confirmation and the GOAT    *)
(* SPV covers its block; Gateway.sol postPeginData only checks that the    *)
(* SPV hash at the proof height matches (no depth). SPV entries stay after *)
(* a reorg (the node writer only appends; a relay rewrite may come after   *)
(* the post). A reorg that swaps the Confirm block for a Cancel block      *)
(* gives the user the refund and pegBTC (NoUnbackedMint).                  *)
(* SPV feeders: a separate header relay syncs Bitcoin headers to the SPV   *)
(*   contract, and the contract does not enforce their depth: spvLag = 0   *)
(*   ("tip" rows). The node's own writer records up to tip -               *)
(*   BTC_BLOCK_CONFIRMS: spvLag = k ("node" rows).                         *)
(* Parameters (frozen variables): t0; spvLag (SPV records x once tip >=    *)
(*   x + spvLag); postConf (honest post depth, 1 in the code); maxReorg.   *)
(*   NetSet = {}: sweep the *Range constants, else ShippedParams.          *)
(*   GateOverlap 1 = the code (broadcast while tip < H_p + T0), 0 = one    *)
(*   block earlier. ByzPoster: a colluding member posts with any SPV       *)
(*   header.                                                               *)
(* Fix: every header the mint can use is deeper than any reorg. ParamsOK = *)
(*   ByzOk with ByzPoster, else HonestOk; both exact.                      *)
(* Exhaustiveness: the guards compare the reorg depth with spvLag + 1 and  *)
(*   postConf, and the tip with H_p + T0. spvLag 0..3, postConf 1..4,      *)
(*   maxReorg 1..4 give every order with margins 0 and 1. The window       *)
(*   H0..MaxH holds every violation up to translation and T0 >= 2*maxReorg *)
(*   + 3 is a translate, so T0 1..11 covers every T0.                      *)
(* Not modeled: gateway_post_pegin_data's SPV overwrite (UPDATE_SPV flag). *)
(* Configs: configs/node/aggregates/instance/PeginConfirmCancelReorg/,     *)
(*   tiers in audit/tla/checks.txt.                                        *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    NetSet,          \* {} = generic sweep, else the networks whose shipped values to use
    T0Range,         \* generic sweep: connector_z CSV values
    SpvLagRange,     \* generic sweep: SPV feeder lag values
    PostConfRange,   \* generic sweep: honest post depth values
    MaxReorgRange,   \* generic sweep: reorg depth bounds
    SpvFeeder,       \* shipped: "node" (node writer, spvLag = BtcBlockConfirms) | "tip" (header relay, 0)
    ReorgBound,      \* shipped maxReorg: "evidence" (max(1, EvidenceConfirmations)) | "spv+1"
    ParamFilter,     \* "all" | "ok" (ParamsOK) | "notok" | "honestOnly" (HonestOk /\ ~ByzOk)
    GateOverlap,     \* 1 = the code (broadcast while tip < H_p + T0); 0 = closes one block earlier
    ByzPoster        \* a colluding committee member may post with any header the SPV holds

ASSUME /\ NetSet \subseteq Networks
       /\ GateOverlap \in {0, 1}
       /\ SpvFeeder \in {"node", "tip"} /\ ReorgBound \in {"evidence", "spv+1"}
       /\ ParamFilter \in {"all", "ok", "notok", "honestOnly"}
       /\ SpvLagRange \subseteq Nat
       /\ T0Range \cup PostConfRange \cup MaxReorgRange \subseteq Nat \ {0}

\* The relayer node's instance statuses (InstanceBridgeInStatus).
Presigned            == "Presigned"
RelayerL1Broadcasted == "RelayerL1Broadcasted"
UserCanceled         == "UserCanceled"
Statuses == {Presigned, RelayerL1Broadcasted, UserCanceled}

Hp == 1                  \* Peg-In-Prepare height (only differences matter; never reorged)
Generic == "generic"     \* net value of a generic-sweep run
Max(a, b) == IF a >= b THEN a ELSE b

VARIABLES
    net,           \* frozen: network whose shipped values are used (Generic in a sweep)
    t0,            \* frozen: connector_z CSV
    spvLag,        \* frozen: the SPV records height x only once tip >= x + spvLag
    postConf,      \* frozen: confirmations the honest relayer's post waits
    maxReorg,      \* frozen: deepest reorg the adversary can produce
    h,             \* Bitcoin tip
    confirmAt,     \* height of Peg-In-Confirm in the current chain, 0 if none
    cancelAt,      \* height of Peg-In-Cancel in the current chain, 0 if none
    memConfirm,    \* Confirm in some mempool
    memCancel,     \* Cancel in some mempool
    spvTop,        \* highest height the SPV contract records
    spvStaleFrom,  \* lowest SPV height whose hash a reorg replaced (NoStale if none)
    spvHasConfirm, \* the SPV holds (current or stale) the hash of a block with the Confirm
    status,        \* the relayer node's instance status
    minted,        \* Gateway.postPeginData minted pegBTC
    reorged        \* the one reorg happened

params == <<net, t0, spvLag, postConf, maxReorg>>
vars == <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
          spvStaleFrom, spvHasConfirm, status, minted, reorged>>

CancelFrom == Hp + t0                        \* first block that may hold the Cancel
GateOpen == h < Hp + t0 - (1 - GateOverlap)  \* signing / broadcast gate (signing_gate_for)
\* Window: a violation needs a Confirm block that a reorg of depth <= maxReorg
\* removes and a Cancel at >= H_p + T0; idle blocks outside this window can
\* be dropped (the Confirm waits in a mempool), so every violation fits.
H0 == Max(Hp, CancelFrom - maxReorg - 2)     \* first tip
MaxH == CancelFrom + maxReorg + 3            \* last tip
NoStale == MaxH + 1                          \* spvStaleFrom when nothing is stale

ByzOk == spvLag >= maxReorg                       \* the SPV depth alone beats every reorg
HonestOk == Max(spvLag, postConf - 1) >= maxReorg \* honest relayer: the SPV depth or its own wait
ParamsOK == IF ByzPoster THEN ByzOk ELSE HonestOk

\* Shipped values of network n (ShippedTimelockValues).
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

\* Action: the relayer broadcasts the aggregated Peg-In-Confirm while the
\* gate is open and neither tx is on chain; it waits in mempools until mined.
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900-960
\* Source: pegin_confirm_broadcast_blocked() in instance_jobs.rs:875-893
\* Source: signing_gate_for() in node/src/aggregates/instance.rs:602-617
Broadcast ==
    /\ status = Presigned /\ GateOpen
    /\ confirmAt = 0 /\ cancelAt = 0 /\ ~memConfirm
    /\ memConfirm' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memCancel, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

\* Action: the user broadcasts the Peg-In-Cancel; mempools accept it once the
\* next block satisfies the CSV (BIP68).
\* Source: environment (user); connector_z leaf 1, BitVM goat/src/connectors/connector_z.rs:46-52
UserCancel ==
    /\ h + 1 >= CancelFrom /\ cancelAt = 0 /\ confirmAt = 0 /\ ~memCancel
    /\ memCancel' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

\* Action: a new block carrying the Confirm, the CSV-valid Cancel, or neither.
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

\* Action: an SPV feeder appends height spvTop + 1 (current-chain hash) once it
\* is spvLag blocks below the tip; recorded heights stay after a reorg.
\* Source: spv_header_hash_update() in node/src/scheduled_tasks/spv_maintenance_tasks.rs:9-39 (node writer)
\* Source: environment (separate header relay, spvLag = 0)
SpvRecord ==
    /\ spvTop + 1 + spvLag <= h
    /\ spvTop' = spvTop + 1
    /\ spvHasConfirm' = (spvHasConfirm \/ (confirmAt > 0 /\ confirmAt = spvTop + 1))
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvStaleFrom,
                   status, minted, reorged>>

\* Action: one reorg of depth d replaces the blocks above f = h - d by
\* f+1..h+1, carrying the CSV-valid Cancel, the Confirm, or neither; SPV
\* entries above f stay and are now stale.
\* Source: environment (miner, possibly colluding with the user)
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

\* Action: the relayer's scan: confirmed Confirm -> RelayerL1Broadcasted,
\* confirmed Cancel -> UserCanceled.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:489-493
Scan ==
    /\ status = Presigned
    /\ \/ confirmAt > 0 /\ status' = RelayerL1Broadcasted
       \/ confirmAt = 0 /\ cancelAt > 0 /\ status' = UserCanceled
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, minted, reorged>>

\* The SPV holds the current-chain hash of height x.
SpvCurrent(x) == x <= spvTop /\ x < spvStaleFrom

\* Action: the honest relayer posts: the Confirm is confirmed postConf deep in
\* its backend and the SPV holds the current hash of its block.
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:1020-1031
\* Source: gateway_post_pegin_data() in crates/client/src/goat_chain/mod.rs:447-471
\* Source: Gateway.sol postPeginData
HonestPost ==
    /\ status = RelayerL1Broadcasted /\ ~minted
    /\ confirmAt > 0 /\ SpvCurrent(confirmAt)
    /\ h - confirmAt + 1 >= postConf
    /\ minted' = TRUE
    /\ UNCHANGED <<params, h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, status, reorged>>

\* Action: a colluding committee member (it holds the gossiped endorsements)
\* posts with any header the SPV holds, also a stale one.
\* Source: environment (Byzantine committee member)
\* Source: Gateway.sol postPeginData / _verifyMerkleInclusion (onlyCommittee, blockHash match only)
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

\* Safety only: no fairness.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* The user never holds both the refund (Cancel on chain) and pegBTC.
NoUnbackedMint == ~(minted /\ cancelAt > 0)

(* Safety properties *)

\* The relayer's instance never leaves RelayerL1Broadcasted.
RelayerL1NeverRegresses ==
    [][status = RelayerL1Broadcasted => status' = RelayerL1Broadcasted]_vars

====
