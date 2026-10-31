---- MODULE PeginConfirmCancelReorg ----
(***************************************************************************)
(* H6: Peg-In-Confirm vs Peg-In-Cancel across a Bitcoin reorg - the user   *)
(* gets the BTC refund AND pegBTC ("unbacked mint").                       *)
(*                                                                         *)
(* Code at dev 60562f8 (after #476):                                       *)
(*                                                                         *)
(*  connector_z (goat bab46c2, src/connectors/connector_z.rs:38-52):       *)
(*    leaf 0 = n-of-n (Peg-In-Confirm), leaf 1 = user key + CSV            *)
(*    refund_blocks_timelock = T0 (Peg-In-Cancel). Both spend the same     *)
(*    Peg-In-Prepare output, so they conflict. BIP68: Cancel is valid in   *)
(*    a block of height >= H_p + T0 and so enters mempools at tip          *)
(*    H_p + T0 - 1.                                                        *)
(*                                                                         *)
(*  node/src/aggregates/instance.rs:189-191                                *)
(*    pub fn signing_open(&self, prepare_height, height) -> bool {         *)
(*        self.cancel_from_height(prepare_height).is_none_or(|t0| height < t0) } *)
(*  instance_jobs.rs:875-893 pegin_confirm_broadcast_blocked: the relayer  *)
(*    broadcasts while tip < H_p + T0 and no Cancel is CONFIRMED. A Confirm *)
(*    broadcast at tip H_p+T0-1 competes with the Cancel for block H_p+T0  *)
(*    (the one-block overlap, constant Overlap below).                     *)
(*                                                                         *)
(*  instance.rs:490-493 + 509-522: a confirmed Confirm moves the instance  *)
(*    to RelayerL1Broadcasted; nothing ever moves it back (step 2 only     *)
(*    runs for UserBroadcastPeginPrepare | Presigned). on_entered          *)
(*    (instance.rs:792-797) enqueues JOB_POST_PEGIN_DATA on the relayer.    *)
(*                                                                         *)
(*  instance_jobs.rs:1020-1031 post_pegin_data: posts as soon as           *)
(*    get_tx_status(..).block_height is Some (ONE confirmation) and        *)
(*    `spv_height >= pegin_height` - no depth of its own.                   *)
(*                                                                         *)
(*  Gateway.sol:199-211,358-394 postPeginData -> _verifyMerkleInclusion:   *)
(*    only `bitcoinSPV.blockHash(proof.height) == blockHash`; no depth,    *)
(*    no PoW, no latestHeight check. onlyCommittee: ANY committee member   *)
(*    holding the gossiped endorsements (PeginConfirmPartialSig carries    *)
(*    endorse_sig, instance_jobs.rs:765-776) may post.                     *)
(*                                                                         *)
(*  spv_maintenance_tasks.rs:14-31 (the node-side SPV writer, run when     *)
(*    ENABLE_UPDATE_SPV_CONTRACT): records heights last+1..tip-k with      *)
(*    k = BTC_BLOCK_CONFIRMS (util/src/lib.rs:13-21: 6 mainnet, 10 testnet,*)
(*    1 regtest; env-overridable, env.rs:277-282). It only appends: a hash *)
(*    recorded before a reorg is never rewritten (stale). (The only rewrite *)
(*    is goat_chain/mod.rs:449-471, which overwrites a mismatching height  *)
(*    with the POSTING relayer's own backend view - not modeled.)          *)
(*                                                                         *)
(* Model: one instance past Presigned; Prepare fixed at height Hp (never   *)
(* reorged). The chain holds at most one of Confirm/Cancel. One reorg of   *)
(* depth 1..MaxReorg replaces the top blocks by a one-block-longer branch  *)
(* that may carry the Cancel instead of the Confirm (user + one miner).    *)
(* SPV records a height once it is SpvLag blocks below the tip; entries    *)
(* above a later fork point turn stale and stay.                           *)
(*                                                                         *)
(* Unbacked mint needs a reorg deeper than SpvLag: a recorded block at x   *)
(* was recorded at tip >= x + SpvLag. With the node writer that is          *)
(* d >= BTC_BLOCK_CONFIRMS + 1; with an SPV feeder that records the tip    *)
(* (SpvLag = 0) d = 1 suffices. Nothing in the node or the contract ties   *)
(* the mint depth to the reorg bound - post_pegin_data's own wait is 0.    *)
(* The one-block overlap does NOT matter against an adversarial reorg (see *)
(* PeginConfirmCancelReorgGateOnly.cfg); it matters for a natural          *)
(* stale-block race, where both txs are valid for the same block.          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    T0,          \* connector_z CSV
    Hp,          \* Peg-In-Prepare height (fixed)
    Overlap,     \* 1 = current gate (broadcast while tip < Hp+T0); 0 = gate closes one block earlier
    SpvLag,      \* SPV records height x once tip >= x + SpvLag
    PostConf,    \* confirmations the honest relayer's post waits (current code: 1)
    MaxReorg,    \* maximum reorg depth
    ByzPoster,   \* a colluding committee member may post with any header SPV holds
    MaxHeight

ASSUME Overlap \in {0, 1} /\ PostConf >= 1 /\ MaxReorg >= 1 /\ Hp >= 1

VARIABLES
    h,             \* Bitcoin tip
    confirmAt,     \* height of Peg-In-Confirm in the current chain, 0 if none
    cancelAt,      \* height of Peg-In-Cancel in the current chain, 0 if none
    memConfirm,    \* Confirm in some mempool
    memCancel,     \* Cancel in some mempool
    spvTop,        \* highest height recorded by the SPV contract
    spvStaleFrom,  \* lowest stale SPV height (MaxHeight + 1 if none)
    spvHasConfirm, \* SPV recorded (current or stale) a header whose block holds the Confirm
    status,        \* the relayer node's instance status
    minted,        \* Gateway.postPeginData minted pegBTC
    reorged

vars == <<h, confirmAt, cancelAt, memConfirm, memCancel, spvTop, spvStaleFrom,
          spvHasConfirm, status, minted, reorged>>

NoStale == MaxHeight + 1
CancelFrom == Hp + T0                    \* first block that may hold the Cancel
GateOpen == h < Hp + T0 - (1 - Overlap)  \* signing_open / broadcast gate

TypeOK ==
    /\ h \in Hp..MaxHeight
    /\ confirmAt \in 0..MaxHeight /\ cancelAt \in 0..MaxHeight
    /\ ~(confirmAt > 0 /\ cancelAt > 0)
    /\ memConfirm \in BOOLEAN /\ memCancel \in BOOLEAN
    /\ spvTop \in Hp..MaxHeight /\ spvStaleFrom \in 1..NoStale
    /\ spvHasConfirm \in BOOLEAN
    /\ status \in {"Presigned", "RelayerL1Broadcasted", "UserCanceled"}
    /\ minted \in BOOLEAN /\ reorged \in BOOLEAN

Init ==
    /\ h = Hp
    /\ confirmAt = 0 /\ cancelAt = 0
    /\ memConfirm = FALSE /\ memCancel = FALSE
    /\ spvTop = Hp /\ spvStaleFrom = NoStale /\ spvHasConfirm = FALSE
    /\ status = "Presigned"
    /\ minted = FALSE /\ reorged = FALSE

--------------------------------------------------------------------------
(* Relayer broadcast of the aggregated Confirm (instance_jobs.rs:900-947). *)
Broadcast ==
    /\ status = "Presigned" /\ GateOpen
    /\ confirmAt = 0 /\ cancelAt = 0 /\ ~memConfirm
    /\ memConfirm' = TRUE
    /\ UNCHANGED <<h, confirmAt, cancelAt, memCancel, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

(* BIP68: the Cancel is accepted by mempools when the NEXT block satisfies the CSV. *)
UserCancel ==
    /\ h + 1 >= CancelFrom /\ cancelAt = 0 /\ confirmAt = 0 /\ ~memCancel
    /\ memCancel' = TRUE
    /\ UNCHANGED <<h, confirmAt, cancelAt, memConfirm, spvTop, spvStaleFrom,
                   spvHasConfirm, status, minted, reorged>>

(* A new block, carrying the Confirm, the Cancel (if CSV-valid), or neither. *)
Mine ==
    /\ h < MaxHeight
    /\ h' = h + 1
    /\ \/ /\ memConfirm /\ confirmAt = 0 /\ cancelAt = 0
          /\ confirmAt' = h + 1 /\ memConfirm' = FALSE /\ memCancel' = FALSE
          /\ UNCHANGED cancelAt
       \/ /\ memCancel /\ cancelAt = 0 /\ confirmAt = 0 /\ h + 1 >= CancelFrom
          /\ cancelAt' = h + 1 /\ memCancel' = FALSE /\ memConfirm' = FALSE
          /\ UNCHANGED confirmAt
       \/ UNCHANGED <<confirmAt, cancelAt, memConfirm, memCancel>>
    /\ UNCHANGED <<spvTop, spvStaleFrom, spvHasConfirm, status, minted, reorged>>

(* spv_header_hash_update: append height spvTop+1 once it is SpvLag deep. *)
SpvRecord ==
    /\ spvTop + 1 + SpvLag <= h
    /\ spvTop' = spvTop + 1
    /\ spvHasConfirm' = (spvHasConfirm \/ (confirmAt > 0 /\ confirmAt = spvTop + 1))
    /\ UNCHANGED <<h, confirmAt, cancelAt, memConfirm, memCancel, spvStaleFrom,
                   status, minted, reorged>>

(* One reorg of depth d: blocks above f = h - d are replaced by f+1..h+1.  *)
(* The new branch may carry the Cancel at a CSV-valid height, or the       *)
(* Confirm again, or neither. SPV entries above f stay, now stale.          *)
Reorg ==
    /\ ~reorged /\ h < MaxHeight
    /\ \E d \in 1..MaxReorg :
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
    /\ UNCHANGED <<spvTop, spvHasConfirm, status, minted>>

Environment == Broadcast \/ UserCancel \/ Mine \/ SpvRecord \/ Reorg

--------------------------------------------------------------------------
(* decide_btc_snapshot on the relayer: L1 never regresses. *)
Scan ==
    /\ status = "Presigned"
    /\ \/ confirmAt > 0 /\ status' = "RelayerL1Broadcasted"
       \/ confirmAt = 0 /\ cancelAt > 0 /\ status' = "UserCanceled"
    /\ UNCHANGED <<h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, minted, reorged>>

SpvCurrent(x) == x <= spvTop /\ x < spvStaleFrom

(* post_pegin_data: confirmed in the backend (current chain), SPV covers   *)
(* the block and holds ITS hash (else gateway_post_pegin_data bails), and  *)
(* PostConf confirmations.                                                 *)
HonestPost ==
    /\ status = "RelayerL1Broadcasted" /\ ~minted
    /\ confirmAt > 0 /\ SpvCurrent(confirmAt)
    /\ h - confirmAt + 1 >= PostConf
    /\ minted' = TRUE
    /\ UNCHANGED <<h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, status, reorged>>

(* A colluding committee member posts the Confirm with a header the SPV    *)
(* holds - possibly stale. The contract checks nothing else.               *)
ByzPost ==
    /\ ByzPoster /\ ~minted /\ spvHasConfirm
    /\ minted' = TRUE
    /\ UNCHANGED <<h, confirmAt, cancelAt, memConfirm, memCancel, spvTop,
                   spvStaleFrom, spvHasConfirm, status, reorged>>

Next == Environment \/ Scan \/ HonestPost \/ ByzPost
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* The user cannot hold both the refund and pegBTC. *)
NoUnbackedMint == ~(minted /\ cancelAt > 0)

RelayerL1NeverRegresses ==
    [][status = "RelayerL1Broadcasted" => status' = "RelayerL1Broadcasted"]_vars

====
