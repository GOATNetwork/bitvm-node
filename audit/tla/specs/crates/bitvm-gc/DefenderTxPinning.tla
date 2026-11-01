---- MODULE DefenderTxPinning ----
(***************************************************************************)
(* Absolute-fee pinning of the presigned defender txs through their        *)
(*   keyless P2A anchor (audit M3).                                        *)
(* Code: goat bab46c2: OperatorChallengeNack, OperatorCommitTimeout        *)
(*   (goat/src/transactions/watchtower_challenge.rs:543-576, :714-748) and *)
(*   Disprove (assert.rs:316-338) are v2 with one output, the keyless      *)
(*   p2a_output (scripts.rs:182-187), and a fee fixed at presign time      *)
(*   (relay_fee, base.rs:345-347). Node: broadcast_tx_with_cpfp builds one *)
(*   v2 child that only lifts the parent (node/src/utils/btc.rs:239-358).  *)
(* M3: the operator broadcasts P bare and pins its anchor with a large     *)
(*   sub-market child (up to the 101 kvB descendant limit). BIP125 rule 3  *)
(*   makes the defender's replacement out-pay the pin's absolute fee, so P *)
(*   stays unconfirmed and Take2 wins.                                     *)
(* Fix (TRUC): v3 parent <= 10 kvB, one child <= 1 kvB, sibling eviction.  *)
(*   Not covered: VerifierAssert (60 kvB, cannot be TRUC) and Disprove's   *)
(*   SIGHASH_NONE anchor stripping.                                        *)
(* Parameters: see CONSTANTS; deadline per defender tx in ShippedDeadline. *)
(*   Units: 1 kvB and 1000 sat; P = 1 kvB at feerate 1 (the presigned      *)
(*   rate); miners take a package iff its feerate >= market. Not modeled:  *)
(*   rule-5 count pinning, replacement cycling.                            *)
(* ParamsOK (TRUC fix, exact - Boundary.cfg): react + incl + 1 <=          *)
(*   deadline. With TRUC the pin pays at most (market - 1) x 1 kvB, so the *)
(*   fee side never binds.                                                 *)
(* Exhaustive: time enters only as react + incl vs deadline; react 1..2,   *)
(*   incl 0..2, deadline 1..6 give margin <= -1, 0 and >= +1 for every     *)
(*   split. market 1..3 covers no and some fee pressure, headroom {0, 5}   *)
(*   today's node and a budget far below the 100 kvB pin.                  *)
(* Configs: configs/crates/bitvm-gc/DefenderTxPinning/, tiers in           *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    TRUC,             \* FIX: defender txs presigned as version 3
    PSize,            \* defender tx size (kvB)
    PFee,             \* defender tx presigned fee (1000 sat)
    Incr,             \* incremental relay feerate (BIP125 rule 4)
    DefChildSize,     \* defender CPFP child size
    V2DescendantMax,  \* v2 descendant size limit incl. the parent (101 kvB)
    TrucChildMax,     \* TRUC child size cap (1 kvB)
    TrucParentMax,    \* TRUC parent size cap (10 kvB)
    UseShipped,       \* deadline / react / incl from ShippedTimelockValues (market / headroom from their ranges)
    NetSet,           \* subset of Networks swept when UseShipped
    DeadlineRange,    \* blocks from the defender's trigger tip (0) to Take2's first block
    ReactionRange,    \* reaction blocks (>= 1)
    InclusionRange,   \* extra blocks for a market-rate package to be mined
    MarketRange,      \* feerate needed to confirm before the deadline (1 = the presigned rate)
    HeadroomRange,    \* defender fee headroom above the bare CPFP need
    ParamSel          \* Init filter: "all" | "ok" | "notOK"

VARIABLES
    net,       \* frozen: network name ("abstract" for the sweep)
    defTx,     \* frozen: which defender tx ("NACK" | "CommitTimeout" | "Disprove" | "abstract")
    deadline,  \* frozen: first block Take2 can be mined in, relative to the trigger tip 0
    react,     \* frozen: reaction blocks
    incl,      \* frozen: inclusion blocks
    market,    \* frozen: market feerate
    headroom,  \* frozen: defender fee headroom
    now,       \* chain tip height
    pState,    \* defender tx P: "absent" | "mempool" | "confirmed"
    child,     \* owner of the (single) anchor child: "none" | "attacker" | "defender"
    cSize,     \* anchor child size
    cFee,      \* anchor child absolute fee
    dAt,       \* tip at which the defender's child was broadcast
    take2      \* the competing Take2 confirmed

params == <<net, defTx, deadline, react, incl, market, headroom>>
vars == <<params, now, pState, child, cSize, cFee, dAt, take2>>

\* The fix applies: a v3 parent within the TRUC size cap.
ParentIsTruc == TRUC /\ PSize <= TrucParentMax
\* Largest child the attacker may attach.
ChildCap == IF ParentIsTruc THEN TrucChildMax ELSE V2DescendantMax - PSize
\* Most the defender pays for its child: the package need plus headroom.
Budget == market * (PSize + DefChildSize) - PFee + headroom

\* Every event of interest has happened by then.
Horizon == deadline + react + incl + 1
Done == now = Horizon

TypeOk ==
    /\ deadline \in Nat /\ react \in Nat /\ react >= 1 /\ incl \in Nat
    /\ market \in Nat /\ headroom \in Nat
    /\ now \in 0..Horizon
    /\ pState \in {"absent", "mempool", "confirmed"}
    /\ child \in {"none", "attacker", "defender"}
    /\ cSize \in 0..V2DescendantMax
    /\ cFee \in 0..(V2DescendantMax * market + Budget)
    /\ dAt \in 0..Horizon
    /\ take2 \in BOOLEAN

---------------------------------------------------------------------------
(* Parameter conditions.                                                   *)

ParamsOK == react + incl + 1 <= deadline

Selected ==
    CASE ParamSel = "all"   -> TRUE
      [] ParamSel = "ok"    -> ParamsOK
      [] ParamSel = "notOK" -> ~ParamsOK

\* Shipped deadline per defender tx, measured from the tip its own CSV matures at; Disprove
\* also loses the worst ChallengeAssert latency react + incl (GC eval 0, see AssertFrontRun.tla).
ShippedDeadline(n, tx) ==
    CASE tx = "NACK"          -> ConnectorF[n] - OperatorAck[n]
      [] tx = "CommitTimeout" -> ConnectorF[n] - OperatorCommit[n]
      [] tx = "Disprove"      -> ConnectorD[n] - ProverConnector[n]
                                   - (ReactionBlocks[n] + InclusionBlocks[n])

\* P is valid and the defender node fires at tip 0 (is_timelock_ready, node/src/aggregates/graph_scan.rs:474-476),
\* one block after the mempool would take P, so the attacker may already have pinned it.
Init ==
    /\ IF UseShipped
         THEN \E n \in NetSet, tx \in {"NACK", "CommitTimeout", "Disprove"} :
                /\ net = n /\ defTx = tx
                /\ deadline = ShippedDeadline(n, tx)
                /\ react = ReactionBlocks[n]
                /\ incl = InclusionBlocks[n]
         ELSE /\ net = "abstract" /\ defTx = "abstract"
              /\ deadline \in DeadlineRange
              /\ react \in ReactionRange
              /\ incl \in InclusionRange
    /\ market \in MarketRange
    /\ headroom \in HeadroomRange
    /\ Selected
    /\ now = 0
    /\ pState = "absent"
    /\ child = "none"
    /\ cSize = 0
    /\ cFee = 0
    /\ dAt = 0
    /\ take2 = FALSE

---------------------------------------------------------------------------
(* Fee rules and enabling conditions.                                      *)

\* Minimal defender child fee: lift the package to market and, if it must
\* evict an attacker child, pay the evicted absolute fee + incremental relay
\* for its own size (BIP125 rules 3 and 4).
PkgNeed == market * (PSize + DefChildSize) - PFee
RbfNeed == IF child = "attacker" THEN cFee + Incr * DefChildSize ELSE 0
NeedFee == IF PkgNeed > RbfNeed THEN PkgNeed ELSE RbfNeed
\* The replacement must also have a higher feerate than what it evicts.
FeerateOK == child = "attacker" => NeedFee * cSize > cFee * DefChildSize

DefPkgEn  == pState = "absent"
DefCPFPEn ==
    /\ pState = "mempool"
    /\ child \in {"none", "attacker"}
    /\ NeedFee <= Budget
    /\ FeerateOK
BareEn == pState = "absent"
PinEn  == pState = "mempool" /\ child = "none" /\ market >= 2
Take2En == now + 1 >= deadline /\ pState # "confirmed" /\ ~take2

PackageMined == child # "none" /\ PFee + cFee >= market * (PSize + cSize)
ParentMined  == PFee >= market * PSize
Minable == pState = "mempool" /\ (PackageMined \/ ParentMined)
\* The defender's market-rate package is mined at the latest incl blocks after its broadcast.
MineForced == Minable /\ child = "defender" /\ now >= dAt + incl

\* The defender must act by tip react - 1 (react >= 1 counts the next block).
DefenderDue == (DefPkgEn \/ DefCPFPEn) /\ now >= react - 1

---------------------------------------------------------------------------
(* Actions.                                                                *)

\* Action: the defender node broadcasts P with a CPFP child lifting the package to market.
\* Source: broadcast_tx_with_cpfp(), node/src/utils/btc.rs:330-358; callers node/src/aggregates/graph_pegout_jobs.rs:706, :729, :1020.
DefenderPackage ==
    /\ DefPkgEn
    /\ pState' = "mempool"
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ dAt' = now
    /\ UNCHANGED <<params, now, take2>>

\* Action: the operator broadcasts the presigned P alone, before the defender.
\* Source: environment (P is fully presigned; every graph participant has it).
AttackerBroadcastBare ==
    /\ BareEn
    /\ pState' = "mempool"
    /\ UNCHANGED <<params, now, child, cSize, cFee, dAt, take2>>

\* Action: the operator pins P's anchor with a child of size sz at a sub-market feerate r.
\* Source: environment; the anchor is the keyless p2a_output(), goat scripts.rs:182-187.
AttackerPin ==
    /\ PinEn
    /\ \E sz \in 1..ChildCap, r \in 1..(market - 1) :
        /\ child' = "attacker"
        /\ cSize' = sz
        /\ cFee' = sz * r
    /\ UNCHANGED <<params, now, pState, dAt, take2>>

\* Action: the defender CPFPs a bare P or replaces the pin, within budget and BIP125 rules 3, 4 and feerate.
\* Source: build_cpfp_txns(), node/src/utils/btc.rs:239-328 (the child only lifts the parent: headroom ~ 0).
DefenderCPFP ==
    /\ DefCPFPEn
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ dAt' = now
    /\ UNCHANGED <<params, now, pState, take2>>

\* When nobody can act and P cannot be mined, Mine jumps to Take2's maturity (sound).
Busy == DefPkgEn \/ DefCPFPEn \/ BareEn \/ PinEn \/ Minable \/ Take2En
NextStop == IF ~take2 /\ deadline - 1 > now THEN deadline - 1 ELSE Horizon

\* Action: one block; P (+ child) is mined iff its package feerate meets market. Blocked while the defender is due.
\* Source: Bitcoin consensus and miner package-feerate policy.
Mine ==
    /\ now < Horizon
    /\ ~DefenderDue
    /\ now' = IF Busy THEN now + 1 ELSE NextStop
    /\ \E inc \in (IF MineForced THEN {TRUE}
                   ELSE IF Minable THEN {TRUE, FALSE} ELSE {FALSE}) :
         pState' = IF inc THEN "confirmed" ELSE pState
    /\ UNCHANGED <<params, child, cSize, cFee, dAt, take2>>

\* Action: Take2 matured with P unconfirmed: the operator replaces P (+ pin) with Take2 (a tie goes to the operator).
\* Source: take2(), node/src/aggregates/graph_pegout_jobs.rs:1500-1537; goat transactions/take2.rs:56-77.
OperatorTake2 ==
    /\ Take2En
    /\ take2' = TRUE
    /\ UNCHANGED <<params, now, pState, child, cSize, cFee, dAt>>

\* Action: stutter at the horizon (not a deadlock).
\* Source: model bound.
Halt == Done /\ UNCHANGED vars

Next ==
    \/ DefenderPackage
    \/ AttackerBroadcastBare
    \/ AttackerPin
    \/ DefenderCPFP
    \/ Mine
    \/ OperatorTake2
    \/ Halt

\* No fairness: the defender's progress is forced by DefenderDue and MineForced.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* The operator never gets Take2 against a pending defender tx.
DefenderConfirmsBeforeDeadline == ~take2

====
