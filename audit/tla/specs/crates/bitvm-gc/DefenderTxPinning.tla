---- MODULE DefenderTxPinning ----
(***************************************************************************)
(* Absolute-fee (BIP125 rule 3/4) pinning of the presigned defender txs    *)
(* through their keyless P2A anchor (audit M3).                            *)
(*                                                                         *)
(* Ground truth: external goat crate, checkout bab46c2:                    *)
(*  - OperatorChallengeNack (watchtower_challenge.rs:543-575: AckConnector *)
(*    leaf 2 + ConnectorF leaf 1, n-of-n SIGHASH_ALL), OperatorCommit-     *)
(*    Timeout (:714-747: ConnectorE leaf 1 + ConnectorF leaf 1, ALL) and   *)
(*    Disprove (assert.rs:316-355: ProverConnector leaf 1 + ConnectorD     *)
(*    leaf 1, SIGHASH_NONE) are all `Version(2)` with the SINGLE output    *)
(*    p2a_output() - 240 sat to OP_1 <0x4e73> (scripts.rs:174-186,         *)
(*    base.rs:34), spendable by ANYONE with an empty witness.              *)
(*  - Their fee is fixed at presign time: relay_fee(vsize) = vsize * 1.2 * *)
(*    1 sat/vB (base.rs:20,345-347; NACK/Timeout/Disprove 800 vB,          *)
(*    base.rs:27,31,33). The only way to raise it is CPFP on the anchor.   *)
(*  - They are fully presigned: any graph participant (incl. the operator) *)
(*    can broadcast them the moment they become valid.                     *)
(*  - They race Take2 (take2.rs:56-77): NACK / CommitTimeout must confirm  *)
(*    before ConnectorF leaf 0's CSV, Disprove before ConnectorD leaf 0's. *)
(*  - Node: broadcast_tx_with_cpfp (node/src/utils/btc.rs:330-358) builds  *)
(*    ONE v2 child on the anchor (build_cpfp_txns, btc.rs:239-328) whose   *)
(*    fee only lifts the PARENT to the current fee rate; it never budgets  *)
(*    for replacing a competing child. Callers: graph_pegout_jobs.rs:706   *)
(*    (NACK), :729/:1162 (timeouts), :977 (VerifierAssert), :1020 (Dispr.) *)
(*                                                                         *)
(* Attack: the operator broadcasts P (the defender tx) bare as soon as it  *)
(* is valid and attaches a LARGE child at a feerate below the market, so   *)
(* the package never gets mined. The defender's child conflicts with the   *)
(* pin on the anchor; BIP125 rule 3 makes it pay MORE ABSOLUTE FEE than    *)
(* the whole pin (+ rule 4 incremental relay for its own size). With v2    *)
(* the pin may be up to the 101 kvB descendant-size limit (incl. P), so    *)
(* its absolute fee dwarfs any CPFP budget; P stays unconfirmed until the  *)
(* Take2 timelock matures, and the operator (whose stake is the whole      *)
(* peg-in) replaces P+pin with Take2.                                      *)
(*                                                                         *)
(* Fix design (TRUC = TRUE): presign the defender txs as version 3 (BIP431 *)
(* TRUC). Policy then caps the parent at 10 kvB, allows exactly one child  *)
(* of at most 1 kvB, and lets a new child replace the existing one         *)
(* (sibling eviction / 1p1c package RBF). The pin's absolute fee is        *)
(* therefore bounded by 1 kvB x (sub-market feerate) and the defender      *)
(* always outbids it. NOTE: VerifierAssert (base.rs:25 estimates 60000 vB, *)
(* i.e. far above TRUC's 10 kvB parent cap) cannot become TRUC; with the   *)
(* numbers below its own CPFP need (~Market x 60 kvB) already exceeds the  *)
(* largest pin a 101 kvB package allows, so the absolute-fee pin is weak   *)
(* there - it is NOT covered by this fix and is left as a residual note.   *)
(* Disprove's SIGHASH_NONE additionally lets anyone strip its anchor       *)
(* output (fee stays bounded by its ~3.3k sat inputs); not modeled.        *)
(*                                                                         *)
(* Units / assumptions (deliberately minimal):                             *)
(*  - size unit = 1 kvB, fee unit = 1000 sat, feerate 1 = min relay;       *)
(*    P = 1 kvB at feerate 1 (the presigned ~1.2 sat/vB);                  *)
(*  - market = feerate needed to be mined before the deadline, constant;   *)
(*  - miners take a package iff its package feerate >= market;             *)
(*  - defender budget = what lifts P+child to market, plus headroom;       *)
(*    the CURRENT node has headroom ~ 0 (parent-only CPFP);                *)
(*  - descendant-count pinning (rule 5) and replacement cycling are not    *)
(*    modeled; the attacker's later Take2 replacement of P+pin is assumed  *)
(*    affordable (it is bounded by the pin fee, << the peg-in).            *)
(*                                                                         *)
(* Timing (no instant reaction). Tip 0 is the tip at which the defender    *)
(* node fires (graph_scan.rs:474-476 is_timelock_ready: tip >= c + k, one  *)
(* block after the mempool would take P - the attacker may already have    *)
(* broadcast P bare and pinned it by then). An action at tip `now` lands   *)
(* in block now+1. The defender broadcasts (package, or CPFP / pin         *)
(* eviction) at tip <= react - 1 (react >= 1 counts the next block,        *)
(* ReactionBlocks) and a package that pays the market is mined within      *)
(* incl more blocks (InclusionBlocks). Take2 can be mined from block       *)
(* `deadline` on and wins any same-block tie. Per defender tx, with the    *)
(* node firing at tip c + k (k = its own CSV):                             *)
(*   NACK           deadline = connector_f - operator_ack                  *)
(*   Commit-Timeout deadline = connector_f - operator_commit               *)
(*   Disprove       deadline = connector_d - prover_connector              *)
(*                             - (react + incl)  (worst ChallengeAssert    *)
(*                             latency after OperatorAssert, GC eval 0,    *)
(*                             see AssertFrontRun.tla)                     *)
(*                                                                         *)
(* ParamsOK (fix design, exact - DefenderTxPinning/Boundary.cfg and the     *)
(* margin-0 class of the pass sweep): react + incl + 1 <= deadline. With   *)
(* TRUC the fee side never binds for these units: the pin pays at most     *)
(* (market-1) x 1 kvB, so the defender's NeedFee is its own package need   *)
(* 2*market - 1 <= Budget for any headroom >= 0, and its feerate beats     *)
(* the pin's.                                                              *)
(*                                                                         *)
(* Frozen parameters chosen in Init: deadline, react, incl, market,        *)
(* headroom, either from the sweep ranges or (UseShipped) from             *)
(* ShippedTimelockValues per net in NetSet (deadline = each of the three   *)
(* defender txs above; market / headroom still from their ranges).         *)
(* Why the sweep is exhaustive: time only enters through `now` vs          *)
(* react - 1, the inclusion deadline dAt + incl and deadline - 1; the      *)
(* defender's latest landing block is react + incl, so the only timing     *)
(* relation is react + incl vs deadline: react 1..2, incl 0..2 (sum 1..4)  *)
(* with deadline 1..6 realises margin <= -1, 0 and >= +1 for every split.  *)
(* Fees enter through market vs the presigned feerate (1 = no pressure, P  *)
(* confirms alone; >= 2 = pressure) and headroom vs the pin fee (0 = the   *)
(* node today, 5 = generous but << the 100 kvB pin): market 1..3,          *)
(* headroom {0, 5}.                                                        *)
(*                                                                         *)
(* Code scope (current tree): node/src/utils/btc.rs                        *)
(* (broadcast_tx_with_cpfp, build_cpfp_txns),                              *)
(* node/src/aggregates/graph_pegout_jobs.rs (challenge_nack,               *)
(* commit_timeout, disprove, take2), node/src/aggregates/graph_scan.rs     *)
(* (is_timelock_ready), goat bab46c2 presigned tx versions as cited above. *)
(*                                                                         *)
(* Configs and tiers (checks.txt):                                         *)
(*  live     DefenderTxPinning(.cfg|Shipped)  v2 + keyless P2A (current)   *)
(*  design   DefenderTxPinningFixed, ...FixedShipped (TRUC over ParamsOK;  *)
(*           shipped Bitcoin/Testnet4/Signet)                              *)
(*  boundary DefenderTxPinningBoundary (outside ParamsOK), ...Regtest      *)
(*           (TRUC with the shipped Regtest deadlines, outside ParamsOK)   *)
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
    UseShipped,       \* deadline / react / incl from ShippedTimelockValues
    NetSet,           \* subset of Networks swept when UseShipped
    DeadlineRange,    \* blocks from the defender's trigger tip to Take2's first block
    ReactionRange,    \* reaction blocks (>= 1)
    InclusionRange,   \* extra blocks for a market-rate package to be mined
    MarketRange,      \* feerate needed to confirm before the deadline
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

ParentIsTruc == TRUC /\ PSize <= TrucParentMax
ChildCap == IF ParentIsTruc THEN TrucChildMax ELSE V2DescendantMax - PSize
Budget == market * (PSize + DefChildSize) - PFee + headroom

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

\* Shipped deadline of each defender tx (see header).
ShippedDeadline(n, tx) ==
    CASE tx = "NACK"          -> ConnectorF[n] - OperatorAck[n]
      [] tx = "CommitTimeout" -> ConnectorF[n] - OperatorCommit[n]
      [] tx = "Disprove"      -> ConnectorD[n] - ProverConnector[n]
                                   - (ReactionBlocks[n] + InclusionBlocks[n])

\* P has just become valid and the defender node fires (tip 0).
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
\* ... and the replacement must also have a higher feerate than what it evicts.
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
\* The defender's market-rate package is mined at the latest incl blocks
\* after its broadcast.
MineForced == Minable /\ child = "defender" /\ now >= dAt + incl

\* The defender must have acted by tip react - 1 whenever it can.
DefenderDue == (DefPkgEn \/ DefCPFPEn) /\ now >= react - 1

---------------------------------------------------------------------------
(* Actions.                                                                *)

\* Action: the defender node broadcasts P together with its CPFP child as
\* a package (child fee lifts the package to market).
\* Source: broadcast_tx_with_cpfp() in node/src/utils/btc.rs:330-358
\* (build_cpfp_txns :239-328), called by challenge_nack() / commit_timeout()
\* / disprove() in node/src/aggregates/graph_pegout_jobs.rs:706, :729, :1020.
DefenderPackage ==
    /\ DefPkgEn
    /\ pState' = "mempool"
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ dAt' = now
    /\ UNCHANGED <<params, now, take2>>

\* Action: anyone (the operator) broadcasts the presigned P bare, first.
\* Source: environment (P is fully presigned; any graph participant has it).
AttackerBroadcastBare ==
    /\ BareEn
    /\ pState' = "mempool"
    /\ UNCHANGED <<params, now, child, cSize, cFee, dAt, take2>>

\* Action: pin - a child of size sz at a sub-market feerate r on the
\* keyless anchor, as large as the descendant limit allows.
\* Source: environment; p2a_output() in goat scripts.rs:174-186 is keyless.
AttackerPin ==
    /\ PinEn
    /\ \E sz \in 1..ChildCap, r \in 1..(market - 1) :
        /\ child' = "attacker"
        /\ cSize' = sz
        /\ cFee' = sz * r
    /\ UNCHANGED <<params, now, pState, dAt, take2>>

\* Action: the defender CPFPs a bare P (or replaces the pinning child)
\* within its budget, subject to BIP125 rules 3/4 and the feerate rule.
\* Source: broadcast_tx_with_cpfp() / build_cpfp_txns() in
\* node/src/utils/btc.rs:239-358 (today the child only lifts the parent:
\* headroom ~ 0).
DefenderCPFP ==
    /\ DefCPFPEn
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ dAt' = now
    /\ UNCHANGED <<params, now, pState, take2>>

\* Time abstraction (sound, stuttering only): when nobody can act and P
\* cannot be mined, every block until Take2 matures changes only `now`.
Busy == DefPkgEn \/ DefCPFPEn \/ BareEn \/ PinEn \/ Minable \/ Take2En
NextStop == IF ~take2 /\ deadline - 1 > now THEN deadline - 1 ELSE Horizon

\* Action: one block; P (+ child) is mined iff its package feerate meets
\* the market, at the latest incl blocks after the defender's broadcast.
\* Blocked while the defender is due.
\* Source: Bitcoin consensus + miner package-feerate policy.
Mine ==
    /\ now < Horizon
    /\ ~DefenderDue
    /\ now' = IF Busy THEN now + 1 ELSE NextStop
    /\ \E inc \in (IF MineForced THEN {TRUE}
                   ELSE IF Minable THEN {TRUE, FALSE} ELSE {FALSE}) :
         pState' = IF inc THEN "confirmed" ELSE pState
    /\ UNCHANGED <<params, child, cSize, cFee, dAt, take2>>

\* Action: Take2's timelock matured while P is still unconfirmed: the
\* operator replaces P (+ pin) with Take2 and wins the connector (Take2
\* lands in block now+1 >= deadline; a same-block tie goes to the operator).
\* Source: take2() in node/src/aggregates/graph_pegout_jobs.rs:1500-1537
\* (a cheating operator signs it itself); goat take2.rs:56-77.
OperatorTake2 ==
    /\ Take2En
    /\ take2' = TRUE
    /\ UNCHANGED <<params, now, pState, child, cSize, cFee, dAt>>

\* Action: end of the horizon - stutter (not a deadlock).
\* Source: model bound (no code).
Halt == Done /\ UNCHANGED vars

Next ==
    \/ DefenderPackage
    \/ AttackerBroadcastBare
    \/ AttackerPin
    \/ DefenderCPFP
    \/ Mine
    \/ OperatorTake2
    \/ Halt

\* No fairness: the only property is a safety invariant; the defender's
\* progress is forced by DefenderDue / MineForced, not by WF/SF.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* The defender tx confirms before the competing timelock matures, i.e. the
\* operator never gets Take2 against a pending defender tx.
DefenderConfirmsBeforeDeadline == ~take2

(* Safety properties (temporal): none.                                     *)
(* Liveness: none (bounded horizon).                                       *)

====
