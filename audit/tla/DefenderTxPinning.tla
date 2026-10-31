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
(*  - Node: broadcast_tx_with_cpfp (node/src/utils/btc.rs:330-357) builds  *)
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
(*  - Market = feerate needed to be mined before the deadline, constant;  *)
(*  - miners take a package iff its package feerate >= Market;             *)
(*  - defender budget = what lifts P+child to Market, plus Headroom;       *)
(*    the CURRENT node has Headroom ~ 0 (parent-only CPFP);                *)
(*  - descendant-count pinning (rule 5) and replacement cycling are not    *)
(*    modeled; the attacker's later Take2 replacement of P+pin is assumed  *)
(*    affordable (it is bounded by the pin fee, << the peg-in).            *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    TRUC,             \* FIX: defender txs presigned as version 3
    PSize, PFee,      \* defender tx size / presigned fee
    Market,           \* feerate needed to confirm before the deadline
    Incr,             \* incremental relay feerate (BIP125 rule 4)
    DefChildSize,     \* defender CPFP child size
    Headroom,         \* defender fee headroom above the bare CPFP need
    V2DescendantMax,  \* v2 descendant size limit incl. the parent (101 kvB)
    TrucChildMax,     \* TRUC child size cap (1 kvB)
    TrucParentMax,    \* TRUC parent size cap (10 kvB)
    Deadline,         \* blocks until the competing Take2 timelock matures
    MaxT

ParentIsTruc == TRUC /\ PSize <= TrucParentMax
ChildCap == IF ParentIsTruc THEN TrucChildMax ELSE V2DescendantMax - PSize
Budget == Market * (PSize + DefChildSize) - PFee + Headroom

VARIABLES
    now,
    pState,  \* "absent" | "mempool" | "confirmed"
    child,   \* who owns the (single) anchor child: "none" | "attacker" | "defender"
    cSize,
    cFee,
    take2    \* the competing Take2 confirmed

vars == <<now, pState, child, cSize, cFee, take2>>

TypeOK ==
    /\ now \in 0..MaxT
    /\ pState \in {"absent", "mempool", "confirmed"}
    /\ child \in {"none", "attacker", "defender"}
    /\ cSize \in 0..V2DescendantMax
    /\ cFee \in 0..(V2DescendantMax * Market + Budget)
    /\ take2 \in BOOLEAN

\* P has just become valid (e.g. the ProverConnector CSV matured).
Init ==
    /\ now = 0
    /\ pState = "absent"
    /\ child = "none"
    /\ cSize = 0
    /\ cFee = 0
    /\ take2 = FALSE

\* Minimal defender child fee: lift the package to Market and, if it must
\* evict an attacker child, pay the evicted absolute fee + incremental relay
\* for its own size (BIP125 rules 3 and 4).
PkgNeed == Market * (PSize + DefChildSize) - PFee
RbfNeed == IF child = "attacker" THEN cFee + Incr * DefChildSize ELSE 0
NeedFee == IF PkgNeed > RbfNeed THEN PkgNeed ELSE RbfNeed
\* ... and the replacement must also have a higher feerate than what it evicts.
FeerateOK == child = "attacker" => NeedFee * cSize > cFee * DefChildSize

---------------------------------------------------------------------------
\* Defender broadcasts P together with its CPFP child (broadcast_package).
DefenderPackage ==
    /\ pState = "absent"
    /\ pState' = "mempool"
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ UNCHANGED <<now, take2>>

\* Anyone (the operator) broadcasts the presigned P bare, first.
AttackerBroadcastBare ==
    /\ pState = "absent"
    /\ pState' = "mempool"
    /\ UNCHANGED <<now, child, cSize, cFee, take2>>

\* Pin: a child of size s at a sub-market feerate r on the keyless anchor.
AttackerPin ==
    /\ pState = "mempool"
    /\ child = "none"
    /\ \E s \in 1..ChildCap, r \in 1..(Market - 1) :
        /\ child' = "attacker"
        /\ cSize' = s
        /\ cFee' = s * r
    /\ UNCHANGED <<now, pState, take2>>

\* Defender CPFP (or replace the pinning child), within its budget.
DefenderCPFP ==
    /\ pState = "mempool"
    /\ child \in {"none", "attacker"}
    /\ NeedFee <= Budget
    /\ FeerateOK
    /\ child' = "defender"
    /\ cSize' = DefChildSize
    /\ cFee' = NeedFee
    /\ UNCHANGED <<now, pState, take2>>

\* The defender acts before each block whenever it can.
DefenderDue == ENABLED DefenderPackage \/ ENABLED DefenderCPFP

PackageMined == child # "none" /\ PFee + cFee >= Market * (PSize + cSize)
ParentMined  == PFee >= Market * PSize

Mine ==
    /\ now < MaxT
    /\ ~DefenderDue
    /\ now' = now + 1
    /\ pState' = IF pState = "mempool" /\ (PackageMined \/ ParentMined)
                 THEN "confirmed" ELSE pState
    /\ UNCHANGED <<child, cSize, cFee, take2>>

\* Take2's timelock matured while P is still unconfirmed: the operator
\* replaces P (+ pin) with Take2 and wins the connector.
OperatorTake2 ==
    /\ now >= Deadline
    /\ pState # "confirmed"
    /\ ~take2
    /\ take2' = TRUE
    /\ UNCHANGED <<now, pState, child, cSize, cFee>>

Next == DefenderPackage \/ AttackerBroadcastBare \/ AttackerPin
        \/ DefenderCPFP \/ Mine \/ OperatorTake2

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* The defender tx confirms before the competing timelock matures, i.e. the
\* operator never gets Take2 against a pending defender tx.
DefenderConfirmsBeforeDeadline == ~take2

====
