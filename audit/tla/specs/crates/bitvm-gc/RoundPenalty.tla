---- MODULE RoundPenalty ----
(***************************************************************************)
(* Out-of-slot ("late") kickoffs escape every on-chain penalty because the *)
(* penalty txs hang off operator-key-only connectors (audit M5).           *)
(*                                                                         *)
(* Ground truth: external goat crate, checkout bab46c2, plus bitvm-gc:     *)
(*  - Prekickoff_{i+1} (transactions/prekickoff.rs:93-181) spends          *)
(*    PrekickoffConn_i and outputs [ForceSkipConn_{i+1} (DUST),            *)
(*    KickoffConn_{i+1}, PrekickoffConn_{i+1}, P2A]; it is signed by the   *)
(*    operator alone (sign_input_0, :183-196).                             *)
(*  - ForceSkipConnector, KickoffConnector, PrekickoffConnector and        *)
(*    GuardianConnector are ALL `<operator_pk> OP_CHECKSIG` leaves with    *)
(*    the operator key as taproot internal key                             *)
(*    (connectors/kickoff_connectors.rs:14-227) - the operator alone can   *)
(*    spend each of them, with ANY tx, at ANY time.                        *)
(*  - Penalties for graph/slot i (wired in crates/bitvm-gc/src/operator/   *)
(*    api.rs:87-167), all presigned by the operator with SIGHASH_NONE so   *)
(*    any verifier can add outputs and broadcast:                          *)
(*      ForceSkipKickoff_i  = KickoffConn_i + ForceSkipConn_{i+1}          *)
(*                            (prekickoff.rs:274-311)                      *)
(*      QuickChallenge_i    = Guardian_i    + ForceSkipConn_{i+1}          *)
(*                            (prekickoff.rs:407-445)                      *)
(*      ChallengeIncompleteKickoff_i = Guardian_i + PrekickoffConn_{i+1}   *)
(*                            (prekickoff.rs:542-578)                      *)
(*    Guardian_i is an input of both Take1 (take1.rs:82-83) and Take2      *)
(*    (take2.rs:76-77), so spending it kills the slot's payout.            *)
(*  - Node: enforce_previous_slot (node/src/aggregates/graph_pegout_jobs.  *)
(*    rs:506-592), run once Pre-Kickoff-N confirms: Force-Skip slot N-1 if *)
(*    its kickoff never appeared (:569-579), else Quick-Challenge it if    *)
(*    unsettled (:584-591). ChallengeIncompleteKickoff is only DETECTED    *)
(*    (node/src/utils/graph_chain_state.rs:152-158), never broadcast by    *)
(*    node code. One-graph-per-slot / continuity is checked off-chain only *)
(*    (node/src/aggregates/graph.rs:597-632).                              *)
(*                                                                         *)
(* Attack: in the block where Prekickoff_{i+1} confirms (same package even)*)
(* the operator spends ForceSkipConn_{i+1} to itself. ForceSkipKickoff_i   *)
(* and QuickChallenge_i become permanently invalid (missing input). It     *)
(* then broadcasts Prekickoff_{i+2} (consuming PrekickoffConn_{i+1}, so    *)
(* ChallengeIncompleteKickoff_i is dead too). Kickoff_i - still spendable, *)
(* since nothing could Force-Skip it - can now be fired at any later time  *)
(* and runs to Take1/Take2 with no Guardian penalty.                       *)
(*                                                                         *)
(* Fix design (ForceSkipNofN = TRUE): ForceSkipConnector becomes an        *)
(* n-of-n (committee) key spend; the committee co-presigns input 1 of      *)
(* ForceSkipKickoff_i and QuickChallenge_i (SIGHASH_NONE, as today). This  *)
(* is the minimal change: the honest operator never spends ForceSkipConn   *)
(* (the node skips a slot via operator_skip_graph(), node/src/utils/       *)
(* graph_tx.rs:263-326, signing SkipKickoff on KickoffConn with            *)
(* operator_sign_skip_kickoff(), crates/bitvm-gc/src/operator/api.rs:453), *)
(* so nothing else needs that key.                                         *)
(* A relative timelock on an operator leaf is NOT enough: once the CSV     *)
(* expires the operator can still burn the connector and every slot it     *)
(* kicks off after that is again penalty-free. With the n-of-n connector   *)
(* QuickChallenge_i stays valid forever once round i+1 exists, so a late   *)
(* Kickoff_i is always answerable before its Take timelock.                *)
(* (The operator can still abandon its chain by spending PrekickoffConn_i  *)
(* with a non-canonical tx; then round i+1 never exists, nothing is        *)
(* "late", and the off-chain continuity check rejects follow-up graphs.)   *)
(*                                                                         *)
(* Generosity to the current design: watchers here DO broadcast            *)
(* ChallengeIncompleteKickoff (node code does not), so the counterexample  *)
(* must also advance to round i+2, as stated in the finding.               *)
(* Abstractions: one slot i = 0; the operator may chain several txs into   *)
(* one block (no Mine between its steps).                                  *)
(*                                                                         *)
(* Timing (no instant reaction). An action at tip `now` lands in block     *)
(* now+1. A penalty can only be sent once its inputs are confirmed (the    *)
(* node acts on confirmed txs: enforce_previous_slot waits for Pre-Kickoff *)
(* N, :516-518, and sees the kickoff via tx_visible); from the block E in  *)
(* which its last input confirmed, watchers land it in block <= E + react  *)
(* + incl (react >= 1 counts the next block, ReactionBlocks; incl =        *)
(* InclusionBlocks); the reaction restarts on every new event (a late      *)
(* kickoff that out-bids a pending Force-Skip). takecsv is the Take1 CSV   *)
(* after Kickoff_0 (connector_a; Take2 is later, so Take1 is the binding   *)
(* race); Take lands in block >= kickoffAt + takecsv and wins a same-block *)
(* tie.                                                                    *)
(* ParamsOK (fix design, exact - RoundPenalty/Boundary.cfg, and the         *)
(* margin-0 class is in the pass sweep): react + incl + 1 <= takecsv: a    *)
(* late Kickoff_0 confirmed in block K is Quick-Challenged in block <=     *)
(* K + react + incl < K + takecsv. (validate_timelock_config only demands  *)
(* connector_a >= react + incl + safety, which implies ParamsOK only when  *)
(* safety >= 1; the shipped values all satisfy ParamsOK.)                  *)
(* The bug does not depend on timing: ForceSkipConn_1 is burnt in the same *)
(* block that creates it and Prekickoff_2 follows in that block, so no     *)
(* penalty is ever enabled at a confirmed tip.                             *)
(* Frozen parameters chosen in Init, from the sweep ranges or (UseShipped) *)
(* ShippedTimelockValues per net in NetSet (takecsv = ConnectorA, react /  *)
(* incl = Reaction/InclusionBlocks). Why the sweep is exhaustive: the only *)
(* timing relation is the watcher's latest landing (event + react + incl)  *)
(* vs the Take maturity (kickoff + takecsv); react 1..2, incl 0..2 (sum    *)
(* 1..4) with takecsv 1..6 realise margin <= -1, 0 and >= +1 for every     *)
(* split.                                                                  *)
(*                                                                         *)
(* Code scope (current tree): node/src/aggregates/graph_pegout_jobs.rs     *)
(* (kickoff, enforce_previous_slot, take1), node/src/utils/graph_tx.rs     *)
(* (operator_kickoff, operator_skip_graph, verifier_force_skip_kickoff,    *)
(* verifier_quick_challenge), crates/bitvm-gc/src/operator/api.rs          *)
(* (penalty wiring), goat bab46c2 kickoff connectors as cited above.       *)
(*                                                                         *)
(* Configs and tiers (checks.txt):                                         *)
(*  live     RoundPenalty(.cfg|Shipped)  operator-key ForceSkipConnector   *)
(*  design   RoundPenaltyFixed, ...FixedShipped (n-of-n ForceSkipConnector *)
(*           over ParamsOK / all four shipped networks)                    *)
(*  boundary RoundPenaltyBoundary (n-of-n, outside ParamsOK)               *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    ForceSkipNofN,  \* FIX: ForceSkipConnector is n-of-n instead of operator-only
    UseShipped,     \* parameters from ShippedTimelockValues (per net in NetSet)
    NetSet,         \* subset of Networks swept when UseShipped
    TakeCSVRange,   \* blocks after Kickoff_0 before the operator can Take (connector_a)
    ReactionRange,  \* reaction blocks (>= 1)
    InclusionRange, \* extra blocks for a penalty to be mined
    ParamSel        \* Init filter: "all" | "ok" | "notOK"

VARIABLES
    net,        \* frozen: network name ("abstract" for the sweep)
    takecsv,    \* frozen: Take1 CSV after Kickoff_0 (connector_a)
    react,      \* frozen: reaction blocks
    incl,       \* frozen: inclusion blocks
    now,        \* chain tip height
    prek1,      \* Prekickoff_1 (round 1) confirmed
    prek1At,    \* ... in this block
    kc0,        \* KickoffConn_0: "unspent" | "kickoff" | "skipped" | "forceSkipped"
    fs1,        \* ForceSkipConn_1: "none" | "unspent" | "forceSkip" | "quickChallenge" | "operator"
    pc1,        \* PrekickoffConn_1: "none" | "unspent" | "prek2" | "cik"
    g0,         \* Guardian_0: "none" | "unspent" | "take" | "quickChallenge" | "cik"
    kickoffAt,  \* block Kickoff_0 landed in
    late        \* Kickoff_0 landed in a block AFTER the one that confirmed round 1

params == <<net, takecsv, react, incl>>
vars == <<params, now, prek1, prek1At, kc0, fs1, pc1, g0, kickoffAt, late>>

Horizon == takecsv + react + incl + 3
Done == now = Horizon

TypeOk ==
    /\ takecsv \in Nat /\ react \in Nat /\ react >= 1 /\ incl \in Nat
    /\ now \in 0..Horizon
    /\ prek1 \in BOOLEAN
    /\ prek1At \in 0..(Horizon + 1)
    /\ kc0 \in {"unspent", "kickoff", "skipped", "forceSkipped"}
    /\ fs1 \in {"none", "unspent", "forceSkip", "quickChallenge", "operator"}
    /\ pc1 \in {"none", "unspent", "prek2", "cik"}
    /\ g0 \in {"none", "unspent", "take", "quickChallenge", "cik"}
    /\ kickoffAt \in 0..(Horizon + 1)
    /\ late \in BOOLEAN

---------------------------------------------------------------------------
(* Parameter conditions.                                                   *)

ParamsOK == react + incl + 1 <= takecsv

Selected ==
    CASE ParamSel = "all"   -> TRUE
      [] ParamSel = "ok"    -> ParamsOK
      [] ParamSel = "notOK" -> ~ParamsOK

\* Round 0 (Prekickoff_0) is confirmed: KickoffConn_0 exists.
Init ==
    /\ IF UseShipped
         THEN \E n \in NetSet :
                /\ net = n
                /\ takecsv = ConnectorA[n]
                /\ react = ReactionBlocks[n]
                /\ incl = InclusionBlocks[n]
         ELSE /\ net = "abstract"
              /\ takecsv \in TakeCSVRange
              /\ react \in ReactionRange
              /\ incl \in InclusionRange
    /\ Selected
    /\ now = 0
    /\ prek1 = FALSE
    /\ prek1At = 0
    /\ kc0 = "unspent"
    /\ fs1 = "none"
    /\ pc1 = "none"
    /\ g0 = "none"
    /\ kickoffAt = 0
    /\ late = FALSE

---------------------------------------------------------------------------
(* Operator (possibly malicious; operator-key spends are unconstrained).   *)

\* Action: the operator's Kickoff_0 lands (spends KickoffConn_0, creates
\* Guardian_0); it is "late" if round 1 was already confirmed in an earlier
\* block.
\* Source: kickoff() in node/src/aggregates/graph_pegout_jobs.rs:261-303
\* via operator_kickoff() in node/src/utils/graph_tx.rs:328; a malicious
\* operator may send it at any time (operator key only).
OpKickoff ==
    /\ kc0 = "unspent"
    /\ kc0' = "kickoff"
    /\ g0' = "unspent"
    /\ kickoffAt' = now + 1
    /\ late' = (prek1 /\ now + 1 > prek1At)
    /\ UNCHANGED <<params, now, prek1, prek1At, fs1, pc1>>

\* Action: the honest way to skip slot 0 (SkipKickoff on KickoffConn_0).
\* Source: operator_skip_graph() in node/src/utils/graph_tx.rs:263-326
\* (operator_sign_skip_kickoff(), crates/bitvm-gc/src/operator/api.rs:453).
OpSkip ==
    /\ kc0 = "unspent"
    /\ kc0' = "skipped"
    /\ UNCHANGED <<params, now, prek1, prek1At, fs1, pc1, g0, kickoffAt, late>>

\* Action: Prekickoff_1 lands (spends PrekickoffConn_0, creates
\* ForceSkipConn_1 and PrekickoffConn_1).
\* Source: operator_sign_prekickoff_input_0() used by operator_kickoff() /
\* operator_skip_graph() in node/src/utils/graph_tx.rs:270, :332; goat
\* transactions/prekickoff.rs:93-181 (operator signature only).
OpPrekickoff1 ==
    /\ ~prek1
    /\ prek1' = TRUE
    /\ prek1At' = now + 1
    /\ fs1' = "unspent"
    /\ pc1' = "unspent"
    /\ UNCHANGED <<params, now, kc0, g0, kickoffAt, late>>

\* Action: Prekickoff_2 lands, consuming PrekickoffConn_1 (kills
\* ChallengeIncompleteKickoff_0).
\* Source: same as OpPrekickoff1 for the next round.
OpPrekickoff2 ==
    /\ pc1 = "unspent"
    /\ pc1' = "prek2"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, fs1, g0, kickoffAt, late>>

\* Action: THE BUG - the operator spends ForceSkipConn_1 to itself, killing
\* ForceSkipKickoff_0 and QuickChallenge_0.
\* Source: environment (operator key); ForceSkipConnector is
\* <operator_pk> OP_CHECKSIG, goat connectors/kickoff_connectors.rs:14-227.
OpBurnForceSkipConn ==
    /\ ~ForceSkipNofN
    /\ fs1 = "unspent"
    /\ fs1' = "operator"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, pc1, g0, kickoffAt, late>>

\* Action: Take1 / Take2 (both consume Guardian_0) land from block
\* kickoffAt + takecsv on.
\* Source: take1() in node/src/aggregates/graph_pegout_jobs.rs:1470
\* (is_take1_timelock_expired, node/src/utils/btc.rs:24-32); goat
\* take1.rs:82-83 / take2.rs:76-77 spend the Guardian.
OpTake ==
    /\ g0 = "unspent"
    /\ now + 1 >= kickoffAt + takecsv
    /\ g0' = "take"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, fs1, pc1, kickoffAt, late>>

---------------------------------------------------------------------------
(* Watchers (anyone holding the presigned SIGHASH_NONE penalties). A       *)
(* penalty needs its inputs confirmed (tip >= the block they landed in).   *)

Max2(a, b) == IF a >= b THEN a ELSE b

ForceSkipEnabled == kc0 = "unspent" /\ fs1 = "unspent" /\ now >= prek1At
QCEnabled        == g0 = "unspent" /\ fs1 = "unspent" /\ now >= Max2(kickoffAt, prek1At)
CIKEnabled       == g0 = "unspent" /\ pc1 = "unspent" /\ now >= Max2(kickoffAt, prek1At)

\* Block whose confirmation enabled the penalty (the reaction restarts on
\* each new event); a watcher's penalty lands by that + react + incl.
ForceSkipFrom == prek1At
QCFrom        == Max2(kickoffAt, prek1At)
PenaltyDue ==
    \/ ForceSkipEnabled /\ now + 1 >= ForceSkipFrom + react + incl
    \/ (QCEnabled \/ CIKEnabled) /\ now + 1 >= QCFrom + react + incl

\* Action: ForceSkipKickoff_0 lands (KickoffConn_0 + ForceSkipConn_1):
\* slot 0 can no longer be kicked off.
\* Source: enforce_previous_slot() in node/src/aggregates/
\* graph_pegout_jobs.rs:506-592 (kickoff not visible, :570-579) via
\* verifier_force_skip_kickoff() in node/src/utils/graph_tx.rs:41-70.
ForceSkipKickoff ==
    /\ ForceSkipEnabled
    /\ kc0' = "forceSkipped"
    /\ fs1' = "forceSkip"
    /\ UNCHANGED <<params, now, prek1, prek1At, pc1, g0, kickoffAt, late>>

\* Action: QuickChallenge_0 lands (Guardian_0 + ForceSkipConn_1): the slot's
\* payout is dead.
\* Source: enforce_previous_slot() in node/src/aggregates/
\* graph_pegout_jobs.rs:506-592 (kickoff visible and unsettled, :580-591)
\* via verifier_quick_challenge() in node/src/utils/graph_tx.rs:72-99.
QuickChallenge ==
    /\ QCEnabled
    /\ g0' = "quickChallenge"
    /\ fs1' = "quickChallenge"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, pc1, kickoffAt, late>>

\* Action: ChallengeIncompleteKickoff_0 lands (Guardian_0 +
\* PrekickoffConn_1). Generous to the current design: node code only
\* DETECTS it, it never broadcasts it.
\* Source: environment (any holder of the presigned tx); detection only in
\* node/src/utils/graph_chain_state.rs:152-158.
ChallengeIncompleteKickoff ==
    /\ CIKEnabled
    /\ g0' = "cik"
    /\ pc1' = "cik"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, fs1, kickoffAt, late>>

---------------------------------------------------------------------------

\* Action: one block; blocked while a watcher penalty is due.
\* Source: Bitcoin consensus.
Mine ==
    /\ now < Horizon
    /\ ~PenaltyDue
    /\ now' = now + 1
    /\ UNCHANGED <<params, prek1, prek1At, kc0, fs1, pc1, g0, kickoffAt, late>>

\* Action: end of the horizon - stutter (not a deadlock).
\* Source: model bound (no code).
Halt == Done /\ UNCHANGED vars

Next ==
    \/ OpKickoff
    \/ OpSkip
    \/ OpPrekickoff1
    \/ OpPrekickoff2
    \/ OpBurnForceSkipConn
    \/ OpTake
    \/ ForceSkipKickoff
    \/ QuickChallenge
    \/ ChallengeIncompleteKickoff
    \/ Mine
    \/ Halt

\* No fairness: the only property is a safety invariant; watcher progress
\* is forced by PenaltyDue on Mine, not by WF/SF.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* A kickoff broadcast after the next round started loses its Guardian to
\* a penalty, i.e. never reaches Take1/Take2.
LateKickoffPenalized == ~(late /\ g0 = "take")

(* Safety properties (temporal): none.                                     *)
(* Liveness: none (bounded horizon).                                       *)

====
