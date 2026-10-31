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
(*    the operator key as taproot internal key                            *)
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
(* (the node skips a slot via operator_skip_kickoff on KickoffConn,        *)
(* node/src/utils/graph_tx.rs:291-316), so nothing else needs that key.    *)
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
(* Abstractions: one slot i = 0; watchers broadcast an enabled penalty     *)
(* within Reaction blocks; TakeCSV (> Reaction) stands for the Take1/Take2 *)
(* timelocks after the kickoff; the operator may chain several txs into    *)
(* one block (no Mine between its steps).                                  *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    ForceSkipNofN,  \* FIX: ForceSkipConnector is n-of-n instead of operator-only
    TakeCSV,        \* blocks after Kickoff_0 before the operator can Take
    Reaction,       \* blocks within which watchers broadcast an enabled penalty
    MaxT

ASSUME Reaction < TakeCSV

VARIABLES
    now,
    prek1,      \* Prekickoff_1 (round 1) confirmed
    prek1At,    \* ... at this height
    kc0,        \* KickoffConn_0: "unspent" | "kickoff" | "skipped" | "forceSkipped"
    fs1,        \* ForceSkipConn_1: "none" | "unspent" | "forceSkip" | "quickChallenge" | "operator"
    pc1,        \* PrekickoffConn_1: "none" | "unspent" | "prek2" | "cik"
    g0,         \* Guardian_0: "none" | "unspent" | "take" | "quickChallenge" | "cik"
    kickoffAt,
    late,       \* Kickoff_0 broadcast in a block AFTER the one that confirmed round 1
    wait        \* blocks a penalty has been enabled without being broadcast

vars == <<now, prek1, prek1At, kc0, fs1, pc1, g0, kickoffAt, late, wait>>

TypeOK ==
    /\ now \in 0..MaxT
    /\ prek1 \in BOOLEAN
    /\ prek1At \in 0..MaxT
    /\ kc0 \in {"unspent", "kickoff", "skipped", "forceSkipped"}
    /\ fs1 \in {"none", "unspent", "forceSkip", "quickChallenge", "operator"}
    /\ pc1 \in {"none", "unspent", "prek2", "cik"}
    /\ g0 \in {"none", "unspent", "take", "quickChallenge", "cik"}
    /\ kickoffAt \in 0..MaxT
    /\ late \in BOOLEAN
    /\ wait \in 0..Reaction

\* Round 0 (Prekickoff_0) is confirmed: KickoffConn_0 exists.
Init ==
    /\ now = 0
    /\ prek1 = FALSE
    /\ prek1At = 0
    /\ kc0 = "unspent"
    /\ fs1 = "none"
    /\ pc1 = "none"
    /\ g0 = "none"
    /\ kickoffAt = 0
    /\ late = FALSE
    /\ wait = 0

---------------------------------------------------------------------------
(* Operator (possibly malicious; operator-key spends are unconstrained).  *)

OpKickoff ==
    /\ kc0 = "unspent"
    /\ kc0' = "kickoff"
    /\ g0' = "unspent"
    /\ kickoffAt' = now
    /\ late' = (prek1 /\ now > prek1At)
    /\ UNCHANGED <<now, prek1, prek1At, fs1, pc1, wait>>

\* operator_skip_kickoff (prekickoff.rs:21-63): the honest way to skip.
OpSkip ==
    /\ kc0 = "unspent"
    /\ kc0' = "skipped"
    /\ UNCHANGED <<now, prek1, prek1At, fs1, pc1, g0, kickoffAt, late, wait>>

OpPrekickoff1 ==
    /\ ~prek1
    /\ prek1' = TRUE
    /\ prek1At' = now
    /\ fs1' = "unspent"
    /\ pc1' = "unspent"
    /\ UNCHANGED <<now, kc0, g0, kickoffAt, late, wait>>

OpPrekickoff2 ==
    /\ pc1 = "unspent"
    /\ pc1' = "prek2"
    /\ UNCHANGED <<now, prek1, prek1At, kc0, fs1, g0, kickoffAt, late, wait>>

\* THE BUG: ForceSkipConn_1 is operator-key-only.
OpBurnForceSkipConn ==
    /\ ~ForceSkipNofN
    /\ fs1 = "unspent"
    /\ fs1' = "operator"
    /\ UNCHANGED <<now, prek1, prek1At, kc0, pc1, g0, kickoffAt, late, wait>>

\* Take1 / Take2 (both consume Guardian_0) after the timelock.
OpTake ==
    /\ g0 = "unspent"
    /\ now >= kickoffAt + TakeCSV
    /\ g0' = "take"
    /\ UNCHANGED <<now, prek1, prek1At, kc0, fs1, pc1, kickoffAt, late, wait>>

---------------------------------------------------------------------------
(* Watchers (anyone holding the presigned SIGHASH_NONE penalties).        *)

ForceSkipEnabled == kc0 = "unspent" /\ fs1 = "unspent"
QCEnabled        == g0 = "unspent" /\ fs1 = "unspent"
CIKEnabled       == g0 = "unspent" /\ pc1 = "unspent"
PenaltyEnabled   == ForceSkipEnabled \/ QCEnabled \/ CIKEnabled

ForceSkipKickoff ==
    /\ ForceSkipEnabled
    /\ kc0' = "forceSkipped"
    /\ fs1' = "forceSkip"
    /\ UNCHANGED <<now, prek1, prek1At, pc1, g0, kickoffAt, late, wait>>

QuickChallenge ==
    /\ QCEnabled
    /\ g0' = "quickChallenge"
    /\ fs1' = "quickChallenge"
    /\ UNCHANGED <<now, prek1, prek1At, kc0, pc1, kickoffAt, late, wait>>

ChallengeIncompleteKickoff ==
    /\ CIKEnabled
    /\ g0' = "cik"
    /\ pc1' = "cik"
    /\ UNCHANGED <<now, prek1, prek1At, kc0, fs1, kickoffAt, late, wait>>

---------------------------------------------------------------------------
Mine ==
    /\ now < MaxT
    /\ PenaltyEnabled => wait < Reaction
    /\ now' = now + 1
    /\ wait' = IF PenaltyEnabled THEN wait + 1 ELSE 0
    /\ UNCHANGED <<prek1, prek1At, kc0, fs1, pc1, g0, kickoffAt, late>>

Next ==
    \/ OpKickoff \/ OpSkip \/ OpPrekickoff1 \/ OpPrekickoff2
    \/ OpBurnForceSkipConn \/ OpTake
    \/ ForceSkipKickoff \/ QuickChallenge \/ ChallengeIncompleteKickoff
    \/ Mine

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* A kickoff broadcast after the next round started must lose its Guardian
\* to a penalty, i.e. never reach Take1/Take2.
LateKickoffPenalized == ~(late /\ g0 = "take")

====
