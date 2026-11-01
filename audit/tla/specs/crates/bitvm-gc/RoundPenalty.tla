---- MODULE RoundPenalty ----
(***************************************************************************)
(* Late kickoffs escape every on-chain penalty because the penalty txs     *)
(*   spend operator-key-only connectors (audit M5).                        *)
(* Code: goat bab46c2: Prekickoff_{i+1}                                    *)
(*   (goat/src/transactions/prekickoff.rs:93-181, operator-signed) creates *)
(*   ForceSkipConn_{i+1}, KickoffConn_{i+1} and PrekickoffConn_{i+1};      *)
(*   every kickoff connector is <operator_pk> OP_CHECKSIG                  *)
(*   (connectors/kickoff_connectors.rs:14-227). The SIGHASH_NONE penalties *)
(*   of slot i (wired in crates/bitvm-gc/src/operator/api.rs:150-167):     *)
(*   ForceSkipKickoff_i = KickoffConn_i + ForceSkipConn_{i+1},             *)
(*   QuickChallenge_i = Guardian_i + ForceSkipConn_{i+1},                  *)
(*   ChallengeIncompleteKickoff_i = Guardian_i + PrekickoffConn_{i+1};     *)
(*   Guardian_i is a Take1/Take2 input. Node: enforce_previous_slot        *)
(*   (node/src/aggregates/graph_pegout_jobs.rs:506-592) sends ForceSkip or *)
(*   QuickChallenge; ChallengeIncompleteKickoff is only detected.          *)
(* M5: the operator burns ForceSkipConn_1 in the block that creates it and *)
(*   advances to round 2 in the same block, so no penalty is ever enabled  *)
(*   at a confirmed tip; it then kicks off slot 0 late and takes.          *)
(*   Timing-independent. The model lets watchers send                      *)
(*   ChallengeIncompleteKickoff (the node does not).                       *)
(* Fix: ForceSkipConnector becomes n-of-n, so QuickChallenge_i stays valid *)
(*   once round i+1 exists. A CSV on the operator leaf is not enough: the  *)
(*   operator burns the connector after it expires.                        *)
(* Parameters: see CONSTANTS. One slot (i = 0); the operator may chain     *)
(*   several txs into one block.                                           *)
(* ParamsOK (fix, exact - Boundary.cfg): react + incl + 1 <= takecsv.      *)
(*   validate_timelock_config (connector_a >= react + incl + safety)       *)
(*   implies it only when safety >= 1; all shipped values satisfy it.      *)
(* Exhaustive: the only timing relation is a watcher's latest landing      *)
(*   (event + react + incl) vs the Take maturity (kickoff + takecsv);      *)
(*   react 1..2, incl 0..2, takecsv 1..6 give margin <= -1, 0 and >= +1    *)
(*   for every split.                                                      *)
(* Configs: configs/crates/bitvm-gc/RoundPenalty/, tiers in                *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    ForceSkipNofN,  \* FIX: ForceSkipConnector is n-of-n instead of operator-only
    UseShipped,     \* parameters from ShippedTimelockValues (per net in NetSet)
    NetSet,         \* subset of Networks swept when UseShipped
    TakeCSVRange,   \* blocks after Kickoff_0 before Take1 (connector_a; Take2 is later)
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

\* Every event of interest has happened by then.
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

\* Action: Kickoff_0 confirms (spends KickoffConn_0, creates Guardian_0); "late" if round 1 confirmed earlier.
\* Source: kickoff(), node/src/aggregates/graph_pegout_jobs.rs:261-303, via operator_kickoff(), node/src/utils/graph_tx.rs:328-396.
OpKickoff ==
    /\ kc0 = "unspent"
    /\ kc0' = "kickoff"
    /\ g0' = "unspent"
    /\ kickoffAt' = now + 1
    /\ late' = (prek1 /\ now + 1 > prek1At)
    /\ UNCHANGED <<params, now, prek1, prek1At, fs1, pc1>>

\* Action: the operator skips slot 0 honestly (SkipKickoff spends KickoffConn_0).
\* Source: operator_skip_graph(), node/src/utils/graph_tx.rs:263-326; crates/bitvm-gc/src/operator/api.rs:453-491.
OpSkip ==
    /\ kc0 = "unspent"
    /\ kc0' = "skipped"
    /\ UNCHANGED <<params, now, prek1, prek1At, fs1, pc1, g0, kickoffAt, late>>

\* Action: Prekickoff_1 confirms (spends PrekickoffConn_0, creates ForceSkipConn_1 and PrekickoffConn_1).
\* Source: node/src/utils/graph_tx.rs:270, :332 (operator_sign_prekickoff_input_0); goat transactions/prekickoff.rs:93-181.
OpPrekickoff1 ==
    /\ ~prek1
    /\ prek1' = TRUE
    /\ prek1At' = now + 1
    /\ fs1' = "unspent"
    /\ pc1' = "unspent"
    /\ UNCHANGED <<params, now, kc0, g0, kickoffAt, late>>

\* Action: Prekickoff_2 confirms, spending PrekickoffConn_1 (kills ChallengeIncompleteKickoff_0).
\* Source: as OpPrekickoff1, for the next round.
OpPrekickoff2 ==
    /\ pc1 = "unspent"
    /\ pc1' = "prek2"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, fs1, g0, kickoffAt, late>>

\* Action: M5 - the operator spends ForceSkipConn_1 to itself, killing ForceSkipKickoff_0 and QuickChallenge_0.
\* Source: environment (operator key); ForceSkipConnector is <operator_pk> OP_CHECKSIG, goat kickoff_connectors.rs:176-196.
OpBurnForceSkipConn ==
    /\ ~ForceSkipNofN
    /\ fs1 = "unspent"
    /\ fs1' = "operator"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, pc1, g0, kickoffAt, late>>

\* Action: Take1 or Take2 (both spend Guardian_0) confirms, from block kickoffAt + takecsv on.
\* Source: take1(), node/src/aggregates/graph_pegout_jobs.rs:1470-1497; goat take1.rs:82-83, take2.rs:76-77.
OpTake ==
    /\ g0 = "unspent"
    /\ now + 1 >= kickoffAt + takecsv
    /\ g0' = "take"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, fs1, pc1, kickoffAt, late>>

---------------------------------------------------------------------------
(* Watchers (anyone holding the presigned SIGHASH_NONE penalties). A       *)
(* penalty needs its inputs confirmed and lands by event + react + incl.   *)

Max2(a, b) == IF a >= b THEN a ELSE b

ForceSkipEnabled == kc0 = "unspent" /\ fs1 = "unspent" /\ now >= prek1At
QCEnabled        == g0 = "unspent" /\ fs1 = "unspent" /\ now >= Max2(kickoffAt, prek1At)
CIKEnabled       == g0 = "unspent" /\ pc1 = "unspent" /\ now >= Max2(kickoffAt, prek1At)

\* Block whose confirmation enabled the penalty; the reaction restarts on each new event.
ForceSkipFrom == prek1At
QCFrom        == Max2(kickoffAt, prek1At)
PenaltyDue ==
    \/ ForceSkipEnabled /\ now + 1 >= ForceSkipFrom + react + incl
    \/ (QCEnabled \/ CIKEnabled) /\ now + 1 >= QCFrom + react + incl

\* Action: ForceSkipKickoff_0 confirms (KickoffConn_0 + ForceSkipConn_1): slot 0 can no longer kick off.
\* Source: enforce_previous_slot(), node/src/aggregates/graph_pegout_jobs.rs:570-579; node/src/utils/graph_tx.rs:41-70.
ForceSkipKickoff ==
    /\ ForceSkipEnabled
    /\ kc0' = "forceSkipped"
    /\ fs1' = "forceSkip"
    /\ UNCHANGED <<params, now, prek1, prek1At, pc1, g0, kickoffAt, late>>

\* Action: QuickChallenge_0 confirms (Guardian_0 + ForceSkipConn_1): the slot's payout is dead.
\* Source: enforce_previous_slot(), node/src/aggregates/graph_pegout_jobs.rs:584-591; node/src/utils/graph_tx.rs:72-99.
QuickChallenge ==
    /\ QCEnabled
    /\ g0' = "quickChallenge"
    /\ fs1' = "quickChallenge"
    /\ UNCHANGED <<params, now, prek1, prek1At, kc0, pc1, kickoffAt, late>>

\* Action: ChallengeIncompleteKickoff_0 confirms (Guardian_0 + PrekickoffConn_1); the node never sends it.
\* Source: environment (any holder of the presigned tx); node detection only, node/src/utils/graph_chain_state.rs:152-158.
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

\* Action: stutter at the horizon (not a deadlock).
\* Source: model bound.
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

\* No fairness: watcher progress is forced by PenaltyDue on Mine.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* A late kickoff never reaches Take1/Take2.
LateKickoffPenalized == ~(late /\ g0 = "take")

====
