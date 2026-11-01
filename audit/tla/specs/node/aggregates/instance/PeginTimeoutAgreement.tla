---- MODULE PeginTimeoutAgreement ----
(***************************************************************************)
(* Two committee nodes decide one peg-in: n1 (relayer, buffer b1) and n2   *)
(* (b2). decide_btc_snapshot (node/src/aggregates/instance.rs:500-505)     *)
(* times out at H_p + T0 + B unless THIS node's backend shows the Confirm  *)
(* in its mempool (TxFact, instance.rs:201-203); B is per node (env.rs:    *)
(* 184-190). From Timeout a confirmed Confirm only alerts (instance.rs:    *)
(* 463-465), and the post job is queued only on entering                   *)
(* RelayerL1Broadcasted (instance.rs:792-795). The relayer broadcasts only *)
(* while tip < H_p + T0, always the same presigned tx (fixed fee, no       *)
(* bump); anyone holding the signed tx can broadcast it later.             *)
(* Finding M2: nodes can disagree (Agreement), and a confirmed Confirm may *)
(*   never be minted (MintAfterConfirm).                                   *)
(* Parameters (frozen variables): t0, b1, b2, incl (a pending Confirm      *)
(*   lands at most incl blocks after its broadcast unless a Cancel wins).  *)
(*   NetSet = {}: sweep the *Range constants; shipped: ConnectorZ,         *)
(*   PeginAbandonBufferBlocks, incl = max(1, InclusionBlocks) ("budget")   *)
(*   or B + 2 ("stuck"). ByzBroadcast: a member broadcasts at any height.  *)
(* Fix "revert": Timeout + confirmed Confirm -> RelayerL1Broadcasted,      *)
(*   needs no margin (no ParamsOK). "relayerPosts" fixes only              *)
(*   MintAfterConfirm.                                                     *)
(*   The current code with honest broadcasters holds iff HonestOk, exact.  *)
(* Exhaustiveness: the guards compare the tip with H_p + T0, H_p + T0 +    *)
(*   B_n and bcast + incl; a node can time out on a pending honest Confirm *)
(*   iff incl >= B_n + 2, so B 1..3 and incl 1..6 cover every class with   *)
(*   margins 0 and 1. T0 >= incl + 2 is a translate and a smaller T0 only  *)
(*   clips the window H0..MaxH: T0 in {1, 2, 8}.                           *)
(* Configs: configs/node/aggregates/instance/PeginTimeoutAgreement/, tiers *)
(*   in audit/tla/checks.txt.                                              *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    NetSet,         \* {} = generic sweep, else the networks whose shipped values to use
    T0Range,        \* generic sweep: connector_z CSV values
    B1Range,        \* generic sweep: relayer n1's abandon buffer values
    B2Range,        \* generic sweep: node n2's abandon buffer values
    InclRange,      \* generic sweep: Confirm inclusion delay bounds
    ShippedIncl,    \* shipped: "budget" (max(1, InclusionBlocks)) | "stuck" (B + 2)
    ParamFilter,    \* "all" | "honestOK" (HonestOk) | "honestNotOK"
    Fix,            \* "none" | "revert" | "relayerPosts"
    ByzBroadcast    \* a Byzantine committee member may broadcast the Confirm at any height

ASSUME /\ Fix \in {"none", "revert", "relayerPosts"}
       /\ NetSet \subseteq Networks
       /\ ShippedIncl \in {"budget", "stuck"}
       /\ ParamFilter \in {"all", "honestOK", "honestNotOK"}
       /\ T0Range \cup B1Range \cup B2Range \cup InclRange \subseteq Nat \ {0}

\* InstanceBridgeInStatus values a node can take.
Presigned            == "Presigned"
RelayerL1Broadcasted == "RelayerL1Broadcasted"
RelayerL2Minted      == "RelayerL2Minted"
Timeout              == "Timeout"
UserCanceled         == "UserCanceled"
Statuses == {Presigned, RelayerL1Broadcasted, RelayerL2Minted, Timeout, UserCanceled}

\* Peg-In-Confirm states.
NotSent   == "none"        \* nobody holds it
Pending   == "pending"     \* some miner/mempool holds it
Confirmed == "confirmed"
ConfirmStates == {NotSent, Pending, Confirmed}

Nodes == {"n1", "n2"}
Relayers == {"n1"}       \* is_relayer() (env.rs:255), per node
Hp == 1                  \* Peg-In-Prepare height (only differences matter)
Generic == "generic"     \* net value of a generic-sweep run
Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

VARIABLES
    net,      \* frozen: network whose shipped values are used (Generic in a sweep)
    t0,       \* frozen: connector_z CSV
    b1,       \* frozen: relayer n1's abandon buffer
    b2,       \* frozen: node n2's abandon buffer
    incl,     \* frozen: inclusion delay bound of a pending Confirm
    h,        \* Bitcoin tip
    confirm,  \* Peg-In-Confirm state (ConfirmStates)
    bcastAt,  \* tip at which the pending Confirm was broadcast
    seen,     \* seen[n]: node n's backend reports the Confirm in its mempool
    cancel,   \* Peg-In-Cancel confirmed
    status,   \* status[n]: node n's instance status
    postJob,  \* postJob[n]: JOB_POST_PEGIN_DATA queued on n
    minted    \* Goat BridgeIn

params == <<net, t0, b1, b2, incl>>
vars == <<params, h, confirm, bcastAt, seen, cancel, status, postJob, minted>>

B == [n \in Nodes |-> IF n = "n1" THEN b1 ELSE b2]   \* abandon buffer per node
\* First tip: an earlier honest broadcast is mined by H_p + T0 - 1, like one here.
H0 == Max(Hp, Hp + t0 - incl - 1)
\* Last tip: every honest Confirm and a Byzantine one sent after every abandon
\* height have landed.
MaxH == Hp + t0 + Max(b1, b2) + incl + 1

\* Current code, honest broadcasters: no node can time out on a pending Confirm.
HonestOk == incl <= Min(b1, b2) + 1

InitParams ==
    /\ IF NetSet = {}
          THEN /\ net = Generic
               /\ t0 \in T0Range /\ b1 \in B1Range /\ b2 \in B2Range /\ incl \in InclRange
          ELSE /\ net \in NetSet
               /\ t0 = ConnectorZ[net]
               /\ b1 = PeginAbandonBufferBlocks[net] /\ b2 = b1
               /\ incl = IF ShippedIncl = "budget" THEN Max(1, InclusionBlocks[net])
                         ELSE PeginAbandonBufferBlocks[net] + 2
    /\ CASE ParamFilter = "all"      -> TRUE
         [] ParamFilter = "honestOK" -> HonestOk
         [] OTHER                    -> ~HonestOk

TypeOk ==
    /\ net \in NetSet \cup {Generic}
    /\ t0 \in Nat \ {0} /\ b1 \in Nat \ {0} /\ b2 \in Nat \ {0} /\ incl \in Nat \ {0}
    /\ h \in H0..MaxH
    /\ confirm \in ConfirmStates
    /\ bcastAt \in 0..MaxH
    /\ seen \in [Nodes -> BOOLEAN]
    /\ cancel \in BOOLEAN
    /\ status \in [Nodes -> Statuses]
    /\ postJob \in [Nodes -> BOOLEAN]
    /\ minted \in BOOLEAN

Init ==
    /\ InitParams
    /\ h = H0
    /\ confirm = NotSent /\ bcastAt = 0
    /\ seen = [n \in Nodes |-> FALSE]
    /\ cancel = FALSE
    /\ status = [n \in Nodes |-> Presigned]
    /\ postJob = [n \in Nodes |-> FALSE]
    /\ minted = FALSE

NoSeen == [n \in Nodes |-> FALSE]   \* no backend shows the Confirm in its mempool

--------------------------------------------------------------------------
(* Actions: environment *)

\* Action: a new block carries the pending Confirm, the CSV-valid Cancel, or
\* neither; not neither at the Confirm's inclusion deadline bcastAt + incl.
\* Source: Bitcoin consensus
Mine ==
    /\ h < MaxH /\ h' = h + 1
    /\ \/ /\ confirm = Pending
          /\ confirm' = Confirmed /\ seen' = NoSeen
          /\ UNCHANGED cancel
       \/ /\ h + 1 >= Hp + t0 /\ confirm # Confirmed /\ ~cancel
          /\ cancel' = TRUE /\ confirm' = NotSent /\ seen' = NoSeen
       \/ /\ ~(confirm = Pending /\ h + 1 >= bcastAt + incl)
          /\ UNCHANGED <<confirm, seen, cancel>>
    /\ UNCHANGED <<params, bcastAt, status, postJob, minted>>

\* Action: the relayer broadcasts the aggregated Confirm while tip < H_p + T0
\* and no Cancel is confirmed; its own backend sees it.
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900-960
\* Source: pegin_confirm_broadcast_blocked() in node/src/aggregates/instance_jobs.rs:875-893
RelayerBroadcast(n) ==
    /\ n \in Relayers /\ status[n] = Presigned /\ h < Hp + t0
    /\ confirm = NotSent /\ ~cancel
    /\ confirm' = Pending /\ bcastAt' = h /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<params, h, cancel, status, postJob, minted>>

\* Action: a Byzantine committee member aggregates the gossiped partial
\* signatures and broadcasts at any height.
\* Source: environment (Byzantine member; partial sigs sent by pegin_confirm_sign(),
\*   node/src/aggregates/instance_jobs.rs:765-776)
ByzantineBroadcast ==
    /\ ByzBroadcast /\ confirm = NotSent /\ ~cancel /\ h + incl <= MaxH
    /\ confirm' = Pending /\ bcastAt' = h
    /\ UNCHANGED <<params, h, seen, cancel, status, postJob, minted>>

\* Action: node n's backend learns the pending Confirm.
\* Source: environment (mempool propagation); tx_fact() in node/src/aggregates/instance_scan.rs:257-266
Propagate(n) ==
    /\ confirm = Pending /\ ~seen[n]
    /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, cancel, status, postJob, minted>>

\* Action: node n's backend drops the pending Confirm (eviction, restart).
\* Source: environment (eviction, restart); tx_fact() in node/src/aggregates/instance_scan.rs:257-266
Evict(n) ==
    /\ confirm = Pending /\ seen[n]
    /\ seen' = [seen EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, cancel, status, postJob, minted>>

--------------------------------------------------------------------------
(* Actions: per-node decisions *)

\* Action: node n's scan: confirmed Confirm -> RelayerL1Broadcasted (post job
\* on a relayer); confirmed Cancel -> UserCanceled; past H_p + T0 + B[n] with
\* the Confirm not in its mempool -> Timeout (post job cancelled); from
\* Timeout only a Cancel moves on, unless a Fix applies.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:456-468,489-505
\* Source: on_entered() in node/src/aggregates/instance.rs:790-795
\* Source: enter_failure() in node/src/aggregates/instance.rs:842-844
Scan(n) ==
    /\ LET s == status[n]
           rel == n \in Relayers
       IN
       \/ /\ s = Presigned /\ confirm = Confirmed
          /\ status' = [status EXCEPT ![n] = RelayerL1Broadcasted]
          /\ postJob' = [postJob EXCEPT ![n] = rel]
       \/ /\ s = Presigned /\ confirm # Confirmed /\ cancel
          /\ status' = [status EXCEPT ![n] = UserCanceled]
          /\ postJob' = [postJob EXCEPT ![n] = FALSE]
       \/ /\ s = Presigned /\ confirm # Confirmed /\ ~cancel
          /\ h >= Hp + t0 + B[n] /\ ~seen[n]
          /\ status' = [status EXCEPT ![n] = Timeout]
          /\ postJob' = [postJob EXCEPT ![n] = FALSE]   \* cancel_phase_jobs(PHASE_POST)
       \/ /\ s = Timeout /\ cancel
          /\ status' = [status EXCEPT ![n] = UserCanceled]
          /\ UNCHANGED postJob
       \* Timeout + confirmed Confirm: the code only alerts (no step).
       \/ /\ s = Timeout /\ ~cancel /\ confirm = Confirmed /\ Fix = "revert"
          /\ status' = [status EXCEPT ![n] = RelayerL1Broadcasted]
          /\ postJob' = [postJob EXCEPT ![n] = rel]
       \/ /\ s = Timeout /\ ~cancel /\ confirm = Confirmed /\ Fix = "relayerPosts"
          /\ rel /\ ~postJob[n] /\ ~minted
          /\ postJob' = [postJob EXCEPT ![n] = TRUE]
          /\ UNCHANGED status
    /\ UNCHANGED <<params, h, confirm, bcastAt, seen, cancel, minted>>

\* Action: the relayer's post job mints on Goat (the Confirm is confirmed).
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:984
\* Source: Gateway.sol postPeginData
Post(n) ==
    /\ postJob[n] /\ ~minted /\ confirm = Confirmed
    /\ minted' = TRUE
    /\ postJob' = [postJob EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, seen, cancel, status>>

\* Action: node n sees the Goat BridgeIn: success from a live state; a failed
\* node only alerts.
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
SeeMint(n) ==
    /\ minted /\ status[n] \in {Presigned, RelayerL1Broadcasted}
    /\ status' = [status EXCEPT ![n] = RelayerL2Minted]
    /\ UNCHANGED <<params, h, confirm, bcastAt, seen, cancel, postJob, minted>>

Next ==
    \/ Mine
    \/ ByzantineBroadcast
    \/ \E n \in Nodes : RelayerBroadcast(n)
    \/ \E n \in Nodes : Propagate(n)
    \/ \E n \in Nodes : Evict(n)
    \/ \E n \in Nodes : Scan(n)
    \/ \E n \in Nodes : Post(n)
    \/ \E n \in Nodes : SeeMint(n)

\* Fairness: blocks keep coming; every node keeps scanning and running its
\* queued jobs. Propagation, eviction, broadcasts and the Cancel are not fair.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Mine)
    /\ \A n \in Nodes : WF_vars(Scan(n)) /\ WF_vars(Post(n)) /\ WF_vars(SeeMint(n))

--------------------------------------------------------------------------
\* A node's view of the peg-in's outcome.
Outcome(s) ==
    CASE s \in {RelayerL1Broadcasted, RelayerL2Minted} -> "pegged"
      [] s = UserCanceled -> "canceled"
      [] s = Timeout -> "abandoned"
      [] OTHER -> "open"

(* Safety invariants *)

\* No mint without a confirmed Peg-In-Confirm.
MintOnlyAfterConfirm == minted => confirm = Confirmed

(* Liveness *)

\* The nodes eventually agree on one terminal outcome.
Agreement ==
    <>[](\A n, m \in Nodes : Outcome(status[n]) = Outcome(status[m])
                             /\ Outcome(status[n]) # "open")

\* A confirmed Peg-In-Confirm (BTC under the n-of-n) is eventually minted.
MintAfterConfirm == (confirm = Confirmed) ~> minted

====
