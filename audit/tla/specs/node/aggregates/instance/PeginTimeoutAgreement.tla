---- MODULE PeginTimeoutAgreement ----
(***************************************************************************)
(* PURPOSE. M2: Timeout is a per-node decision, but Peg-In-Confirm is      *)
(* global - honest nodes can disagree on a peg-in's outcome, and a         *)
(* confirmed Confirm (user BTC under n-of-n) may never be minted.          *)
(*                                                                         *)
(* CODE SCOPE (dev 60562f8, after #476):                                   *)
(*  node/src/aggregates/instance.rs:442-527 decide_btc_snapshot, step 2    *)
(*    (497-503): Timeout once snapshot.height >= abandon_height (H_p+T0+B, *)
(*    instance.rs:183) and !confirm.in_mempool. in_mempool is THIS node's  *)
(*    backend view (tx_fact, node/src/aggregates/instance_scan.rs:257-266; *)
(*    TxFact doc instance.rs:201-203). B is per node (node/src/env.rs:     *)
(*    184-190 PEGIN_ABANDON_BUFFER_BLOCKS, clamp 1..100000; default        *)
(*    PeginAbandonBufferBlocks = evidence+inclusion+safety, regtest 6).    *)
(*  instance.rs:456-468: from Timeout only a confirmed Cancel moves on; a  *)
(*    confirmed Confirm raises PeginConfirmAfterTimeout and nothing else.  *)
(*  instance.rs:826-864 enter_failure: graphs obsoleted, the outbox        *)
(*    closed, ANSWER/PRESIGN/CONFIRM/POST jobs cancelled.                  *)
(*  instance.rs:773-797 on_entered: JOB_POST_PEGIN_DATA is enqueued only   *)
(*    on ENTERING RelayerL1Broadcasted, on a relayer (env.rs:255 is_relayer*)
(*    = per-node ENABLE_RELAYER).                                          *)
(*  instance.rs:561-571 decide_l2_minted: a failed instance only alerts.   *)
(*  instance_scan.rs:162-178,228-239: a Timeout instance whose Confirm      *)
(*    confirmed leaves the scan (SETTLED_TIMEOUTS).                        *)
(*  node/src/aggregates/instance_jobs.rs:875-947: the relayer broadcasts   *)
(*    (and re-broadcasts, instance.rs:575 rebroadcast_due) only while tip  *)
(*    < H_p+T0, always the SAME presigned tx: its fee is fixed and never   *)
(*    bumped, so the InclusionBlocks budget ("including fee bumping") does *)
(*    not bound its inclusion; a fee spike can hold it. Once broadcast the *)
(*    raw tx is public (anyone re-relays it); a Byzantine committee member *)
(*    holding the gossiped partial signatures can broadcast it at any time.*)
(*                                                                         *)
(* MODEL. Two committee nodes: n1 (the relayer, buffer b1) and n2 (b2).    *)
(* Each node's mempool view of the pending Confirm flips nondeterministic- *)
(* ally (propagation, eviction, restart, backend differences). Nodes scan  *)
(* and run jobs at arbitrary times (weak fairness only).                   *)
(*                                                                         *)
(* PARAMETERS (frozen variables): t0 (connector_z CSV), b1/b2 (abandon     *)
(* buffers), incl (a pending Confirm lands at most incl blocks after the   *)
(* tip it was broadcast at, unless a Cancel wins first). Generic sweep     *)
(* (NetSet = {}): from the *Range constants. Shipped: t0 = ConnectorZ[net],*)
(* b1 = b2 = PeginAbandonBufferBlocks[net], incl = max(1, InclusionBlocks  *)
(* [net]) (ShippedIncl = "budget") or b + 2 ("stuck": held by a fee spike  *)
(* just past the buffer).                                                  *)
(*                                                                         *)
(* EXHAUSTIVENESS. The guards compare the tip with H_p+T0 (gate, CSV),     *)
(* with H_p+T0+B_n (abandon) and with bcast+incl (inclusion deadline). For *)
(* an honest broadcast (bcast <= H_p+T0-1) a node can time out with the    *)
(* Confirm still pending iff incl >= B_n + 2, so the classes are incl-B_n  *)
(* in {<= 1, 2, >= 3} per node and the order of B1, B2: B \in 1..3, incl   *)
(* \in 1..6 covers them with ties and margins 0, 1. T0 only matters through*)
(* the window clip: every T0 >= incl + 2 gives a translate, and a smaller  *)
(* T0 only drops early broadcasts that are equivalent to one at the window *)
(* start (below), so T0 \in {1, 2, 8} (clipped, clipped, translate).       *)
(*                                                                         *)
(* WINDOW. The model starts at tip max(Hp, H_p+T0-incl-1) with nothing     *)
(* broadcast: an earlier honest broadcast is mined by H_p+T0-1, before any *)
(* Cancel or Timeout is possible, exactly like a broadcast at the window   *)
(* start. It stops at H_p+T0+max(B)+incl+1: every honest Confirm lands by  *)
(* then, and a Byzantine broadcast is allowed up to incl blocks before the *)
(* end, i.e. after every node's abandon height (the latest interesting     *)
(* case), so its inclusion deadline also lies inside the window.           *)
(*                                                                         *)
(* FIX (constant Fix): "none" = current code; "revert" = Timeout +         *)
(* confirmed Confirm -> RelayerL1Broadcasted (post job on a relayer), the  *)
(* outcome converges; ParamsOK = TRUE (no timing margin needed, verified   *)
(* over the whole sweep with the Byzantine broadcaster on), so there is no *)
(* boundary config. "relayerPosts" = the relayer posts whenever it sees    *)
(* the Confirm confirmed, even in Timeout: mint is live, Agreement is not. *)
(* Current code with honest broadcasters only is safe iff HonestOk (incl   *)
(* <= B+1 for every node; for MintAfterConfirm only the relayer's B1       *)
(* counts) - EXACT, checked point by point (108 points).                   *)
(*                                                                         *)
(* CONFIGS -> TIERS (audit/tla/checks.txt):                                *)
(*   live   PeginTimeoutAgreement/M2.cfg, ...Mint.cfg (honest-only sweep,     *)
(*          incl up to 6 > B+1), ...Shipped.cfg (late Byzantine broadcast, *)
(*          shipped values)                                                *)
(*   pass   PeginTimeoutAgreement/ShippedHonest.cfg (current code, shipped, *)
(*          honest broadcasters, Confirm within the inclusion budget)      *)
(*   design PeginTimeoutAgreement/Fixed.cfg, ...FixedShipped.cfg (revert), *)
(*          ...RelayerPosts.cfg (partial fix, mint only)                   *)
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

\* Instance statuses (InstanceBridgeInStatus).
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
Relayers == {"n1"}
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
    status,   \* status[n]
    postJob,  \* postJob[n]: JOB_POST_PEGIN_DATA queued on n
    minted    \* Goat BridgeIn

params == <<net, t0, b1, b2, incl>>
vars == <<params, h, confirm, bcastAt, seen, cancel, status, postJob, minted>>

B == [n \in Nodes |-> IF n = "n1" THEN b1 ELSE b2]
H0 == Max(Hp, Hp + t0 - incl - 1)          \* window start (see header)
MaxH == Hp + t0 + Max(b1, b2) + incl + 1   \* window end (see header)

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

NoSeen == [n \in Nodes |-> FALSE]

--------------------------------------------------------------------------
(* Actions: environment *)

\* Action: a new block carries the pending Confirm, or the CSV-valid Cancel
\*   (they conflict), or neither - but not "neither/other" once this block
\*   is the Confirm's inclusion deadline (bcastAt + incl).
\* Source: Bitcoin consensus (connector_z leaf 1 CSV T0 for the Cancel)
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

\* Action: the relayer's broadcast job sends the aggregated Confirm while the
\*   gate is open (tip < H_p+T0) and no Cancel is confirmed; its own backend
\*   sees it.
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900;
\*   pegin_confirm_broadcast_blocked() instance_jobs.rs:875
RelayerBroadcast(n) ==
    /\ n \in Relayers /\ status[n] = Presigned /\ h < Hp + t0
    /\ confirm = NotSent /\ ~cancel
    /\ confirm' = Pending /\ bcastAt' = h /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<params, h, cancel, status, postJob, minted>>

\* Action: a Byzantine committee member aggregates the gossiped partial
\*   signatures and broadcasts at any height (no T0 gate binds it).
\* Source: environment (Byzantine committee member; partial sigs gossiped by
\*   pegin_confirm_sign() node/src/aggregates/instance_jobs.rs:659)
ByzantineBroadcast ==
    /\ ByzBroadcast /\ confirm = NotSent /\ ~cancel /\ h + incl <= MaxH
    /\ confirm' = Pending /\ bcastAt' = h
    /\ UNCHANGED <<params, h, seen, cancel, status, postJob, minted>>

\* Action: node n's backend learns the pending Confirm.
\* Source: environment (mempool propagation; tx_fact() node/src/aggregates/instance_scan.rs:257)
Propagate(n) ==
    /\ confirm = Pending /\ ~seen[n]
    /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, cancel, status, postJob, minted>>

\* Action: node n's backend drops the pending Confirm (eviction, restart).
\* Source: environment (mempool eviction; tx_fact() node/src/aggregates/instance_scan.rs:257)
Evict(n) ==
    /\ confirm = Pending /\ seen[n]
    /\ seen' = [seen EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, cancel, status, postJob, minted>>

--------------------------------------------------------------------------
(* Actions: per-node decisions *)

\* Action: node n's Bitcoin scan decides from its snapshot: a confirmed
\*   Confirm -> RelayerL1Broadcasted (post job on a relayer); a confirmed
\*   Cancel -> UserCanceled; past H_p+T0+B[n] with the Confirm not in its
\*   mempool -> Timeout (post job cancelled); from Timeout only a Cancel
\*   moves on, unless a Fix applies.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442 (456-468, 488-503);
\*   on_entered() instance.rs:773; enter_failure() instance.rs:826
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
       \* Timeout + confirmed Confirm: current code only alerts (no step).
       \/ /\ s = Timeout /\ ~cancel /\ confirm = Confirmed /\ Fix = "revert"
          /\ status' = [status EXCEPT ![n] = RelayerL1Broadcasted]
          /\ postJob' = [postJob EXCEPT ![n] = rel]
       \/ /\ s = Timeout /\ ~cancel /\ confirm = Confirmed /\ Fix = "relayerPosts"
          /\ rel /\ ~postJob[n] /\ ~minted
          /\ postJob' = [postJob EXCEPT ![n] = TRUE]
          /\ UNCHANGED status
    /\ UNCHANGED <<params, h, confirm, bcastAt, seen, cancel, minted>>

\* Action: the relayer's post job mints on Goat (the Confirm is confirmed).
\* Source: post_pegin_data() in node/src/aggregates/instance_jobs.rs:984; Gateway.sol postPeginData
Post(n) ==
    /\ postJob[n] /\ ~minted /\ confirm = Confirmed
    /\ minted' = TRUE
    /\ postJob' = [postJob EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<params, h, confirm, bcastAt, seen, cancel, status>>

\* Action: node n sees the Goat BridgeIn: success from a live state; a
\*   failed (Timeout) node only alerts.
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

\* Fairness: blocks keep coming (WF Mine; the inclusion deadline then forces
\* a pending Confirm in unless a Cancel wins); every node keeps running its
\* maintenance scan (REGULAR_TASK_INTERVAL_SECOND loop) and its queued jobs
\* (the engine retries them), so WF on Scan, Post and SeeMint. Propagation,
\* eviction, broadcasts and the user's Cancel are not fair (adversarial or
\* optional).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Mine)
    /\ \A n \in Nodes : WF_vars(Scan(n)) /\ WF_vars(Post(n)) /\ WF_vars(SeeMint(n))

--------------------------------------------------------------------------
Outcome(s) ==
    CASE s \in {RelayerL1Broadcasted, RelayerL2Minted} -> "pegged"
      [] s = UserCanceled -> "canceled"
      [] s = Timeout -> "abandoned"
      [] OTHER -> "open"

(* Safety invariants *)

\* No mint without a confirmed Peg-In-Confirm.
MintOnlyAfterConfirm == minted => confirm = Confirmed

(* Safety properties: none. *)

(* Liveness *)

\* All honest nodes eventually agree on the same terminal outcome.
Agreement ==
    <>[](\A n, m \in Nodes : Outcome(status[n]) = Outcome(status[m])
                             /\ Outcome(status[n]) # "open")

\* A confirmed Peg-In-Confirm (user BTC locked under n-of-n) is eventually minted on Goat.
MintAfterConfirm == (confirm = Confirmed) ~> minted

====
