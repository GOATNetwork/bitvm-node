---- MODULE PeginTimeoutAgreement ----
(***************************************************************************)
(* M2: Timeout is a per-node decision, but Peg-In-Confirm is global.       *)
(*                                                                         *)
(* Code at dev 60562f8 (after #476):                                       *)
(*                                                                         *)
(*  node/src/aggregates/instance.rs:501-506 (decide_btc_snapshot)          *)
(*    } else if let Some(confirm) = confirm                                *)
(*        && deadlines.abandon_height(prepare_height).is_some_and(|h| snapshot.height >= h) *)
(*        && !confirm.in_mempool { current = Timeout; }                    *)
(*    `in_mempool` is THIS node's backend view (TxFact doc, instance.rs:   *)
(*    201-203: "Per-node: another node may not see it"), and B is per node *)
(*    (env.rs:182-190 PEGIN_ABANDON_BUFFER_BLOCKS, clamp 1..100000).        *)
(*                                                                         *)
(*  instance.rs:456-468: from Timeout only a confirmed Cancel moves on; a  *)
(*    confirmed Confirm raises PeginConfirmAfterTimeout and nothing else.  *)
(*  instance.rs:826-864 enter_failure: graphs obsoleted, the instance      *)
(*    outbox closed, ANSWER/PRESIGN/CONFIRM/POST jobs cancelled.           *)
(*  instance.rs:792-797: JOB_POST_PEGIN_DATA is only enqueued on ENTERING  *)
(*    RelayerL1Broadcasted, on a relayer (env.rs:255-261 is_relayer: a     *)
(*    per-node ENABLE_RELAYER flag).                                       *)
(*  instance.rs:561-571 decide_l2_minted: a failed instance only alerts.   *)
(*  instance_scan.rs:162-178,228-239: a Timeout instance whose Confirm      *)
(*    confirmed leaves the scan (SETTLED_TIMEOUTS).                        *)
(*                                                                         *)
(* Meanwhile the signed Confirm stays valid until a Cancel confirms: the   *)
(* honest relayer only broadcasts before T0 (instance_jobs.rs:875-893),    *)
(* but once broadcast the raw tx is public and anyone (the user, any      *)
(* mempool) re-relays it; a Byzantine committee member holding the gossiped *)
(* partial signatures can aggregate and broadcast it at any time           *)
(* (ByzBroadcast).                                                         *)
(*                                                                         *)
(* Two committee nodes: n1 (the relayer, buffer B1) and n2 (buffer B2).     *)
(* Each node's mempool view of the pending Confirm flips nondeterministically *)
(* (propagation, eviction under a fee spike - the Confirm fee is fixed at  *)
(* presign time -, restart, backend differences).                          *)
(*                                                                         *)
(* Fix (constant Fix):                                                     *)
(*   "none"         current code                                           *)
(*   "revert"       Timeout + confirmed Confirm -> RelayerL1Broadcasted    *)
(*                  (post job on a relayer); outcome converges            *)
(*   "relayerPosts" the relayer posts whenever it sees the Confirm          *)
(*                  confirmed, even in Timeout; mint is live, but the      *)
(*                  Timeout node still disagrees (Agreement still fails)   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS T0, Hp, B1, B2, MaxHeight, Fix, ByzBroadcast

Nodes == {"n1", "n2"}
Relayers == {"n1"}
B == [n \in Nodes |-> IF n = "n1" THEN B1 ELSE B2]

ASSUME Fix \in {"none", "revert", "relayerPosts"}
ASSUME \A n \in Nodes : Hp + T0 + B[n] < MaxHeight

Live == {"Presigned", "RelayerL1Broadcasted", "RelayerL2Minted"}
Statuses == Live \cup {"Timeout", "UserCanceled"}

VARIABLES
    h,        \* Bitcoin tip
    confirm,  \* "none" | "pending" (some miner/mempool holds it) | "confirmed"
    seen,     \* seen[n]: node n's backend reports the Confirm in its mempool
    cancel,   \* Peg-In-Cancel confirmed
    status,   \* status[n]
    postJob,  \* postJob[n]: JOB_POST_PEGIN_DATA queued on n
    minted    \* Goat BridgeIn

vars == <<h, confirm, seen, cancel, status, postJob, minted>>

TypeOK ==
    /\ h \in Hp..MaxHeight
    /\ confirm \in {"none", "pending", "confirmed"}
    /\ seen \in [Nodes -> BOOLEAN]
    /\ cancel \in BOOLEAN
    /\ status \in [Nodes -> Statuses]
    /\ postJob \in [Nodes -> BOOLEAN]
    /\ minted \in BOOLEAN

Init ==
    /\ h = Hp
    /\ confirm = "none"
    /\ seen = [n \in Nodes |-> FALSE]
    /\ cancel = FALSE
    /\ status = [n \in Nodes |-> "Presigned"]
    /\ postJob = [n \in Nodes |-> FALSE]
    /\ minted = FALSE

NoSeen == [n \in Nodes |-> FALSE]

--------------------------------------------------------------------------
(* Environment *)

Tick ==
    /\ h < MaxHeight /\ h' = h + 1
    /\ UNCHANGED <<confirm, seen, cancel, status, postJob, minted>>

\* The relayer's broadcast job: gate open (tip < H_p + T0), no Cancel confirmed.
RelayerBroadcast(n) ==
    /\ n \in Relayers /\ status[n] = "Presigned" /\ h < Hp + T0
    /\ confirm = "none" /\ ~cancel
    /\ confirm' = "pending" /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<h, cancel, status, postJob, minted>>

\* A Byzantine committee member aggregates the gossiped partial signatures
\* and broadcasts at any height (no T0 gate binds it).
ByzantineBroadcast ==
    /\ ByzBroadcast /\ confirm = "none" /\ ~cancel
    /\ confirm' = "pending"
    /\ UNCHANGED <<h, seen, cancel, status, postJob, minted>>

Propagate(n) ==
    /\ confirm = "pending" /\ ~seen[n]
    /\ seen' = [seen EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<h, confirm, cancel, status, postJob, minted>>

Evict(n) ==
    /\ confirm = "pending" /\ seen[n]
    /\ seen' = [seen EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<h, confirm, cancel, status, postJob, minted>>

ConfirmMined ==
    /\ confirm = "pending" /\ ~cancel
    /\ confirm' = "confirmed" /\ seen' = NoSeen
    /\ UNCHANGED <<h, cancel, status, postJob, minted>>

\* The user's Peg-In-Cancel (connector_z leaf 1, CSV T0); conflicts with the Confirm.
CancelMined ==
    /\ h >= Hp + T0 /\ confirm # "confirmed" /\ ~cancel
    /\ cancel' = TRUE /\ confirm' = "none" /\ seen' = NoSeen
    /\ UNCHANGED <<h, status, postJob, minted>>

--------------------------------------------------------------------------
(* Per-node decisions *)

\* decide_btc_snapshot + on_entered on node n.
Scan(n) ==
    LET s == status[n]
        rel == n \in Relayers
    IN
    \/ /\ s = "Presigned" /\ confirm = "confirmed"
       /\ status' = [status EXCEPT ![n] = "RelayerL1Broadcasted"]
       /\ postJob' = [postJob EXCEPT ![n] = rel]
    \/ /\ s = "Presigned" /\ confirm # "confirmed" /\ cancel
       /\ status' = [status EXCEPT ![n] = "UserCanceled"]
       /\ postJob' = [postJob EXCEPT ![n] = FALSE]
    \/ /\ s = "Presigned" /\ confirm # "confirmed" /\ ~cancel
       /\ h >= Hp + T0 + B[n] /\ ~seen[n]
       /\ status' = [status EXCEPT ![n] = "Timeout"]
       /\ postJob' = [postJob EXCEPT ![n] = FALSE]   \* cancel_phase_jobs(PHASE_POST)
    \/ /\ s = "Timeout" /\ cancel
       /\ status' = [status EXCEPT ![n] = "UserCanceled"]
       /\ UNCHANGED postJob
    \* Timeout + confirmed Confirm: current code only alerts (no step).
    \/ /\ s = "Timeout" /\ ~cancel /\ confirm = "confirmed" /\ Fix = "revert"
       /\ status' = [status EXCEPT ![n] = "RelayerL1Broadcasted"]
       /\ postJob' = [postJob EXCEPT ![n] = rel]
    \/ /\ s = "Timeout" /\ ~cancel /\ confirm = "confirmed" /\ Fix = "relayerPosts"
       /\ rel /\ ~postJob[n] /\ ~minted
       /\ postJob' = [postJob EXCEPT ![n] = TRUE]
       /\ UNCHANGED status

ScanStep(n) == Scan(n) /\ UNCHANGED <<h, confirm, seen, cancel, minted>>

\* post_pegin_data on the relayer.
Post(n) ==
    /\ postJob[n] /\ ~minted /\ confirm = "confirmed"
    /\ minted' = TRUE
    /\ postJob' = [postJob EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<h, confirm, seen, cancel, status>>

\* decide_l2_minted: success from a live state; a failed node only alerts.
SeeMint(n) ==
    /\ minted /\ status[n] \in {"Presigned", "RelayerL1Broadcasted"}
    /\ status' = [status EXCEPT ![n] = "RelayerL2Minted"]
    /\ UNCHANGED <<h, confirm, seen, cancel, postJob, minted>>

Next ==
    \/ Tick \/ ByzantineBroadcast \/ ConfirmMined \/ CancelMined
    \/ \E n \in Nodes : RelayerBroadcast(n) \/ Propagate(n) \/ Evict(n)
                        \/ ScanStep(n) \/ Post(n) \/ SeeMint(n)

\* Time passes, nodes keep scanning and running their jobs, and a pending
\* Confirm is eventually mined unless a Cancel wins. Propagation, eviction,
\* broadcasts and the user's Cancel are not fair (adversarial / optional).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Tick) /\ WF_vars(ConfirmMined)
    /\ \A n \in Nodes : WF_vars(ScanStep(n)) /\ WF_vars(Post(n)) /\ WF_vars(SeeMint(n))

--------------------------------------------------------------------------
(* Properties *)

Outcome(s) ==
    CASE s \in {"RelayerL1Broadcasted", "RelayerL2Minted"} -> "pegged"
      [] s = "UserCanceled" -> "canceled"
      [] s = "Timeout" -> "abandoned"
      [] OTHER -> "open"

\* All honest nodes eventually agree on the terminal outcome.
Agreement ==
    <>[](\A n, m \in Nodes : Outcome(status[n]) = Outcome(status[m])
                             /\ Outcome(status[n]) # "open")

\* A confirmed Peg-In-Confirm (the user's BTC now locked under n-of-n)
\* is eventually minted on Goat.
MintAfterConfirm == (confirm = "confirmed") ~> minted

\* Safety sanity: no mint without a confirmed Confirm.
MintOnlyAfterConfirm == minted => confirm = "confirmed"

====
