---- MODULE InstancePresigned ----
(***************************************************************************)
(* Finding 2 (fixed before #476): Instance.status had no protection        *)
(* against a stale write of Presigned. Graph-status code wrote Presigned as *)
(* a side effect of a graph reaching CommitteePresigned, from P2P handlers  *)
(* and chain rescans, so a replayed event could knock an instance that had  *)
(* moved on (RelayerL1Broadcasted, RelayerL2Minted, a failure status) back  *)
(* to Presigned. The fix guarded that write.                                *)
(*                                                                         *)
(* After #476 that side-effect write is gone: graph status changes never    *)
(* touch the instance row. This spec re-derives every Instance.status       *)
(* writer from the current tree and checks the same property:              *)
(*   - Instance aggregate commit (node/src/aggregates/instance.rs:696):     *)
(*     the only writer of Presigned, via decide_graph_endorsed (instance.rs: *)
(*     550), which moves UserBroadcastPeginPrepare and nothing else. The     *)
(*     apply runs in one BEGIN IMMEDIATE transaction                        *)
(*     (crates/engine/src/worker.rs:177) and its UPDATE carries             *)
(*     `WHERE status = <status read by the apply>`, so a decision always     *)
(*     acts on the current row. A GraphEndorsed event can arrive late or    *)
(*     twice; it is parked while the instance is UserInited or              *)
(*     CommitteesAnswered (instance.rs:1271).                                *)
(*   - upsert_pegin_request_instance (crates/store/src/localdb/instance.rs: *)
(*     347): a replayed pegin request rewrites the row only                 *)
(*     `WHERE instance.status = 'UserInited'`, with status UserInited.       *)
(*   - insert_instance_if_absent (instance.rs:291): ON CONFLICT DO NOTHING, *)
(*     never touches an existing row, so it is not modeled.                 *)
(*                                                                         *)
(* "Advanced" stands for every status that follows or replaces Presigned   *)
(* (RelayerL1Broadcasted, RelayerL2Minted, Timeout, UserCanceled,           *)
(* UserDiscarded, NoEnoughCommitteesAnswered); no writer distinguishes them *)
(* for this property. InstanceLifecycle.tla models the forward decisions in *)
(* detail.                                                                  *)
(*                                                                         *)
(* Config (audit/tla/specs.txt): InstancePresignedFixed.cfg - pass.         *)
(***************************************************************************)
EXTENDS Naturals

\* Instance.status values (InstanceBridgeInStatus, crates/store/src/schema.rs:205).
UserInited                == "UserInited"
CommitteesAnswered        == "CommitteesAnswered"
UserBroadcastPeginPrepare == "UserBroadcastPeginPrepare"
Presigned                 == "Presigned"
Advanced                  == "Advanced"

Statuses == {UserInited, CommitteesAnswered, UserBroadcastPeginPrepare, Presigned, Advanced}

\* Protocol order, for the no-regression property.
Rank(s) ==
    CASE s = UserInited -> 0
      [] s = CommitteesAnswered -> 1
      [] s = UserBroadcastPeginPrepare -> 2
      [] s = Presigned -> 3
      [] s = Advanced -> 4

VARIABLES
    status      \* Instance.status of the local row

vars == <<status>>

TypeOk == status \in Statuses

Init == status = UserInited

--------------------------------------------------------------------------
(* Actions *)

\* Action: the answer window closes: CommitteesAnswered with a quorum,
\* otherwise NoEnoughCommitteesAnswered (a failure status).
\* Source: decide_answer_window() in node/src/aggregates/instance.rs:526
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideAnswerWindow ==
    /\ status = UserInited
    /\ status' \in {CommitteesAnswered, Advanced}

\* Action: a Bitcoin snapshot moves the instance forward: Prepare confirmed
\* (UserBroadcastPeginPrepare) or a conflicting spend (UserDiscarded); then
\* Confirm confirmed, Cancel confirmed or Timeout. Failure statuses only move
\* Timeout -> UserCanceled, both Advanced.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideBitcoinSnapshot ==
    \/ status = CommitteesAnswered /\ status' \in {UserBroadcastPeginPrepare, Advanced}
    \/ status \in {UserBroadcastPeginPrepare, Presigned} /\ status' = Advanced

\* Action: the Goat BridgeIn (mint) event: RelayerL2Minted from any live
\* status; only an alert for a failed instance (both Advanced here).
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideL2Minted ==
    /\ status # Advanced
    /\ status' = Advanced

\* Action: a GraphEndorsed event, possibly late or replayed, is applied:
\* parked before the Presign phase, otherwise decide_graph_endorsed reads the
\* current status and moves only UserBroadcastPeginPrepare to Presigned once
\* enough graphs are endorsed (the threshold is left nondeterministic).
\* Source: apply() EVENT_GRAPH_ENDORSED arm in node/src/aggregates/instance.rs:1271-1289
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550
ApplyGraphEndorsed ==
    /\ status \notin {UserInited, CommitteesAnswered}
    /\ status' = IF status = UserBroadcastPeginPrepare THEN Presigned ELSE status

\* Action: the pegin-request monitor sees the request again and rewrites the
\* row, which it does only while the row is still UserInited.
\* Source: pegin_request_monitor() in node/src/aggregates/instance_scan.rs:371,460
\* Source: upsert_pegin_request_instance() in crates/store/src/localdb/instance.rs:347
UpsertPeginRequest ==
    /\ status = UserInited
    /\ status' = UserInited

Next ==
    \/ DecideAnswerWindow
    \/ DecideBitcoinSnapshot
    \/ DecideL2Minted
    \/ ApplyGraphEndorsed
    \/ UpsertPeginRequest

\* No fairness: only safety is checked.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* (none beyond TypeOk)

--------------------------------------------------------------------------
(* Safety properties *)

\* Once an instance has moved past Presigned it is never written back to it.
NeverRegressPastPresigned == [][(status = Advanced => status' = Advanced)]_vars

\* No writer moves the instance backwards along the protocol order.
InstanceStatusNeverRegresses == [][Rank(status') >= Rank(status)]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* (none)

====
