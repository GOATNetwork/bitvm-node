---- MODULE InstancePresigned ----
(***************************************************************************)
(* Every writer of Instance.status in the current tree:                    *)
(*   - the Instance aggregate's commit (node/src/aggregates/instance.rs:   *)
(*     696): one BEGIN IMMEDIATE apply whose UPDATE only matches the       *)
(*     status the apply read (instance.rs:707); Presigned is written only  *)
(*     by decide_graph_endorsed (instance.rs:550), from                    *)
(*     UserBroadcastPeginPrepare;                                          *)
(*   - upsert_pegin_request_instance (crates/store/src/localdb/            *)
(*     instance.rs:347): rewrites the row only while it is UserInited, to  *)
(*     UserInited.                                                         *)
(*   insert_instance_if_absent (localdb/instance.rs:291, ON CONFLICT DO    *)
(*   NOTHING) never touches an existing row: not modeled.                  *)
(* Finding 2: an instance past Presigned is never written back to it       *)
(*   (NeverRegressPastPresigned), even with late or replayed GraphEndorsed *)
(*   events and replayed pegin requests.                                   *)
(* "Advanced" stands for every status after or instead of Presigned; no    *)
(* writer distinguishes them for this property (InstanceLifecycle.tla      *)
(* models them). No parameters.                                            *)
(* Configs: configs/node/aggregates/instance/InstancePresigned/, tiers in  *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals

\* InstanceBridgeInStatus (crates/store/src/schema.rs:205), the later ones merged into Advanced.
UserInited                == "UserInited"
CommitteesAnswered        == "CommitteesAnswered"
UserBroadcastPeginPrepare == "UserBroadcastPeginPrepare"
Presigned                 == "Presigned"
Advanced                  == "Advanced"

Statuses == {UserInited, CommitteesAnswered, UserBroadcastPeginPrepare, Presigned, Advanced}

\* Protocol order.
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

\* Action: the answer window closes: CommitteesAnswered with a quorum, else
\* NoEnoughCommitteesAnswered (Advanced).
\* Source: decide_answer_window() in node/src/aggregates/instance.rs:526
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideAnswerWindow ==
    /\ status = UserInited
    /\ status' \in {CommitteesAnswered, Advanced}

\* Action: a Bitcoin snapshot moves the instance forward: Prepare confirmed or
\* a conflicting spend; then Confirm, Cancel or Timeout (Advanced; from a
\* failure status only Timeout -> UserCanceled, Advanced to Advanced).
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideBitcoinSnapshot ==
    \/ status = CommitteesAnswered /\ status' \in {UserBroadcastPeginPrepare, Advanced}
    \/ status \in {UserBroadcastPeginPrepare, Presigned} /\ status' = Advanced

\* Action: the Goat BridgeIn event: RelayerL2Minted from any live status; a
\* failed instance only alerts.
\* Source: decide_l2_minted() in node/src/aggregates/instance.rs:561
\* Source: commit() in node/src/aggregates/instance.rs:696
DecideL2Minted ==
    /\ status # Advanced
    /\ status' = Advanced

\* Action: a GraphEndorsed event, possibly late or replayed: parked before the
\* Presign phase, else only UserBroadcastPeginPrepare moves to Presigned
\* (the endorsement threshold is left nondeterministic).
\* Source: apply() EVENT_GRAPH_ENDORSED arm in node/src/aggregates/instance.rs:1271-1289
\* Source: decide_graph_endorsed() in node/src/aggregates/instance.rs:550
ApplyGraphEndorsed ==
    /\ status \notin {UserInited, CommitteesAnswered}
    /\ status' = IF status = UserBroadcastPeginPrepare THEN Presigned ELSE status

\* Action: the pegin-request monitor sees the request again and rewrites the
\* row, only while it is UserInited.
\* Source: pegin_request_monitor() in node/src/aggregates/instance_scan.rs:371 (call at :460)
\* Source: upsert_pegin_request_instance() in crates/store/src/localdb/instance.rs:347-403
UpsertPeginRequest ==
    /\ status = UserInited
    /\ status' = UserInited

Next ==
    \/ DecideAnswerWindow
    \/ DecideBitcoinSnapshot
    \/ DecideL2Minted
    \/ ApplyGraphEndorsed
    \/ UpsertPeginRequest

\* Safety only: no fairness.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety properties *)

\* An instance past Presigned is never written back to it (Finding 2).
NeverRegressPastPresigned == [][(status = Advanced => status' = Advanced)]_vars

\* No writer moves the instance backwards along the protocol order.
InstanceStatusNeverRegresses == [][Rank(status') >= Rank(status)]_vars

====
