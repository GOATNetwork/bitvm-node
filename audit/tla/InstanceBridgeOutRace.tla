---- MODULE InstanceBridgeOutRace ----
(***************************************************************************)
(* Formal model of a race found while auditing every remaining stateful    *)
(* enum after GraphStatus/InstanceBridgeInStatus (see audit/TLAPlus-*.md). *)
(*                                                                         *)
(* `InstanceBridgeOutStatus` (crates/store/src/schema.rs:223-229) is       *)
(* written from three independently-scheduled, uncoordinated tasks with   *)
(* no shared transaction spanning read+decide+write in any of them:       *)
(*   - the RPC-service task (node/src/rpc_service/handler/bitvm_handler.rs, *)
(*     `bridge_out_init_tag`) - stale-read-then-full-row-upsert, sets      *)
(*     Initialize.                                                        *)
(*   - the GoatChain L2-event watcher (node/src/scheduled_tasks/          *)
(*     event_watch_task.rs), 5s tokio task - unconditional targeted        *)
(*     `update_instance` on SwapClaimEvent/SwapRefundEvent, sets           *)
(*     Claim/Refund with NO status precondition (`InstanceUpdate`'s WHERE  *)
(*     clause is only `hex(instance_id)=?`, confirmed via                  *)
(*     crates/store/src/localdb.rs - no `with_only_if_status_in` exists    *)
(*     anywhere in the codebase for this entity).                         *)
(*   - the maintenance task (node/src/scheduled_tasks/                    *)
(*     instance_maintenance_tasks.rs, `instance_bridge_out_monitor`), 10s  *)
(*     tokio task - batch-reads a stale snapshot, then per-row does an     *)
(*     unconditional targeted `update_instance` to Timeout with no re-     *)
(*     check at write time.                                                *)
(*                                                                         *)
(* Modeled the same way GraphLifecycle.tla models its GoatRace actions:    *)
(* every writer is unconditional on the CURRENT status - that's the        *)
(* verified real behavior, not a simplification of it.                    *)
(***************************************************************************)
Statuses == {"Initialize", "Claim", "Timeout", "Refund"}

\* Once a bridge-out instance is claimed, timed out, or refunded, that is
\* meant to be the final outcome - Initialize is the only non-terminal
\* status.
TerminalStatuses == {"Claim", "Timeout", "Refund"}

VARIABLE status
vars == <<status>>

TypeOK == status \in Statuses

Init == status = "Initialize"

--------------------------------------------------------------------------
(* Every action below is unconditional on the current status - confirmed  *)
(* real behavior for all three writers, not a modeling simplification.    *)

RpcStaleInit ==      status' = "Initialize" \* bitvm_handler.rs bridge_out_init_tag, stale full-row upsert
WatchEventClaim ==   status' = "Claim"      \* event_watch_task.rs handle_swap_claim_events
WatchEventRefund ==  status' = "Refund"     \* event_watch_task.rs handle_swap_refund_events
MaintenanceTimeout == status' = "Timeout"   \* instance_maintenance_tasks.rs instance_bridge_out_monitor

Next ==
    \/ RpcStaleInit
    \/ WatchEventClaim
    \/ WatchEventRefund
    \/ MaintenanceTimeout

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Next)

\* Proposed fix design (not applied to code - same atomic-CAS pattern as
\* the GraphStatus/InstanceBridgeInStatus fixes: only write if the row
\* isn't already in a terminal status, folded into the UPDATE's WHERE
\* clause so there's no read-then-write gap).
NextFixed ==
    \/ (status \notin TerminalStatuses /\ RpcStaleInit)
    \/ (status \notin TerminalStatuses /\ WatchEventClaim)
    \/ (status \notin TerminalStatuses /\ WatchEventRefund)
    \/ (status \notin TerminalStatuses /\ MaintenanceTimeout)

SpecFixed == Init /\ [][NextFixed]_vars
FairSpecFixed == SpecFixed /\ WF_vars(NextFixed)

--------------------------------------------------------------------------
(* Safety property: once a bridge-out instance reaches a final outcome,   *)
(* it never changes again - e.g. a successfully Claimed instance must     *)
(* never be silently reset by a stale maintenance-task Timeout write.     *)
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

====
