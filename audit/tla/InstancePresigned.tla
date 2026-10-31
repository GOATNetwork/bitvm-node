---- MODULE InstancePresigned ----
(***************************************************************************)
(* Formal model of the SECOND race found by the same audit that produced   *)
(* GraphLifecycle.tla: `Instance.status` (InstanceBridgeInStatus,          *)
(* crates/store/src/schema.rs:194-217) has NO terminal-status protection   *)
(* anywhere in the codebase (confirmed: `grep -n "impl InstanceBridgeInStatus"` *)
(* has zero hits, unlike GraphStatus which has is_closed()).               *)
(*                                                                         *)
(* This is deliberately NOT a full Instance-lifecycle spec - InstanceBridgeInStatus's *)
(* full transition graph has not been ground-truth-traced with the same    *)
(* rigor GraphLifecycle.tla's was. It models exactly the one confirmed     *)
(* regression: `store_graph` (node/src/utils.rs, ~4438) and                *)
(* `update_graph_status_guarded` (node/src/utils.rs, ~5195) both write     *)
(* `InstanceBridgeInStatus::Presigned` unconditionally as a side effect of *)
(* a graph reaching `CommitteePresigned`, reachable from independent P2P-  *)
(* message handlers (handle.rs) and chain-rescans (graph_scan)             *)
(* with no coordination - so a stale/replayed event could revert an        *)
(* instance that already progressed past Presigned (e.g. to                *)
(* RelayerL1Broadcasted or RelayerL2Minted, written by instance_btc_tx_monitor *)
(* and handle_bridge_in_events respectively) back down to Presigned.       *)
(*                                                                         *)
(* "Advanced" below is an abstract stand-in for every real status that     *)
(* causally follows Presigned (RelayerL1Broadcasted, RelayerL2Minted,      *)
(* RelayerL2MintedFailed, PresignedFailed, Timeout, UserCanceled,          *)
(* UserDiscarded, NoEnoughCommitteesAnswered) - the guard treats all of    *)
(* them identically (refuse), so collapsing them loses no precision for    *)
(* the property being checked here.                                       *)
(***************************************************************************)

Statuses == {"Early", "Presigned", "Advanced"}

VARIABLE status
vars == <<status>>

TypeOK == status \in Statuses

Init == status = "Early"

--------------------------------------------------------------------------
(* The real, legitimate forward progression (instance_btc_tx_monitor,      *)
(* handle_bridge_in_events, etc. - the various writers that correctly      *)
(* advance status once real on-chain/L2 events are observed).              *)

AdvancePastPresigned ==
    /\ status = "Presigned"
    /\ status' = "Advanced"

--------------------------------------------------------------------------
(* The race: store_graph / update_graph_status_guarded writing Presigned   *)
(* as a side effect, reachable from an independent P2P/rescan path.        *)

\* As originally written: unconditional, matching the confirmed bug.
SetPresignedUnguarded ==
    status' = "Presigned"

\* The actual fix: set_instance_presigned_guarded, node/src/utils.rs -
\* only writes Presigned if the instance hasn't already moved past it.
SetPresignedGuarded ==
    /\ status \in {"Early", "Presigned"}
    /\ status' = "Presigned"

--------------------------------------------------------------------------
NextBug == AdvancePastPresigned \/ SetPresignedUnguarded
NextFixed == AdvancePastPresigned \/ SetPresignedGuarded

SpecBug == Init /\ [][NextBug]_vars
SpecFixed == Init /\ [][NextFixed]_vars

--------------------------------------------------------------------------
(* The property: once an instance is Advanced, it must never regress. This *)
(* is deliberately not "terminal is absorbing" in the GraphStatus sense -  *)
(* Advanced isn't necessarily terminal in reality, it just must never be   *)
(* undone by the Presigned side-effect write specifically. *)
NeverRegressPastPresigned == [][(status = "Advanced" => status' = "Advanced")]_vars

====
