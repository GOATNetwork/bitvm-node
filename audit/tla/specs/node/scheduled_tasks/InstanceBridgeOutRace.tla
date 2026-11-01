---- MODULE InstanceBridgeOutRace ----
(***************************************************************************)
(* Finding 6 (round 1): a stale write to the bridge-out status could       *)
(* overwrite a final outcome (e.g. a maintenance Timeout over a Claim).    *)
(*                                                                         *)
(* Models the swap_escrow row (SwapEscrowStatus, crates/store/src/         *)
(* schema.rs:252-264) and its writers, each one guarded SQL statement, so  *)
(* each is one atomic action:                                              *)
(*   - GOAT event watcher (event_watch/bridge_out.rs): Initialize by       *)
(*     INSERT .. ON CONFLICT DO NOTHING; Claim / Refund by an UPDATE       *)
(*     guarded on status IN (Initialize, Timeout);                         *)
(*   - maintenance (swap_maintenance_tasks.rs): Timeout by an UPDATE       *)
(*     guarded on status = Initialize.                                     *)
(* Properties: Claim and Refund are final; Timeout is replaced only by an  *)
(* on-chain Claim/Refund; no write returns a row to Initialize.            *)
(* No parameters. One escrow; the refund deadline is not modelled (Timeout *)
(* may fire whenever the row is Initialize), a superset of the code's      *)
(* behaviour, so the safety properties carry over.                         *)
(* Configs: configs/node/scheduled_tasks/InstanceBridgeOutRace/, tiers in  *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)

\* Row states; EscrowAbsent = no swap_escrow row for this escrow_hash yet.
EscrowAbsent     == "Absent"
EscrowInitialize == "Initialize"
EscrowClaim      == "Claim"
EscrowTimeout    == "Timeout"
EscrowRefund     == "Refund"

EscrowStates == {EscrowAbsent, EscrowInitialize, EscrowClaim, EscrowTimeout, EscrowRefund}

\* Final outcomes, reported by the swap contract.
TerminalStatuses == {EscrowClaim, EscrowRefund}

\* Statuses the Claim/Refund UPDATE accepts (with_only_if_status_in).
ChainOverridable == {EscrowInitialize, EscrowTimeout}

VARIABLES
    status      \* swap_escrow.status of the modelled escrow

vars == <<status>>

TypeOk == status \in EscrowStates

Init == status = EscrowAbsent

--------------------------------------------------------------------------
\* Action: watcher creates the row in Initialize on the swap Initialize event
\* (a replayed event is a no-op, so not a step).
\* Source: node/src/scheduled_tasks/event_watch/bridge_out.rs:88-156 (insert at 130);
\*         crates/store/src/localdb/swap.rs:177-210 (ON CONFLICT DO NOTHING at 187)
WatchEventInitialize ==
    /\ status = EscrowAbsent
    /\ status' = EscrowInitialize

\* Action: watcher records Claim on the swap Claim event, only from Initialize or Timeout.
\* Source: node/src/scheduled_tasks/event_watch/bridge_out.rs:158-245 (guarded UPDATE at 204-216);
\*         crates/store/src/localdb/swap.rs:109-112,159-166,250-257
WatchEventClaim ==
    /\ status \in ChainOverridable
    /\ status' = EscrowClaim

\* Action: watcher records Refund on the swap Refund event, only from Initialize or Timeout.
\* Source: node/src/scheduled_tasks/event_watch/bridge_out.rs:247-302 (guarded UPDATE at 263-273)
WatchEventRefund ==
    /\ status \in ChainOverridable
    /\ status' = EscrowRefund

\* Action: maintenance marks an Initialize escrow Timeout (deadline abstracted).
\* Source: node/src/scheduled_tasks/swap_maintenance_tasks.rs:10-17 (called at mod.rs:277-281);
\*         crates/store/src/localdb/swap.rs:261-276
MaintenanceTimeout ==
    /\ status = EscrowInitialize
    /\ status' = EscrowTimeout

Next ==
    \/ WatchEventInitialize
    \/ WatchEventClaim
    \/ WatchEventRefund
    \/ MaintenanceTimeout

\* No fairness: only safety is checked.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* A recorded Claim or Refund never changes.
TerminalStatusesAreAbsorbing ==
    [][(status \in TerminalStatuses => status' = status)]_status

\* A locally derived Timeout is only ever replaced by an on-chain outcome.
TimeoutOnlyResolvedOnChain ==
    [][(status = EscrowTimeout => status' \in {EscrowTimeout} \cup TerminalStatuses)]_status

\* Initialize is entered only when the row is created.
NoResurrectionToInitialize ==
    [][(status' = EscrowInitialize => status \in {EscrowAbsent, EscrowInitialize})]_status

====
