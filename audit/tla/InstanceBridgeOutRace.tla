---- MODULE InstanceBridgeOutRace ----
(***************************************************************************)
(* Round-1 Finding 6 (audit/TLAPlus-20260710.md): the bridge-out status    *)
(* had several uncoordinated writers with no status precondition, so a     *)
(* stale write could resurrect or overwrite a final outcome (e.g. a        *)
(* maintenance Timeout clobbering a Claim).                                *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476). The old InstanceBridgeOutStatus *)
(* on the instance row is gone; the bridge-out (swap) lifecycle is now the *)
(* `swap_escrow` row, status SwapEscrowStatus (crates/store/src/schema.rs  *)
(* 252-264):                                                               *)
(*   Initialize, Claim, Refund  mirror the swap contract's events;         *)
(*   Timeout                    is derived locally when refund_deadline    *)
(*                              passes, and a later on-chain Claim/Refund  *)
(*                              event still overrides it (schema.rs 255).  *)
(* Writers (the old RPC full-row upsert no longer exists; rpc_service only *)
(* reads swap_escrow):                                                     *)
(*   - GOAT event watcher, node/src/scheduled_tasks/event_watch/          *)
(*     bridge_out.rs: Initialize via insert_swap_escrow_if_absent (INSERT  *)
(*     .. ON CONFLICT DO NOTHING), Claim / Refund via update_swap_escrow   *)
(*     with_only_if_status_in([Initialize, Timeout]) - the guard is folded *)
(*     into the UPDATE's WHERE clause (crates/store/src/localdb/swap.rs    *)
(*     109-112, 159-166, 250-257).                                         *)
(*   - maintenance, node/src/scheduled_tasks/swap_maintenance_tasks.rs     *)
(*     swap_escrow_timeout_monitor -> timeout_expired_swap_escrows         *)
(*     (swap.rs 261-276): one UPDATE .. WHERE status = 'Initialize'.       *)
(* Every write is a single guarded SQL statement, so each is one atomic    *)
(* action with its guard on the CURRENT status (no read-then-write gap).   *)
(*                                                                         *)
(* PROPERTY, re-derived for the current design: Claim and Refund are the   *)
(* final outcomes (absorbing); Timeout is provisional and can only be      *)
(* replaced by an on-chain Claim/Refund; nothing ever returns a row to     *)
(* Initialize. The old property also treated Timeout as absorbing; the     *)
(* current code deliberately lets the chain event override it, so that     *)
(* reading no longer applies (not a bug: the contract event is            *)
(* authoritative).                                                         *)
(*                                                                         *)
(* CONFIGS: InstanceBridgeOutRaceFixed.cfg (tier pass) - the current code. *)
(* Abstractions: one escrow; the refund deadline is not modeled (the       *)
(* Timeout write may fire whenever the row is Initialize, a superset of    *)
(* the real behaviour, which is sound for the safety properties).          *)
(***************************************************************************)

\* Row states. EscrowAbsent = no swap_escrow row for this escrow_hash yet.
EscrowAbsent     == "Absent"
EscrowInitialize == "Initialize"
EscrowClaim      == "Claim"
EscrowTimeout    == "Timeout"
EscrowRefund     == "Refund"

EscrowStates == {EscrowAbsent, EscrowInitialize, EscrowClaim, EscrowTimeout, EscrowRefund}

\* Outcomes reported by the swap contract: final once recorded.
TerminalStatuses == {EscrowClaim, EscrowRefund}

\* Statuses the Claim/Refund UPDATE accepts (with_only_if_status_in).
ChainOverridable == {EscrowInitialize, EscrowTimeout}

VARIABLES
    status      \* swap_escrow.status of the modeled escrow

vars == <<status>>

TypeOk == status \in EscrowStates

Init == status = EscrowAbsent

--------------------------------------------------------------------------
\* Action: the watcher sees the swap Initialize event and creates the row in
\* Initialize. A replayed Initialize hits ON CONFLICT DO NOTHING (a no-op,
\* so it is not a separate step), whatever status the row has reached.
\* Source: handle_swap_init_events() in node/src/scheduled_tasks/event_watch/bridge_out.rs:88-130;
\*         insert_swap_escrow_if_absent() in crates/store/src/localdb/swap.rs:177-213 (ON CONFLICT DO NOTHING, 187)
WatchEventInitialize ==
    /\ status = EscrowAbsent
    /\ status' = EscrowInitialize

\* Action: the watcher sees the swap Claim event. The UPDATE only matches a
\* row in Initialize or Timeout; otherwise zero rows change (an event for an
\* unknown escrow is skipped before the UPDATE).
\* Source: handle_swap_claim_events() in node/src/scheduled_tasks/event_watch/bridge_out.rs:158-223;
\*         update_swap_escrow() / with_only_if_status_in() in crates/store/src/localdb/swap.rs:109-112,159-166,250-257
WatchEventClaim ==
    /\ status \in ChainOverridable
    /\ status' = EscrowClaim

\* Action: the watcher sees the swap Refund event; same guard as Claim.
\* Source: handle_swap_refund_events() in node/src/scheduled_tasks/event_watch/bridge_out.rs:247-280
WatchEventRefund ==
    /\ status \in ChainOverridable
    /\ status' = EscrowRefund

\* Action: the maintenance tick marks a still-Initialize escrow whose
\* refund_deadline has passed as Timeout (single UPDATE .. WHERE status =
\* 'Initialize'; the deadline condition is abstracted away).
\* Source: swap_escrow_timeout_monitor() in node/src/scheduled_tasks/swap_maintenance_tasks.rs:10-17
\*         (run() in node/src/scheduled_tasks/mod.rs:277-281);
\*         timeout_expired_swap_escrows() in crates/store/src/localdb/swap.rs:261-276
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
\* ---- Safety invariants ----
\* (TypeOk above.)

\* ---- Safety properties ----

\* A recorded Claim or Refund is final: no later write changes it (e.g. a
\* stale maintenance Timeout never clobbers a Claim).
TerminalStatusesAreAbsorbing ==
    [][(status \in TerminalStatuses => status' = status)]_status

\* A locally derived Timeout is only ever replaced by an on-chain outcome.
TimeoutOnlyResolvedOnChain ==
    [][(status = EscrowTimeout => status' \in {EscrowTimeout} \cup TerminalStatuses)]_status

\* No writer resurrects a row to Initialize: it is entered only on creation.
NoResurrectionToInitialize ==
    [][(status' = EscrowInitialize => status \in {EscrowAbsent, EscrowInitialize})]_status

\* ---- Liveness ----
\* None: resolution depends on the refund deadline and the contract events,
\* which this safety model does not constrain.

====
