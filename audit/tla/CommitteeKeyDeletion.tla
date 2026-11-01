---- MODULE CommitteeKeyDeletion ----
(***************************************************************************)
(* PURPOSE. H2: the bridge's existential-honesty argument - "one honest    *)
(* committee member deletes its instance key, so n-of-n can never sign     *)
(* again" - does not hold for the code as configured and as written.       *)
(*                                                                         *)
(* CODE SCOPE (dev 60562f8, after #476):                                   *)
(*  crates/bitvm-gc/src/keys.rs:217-264 create_instance_keypair_envelope:  *)
(*    the instance key is random (OsRng) and lives only in an envelope     *)
(*    encrypted under a KEK derived from the node master key; keys.rs:332  *)
(*    delete_instance_keypair_envelope deletes it. So deletion is          *)
(*    meaningful: master key + disk of every member recovers every n-of-n  *)
(*    instance key that was not deleted.                                   *)
(*  node/src/env.rs:157-161: DEFAULT_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE  *)
(*    = false; delete timelock 32 blocks (KD, all networks; not exported   *)
(*    to ShippedTimelockValues, so KDShipped below).                       *)
(*  node/src/aggregates/instance.rs:906-919 request_key_delete: with       *)
(*    deletion disabled "the intent is only recorded";                     *)
(*    node/src/aggregates/instance_jobs.rs:1086-1094 DeleteInstanceKeyRunner*)
(*    likewise.                                                            *)
(*  crates/store/src/schema.rs:242-249 deletes_key_on_entry =              *)
(*    NoEnoughCommitteesAnswered | UserDiscarded | UserCanceled (never      *)
(*    Timeout); instance.rs:890-899 enter_failure keeps the key "for       *)
(*    manual handling" on Timeout.                                         *)
(*  instance.rs:508-517 decide_btc_snapshot step 3: success side deletes   *)
(*    once the Confirm is KD deep, only from RelayerL1Broadcasted |        *)
(*    RelayerL2Minted, and those statuses are only scanned when deletion   *)
(*    is enabled (node/src/aggregates/instance_scan.rs:182-190).           *)
(*  instance.rs:456-468: Timeout + confirmed Confirm only alerts; the row  *)
(*    leaves the scan (instance_scan.rs:228-239). No later deletion.       *)
(*                                                                         *)
(* MODEL. BTC under n-of-n: connector_z leaf 0 (the Peg-In-Prepare output, *)
(* until the user's Cancel spends it) and C0 (Peg-In-Confirm output). The  *)
(* n-of-n needs EVERY member's key, so with >= 1 honest-at-the-time member *)
(* the BTC is safe iff that member's key is gone. The model tracks the one *)
(* honest member; Byzantine members keep their keys forever.               *)
(* The security claim, with a window W: once the instance settled - the    *)
(* Confirm confirmed, or the honest node gave it up (Timeout) - and W more *)
(* blocks passed, a compromise of every member finds the honest key gone.  *)
(* A Cancel spends connector_z, so nothing is at stake after it.           *)
(* CommitteesAnswered keeps the key too (it never expires), but no BTC is  *)
(* under the n-of-n before Peg-In-Prepare confirms: not modeled.           *)
(* No hidden timing: the honest node scans - and its queued delete job     *)
(* runs - at most react blocks late (block x is handled before block       *)
(* x + react + 1 arrives; react = 0 is "before the next block"); the       *)
(* adversary schedules within that bound. The Confirm and the Cancel are   *)
(* carried by blocks, so a scan of block x sees what block x holds.        *)
(*                                                                         *)
(* PARAMETERS (frozen variables): t0, b (Timeout at H_p+T0+B), kd          *)
(* (success-side delete delay), react (scan lag bound), tdelay (fix:       *)
(* blocks after entering Timeout before deleting), win (the claim's W).    *)
(* Generic sweep (NetSet = {}): from the *Range constants. Shipped: t0 =   *)
(* ConnectorZ[net], b = PeginAbandonBufferBlocks[net], kd = 32, react =    *)
(* ReactionBlocks[net], tdelay = kd (the fix reuses the delete timelock),  *)
(* win = kd + react (the window the success side is built for).            *)
(*                                                                         *)
(* EXHAUSTIVENESS. Deletion is due at confirmH + kd (success) or timeoutH  *)
(* + tdelay (fix) and happens at most react blocks later; a compromise     *)
(* needs tip > settle + win. So only kd + react vs win and tdelay + react  *)
(* vs win matter: kd, tdelay, react \in 0..2, win \in 0..4 cover every     *)
(* class (difference <= -1, 0, 1, >= 2). T0 and B only place the Cancel    *)
(* and Timeout points: the model starts at tip H_p+T0-1 (a Confirm mined   *)
(* earlier behaves like one mined there - only the success path exists     *)
(* before T0), so every T0 gives a translate, and every B >= 1 the same    *)
(* orderings; T0, B \in 1..2 suffice. The model stops at                   *)
(* H_p+T0+B+react+win+3: a Confirm that stays pending blocks Timeout and   *)
(* can be mined earlier with the same relative timing, so every settle     *)
(* point and its compromise height fit.                                    *)
(*                                                                         *)
(* FIX DESIGN. Deletion on, every terminal state deletes incl. Timeout.    *)
(* ParamsOK: kd + react <= win /\ tdelay + react <= win. EXACT (checked    *)
(* point by point; the Boundary cfg fails).                                *)
(*                                                                         *)
(* CONFIGS -> TIERS (audit/tla/specs.txt):                                 *)
(*   live     CommitteeKeyDeletion.cfg (deletion off, sweep),              *)
(*            CommitteeKeyDeletionTimeout.cfg (on, never on Timeout),      *)
(*            ...Shipped.cfg, ...TimeoutShipped.cfg (shipped values)       *)
(*   design   CommitteeKeyDeletionFixed.cfg (ParamsOK sweep),              *)
(*            CommitteeKeyDeletionFixedShipped.cfg                         *)
(*   boundary CommitteeKeyDeletionFixedBoundary.cfg (~ParamsOK sweep)      *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    NetSet,             \* {} = generic sweep, else the networks whose shipped values to use
    T0Range,            \* generic sweep: connector_z CSV values
    BRange,             \* generic sweep: abandon buffer values
    KDRange,            \* generic sweep: success-side delete delays
    ReactRange,         \* generic sweep: scan lag bounds
    TimeoutDelayRange,  \* generic sweep: fix's delete delay after Timeout
    WindowRange,        \* generic sweep: the claim's window W
    ParamFilter,        \* "all" | "ok" (ParamsOK) | "notok"
    DeleteEnabled,      \* ENABLE_COMMITTEE_INSTANCE_KEY_DELETE (code default FALSE)
    DeleteOnTimeout     \* fix: delete on Timeout too

ASSUME /\ NetSet \subseteq Networks
       /\ ParamFilter \in {"all", "ok", "notok"}
       /\ T0Range \cup BRange \subseteq Nat \ {0}
       /\ KDRange \cup ReactRange \cup TimeoutDelayRange \cup WindowRange \subseteq Nat

\* The honest member's instance statuses (InstanceBridgeInStatus).
Presigned            == "Presigned"
RelayerL1Broadcasted == "RelayerL1Broadcasted"
Timeout              == "Timeout"
UserCanceled         == "UserCanceled"
Statuses == {Presigned, RelayerL1Broadcasted, Timeout, UserCanceled}

\* Peg-In-Confirm states.
NotSent   == "none"
Pending   == "pending"
Confirmed == "confirmed"
ConfirmStates == {NotSent, Pending, Confirmed}

Hp == 1              \* Peg-In-Prepare height (only differences matter)
Generic == "generic" \* net value of a generic-sweep run
KDShipped == 32      \* env.rs:161 DEFAULT_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS

VARIABLES
    net,         \* frozen: network whose shipped values are used (Generic in a sweep)
    t0,          \* frozen: connector_z CSV
    b,           \* frozen: abandon buffer
    kd,          \* frozen: success-side delete delay
    react,       \* frozen: scan lag bound
    tdelay,      \* frozen: fix's delete delay after Timeout
    win,         \* frozen: the claim's window W
    h,           \* Bitcoin tip
    scannedH,    \* highest tip the honest node has scanned
    confirm,     \* Peg-In-Confirm state (ConfirmStates)
    confirmH,    \* height of the block holding the Confirm
    cancel,      \* Peg-In-Cancel confirmed (connector_z spent by the user)
    status,      \* the honest member's instance status
    timeoutH,    \* tip at which the honest node entered Timeout
    keyDeleted,  \* the honest member's envelope deleted
    swept        \* all keys compromised and the BTC moved after settlement

params == <<net, t0, b, kd, react, tdelay, win>>
vars == <<params, h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

H0 == Hp + t0 - 1                        \* window start (see header)
MaxH == Hp + t0 + b + react + win + 3    \* window end (see header)

ParamsOK == kd + react <= win /\ (DeleteOnTimeout => tdelay + react <= win)

InitParams ==
    /\ IF NetSet = {}
          THEN /\ net = Generic
               /\ t0 \in T0Range /\ b \in BRange /\ kd \in KDRange
               /\ react \in ReactRange /\ tdelay \in TimeoutDelayRange /\ win \in WindowRange
          ELSE /\ net \in NetSet
               /\ t0 = ConnectorZ[net] /\ b = PeginAbandonBufferBlocks[net]
               /\ kd = KDShipped /\ react = ReactionBlocks[net]
               /\ tdelay = KDShipped /\ win = KDShipped + ReactionBlocks[net]
    /\ CASE ParamFilter = "all" -> TRUE
         [] ParamFilter = "ok"  -> ParamsOK
         [] OTHER               -> ~ParamsOK

TypeOk ==
    /\ net \in NetSet \cup {Generic}
    /\ t0 \in Nat \ {0} /\ b \in Nat \ {0}
    /\ kd \in Nat /\ react \in Nat /\ tdelay \in Nat /\ win \in Nat
    /\ h \in H0..MaxH /\ scannedH \in (H0 - 1)..MaxH
    /\ confirm \in ConfirmStates /\ confirmH \in 0..MaxH
    /\ cancel \in BOOLEAN /\ status \in Statuses /\ timeoutH \in 0..MaxH
    /\ keyDeleted \in BOOLEAN /\ swept \in BOOLEAN

Init ==
    /\ InitParams
    /\ h = H0 /\ scannedH = H0 - 1
    /\ confirm = NotSent /\ confirmH = 0 /\ cancel = FALSE
    /\ status = Presigned /\ timeoutH = 0
    /\ keyDeleted = FALSE /\ swept = FALSE

--------------------------------------------------------------------------
(* Actions: environment *)

\* Action: the next block arrives - only while the honest node is at most
\*   react blocks behind - carrying the pending Confirm, the user's CSV-valid
\*   Cancel (they conflict), or neither.
\* Source: Bitcoin consensus (connector_z leaf 1 CSV T0 for the Cancel)
Tick ==
    /\ h - scannedH <= react /\ h < MaxH /\ h' = h + 1
    /\ \/ /\ confirm = Pending /\ ~cancel
          /\ confirm' = Confirmed /\ confirmH' = h + 1
          /\ UNCHANGED cancel
       \/ /\ h + 1 >= Hp + t0 /\ confirm # Confirmed /\ ~cancel
          /\ cancel' = TRUE /\ confirm' = NotSent
          /\ UNCHANGED confirmH
       \/ UNCHANGED <<confirm, confirmH, cancel>>
    /\ UNCHANGED <<params, scannedH, status, timeoutH, keyDeleted, swept>>

\* Action: the signed Confirm is broadcast - by the relayer before T0, or
\*   later by anyone holding it (re-relay, a Byzantine aggregator).
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900;
\*   environment (re-relay, Byzantine aggregator)
Broadcast ==
    /\ confirm = NotSent /\ ~cancel
    /\ confirm' = Pending
    /\ UNCHANGED <<params, h, scannedH, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

--------------------------------------------------------------------------
(* Actions: the honest member's node *)

Del(cond) == keyDeleted \/ (DeleteEnabled /\ cond)

\* Action: the honest node scans the tip: decides the status (confirmed
\*   Confirm -> RelayerL1Broadcasted, Cancel -> UserCanceled, past
\*   H_p+T0+B with no Confirm visible -> Timeout) and runs the key deletion
\*   the transition queues: on entering UserCanceled, on the success side
\*   once the Confirm is kd deep, and (fix) tdelay after entering Timeout.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:442 (456-468, 488-517);
\*   enter_failure() instance.rs:826 (890-899); request_key_delete() instance.rs:906;
\*   DeleteInstanceKeyRunner instance_jobs.rs:1086; deletes_key_on_entry() crates/store/src/schema.rs:242
Scan ==
    /\ scannedH < h
    /\ scannedH' = h
    /\ LET s1 == CASE status = Presigned /\ confirm = Confirmed -> RelayerL1Broadcasted
                   [] status = Presigned /\ cancel -> UserCanceled
                   [] status = Presigned /\ confirm = NotSent /\ h >= Hp + t0 + b -> Timeout
                   [] status = Timeout /\ cancel -> UserCanceled
                   [] OTHER -> status
           tH == IF s1 = Timeout /\ status # Timeout THEN h ELSE timeoutH
           failureDelete == s1 = UserCanceled /\ status # UserCanceled
           successDelete == s1 = RelayerL1Broadcasted /\ confirm = Confirmed
                            /\ confirmH + kd <= h
           timeoutDelete == DeleteOnTimeout /\ s1 = Timeout /\ tH + tdelay <= h
       IN /\ status' = s1
          /\ timeoutH' = tH
          /\ keyDeleted' = Del(failureDelete \/ successDelete \/ timeoutDelete)
    /\ UNCHANGED <<params, h, confirm, confirmH, cancel, swept>>

--------------------------------------------------------------------------
(* Actions: the attacker *)

FundsAtRisk == ~cancel   \* connector_z leaf 0 or C0 still holds the BTC

Settled ==
    \/ confirm = Confirmed /\ h > confirmH + win
    \/ status = Timeout /\ h > timeoutH + win

\* Action: the attacker compromises every member's master key + disk once
\*   the instance settled W blocks ago, and moves the BTC with the n-of-n if
\*   all keys still exist.
\* Source: environment (key compromise; keys.rs:217-264 recovers every
\*   undeleted envelope from master key + disk)
Compromise ==
    /\ Settled /\ FundsAtRisk /\ ~keyDeleted /\ ~swept
    /\ swept' = TRUE
    /\ UNCHANGED <<params, h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted>>

Next ==
    \/ Tick
    \/ Broadcast
    \/ Scan
    \/ Compromise

\* Safety only: no fairness needed.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* No full compromise after settlement + W finds the honest key still present.
NoSweepAfterSettlement == ~swept

\* The success side never deletes before the Confirm is kd deep (sanity).
NoEarlySuccessDelete ==
    (keyDeleted /\ status = RelayerL1Broadcasted /\ ~DeleteOnTimeout)
        => confirmH + kd <= h

(* Safety properties: none. Liveness: none (safety findings). *)

====
