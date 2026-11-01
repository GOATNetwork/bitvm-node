---- MODULE CommitteeKeyDeletion ----
(***************************************************************************)
(* H2: "one honest committee member deletes its instance key, so the       *)
(* n-of-n can never sign again" does not hold for the code. The instance   *)
(* key is random and lives only in an envelope under a KEK from the node   *)
(* master key (crates/bitvm-gc/src/keys.rs:217, deleted at :332), so       *)
(* master key + disk recover every key that was not deleted.               *)
(* Code: deletion is off by default (node/src/env.rs:158); Timeout keeps   *)
(*   the key (schema.rs:242 deletes_key_on_entry; instance.rs:890-900),    *)
(*   also when the Confirm confirms later (instance.rs:459-465 alerts).    *)
(* Model: the BTC under the n-of-n (connector_z leaf 0, then C0) is safe   *)
(*   iff the one honest member's key is gone. NoSweepAfterSettlement: W    *)
(*   blocks after the instance settled (Confirm confirmed, or the honest   *)
(*   node in Timeout), a compromise of every member finds the honest key   *)
(*   deleted. The honest node handles block x before block x + react + 1.  *)
(* Parameters (frozen variables): t0; b (Timeout at H_p + T0 + B); kd      *)
(*   (success-side delete delay); react; tdelay (fix: delete delay after   *)
(*   Timeout); win (W). NetSet = {}: sweep the *Range constants; shipped:  *)
(*   ConnectorZ, PeginAbandonBufferBlocks, kd = tdelay = 32,               *)
(*   ReactionBlocks, W = kd + react.                                       *)
(* Fix: deletion on, every terminal state deletes, Timeout too. ParamsOK   *)
(*   (kd + react <= W /\ tdelay + react <= W) is exact.                    *)
(* Exhaustiveness: deletion is due at confirmH + kd or timeoutH + tdelay   *)
(*   and runs up to react blocks later, so only kd + react and tdelay +    *)
(*   react vs W matter: kd, tdelay, react 0..2, W 0..4 cover every class.  *)
(*   T0 and B only place the Cancel and Timeout: T0, B 1..2 suffice.       *)
(* Configs: configs/node/aggregates/instance/CommitteeKeyDeletion/, tiers  *)
(*   in audit/tla/checks.txt.                                              *)
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
    DeleteEnabled,      \* ENABLE_COMMITTEE_INSTANCE_KEY_DELETE (default FALSE, env.rs:158)
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
KDShipped == 32      \* DEFAULT_COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS (env.rs:161)

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
    swept        \* all keys compromised and the BTC moved after settlement + W

params == <<net, t0, b, kd, react, tdelay, win>>
vars == <<params, h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

\* First tip: before T0 only the success path exists, and a Confirm mined
\* earlier behaves like one mined here.
H0 == Hp + t0 - 1
\* Last tip: a pending Confirm blocks Timeout and can be mined earlier with
\* the same relative timing, so every settle point and its compromise fit.
MaxH == Hp + t0 + b + react + win + 3

\* The fix's condition: every deletion lands within W of settling.
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

\* Action: the next block, while the honest node is at most react blocks
\* behind, carrying the pending Confirm, the CSV-valid Cancel, or neither.
\* Source: Bitcoin consensus
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

\* Action: the signed Confirm is broadcast, by the relayer before T0 or later
\* by anyone holding it.
\* Source: broadcast_pegin_confirm() in node/src/aggregates/instance_jobs.rs:900
\* Source: environment (re-relay, Byzantine aggregator)
Broadcast ==
    /\ confirm = NotSent /\ ~cancel
    /\ confirm' = Pending
    /\ UNCHANGED <<params, h, scannedH, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

--------------------------------------------------------------------------
(* Actions: the honest member's node *)

\* The key after a step that requests deletion when cond holds.
Del(cond) == keyDeleted \/ (DeleteEnabled /\ cond)

\* Action: the honest node scans the tip, decides the status (Confirm ->
\* RelayerL1Broadcasted, Cancel -> UserCanceled, past H_p + T0 + B with no
\* Confirm visible -> Timeout) and runs the key deletion it queues: on
\* entering UserCanceled, once the Confirm is kd deep, (fix) tdelay after Timeout.
\* Source: decide_btc_snapshot() in node/src/aggregates/instance.rs:456-468,489-517
\* Source: enter_failure() in node/src/aggregates/instance.rs:890-900
\* Source: request_key_delete() in node/src/aggregates/instance.rs:906-929
\* Source: DeleteInstanceKeyRunner in node/src/aggregates/instance_jobs.rs:1086-1094
\* Source: deletes_key_on_entry() in crates/store/src/schema.rs:242-249
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

\* The instance settled more than W blocks ago.
Settled ==
    \/ confirm = Confirmed /\ h > confirmH + win
    \/ status = Timeout /\ h > timeoutH + win

\* Action: the attacker compromises every member's master key and disk after
\* settlement + W and moves the BTC with the n-of-n if all keys still exist.
\* Source: environment (key compromise; crates/bitvm-gc/src/keys.rs:217-264 envelopes)
Compromise ==
    /\ Settled /\ FundsAtRisk /\ ~keyDeleted /\ ~swept
    /\ swept' = TRUE
    /\ UNCHANGED <<params, h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted>>

Next ==
    \/ Tick
    \/ Broadcast
    \/ Scan
    \/ Compromise

\* Safety only: no fairness.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants *)

\* No full compromise after settlement + W finds the honest key present.
NoSweepAfterSettlement == ~swept

\* The success side never deletes before the Confirm is kd deep.
NoEarlySuccessDelete ==
    (keyDeleted /\ status = RelayerL1Broadcasted /\ ~DeleteOnTimeout)
        => confirmH + kd <= h

====
