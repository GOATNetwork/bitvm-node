---- MODULE CommitteeKeyDeletion ----
(***************************************************************************)
(* H2: the bridge's existential-honesty argument - "one honest committee   *)
(* member deletes its instance key, so n-of-n can never sign again" - does *)
(* not hold for the code as configured and as written.                     *)
(*                                                                         *)
(* Code at dev 60562f8 (after #476):                                       *)
(*                                                                         *)
(*  crates/bitvm-gc/src/keys.rs:217-264: the instance key is random        *)
(*    (OsRng) and lives only in an envelope encrypted under a KEK derived  *)
(*    from the node master key; keys.rs:332-357 deletes the envelope. So   *)
(*    deletion is meaningful: master key + disk of every member recovers   *)
(*    every n-of-n instance key that was not deleted.                      *)
(*  node/src/env.rs:157-158  DEFAULT_ENABLE_COMMITTEE_INSTANCE_KEY_DELETE  *)
(*    = false; env.rs:159-161 delete timelock 32 blocks (KD).               *)
(*  instance.rs:906-919 request_key_delete: with deletion disabled "the    *)
(*    intent is only recorded"; instance_jobs.rs:1092-1094 likewise.        *)
(*  crates/store/src/schema.rs:242-249 deletes_key_on_entry =              *)
(*    NoEnoughCommitteesAnswered | UserDiscarded | UserCanceled (never      *)
(*    Timeout; schema.rs:936 asserts it). instance.rs:890-899 keeps the key *)
(*    "for manual handling" on Timeout.                                    *)
(*  instance.rs:509-517: success side deletes once the Confirm is KD deep, *)
(*    only from RelayerL1Broadcasted | RelayerL2Minted, and those statuses *)
(*    are only scanned when deletion is enabled (instance_scan.rs:182-190). *)
(*  instance.rs:456-468: Timeout + confirmed Confirm only alerts; the row  *)
(*    leaves the scan (instance_scan.rs:228-239). No later deletion.       *)
(*                                                                         *)
(* BTC under n-of-n: connector_z leaf 0 (Peg-In-Prepare output, until the  *)
(* user's Cancel spends it) and C0 (Peg-In-Confirm output). The n-of-n     *)
(* needs EVERY member's key, so with >= 1 honest-at-the-time member the    *)
(* BTC is safe iff that member's key is gone. The model tracks the one     *)
(* honest member; Byzantine members keep their keys forever.               *)
(*                                                                         *)
(* Settled: the Confirm is confirmed (C0 funded), or the honest node gave  *)
(* the instance up (Timeout) - plus the KD delete delay. A Cancel spends   *)
(* connector_z, so nothing is at stake after it.                           *)
(*                                                                         *)
(* CommitteesAnswered keeps the key too (it never expires), but no BTC is  *)
(* under the n-of-n before Peg-In-Prepare confirms, so it is not a sweep   *)
(* risk and is not modeled here.                                           *)
(*                                                                         *)
(* The honest node scans every height before the next block (Tick waits    *)
(* for the scan) and a queued delete job runs within that scan.            *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS T0, B, KD, Hp, MaxHeight,
          DeleteEnabled,    \* ENABLE_COMMITTEE_INSTANCE_KEY_DELETE (default FALSE)
          DeleteOnTimeout,  \* fix: delete on Timeout too
          TimeoutDelay      \* fix: blocks after entering Timeout before deleting

VARIABLES
    h, scannedH,
    confirm,     \* "none" | "pending" | "confirmed"
    confirmH,
    cancel,      \* Peg-In-Cancel confirmed (connector_z spent by the user)
    status,      \* the honest member's instance status
    timeoutH,
    keyDeleted,  \* the honest member's envelope deleted
    swept        \* all keys compromised and the BTC moved after settlement

vars == <<h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

Statuses == {"Presigned", "RelayerL1Broadcasted", "Timeout", "UserCanceled"}

TypeOK ==
    /\ h \in Hp..MaxHeight /\ scannedH \in 0..MaxHeight
    /\ confirm \in {"none", "pending", "confirmed"} /\ confirmH \in 0..MaxHeight
    /\ cancel \in BOOLEAN /\ status \in Statuses /\ timeoutH \in 0..MaxHeight
    /\ keyDeleted \in BOOLEAN /\ swept \in BOOLEAN

Init ==
    /\ h = Hp /\ scannedH = Hp - 1
    /\ confirm = "none" /\ confirmH = 0 /\ cancel = FALSE
    /\ status = "Presigned" /\ timeoutH = 0
    /\ keyDeleted = FALSE /\ swept = FALSE

--------------------------------------------------------------------------
(* Environment *)

Tick ==
    /\ scannedH = h /\ h < MaxHeight /\ h' = h + 1
    /\ UNCHANGED <<scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

\* The signed Confirm is broadcast - by the relayer before T0, or later by
\* anyone holding it (re-relay, a Byzantine aggregator).
Broadcast ==
    /\ confirm = "none" /\ ~cancel
    /\ confirm' = "pending"
    /\ UNCHANGED <<h, scannedH, confirmH, cancel, status, timeoutH, keyDeleted, swept>>

ConfirmMined ==
    /\ confirm = "pending" /\ ~cancel
    /\ confirm' = "confirmed" /\ confirmH' = h
    /\ UNCHANGED <<h, scannedH, cancel, status, timeoutH, keyDeleted, swept>>

CancelMined ==
    /\ h >= Hp + T0 /\ confirm # "confirmed" /\ ~cancel
    /\ cancel' = TRUE /\ confirm' = "none"
    /\ UNCHANGED <<h, scannedH, confirmH, status, timeoutH, keyDeleted, swept>>

--------------------------------------------------------------------------
(* The honest member's node: decide_btc_snapshot + key deletion *)

Del(cond) == keyDeleted \/ (DeleteEnabled /\ cond)

Scan ==
    /\ scannedH < h
    /\ scannedH' = h
    /\ LET s1 == CASE status = "Presigned" /\ confirm = "confirmed" -> "RelayerL1Broadcasted"
                   [] status = "Presigned" /\ cancel -> "UserCanceled"
                   \* Timeout: past H_p+T0+B, Confirm neither confirmed nor visible
                   [] status = "Presigned" /\ confirm = "none" /\ h >= Hp + T0 + B -> "Timeout"
                   [] status = "Timeout" /\ cancel -> "UserCanceled"
                   [] OTHER -> status
           tH == IF s1 = "Timeout" /\ status # "Timeout" THEN h ELSE timeoutH
           \* schema.rs deletes_key_on_entry (UserCanceled here)
           failureDelete == s1 = "UserCanceled" /\ status # "UserCanceled"
           \* instance.rs:509-517
           successDelete == s1 = "RelayerL1Broadcasted" /\ confirm = "confirmed"
                            /\ confirmH + KD <= h
           \* the fix: Timeout deletes too (also Timeout + late confirmed Confirm)
           timeoutDelete == DeleteOnTimeout /\ s1 = "Timeout" /\ tH + TimeoutDelay <= h
       IN /\ status' = s1
          /\ timeoutH' = tH
          /\ keyDeleted' = Del(failureDelete \/ successDelete \/ timeoutDelete)
    /\ UNCHANGED <<h, confirm, confirmH, cancel, swept>>

--------------------------------------------------------------------------
(* The attacker: compromises every member's master key + disk after the   *)
(* instance settled, and signs with the n-of-n if all keys still exist.    *)

FundsAtRisk == ~cancel   \* connector_z leaf 0 or C0 still holds the BTC

Settled ==
    \/ confirm = "confirmed" /\ h > confirmH + KD
    \/ status = "Timeout" /\ h > timeoutH + KD

Compromise ==
    /\ Settled /\ FundsAtRisk /\ ~keyDeleted /\ ~swept
    /\ swept' = TRUE
    /\ UNCHANGED <<h, scannedH, confirm, confirmH, cancel, status, timeoutH, keyDeleted>>

Next == Tick \/ Broadcast \/ ConfirmMined \/ CancelMined \/ Scan \/ Compromise
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
NoSweepAfterSettlement == ~swept

\* Sanity: deletion never precedes the Confirm being KD deep on the success path.
NoEarlySuccessDelete ==
    (keyDeleted /\ status = "RelayerL1Broadcasted" /\ ~DeleteOnTimeout)
        => confirmH + KD <= h

====
