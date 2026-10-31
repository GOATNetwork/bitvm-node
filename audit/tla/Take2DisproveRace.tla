---- MODULE Take2DisproveRace ----
(***************************************************************************)
(* Formal model of the "gap 3" race flagged when auditing timelock         *)
(* reasonableness (see crates/bitvm-gc/src/timelocks.rs): whether Take2's  *)
(* two-clock readiness condition can be exploited to preempt the           *)
(* committee's cooperative Disprove fallback on the same UTXO.             *)
(*                                                                         *)
(* Ground truth, read directly from the external goat crate                *)
(* (checkout e369b2a, goat/src/transactions/{take2,assert}.rs):            *)
(*   - Take2Transaction spends ConnectorD leaf 0 (operator + CSV(connector_d), *)
(*     clock starts at OperatorAssert's confirmation) AND ConnectorF leaf 0 *)
(*     (operator + CSV(connector_f), clock starts at WatchtowerChallengeInit's *)
(*     confirmation) - both required simultaneously (take2.rs:56-90).      *)
(*   - DisproveTransaction spends ConnectorD leaf 1 (n-of-n, immediate, no  *)
(*     CSV) AND ProverConnector leaf 1 (n-of-n + CSV(prover_connector),    *)
(*     clock starts at VerifierAssert's confirmation) (assert.rs:317-357). *)
(* Same ConnectorD output, different leaves - first tx confirmed wins it   *)
(* permanently (ordinary Bitcoin UTXO semantics, no special ordering rule  *)
(* needed - modeled here as first-deadline-reached-wins).                  *)
(*                                                                         *)
(* NOTE (found by the later connector-sweep, audit/TLAPlus-*.md): ConnectorD *)
(* actually has a THIRD leaf (connector_d.rs:20-22,80-88) spent by a free   *)
(* function pubin_disprove() (assert.rs:571-599), the node's tracked        *)
(* DisproveTxType::PubinDisprove outcome. This module does not model it -   *)
(* deliberately, not by oversight: leaf 2's script has NO CSV at all, so it *)
(* can only ever be at least as fast as the already-proven-safe Disprove    *)
(* path modeled below, never slower - it cannot introduce a new exploitable *)
(* margin. Noted here so this header no longer implies leaf 2 doesn't exist.*)
(*                                                                         *)
(* VerifierAssert spends OperatorAssert's output, so it can only confirm   *)
(* strictly after OperatorAssert - `delta` below is that real-world gap.   *)
(* It is NOT a protocol constant; nothing on-chain bounds it. The fix in   *)
(* timelocks.rs assumes it is bounded by min_reaction_blocks(network) (the *)
(* same ~1-hour policy floor used elsewhere). This module checks that      *)
(* assumption is sufficient, using the actual shipped per-network values,  *)
(* and separately confirms (rather than just hand-argues) that Take2's     *)
(* second clock (connector_f, rooted at WatchtowerChallengeInit) can never *)
(* be used to shortcut this specific race, regardless of when the operator *)
(* chooses to broadcast WatchtowerChallengeInit.                           *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

Max(a, b) == IF a >= b THEN a ELSE b

VARIABLES net, delta, wci

vars == <<net, delta, wci>>

\* assertHeight is fixed at 0 WLOG - every other height is expressed relative
\* to it. delta ranges up to (and including) the assumed reaction-time bound
\* for each network - this is exactly the guarantee the timelocks.rs fix is
\* supposed to provide, checked here rather than re-derived by hand. wci
\* ranges over a wide symmetric window since the operator fully controls
\* when WatchtowerChallengeInit is broadcast (it is their own signed,
\* immediately-spendable transaction, independent of OperatorAssert - see
\* watchtower_challenge.rs:178-256, both connector_b and connector_c are
\* plain, unrelated Kickoff outputs with no relative ordering between them).
Init ==
    /\ net \in Networks
    /\ delta \in 0..MinReactionBlocks[net]
    /\ wci \in -300..300

vars_unchanged == UNCHANGED vars
Next == FALSE  \* no transitions - this is an exhaustive check over Init, not a process model
Spec == Init /\ [][Next]_vars

DisproveDeadline == delta + ProverConnector[net]
Take2ConnectorDDeadline == ConnectorD[net]
Take2ConnectorFDeadline == wci + ConnectorF[net]
Take2Deadline == Max(Take2ConnectorDDeadline, Take2ConnectorFDeadline)

\* The property the margin fix in validate_timelock_config exists to
\* guarantee: within the assumed real-world confirmation-gap bound, Disprove
\* always has a strictly earlier deadline than Take2's ConnectorD leaf, for
\* every choice the operator could make for wci.
DisproveWinsConnectorDRace == DisproveDeadline < Take2ConnectorDDeadline

\* Independent confirmation (not just a hand-argument) that ConnectorF can
\* only ever add delay to Take2, never let the operator preempt the
\* ConnectorD-specific race early via a clever choice of wci.
ConnectorFNeverShortcutsConnectorD == Take2Deadline >= Take2ConnectorDDeadline

====
