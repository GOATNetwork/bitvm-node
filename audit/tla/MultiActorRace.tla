---- MODULE MultiActorRace ----
(***************************************************************************)
(* Take2DisproveRace.tla abstracted "the watchtower" and "the verifier" as *)
(* single actors. The real protocol has N independent watchtowers and M    *)
(* independent verifiers (audit/tla/Take2DisproveRace.tla's header /        *)
(* node/README.md document the single-actor version). This module checks  *)
(* whether N=2/M=2 introduces anything the single-actor abstraction        *)
(* couldn't see - the concern being: with multiple independent actors      *)
(* timing their own actions, could the "any ONE honest actor suffices"     *)
(* property (verified structurally true by a dedicated research pass -    *)
(* see below) actually fail on the TIMING axis even though it holds        *)
(* logically?                                                              *)
(*                                                                         *)
(* Ground truth (verified by reading goat/src/{connectors,transactions}/*.rs *)
(* directly, not assumed):                                                 *)
(*   - WATCHTOWERS: all N watchtowers' WatchtowerChallengeConnector[i]/    *)
(*     AckConnector[i] pairs are outputs of the SAME, single                *)
(*     WatchtowerChallengeInitTransaction. So every watchtower's challenge  *)
(*     window AND the operator's ack window for that slot are measured     *)
(*     from the SAME shared height, regardless of which watchtower acts or *)
(*     when. There is no genuine multi-clock complexity on this side - N   *)
(*     watchtowers share ONE clock. If watchtower i is un-acked, its Nack  *)
(*     spends the shared ConnectorF leaf1, permanently blocking Take2's    *)
(*     leaf0 (first-confirmed-wins UTXO semantics) - true 1-of-N by        *)
(*     construction, confirmed via detect_watchtower_flow_disprove         *)
(*     (node/src/utils.rs:1299-1326), which returns Disprove on the FIRST  *)
(*     nack found, no counting/quorum.                                     *)
(*   - VERIFIERS: structurally identical EXCEPT each verifier's clock       *)
(*     genuinely is independent - VerifierAssertTransaction[i] confirms at *)
(*     verifier i's own pace (whenever THEY finish detecting fraud), not a *)
(*     shared height. This is the one place N/M actually could matter.     *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

VARIABLES
    net,
    wtChallengeHeight1, wtChallengeHeight2, \* watchtower i challenges at this height within [0, WatchtowerChallenge[net]], or NEVER
    verifierDelta1, verifierDelta2          \* verifier i's own independent assert-confirmation gap after OperatorAssert (assertHeight = 0 WLOG), or NEVER

vars == <<net, wtChallengeHeight1, wtChallengeHeight2, verifierDelta1, verifierDelta2>>

NEVER == -1

Init ==
    /\ net \in Networks
    /\ wtChallengeHeight1 \in ({NEVER} \cup 0..WatchtowerChallenge[net])
    /\ wtChallengeHeight2 \in ({NEVER} \cup 0..WatchtowerChallenge[net])
    /\ verifierDelta1 \in ({NEVER} \cup 0..MinReactionBlocks[net])
    /\ verifierDelta2 \in ({NEVER} \cup 0..MinReactionBlocks[net])

Next == FALSE \* exhaustive check over Init, not a process model - see Take2DisproveRace.tla
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Watchtower side: both slots share ONE clock (WatchtowerChallengeInit's  *)
(* confirmation, height 0 here), independent of when each watchtower acts. *)

Challenged(h) == h # NEVER
NackDeadline == OperatorAck[net]                 \* shared, same for every watchtower slot
Take2ReadyHeightViaF == ConnectorF[net]
OperatorAckWindow(challengeHeight) == NackDeadline - challengeHeight

\* For every possible timing of both watchtowers - including both waiting
\* until the literal last block of their window - an operator notified the
\* instant a challenge lands still has a strictly positive number of blocks
\* to construct and confirm their Ack before the shared deadline. Checked
\* per watchtower since neither's window depends on the other's timing (no
\* shared clock to contend over on THIS axis).
WatchtowerAckWindowAlwaysPositive ==
    /\ (Challenged(wtChallengeHeight1) => OperatorAckWindow(wtChallengeHeight1) > 0)
    /\ (Challenged(wtChallengeHeight2) => OperatorAckWindow(wtChallengeHeight2) > 0)

\* If a watchtower's Nack ever becomes available (operator failed to ack in
\* time - the worst case for the operator), it is always available strictly
\* before Take2 could fire via connector_f, independent of the OTHER
\* watchtower's behavior or timing.
NackAlwaysBeatsTake2ViaF ==
    /\ (Challenged(wtChallengeHeight1) => NackDeadline < Take2ReadyHeightViaF)
    /\ (Challenged(wtChallengeHeight2) => NackDeadline < Take2ReadyHeightViaF)

--------------------------------------------------------------------------
(* ConnectorF leaf 1 (the "committee blocks Take2" leaf) has TWO           *)
(* alternative spenders, not one - confirmed by reading                    *)
(* goat/src/transactions/watchtower_challenge.rs directly:                 *)
(* OperatorChallengeNackTransaction (leaf1, checked above via              *)
(* NackAlwaysBeatsTake2ViaF) AND OperatorCommitTimeoutTransaction (also     *)
(* leaf1, watchtower_challenge.rs:714-747, jointly spending ConnectorE     *)
(* leaf1 as its other input). The Rust side already enforces               *)
(* operator_commit < connector_f (timelocks.rs's                          *)
(* ensure_lt("operator_commit", ..., "connector_f", ...)) but - unlike the *)
(* operator_ack/Nack case - that comparison was never independently        *)
(* confirmed here using real shipped values. Same shared clock root as     *)
(* every other property in this module (WatchtowerChallengeInit's          *)
(* confirmation - operator_commit's clock starts there via ConnectorE's    *)
(* own construction, symmetric to operator_ack's), and not a multi-actor   *)
(* quantity (one operator, one commit-or-not decision per graph, not per   *)
(* watchtower), so no new VARIABLE is needed - just the real numbers.      *)
CommitTimeoutDeadline == OperatorCommit[net]
CommitTimeoutAlwaysBeatsTake2ViaF == CommitTimeoutDeadline < Take2ReadyHeightViaF

--------------------------------------------------------------------------
(* Verifier side: genuinely independent clocks - each verifier's own delta. *)

DisproveDeadline(delta) == delta + ProverConnector[net]
Take2ReadyHeightViaD == ConnectorD[net]

\* Symmetric to the watchtower property: EACH verifier's disprove deadline
\* (rooted at THEIR OWN assert height) must beat Take2's connector_d
\* deadline, regardless of the other verifier's independent timing.
DisproveAlwaysBeatsTake2ViaD ==
    /\ (verifierDelta1 # NEVER => DisproveDeadline(verifierDelta1) < Take2ReadyHeightViaD)
    /\ (verifierDelta2 # NEVER => DisproveDeadline(verifierDelta2) < Take2ReadyHeightViaD)

====
