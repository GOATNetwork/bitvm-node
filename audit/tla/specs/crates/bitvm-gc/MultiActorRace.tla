---- MODULE MultiActorRace ----
(***************************************************************************)
(* Purpose: Take2DisproveRace.tla treats "the watchtower" and "the         *)
(* verifier" as single actors. The protocol has N watchtowers and M        *)
(* verifiers, and any ONE honest actor must suffice. This module checks    *)
(* N = M = 2 on the timing axis: can independent actors' timing open a gap *)
(* the single-actor abstraction cannot see? Findings 5/10. Init-only       *)
(* arithmetic over the shipped per-network timelocks (ShippedTimelocks).   *)
(*                                                                         *)
(* Code scope (current tree):                                              *)
(*   goat crate bab46c2 (Cargo.lock), goat/src:                            *)
(*     transactions/watchtower_challenge.rs:209-222  every watchtower's    *)
(*       WatchtowerChallengeConnector[i] / AckConnector[i] pair is an      *)
(*       output of the ONE WatchtowerChallengeInit, as are ConnectorE      *)
(*       (:228-231) and ConnectorF (:234-237): all watchtower clocks start *)
(*       at the same height.                                               *)
(*     connectors/watchtower_connectors.rs:40-59  challenge leaf 0         *)
(*       (watchtower key, no CSV); timeout leaf 1 = operator +             *)
(*       CSV(watchtower_challenge).                                        *)
(*     connectors/watchtower_connectors.rs:156-163  AckConnector leaf 2 =  *)
(*       n-of-n + CSV(operator_ack), spent by OperatorChallengeNack        *)
(*       together with ConnectorF leaf 1 (watchtower_challenge.rs:550-554).*)
(*     connectors/connector_e.rs:56-65  ConnectorE leaf 1 = n-of-n +       *)
(*       CSV(operator_commit), spent by OperatorCommitTimeout together     *)
(*       with ConnectorF leaf 1 (watchtower_challenge.rs:721-725).         *)
(*     connectors/connector_f.rs:38-55  leaf 0 = operator +                *)
(*       CSV(connector_f) (Take2), leaf 1 = n-of-n, no CSV (NACK /         *)
(*       CommitTimeout): first confirmed spend wins the output.            *)
(*     Verifier side: VerifierAssert[i] confirms at verifier i's own pace  *)
(*       and roots ProverConnector[i] (assert.rs:210-245); Disprove[i]     *)
(*       spends it with ConnectorD leaf 1 (assert.rs:316-327). The one     *)
(*       place where M independent clocks exist.                           *)
(*   node:                                                                 *)
(*     node/src/aggregates/graph_scan.rs:573-700 watchtower_flow: NACK is  *)
(*       ready per watchtower slot (:648-656, :677), CommitTimeout at       *)
(*       wci + operator_commit (:681-686).                                 *)
(*     node/src/utils/graph_chain_state.rs:195-220                         *)
(*       detect_watchtower_flow_disprove: the FIRST confirmed NACK settles *)
(*       the graph as disproved, no counting or quorum (true 1-of-N).      *)
(*     node/src/aggregates/graph_scan.rs:742-790 (Disprove), :792-843      *)
(*       (Take2 readiness, both clocks).                                   *)
(*   crates/bitvm-gc/src/timelocks.rs:173-239 validate_timelock_config.    *)
(*     Comparisons it enforces on these races:                             *)
(*       :186      every value >= reaction_blocks                          *)
(*       :203-207  watchtower_challenge >= action_window + proof_blocks    *)
(*       :208-214  operator_ack - watchtower_challenge >= action_window    *)
(*       :215-221  operator_commit - max(watchtower_challenge,             *)
(*                 operator_ack) >= confirmed_action_window                *)
(*       :222      prover_connector >= action_window                       *)
(*       :223-229  connector_d - prover_connector >= action_window         *)
(*       :230-236  connector_f - operator_commit >= confirmed_action_window*)
(*     (action_window = reaction + inclusion + safety, :91-95;             *)
(*      confirmed_action_window = evidence + inclusion + safety, :103-107).*)
(*   What the validator implies for EVERY config it accepts, vs. what      *)
(*   holds only because the shipped values have slack:                     *)
(*     WatchtowerAckWindowAlwaysPositive, OperatorAckWindowMeetsActionWindow*)
(*       - implied (:208-214, action_window >= 1 on every network).        *)
(*     NackAlwaysBeatsTake2ViaF, CommitTimeoutAlwaysBeatsTake2ViaF -       *)
(*       implied only where confirmed_action_window > 0 (then              *)
(*       connector_f - operator_ack >= 2 * confirmed_action_window). On    *)
(*       Regtest it is 0 and ensure_gap_at_least uses saturating_sub       *)
(*       (:252-266), so the validator puts NO order between operator_ack,  *)
(*       operator_commit and connector_f there.                            *)
(*     DisproveAlwaysBeatsTake2ViaD - NOT implied: at the :223-229 floor a *)
(*       verifier one action window late only ties Take2 (reproduced by    *)
(*       Take2DisproveRace/Validated.cfg).                                  *)
(*   Every shipped config passes all of them.                              *)
(*                                                                         *)
(* Config / tier: MultiActorRace/Shipped.cfg (pass), shipped values; the validator *)
(* floors on the shipped configs are an ASSUME (constant-level).          *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

\* A watchtower that never challenges / a verifier that never asserts.
NEVER == -1

\* confirmed_action_window() and watchtower_proof_window() of
\* timelocks.rs:97-107 (ShippedTimelockValues carries the components).
ConfirmedActionWindow == [n \in Networks |->
    EvidenceConfirmations[n] + InclusionBlocks[n] + SafetyBlocks[n]]
WatchtowerProofWindow == [n \in Networks |-> ActionWindow[n] + WatchtowerProofBlocks[n]]

Max(a, b) == IF a >= b THEN a ELSE b

\* ensure_gap_at_least(left, right, required) of timelocks.rs:252-266: the
\* gap is right.saturating_sub(left), so a required gap of 0 accepts any order.
GapAtLeast(left, right, required) == Max(right - left, 0) >= required

\* Assumption: each shipped config passes every validator comparison on these races
\* (timelocks.rs:186,203-236). Constant-level, so checked once as an ASSUME
\* instead of on each of the ~8.5M states.
MeetsValidatorFloors(n) ==
    /\ \A v \in {ProverConnector[n], ConnectorD[n], WatchtowerChallenge[n],
                 OperatorAck[n], OperatorCommit[n], ConnectorF[n]} :
           v >= ReactionBlocks[n]
    /\ WatchtowerChallenge[n] >= WatchtowerProofWindow[n]
    /\ GapAtLeast(WatchtowerChallenge[n], OperatorAck[n], ActionWindow[n])
    /\ GapAtLeast(Max(WatchtowerChallenge[n], OperatorAck[n]), OperatorCommit[n],
                  ConfirmedActionWindow[n])
    /\ ProverConnector[n] >= ActionWindow[n]
    /\ GapAtLeast(ProverConnector[n], ConnectorD[n], ActionWindow[n])
    /\ GapAtLeast(OperatorCommit[n], ConnectorF[n], ConfirmedActionWindow[n])

ASSUME ShippedConfigsMeetValidatorFloors == \A n \in Networks : MeetsValidatorFloors(n)

VARIABLES
    net,                 \* Bitcoin network whose timelocks and timing budget apply
    wtChallengeHeight1,  \* watchtower 1 challenges at this height after WatchtowerChallengeInit, or NEVER
    wtChallengeHeight2,  \* watchtower 2 challenges at this height after WatchtowerChallengeInit, or NEVER
    verifierDelta1,      \* verifier 1's VerifierAssert confirms this long after OperatorAssert, or NEVER
    verifierDelta2       \* verifier 2's VerifierAssert confirms this long after OperatorAssert, or NEVER

vars == <<net, wtChallengeHeight1, wtChallengeHeight2, verifierDelta1, verifierDelta2>>

WatchtowerHeights(n) == {NEVER} \cup 0..WatchtowerChallenge[n]
VerifierDeltas(n)    == {NEVER} \cup 0..MinReactionBlocks[n]

\* Written as disjunctions: x \in {NEVER} \cup 0..k would make TLC build the
\* union set on every state.
TypeOk ==
    /\ net \in Networks
    /\ wtChallengeHeight1 = NEVER \/ wtChallengeHeight1 \in 0..WatchtowerChallenge[net]
    /\ wtChallengeHeight2 = NEVER \/ wtChallengeHeight2 \in 0..WatchtowerChallenge[net]
    /\ verifierDelta1 = NEVER \/ verifierDelta1 \in 0..MinReactionBlocks[net]
    /\ verifierDelta2 = NEVER \/ verifierDelta2 \in 0..MinReactionBlocks[net]

\* Action: the only "step": pick a network and, independently for each of two
\* watchtowers, a challenge height inside its window (or no challenge), and
\* for each of two verifiers an assert delay within one action window (or no
\* assert). WatchtowerChallengeInit and OperatorAssert are each at height 0
\* of their own clock.
\* Source: environment (actor timing); windows from default_timelock_config()
\*   in crates/bitvm-gc/src/timelocks.rs:54-61 via ShippedTimelockValues.tla.
Init ==
    /\ net \in Networks
    /\ wtChallengeHeight1 \in WatchtowerHeights(net)
    /\ wtChallengeHeight2 \in WatchtowerHeights(net)
    /\ verifierDelta1 \in VerifierDeltas(net)
    /\ verifierDelta2 \in VerifierDeltas(net)

\* No transitions: an exhaustive check over Init, not a process model.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
Challenged(h)               == h # NEVER
NackDeadline                == OperatorAck[net]       \* AckConnector leaf 2 CSV, shared by every slot
CommitTimeoutDeadline       == OperatorCommit[net]    \* ConnectorE leaf 1 CSV, same clock root
Take2ReadyHeightViaF        == ConnectorF[net]        \* ConnectorF leaf 0 CSV, same clock root
OperatorAckWindow(h)        == NackDeadline - h       \* blocks the operator has to get its Ack in
DisproveDeadline(d)         == d + ProverConnector[net]
Take2ReadyHeightViaD        == ConnectorD[net]

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* Whenever each watchtower challenges (even in the last block of its
\* window), the operator still has a positive number of blocks to Ack it
\* before the shared NACK deadline.
WatchtowerAckWindowAlwaysPositive ==
    /\ (Challenged(wtChallengeHeight1) => OperatorAckWindow(wtChallengeHeight1) > 0)
    /\ (Challenged(wtChallengeHeight2) => OperatorAckWindow(wtChallengeHeight2) > 0)

\* The operator's Ack window is at least the action window the validator
\* budgets (timelocks.rs:208-214), for every challenge timing.
OperatorAckWindowMeetsActionWindow ==
    /\ (Challenged(wtChallengeHeight1) => OperatorAckWindow(wtChallengeHeight1) >= ActionWindow[net])
    /\ (Challenged(wtChallengeHeight2) => OperatorAckWindow(wtChallengeHeight2) >= ActionWindow[net])

\* If a challenged watchtower is not acked, its NACK becomes valid strictly
\* before Take2 via ConnectorF, independent of the other watchtower.
NackAlwaysBeatsTake2ViaF ==
    /\ (Challenged(wtChallengeHeight1) => NackDeadline < Take2ReadyHeightViaF)
    /\ (Challenged(wtChallengeHeight2) => NackDeadline < Take2ReadyHeightViaF)

\* The second ConnectorF leaf-1 spender, OperatorCommitTimeout, also becomes
\* valid strictly before Take2 via ConnectorF.
CommitTimeoutAlwaysBeatsTake2ViaF == CommitTimeoutDeadline < Take2ReadyHeightViaF

\* Each verifier's Disprove, rooted at its OWN assert height, becomes valid
\* strictly before Take2's ConnectorD leaf, whatever the other verifier does.
DisproveAlwaysBeatsTake2ViaD ==
    /\ (verifierDelta1 # NEVER => DisproveDeadline(verifierDelta1) < Take2ReadyHeightViaD)
    /\ (verifierDelta2 # NEVER => DisproveDeadline(verifierDelta2) < Take2ReadyHeightViaD)

====
