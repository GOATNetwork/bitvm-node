---- MODULE MultiActorRace ----
(***************************************************************************)
(* 1-of-N timing margins with two watchtowers and two verifiers acting     *)
(* independently (Findings 5, 10). Init-only arithmetic over the shipped   *)
(* values. Take2DisproveRace.tla is the single-actor view.                 *)
(* Code (goat bab46c2, goat/src): the one WatchtowerChallengeInit creates  *)
(*   every watchtower's challenge/Ack connector pair, ConnectorE and       *)
(*   ConnectorF (transactions/watchtower_challenge.rs:209-237), so all     *)
(*   watchtower clocks share one root. A watchtower challenges via leaf 0  *)
(*   before leaf 1's CSV(watchtower_challenge)                             *)
(*   (watchtower_connectors.rs:40-59). NACK = AckConnector leaf 2,         *)
(*   CSV(operator_ack), + ConnectorF leaf 1                                *)
(*   (watchtower_connectors.rs:156-163, watchtower_challenge.rs:550-554);  *)
(*   CommitTimeout = ConnectorE leaf 1, CSV(operator_commit), + ConnectorF *)
(*   leaf 1 (connector_e.rs:56-65, watchtower_challenge.rs:721-725); Take2 *)
(*   = ConnectorF leaf 0, CSV(connector_f) (connector_f.rs:38-47). Each    *)
(*   VerifierAssert[i] roots its own ProverConnector[i]                    *)
(*   (assert.rs:210-245). Node: watchtower_flow                            *)
(*   (node/src/aggregates/graph_scan.rs:573-697); the first confirmed NACK *)
(*   disproves the graph (node/src/utils/graph_chain_state.rs:195-220).    *)
(* Findings: all margins hold on the shipped values.                       *)
(*   validate_timelock_config (timelocks.rs:173-239) implies the two       *)
(*   Ack-window properties for any config, the two "beats Take2 via F"     *)
(*   properties only where confirmed_action_window > 0 (not Regtest), and  *)
(*   not DisproveAlwaysBeatsTake2ViaD (Take2DisproveRace/Validated.cfg).   *)
(* Parameters: each watchtower's challenge height (0..watchtower_challenge *)
(*   or never), each verifier's assert delay (0..action_window or never).  *)
(* Exhaustive: every height in each window, independently per actor.       *)
(* Configs: configs/crates/bitvm-gc/MultiActorRace/, tiers in              *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelocks

\* A watchtower that never challenges / a verifier that never asserts.
NEVER == -1

\* confirmed_action_window() and watchtower_proof_window(), timelocks.rs:97-107.
ConfirmedActionWindow == [n \in Networks |->
    EvidenceConfirmations[n] + InclusionBlocks[n] + SafetyBlocks[n]]
WatchtowerProofWindow == [n \in Networks |-> ActionWindow[n] + WatchtowerProofBlocks[n]]

Max(a, b) == IF a >= b THEN a ELSE b

\* ensure_gap_at_least (timelocks.rs:252-266): a required gap of 0 accepts any order.
GapAtLeast(left, right, required) == Max(right - left, 0) >= required

\* validate_timelock_config's checks on these races (timelocks.rs:186, :203-236).
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

\* Every shipped config passes them (constant-level, checked once).
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

\* Disjunctions, so TLC does not build {NEVER} \cup 0..k on every state.
TypeOk ==
    /\ net \in Networks
    /\ wtChallengeHeight1 = NEVER \/ wtChallengeHeight1 \in 0..WatchtowerChallenge[net]
    /\ wtChallengeHeight2 = NEVER \/ wtChallengeHeight2 \in 0..WatchtowerChallenge[net]
    /\ verifierDelta1 = NEVER \/ verifierDelta1 \in 0..MinReactionBlocks[net]
    /\ verifierDelta2 = NEVER \/ verifierDelta2 \in 0..MinReactionBlocks[net]

\* Action: pick a network, each watchtower's challenge height and each
\* verifier's assert delay (or none); WCI and OperatorAssert are each at 0.
\* Source: environment (actor timing); windows from crates/bitvm-gc/src/timelocks.rs:54-61.
Init ==
    /\ net \in Networks
    /\ wtChallengeHeight1 \in WatchtowerHeights(net)
    /\ wtChallengeHeight2 \in WatchtowerHeights(net)
    /\ verifierDelta1 \in VerifierDeltas(net)
    /\ verifierDelta2 \in VerifierDeltas(net)

\* No steps: TLC checks the invariants on every initial state.
Next == FALSE

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
Challenged(h)               == h # NEVER
NackDeadline                == OperatorAck[net]       \* AckConnector leaf 2 CSV, shared by every slot
CommitTimeoutDeadline       == OperatorCommit[net]    \* ConnectorE leaf 1 CSV, same clock root
Take2ReadyHeightViaF        == ConnectorF[net]        \* ConnectorF leaf 0 CSV, same clock root
OperatorAckWindow(h)        == NackDeadline - h       \* blocks the operator has to get its Ack in
DisproveDeadline(d)         == d + ProverConnector[net]  \* ProverConnector leaf 1 CSV, own clock
Take2ReadyHeightViaD        == ConnectorD[net]        \* ConnectorD leaf 0 CSV

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* A challenge even in the last block of its window leaves the operator time to Ack.
WatchtowerAckWindowAlwaysPositive ==
    /\ (Challenged(wtChallengeHeight1) => OperatorAckWindow(wtChallengeHeight1) > 0)
    /\ (Challenged(wtChallengeHeight2) => OperatorAckWindow(wtChallengeHeight2) > 0)

\* ... and at least one action window (timelocks.rs:208-214).
OperatorAckWindowMeetsActionWindow ==
    /\ (Challenged(wtChallengeHeight1) => OperatorAckWindow(wtChallengeHeight1) >= ActionWindow[net])
    /\ (Challenged(wtChallengeHeight2) => OperatorAckWindow(wtChallengeHeight2) >= ActionWindow[net])

\* An unacked challenge's NACK becomes valid strictly before Take2 via ConnectorF.
NackAlwaysBeatsTake2ViaF ==
    /\ (Challenged(wtChallengeHeight1) => NackDeadline < Take2ReadyHeightViaF)
    /\ (Challenged(wtChallengeHeight2) => NackDeadline < Take2ReadyHeightViaF)

\* OperatorCommitTimeout becomes valid strictly before Take2 via ConnectorF.
CommitTimeoutAlwaysBeatsTake2ViaF == CommitTimeoutDeadline < Take2ReadyHeightViaF

\* Each verifier's Disprove becomes valid strictly before Take2's ConnectorD leaf.
DisproveAlwaysBeatsTake2ViaD ==
    /\ (verifierDelta1 # NEVER => DisproveDeadline(verifierDelta1) < Take2ReadyHeightViaD)
    /\ (verifierDelta2 # NEVER => DisproveDeadline(verifierDelta2) < Take2ReadyHeightViaD)

====
