---- MODULE BridgeSafety ----
(* Current code after WCI confirms in block 0 and OperatorAssert in block *)
(* assertAt, which may be after Connector-F has matured.                   *)
(* One watchtower may be offline or collude; the verifier remains honest.  *)
(* The operator controls Commit-Pubin, ACK and watchtower timeout spends.  *)
(* Pubin data, when published, is assumed consistent with the Assert; this *)
(* restricts the attacker and omits the independent Pubin-Disprove path.    *)
(* Honest enabled defences confirm within ActionWindow after discovery.   *)
(* h is the block being built; nodes see confirmed data from block h - 1. *)
EXTENDS Integers, ShippedTimelockValues

VARIABLES net, h, proofValid, watchtower, ack, branchAt,
          e, f, d, assertAt, verifierAssertAt
vars == <<net, h, proofValid, watchtower, ack, branchAt,
          e, f, d, assertAt, verifierAssertAt>>

Max(a, b) == IF a >= b THEN a ELSE b
(* Assert heights that dominate the rest. The defences run relative to    *)
(* the Assert, and Take-2 needs both max(assertAt + D, F) and an open F:   *)
(*  - 0: the Assert with WCI, as before;                                  *)
(*  - F - D: the latest Assert whose Take-2 still waits for F, which gives *)
(*    the defences the least time of any Assert up to F - D;               *)
(*  - F: Connector-F has matured, so Take-2 waits only for D. Every Assert *)
(*    in F - D..F has the same D window; this one leaves the most WCI-     *)
(*    rooted spends of F to the operator's choice.                         *)
AssertHeights == {0, Max(0, ConnectorF[net] - ConnectorD[net]), ConnectorF[net]}
Horizon == ConnectorF[net] + ConnectorD[net]
             + ProverConnector[net] + 2 * ActionWindow[net] + 3

Init ==
    /\ net \in Networks
    /\ h = 1
    /\ proofValid \in BOOLEAN
    /\ watchtower = "open" /\ ack = "open" /\ branchAt = 0
    /\ e = "open" /\ f = "open" /\ d = "open"
    /\ assertAt \in AssertHeights /\ verifierAssertAt = -1

TypeOk ==
    /\ net \in Networks /\ h \in 1..Horizon /\ proofValid \in BOOLEAN
    /\ watchtower \in {"open", "challenged", "timeout"}
    /\ ack \in {"open", "acked", "timeout", "nacked"}
    /\ e \in {"open", "committed", "timeout"}
    /\ f \in {"open", "timeout", "nacked", "take2"}
    /\ d \in {"open", "disproved", "take2"}
    /\ branchAt \in 0..h /\ assertAt \in AssertHeights /\ verifierAssertAt \in -1..h

(* Source: graph_scan.rs watchtower_flow, Commit-Timeout signal at :697.  *)
(* T6 alone gates it; unresolved watchtower branches do not.              *)
CommitTimeoutEnabled ==
    /\ e = "open" /\ f = "open" /\ h >= OperatorCommit[net] + 1
(* Source: graph_scan.rs watchtower_flow, NackReady at :648-659.           *)
NackEnabled ==
    /\ watchtower = "challenged" /\ h > branchAt
    /\ ack = "open" /\ f = "open" /\ h >= OperatorAck[net] + 1
(* Source: graph_pegout_jobs.rs verifier_assert, proof check at :775. An   *)
(* invalid proof is challenged without waiting for Connector E.          *)
ChallengeEnabled ==
    /\ ~proofValid /\ d = "open" /\ h > assertAt
    /\ verifierAssertAt = -1
(* Source: graph_scan.rs wrongly_challenge_timeout and                    *)
(* is_spendable_in_next_block: due once block h satisfies the CSV.        *)
DisproveEnabled ==
    /\ d = "open" /\ verifierAssertAt >= 1
    /\ h >= verifierAssertAt + ProverConnector[net]

(* Action: the operator publishes an ACK, even without a WT challenge.    *)
(* Source: goat transactions/watchtower_challenge.rs operator_challenge_ack. *)
PublishAck ==
    /\ ack = "open" /\ ack' = "acked" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, watchtower, e, f, d, assertAt, verifierAssertAt>>

(* Action: an optional watchtower challenge confirms. No honest WT is    *)
(* assumed: one honest verifier must still protect against invalid proof. *)
PublishWatchtowerChallenge ==
    /\ watchtower = "open" /\ watchtower' = "challenged" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, ack, e, f, d, assertAt, verifierAssertAt>>

(* Action: the operator may spend the WT timeout, but may withhold it.     *)
(* Source: goat WatchtowerChallengeTimeoutTransaction, WCI-rooted CSV.    *)
WatchtowerTimeout ==
    /\ watchtower = "open" /\ ack = "open" /\ h >= WatchtowerChallenge[net]
    /\ watchtower' = "timeout" /\ ack' = "timeout" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, e, f, d, assertAt, verifierAssertAt>>

(* Action: the operator publishes its WOTS pubin evidence. The E leaf     *)
(* does not require watchtower resolution, unlike the honest node's job. *)
PublishPubin ==
    /\ e = "open" /\ e' = "committed"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, f, d, assertAt, verifierAssertAt>>

(* Actions: honest verifier defences, confirmed at h.                     *)
CommitTimeout ==
    /\ CommitTimeoutEnabled
    /\ e' = "timeout" /\ f' = "timeout"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, d, assertAt, verifierAssertAt>>
Nack ==
    /\ NackEnabled /\ ack' = "nacked" /\ f' = "nacked"
    /\ UNCHANGED <<net, h, proofValid, watchtower, branchAt, e, d, assertAt, verifierAssertAt>>
ChallengeAssert ==
    /\ ChallengeEnabled /\ verifierAssertAt' = h
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, f, d, assertAt>>
Disprove ==
    /\ DisproveEnabled /\ d' = "disproved"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, f, assertAt, verifierAssertAt>>

(* Action: Take-2 spends D and F at their actual CSV maturity.             *)
(* Source: goat transactions/take2.rs, ConnectorD and ConnectorF inputs.  *)
Take2 ==
    /\ d = "open" /\ f = "open"
    /\ h >= assertAt + ConnectorD[net] /\ h >= ConnectorF[net]
    /\ d' = "take2" /\ f' = "take2"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, assertAt, verifierAssertAt>>

(* Do not let time starve an enabled honest defence beyond its budget.    *)
Tick ==
    /\ h < Horizon
    /\ ~(CommitTimeoutEnabled /\ h >= OperatorCommit[net] + 1 + ActionWindow[net])
    /\ ~(NackEnabled /\ h >= Max(OperatorAck[net] + 1, branchAt + 1) + ActionWindow[net])
    /\ ~(ChallengeEnabled /\ h >= assertAt + 1 + ActionWindow[net])
    /\ ~(DisproveEnabled /\ h >= verifierAssertAt + ProverConnector[net] + ActionWindow[net])
    /\ h' = h + 1
    /\ UNCHANGED <<net, proofValid, watchtower, ack, branchAt, e, f, d, assertAt, verifierAssertAt>>

(* Once D or F is spent, Take-2 can no longer happen and D never reopens,  *)
(* so no later step can violate a requirement; the model stops there.     *)
Next == /\ d = "open" /\ f = "open"
        /\ \/ PublishAck \/ PublishWatchtowerChallenge \/ WatchtowerTimeout \/ PublishPubin
           \/ CommitTimeout \/ Nack \/ ChallengeAssert \/ Disprove \/ Take2 \/ Tick
Spec == Init /\ [][Next]_vars

(* Protocol requirements, not expected failures or recorded attack traces. *)
NoInvalidProofTake2 == d = "take2" => proofValid
Take2HasCommittedPubin == d = "take2" => e = "committed"
====
