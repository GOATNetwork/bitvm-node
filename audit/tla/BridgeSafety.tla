---- MODULE BridgeSafety ----
(* Current code after WCI and OperatorAssert confirm in block 0.           *)
(* One watchtower may be offline or collude; the verifier remains honest.  *)
(* The operator controls Commit-Pubin, ACK and watchtower timeout spends.  *)
(* Pubin data, when published, is assumed consistent with the Assert; this *)
(* restricts the attacker and omits the independent Pubin-Disprove path.    *)
(* Honest enabled defences confirm within ActionWindow after discovery.   *)
(* h is the block being built; nodes see confirmed data from block h - 1. *)
EXTENDS Integers, ShippedTimelockValues

VARIABLES net, h, proofValid, watchtower, ack, branchAt,
          e, f, d, verifierAssertAt
vars == <<net, h, proofValid, watchtower, ack, branchAt,
          e, f, d, verifierAssertAt>>

Max(a, b) == IF a >= b THEN a ELSE b
Horizon == Max(ConnectorD[net], ConnectorF[net])
             + ProverConnector[net] + 2 * ActionWindow[net] + 3

Init ==
    /\ net \in Networks
    /\ h = 1
    /\ proofValid \in BOOLEAN
    /\ watchtower = "open" /\ ack = "open" /\ branchAt = 0
    /\ e = "open" /\ f = "open" /\ d = "open"
    /\ verifierAssertAt = -1

TypeOk ==
    /\ net \in Networks /\ h \in 1..Horizon /\ proofValid \in BOOLEAN
    /\ watchtower \in {"open", "challenged", "timeout"}
    /\ ack \in {"open", "acked", "timeout", "nacked"}
    /\ e \in {"open", "committed", "timeout"}
    /\ f \in {"open", "timeout", "nacked", "take2"}
    /\ d \in {"open", "disproved", "take2"}
    /\ branchAt \in 0..h /\ verifierAssertAt \in -1..h

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
    /\ ~proofValid /\ d = "open" /\ verifierAssertAt = -1
(* Source: graph_scan.rs wrongly_challenge_timeout and is_timelock_ready. *)
DisproveEnabled ==
    /\ d = "open" /\ verifierAssertAt >= 1
    /\ h >= verifierAssertAt + ProverConnector[net] + 1

(* Action: the operator publishes an ACK, even without a WT challenge.    *)
(* Source: goat transactions/watchtower_challenge.rs operator_challenge_ack. *)
PublishAck ==
    /\ ack = "open" /\ ack' = "acked" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, watchtower, e, f, d, verifierAssertAt>>

(* Action: an optional watchtower challenge confirms. No honest WT is    *)
(* assumed: one honest verifier must still protect against invalid proof. *)
PublishWatchtowerChallenge ==
    /\ watchtower = "open" /\ watchtower' = "challenged" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, ack, e, f, d, verifierAssertAt>>

(* Action: the operator may spend the WT timeout, but may withhold it.     *)
(* Source: goat WatchtowerChallengeTimeoutTransaction, WCI-rooted CSV.    *)
WatchtowerTimeout ==
    /\ watchtower = "open" /\ ack = "open" /\ h >= WatchtowerChallenge[net]
    /\ watchtower' = "timeout" /\ ack' = "timeout" /\ branchAt' = h
    /\ UNCHANGED <<net, h, proofValid, e, f, d, verifierAssertAt>>

(* Action: the operator publishes its WOTS pubin evidence. The E leaf     *)
(* does not require watchtower resolution, unlike the honest node's job. *)
PublishPubin ==
    /\ e = "open" /\ e' = "committed"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, f, d, verifierAssertAt>>

(* Actions: honest verifier defences, confirmed at h.                     *)
CommitTimeout ==
    /\ CommitTimeoutEnabled
    /\ e' = "timeout" /\ f' = "timeout"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, d, verifierAssertAt>>
Nack ==
    /\ NackEnabled /\ ack' = "nacked" /\ f' = "nacked"
    /\ UNCHANGED <<net, h, proofValid, watchtower, branchAt, e, d, verifierAssertAt>>
ChallengeAssert ==
    /\ ChallengeEnabled /\ verifierAssertAt' = h
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, f, d>>
Disprove ==
    /\ DisproveEnabled /\ d' = "disproved"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, f, verifierAssertAt>>

(* Action: Take-2 spends D and F at their actual CSV maturity.             *)
(* Source: goat transactions/take2.rs, ConnectorD and ConnectorF inputs.  *)
Take2 ==
    /\ d = "open" /\ f = "open"
    /\ h >= ConnectorD[net] /\ h >= ConnectorF[net]
    /\ d' = "take2" /\ f' = "take2"
    /\ UNCHANGED <<net, h, proofValid, watchtower, ack, branchAt, e, verifierAssertAt>>

(* Do not let time starve an enabled honest defence beyond its budget.    *)
Tick ==
    /\ h < Horizon
    /\ ~(CommitTimeoutEnabled /\ h >= OperatorCommit[net] + 1 + ActionWindow[net])
    /\ ~(NackEnabled /\ h >= Max(OperatorAck[net] + 1, branchAt + 1) + ActionWindow[net])
    /\ ~(ChallengeEnabled /\ h >= 1 + ActionWindow[net])
    /\ ~(DisproveEnabled /\ h >= verifierAssertAt + ProverConnector[net] + 1 + ActionWindow[net])
    /\ h' = h + 1
    /\ UNCHANGED <<net, proofValid, watchtower, ack, branchAt, e, f, d, verifierAssertAt>>

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
