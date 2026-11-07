---- MODULE VerifierAssertDecision ----
(***************************************************************************)
(* What a verifier does once an OperatorAssert is confirmed                *)
(* (verifier_assert in node/src/aggregates/graph_pegout_jobs.rs), checked  *)
(* over every combination of what it can observe. The timing side of the  *)
(* same job (how fast each outcome has to land) is TransactionGraph.tla.   *)
(*                                                                         *)
(*   - The Groth16 proof is checked first and on its own: an invalid proof *)
(*     goes straight to ChallengeAssert, without waiting for the           *)
(*     commit-pubin (Connector-E) or the ACK connectors.                   *)
(*   - A valid proof is only accepted once its pubin matches the           *)
(*     commit-pubin. The commit-pubin counts as soon as it is in the       *)
(*     mempool; Commit-Pubin is not presigned, so it is found by the       *)
(*     Connector-E outpoint it spends. A mismatch sends a Pubin-Disprove.  *)
(*   - A match is final only once every ACK connector is settled (spent by *)
(*     an ACK, or by a confirmed timeout), because a later ACK can still   *)
(*     disprove the pubin.                                                 *)
(*   - Failing to read the proof or to check the pubin is never a verdict: *)
(*     the job retries.                                                    *)
(***************************************************************************)
EXTENDS Naturals

VARIABLES assertSettled, proof, commit, pubin, acksSettled

vars == <<assertSettled, proof, commit, pubin, acksSettled>>

Init ==
    \* Connector-D or this verifier's connector of the assert is already spent.
    /\ assertSettled \in BOOLEAN
    \* "Unreadable": witness extraction or verifying-key load failed.
    /\ proof \in {"Valid", "Invalid", "Unreadable"}
    \* What spends Connector-E, and whether it is confirmed.
    /\ commit \in {"None", "PubinMempool", "PubinConfirmed", "TimeoutMempool", "TimeoutConfirmed"}
    \* "CheckError": the ACK inputs or the pubin check could not be evaluated.
    /\ pubin \in {"Consistent", "Inconsistent", "CheckError"}
    /\ acksSettled \in BOOLEAN

Next == FALSE  \* exhaustive check over Init, same idiom as TransactionGraph.tla
Spec == Init /\ [][Next]_vars

CommitPubinSeen == commit \in {"PubinMempool", "PubinConfirmed"}

\* Mirrors the order of checks in verifier_assert.
Decision ==
    IF assertSettled THEN "Done"
    ELSE IF proof = "Unreadable" THEN "Retry"
    ELSE IF proof = "Invalid" THEN "ChallengeAssert"
    ELSE IF commit = "None" \/ commit = "TimeoutMempool" THEN "Retry"
    ELSE IF commit = "TimeoutConfirmed" THEN "Done"
    ELSE IF pubin = "CheckError" THEN "Retry"
    ELSE IF pubin = "Inconsistent" THEN "PubinDisprove"
    ELSE IF ~acksSettled THEN "Retry"
    ELSE "Done"

\* C2: an invalid proof is challenged whatever the commit-pubin and ACK
\* state - in particular before the commit-pubin exists.
InvalidProofChallengedWithoutCommit ==
    (~assertSettled /\ proof = "Invalid") => Decision = "ChallengeAssert"

\* A commit-pubin still in the mempool is enough to disprove a wrong pubin.
MempoolCommitSuffices ==
    (~assertSettled /\ proof = "Valid" /\ commit = "PubinMempool" /\ pubin = "Inconsistent")
        => Decision = "PubinDisprove"

\* A check that could not run is retried: it never becomes a challenge, a
\* disprove, or an acceptance.
CheckFailureIsNotAVerdict ==
    (~assertSettled /\ (proof = "Unreadable" \/ (proof = "Valid" /\ CommitPubinSeen /\ pubin = "CheckError")))
        => Decision = "Retry"

\* An open assert is only left alone when the proof is valid, the pubin
\* matches the commit-pubin and every ACK connector is settled, or when a
\* confirmed Commit-Timeout has already blocked Take-2.
AcceptOnlyWhenEverythingChecked ==
    (~assertSettled /\ Decision = "Done")
        => \/ commit = "TimeoutConfirmed"
           \/ proof = "Valid" /\ CommitPubinSeen /\ pubin = "Consistent" /\ acksSettled

\* Every challenge is backed by the observation it claims.
ChallengesAreJustified ==
    /\ Decision = "ChallengeAssert" => proof = "Invalid"
    /\ Decision = "PubinDisprove" => proof = "Valid" /\ CommitPubinSeen /\ pubin = "Inconsistent"

====
