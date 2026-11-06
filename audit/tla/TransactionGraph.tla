---- MODULE TransactionGraph ----
(* Basic maturity relations, not a model of relay, jobs, proofs or settlement. *)
(* Values are generated from Rust; transaction wiring and CSV inputs are     *)
(* checked separately by tests/transaction_graph_invariants.rs.              *)
EXTENDS Integers, ShippedTimelockValues

VARIABLES net, verifierDelay, wciHeight
vars == <<net, verifierDelay, wciHeight>>

(* OperatorAssert confirms at height 0. WCI may precede or follow it.        *)
(* This bounded range includes both sides of the D/F maturity crossover.    *)
Init ==
    /\ net \in Networks
    /\ verifierDelay \in 0..ActionWindow[net]
    /\ wciHeight \in (-ConnectorF[net])..ConnectorD[net]
Next == FALSE
Spec == Init /\ [][Next]_vars

TypeOk ==
    /\ net \in Networks
    /\ verifierDelay \in 0..ActionWindow[net]
    /\ wciHeight \in (-ConnectorF[net])..ConnectorD[net]

Max(a, b) == IF a >= b THEN a ELSE b
Take2Height == Max(ConnectorD[net], wciHeight + ConnectorF[net])

Take1MeetsConfiguredBudget == ConnectorA[net] >= ActionWindow[net]
AckMeetsConfiguredBudget == OperatorAck[net] - WatchtowerChallenge[net] >= ActionWindow[net]
(* Disprove-X before Take-2. Through D, after an Assert that arrives once *)
(* F has matured: the block it is seen in, an ActionWindow each for       *)
(* Verifier-Assert and for Disprove-X after the CSV, strictly before      *)
(* Take-2's block. Through F, after a Commit-Pubin held back until just   *)
(* before T6: reaction, Verifier-Assert inclusion, the prover-connector   *)
(* CSV, its own inclusion and safety.                                     *)
DisproveMeetsConfiguredBudget ==
    ConnectorD[net] - ProverConnector[net] >= 2 * ActionWindow[net] + 2
LateCommitMeetsConfiguredBudget ==
    ConnectorF[net] - OperatorCommit[net] >= ProverConnector[net] + DisproveWindow[net]
TimeoutsMatureBeforeTake2ViaF ==
    /\ OperatorAck[net] < ConnectorF[net]
    /\ OperatorCommit[net] < ConnectorF[net]

(* Assumption: VerifierAssert confirms at most ActionWindow after Assert.   *)
(* This compares earliest validity heights; BridgeSafety checks when      *)
(* Disprove-X actually confirms against Take-2.                           *)
DisproveMaturesBeforeTake2ViaD ==
    verifierDelay + ProverConnector[net] < ConnectorD[net]

Take2RequiresBothTimelocks ==
    /\ Take2Height >= ConnectorD[net]
    /\ Take2Height >= wciHeight + ConnectorF[net]
====
