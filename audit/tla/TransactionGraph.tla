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
(* Disprove-X: reaction, Verifier-Assert inclusion, the prover-connector  *)
(* CSV, its own inclusion and safety before Take-2 through either clock;  *)
(* through F the event is a Commit-Pubin held back until just before T6. *)
DisproveMeetsConfiguredBudget ==
    ConnectorD[net] - ProverConnector[net] >= DisproveWindow[net]
LateCommitMeetsConfiguredBudget ==
    ConnectorF[net] - OperatorCommit[net] >= ProverConnector[net] + DisproveWindow[net]
TimeoutsMatureBeforeTake2ViaF ==
    /\ OperatorAck[net] < ConnectorF[net]
    /\ OperatorCommit[net] < ConnectorF[net]

(* Assumption: VerifierAssert confirms at most ActionWindow after Assert.   *)
(* This compares earliest validity heights, not actual confirmation times. *)
DisproveMaturesBeforeTake2ViaD ==
    verifierDelay + ProverConnector[net] < ConnectorD[net]

Take2RequiresBothTimelocks ==
    /\ Take2Height >= ConnectorD[net]
    /\ Take2Height >= wciHeight + ConnectorF[net]
====
