---- MODULE PegoutPoolCapacity ----
(***************************************************************************)
(* H5: an honest operator answers ChallengeAsserts one at a time; with N   *)
(* verifiers and E blocks of GC evaluation per Wrongly-Challenged, the     *)
(* last answer comes after prover_connector and that verifier Disproves.   *)
(* Models: one JOB_WRONGLY_CHALLENGED per ChallengeAssert (graph_scan.rs   *)
(* assert_flow, graph_pegout.rs route_signal) in the Pegout pool, one      *)
(* node-wide semaphore of pegout_pool_slots permits (default 1;            *)
(* crates/engine/src/jobs.rs:67-69, config.rs:98); claim_due_engine_jobs   *)
(* claims nothing of an aggregate that already has a job Running           *)
(* (crates/store/src/engine/mod.rs:1351-1353), so a graph's N answers run  *)
(* serially. Worst case: G graphs' ChallengeAsserts confirm at height 0;   *)
(* the executor claims a claimable job before the next block, which one is *)
(* nondeterministic. Parameters (frozen variables chosen in Init):         *)
(*   numGraphs G, numChallenges N - graphs challenged at once, verifiers   *)
(*   evalBlocks E - blocks of GC evaluation per answer                     *)
(*   proverConnector T2, inclBlocks Incl, reactBlocks React - timing       *)
(*   pegoutSlots - pegout_pool_slots                                       *)
(* Fix (ParamsOK, exact): React + W + Incl <= T2 with                      *)
(*   W = E * (N + IF Slots >= G THEN 0 ELSE ((G-1)*N) \div Slots),         *)
(*   G = the operator's cap on concurrently challenged graphs.             *)
(* The per-graph budget React + N*E + Incl <= T2 is not enough (G >= 2).   *)
(* Exhaustiveness: React and Incl only shift the window (0..1 shows both   *)
(* count); G, N, Slots in 1..3 cover Slots <, =, > G and every rounding of *)
(* (G-1)*N / Slots; E in 1..2 covers unit vs multi-block evaluation; T2 in *)
(* 1..21 gives margin -1, 0, +1 for every point (W <= 18).                 *)
(* Configs: configs/crates/engine/PegoutPoolCapacity/, tiers in            *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, ShippedTimelockValues

CONSTANTS
    PerAggregateSerial,  \* TRUE: one Running job per graph aggregate (the current claim gate)
    VarDur,              \* TRUE: an evaluation takes any 1..evalBlocks blocks; FALSE: exactly evalBlocks
    UseShipped,          \* TRUE: timing from ShippedTimelockValues, E from EvalSecsRange
    Region,              \* parameter points Init keeps (see InRegion)
    GRange,              \* graphs challenged in one block
    NRange,              \* ChallengeAsserts per graph
    SlotsRange,          \* pegout_pool_slots
    ERange,              \* abstract mode: evaluation blocks per answer
    T2Range,             \* abstract mode: prover_connector
    InclRange,           \* abstract mode: inclusion blocks
    ReactRange,          \* abstract mode: reaction blocks
    NetSet,              \* shipped mode: networks swept
    EvalSecsRange        \* shipped mode: GC evaluation times in seconds, E = ceil(secs / block interval)

ASSUME PerAggregateSerial \in BOOLEAN /\ VarDur \in BOOLEAN /\ UseShipped \in BOOLEAN
ASSUME Region \in {"All", "ParamsOK", "Edge", "PerGraphOnly"}
ASSUME NetSet \subseteq Networks
ASSUME GRange \subseteq Nat \ {0} /\ NRange \subseteq Nat \ {0} /\ SlotsRange \subseteq Nat \ {0}

CeilDiv(a, b) == (a + b - 1) \div b

VARIABLES
    network,          \* frozen: network of the shipped values ("abstract" in abstract mode)
    numGraphs,        \* frozen: G, graphs whose ChallengeAsserts land together
    numChallenges,    \* frozen: N, ChallengeAsserts per graph
    evalBlocks,       \* frozen: E, blocks of GC evaluation per answer
    proverConnector,  \* frozen: prover_connector CSV in blocks
    inclBlocks,       \* frozen: blocks a broadcast needs to confirm
    reactBlocks,      \* frozen: blocks before the scan has queued the jobs
    pegoutSlots,      \* frozen: pegout_pool_slots
    height,           \* blocks since the ChallengeAsserts confirmed
    queued,           \* queued[g]: ChallengeAsserts of graph g not yet claimed
    running,          \* running[g][d]: answers of graph g running with d blocks of evaluation left
    answered          \* answered[g]: answers of graph g broadcast

params == <<network, numGraphs, numChallenges, evalBlocks, proverConnector,
            inclBlocks, reactBlocks, pegoutSlots>>
vars   == <<params, height, queued, running, answered>>

Graphs        == 1..numGraphs
EvalDurations == IF VarDur THEN 1..evalBlocks ELSE {evalBlocks}

\* Last height at which a Wrongly-Challenged broadcast still confirms before Disprove is valid.
LastBroadcast == proverConnector - inclBlocks

\* W: worst-case blocks from reactBlocks to the last answer (see header).
WorstAnswerBlocks ==
    IF PerAggregateSerial
      THEN evalBlocks * (numChallenges + IF pegoutSlots >= numGraphs THEN 0
                                         ELSE ((numGraphs - 1) * numChallenges) \div pegoutSlots)
      ELSE evalBlocks * CeilDiv(numGraphs * numChallenges, pegoutSlots)

\* The fix's graph-validation margin.
ParamsOK == reactBlocks + WorstAnswerBlocks + inclBlocks <= proverConnector

\* Per-graph budget: enough for one graph's N answers.
PerGraphBudget == reactBlocks + numChallenges * evalBlocks + inclBlocks <= proverConnector

\* Init keeps only the parameter points of Region.
InRegion ==
    CASE Region = "All"          -> TRUE
      [] Region = "ParamsOK"     -> ParamsOK
      [] Region = "Edge"         -> reactBlocks + WorstAnswerBlocks + inclBlocks = proverConnector + 1
      [] Region = "PerGraphOnly" -> PerGraphBudget /\ ~ParamsOK

RECURSIVE SumSet(_, _)
SumSet(f, S) == IF S = {} THEN 0
                ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumSet(f, S \ {x})

\* Answers of graph g running; all answers running.
RunningOfGraph(g) == SumSet(running[g], 1..evalBlocks)
TotalRunning      == SumSet([g \in Graphs |-> RunningOfGraph(g)], Graphs)

TypeOk ==
    /\ network \in Networks \cup {"abstract"}
    /\ numGraphs \in Nat \ {0} /\ numChallenges \in Nat \ {0} /\ evalBlocks \in Nat \ {0}
    /\ proverConnector \in Nat /\ inclBlocks \in Nat /\ reactBlocks \in Nat
    /\ pegoutSlots \in Nat \ {0}
    /\ height \in 0..LastBroadcast
    /\ queued \in [Graphs -> 0..numChallenges]
    /\ running \in [Graphs -> [1..evalBlocks -> 0..numChallenges]]
    /\ answered \in [Graphs -> 0..numChallenges]
    /\ \A g \in Graphs : queued[g] + RunningOfGraph(g) + answered[g] = numChallenges

ParamInit ==
    /\ numGraphs \in GRange /\ numChallenges \in NRange /\ pegoutSlots \in SlotsRange
    /\ IF UseShipped
       THEN /\ network \in NetSet
            /\ proverConnector = ProverConnector[network]
            /\ inclBlocks = InclusionBlocks[network]
            /\ reactBlocks = ReactionBlocks[network]
            /\ evalBlocks \in {CeilDiv(s, BlockIntervalSecs[network]) : s \in EvalSecsRange}
       ELSE /\ network = "abstract"
            /\ proverConnector \in T2Range /\ inclBlocks \in InclRange
            /\ reactBlocks \in ReactRange
            /\ evalBlocks \in ERange

Init ==
    /\ ParamInit
    /\ proverConnector > inclBlocks
    /\ InRegion
    /\ height = 0
    /\ queued = [g \in Graphs |-> numChallenges]
    /\ running = [g \in Graphs |-> [d \in 1..evalBlocks |-> 0]]
    /\ answered = [g \in Graphs |-> 0]

-----------------------------------------------------------------------------
\* A job of graph g is claimable: past React, a free permit, and (gate) no job of g running.
CanClaim(g) ==
    /\ height >= reactBlocks
    /\ queued[g] > 0
    /\ TotalRunning < pegoutSlots
    /\ PerAggregateSerial => RunningOfGraph(g) = 0

\* Action: executor claims a Wrongly-Challenged job of graph g, takes a permit
\* and starts a GC evaluation of d blocks.
\* Source: crates/engine/src/jobs.rs:133-168 (semaphores 67-69);
\*         crates/store/src/engine/mod.rs:1336-1393 (aggregate gate 1351-1353);
\*         node/src/aggregates/graph_pegout_jobs.rs:1327-1465 (evaluation at 1432)
Claim(g, d) ==
    /\ CanClaim(g)
    /\ queued' = [queued EXCEPT ![g] = @ - 1]
    /\ running' = [running EXCEPT ![g][d] = @ + 1]
    /\ UNCHANGED <<params, height, answered>>

\* Action: a block is mined once nothing is claimable; evaluations advance one
\* block, finished ones broadcast their Wrongly-Challenged and free the permit.
\* Source: Bitcoin consensus; broadcast at node/src/aggregates/graph_pegout_jobs.rs:1445
Tick ==
    /\ height < LastBroadcast
    /\ ~\E g \in Graphs : CanClaim(g)
    /\ height' = height + 1
    /\ answered' = [g \in Graphs |-> answered[g] + running[g][1]]
    /\ running' = [g \in Graphs |->
                     [d \in 1..evalBlocks |-> IF d < evalBlocks THEN running[g][d + 1] ELSE 0]]
    /\ UNCHANGED <<params, queued>>

Next ==
    \/ \E g \in Graphs, d \in EvalDurations : Claim(g, d)
    \/ Tick

\* No fairness: the deadline is an invariant; executor promptness is Tick's guard.
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* By LastBroadcast every ChallengeAssert is answered (no Disprove of the honest operator).
HonestOperatorAnswersAll ==
    height = LastBroadcast => \A g \in Graphs : answered[g] = numChallenges

\* Every initial parameter point satisfies ParamsOK.
TimelockBudgetCoversAnswers == ParamsOK

\* No step changes the parameters.
ParamsFrozen == [][UNCHANGED params]_vars

====
