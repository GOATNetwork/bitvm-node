---- MODULE PegoutPoolCapacity ----
(***************************************************************************)
(* PURPOSE. Finding H5: an honest operator answers ChallengeAsserts one at *)
(* a time, so with N verifiers challenging and E blocks of GC evaluation   *)
(* per answer the last Wrongly-Challenged is broadcast at ~N*E blocks -    *)
(* past prover_connector when N*E > prover_connector - Incl - React, and   *)
(* that verifier disproves an honest operator. The Pegout pool is also     *)
(* shared by every graph of the operator, so G graphs challenged together  *)
(* queue behind each other.                                               *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476):                                 *)
(*  - assert_flow (node/src/aggregates/graph_scan.rs:700-738) emits one    *)
(*    ChallengeAssertSent{challenge_assert_txid, verifier_index} per       *)
(*    confirmed Verifier-Assert (:734); route_signal                       *)
(*    (node/src/aggregates/graph_pegout.rs:253, :275) routes each to       *)
(*    JOB_WRONGLY_CHALLENGED, one job per verifier (distinct params).      *)
(*  - pegout_job_pool (graph_pegout.rs:87-96): JOB_WRONGLY_CHALLENGED =>   *)
(*    JobPool::Pegout. crates/engine/src/config.rs:97-99 defaults          *)
(*    cpu_pool_slots 1, pegout_pool_slots 1, network_pool_slots 4;         *)
(*    crates/engine/src/jobs.rs:67-69 makes each ONE Semaphore of that     *)
(*    many permits for the whole node (shared by ALL graphs).              *)
(*  - claim_due_engine_jobs (crates/store/src/engine/mod.rs:1336-1393)     *)
(*    skips every job of an aggregate that already has a job Running under *)
(*    a live lease, in any pool (:1351-1353). All N answers of a graph     *)
(*    belong to ONE aggregate, so they are serialized even if              *)
(*    pegout_pool_slots were raised; different graphs are not.             *)
(*  - wrongly_challenged (node/src/aggregates/graph_pegout_jobs.rs:1327-   *)
(*    1465) runs the BABE GC evaluation inline                             *)
(*    (recover_real_wrongly_challenged_witness :1432 ->                    *)
(*    crates/bitvm-gc/src/babe_adapter.rs:653 prover.check_compute_msg,    *)
(*    the base instance then up to BABE_M_CC-1 = 6 more, :60), then        *)
(*    broadcasts and goes back to Pending for one block (broadcast_pending *)
(*    :230) - that re-run is cheap and not modelled. The evaluation time   *)
(*    is not a constant of this repo, so E is a swept parameter.           *)
(*  - wrongly_challenge_timeout (graph_scan.rs:742-788): once the          *)
(*    ChallengeAssert has prover_connector confirmations unanswered, the   *)
(*    verifier's disprove job fires (WronglyChallengeTimeout, :781).       *)
(*  - validate_timelock_config (crates/bitvm-gc/src/timelocks.rs:222)      *)
(*    checks only ensure_at_least("prover_connector", .., action_window):  *)
(*    no term for N answers of E blocks each.                              *)
(*                                                                         *)
(* Worst case: the ChallengeAsserts of G graphs (N each) confirm in the    *)
(* same block, height 0 (colluding verifiers can arrange it). Time is in   *)
(* blocks. The executor is work-conserving: a job that can be claimed is   *)
(* claimed before the next block; WHICH job is claimed is nondeterministic *)
(* (claim_due_engine_jobs orders by next_at, created_at, which an attacker *)
(* shapes by the order of its ChallengeAsserts).                           *)
(*                                                                         *)
(* PARAMETERS (frozen variables, chosen once in Init):                     *)
(*   numGraphs       G: graphs of the operator challenged in one block     *)
(*   numChallenges   N: ChallengeAsserts per graph (verifiers)             *)
(*   evalBlocks      E: blocks of GC evaluation per Wrongly-Challenged     *)
(*   proverConnector T2: the prover_connector CSV                          *)
(*   inclBlocks      InclusionBlocks; answers must be broadcast by         *)
(*                   proverConnector - inclBlocks                          *)
(*   reactBlocks     ReactionBlocks; nothing is claimed before height      *)
(*                   reactBlocks                                           *)
(*   pegoutSlots     pegout_pool_slots (shipped default 1)                 *)
(* The claim gate (PerAggregateSerial) is a design CONSTANT; VarDur lets   *)
(* every evaluation take any 1..E blocks instead of exactly E.             *)
(*                                                                         *)
(* WORST-CASE ANSWER TIME. With the per-aggregate gate a graph's N answers *)
(* run one after another; while the last graph waits, every slot is busy   *)
(* with the other G-1 graphs' work, so it waits at most                    *)
(* floor((G-1)*N/Slots) rounds of E blocks when Slots < G (the others can  *)
(* fill all slots that long by round-robin), and never when Slots >= G:    *)
(*   W == E * (N + IF Slots >= G THEN 0 ELSE ((G-1)*N) \div Slots)         *)
(* Without the gate (alternative design) W == E * ceil(G*N / Slots).       *)
(* FIX DESIGN (ParamsOK), validated per graph with G = the operator's cap  *)
(* on concurrently challengeable graphs (or Slots >= G reserved):          *)
(*   ParamsOK == React + W + Incl <= prover_connector                      *)
(* ParamsOK is EXACT for both gate settings (a full-sweep state dump of    *)
(* all 4428 abstract points: every point inside passes, every point       *)
(* outside fails) and stays sufficient with VarDur = TRUE.                *)
(* The ORIGINAL per-graph fix (prover_connector >= React + N*E + Incl,     *)
(* i.e. G = 1) is NOT enough: two graphs challenged in one block share the *)
(* single Pegout slot. Raising pegout_pool_slots alone does not help (the  *)
(* per-aggregate gate); lifting the gate is rejected because each          *)
(* evaluation holds a flat GC in memory.                                   *)
(*                                                                         *)
(* EXHAUSTIVENESS of the abstract ranges: React and Incl only shift the    *)
(* window, so only T2 - Incl - React matters; React, Incl in 0..1 show     *)
(* both are counted. The schedule depends on G, N, Slots through Slots vs  *)
(* G (<, =, >) and the rounding of (G-1)*N / Slots; G, N, Slots in 1..3    *)
(* cover every such class and E in 1..2 covers unit vs multi-block         *)
(* evaluations. T2 in 1..21 gives margin -1, 0, +1 for every combination   *)
(* (W <= 18, React + Incl <= 2); a larger T2 only adds idle blocks.        *)
(*                                                                         *)
(* SHIPPED VALUES (UseShipped = TRUE): network \in NetSet, proverConnector *)
(* = ProverConnector[net], inclBlocks = InclusionBlocks[net], reactBlocks  *)
(* = ReactionBlocks[net]; evalBlocks = ceil(EvalSecs / BlockIntervalSecs   *)
(* [net]) for EvalSecs \in EvalSecsRange; N, G, Slots from their ranges.   *)
(*                                                                         *)
(* CONFIGS AND TIERS (specs.txt):                                          *)
(*   live      PegoutPoolCapacity.cfg              shipped, 1 slot         *)
(*   live      PegoutPoolCapacitySlotsOnly.cfg     shipped, 5 slots        *)
(*   design    PegoutPoolCapacityFixed.cfg         fix, abstract sweep     *)
(*   design    PegoutPoolCapacityFixedShipped.cfg  fix, shipped            *)
(*   boundary  PegoutPoolCapacityBoundary.cfg      T2 one block short      *)
(*   boundary  PegoutPoolCapacityPerGraphOnly.cfg  original per-graph fix  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, ShippedTimelockValues

CONSTANTS
    PerAggregateSerial,  \* claim_due_engine_jobs gate: one Running job per graph aggregate
    VarDur,              \* TRUE: an evaluation takes any 1..evalBlocks blocks; FALSE: exactly evalBlocks
    UseShipped,          \* TRUE: proverConnector/inclBlocks/reactBlocks from ShippedTimelockValues
    Region,              \* "All" | "ParamsOK" | "Edge" | "PerGraphOnly": which parameter points Init keeps
    GRange,              \* both modes: graphs challenged in one block
    NRange,              \* both modes: ChallengeAsserts per graph
    SlotsRange,          \* both modes: pegout_pool_slots
    ERange,              \* abstract mode: evaluation blocks per answer
    T2Range,             \* abstract mode: prover_connector values
    InclRange,           \* abstract mode: inclusion blocks
    ReactRange,          \* abstract mode: reaction blocks
    NetSet,              \* shipped mode: networks swept, \subseteq Networks
    EvalSecsRange        \* shipped mode: GC evaluation times in seconds

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

\* Last height at which a Wrongly-Challenged may be broadcast and still
\* confirm before the verifier's Disprove becomes valid.
LastBroadcast == proverConnector - inclBlocks

\* Worst-case height of the last answer, measured from reactBlocks.
WorstAnswerBlocks ==
    IF PerAggregateSerial
      THEN evalBlocks * (numChallenges + IF pegoutSlots >= numGraphs THEN 0
                                         ELSE ((numGraphs - 1) * numChallenges) \div pegoutSlots)
      ELSE evalBlocks * CeilDiv(numGraphs * numChallenges, pegoutSlots)

\* The fix's margin (graph validation).
ParamsOK == reactBlocks + WorstAnswerBlocks + inclBlocks <= proverConnector

\* The original per-graph fix: enough for ONE graph's N answers.
PerGraphBudget == reactBlocks + numChallenges * evalBlocks + inclBlocks <= proverConnector

InRegion ==
    CASE Region = "All"          -> TRUE
      [] Region = "ParamsOK"     -> ParamsOK
      [] Region = "Edge"         -> reactBlocks + WorstAnswerBlocks + inclBlocks = proverConnector + 1
      [] Region = "PerGraphOnly" -> PerGraphBudget /\ ~ParamsOK

RECURSIVE SumSet(_, _)
SumSet(f, S) == IF S = {} THEN 0
                ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumSet(f, S \ {x})

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
\* A due Wrongly-Challenged job of graph g can be claimed: past the
\* reaction delay, a free Pegout permit, and (current code) no other job of
\* the same graph aggregate running.
CanClaim(g) ==
    /\ height >= reactBlocks
    /\ queued[g] > 0
    /\ TotalRunning < pegoutSlots
    /\ PerAggregateSerial => RunningOfGraph(g) = 0

\* Action: the executor claims one due Wrongly-Challenged job of graph g
\*   (taking a Pegout permit) and starts its GC evaluation, which will take
\*   d blocks.
\* Source: claim_and_spawn() in crates/engine/src/jobs.rs:133-170 (Semaphore :67-69);
\*         claim_due_engine_jobs() in crates/store/src/engine/mod.rs:1336-1393 (aggregate gate :1351-1353);
\*         wrongly_challenged() in node/src/aggregates/graph_pegout_jobs.rs:1327 (evaluation :1432)
Claim(g, d) ==
    /\ CanClaim(g)
    /\ queued' = [queued EXCEPT ![g] = @ - 1]
    /\ running' = [running EXCEPT ![g][d] = @ + 1]
    /\ UNCHANGED <<params, height, answered>>

\* Action: a Bitcoin block is mined (only once no job is claimable - the
\*   executor is work-conserving); every running evaluation advances one
\*   block and a finished one broadcasts its Wrongly-Challenged at the new
\*   height, releasing its permit.
\* Source: Bitcoin consensus (block production); broadcast in wrongly_challenged()
\*         node/src/aggregates/graph_pegout_jobs.rs:1327-1465
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

\* No fairness: the property is an invariant at the deadline height; the
\* executor's promptness is encoded in Tick's guard.
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* ---- Safety invariants

\* By the last useful broadcast height every ChallengeAssert of every graph
\* is answered (so no verifier can Disprove the honest operator).
HonestOperatorAnswersAll ==
    height = LastBroadcast => \A g \in Graphs : answered[g] = numChallenges

\* (Parameter check) the swept/shipped parameters satisfy the fix's
\* validation arithmetic.
TimelockBudgetCoversAnswers == ParamsOK

\* ---- Safety properties

\* The parameters are frozen: no step changes them.
ParamsFrozen == [][UNCHANGED params]_vars

\* ---- Liveness
\* None: the deadline is stated as an invariant at height LastBroadcast.

====
