---- MODULE JobObligationPersistence ----
(***************************************************************************)
(* H3: one defence obligation (challenge_kickoff, wrongly_challenged or    *)
(* disprove) must be broadcast in time to confirm before the               *)
(* counterparty's CSV path matures. Models the graph chain scan            *)
(* (graph_scan.rs), which asks for the job under a stable id               *)
(* (effects.rs:30) that engine_job stores with INSERT OR IGNORE: a         *)
(* terminal row is never run again.                                        *)
(* Findings (current code, FixRearm = FALSE):                              *)
(*   (a) a panic ends the row Poisoned; the job never re-runs              *)
(*   (b) a transient Goat revert classified Permanent ends it Done         *)
(*   (c) give-up paths end it Failed (relayer Goat-side jobs only)         *)
(*   (d) a closing stage is decided at 1 confirmation and never rescanned: *)
(*       a reorg replacing Take-1 by a Challenge leaves a false closure    *)
(* Fix (FixRearm = TRUE): re-arm an unbroadcast terminal job under a new   *)
(* generation while the chain still demands it; close at closeDepth.       *)
(* Parameters (frozen variables chosen in Init, see VARIABLES): window,    *)
(* reactBlocks, inclBlocks, retryBlocks, faultBudget, maxReorg,            *)
(* closeDepth (code: 1).                                                   *)
(* ParamsOK (exact): closeDepth > maxReorg /\ reactBlocks                  *)
(*   + faultBudget*retryBlocks + maxReorg + inclBlocks <= window           *)
(* Exhaustiveness: every guard compares a per-block counter with one       *)
(* parameter; the outcome depends on closeDepth vs maxReorg and the sign   *)
(* of the timing margin. React, Incl, faults, maxReorg in 0..2, retry in   *)
(* 1..2, closeDepth in 1..3 hit every class; window in 1..11 gives margin  *)
(* -1, 0, +1 for every point (the sum is at most 10).                      *)
(* Configs: configs/crates/engine/JobObligationPersistence/, tiers in      *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelockValues

CONSTANTS
    FixRearm,         \* FALSE: current code; TRUE: fix design
    FaultKinds,       \* fault paths that exist: "Panic" (a), "Revert" (b), "GiveUp" (c)
    ReorgFaults,      \* 1: the closing tx may be mined first and then reorged out (d); 0: no reorg
    UseShipped,       \* TRUE: window/react/incl/closeDepth from ShippedTimelockValues
    Region,           \* parameter points Init keeps (see InRegion)
    WindowRange,      \* abstract mode: deadline windows
    ReactRange,       \* abstract mode: reaction blocks
    InclRange,        \* abstract mode: inclusion blocks
    CloseDepthRange,  \* abstract mode: closing confirmation depths
    RetryRange,       \* blocks per re-armed attempt
    FaultRange,       \* fault budgets
    MaxReorgRange,    \* reorg depths (shipped mode keeps only those < BtcBlockConfirms)
    NetSet,           \* shipped mode: networks swept
    Obligations,      \* shipped mode: defence jobs swept
    CloseDepthRule    \* shipped mode: closeDepth = 1 ("Code"), BtcBlockConfirms or EvidenceConfirmations

\* Fault kinds, paths (a), (b), (c) of the header.
FaultPanic  == "Panic"
FaultRevert == "Revert"
FaultGiveUp == "GiveUp"

\* engine_job row states plus JobNone = no row yet.
JobNone     == "None"
JobPending  == "Pending"
JobDone     == "Done"
JobFailed   == "Failed"
JobPoisoned == "Poisoned"
JobStates   == {JobNone, JobPending, JobDone, JobFailed, JobPoisoned}

\* The two conflicting spends that may be on the best chain.
TxClose  == "Close"    \* the closing tx (e.g. Take-1)
TxDefend == "Defend"   \* the tx that creates the obligation (e.g. Challenge, ChallengeAssert)

ASSUME FaultKinds \subseteq {FaultPanic, FaultRevert, FaultGiveUp}
ASSUME ReorgFaults \in {0, 1}
ASSUME Region \in {"All", "ParamsOK", "NotParamsOK", "Edge", "TimingOK", "SafetyBudget"}
ASSUME NetSet \subseteq Networks
ASSUME Obligations \subseteq {"challenge_kickoff", "wrongly_challenged", "disprove"}
ASSUME CloseDepthRule \in {"Code", "BtcBlockConfirms", "EvidenceConfirmations"}

Max(a, b) == IF a > b THEN a ELSE b

\* Shipped deadline window of an obligation.
Window(o, n) ==
    CASE o = "challenge_kickoff"  -> ConnectorA[n]
      [] o = "wrongly_challenged" -> ProverConnector[n]
      [] o = "disprove"           -> ConnectorD[n] - ProverConnector[n]

\* Shipped closing depth under CloseDepthRule.
ShippedCloseDepth(n) ==
    CASE CloseDepthRule = "Code"                  -> 1
      [] CloseDepthRule = "BtcBlockConfirms"      -> BtcBlockConfirms[n]
      [] CloseDepthRule = "EvidenceConfirmations" -> Max(1, EvidenceConfirmations[n])

VARIABLES
    network,        \* frozen: network of the shipped values ("abstract" in abstract mode)
    obligation,     \* frozen: defence job ("abstract" in abstract mode)
    window,         \* frozen: blocks from the obligation tx to the counterparty's CSV
    reactBlocks,    \* frozen: blocks from first sighting to the first attempt
    inclBlocks,     \* frozen: blocks from broadcast to confirmation
    retryBlocks,    \* frozen: blocks per re-armed attempt
    faultBudget,    \* frozen: attempts that may end without a broadcast
    maxReorg,       \* frozen: deepest reorg
    closeDepth,     \* frozen: confirmations at which a closing stage is decided
    bestTx,         \* TxClose | TxDefend: the spend on the best chain
    confs,          \* confirmations of bestTx (1 in the block that mines it)
    countered,      \* the counterparty discharged the obligation (answered on chain)
    scanned,        \* the chain scan for this height ran (SCAN_MARKS)
    closed,         \* local Graph.status is closed (absorbing, never rescanned)
    job,            \* engine_job row of the defence job
    claimWait,      \* blocks until the Pending row is claimed
    jobGeneration,  \* fix only: generation component of the job id
    broadcast,      \* the defence transaction was broadcast
    faultsLeft,     \* remaining fault budget
    reorgsLeft      \* remaining reorg budget

params == <<network, obligation, window, reactBlocks, inclBlocks, retryBlocks,
            faultBudget, maxReorg, closeDepth>>
state  == <<bestTx, confs, countered, scanned, closed, job, claimWait,
            jobGeneration, broadcast, faultsLeft, reorgsLeft>>
vars   == <<params, state>>

\* Reorg depth in effect (0 without ReorgFaults).
EffReorg == IF ReorgFaults > 0 THEN maxReorg ELSE 0

\* The fix's margin: closure half and timing half.
CloseOK  == closeDepth > EffReorg
TimingOK == reactBlocks + faultBudget * retryBlocks + EffReorg + inclBlocks <= window
ParamsOK == CloseOK /\ TimingOK

\* Faults and reorg fit in safety_blocks, the slack validate_timelock_config
\* reserves in every window (window >= reaction + inclusion + safety).
SafetyBudget == UseShipped /\ faultBudget * retryBlocks + EffReorg <= SafetyBlocks[network]

\* Just outside ParamsOK: closeDepth = maxReorg with timing met, or timing one
\* block short with closure met (and window > inclBlocks).
Edge ==
    \/ closeDepth = EffReorg /\ TimingOK
    \/ CloseOK /\ window > inclBlocks
       /\ reactBlocks + faultBudget * retryBlocks + EffReorg + inclBlocks = window + 1

\* Init keeps only the parameter points of Region.
InRegion ==
    CASE Region = "All"          -> TRUE
      [] Region = "Edge"         -> Edge
      [] Region = "ParamsOK"     -> ParamsOK
      [] Region = "NotParamsOK"  -> ~ParamsOK
      [] Region = "TimingOK"     -> TimingOK
      [] Region = "SafetyBudget" -> SafetyBudget

\* The chain still demands the defence.
Pre == bestTx = TxDefend /\ ~countered

TypeOk ==
    /\ network \in Networks \cup {"abstract"}
    /\ obligation \in {"challenge_kickoff", "wrongly_challenged", "disprove", "abstract"}
    /\ window \in Int /\ reactBlocks \in Nat /\ inclBlocks \in Nat
    /\ retryBlocks \in Nat \ {0} /\ faultBudget \in Nat
    /\ maxReorg \in Nat /\ closeDepth \in Nat \ {0}
    /\ bestTx \in {TxClose, TxDefend}
    /\ confs \in Nat \ {0}
    /\ countered \in BOOLEAN /\ scanned \in BOOLEAN /\ closed \in BOOLEAN
    /\ job \in JobStates
    /\ claimWait \in Nat
    /\ jobGeneration \in 0..faultBudget
    /\ broadcast \in BOOLEAN
    /\ faultsLeft \in 0..faultBudget /\ reorgsLeft \in 0..ReorgFaults

ParamInit ==
    IF UseShipped
    THEN /\ network \in NetSet
         /\ obligation \in Obligations
         /\ window = Window(obligation, network)
         /\ reactBlocks = ReactionBlocks[network]
         /\ inclBlocks = InclusionBlocks[network]
         /\ closeDepth = ShippedCloseDepth(network)
         /\ maxReorg \in {r \in MaxReorgRange : r < BtcBlockConfirms[network]}
         /\ retryBlocks \in RetryRange
         /\ faultBudget \in FaultRange
    ELSE /\ network = "abstract" /\ obligation = "abstract"
         /\ window \in WindowRange
         /\ reactBlocks \in ReactRange
         /\ inclBlocks \in InclRange
         /\ closeDepth \in CloseDepthRange
         /\ maxReorg \in MaxReorgRange
         /\ retryBlocks \in RetryRange
         /\ faultBudget \in FaultRange

Init ==
    /\ ParamInit
    /\ InRegion
    \* With ReorgFaults the closing tx may be mined first.
    /\ bestTx \in IF ReorgFaults > 0 THEN {TxClose, TxDefend} ELSE {TxDefend}
    /\ confs = 1
    /\ countered = FALSE
    /\ scanned = FALSE
    /\ closed = FALSE
    /\ job = JobNone
    /\ claimWait = 0
    /\ jobGeneration = 0
    /\ broadcast = FALSE
    /\ faultsLeft = faultBudget
    /\ reorgsLeft = ReorgFaults

-----------------------------------------------------------------------------
\* The scan closes the graph now (absorbing).
ClosesNow == bestTx = TxClose /\ confs >= closeDepth

\* The scan makes the row Pending: code - only a missing row (INSERT OR IGNORE);
\* fix - also a terminal row that did not broadcast (new generation).
Arms ==
    IF FixRearm THEN ~broadcast /\ job \in {JobNone, JobDone, JobFailed, JobPoisoned}
                ELSE job = JobNone

\* Action: node's once-per-height scan of an open graph closes it at closeDepth
\* confirmations and, while the chain demands the defence, enqueues the job
\* (first row after reactBlocks, re-armed row after retryBlocks - 1).
\* Source: node/src/aggregates/graph_scan.rs:131-155,169-240 (SCAN_MARKS at 197), gather_chain_scan 303;
\*         node/src/utils/graph_chain_state.rs:302-316 (1-conf closure, node/src/utils/btc.rs:457);
\*         node/src/aggregates/graph_pegout.rs:598-606; crates/engine/src/effects.rs:30;
\*         crates/store/src/engine/mod.rs:1276-1315 (INSERT OR IGNORE at 1282);
\*         crates/engine/src/worker.rs:330-349
Scan ==
    /\ ~closed /\ ~scanned
    /\ scanned' = TRUE
    /\ closed' = ClosesNow
    /\ IF Pre /\ Arms
          THEN /\ job' = JobPending
               /\ claimWait' = IF job = JobNone THEN reactBlocks ELSE retryBlocks - 1
               /\ jobGeneration' = IF job = JobNone THEN jobGeneration ELSE jobGeneration + 1
          ELSE UNCHANGED <<job, claimWait, jobGeneration>>
    /\ UNCHANGED <<params, bestTx, confs, countered, broadcast, faultsLeft, reorgsLeft>>

\* The executor claims the due row and runs settlement_step with the given outcome.
RunBase(outcome) ==
    /\ job = JobPending /\ claimWait = 0
    /\ outcome
    /\ UNCHANGED <<params, bestTx, confs, countered, scanned, closed, claimWait,
                   jobGeneration, reorgsLeft>>

\* Action: defence job on a closed graph or with no obligation ends Done without a broadcast.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:76-96 (closed graph), 193-201 (spend confirmed)
RunIgnored ==
    RunBase(/\ (closed \/ ~Pre)
            /\ job' = JobDone
            /\ UNCHANGED <<broadcast, faultsLeft>>)

\* Action: defence job broadcasts the defence tx while the chain demands it; row ends Done.
\* Source: crates/engine/src/jobs.rs:133-168,188-301;
\*         node/src/aggregates/graph_pegout_jobs.rs:76 (challenge_kickoff 595, wrongly_challenged 1327)
RunBroadcast ==
    RunBase(/\ ~closed /\ Pre
            /\ job' = JobDone /\ broadcast' = TRUE
            /\ UNCHANGED faultsLeft)

\* Row state each fault path leaves.
FaultEnd(k) ==
    CASE k = FaultPanic  -> JobPoisoned
      [] k = FaultRevert -> JobDone
      [] k = FaultGiveUp -> JobFailed

\* Action: defence job ends terminal without a broadcast (environment fault, up
\* to faultBudget): (a) panic -> Poisoned, (b) revert -> Done, (c) give-up -> Failed.
\* Source: (a) crates/engine/src/jobs.rs:223,245; crates/store/src/engine/mod.rs:1474-1476;
\*         (b) node/src/aggregates/graph_jobs.rs:130-135; node/src/error.rs:33-77;
\*         (c) node/src/aggregates/graph_pegout_jobs.rs:1612,1622; crates/engine/src/jobs.rs:203
RunFault ==
    \E k \in FaultKinds :
        RunBase(/\ ~closed /\ Pre /\ faultsLeft > 0
                /\ job' = FaultEnd(k) /\ faultsLeft' = faultsLeft - 1
                /\ UNCHANGED broadcast)

Run == RunIgnored \/ RunBroadcast \/ RunFault

\* Nothing left to decide: the defence deadline passed, or the closure is past any reorg.
Settled ==
    \/ bestTx = TxDefend /\ confs - 1 + inclBlocks > window
    \/ bestTx = TxClose /\ confs > Max(closeDepth, EffReorg)

\* Action: a block is mined, once this height's scan ran (or the graph is closed)
\* and no job is due; claimWait counts down.
\* Source: Bitcoin consensus
Tick ==
    /\ ~Settled
    /\ scanned \/ closed
    /\ ~(job = JobPending /\ claimWait = 0)
    /\ confs' = confs + 1
    /\ scanned' = FALSE
    /\ claimWait' = IF job = JobPending THEN claimWait - 1 ELSE claimWait
    /\ UNCHANGED <<params, bestTx, countered, closed, job, jobGeneration, broadcast,
                   faultsLeft, reorgsLeft>>

\* Action: a reorg of depth <= maxReorg replaces the closing tx by the obligation
\* tx; same height, so a scan that already ran is not repeated (SCAN_MARKS).
\* Source: environment; node/src/aggregates/graph_scan.rs:78,197
Reorg ==
    /\ reorgsLeft > 0
    /\ bestTx = TxClose /\ confs <= maxReorg
    /\ bestTx' = TxDefend
    /\ confs' \in 1..maxReorg
    /\ reorgsLeft' = reorgsLeft - 1
    /\ UNCHANGED <<params, countered, scanned, closed, job, claimWait, jobGeneration,
                   broadcast, faultsLeft>>

\* Action: counterparty discharges the obligation on chain first.
\* Source: environment
Counter ==
    /\ Pre
    /\ countered' = TRUE
    /\ UNCHANGED <<params, bestTx, confs, scanned, closed, job, claimWait, jobGeneration,
                   broadcast, faultsLeft, reorgsLeft>>

Next ==
    \/ Scan
    \/ Run
    \/ Tick
    \/ Reorg
    \/ Counter

\* No fairness: deadlines are invariants over heights; node promptness is Tick's guard.
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Past window - inclBlocks with the obligation still open, the defence was broadcast.
DefenceEventuallyRuns == (Pre /\ confs - 1 + inclBlocks > window) => broadcast

\* The graph is closed only while the closing tx is on the best chain.
NoFalseClosure == closed => bestTx = TxClose

\* No step changes the parameters.
ParamsFrozen == [][UNCHANGED params]_vars

====
