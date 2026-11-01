---- MODULE JobObligationPersistence ----
(***************************************************************************)
(* PURPOSE. Finding H3: a time-critical defence job whose chain           *)
(* precondition still holds can become permanently unrunnable, and a       *)
(* 1-confirmation closure is irreversible under a reorg. The spec follows *)
(* ONE obligation - e.g. the verifier's `disprove` (WronglyChallenge-      *)
(* Timeout), the operator's `wrongly_challenged` (ChallengeAssertSent) or  *)
(* the verifier's `challenge_kickoff` (KickoffSent): the chain says "act", *)
(* and the action must be broadcast early enough to confirm before the     *)
(* counterparty's CSV path matures.                                       *)
(*                                                                         *)
(* CODE SCOPE (dev @ 60562f8, after #476 - event-sourced aggregates on     *)
(* crates/engine):                                                         *)
(*   node/src/aggregates/graph_scan.rs       scan_graphs_on_chain, SCAN_MARKS*)
(*   node/src/aggregates/graph_pegout.rs     apply_chain_scan, route_signal *)
(*   node/src/aggregates/graph_pegout_jobs.rs settlement_step               *)
(*   node/src/aggregates/graph_jobs.rs       failure classification          *)
(*   node/src/utils/graph_chain_state.rs     closing-stage decision          *)
(*   node/src/utils/btc.rs                   tx_confirmed (>= 1 conf)       *)
(*   node/src/error.rs                       classify_failure / revert text *)
(*   crates/engine/src/{effects,worker,jobs,config}.rs  job id, enqueue, run*)
(*   crates/store/src/engine/mod.rs          insert_engine_job, finish     *)
(*   crates/store/src/schema.rs              closed statuses, transitions   *)
(*                                                                         *)
(* HOW THE OBLIGATION BECOMES A JOB (current code):                        *)
(*  - scan_graphs_on_chain (graph_scan.rs:131) scans each monitored graph  *)
(*    once per (graph, height, status) (SCAN_MARKS, :197); apply_chain_scan*)
(*    (graph_pegout.rs:597-606) turns every signal into                    *)
(*      JobSpec::new(&ctx.aggregate, PHASE_SETTLEMENT, action,             *)
(*                   pegout_job_pool(action), signal.encode()?)            *)
(*    and JobSpec::new derives the id from (aggregate, phase, action,      *)
(*    params) - stable_job_id, effects.rs:30. The signal JSON is the same  *)
(*    on every scan (e.g. WronglyChallengeTimeout{txid, index}), so every  *)
(*    scan asks for the SAME job id.                                       *)
(*  - insert_engine_job (store engine/mod.rs:1276) is "INSERT OR IGNORE    *)
(*    INTO engine_job ..." (:1282); a known id is left as it is.           *)
(*    worker.rs:335-348:                                                   *)
(*      Existing(Done | Cancelled) => "job already ran; not run again"     *)
(*      Existing(state)            => warn!("job re-enqueued after a       *)
(*                                    terminal failure; not run again")    *)
(*    Terminal rows are only purged after terminal_retention_secs = 15     *)
(*    days (engine config.rs:101), far past any timelock.                  *)
(*                                                                         *)
(* WAYS THE ONE ROW GOES TERMINAL WITHOUT A BROADCAST:                     *)
(*  (a) panic: execute_job (engine jobs.rs:222) catch_unwind, :247         *)
(*        Err(payload) => EngineJobFinish::Poisoned(..)                    *)
(*      finish_engine_job (store engine/mod.rs:1440, :1475) writes state   *)
(*      'Poisoned'. config.rs:59-64 says "The first poison holds nothing   *)
(*      back" - but that only releases the per-(aggregate, action) poison  *)
(*      row; the job ROW stays Poisoned and claim_due_engine_jobs only     *)
(*      claims Pending/Running rows. The manual /v1/debug                  *)
(*      clear_engine_poison (debug_handler.rs:85, store                    *)
(*      clear_engine_aggregate_poison :934) deletes the poison row only.   *)
(*      graph.rs:725 just logs "job panicked".                             *)
(*  (b) Permanent-classified revert: graph_jobs.rs:130-134                 *)
(*        FailureClass::Permanent(reason) if pegout =>                     *)
(*            plan_outcome(&GraphPlan::noted(format!("rejected: ..")))     *)
(*      i.e. JobOutcome::Done. permanent_rejection / revert_message        *)
(*      (error.rs:45-77) classify ANY alloy contract/transport error whose *)
(*      text contains "revert" as permanent - including a transient revert *)
(*      (lagging Goat node, SPV race, eth_call during an upgrade). Of the  *)
(*      defence jobs, only those that call Goat are exposed               *)
(*      (challenge_kickoff's gateway_get_withdraw_data /                   *)
(*      btc_spv_latest_height, the relayer's proceed_withdraw /            *)
(*      finish_happy etc.). Bitcoin broadcasts (disprove, NACK,            *)
(*      wrongly_challenged) surface esplora errors => Transient.           *)
(*  (c) give-up paths: Step::ignore after N attempts (graph_pegout_jobs.rs *)
(*      withdraw_missing :1612 / withdraw_not_proceeded :1622, relayer     *)
(*      only, alerted), deadline_at => Failed (jobs.rs:203; pegout jobs    *)
(*      set no deadline), Unknown x20 => Failed (graph_jobs.rs:148, setup  *)
(*      jobs only). For the Bitcoin defence jobs (c) is NOT a live path;   *)
(*      it is modelled for the relayer's Goat-side obligations.            *)
(*  (d) CLOSURE AT ONE CONFIRMATION, NEVER REVISITED:                      *)
(*    tx_confirmed / outpoint_spent_confirmed (btc.rs:451, :457) are       *)
(*    Esplora `confirmed` = >= 1 confirmation. graph_chain_state.rs:253    *)
(*    "Mempool transactions can be replaced and must not decide a terminal *)
(*    stage" - but a 1-conf block can be reorged just as well: :302-316    *)
(*    Connector-A spent (confirmed) by Take-1 => OperatorTake1;            *)
(*    Disprove/Skipped/Take2 the same way. get_closed_status              *)
(*    (schema.rs:384-391) = {Take1, Take2, Skipped, Disprove};             *)
(*    allowed_transition_from (schema.rs:438) has no edge OUT of a closed  *)
(*    status; monitored_statuses (graph_scan.rs:113) excludes them, so a   *)
(*    closed graph is never scanned again; settlement_step                 *)
(*    (graph_pegout_jobs.rs:96) ends any queued settlement job of a closed *)
(*    graph as Step::ignore("graph is ..").                                *)
(*    Concrete race: a late Challenge and the operator's Take-1 both spend *)
(*    Connector-A. Take-1 wins block h, every node closes the graph as     *)
(*    OperatorTake1; a reorg mines the Challenge instead. The graph is     *)
(*    really in Challenge, but the operator never sends Watchtower-        *)
(*    Challenge-Init / commit / assert and verifiers never act on it.      *)
(*                                                                         *)
(* FIX DESIGN (FixRearm = TRUE): obligations are re-derived from chain     *)
(* state on every scan and a job whose row is terminal WITHOUT having      *)
(* broadcast is re-armed while the precondition holds (a generation        *)
(* component in the job id, `jobGeneration`); and a stage is closed only   *)
(* at a confirmation depth > the maximum reorg depth.                      *)
(*                                                                         *)
(* TIMING PARAMETERS (frozen variables, chosen once in Init):              *)
(*   window       blocks from the obligation tx's confirmation (height d0) *)
(*                until the counterparty's CSV path matures. A defence     *)
(*                broadcast at height d0 + o is in time iff                *)
(*                o + inclBlocks <= window - the convention of the code's  *)
(*                own budget (validate_timelock_config: ensure_at_least(   *)
(*                window, reaction + inclusion + safety)).                 *)
(*   reactBlocks  ReactionBlocks: the first attempt runs reactBlocks after *)
(*                the scan that first sees the obligation.                 *)
(*   inclBlocks   InclusionBlocks: broadcast -> confirmed.                 *)
(*   retryBlocks  blocks a re-armed attempt costs: re-armed at the next    *)
(*                block's scan (SCAN_MARKS), run retryBlocks - 1 blocks    *)
(*                after it (1 when the new generation's 10 s engine        *)
(*                backoff, config.rs:94, fits in the block).               *)
(*   faultBudget  attempts that end terminal without a broadcast.          *)
(*   maxReorg     deepest reorg (only with ReorgFaults = 1). A reorg of    *)
(*                depth <= maxReorg removes the closing tx and may mine    *)
(*                the obligation tx anywhere in the replaced range, so it  *)
(*                is seen with c \in 1..maxReorg confirmations on the clock.*)
(*   closeDepth   confirmations at which a closing stage is decided        *)
(*                (current code: 1).                                       *)
(* Worst case the defence goes out at offset                               *)
(*     o = c + reactBlocks + faultBudget * retryBlocks  (c = 0, no reorg)  *)
(* Hence the fix needs                                                     *)
(*     ParamsOK == closeDepth > maxReorg                                   *)
(*      /\ reactBlocks + faultBudget*retryBlocks + maxReorg + inclBlocks   *)
(*           <= window                                                     *)
(* (maxReorg read as 0 when ReorgFaults = 0). ParamsOK is EXACT: a         *)
(* full-sweep state dump of all 5346 abstract points showed every point    *)
(* inside passes and every point outside has a counterexample.             *)
(*                                                                         *)
(* EXHAUSTIVENESS of the abstract ranges: every guard compares a counter   *)
(* that moves by one per block (confs, claimWait) with one parameter; the  *)
(* outcome is decided by (i) closeDepth vs maxReorg and (ii) the sign of   *)
(* window - inclBlocks - (maxReorg + reactBlocks + faultBudget *           *)
(* retryBlocks). reactBlocks, inclBlocks, faultBudget, maxReorg in 0..2,   *)
(* retryBlocks in 1..2 and closeDepth in 1..3 hit every value class of     *)
(* each term, and window in 1..11 gives margin -1, 0 and +1 for every      *)
(* combination (the sum is at most 10).                                    *)
(*                                                                         *)
(* SHIPPED VALUES (UseShipped = TRUE): network \in NetSet; the obligation  *)
(* picks its window from ShippedTimelockValues:                            *)
(*   challenge_kickoff  ConnectorA                                         *)
(*   wrongly_challenged ProverConnector                                    *)
(*   disprove           ConnectorD - ProverConnector                       *)
(* reactBlocks = ReactionBlocks, inclBlocks = InclusionBlocks; maxReorg <  *)
(* BtcBlockConfirms[net] (the node's own finality depth, SPV updater lag); *)
(* the fix closes at BtcBlockConfirms[net] (CloseDepthRule). Region        *)
(* "SafetyBudget" sweeps every split faultBudget * retryBlocks + maxReorg  *)
(* <= SafetyBlocks[net], the allowance validate_timelock_config reserves.  *)
(*                                                                         *)
(* CONFIGS AND TIERS (checks.txt):                                         *)
(*   live      JobObligationPersistence/H3Panic.cfg          (a) panic, shipped    *)
(*   live      JobObligationPersistence/Rejected.cfg  (b) revert, shipped   *)
(*   live      JobObligationPersistence/Reorg.cfg     (d) 1-conf closure    *)
(*   design    JobObligationPersistence/Fixed.cfg     fix, abstract sweep   *)
(*   design    JobObligationPersistence/FixedShipped.cfg fix, shipped       *)
(*   boundary  JobObligationPersistence/Boundary.cfg  just outside ParamsOK *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelockValues

CONSTANTS
    FixRearm,         \* FALSE: current code (stable id + INSERT OR IGNORE); TRUE: fix design
    FaultKinds,       \* \subseteq {"Panic", "Revert", "GiveUp"}: terminal paths (a), (b), (c) that exist
    ReorgFaults,      \* 0 | 1: whether the race (closing tx mined first, then reorged) is played
    UseShipped,       \* TRUE: parameters from ShippedTimelockValues; FALSE: from the ranges below
    Region,           \* "All" | "ParamsOK" | "NotParamsOK" | "Edge" | "TimingOK" | "SafetyBudget"
    WindowRange,      \* abstract mode: deadline windows (blocks)
    ReactRange,       \* abstract mode: reaction blocks
    InclRange,        \* abstract mode: inclusion blocks
    CloseDepthRange,  \* abstract mode: closing confirmation depths
    RetryRange,       \* both modes: blocks per re-armed attempt
    FaultRange,       \* both modes: terminal-without-broadcast budgets
    MaxReorgRange,    \* both modes: reorg depths (shipped: also < BtcBlockConfirms)
    NetSet,           \* shipped mode: networks swept, \subseteq Networks
    Obligations,      \* shipped mode: \subseteq {"challenge_kickoff", "wrongly_challenged", "disprove"}
    CloseDepthRule    \* shipped mode: "Code" (1) | "BtcBlockConfirms" | "EvidenceConfirmations"

\* Fault kinds (paths (a), (b), (c) of the header).
FaultPanic  == "Panic"
FaultRevert == "Revert"
FaultGiveUp == "GiveUp"

\* engine_job row states (EngineJobState) plus "no row yet".
JobNone     == "None"
JobPending  == "Pending"
JobDone     == "Done"
JobFailed   == "Failed"
JobPoisoned == "Poisoned"
JobStates   == {JobNone, JobPending, JobDone, JobFailed, JobPoisoned}

\* Which of the two conflicting spends is on the best chain.
TxClose  == "Close"    \* the closing tx (e.g. Take-1)
TxDefend == "Defend"   \* the tx that creates the obligation (e.g. Challenge, ChallengeAssert)

ASSUME FaultKinds \subseteq {FaultPanic, FaultRevert, FaultGiveUp}
ASSUME ReorgFaults \in {0, 1}
ASSUME Region \in {"All", "ParamsOK", "NotParamsOK", "Edge", "TimingOK", "SafetyBudget"}
ASSUME NetSet \subseteq Networks
ASSUME Obligations \subseteq {"challenge_kickoff", "wrongly_challenged", "disprove"}
ASSUME CloseDepthRule \in {"Code", "BtcBlockConfirms", "EvidenceConfirmations"}

Max(a, b) == IF a > b THEN a ELSE b

\* Deadline window of an obligation on a network (shipped CSV values).
Window(o, n) ==
    CASE o = "challenge_kickoff"  -> ConnectorA[n]
      [] o = "wrongly_challenged" -> ProverConnector[n]
      [] o = "disprove"           -> ConnectorD[n] - ProverConnector[n]

ShippedCloseDepth(n) ==
    CASE CloseDepthRule = "Code"                  -> 1
      [] CloseDepthRule = "BtcBlockConfirms"      -> BtcBlockConfirms[n]
      [] CloseDepthRule = "EvidenceConfirmations" -> Max(1, EvidenceConfirmations[n])

VARIABLES
    network,        \* frozen: network of the shipped values ("abstract" in abstract mode)
    obligation,     \* frozen: which defence job ("abstract" in abstract mode)
    window,         \* frozen: deadline window in blocks
    reactBlocks,    \* frozen: blocks from first sighting to the first attempt
    inclBlocks,     \* frozen: blocks from broadcast to confirmation
    retryBlocks,    \* frozen: blocks per re-armed attempt
    faultBudget,    \* frozen: attempts that may end terminal without a broadcast
    maxReorg,       \* frozen: deepest reorg the environment may perform
    closeDepth,     \* frozen: confirmations at which a closing stage is decided
    bestTx,         \* TxClose | TxDefend: which conflicting spend is on the best chain
    confs,          \* confirmations of bestTx (1 in the block that mines it)
    countered,      \* the counterparty discharged the obligation (answered on chain)
    scanned,        \* the chain scan for this height ran (SCAN_MARKS)
    closed,         \* local Graph.status is closed (absorbing, never rescanned)
    job,            \* engine_job row of the defence job
    claimWait,      \* blocks until the Pending row is claimed
    jobGeneration,  \* FIX design only: generation component of the job id
    broadcast,      \* the defence transaction was broadcast
    faultsLeft,     \* remaining terminal-without-broadcast runs
    reorgsLeft      \* remaining reorg budget

params == <<network, obligation, window, reactBlocks, inclBlocks, retryBlocks,
            faultBudget, maxReorg, closeDepth>>
state  == <<bestTx, confs, countered, scanned, closed, job, claimWait,
            jobGeneration, broadcast, faultsLeft, reorgsLeft>>
vars   == <<params, state>>

\* Reorg depth that matters (0 when the race is not played).
EffReorg == IF ReorgFaults > 0 THEN maxReorg ELSE 0

\* The fix's margin, split in its closure and timing halves.
CloseOK  == closeDepth > EffReorg
TimingOK == reactBlocks + faultBudget * retryBlocks + EffReorg + inclBlocks <= window
ParamsOK == CloseOK /\ TimingOK

\* The code's own allowance: validate_timelock_config guarantees every
\* window >= reaction + inclusion + safety, so faults and reorg depth may
\* share safety_blocks.
SafetyBudget == UseShipped /\ faultBudget * retryBlocks + EffReorg <= SafetyBlocks[network]

\* Just outside ParamsOK: closure depth equal to the reorg depth with the
\* timing met, or the timing short by exactly one block with closure met
\* (and window > inclBlocks, so the window is not already lost in the first
\* block).
Edge ==
    \/ closeDepth = EffReorg /\ TimingOK
    \/ CloseOK /\ window > inclBlocks
       /\ reactBlocks + faultBudget * retryBlocks + EffReorg + inclBlocks = window + 1

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
    \* With a reorg budget the closing tx may be mined first (the race);
    \* the obligation may also simply be on chain from the start.
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
\* A closing stage seen at closeDepth confirmations is written and absorbing.
ClosesNow == bestTx = TxClose /\ confs >= closeDepth

\* Which rows the scan (re)arms. CURRENT: enqueue_job(stable id) -> INSERT
\* OR IGNORE, only a missing row becomes Pending, a terminal row stays
\* terminal ("not run again"). FIX: a row that ended without a broadcast is
\* re-armed under a new generation while Pre holds.
Arms ==
    IF FixRearm THEN ~broadcast /\ job \in {JobNone, JobDone, JobFailed, JobPoisoned}
                ELSE job = JobNone

\* Action: the once-per-(graph, height, status) chain scan of an open graph.
\*   It decides the closing stage at closeDepth confirmations (absorbing) and,
\*   while the chain demands the defence, enqueues the defence job: the first
\*   row runs reactBlocks later, a re-armed row (fix only) retryBlocks - 1
\*   later. Current code re-requests the same stable id, which INSERT OR
\*   IGNORE drops once the row exists.
\* Source: scan_graphs_on_chain() in node/src/aggregates/graph_scan.rs:131-228 (SCAN_MARKS :197);
\*         gather_chain_scan() graph_scan.rs:303 -> graph_chain_state.rs:302-316 (1-conf closure via
\*         outpoint_spent_confirmed() in node/src/utils/btc.rs:457);
\*         apply_chain_scan() in node/src/aggregates/graph_pegout.rs:551, enqueue_job :597-606;
\*         stable_job_id() in crates/engine/src/effects.rs:30;
\*         insert_engine_job() in crates/store/src/engine/mod.rs:1276-1282; crates/engine/src/worker.rs:332-348
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

\* The executor claims the due row and runs settlement_step.
RunBase(outcome) ==
    /\ job = JobPending /\ claimWait = 0
    /\ outcome
    /\ UNCHANGED <<params, bestTx, confs, countered, scanned, closed, claimWait,
                   jobGeneration, reorgsLeft>>

\* Action: the defence job runs on a closed graph, or the obligation is gone
\*   (or looks gone): Step::ignore, the row ends Done without a broadcast.
\* Source: settlement_step() in node/src/aggregates/graph_pegout_jobs.rs:76-96 (closed graph);
\*         settled_by() graph_pegout_jobs.rs:193-196 (spend already confirmed)
RunIgnored ==
    RunBase(/\ (closed \/ ~Pre)
            /\ job' = JobDone
            /\ UNCHANGED <<broadcast, faultsLeft>>)

\* Action: the defence job runs while the chain demands it and broadcasts
\*   the defence transaction; the row ends Done.
\* Source: claim_and_spawn()/execute_job() in crates/engine/src/jobs.rs:133-247;
\*         settlement_step() in node/src/aggregates/graph_pegout_jobs.rs:76 (e.g. wrongly_challenged :1327,
\*         challenge_kickoff :595)
RunBroadcast ==
    RunBase(/\ ~closed /\ Pre
            /\ job' = JobDone /\ broadcast' = TRUE
            /\ UNCHANGED faultsLeft)

\* Row state each fault path leaves behind.
FaultEnd(k) ==
    CASE k = FaultPanic  -> JobPoisoned
      [] k = FaultRevert -> JobDone
      [] k = FaultGiveUp -> JobFailed

\* Action: the defence job runs while the chain demands it but ends terminal
\*   without a broadcast: (a) panic -> Poisoned, (b) transient revert
\*   classified Permanent -> Done("rejected: .."), (c) give-up -> Failed.
\*   Nondeterministic, bounded by faultBudget (environment).
\* Source: execute_job() in crates/engine/src/jobs.rs:222,247 (catch_unwind -> Poisoned),
\*         finish_engine_job() in crates/store/src/engine/mod.rs:1440-1476;
\*         graph_jobs.rs:130-134 + classify_failure() in node/src/error.rs:33-77 (Permanent revert);
\*         withdraw_missing() graph_pegout_jobs.rs:1612, jobs.rs:203 (give-up / deadline)
RunFault ==
    \E k \in FaultKinds :
        RunBase(/\ ~closed /\ Pre /\ faultsLeft > 0
                /\ job' = FaultEnd(k) /\ faultsLeft' = faultsLeft - 1
                /\ UNCHANGED broadcast)

Run == RunIgnored \/ RunBroadcast \/ RunFault

\* Nothing left to decide: the defence deadline passed, or the closing tx
\* is decided and beyond any reorg.
Settled ==
    \/ bestTx = TxDefend /\ confs - 1 + inclBlocks > window
    \/ bestTx = TxClose /\ confs > Max(closeDepth, EffReorg)

\* Action: a Bitcoin block is mined. Only after this height's scan ran (or
\*   the graph is closed and no longer scanned) and no claimable job waits:
\*   the executor is prompt, its latency is reactBlocks / retryBlocks,
\*   counted down in claimWait.
\* Source: Bitcoin consensus (block production); maintenance tick that calls
\*         scan_graphs_on_chain() once per new height (node/src/aggregates/graph_scan.rs:131)
Tick ==
    /\ ~Settled
    /\ scanned \/ closed
    /\ ~(job = JobPending /\ claimWait = 0)
    /\ confs' = confs + 1
    /\ scanned' = FALSE
    /\ claimWait' = IF job = JobPending THEN claimWait - 1 ELSE claimWait
    /\ UNCHANGED <<params, bestTx, countered, closed, job, jobGeneration, broadcast,
                   faultsLeft, reorgsLeft>>

\* Action: a reorg of depth <= maxReorg replaces the closing tx's block and
\*   mines the conflicting spend somewhere in the replaced range. Same
\*   height: if this height's scan already ran, SCAN_MARKS holds (graph, h,
\*   status), so the next scan is at the next height.
\* Source: environment (Bitcoin reorg); SCAN_MARKS in node/src/aggregates/graph_scan.rs:78,197
Reorg ==
    /\ reorgsLeft > 0
    /\ bestTx = TxClose /\ confs <= maxReorg
    /\ bestTx' = TxDefend
    /\ confs' \in 1..maxReorg
    /\ reorgsLeft' = reorgsLeft - 1
    /\ UNCHANGED <<params, countered, scanned, closed, job, claimWait, jobGeneration,
                   broadcast, faultsLeft>>

\* Action: the counterparty acts first and discharges the obligation on chain.
\* Source: environment (counterparty transaction)
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

\* No fairness: every property is a safety property over block heights; the
\* honest node's promptness is encoded in Tick's guards (scan and due jobs
\* happen before the next block), the adversary is unconstrained.
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* ---- Safety invariants

\* Once the obligation is older than window - inclBlocks blocks while the
\* chain still demands it, the defence has been broadcast (in time to confirm).
DefenceEventuallyRuns == (Pre /\ confs - 1 + inclBlocks > window) => broadcast

\* The node never treats the graph as closed while the best chain says the
\* closing transaction is not there.
NoFalseClosure == closed => bestTx = TxClose

\* (Parameter check, FixedShipped.cfg) the shipped windows leave the margin
\* the fix design needs.
\* ParamsOK - defined above.

\* ---- Safety properties

\* The timing parameters are frozen: no step changes them.
ParamsFrozen == [][UNCHANGED params]_vars

\* ---- Liveness
\* None: deadlines are stated as invariants over block heights
\* (DefenceEventuallyRuns), which is stronger than "eventually".

====
