---- MODULE JobObligationPersistence ----
(***************************************************************************)
(* H3: a time-critical defence job whose chain precondition still holds   *)
(* can become permanently unrunnable, and a 1-confirmation closure is      *)
(* irreversible under a 1-block reorg.  Checked against dev @ 60562f8      *)
(* (after the #476 engine refactor).                                      *)
(*                                                                         *)
(* ONE OBLIGATION, e.g. the verifier's `disprove` (WronglyChallengeTimeout)*)
(* or `challenge_nack` (NackReady), or the operator's `wrongly_challenged`  *)
(* / `watchtower_challenge_init` (ChallengeSent): the chain says "act",    *)
(* and the action must be broadcast before a deadline height.             *)
(*                                                                         *)
(* HOW THE OBLIGATION BECOMES A JOB (current code):                        *)
(*  - graph_scan.rs:197 scans each monitored graph once per (height,       *)
(*    status); graph_pegout.rs:598-607 turns every signal into              *)
(*      JobSpec::new(&ctx.aggregate, PHASE_SETTLEMENT, action,             *)
(*                   pegout_job_pool(action), signal.encode()?)            *)
(*    and JobSpec::new derives the id from (aggregate, phase, action,      *)
(*    params) - effects.rs:29-43 stable_job_id. The signal JSON is the     *)
(*    same on every scan (e.g. WronglyChallengeTimeout{txid, index}), so   *)
(*    every scan asks for the SAME job id.                                 *)
(*  - store engine/mod.rs:1276-1315 insert_engine_job is                   *)
(*      "INSERT OR IGNORE INTO engine_job ..." (line 1282); a known id is  *)
(*    left as it is. worker.rs:335-348:                                    *)
(*      Existing(Done | Cancelled) => "job already ran; not run again"     *)
(*      Existing(state)            => warn!("job re-enqueued after a       *)
(*                                    terminal failure; not run again")    *)
(*    Terminal rows are only purged after terminal_retention_secs = 15     *)
(*    days (config.rs:101), far past any timelock.                        *)
(*                                                                         *)
(* WAYS THE ONE ROW GOES TERMINAL WITHOUT A BROADCAST:                     *)
(*  (a) panic: jobs.rs:222 catch_unwind, :247                              *)
(*        Err(payload) => EngineJobFinish::Poisoned(..)                    *)
(*      engine/mod.rs:1474 writes state 'Poisoned'. config.rs:59-64 says   *)
(*      "The first poison holds nothing back" - but that only releases the *)
(*      per-(aggregate, action) poison row; the job ROW stays Poisoned and *)
(*      claim_due_engine_jobs only claims Pending/Running rows. The manual *)
(*      /v1/debug clear_engine_poison (debug_handler.rs:85, store          *)
(*      clear_engine_aggregate_poison) deletes the poison row only, so it  *)
(*      does not revive this job either. graph.rs:724 just logs            *)
(*      "job panicked".                                                    *)
(*  (b) Permanent-classified revert: graph_jobs.rs:129-135                 *)
(*        FailureClass::Permanent(reason) if pegout =>                     *)
(*            plan_outcome(&GraphPlan::noted(format!("rejected: ..")))     *)
(*      i.e. JobOutcome::Done. error.rs:56-77 classifies ANY alloy         *)
(*      contract/transport error whose text contains "revert" as           *)
(*      permanent - including a transient revert (lagging Goat node, SPV   *)
(*      race, eth_call during an upgrade). Of the defence jobs, only those *)
(*      that call Goat are exposed (challenge_kickoff's                    *)
(*      gateway_get_withdraw_data/btc_spv_latest_height, the relayer's     *)
(*      proceed_withdraw/finish_happy etc.). Bitcoin broadcasts (disprove, *)
(*      NACK,                                                              *)
(*      wrongly_challenged) surface esplora errors => Transient, so (b)    *)
(*      does NOT apply to them.                                            *)
(*  (c) give-up paths: Step::ignore after N attempts (graph_pegout_jobs.rs *)
(*      withdraw_missing / withdraw_not_proceeded, relayer-only, alerted), *)
(*      deadline_at => Failed (jobs.rs:203; pegout jobs set no deadline),  *)
(*      Unknown x20 => Failed (graph_jobs.rs:148, setup jobs only). So for *)
(*      the Bitcoin defence jobs (c) is NOT a live path; it is modelled    *)
(*      for the relayer's Goat-side obligations.                           *)
(*                                                                         *)
(* (d) CLOSURE AT ONE CONFIRMATION, NEVER REVISITED:                       *)
(*  - utils/btc.rs:451 tx_confirmed / :457 outpoint_spent_confirmed are    *)
(*    Esplora `confirmed` = >= 1 confirmation. graph_chain_state.rs:253    *)
(*    "Mempool transactions can be replaced and must not decide a terminal *)
(*    stage" - but a 1-conf block can be reorged just as well:             *)
(*    :304-316 Connector-A spent (confirmed) by Take-1 => OperatorTake1;   *)
(*    Disprove/Skipped/Take2 the same way.                                 *)
(*  - schema.rs:384-391 closed = {Take1, Take2, Skipped, Disprove};         *)
(*    schema.rs:438-507 has no edge OUT of a closed status;                *)
(*    graph_scan.rs:113-127 monitored_statuses() excludes them, so a closed*)
(*    graph is never scanned again; graph_pegout_jobs.rs:95 makes any      *)
(*    queued settlement job of a closed graph end as                       *)
(*    Step::ignore("graph is ..").                                         *)
(*  Concrete race: a late Challenge and the operator's Take-1 both spend    *)
(*  Connector-A. Take-1 wins block h, every node closes the graph as       *)
(*  OperatorTake1; a 1-block reorg mines the Challenge instead. The graph  *)
(*  is really in Challenge, but the operator never sends                   *)
(*  Watchtower-Challenge-Init / commit / assert (=> commit-timeout         *)
(*  disprove) and verifiers never act on the real outcome.                 *)
(*                                                                         *)
(* FIXED DESIGN (NextFixed): obligations are re-derived from chain state on*)
(* every scan and a job whose row is terminal WITHOUT having broadcast is  *)
(* re-armed while the precondition holds (a generation/attempt component  *)
(* in the job id, `gen` below); and a stage is closed only at a           *)
(* confirmation depth > the maximum reorg depth (CloseDepth > MaxReorg).   *)
(*                                                                         *)
(* Time is in blocks. A job that is due runs within the block (urgency:   *)
(* Tick waits for it), so a violation is never "the node was just slow".  *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Deadline,      \* height by which the defence must be broadcast
    PanicFaults,   \* (a) budget of job runs that panic
    RevertFaults,  \* (b) budget of runs that hit a transient revert classified Permanent
    GiveUpFaults,  \* (c) budget of runs that end on a give-up path
    ReorgFaults,   \* (d) budget of reorgs (0 = the obligation is on chain from the start)
    MaxReorg,      \* deepest reorg the environment may perform
    CloseDepth     \* confirmations at which a closing stage is decided (current code: 1)

ASSUME Deadline \in Nat /\ Deadline > 0
ASSUME {PanicFaults, RevertFaults, GiveUpFaults, ReorgFaults, MaxReorg} \subseteq Nat
ASSUME CloseDepth \in Nat /\ CloseDepth >= 1

JobStates == {"None", "Pending", "Done", "Failed", "Poisoned"}
ConfCap == CloseDepth + MaxReorg + 1

VARIABLES
    h,          \* Bitcoin tip height
    winner,     \* which of two conflicting spends is on the best chain:
                \*   "Close"  - the closing tx (e.g. Take-1)
                \*   "Defend" - the tx that creates the obligation (e.g. Challenge,
                \*              ChallengeAssert past T2)
    conf,       \* confirmations of `winner`
    countered,  \* the counterparty discharged the obligation (e.g. answered on chain)
    scanned,    \* the chain scan for this height ran (SCAN_MARKS)
    closed,     \* local Graph.status is closed (absorbing, never rescanned)
    job,        \* engine_job row of the defence job (stable id)
    due,        \* the Pending row is claimable in this block
    gen,        \* FIXED design only: generation component of the job id
    broadcast,  \* the defence transaction was broadcast
    panics, reverts, giveups, reorgs   \* remaining fault budgets

vars == <<h, winner, conf, countered, scanned, closed, job, due, gen, broadcast,
          panics, reverts, giveups, reorgs>>

TypeOK ==
    /\ h \in 0..Deadline
    /\ winner \in {"Close", "Defend"}
    /\ conf \in 1..ConfCap
    /\ countered \in BOOLEAN
    /\ scanned \in BOOLEAN
    /\ closed \in BOOLEAN
    /\ job \in JobStates
    /\ due \in BOOLEAN
    /\ gen \in Nat
    /\ broadcast \in BOOLEAN
    /\ panics \in 0..PanicFaults /\ reverts \in 0..RevertFaults
    /\ giveups \in 0..GiveUpFaults /\ reorgs \in 0..ReorgFaults

\* The chain still demands the defence.
Pre == winner = "Defend" /\ ~countered

Init ==
    /\ h = 0
    \* With a reorg budget the closing tx is mined first (the race case);
    \* otherwise the obligation is simply on chain at height 0.
    /\ winner = IF ReorgFaults > 0 THEN "Close" ELSE "Defend"
    /\ conf = 1
    /\ countered = FALSE
    /\ scanned = FALSE
    /\ closed = FALSE
    /\ job = "None"
    /\ due = FALSE
    /\ gen = 0
    /\ broadcast = FALSE
    /\ panics = PanicFaults /\ reverts = RevertFaults
    /\ giveups = GiveUpFaults /\ reorgs = ReorgFaults

-----------------------------------------------------------------------------
\* decide_status + transition_graph_status: a closing stage seen at
\* CloseDepth confirmations is written and is absorbing.
ClosesNow == winner = "Close" /\ conf >= CloseDepth

\* CURRENT: graph_scan -> apply_chain_scan -> enqueue_job(stable id) ->
\* INSERT OR IGNORE. Only a missing row becomes Pending; a terminal row
\* stays terminal ("not run again").
ScanCurrent ==
    /\ ~closed /\ ~scanned
    /\ scanned' = TRUE
    /\ closed' = ClosesNow
    /\ IF Pre /\ job = "None"
          THEN job' = "Pending" /\ due' = TRUE
          ELSE UNCHANGED <<job, due>>
    /\ UNCHANGED <<h, winner, conf, countered, gen, broadcast,
                   panics, reverts, giveups, reorgs>>

\* FIXED: the obligation is re-derived each scan; a row that ended without
\* a broadcast is re-armed under a new generation while Pre holds.
ScanFixed ==
    /\ ~closed /\ ~scanned
    /\ scanned' = TRUE
    /\ closed' = ClosesNow
    /\ IF Pre /\ ~broadcast /\ job \in {"None", "Done", "Failed", "Poisoned"}
          THEN /\ job' = "Pending" /\ due' = TRUE
               /\ gen' = IF job = "None" THEN gen ELSE gen + 1
          ELSE UNCHANGED <<job, due, gen>>
    /\ UNCHANGED <<h, winner, conf, countered, broadcast,
                   panics, reverts, giveups, reorgs>>

\* The executor claims the due row and runs settlement_step.
RunBase(outcome) ==
    /\ job = "Pending" /\ due
    /\ due' = FALSE
    /\ outcome
    /\ UNCHANGED <<h, winner, conf, countered, scanned, closed, gen, reorgs>>

\* graph_pegout_jobs.rs:95 closed graph, or settled_by Confirmed (:196):
\* the obligation is gone (or looks gone) - Step::ignore => Done.
RunIgnored ==
    RunBase(/\ (closed \/ ~Pre)
            /\ job' = "Done"
            /\ UNCHANGED <<broadcast, panics, reverts, giveups>>)

RunBroadcast ==
    RunBase(/\ ~closed /\ Pre
            /\ job' = "Done" /\ broadcast' = TRUE
            /\ UNCHANGED <<panics, reverts, giveups>>)

\* (a) the runner panics: Poisoned.
RunPanic ==
    RunBase(/\ ~closed /\ Pre /\ panics > 0
            /\ job' = "Poisoned" /\ panics' = panics - 1
            /\ UNCHANGED <<broadcast, reverts, giveups>>)

\* (b) a transient revert classified Permanent: Done("rejected: ..").
RunRejected ==
    RunBase(/\ ~closed /\ Pre /\ reverts > 0
            /\ job' = "Done" /\ reverts' = reverts - 1
            /\ UNCHANGED <<broadcast, panics, giveups>>)

\* (c) a give-up path: Failed / ignore-after-N.
RunGiveUp ==
    RunBase(/\ ~closed /\ Pre /\ giveups > 0
            /\ job' = "Failed" /\ giveups' = giveups - 1
            /\ UNCHANGED <<broadcast, panics, reverts>>)

Run == RunIgnored \/ RunBroadcast \/ RunPanic \/ RunRejected \/ RunGiveUp

\* A block arrives once this height's scan ran (or the graph is closed and
\* no longer scanned) and no due job is waiting.
Tick ==
    /\ h < Deadline
    /\ scanned \/ closed
    /\ ~(job = "Pending" /\ due)
    /\ h' = h + 1
    /\ conf' = IF conf < ConfCap THEN conf + 1 ELSE conf
    /\ scanned' = FALSE
    /\ due' = (job = "Pending")
    /\ UNCHANGED <<winner, countered, closed, job, gen, broadcast,
                   panics, reverts, giveups, reorgs>>

\* (d) a reorg of depth <= MaxReorg replaces the closing tx's block with one
\* that mines the conflicting spend. Same height: SCAN_MARKS already holds
\* (graph, h, status), so no rescan until the next height.
Reorg ==
    /\ reorgs > 0
    /\ winner = "Close" /\ conf <= MaxReorg
    /\ winner' = "Defend" /\ conf' = 1
    /\ reorgs' = reorgs - 1
    /\ UNCHANGED <<h, countered, scanned, closed, job, due, gen, broadcast,
                   panics, reverts, giveups>>

\* The counterparty acts first (discharges the obligation).
Counter ==
    /\ Pre
    /\ countered' = TRUE
    /\ UNCHANGED <<h, winner, conf, scanned, closed, job, due, gen, broadcast,
                   panics, reverts, giveups, reorgs>>

Next      == ScanCurrent \/ Run \/ Tick \/ Reorg \/ Counter
NextFixed == ScanFixed   \/ Run \/ Tick \/ Reorg \/ Counter

Spec      == Init /\ [][Next]_vars
SpecFixed == Init /\ [][NextFixed]_vars

-----------------------------------------------------------------------------
\* If the chain still demands the defence when the deadline height arrives,
\* the defence was broadcast before it.
DefenceEventuallyRuns == (h = Deadline /\ Pre) => broadcast

\* The node never treats the graph as closed while the best chain says the
\* closing transaction is not there.
NoFalseClosure == closed => winner = "Close"

====
