---- MODULE MaintenanceLoops ----
(***************************************************************************)
(* Scheduling model of the periodic maintenance task (audit H4 + H5).      *)
(*                                                                         *)
(* Ground truth: node/src/scheduled_tasks/mod.rs                           *)
(*   - maintenance_lanes: two loops joined under one tokio::select! with   *)
(*     the cancellation token. Each loop is `sleep; pass.await` and so is  *)
(*     serial: a lane is one program counter here, so two rounds of the    *)
(*     same lane can never overlap. Cancel drops both in-flight passes in  *)
(*     one step.                                                           *)
(*   - run_bitcoin_scans (the BTC lane): graph_chain_scan, then            *)
(*     instance_btc_scan (graph_setup_abandon_scan, operator only, is a    *)
(*     third sub-task of the same shape and is left out).                  *)
(*   - run_with_history_check (the other lane): node_available_pbtc_update *)
(*     (balances), spv_header_hash_update, the gateway history check, then *)
(*     only when history is synced pegin_request_monitor and               *)
(*     scan_answer_windows. swap/inbox/babe cleanups behave like "spv".    *)
(*   - run_subtask_with_timeout: every sub-task has a budget; timeout,     *)
(*     error and panic all end the sub-task as failed and later sub-tasks  *)
(*     still run. A lane round with a failure is reported "failed"; a      *)
(*     history deferral "deferred"; a failed history check "failed".       *)
(* node/src/scheduled_tasks/event_watch/mod.rs history_sync_pending: the   *)
(*   gate compares the local cursor (from_height) with the subgraph's      *)
(*   indexed height (not GOAT finalized); a Syncing status only counts     *)
(*   while fresh (updated_at + LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS) and  *)
(*   the cursor is behind. Metadata errors, hasIndexingErrors and a        *)
(*   timed-out check are "error", never "pending".                         *)
(* node/src/utils/graph_chain_state.rs initial_graph_stage: a graph whose  *)
(*   PreKickoff is confirmed is scanned without GOAT GraphData.            *)
(* Paging, with Batch = N (all items fit one batch):                       *)
(*   - node_maintenance_tasks.rs refresh_operator_batch (balances): the    *)
(*     round starts after the cursor and wraps around the operator list.   *)
(*   - instance_scan.rs pegin_request_monitor_page: the page holds the     *)
(*     pending requests after the cursor (no wrap inside a page); an empty *)
(*     page after the last item restarts from the beginning.               *)
(*   Both store the cursor BEFORE awaiting an item, so a per-item timeout  *)
(*   or the sub-task budget cancelling the item does not make the next     *)
(*   round start at the same item. Failed items stay in the list and are   *)
(*   retried when the rotation comes back to them.                         *)
(*                                                                         *)
(* PreFix = TRUE models the code before 8b55cc1/784a66e: one serial loop   *)
(* (balance, spv, history check, pegin, answer, instance_btc_scan,         *)
(* graph_chain_scan); a pending or failed history check returns early and  *)
(* skips the Bitcoin scans; the gate is `cursor + gap < GOAT finalized or  *)
(* status = Syncing` with no expiry; sub-tasks have no own budget, only a  *)
(* run-level timeout that abandons the rest of the round; paging restarts  *)
(* from the first item every round and the balance refresh stops at its    *)
(* first error; graph_chain_scan always reads GOAT GraphData; deferral and *)
(* sub-task failures were reported as success.                             *)
(*                                                                         *)
(* L16 (pruning terminal instances from the scanned set) is not            *)
(* implemented and is not modelled.                                        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    PreFix,       \* TRUE: the single serial loop before the fix
    N,            \* paging items (operators / pending peg-in requests)
    Gap,          \* watch_contract.gap
    MaxH,         \* GOAT finalized height; bounds the indexer and cursor
    MaxBtcFaults, \* BTC RPC is eventually available: finitely many faults
    GoatOutages   \* GOAT GraphData may become (and stay) unavailable

Paged == {"balance", "pegin"}
\* Next item after a cursor; 0 is "no cursor yet".
Succ(c) == IF c = N THEN 1 ELSE c + 1

VARIABLES
    pc,         \* maintenance lane (PreFix: the single loop)
    bpc,        \* BTC lane ("off" under PreFix)
    cur,        \* paging cursor per paged sub-task: the last item started
                \* (persists across rounds; PreFix records it but ignores it)
    done,       \* items finished by the current paged sub-task
    item,       \* item being awaited, 0 if none
    mFailed,    \* a failure happened in the current maintenance round
    hist,       \* history check result of the current round
    mRan,       \* sub-tasks attempted in the current maintenance round
    mReport,    \* outcome reported at the end of the round ("none" while running)
    bFailed, bRan, bReport,   \* the same for the BTC lane
    cursor,     \* watch_contract.from_height (local history cursor)
    indexed,    \* subgraph _meta.block.number; GOAT finalized is fixed at MaxH
    syncFlag,   \* watch_contract.status = Syncing
    fresh,      \* updated_at is within LOAD_HISTORY_EVENT_NO_WOKING_MAX_SECS
    confirmed,  \* the graph's PreKickoff is confirmed on Bitcoin
    scanned,    \* graph_chain_scan has derived the confirmed graph's stage
    goatUp,     \* GOAT GraphData readable
    btcFaults,  \* BTC RPC faults used so far
    cancelled

mVars == <<pc, cur, done, item, mFailed, hist, mRan, mReport>>
bVars == <<bpc, bFailed, bRan, bReport>>
envVars == <<cursor, indexed, syncFlag, fresh, confirmed, goatUp>>
vars == <<mVars, bVars, envVars, scanned, btcFaults, cancelled>>

MPcs == {"sleep", "balance", "spv", "history", "pegin", "answer",
         "instance", "graph", "stopped"}
Reports == {"none", "success", "deferred", "failed"}
Zero == [t \in Paged |-> 0]

TypeOK ==
    /\ pc \in MPcs
    /\ bpc \in {"off", "sleep", "graph", "instance", "stopped"}
    /\ cur \in [Paged -> 0..N]
    /\ done \in [Paged -> 0..N]
    /\ item \in [Paged -> 0..N]
    /\ mFailed \in BOOLEAN
    /\ hist \in {"none", "synced", "pending", "error"}
    /\ mRan \subseteq MPcs
    /\ mReport \in Reports
    /\ bFailed \in BOOLEAN
    /\ bRan \subseteq {"graph", "instance"}
    /\ bReport \in Reports
    /\ cursor \in 0..MaxH /\ indexed \in 0..MaxH
    /\ syncFlag \in BOOLEAN /\ fresh \in BOOLEAN
    /\ confirmed \in BOOLEAN /\ scanned \in BOOLEAN /\ goatUp \in BOOLEAN
    /\ btcFaults \in 0..MaxBtcFaults
    /\ cancelled \in BOOLEAN

Init ==
    /\ pc = "sleep"
    /\ bpc = IF PreFix THEN "off" ELSE "sleep"
    /\ cur = Zero /\ done = Zero /\ item = Zero
    /\ mFailed = FALSE /\ hist = "none" /\ mRan = {} /\ mReport = "none"
    /\ bFailed = FALSE /\ bRan = {} /\ bReport = "none"
    /\ cursor = 0 /\ indexed = 0 /\ syncFlag = FALSE /\ fresh = FALSE
    /\ confirmed = FALSE /\ scanned = FALSE /\ goatUp = TRUE
    /\ btcFaults = 0 /\ cancelled = FALSE

--------------------------------------------------------------------------
(* Environment: indexer, event watcher, Bitcoin, GOAT GraphData. No        *)
(* fairness: the indexer may stay behind or be rebuilt, the Syncing flag   *)
(* may never clear, GraphData may stay unavailable forever.                *)

IndexAdvance == indexed < MaxH /\ indexed' = indexed + 1
    /\ UNCHANGED <<cursor, syncFlag, fresh, confirmed, goatUp>>
IndexerRebuild == indexed > 0 /\ indexed' = 0
    /\ UNCHANGED <<cursor, syncFlag, fresh, confirmed, goatUp>>
\* monitor_events_item / fetch_history_events: Syncing with a fresh
\* updated_at while the cursor moves towards the indexed height.
WatcherStep == cursor < indexed /\ cursor' = cursor + 1
    /\ syncFlag' = TRUE /\ fresh' = TRUE
    /\ UNCHANGED <<indexed, confirmed, goatUp>>
WatcherSynced == syncFlag /\ syncFlag' = FALSE /\ fresh' = FALSE
    /\ UNCHANGED <<cursor, indexed, confirmed, goatUp>>
\* The history task died: the Syncing row stays and its updated_at ages out.
FlagExpire == fresh /\ fresh' = FALSE
    /\ UNCHANGED <<cursor, indexed, syncFlag, confirmed, goatUp>>
ConfirmPreKickoff == ~confirmed /\ confirmed' = TRUE
    /\ UNCHANGED <<cursor, indexed, syncFlag, fresh, goatUp>>
GoatFlip == GoatOutages /\ goatUp' = ~goatUp
    /\ UNCHANGED <<cursor, indexed, syncFlag, fresh, confirmed>>

Env ==
    /\ \/ IndexAdvance \/ IndexerRebuild \/ WatcherStep \/ WatcherSynced
       \/ FlagExpire \/ ConfirmPreKickoff \/ GoatFlip
    /\ UNCHANGED <<mVars, bVars, scanned, btcFaults, cancelled>>

--------------------------------------------------------------------------
(* Shared pieces *)

\* history_sync_pending (fixed) vs. is_processing_gateway_history_events
\* before the fix (GOAT finalized = MaxH, Syncing without expiry).
HistoryPending ==
    IF PreFix THEN cursor + Gap < MaxH \/ syncFlag
    ELSE cursor + Gap < indexed \/ (cursor < indexed /\ syncFlag /\ fresh)

\* Lane outcome recorded by run_maintenance_tasks.
Report(f, h) ==
    IF PreFix THEN (IF h = "error" THEN "failed" ELSE "success")
    ELSE IF f \/ h = "error" THEN "failed"
    ELSE IF h = "pending" THEN "deferred" ELSE "success"

\* Successor sub-task in the maintenance lane; "END" finishes the round.
NextPc(p) ==
    CASE p = "balance"  -> "spv"
      [] p = "spv"      -> "history"
      [] p = "pegin"    -> "answer"
      [] p = "answer"   -> IF PreFix THEN "instance" ELSE "END"
      [] p = "instance" -> "graph"
      [] p = "graph"    -> "END"

\* Leave the current sub-task for `to` with accumulated failure `f`; `h` is
\* the round's history result. Paging state of the left sub-task is dropped.
MGoto(to, f, h) ==
    /\ mFailed' = f
    /\ done' = Zero /\ item' = Zero
    /\ IF to = "END"
         THEN pc' = "sleep" /\ mReport' = Report(f, h) /\ UNCHANGED mRan
         ELSE pc' = to /\ mRan' = mRan \cup {to} /\ UNCHANGED mReport

\* graph_chain_scan succeeds: a confirmed PreKickoff needs no GraphData after
\* the fix; before it GraphData was read for every graph.
GraphReadable == (confirmed /\ ~PreFix) \/ goatUp

Others == <<bVars, envVars, scanned, btcFaults, cancelled>>

--------------------------------------------------------------------------
(* Maintenance lane (PreFix: the single loop) *)

MStart ==
    /\ pc = "sleep"
    /\ pc' = "balance" /\ mRan' = {"balance"} /\ mReport' = "none"
    /\ mFailed' = FALSE /\ hist' = "none"
    /\ UNCHANGED <<cur, done, item>> /\ UNCHANGED Others

\* spv / answer-window scan / cleanups: success, or error/panic/timeout.
MPlain ==
    /\ pc \in {"spv", "answer"}
    /\ \E f \in BOOLEAN : MGoto(NextPc(pc), mFailed \/ f, hist)
    /\ UNCHANGED <<cur, hist>> /\ UNCHANGED Others

RoundDone(t) ==
    IF PreFix \/ t = "balance" THEN done[t] = N
    ELSE done[t] = N \/ (done[t] > 0 /\ cur[t] = N)

\* Start awaiting the next item; the cursor is stored before the await.
\* PreFix had no cursor and always walked the list from its first item.
PStart(t) ==
    /\ pc = t /\ item[t] = 0 /\ ~RoundDone(t)
    /\ LET i == IF PreFix THEN done[t] + 1 ELSE Succ(cur[t]) IN
         /\ item' = [item EXCEPT ![t] = i]
         /\ cur' = [cur EXCEPT ![t] = i]
    /\ UNCHANGED <<pc, done, mFailed, hist, mRan, mReport>> /\ UNCHANGED Others

PItemOk(t) ==
    /\ pc = t /\ item[t] # 0
    /\ item' = [item EXCEPT ![t] = 0] /\ done' = [done EXCEPT ![t] = @ + 1]
    /\ UNCHANGED <<pc, cur, mFailed, hist, mRan, mReport>> /\ UNCHANGED Others

\* Item error, or (fixed) the per-item maintenance_item_timeout.
PItemFail(t) ==
    /\ pc = t /\ item[t] # 0
    /\ IF PreFix /\ t = "balance"
         \* pre-fix balance refresh: `?` on the first error ends the sub-task
         THEN MGoto(NextPc(pc), TRUE, hist)
         ELSE /\ item' = [item EXCEPT ![t] = 0]
              /\ done' = [done EXCEPT ![t] = @ + 1] /\ mFailed' = TRUE
              /\ UNCHANGED <<pc, mRan, mReport>>
    /\ UNCHANGED <<cur, hist>> /\ UNCHANGED Others

PFinish(t) ==
    /\ pc = t /\ item[t] = 0 /\ RoundDone(t)
    /\ MGoto(NextPc(pc), mFailed, hist)
    /\ UNCHANGED <<cur, hist>> /\ UNCHANGED Others

\* Fixed: the sub-task budget expires while an item is awaited. The cursor
\* already names that item, so the next round starts after it.
PBudget(t) ==
    /\ ~PreFix /\ pc = t /\ item[t] # 0
    /\ MGoto(NextPc(pc), TRUE, hist)
    /\ UNCHANGED <<cur, hist>> /\ UNCHANGED Others

\* Gateway history check. "error" covers metadata unavailable, indexing
\* errors, a negative height, the check's own timeout and a panic.
MHistory ==
    /\ pc = "history"
    /\ \E err \in BOOLEAN :
         LET h == IF err THEN "error"
                  ELSE IF HistoryPending THEN "pending" ELSE "synced" IN
         /\ hist' = h
         /\ MGoto(IF h = "synced" THEN "pegin" ELSE "END", mFailed, h)
    /\ UNCHANGED cur /\ UNCHANGED Others

\* PreFix only: the Bitcoin scans run at the tail of the single loop.
MInstance ==
    /\ pc = "instance"
    /\ \/ MGoto(NextPc(pc), mFailed, hist) /\ UNCHANGED btcFaults
       \/ btcFaults < MaxBtcFaults /\ btcFaults' = btcFaults + 1
          /\ MGoto(NextPc(pc), TRUE, hist)
    /\ UNCHANGED <<cur, hist, bVars, envVars, scanned, cancelled>>

MGraph ==
    /\ pc = "graph"
    /\ \/ GraphReadable /\ scanned' = (scanned \/ confirmed)
          /\ MGoto(NextPc(pc), mFailed, hist) /\ UNCHANGED btcFaults
       \/ btcFaults < MaxBtcFaults /\ btcFaults' = btcFaults + 1
          /\ MGoto(NextPc(pc), TRUE, hist) /\ UNCHANGED scanned
       \/ ~GraphReadable /\ MGoto(NextPc(pc), TRUE, hist)
          /\ UNCHANGED <<scanned, btcFaults>>
    /\ UNCHANGED <<cur, hist, bVars, envVars, cancelled>>

\* PreFix only: MAINTENANCE_RUN_TIMEOUT_SECS fires and the rest of the
\* round, including the Bitcoin scans, is dropped.
MRunTimeout ==
    /\ PreFix /\ pc \notin {"sleep", "stopped"}
    /\ pc' = "sleep" /\ mReport' = "failed" /\ mFailed' = TRUE
    /\ done' = Zero /\ item' = Zero
    /\ UNCHANGED <<cur, hist, mRan>> /\ UNCHANGED Others

MaintLane ==
    \/ MStart \/ MPlain \/ MHistory \/ MInstance \/ MGraph \/ MRunTimeout
    \/ \E t \in Paged : PStart(t) \/ PItemOk(t) \/ PItemFail(t)
                         \/ PFinish(t) \/ PBudget(t)

--------------------------------------------------------------------------
(* BTC lane (fixed only): run_bitcoin_scans. A fault is a BTC RPC error,  *)
(* a panic or the sub-task budget; there are finitely many of them.        *)

BStart ==
    /\ bpc = "sleep"
    /\ bpc' = "graph" /\ bRan' = {"graph"} /\ bFailed' = FALSE /\ bReport' = "none"
    /\ UNCHANGED <<mVars, envVars, scanned, btcFaults, cancelled>>

BGraph ==
    /\ bpc = "graph"
    /\ bpc' = "instance" /\ bRan' = bRan \cup {"instance"}
    /\ \/ GraphReadable /\ scanned' = (scanned \/ confirmed)
          /\ UNCHANGED <<bFailed, btcFaults>>
       \/ btcFaults < MaxBtcFaults /\ btcFaults' = btcFaults + 1
          /\ bFailed' = TRUE /\ UNCHANGED scanned
       \/ ~GraphReadable /\ bFailed' = TRUE /\ UNCHANGED <<scanned, btcFaults>>
    /\ UNCHANGED <<bReport, mVars, envVars, cancelled>>

BInstance ==
    /\ bpc = "instance"
    /\ \/ UNCHANGED <<bFailed, btcFaults>>
       \/ btcFaults < MaxBtcFaults /\ btcFaults' = btcFaults + 1
          /\ bFailed' = TRUE
    /\ bpc' = "sleep"
    /\ bReport' = IF bFailed' THEN "failed" ELSE "success"
    /\ UNCHANGED <<bRan, mVars, envVars, scanned, cancelled>>

BLane == ~PreFix /\ (BStart \/ BGraph \/ BInstance)

--------------------------------------------------------------------------
(* Cancellation: select! drops both in-flight passes together. *)

Cancel ==
    /\ ~cancelled /\ cancelled' = TRUE
    /\ pc' = "stopped" /\ item' = Zero /\ done' = Zero
    /\ bpc' = IF PreFix THEN "off" ELSE "stopped"
    /\ UNCHANGED <<cur, mFailed, hist, mRan, mReport>>
    /\ UNCHANGED <<bFailed, bRan, bReport, envVars, scanned, btcFaults>>

Next == MaintLane \/ BLane \/ Env \/ Cancel

\* The loop that runs the Bitcoin scans is scheduled fairly; the other lane
\* gets no fairness, so its sub-tasks may stall forever.
BtcLoop == IF PreFix THEN MaintLane ELSE BLane

Spec == Init /\ [][Next]_vars /\ WF_vars(BtcLoop)

--------------------------------------------------------------------------
(* Properties *)

\* H4: L2 work is deferred only while the indexer serves blocks the cursor
\* has not reached, and a Syncing status counts only while fresh (otherwise
\* only a backlog larger than one gap defers). A caught-up node, an indexer
\* that lags GOAT or was rebuilt, and a residual flag never defer it.
HistoryDeferralJustified ==
    [][(pc = "history" /\ hist' = "pending") =>
         /\ cursor < indexed
         /\ (cursor + Gap < indexed \/ (syncFlag /\ fresh))]_vars

\* H5: a finished round reports success only when nothing failed and all
\* L2 work ran; "deferred" only for a history backlog. A failed history
\* check is a failure, not a deferral.
ReportHonest ==
    /\ mReport = "success" => ~mFailed /\ hist = "synced"
    /\ mReport = "deferred" => ~mFailed /\ hist = "pending"
    /\ bReport = "success" => ~bFailed

\* H5: a failure, panic or timeout does not stop later sub-tasks; the
\* history state skips only pegin/answer (L2-history-dependent work), never
\* a Bitcoin scan.
AllSubtasksAttempted ==
    /\ mReport # "none" =>
         ({"balance", "spv", "history"}
          \cup (IF hist = "synced" THEN {"pegin", "answer"} ELSE {})
          \cup (IF PreFix THEN {"instance", "graph"} ELSE {})) \subseteq mRan
    /\ bReport # "none" => bRan = {"graph", "instance"}

\* H5: cancelling the service ends both lanes in the same step.
CancelStopsBoth ==
    cancelled => pc = "stopped" /\ bpc \in {"stopped", "off"} /\ item = Zero

\* H4/H5 liveness: with the BTC loop scheduled fairly and BTC RPC eventually
\* available, a confirmed PreKickoff graph is scanned however slow the
\* balance/SPV/history/peg-in work is and whatever the indexer, the Syncing
\* flag and GOAT GraphData do.
BtcScanProgress == confirmed ~> (scanned \/ cancelled)

\* H5: paging never restarts on the item started last - not after a
\* success, an item error, the item timeout or the sub-task budget expiring
\* while the item was awaited. With N = 2 the items strictly alternate, so
\* each one (failed ones included: nothing is dropped) is attempted again
\* whenever the sub-task keeps running.
PagingRotates ==
    [][\A t \in Paged :
         (item[t] = 0 /\ item'[t] # 0 /\ cur[t] # 0) => item'[t] # cur[t]]_vars

====
