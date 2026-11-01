---- MODULE GraphLifecycle ----
(***************************************************************************)
(* One graph's Graph.status column and every code path that writes it,     *)
(*   racing each other and the two chains. Each write is one               *)
(*   transition_graph_status call (Transition in GraphTopology). Each      *)
(*   aggregate apply is one BEGIN IMMEDIATE transaction                    *)
(*   (crates/engine/src/worker.rs:177), so one step here. A chain scan is  *)
(*   not atomic: ApplyChainScan may act on stale facts.                    *)
(* Writers: Definition (node/src/utils/graph_store.rs:400); ChainReconcile *)
(*   (graph_scan.rs gather_chain_scan, graph_pegout.rs apply_chain_scan,   *)
(*   graph_chain_state.rs refresh_graph); GoatEvent                        *)
(*   (node/src/scheduled_tasks/event_watch/gateway.rs:305); four Obsoleted *)
(*   writers (sibling withdrawal, instance failure, pegout RPC,            *)
(*   abandon_setup).                                                       *)
(* Finding 1: a writer that bypasses the guard lets a stale event move the *)
(*   status back or off a closed status. Checked: every writer is guarded. *)
(* Parameter: OtherWriters - writers enabled besides the chain-reconcile   *)
(*   scanners (CoreOnly: none; Fixed: all).                                *)
(* Simplifications: one pending ChainScan (events of a graph apply in      *)
(*   order and chain facts only grow, so a later scan never carries an     *)
(*   older stage); refresh_graph reads and writes in one step; no Bitcoin  *)
(*   reorg; the four Challenge-state disprove detectors are one Disprove   *)
(*   (they differ only in sub_status).                                     *)
(* Configs: configs/node/aggregates/graph/GraphLifecycle/, tiers in        *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals, GraphTopology

CONSTANTS
    OtherWriters    \* enabled writers besides the chain-reconcile scanners (subset of AllOtherWriters)

\* Writers that can be switched off to isolate the chain-reconcile scanners.
WriterDefinition      == "Definition"       \* confirm_finalized_graph_definition
WriterGoatEvent       == "GoatEvent"        \* gateway event watcher
WriterSiblingObsolete == "SiblingObsolete"  \* obsolete_instance_graphs_except after a sibling's withdrawal
WriterPegoutRpc       == "PegoutRpc"        \* pegout RPC obsoleting a claimed instance's graph
WriterInstanceFailure == "InstanceFailure"  \* Instance aggregate enter_failure
WriterSetupAbandon    == "SetupAbandon"     \* Graph aggregate abandon_setup
AllOtherWriters == {WriterDefinition, WriterGoatEvent, WriterSiblingObsolete,
                    WriterPegoutRpc, WriterInstanceFailure, WriterSetupAbandon}

ASSUME OtherWriters \subseteq AllOtherWriters

\* Confirmed Bitcoin progress of the graph; NoBitcoin before its Pre-Kickoff.
NoBitcoin == "NoBitcoin"
BitcoinStages == {NoBitcoin, PreKickoff, OperatorKickOff, Skipped, Challenge,
                  OperatorTake1, OperatorTake2, Disprove}

\* Stages scan_graph_chain_state (node/src/utils/graph_chain_state.rs:222) can report.
ChainStages == {OperatorPresigned, CommitteePresigned, OperatorDataPushed} \cup
               (BitcoinStages \ {NoBitcoin})

\* Goat gateway events that carry a graph status (gateway.rs:351-513, 657-696).
GoatTargets == {OperatorDataPushed, OperatorTake1, OperatorTake2, Disprove}

\* States of a one-shot event.
NotEmitted == "NotEmitted"
Pending    == "Pending"
Handled    == "Handled"
EventStates == {NotEmitted, Pending, Handled}

\* decide_status returned None (no write).
NoTarget == "NoTarget"

\* Empty pending-scan slot.
NoScan == [stage |-> NoTarget, unusable |-> FALSE]
ScanRecords == [stage : ChainStages, unusable : BOOLEAN] \cup {NoScan}

VARIABLES
    status,           \* Graph.status of the local row
    finalized,        \* the stored definition carries committee pre-signatures
    posted,           \* Goat gateway holds this graph's GraphData
    bitcoinStage,     \* confirmed Bitcoin progress of the graph
    prekickoffDead,   \* an input of this (or a lower slot's) Pre-Kickoff is spent elsewhere
    siblingSettled,   \* another graph of the instance completed its withdrawal (Connector-0 spent)
    failureEntries,   \* times the instance entered a failure status (Timeout, then UserCanceled)
    abandoned,        \* the operator retired the unfinished setup at the abandon height
    pendingScan,      \* a gathered ChainScan event not yet applied, or NoScan
    refreshPending,   \* a finalize job will run refresh_graph
    goatEvents,       \* per Goat status event: NotEmitted, Pending (indexed, not handled) or Handled
    siblingObsolete   \* the sibling's withdrawal event that obsoletes this graph

vars == <<status, finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
          failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
          siblingObsolete>>

TypeOk ==
    /\ status \in AllStatuses
    /\ finalized \in BOOLEAN
    /\ posted \in BOOLEAN
    /\ bitcoinStage \in BitcoinStages
    /\ prekickoffDead \in BOOLEAN
    /\ siblingSettled \in BOOLEAN
    /\ failureEntries \in 0..2
    /\ abandoned \in BOOLEAN
    /\ pendingScan \in ScanRecords
    /\ refreshPending \in BOOLEAN
    /\ goatEvents \in [GoatTargets -> EventStates]
    /\ siblingObsolete \in EventStates

--------------------------------------------------------------------------
(* Derived facts *)

InstanceFailed == failureEntries > 0

\* The stage scan_graph_chain_state derives (graph_chain_state.rs:222-455).
ChainStage ==
    IF bitcoinStage # NoBitcoin THEN bitcoinStage
    ELSE IF posted THEN OperatorDataPushed
    ELSE IF finalized THEN CommitteePresigned
    ELSE OperatorPresigned

\* unusable_fact (graph_scan.rs:374): a lower slot is dead, a Pre-Kickoff input is
\* spent, or Connector-0 is taken. Read only before the Pre-Kickoff confirms.
Unusable == prekickoffDead \/ siblingSettled

\* Target of apply_chain_scan (decide_status, node/src/aggregates/graph_pegout.rs:291).
DecideStatus(stage, unusable, instanceFailed) ==
    IF stage \in BitcoinStages \ {NoBitcoin} THEN stage
    ELSE IF unusable THEN Obsoleted
    ELSE IF stage = OperatorDataPushed THEN OperatorDataPushed
    ELSE IF instanceFailed THEN Obsoleted
    ELSE NoTarget

\* The status the column must settle on once the chains stop moving.
ExpectedStatus ==
    IF bitcoinStage # NoBitcoin THEN bitcoinStage
    ELSE IF Unusable THEN Obsoleted
    ELSE IF posted THEN OperatorDataPushed
    ELSE IF InstanceFailed \/ abandoned THEN Obsoleted
    ELSE IF finalized THEN CommitteePresigned
    ELSE OperatorPresigned

Init ==
    /\ status = OperatorPresigned
    /\ finalized = FALSE
    /\ posted = FALSE
    /\ bitcoinStage = NoBitcoin
    /\ prekickoffDead = FALSE
    /\ siblingSettled = FALSE
    /\ failureEntries = 0
    /\ abandoned = FALSE
    /\ pendingScan = NoScan
    /\ refreshPending = FALSE
    /\ goatEvents = [t \in GoatTargets |-> NotEmitted]
    /\ siblingObsolete = NotEmitted

--------------------------------------------------------------------------
(* Environment: the two chains and the instance. *)

\* Action: committee pre-signatures are stored; Definition writes CommitteePresigned and queues refresh_graph.
\* Source: node/src/utils/graph_store.rs:177, 400 (store_finalized_graph_if_needed, confirm_finalized_graph_definition)
\* Source: node/src/aggregates/graph_jobs.rs:1164, 2201 (try_refresh_graph)
StoreFinalizedDefinition ==
    /\ ~finalized
    /\ finalized' = TRUE
    /\ refreshPending' = TRUE
    /\ status' = IF WriterDefinition \in OtherWriters
                    THEN Transition(status, CommitteePresigned, SourceDefinition)
                    ELSE status
    /\ UNCHANGED <<posted, bitcoinStage, prekickoffDead, siblingSettled, failureEntries,
                   abandoned, pendingScan, goatEvents, siblingObsolete>>

\* Action: the relayer posts GraphData on Goat (live, unclaimed instance only).
\* Source: node/src/aggregates/graph_jobs.rs:2221 (post_graph_data)
PostGraphData ==
    /\ ~posted /\ ~InstanceFailed /\ ~siblingSettled
    /\ posted' = TRUE
    /\ goatEvents' = IF WriterGoatEvent \in OtherWriters
                        THEN [goatEvents EXCEPT ![OperatorDataPushed] = Pending]
                        ELSE goatEvents
    /\ UNCHANGED <<status, finalized, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, siblingObsolete>>

\* Action: the graph's Pre-Kickoff confirms.
\* Source: Bitcoin consensus
PrekickoffConfirms ==
    /\ bitcoinStage = NoBitcoin /\ ~prekickoffDead
    /\ bitcoinStage' = PreKickoff
    /\ UNCHANGED <<status, finalized, posted, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: an input of this (or a lower slot's) Pre-Kickoff is spent elsewhere.
\* Source: Bitcoin consensus
PrekickoffInputSpent ==
    /\ bitcoinStage = NoBitcoin /\ ~prekickoffDead
    /\ prekickoffDead' = TRUE
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: the next branch transaction confirms; no Take once a sibling took Connector-0.
\* Source: Bitcoin consensus
BitcoinAdvances ==
    /\ \/ bitcoinStage = PreKickoff /\ bitcoinStage' \in {OperatorKickOff, Skipped}
       \/ bitcoinStage = OperatorKickOff /\ bitcoinStage' \in {Challenge, Disprove}
       \/ bitcoinStage = OperatorKickOff /\ ~siblingSettled /\ bitcoinStage' = OperatorTake1
       \/ bitcoinStage = Challenge /\ bitcoinStage' = Disprove
       \/ bitcoinStage = Challenge /\ ~siblingSettled /\ bitcoinStage' = OperatorTake2
    /\ UNCHANGED <<status, finalized, posted, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: the gateway emits this graph's settlement event after the Take-1, Take-2 or Disprove.
\* Source: Gateway.sol finishWithdrawHappyPath / finishWithdrawUnhappyPath / finishWithdrawDisproved
GoatSettlementEmitted(t) ==
    /\ WriterGoatEvent \in OtherWriters
    /\ t \in {OperatorTake1, OperatorTake2, Disprove}
    /\ bitcoinStage = t /\ goatEvents[t] = NotEmitted
    /\ goatEvents' = [goatEvents EXCEPT ![t] = Pending]
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, siblingObsolete>>

\* Action: a sibling graph takes Connector-0; the gateway emits its withdraw event.
\* Source: Bitcoin consensus; Gateway.sol finishWithdrawHappyPath / finishWithdrawUnhappyPath
SiblingSettles ==
    /\ ~siblingSettled
    /\ bitcoinStage \notin {OperatorTake1, OperatorTake2}
    /\ siblingSettled' = TRUE
    /\ siblingObsolete' = IF WriterSiblingObsolete \in OtherWriters THEN Pending
                          ELSE siblingObsolete
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents>>

\* Action: the instance fails (at most twice); enter_failure obsoletes its graphs in the same apply.
\* Source: node/src/aggregates/instance.rs:442, 526 (decide_btc_snapshot, decide_answer_window)
\* Source: node/src/aggregates/instance.rs:826 (enter_failure)
InstanceEntersFailure ==
    /\ failureEntries < 2 /\ ~posted
    /\ failureEntries' = failureEntries + 1
    /\ status' = IF WriterInstanceFailure \in OtherWriters
                    THEN Transition(status, Obsoleted, SourceChainReconcile)
                    ELSE status
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   abandoned, pendingScan, refreshPending, goatEvents, siblingObsolete>>

Environment ==
    \/ StoreFinalizedDefinition
    \/ PostGraphData
    \/ PrekickoffConfirms
    \/ PrekickoffInputSpent
    \/ BitcoinAdvances
    \/ \E t \in GoatTargets : GoatSettlementEmitted(t)
    \/ SiblingSettles
    \/ InstanceEntersFailure

--------------------------------------------------------------------------
(* Chain-reconcile scanners: the only writers in CoreOnly.cfg. *)

\* Action: the maintenance tick reads both chains and submits a ChainScan for a monitored graph.
\* Source: node/src/aggregates/graph_scan.rs:131, 303 (scan_graphs_on_chain, gather_chain_scan)
GatherChainScan ==
    /\ status \notin TerminalStatuses
    /\ pendingScan = NoScan
    /\ pendingScan' = [stage |-> ChainStage,
                       unusable |-> bitcoinStage = NoBitcoin /\ Unusable]
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, refreshPending, goatEvents, siblingObsolete>>

\* Action: the Graph aggregate applies a possibly stale ChainScan under the ChainReconcile guard.
\* Source: node/src/aggregates/graph_pegout.rs:551, 291 (apply_chain_scan, decide_status)
ApplyChainScan ==
    /\ pendingScan # NoScan
    /\ LET target == DecideStatus(pendingScan.stage, pendingScan.unusable, InstanceFailed)
       IN status' = IF target = NoTarget THEN status
                    ELSE Transition(status, target, SourceChainReconcile)
    /\ pendingScan' = NoScan
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, refreshPending, goatEvents, siblingObsolete>>

\* Action: the finalize job writes the current chain stage under the ChainReconcile guard.
\* Source: node/src/utils/graph_chain_state.rs:22 (refresh_graph)
\* Source: node/src/utils/graph_store.rs:626 (update_graph_status)
RefreshGraph ==
    /\ refreshPending
    /\ status' = Transition(status, ChainStage, SourceChainReconcile)
    /\ refreshPending' = FALSE
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, goatEvents, siblingObsolete>>

ChainReconcile == GatherChainScan \/ ApplyChainScan \/ RefreshGraph

--------------------------------------------------------------------------
(* The other writers. *)

\* Action: the gateway watcher applies an indexed Goat status event under the GoatEvent guard.
\* Source: node/src/scheduled_tasks/event_watch/gateway.rs:305, 351, 431, 657
HandleGoatEvent(t) ==
    /\ goatEvents[t] = Pending
    /\ status' = Transition(status, t, SourceGoatEvent)
    /\ goatEvents' = [goatEvents EXCEPT ![t] = Handled]
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, siblingObsolete>>

\* Action: the sibling's withdraw event obsoletes this graph under the ChainReconcile guard.
\* Source: node/src/scheduled_tasks/event_watch/gateway.rs:395
\* Source: node/src/utils/graph_store.rs:671, 646 (obsolete_instance_graphs_except, obsolete_graph)
HandleSiblingWithdrawal ==
    /\ siblingObsolete = Pending
    /\ status' = Transition(status, Obsoleted, SourceChainReconcile)
    /\ siblingObsolete' = Handled
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents>>

\* Action: the pegout RPC obsoletes an OperatorDataPushed graph whose peg-in is Claimed.
\* Source: node/src/rpc_service/handler/bitvm_handler.rs:1384, 1490
PegoutRpcObsoletes ==
    /\ WriterPegoutRpc \in OtherWriters
    /\ siblingSettled /\ status = OperatorDataPushed
    /\ status' = Transition(status, Obsoleted, SourceChainReconcile)
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: at the abandon height the operator obsoletes its own OperatorPresigned graph.
\* Source: node/src/aggregates/graph_scan.rs:256 (abandon_unfinished_setups)
\* Source: node/src/aggregates/graph.rs:823 (abandon_setup)
AbandonSetup ==
    /\ WriterSetupAbandon \in OtherWriters
    /\ ~abandoned /\ ~InstanceFailed /\ status = OperatorPresigned
    /\ abandoned' = TRUE
    /\ status' = Transition(status, Obsoleted, SourceChainReconcile)
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, pendingScan, refreshPending, goatEvents, siblingObsolete>>

OtherWriterSteps ==
    \/ \E t \in GoatTargets : HandleGoatEvent(t)
    \/ HandleSiblingWithdrawal
    \/ PegoutRpcObsoletes
    \/ AbandonSetup

--------------------------------------------------------------------------
Next == Environment \/ ChainReconcile \/ OtherWriterSteps

\* No fairness on the environment (the chains may stop anywhere). WF on the
\* scanners (every tick rescans a graph whose height or status changed, the
\* engine applies queued events, a finalize job runs refresh_graph) and on the
\* event handlers (the gateway watcher handles every indexed event).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(GatherChainScan)
    /\ WF_vars(ApplyChainScan)
    /\ WF_vars(RefreshGraph)
    /\ \A t \in GoatTargets : WF_vars(HandleGoatEvent(t))
    /\ WF_vars(HandleSiblingWithdrawal)

--------------------------------------------------------------------------
(* Safety invariants *)

\* The status never claims progress the chains lack; a closed status is the settled Bitcoin branch.
StatusBackedByChain ==
    /\ status \in TerminalStatuses => status = bitcoinStage
    /\ status # Obsoleted => status \in StagesBefore(ChainStage) \cup {ChainStage}

--------------------------------------------------------------------------
(* Safety properties *)

\* Outside Obsoleted, the status only moves forward in protocol order (it may skip stages).
NoStatusRegression ==
    [][(status # status' /\ status # Obsoleted /\ status' # Obsoleted)
         => status \in StagesBefore(status')]_vars

\* A closed status is never left.
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_vars

\* Take-1 and Take-2 are never both recorded for one graph.
NoConflictingWithdrawal ==
    /\ [][(status = OperatorTake1 => status' # OperatorTake2)]_vars
    /\ [][(status = OperatorTake2 => status' # OperatorTake1)]_vars

\* A recorded Disprove is never lost.
DisproveIsSticky == [][(status = Disprove => status' = Disprove)]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* Once the chains stop moving, the status settles on ExpectedStatus.
StatusConvergesToChain == <>[](status = ExpectedStatus)

====
