---- MODULE GraphLifecycle ----
(***************************************************************************)
(* One graph's Graph.status column and every code path that writes it,     *)
(* racing each other and the two chains.                                   *)
(*                                                                         *)
(* Finding 1 (fixed in 991faaa): the Bitcoin chain scan and the GoatChain   *)
(* event watcher both wrote Graph.status with a raw UPDATE, so a stale Goat *)
(* event could knock a later status back or off a closed one. #476 kept    *)
(* the fix and widened it: every write now goes through                    *)
(* StorageProcessor::transition_graph_status                               *)
(* (crates/store/src/localdb/graph.rs:450), a conditional UPDATE ... WHERE  *)
(* status IN GraphStatus::allowed_transition_from(target, source)           *)
(* (crates/store/src/schema.rs:438), modeled by Transition in               *)
(* GraphTopology.tla. This spec re-derives the writers from the current     *)
(* tree and checks the guard still keeps the column consistent.             *)
(*                                                                         *)
(* Code scope (dev after #476). Writers of Graph.status:                   *)
(*   Definition     - ingest_graph_definition / confirm_finalized_graph_    *)
(*                    definition, node/src/utils/graph_store.rs:208,400     *)
(*   ChainReconcile - Graph aggregate apply_chain_scan of a ChainScan event *)
(*                    gathered earlier by gather_chain_scan                 *)
(*                    (node/src/aggregates/graph_pegout.rs:551,             *)
(*                    node/src/aggregates/graph_scan.rs:303); refresh_graph *)
(*                    after a graph is finalized                            *)
(*                    (node/src/utils/graph_chain_state.rs:22)              *)
(*   GoatEvent      - gateway event watcher, apply_gateway_graph_status     *)
(*                    (node/src/scheduled_tasks/event_watch/gateway.rs:305) *)
(*   Obsoleted      - obsolete_graph (node/src/utils/graph_store.rs:646)    *)
(*                    from a sibling's withdrawal event (gateway.rs:395),   *)
(*                    the instance entering failure (Instance aggregate     *)
(*                    enter_failure, node/src/aggregates/instance.rs:826),  *)
(*                    the pegout RPC (bitvm_handler.rs:1490); and the       *)
(*                    Graph aggregate abandon_setup (graph.rs:823).         *)
(* An aggregate apply runs in one BEGIN IMMEDIATE transaction               *)
(* (crates/engine/src/worker.rs:177), so each apply and each               *)
(* transition_graph_status call is one atomic step here. What is NOT        *)
(* atomic is a chain scan: its facts are read before the ChainScan event is *)
(* applied, so ApplyChainScan may act on stale facts.                       *)
(*                                                                         *)
(* Deliberate simplifications:                                             *)
(*   - One pending ChainScan. The engine applies a graph's events in order  *)
(*     and the chain facts only grow, so later scans never carry an older   *)
(*     stage than earlier ones; the race that matters is one stale scan     *)
(*     against the other writers.                                           *)
(*   - refresh_graph reads the chain and writes in one step (its read/write *)
(*     gap is the same kind of staleness the pending ChainScan exercises).  *)
(*   - No Bitcoin reorg: confirmed facts only grow. The branch transactions *)
(*     (Kickoff/Skip-Kickoff, Take-1/Challenge/guardian Disprove,          *)
(*     Take-2/Disprove) spend the same outputs, so one branch wins.         *)
(*   - The four Challenge-state disprove detectors collapse into Disprove;  *)
(*     they differ only in sub_status bookkeeping, which gates nothing.     *)
(*                                                                         *)
(* Configs (audit/tla/checks.txt):                                         *)
(*   GraphLifecycle/CoreOnly.cfg - pass: the chain-reconcile scanners alone  *)
(*                                (OtherWriters = {}).                      *)
(*   GraphLifecycle/Fixed.cfg    - pass: every writer of the current code.   *)
(***************************************************************************)
EXTENDS Naturals, GraphTopology

CONSTANTS
    OtherWriters    \* writers besides the chain-reconcile scanners that are enabled, a subset of AllOtherWriters

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

\* Bitcoin progress of the graph: NoBitcoin while its Pre-Kickoff is unconfirmed.
NoBitcoin == "NoBitcoin"
BitcoinStages == {NoBitcoin, PreKickoff, OperatorKickOff, Skipped, Challenge,
                  OperatorTake1, OperatorTake2, Disprove}

\* Stages scan_graph_chain_state can report.
ChainStages == {OperatorPresigned, CommitteePresigned, OperatorDataPushed} \cup
               (BitcoinStages \ {NoBitcoin})

\* Goat gateway events that carry a graph status (gateway.rs:351-512, 657-696).
GoatTargets == {OperatorDataPushed, OperatorTake1, OperatorTake2, Disprove}

\* Life cycle of a one-shot event.
NotEmitted == "NotEmitted"
Pending    == "Pending"
Handled    == "Handled"
EventStates == {NotEmitted, Pending, Handled}

\* decide_status returns None.
NoTarget == "NoTarget"

\* The pending-scan slot is empty.
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
    goatEvents,       \* per Goat status event: NotEmitted, Pending (indexed, unhandled) or Handled
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

\* The stage scan_graph_chain_state derives (graph_chain_state.rs:222-300).
ChainStage ==
    IF bitcoinStage # NoBitcoin THEN bitcoinStage
    ELSE IF posted THEN OperatorDataPushed
    ELSE IF finalized THEN CommitteePresigned
    ELSE OperatorPresigned

\* unusable_fact (graph_scan.rs:374): EarlierSlotDead, PrekickoffInputSpent or
\* ConnectorZeroTaken; only computed while the Pre-Kickoff is unconfirmed.
Unusable == prekickoffDead \/ siblingSettled

\* decide_status (graph_pegout.rs:291).
DecideStatus(stage, unusable, instanceFailed) ==
    IF stage \in BitcoinStages \ {NoBitcoin} THEN stage
    ELSE IF unusable THEN Obsoleted
    ELSE IF stage = OperatorDataPushed THEN OperatorDataPushed
    ELSE IF instanceFailed THEN Obsoleted
    ELSE NoTarget

\* What the column should settle to once the chains stop moving.
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

\* Action: the committee's pre-signatures for the graph are stored locally; in
\* the same transaction the Definition writer moves OperatorPresigned to
\* CommitteePresigned, and the finalize job then runs refresh_graph.
\* Source: store_finalized_graph_if_needed() in node/src/utils/graph_store.rs:177
\* Source: confirm_finalized_graph_definition() in node/src/utils/graph_store.rs:400
\* Source: finalize jobs calling try_refresh_graph() in node/src/aggregates/graph_jobs.rs:1164,2201
StoreFinalizedDefinition ==
    /\ ~finalized
    /\ finalized' = TRUE
    /\ refreshPending' = TRUE
    /\ status' = IF WriterDefinition \in OtherWriters
                    THEN Transition(status, CommitteePresigned, SourceDefinition)
                    ELSE status
    /\ UNCHANGED <<posted, bitcoinStage, prekickoffDead, siblingSettled, failureEntries,
                   abandoned, pendingScan, goatEvents, siblingObsolete>>

\* Action: the relayer posts GraphData on Goat; the gateway emits PostGraphData.
\* The relayer posts only for a live instance whose peg-in is Withdrawable,
\* so never for a failed instance or once a sibling claimed the peg-in.
\* Source: post_graph_data() in node/src/aggregates/graph_jobs.rs:2221
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

\* Action: an input of the Pre-Kickoff (or of a lower slot's) is spent by
\* another confirmed transaction, so the Pre-Kickoff can never confirm.
\* Source: Bitcoin consensus
PrekickoffInputSpent ==
    /\ bitcoinStage = NoBitcoin /\ ~prekickoffDead
    /\ prekickoffDead' = TRUE
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: a confirmed Bitcoin transaction moves the graph along its branch:
\* Kickoff or Skip-Kickoff after Pre-Kickoff; Take-1, Challenge or a guardian
\* disprove after Kickoff; Take-2 or Disprove after Challenge. A Take needs
\* Connector-0, so none follows a sibling's settlement.
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

\* Action: the gateway records this graph's settlement (WithdrawHappy,
\* WithdrawUnhappy or WithdrawDisproved) after its Bitcoin proof.
\* Source: Gateway.sol finishWithdrawHappyPath / finishWithdrawUnhappyPath / finishWithdrawDisproved
GoatSettlementEmitted(t) ==
    /\ WriterGoatEvent \in OtherWriters
    /\ t \in {OperatorTake1, OperatorTake2, Disprove}
    /\ bitcoinStage = t /\ goatEvents[t] = NotEmitted
    /\ goatEvents' = [goatEvents EXCEPT ![t] = Pending]
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, siblingObsolete>>

\* Action: another graph of the instance completes its withdrawal: its Take
\* spends Connector-0 and the gateway marks the peg-in Claimed and emits the
\* sibling's withdraw event.
\* Source: Bitcoin consensus; Gateway.sol finishWithdrawHappyPath / finishWithdrawUnhappyPath
SiblingSettles ==
    /\ ~siblingSettled
    /\ bitcoinStage \notin {OperatorTake1, OperatorTake2}
    /\ siblingSettled' = TRUE
    /\ siblingObsolete' = IF WriterSiblingObsolete \in OtherWriters THEN Pending
                          ELSE siblingObsolete
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents>>

\* Action: the instance enters a failure status (the second entry is
\* Timeout -> UserCanceled, which repeats the cleanup). In the same apply
\* enter_failure obsoletes every graph of the instance. A failed instance
\* never had its GraphData posted (post_graph_data refuses it).
\* Source: decide_btc_snapshot() / decide_answer_window() in node/src/aggregates/instance.rs:442,526
\* Source: enter_failure() in node/src/aggregates/instance.rs:826
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
(* Chain-reconcile scanners: the only writers in the CoreOnly config. *)

\* Action: the maintenance tick reads both chains for a monitored (not closed)
\* graph and submits a ChainScan event carrying the stage and, before the
\* Pre-Kickoff, whether the graph is unusable. Obsoleted graphs are probed
\* for their Pre-Kickoff and fully scanned every OBSOLETED_FULL_SCAN_EVERY
\* heights.
\* Source: scan_graphs_on_chain() in node/src/aggregates/graph_scan.rs:131
\* Source: gather_chain_scan() in node/src/aggregates/graph_scan.rs:303
GatherChainScan ==
    /\ status \notin TerminalStatuses
    /\ pendingScan = NoScan
    /\ pendingScan' = [stage |-> ChainStage,
                       unusable |-> bitcoinStage = NoBitcoin /\ Unusable]
    /\ UNCHANGED <<status, finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, refreshPending, goatEvents, siblingObsolete>>

\* Action: the Graph aggregate applies the (possibly stale) ChainScan:
\* decide_status picks the target, reading instance failure at apply time,
\* and transition_graph_status writes it under the ChainReconcile guard.
\* Source: apply_chain_scan() in node/src/aggregates/graph_pegout.rs:551
\* Source: decide_status() in node/src/aggregates/graph_pegout.rs:291
ApplyChainScan ==
    /\ pendingScan # NoScan
    /\ LET target == DecideStatus(pendingScan.stage, pendingScan.unusable, InstanceFailed)
       IN status' = IF target = NoTarget THEN status
                    ELSE Transition(status, target, SourceChainReconcile)
    /\ pendingScan' = NoScan
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, refreshPending, goatEvents, siblingObsolete>>

\* Action: after storing a finalized graph, the finalize job re-derives the
\* stage and writes it as-is (no decide_status) under the ChainReconcile guard.
\* Source: refresh_graph() in node/src/utils/graph_chain_state.rs:22
\* Source: update_graph_status() in node/src/utils/graph_store.rs:626
RefreshGraph ==
    /\ refreshPending
    /\ status' = Transition(status, ChainStage, SourceChainReconcile)
    /\ refreshPending' = FALSE
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, goatEvents, siblingObsolete>>

ChainReconcile == GatherChainScan \/ ApplyChainScan \/ RefreshGraph

--------------------------------------------------------------------------
(* The other writers. *)

\* Action: the gateway event watcher handles an indexed Goat status event
\* (PostGraphData, WithdrawHappy, WithdrawUnhappy, WithdrawDisproved) under
\* the GoatEvent guard.
\* Source: apply_gateway_graph_status() in node/src/scheduled_tasks/event_watch/gateway.rs:305
\* Source: handle_withdraw_paths_events() / handle_withdraw_disproved_events() / handle_post_graph_data_events() in gateway.rs:351,431,657
HandleGoatEvent(t) ==
    /\ goatEvents[t] = Pending
    /\ status' = Transition(status, t, SourceGoatEvent)
    /\ goatEvents' = [goatEvents EXCEPT ![t] = Handled]
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, siblingObsolete>>

\* Action: handling the sibling's withdraw event obsoletes every other graph of
\* the instance under the ChainReconcile guard (which admits OperatorKickOff
\* and Challenge).
\* Source: handle_withdraw_paths_events() in node/src/scheduled_tasks/event_watch/gateway.rs:395
\* Source: obsolete_instance_graphs_except() / obsolete_graph() in node/src/utils/graph_store.rs:671,646
HandleSiblingWithdrawal ==
    /\ siblingObsolete = Pending
    /\ status' = Transition(status, Obsoleted, SourceChainReconcile)
    /\ siblingObsolete' = Handled
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents>>

\* Action: the pegout RPC, selecting an OperatorDataPushed graph whose peg-in
\* is Claimed and whose own withdrawal never started, obsoletes it.
\* Source: pegout() in node/src/rpc_service/handler/bitvm_handler.rs:1384,1490
PegoutRpcObsoletes ==
    /\ WriterPegoutRpc \in OtherWriters
    /\ siblingSettled /\ status = OperatorDataPushed
    /\ status' = Transition(status, Obsoleted, SourceChainReconcile)
    /\ UNCHANGED <<finalized, posted, bitcoinStage, prekickoffDead, siblingSettled,
                   failureEntries, abandoned, pendingScan, refreshPending, goatEvents,
                   siblingObsolete>>

\* Action: at the abandon height the operator retires its own graph that is
\* still OperatorPresigned (no committee signatures) of a live instance.
\* Source: abandon_unfinished_setups() in node/src/aggregates/graph_scan.rs:256
\* Source: abandon_setup() in node/src/aggregates/graph.rs:823
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

\* Fairness: no fairness on the environment (the chains may stop anywhere).
\* WF on the scanners: the maintenance tick runs scan_graphs_on_chain every
\* tick and rescans a graph whenever the height or its status changed
\* (SCAN_MARKS), and blocks keep coming; the engine worker applies queued
\* events; a finalize job runs refresh_graph right after storing the graph.
\* WF on the event handlers: the gateway watcher handles every indexed event.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(GatherChainScan)
    /\ WF_vars(ApplyChainScan)
    /\ WF_vars(RefreshGraph)
    /\ \A t \in GoatTargets : WF_vars(HandleGoatEvent(t))
    /\ WF_vars(HandleSiblingWithdrawal)

--------------------------------------------------------------------------
(* Safety invariants *)

\* A recorded status never claims progress the chains have not made, and a
\* closed status is exactly the branch Bitcoin settled on.
StatusBackedByChain ==
    /\ status \in TerminalStatuses => status = bitcoinStage
    /\ status # Obsoleted => status \in StagesBefore(ChainStage) \cup {ChainStage}

--------------------------------------------------------------------------
(* Safety properties *)

\* Outside Obsoleted (a side state any live stage may enter and leave), the
\* status only moves forward along the protocol order; it may skip stages.
NoStatusRegression ==
    [][(status # status' /\ status # Obsoleted /\ status' # Obsoleted)
         => status \in StagesBefore(status')]_vars

\* A closed status is never left.
TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_vars

\* The two payout paths are never both recorded for one graph.
NoConflictingWithdrawal ==
    /\ [][(status = OperatorTake1 => status' # OperatorTake2)]_vars
    /\ [][(status = OperatorTake2 => status' # OperatorTake1)]_vars

\* A recorded Disprove (evidence the operator cheated) is never lost.
DisproveIsSticky == [][(status = Disprove => status' = Disprove)]_vars

--------------------------------------------------------------------------
(* Liveness *)

\* Once the chains stop moving, the column settles on what they say: the
\* Bitcoin stage, Obsoleted for an unusable, failed-instance or abandoned
\* graph, otherwise the Goat/definition stage.
StatusConvergesToChain == <>[](status = ExpectedStatus)

====
