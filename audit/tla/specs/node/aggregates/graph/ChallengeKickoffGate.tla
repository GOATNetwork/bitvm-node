---------------------------- MODULE ChallengeKickoffGate ----------------------------
(***************************************************************************)
(* The verifier's Challenge against the operator's Take1 on connector_a    *)
(*   after a Kickoff, with Bitcoin heights, GOAT SPV, the relayer's        *)
(*   proceedWithdraw and the gateway withdraw status. Code:                *)
(*   challenge_kickoff and proceed_withdraw                                *)
(*   (node/src/aggregates/graph_pegout_jobs.rs:595-647, 1648-1694), the    *)
(*   scan's history-sync gate (node/src/scheduled_tasks/mod.rs:229-255),   *)
(*   Gateway.sol initWithdraw, committeeCancelWithdraw, proceedWithdraw    *)
(*   (localnet/contracts @ 3a679bf).                                       *)
(* C5: initWithdraw once spv >= kickoff makes proceedWithdraw revert; the  *)
(*   gate waits on Initialized forever; Take1 plus a manual cancel pays    *)
(*   twice. No timing margin closes it.                                    *)
(* C6: the gate sends only once spv > kickoff, with no connector_a         *)
(*   deadline. Shipped Testnet4, Signet, Regtest fail with a healthy SPV,  *)
(*   Bitcoin once the SPV lags 118 blocks.                                 *)
(* H4: a Goat history-sync stall over the kickoff skips the only scan that *)
(*   queues the challenge job.                                             *)
(* Fix (design): challenge a poisoned Initialized; from FixWake contest    *)
(*   unless Processing; scan during the sync; reject the cancel once the   *)
(*   kickoff is provable. Cost: it also challenges honest withdraws        *)
(*   outside ParamsLive.                                                   *)
(* Parameters (frozen variables): connectorA ca, spvConfirms sc            *)
(*   (BTC_BLOCK_CONFIRMS), spvLag lag, inclusion incl, reaction r,         *)
(*   syncStall; see the VARIABLES. NetSet = {} sweeps the Range constants, *)
(*   else the shipped values of NetSet.                                    *)
(* ParamsOK == ca >= r + incl + 1: the fix is safe (exact). C6Safe ==      *)
(*   ParamsLive == ca >= sc + lag + 2r + incl + 3: the current code is     *)
(*   safe without late init or stall, and the fix leaves honest withdraws  *)
(*   alone (both exact).                                                   *)
(* Exhaustive: every guard compares parameter sums with small constants,   *)
(*   so a verdict is a threshold on ca minus a linear form in sc, lag,     *)
(*   incl, r; sc 1..3, lag 0..2, incl 1..2, r 0..2 with ca across each     *)
(*   threshold reach every class (violated, margin 0, 1, >= 2). r, lag and *)
(*   syncStall are upper bounds. The three conditions were also checked    *)
(*   point by point.                                                       *)
(* Abstractions: one graph, one kickoff, adversarial operator; the dispute *)
(*   after an in-time Challenge is sound; time stops after Take1, after an *)
(*   in-time Challenge, or at Horizon.                                     *)
(* Configs: configs/node/aggregates/graph/ChallengeKickoffGate/, tiers in  *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelockValues

CONSTANTS
    NetSet,             \* {} = sweep the ranges below; else the shipped values of these networks
    ShippedBudget,      \* shipped mode: "range" (reaction, inclusion over 0..budget) or "worst" (= budget)
    ConnectorARange,    \* sweep: connector_a values
    SpvConfirmsRange,   \* sweep: BTC_BLOCK_CONFIRMS values (>= 1)
    InclusionRange,     \* sweep: inclusion blocks (>= 1)
    ReactionRange,      \* sweep: honest reaction blocks
    SpvLagRange,        \* both modes: extra SPV lag beyond the confirms
    SyncStallRange,     \* both modes: Goat history-sync stall lengths
    Region,             \* parameter filter (see InRegion)
    LazySpv,            \* TRUE: SPV posts only when forced, kickoff at KickLatest (a subset: counterexample cfgs only)
    EnableLateInit,     \* TRUE: initWithdraw may follow the kickoff (the contract allows it)
    FixGate,            \* design: challenge_kickoff challenges poisoned Initialized + connector_a wake
    FixScan,            \* design: scan_graphs_on_chain not gated on the history sync
    FixCancel           \* design: committeeCancelWithdraw rejected once the kickoff is provable

\* sc >= 1 makes a pre-kickoff initWithdraw record a height below the kickoff,
\* so btcBlockHeightAtWithdraw is abstracted to withdrawPoisoned.
ASSUME \A x \in SpvConfirmsRange : x >= 1
ASSUME \A n \in Networks : BtcBlockConfirms[n] >= 1
ASSUME \A x \in InclusionRange : x >= 1

\* Gateway WithdrawStatus values (Gateway.sol).
WdNone        == "None"
WdInitialized == "Initialized"
WdCanceled    == "Canceled"
WdProcessing  == "Processing"
WdComplete    == "Complete"
WdStates == {WdNone, WdInitialized, WdCanceled, WdProcessing, WdComplete}

\* Engine job states.
JobIdle    == "Idle"
JobWaiting == "Waiting"
JobDone    == "Done"
JobStates == {JobIdle, JobWaiting, JobDone}

\* Challenge outcome: not sent, confirms before Take1 is valid, or too late.
ChNone   == "No"
ChInTime == "InTime"
ChLate   == "Late"
ChOutcomes == {ChNone, ChInTime, ChLate}

VARIABLES
    net,                \* frozen: network whose shipped values are used ("sweep" in sweep mode)
    connectorA,         \* frozen: connector_a CSV (blocks)
    spvConfirms,        \* frozen: BTC_BLOCK_CONFIRMS
    spvLag,             \* frozen: spvHeight >= btcTip - spvConfirms - spvLag before each block
    inclusion,          \* frozen: a tx sent at tip t confirms by t + inclusion (>= 1)
    reaction,           \* frozen: an honest action runs within `reaction` blocks of becoming due
    syncStall,          \* frozen: longest Goat history-sync stall (0 = none)
    btcTip,             \* Bitcoin tip height
    spvHeight,          \* GOAT bitcoinSPV.latestHeight()
    kickoffHeight,      \* kickoff confirmation height, 0 = not broadcast
    withdrawStatus,     \* Gateway withdrawDataMap[graphId].status
    withdrawPoisoned,   \* btcBlockHeightAtWithdraw >= kickoff height (initWithdraw saw spv >= kickoff)
    historySyncing,     \* Goat history sync "in progress" on the verifier/relayer nodes
    syncStartTip,       \* tip when the current stall began
    stallUsed,          \* the one modeled stall episode happened
    cancelHappened,     \* history: committeeCancelWithdraw happened (HonestWithdraw only)
    scanLate,           \* blocks the due chain scan has been late
    challengeJob,       \* JOB_CHALLENGE_KICKOFF state
    challengeWake,      \* tip at which the challenge job's retry is due
    challengeLate,      \* blocks the due challenge look has been late
    challengeOutcome,   \* ChNone, ChInTime or ChLate
    relayerJob,         \* JOB_PROCEED_WITHDRAW state
    relayerWake,        \* tip at which the relayer job's retry is due
    relayerLate,        \* blocks the due relayer look has been late
    take1Done,          \* operator's Take1 confirmed (connector_a taken uncontested)
    take1Authorized     \* at Take1 time the withdraw was burned or still burnable

params == <<net, connectorA, spvConfirms, spvLag, inclusion, reaction, syncStall>>
syncVars == <<historySyncing, syncStartTip, stallUsed>>
challengeVars == <<challengeJob, challengeWake, challengeLate, challengeOutcome>>
relayerVars == <<relayerJob, relayerWake, relayerLate>>
vars == <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
          syncVars, cancelHappened, scanLate, challengeVars, relayerVars,
          take1Done, take1Authorized>>

Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

--------------------------------------------------------------------------
\* ---- parameter conditions (exact, see header)
\* The fix design is safe: its Challenge confirms before Take1 whenever needed.
ParamsOK == connectorA >= reaction + inclusion + 1
\* The fix design leaves an honest withdraw unchallenged (proceedWithdraw lands first).
ParamsLive == connectorA >= spvConfirms + spvLag + 2 * reaction + inclusion + 3
\* The current gate challenges in time (no late init, no stall). Worst path: the
\* relayer proceeds at kickH + sc + lag + 1 + r; a cancel just after a gate look
\* delays the Challenge to kickH + sc + lag + 2 + 2r, and it needs incl more.
C6Safe == connectorA >= spvConfirms + spvLag + 2 * reaction + inclusion + 3

\* Parameter points a config explores.
InRegion ==
    CASE Region = "all"      -> TRUE
      [] Region = "ok"       -> ParamsOK
      [] Region = "notok"    -> ~ParamsOK
      [] Region = "live"     -> ParamsOK /\ ParamsLive
      [] Region = "notlive"  -> ParamsOK /\ ~ParamsLive
      [] Region = "c6safe"   -> C6Safe
      [] Region = "c6unsafe" -> ~C6Safe

\* Latest kickoff tip; later kickoffs only shift states already explored.
KickLatest == spvConfirms + spvLag + syncStall + 1
\* Last tip explored.
Horizon == KickLatest + Max(connectorA, spvConfirms + spvLag + 1) + 1

Kicked == kickoffHeight > 0
\* Last tip at which a broadcast Challenge still confirms before Take1 is valid.
Deadline == kickoffHeight + connectorA - 1 - inclusion
\* The fix wakes `reaction` blocks before Deadline, so a late look still sends in time.
FixWake == Deadline - reaction
\* proceedWithdraw would pass the KickoffHeightLow check (pegBTC still burnable).
Burnable == withdrawStatus = WdInitialized /\ ~withdrawPoisoned
\* The SPV covers the kickoff block, so a merkle proof of it exists.
KickoffProvable == Kicked /\ kickoffHeight <= spvHeight

--------------------------------------------------------------------------
TypeOk ==
    /\ net \in Networks \cup {"sweep"}
    /\ connectorA \in Nat /\ spvConfirms \in Nat /\ spvLag \in Nat
    /\ inclusion \in Nat /\ reaction \in Nat /\ syncStall \in Nat
    /\ btcTip \in 0..Horizon /\ spvHeight \in 0..Horizon /\ kickoffHeight \in 0..Horizon
    /\ withdrawStatus \in WdStates /\ withdrawPoisoned \in BOOLEAN
    /\ historySyncing \in BOOLEAN /\ syncStartTip \in 0..Horizon /\ stallUsed \in BOOLEAN
    /\ cancelHappened \in BOOLEAN
    /\ scanLate \in 0..reaction /\ challengeLate \in 0..reaction /\ relayerLate \in 0..reaction
    /\ challengeJob \in JobStates /\ challengeWake \in Int /\ challengeOutcome \in ChOutcomes
    /\ relayerJob \in JobStates /\ relayerWake \in Int
    /\ take1Done \in BOOLEAN /\ take1Authorized \in BOOLEAN

Init ==
    /\ IF NetSet = {}
       THEN /\ net = "sweep"
            /\ connectorA \in ConnectorARange /\ spvConfirms \in SpvConfirmsRange
            /\ inclusion \in InclusionRange /\ reaction \in ReactionRange
       ELSE /\ net \in NetSet
            /\ connectorA = ConnectorA[net] /\ spvConfirms = BtcBlockConfirms[net]
            /\ IF ShippedBudget = "worst"
               THEN /\ inclusion = Max(1, InclusionBlocks[net])
                    /\ reaction = ReactionBlocks[net]
               ELSE /\ inclusion \in 1..Max(1, InclusionBlocks[net])
                    /\ reaction \in 0..ReactionBlocks[net]
    /\ spvLag \in SpvLagRange /\ syncStall \in SyncStallRange
    /\ InRegion
    /\ btcTip = spvConfirms /\ spvHeight = 0 /\ kickoffHeight = 0
    /\ withdrawStatus = WdNone /\ withdrawPoisoned = FALSE
    /\ historySyncing = FALSE /\ syncStartTip = 0 /\ stallUsed = FALSE
    /\ cancelHappened = FALSE /\ scanLate = 0
    /\ challengeJob = JobIdle /\ challengeWake = 0 /\ challengeLate = 0
    /\ challengeOutcome = ChNone
    /\ relayerJob = JobIdle /\ relayerWake = 0 /\ relayerLate = 0
    /\ take1Done = FALSE /\ take1Authorized = FALSE

--------------------------------------------------------------------------
\* ---- honest actions that are due (each must run within `reaction` blocks)
ScanGated   == ~FixScan /\ historySyncing
ScanDue     == Kicked /\ ~ScanGated /\ (challengeJob = JobIdle \/ relayerJob = JobIdle)
ChallengeDue == challengeJob = JobWaiting /\ btcTip >= challengeWake
RelayerDue  == relayerJob = JobWaiting /\ btcTip >= relayerWake

\* Action: a Bitcoin block; disabled while the SPV lag or stall bound or an honest reaction window would be exceeded.
\* Source: Bitcoin consensus; reaction = ReactionBlocks, protocol_timing_budget() in crates/bitvm-gc/src/timelocks.rs:142
MineBlock ==
    /\ btcTip < Horizon
    /\ ~take1Done /\ challengeOutcome # ChInTime
    /\ btcTip - spvConfirms - spvHeight <= spvLag
    /\ ~(historySyncing /\ btcTip + 1 - syncStartTip > syncStall)
    /\ ~(ScanDue /\ scanLate >= reaction)
    /\ ~(ChallengeDue /\ challengeLate >= reaction)
    /\ ~(RelayerDue /\ relayerLate >= reaction)
    /\ btcTip' = btcTip + 1
    /\ scanLate' = IF ScanDue THEN scanLate + 1 ELSE 0
    /\ challengeLate' = IF ChallengeDue THEN challengeLate + 1 ELSE 0
    /\ relayerLate' = IF RelayerDue THEN relayerLate + 1 ELSE 0
    /\ UNCHANGED <<params, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, challengeJob, challengeWake, challengeOutcome,
                   relayerJob, relayerWake, take1Done, take1Authorized>>

\* Action: the SPV updater posts one more header to GOAT, up to tip - BTC_BLOCK_CONFIRMS.
\* Source: node/src/scheduled_tasks/spv_maintenance_tasks.rs:9-39 (spv_header_hash_update)
SpvAdvance ==
    /\ spvHeight + 1 <= btcTip - spvConfirms
    /\ LazySpv => btcTip - spvConfirms - spvHeight > spvLag
    /\ spvHeight' = spvHeight + 1
    /\ UNCHANGED <<params, btcTip, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the Gateway history sync falls behind (one episode); the current code skips the chain scan meanwhile.
\* Source: node/src/scheduled_tasks/event_watch/mod.rs:604-621; node/src/scheduled_tasks/mod.rs:229-255
SyncStallStart ==
    /\ syncStall > 0 /\ ~historySyncing /\ ~stallUsed
    /\ historySyncing' = TRUE /\ syncStartTip' = btcTip /\ stallUsed' = TRUE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the history sync catches up; the chain scan runs again.
\* Source: node/src/scheduled_tasks/event_watch/mod.rs:604-621
SyncStallEnd ==
    /\ historySyncing /\ historySyncing' = FALSE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncStartTip, stallUsed, cancelHappened, scanLate, challengeVars,
                   relayerVars, take1Done, take1Authorized>>

\* Action: the operator's Kickoff confirms at the tip, creating connector_a (Take1 after connectorA blocks).
\* Source: environment (operator); connector_a CSV = timelock_config.connector_a
Kickoff ==
    /\ ~Kicked /\ btcTip >= 1 /\ btcTip <= KickLatest
    /\ LazySpv => btcTip = KickLatest
    /\ kickoffHeight' = btcTip
    /\ scanLate' = 0
    /\ UNCHANGED <<params, btcTip, spvHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the operator locks pegBTC; the withdraw is poisoned if the SPV already covers the kickoff.
\* Source: Gateway.sol initWithdraw 428-457 (454 records bitcoinSPV.latestHeight)
InitWithdraw ==
    /\ withdrawStatus \in {WdNone, WdCanceled} /\ ~take1Done
    /\ EnableLateInit \/ ~Kicked
    /\ withdrawStatus' = WdInitialized
    /\ withdrawPoisoned' = (Kicked /\ spvHeight >= kickoffHeight)
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, syncVars, cancelHappened,
                   scanLate, challengeVars, relayerVars, take1Done, take1Authorized>>

\* Action: Take1 confirms once connector_a's CSV has passed without an in-time Challenge; records whether pegBTC was burned or burnable.
\* Source: Bitcoin consensus
Take1 ==
    /\ Kicked /\ ~take1Done /\ challengeOutcome # ChInTime
    /\ btcTip >= kickoffHeight + connectorA
    /\ take1Done' = TRUE
    /\ take1Authorized' = (withdrawStatus = WdProcessing \/ Burnable)
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, scanLate, challengeVars, relayerVars>>

\* Action: the committee cancels an Initialized withdraw and refunds the lock (manual); the fix rejects it once the kickoff is provable.
\* Source: Gateway.sol committeeCancelWithdraw 475-489; crates/client/src/goat_chain/evmchain.rs:193 (no node caller)
CommitteeCancel ==
    /\ withdrawStatus = WdInitialized
    /\ ~(FixCancel /\ KickoffProvable)
    /\ withdrawStatus' = WdCanceled /\ cancelHappened' = TRUE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawPoisoned, syncVars,
                   scanLate, challengeVars, relayerVars, take1Done, take1Authorized>>

\* Action: the chain scan sees the kickoff and queues the challenge and proceed jobs, which inherit its lateness; skipped during a stall unless FixScan.
\* Source: node/src/aggregates/graph_scan.rs:131, 436-464 (scan_graphs_on_chain, stage_signals)
\* Source: node/src/aggregates/graph_pegout.rs:253-264 (route_signal)
ScanChain ==
    /\ ScanDue
    /\ challengeJob' = IF challengeJob = JobIdle THEN JobWaiting ELSE challengeJob
    /\ challengeWake' = IF challengeJob = JobIdle THEN btcTip ELSE challengeWake
    /\ challengeLate' = IF challengeJob = JobIdle THEN scanLate ELSE challengeLate
    /\ relayerJob' = IF relayerJob = JobIdle THEN JobWaiting ELSE relayerJob
    /\ relayerWake' = IF relayerJob = JobIdle THEN btcTip ELSE relayerWake
    /\ relayerLate' = IF relayerJob = JobIdle THEN scanLate ELSE relayerLate
    /\ scanLate' = 0
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, challengeOutcome, take1Done, take1Authorized>>

\* Action: the relayer's proceed job waits while the SPV lags the kickoff, then sends proceedWithdraw (Processing, or a revert that ends the job).
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1648-1694 (proceed_withdraw), 1612-1619 (withdraw_missing)
\* Source: Gateway.sol proceedWithdraw 492-521; node/src/aggregates/graph_jobs.rs:129-134 (revert = Permanent)
RelayerProceed ==
    /\ RelayerDue
    /\ CASE withdrawStatus = WdInitialized /\ spvHeight < kickoffHeight ->
                /\ relayerWake' = btcTip + Max(1, kickoffHeight - spvHeight) /\ relayerLate' = 0
                /\ UNCHANGED <<relayerJob, withdrawStatus>>
         [] withdrawStatus = WdInitialized ->
                /\ relayerJob' = JobDone
                /\ withdrawStatus' = IF ~withdrawPoisoned THEN WdProcessing ELSE withdrawStatus
                /\ UNCHANGED <<relayerWake, relayerLate>>
         [] withdrawStatus = WdNone ->
                /\ relayerWake' = btcTip + 1 /\ relayerLate' = 0
                /\ UNCHANGED <<relayerJob, withdrawStatus>>
         [] OTHER ->
                /\ relayerJob' = JobDone /\ UNCHANGED <<relayerWake, relayerLate, withdrawStatus>>
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawPoisoned, syncVars,
                   cancelHappened, scanLate, challengeVars, take1Done, take1Authorized>>

\* Action: after Take1 the relayer finalizes a Processing withdraw.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1715 (finish_happy); Gateway.sol _finalizeWithdraw 213
FinishHappy ==
    /\ take1Done /\ withdrawStatus = WdProcessing /\ withdrawStatus' = WdComplete
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawPoisoned, syncVars,
                   cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* ---- outcomes of one challenge-job look
SendChallenge ==
    /\ challengeJob' = JobDone
    /\ challengeOutcome' = IF btcTip + inclusion < kickoffHeight + connectorA
                           THEN ChInTime ELSE ChLate
    /\ UNCHANGED <<challengeWake, challengeLate>>

StopJob == challengeJob' = JobDone /\ UNCHANGED <<challengeWake, challengeLate, challengeOutcome>>

WaitBlocks(n) ==
    /\ challengeJob' = JobWaiting
    /\ challengeWake' = IF FixGate
                        THEN Min(btcTip + Max(1, n), FixWake)   \* design: never sleep past the wake
                        ELSE btcTip + Max(1, n)                 \* after_blocks: blocks.max(1)
    /\ challengeLate' = 0
    /\ UNCHANGED challengeOutcome

\* Blocks the SPV-lag after_blocks waits (kickoff_height - spv_height).
SpvWait == IF kickoffHeight >= spvHeight THEN kickoffHeight - spvHeight ELSE 0

\* Current gate (challenge_kickoff, graph_pegout_jobs.rs:595-647).
GateCurrent ==
    CASE take1Done \/ challengeOutcome = ChInTime                       -> StopJob
      [] withdrawStatus \in {WdNone, WdCanceled} /\ kickoffHeight >= spvHeight -> WaitBlocks(SpvWait)
      [] withdrawStatus \in {WdNone, WdCanceled}                        -> SendChallenge
      [] withdrawStatus = WdInitialized                                 -> WaitBlocks(1)
      [] OTHER                                                          -> StopJob

\* Fix design gate: contest unless the withdraw is Processing by FixWake.
Contest ==
    \/ withdrawStatus = WdInitialized /\ withdrawPoisoned           \* proceedWithdraw can never succeed
    \/ withdrawStatus \in {WdNone, WdCanceled} /\ spvHeight > kickoffHeight  \* current rule
    \/ btcTip >= FixWake                                            \* connector_a deadline, regardless of SPV

GateDesign ==
    CASE take1Done \/ challengeOutcome = ChInTime          -> StopJob
      [] withdrawStatus \in {WdProcessing, WdComplete}      -> StopJob
      [] Contest                                            -> SendChallenge
      [] withdrawStatus = WdInitialized                     -> WaitBlocks(1)
      [] OTHER                                              -> WaitBlocks(SpvWait)

\* Action: the challenge job looks (after the scan, then on each retry) and challenges, retries or stops, by GateCurrent or, with FixGate, GateDesign.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:595-647 (challenge_kickoff), 171-173 (after_blocks)
ChallengeLook ==
    /\ ChallengeDue
    /\ IF FixGate THEN GateDesign ELSE GateCurrent
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, scanLate, relayerVars, take1Done, take1Authorized>>

Next ==
    \/ MineBlock
    \/ SpvAdvance
    \/ SyncStallStart
    \/ SyncStallEnd
    \/ Kickoff
    \/ InitWithdraw
    \/ Take1
    \/ CommitteeCancel
    \/ ScanChain
    \/ RelayerProceed
    \/ FinishHappy
    \/ ChallengeLook

\* No fairness: every property is safety; honest timeliness is a guard on MineBlock.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* ==== Safety invariants

\* Take1 only while the pegBTC is burned or still burnable.
NoUnauthorizedTake1 == take1Done => take1Authorized

\* When Take1 pays out, the pegBTC is locked or burned, never refunded.
NoDoublePayment == take1Done => withdrawStatus \in {WdInitialized, WdProcessing, WdComplete}

\* Take1 only after the pegBTC is burned (fix configs only).
Take1OnlyAfterBurn == take1Done => withdrawStatus \in {WdProcessing, WdComplete}

\* A live withdraw that was never cancelled and is not poisoned.
HonestWithdraw ==
    /\ withdrawStatus \in {WdInitialized, WdProcessing, WdComplete}
    /\ ~withdrawPoisoned /\ ~cancelHappened
\* Cost check of the fix: an honest withdraw is never challenged.
NoHonestChallenge == challengeOutcome # ChNone => ~HonestWithdraw

\* ==== Safety properties (temporal)

\* No action changes the timing parameters.
ParamsFrozen == [][UNCHANGED params]_vars

\* Take1 and a sent Challenge are final.
OutcomesFinal ==
    [][/\ take1Done => take1Done'
       /\ challengeOutcome # ChNone => challengeOutcome' = challengeOutcome]_vars

\* ==== Liveness
\* None: which transaction wins connector_a is safety (bounded by Horizon).

=============================================================================
