---------------------------- MODULE ChallengeKickoffGate ----------------------------
(***************************************************************************
PURPOSE
  The verifier's Challenge gate for a confirmed Kickoff: does an honest
  verifier always get a Challenge confirmed on connector_a before the
  operator's Take1 can spend it, whenever the operator's pegBTC is not burned
  (or still burnable) on GOAT? Successor of VerifierKickoffFailOpen.tla
  (#429), whose fix model ASSUMED the GOAT SPV covers the kickoff before
  connector_a expires; here heights are explicit and every timing number is a
  swept parameter.

CODE SCOPE (dev @ 60562f8, after #476; contracts = localnet/contracts @ 3a679bf)
  node/src/aggregates/graph_pegout_jobs.rs
    challenge_kickoff()   595-647  the gate (verifier role)
      622-634  status None|Canceled -> continue; Initialized -> after_blocks(1)
               ("waiting for proceedWithdraw or a cancel"); other -> ignore
      635-642  `if kickoff_height >= spv_height` -> after_blocks(kick - spv)
      644      send_challenge_tx
    after_blocks()        171-173  Step::retry(block_secs * blocks.max(1)):
                                   a retry, never consume-and-drop (#429 gone),
                                   but no bound by the connector_a deadline
    proceed_withdraw()    1648-1694 relayer: waits while spv < kickoff (1684),
                                   then gateway_process_withdraw (1691)
    withdraw_missing()    1612-1619 relayer retry while the withdraw is None
    finish_happy()        1715     relayer, after Take1
  node/src/aggregates/graph_jobs.rs 130-134  a reverted Goat call is
                                   FailureClass::Permanent -> job finished
  node/src/aggregates/graph_scan.rs scan_graphs_on_chain() 131,
    stage_signals() 436-445 -> KickoffSent; graph_pegout.rs route_signal()
    253, 263-264 -> JOB_PROCEED_WITHDRAW (relayer) / JOB_CHALLENGE_KICKOFF
  node/src/scheduled_tasks/mod.rs 229-255  the scan is skipped while
    is_processing_gateway_history_events() (event_watch/mod.rs 604-621) is
    true or errors (DeferredHistorySync / ...Unknown)
  node/src/scheduled_tasks/spv_maintenance_tasks.rs spv_header_hash_update()
    10-40: posts SPV headers up to btc_height - BTC_BLOCK_CONFIRMS (21)
  Gateway.sol: initWithdraw 428-457 (from None/Canceled, no kickoff check,
    454 btcBlockHeightAtWithdraw = bitcoinSPV.latestHeight());
    committeeCancelWithdraw 475-489 (only Initialized, refunds the lock; the
    node never sends it - gateway_cancel_withdraw, crates/client/src/
    goat_chain/evmchain.rs:193, has no caller); proceedWithdraw 492-521
    (503 KickoffHeightLow if btcBlockHeightAtWithdraw >= kickoff height,
    515 Processing + burn); _finalizeWithdraw 213 (needs Processing).
  Timing tables: ShippedTimelockValues.tla (generated from
    crates/bitvm-gc/src/timelocks.rs and crates/util/src/lib.rs 13-21).

FINDINGS
  C5  late initWithdraw: the operator kicks off with no withdraw, waits until
      spv >= kickoff height, then initWithdraw - proceedWithdraw reverts
      KickoffHeightLow forever; the gate checks the status FIRST and on
      Initialized waits forever; Take1 lands unchallenged; a manual cancel
      refunds the locked pegBTC. No timing margin closes it.
  C6  the gate sends only once spv > kickoff height, with no connector_a
      deadline. Current code is safe EXACTLY when C6Safe (below). Worst path:
      the relayer can proceed only at tip kickH+sc+lag+1 (+1 = the SPV post
      trailing its block) +r; until then a manual committee cancel can land
      just after a gate look on Initialized, whose next look is 1+r later, so
      the Challenge goes out at kickH+sc+lag+2+2r. Shipped: Testnet4 (6 vs
      10), Signet (6 vs 6), Regtest (2 vs 1) violate C6Safe with a healthy SPV
      (lag 0) even for an instant node (r 0, incl 1); Bitcoin (144 vs 6, r 6,
      incl 6) is safe for lag <= 117 and fails from lag 118 (~20 h outage).
  H4  a Goat history-sync stall covering the kickoff's confirmation means
      challenge_kickoff is never queued before Take1.
  FIX (design) poisoned Initialized is challenged; once the tip reaches
      kickH+ca-1-incl-r the gate contests regardless of SPV unless Processing,
      and its retries never sleep past that wake; the scan is not gated on the
      history sync; the contract rejects the cancel once the kickoff is
      provable. Safe EXACTLY when ParamsOK. Shipped: Bitcoin, Testnet4, Signet
      hold; Regtest fails (2 < 1+1+1 at r 1) - it needs connector_a >= 3.
      COST: it also challenges an HONEST withdraw whose proceedWithdraw cannot
      land before the wake; honest peg-outs go uncontested EXACTLY when
      ParamsLive - Bitcoin only (lag <= 117); on Testnet4, Signet, Regtest the
      fixed gate would challenge every peg-out unless connector_a is raised.

PARAMETERS (frozen variables, chosen once in Init, UNCHANGED by every action)
  connectorA   Take1's earliest block is kickoffHeight + connectorA.
  spvConfirms  BTC_BLOCK_CONFIRMS: spvHeight <= btcTip - spvConfirms.
  spvLag       extra SPV lag: spvHeight >= btcTip - spvConfirms - spvLag
               before each block (lag+1 transiently, between block and post).
  inclusion    a tx broadcast at tip t confirms at height <= t + inclusion
               (>= 1; shipped = max(1, InclusionBlocks), a fee target). The
               adversary picks the worst and a tie with Take1 goes to the
               operator: a Challenge wins iff t + inclusion < kickH + ca.
  reaction     every honest action (chain scan, due job look, relayer look)
               runs within `reaction` blocks of becoming due (0 = before the
               next block); the scan and the first challenge look share one
               window, since ReactionBlocks budgets discovery + scheduling +
               signing as a whole. EvidenceConfirmations is not read on this
               path (the scan treats a 1-conf kickoff as KickoffSent); a
               detection depth would only add to `reaction`.
  syncStall    longest Goat history-sync stall (one episode; 0 = none).
  Sweep mode (NetSet = {}): each from its CONSTANT range. Shipped mode:
  net \in NetSet, connectorA = ConnectorA[net], spvConfirms =
  BtcBlockConfirms[net], reaction/inclusion over 0..ReactionBlocks[net] /
  1..max(1, InclusionBlocks[net]) ("range") or exactly those budget values
  ("worst": how a fix computes its wake; reaction is an upper bound and a
  faster inclusion only helps the Challenge); lag and stall stay ranges.

WHY THE SWEEP RANGES ARE EXHAUSTIVE
  The model is shift-invariant in the tip (Kickoff may fire at every tip until
  every pre-kickoff spv offset, withdraw state and stall phase is reachable),
  and every guard compares sums of parameters with small constants (gate send
  spv > kickH; race t+incl < kickH+ca; fix wake kickH+ca-1-incl-r; relayer
  spv >= kickH; scan due at kickH, +stall). Every verdict is a threshold on
  ca - (linear form in sc, lag, incl, r); sc 1..3, lag 0..2, incl 1..2,
  r 0..2 with ca across each threshold realise every class (violated,
  margin 0, margin 1, margin >= 2). reaction, spvLag and syncStall are upper
  bounds, so larger values only add behaviours. C6Safe, ParamsOK and
  ParamsLive were also checked POINT BY POINT (one TLC run per tuple, 432 /
  432 / 264 tuples): each holds at every tuple inside and fails at every
  tuple outside, i.e. all three are exact on the grid. Shipped cfgs use the
  real values and do not rely on this argument.

ABSTRACTIONS
  One graph, one kickoff, an adversarial operator; time is the Bitcoin tip.
  The dispute game after an in-time Challenge is assumed sound (as in #429).
  Time stops once Take1 or an in-time Challenge has confirmed (no later step
  changes any property) or at Horizon. LazySpv (counterexample cfgs only):
  the SPV posts only when the lag bound forces it and the kickoff confirms at
  KickLatest - a subset of the behaviours, so a counterexample is genuine.

CONFIGS -> TIERS (checks.txt)
  live      C5, C6, C6Shipped (Testnet4/Signet/Regtest), C6Bitcoin, H4
  pass      C6Exact (current code verifies inside C6Safe), C6BitcoinHealthy
  design    Fixed, FixedShipped (Bitcoin/Testnet4/Signet), FixedHonest,
            FixedHonestBitcoin
  boundary  Boundary (~ParamsOK), FixedRegtest (shipped regtest outside
            ParamsOK), FixedHonestBoundary (~ParamsLive), FixedHonestShipped
            (Testnet4/Signet/Regtest outside ParamsLive)
***************************************************************************)
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
    Region,             \* parameter filter: "all" | "ok" | "notok" | "live" | "notlive" | "c6safe" | "c6unsafe"
    LazySpv,            \* TRUE: SPV posts only when forced, one kickoff tip (counterexample search only)
    EnableLateInit,     \* TRUE: initWithdraw may follow the kickoff (the contract allows it)
    FixGate,            \* design: challenge_kickoff challenges poisoned Initialized + connector_a wake
    FixScan,            \* design: scan_graphs_on_chain not gated on the history sync
    FixCancel           \* design: committeeCancelWithdraw rejected once the kickoff is provable

\* sc >= 1 makes a pre-kickoff initWithdraw record a height below the kickoff,
\* so btcBlockHeightAtWithdraw is abstracted to withdrawPoisoned.
ASSUME \A x \in SpvConfirmsRange : x >= 1
ASSUME \A n \in Networks : BtcBlockConfirms[n] >= 1
ASSUME \A x \in InclusionRange : x >= 1

\* Gateway WithdrawStatus values (Gateway.sol)
WdNone        == "None"
WdInitialized == "Initialized"
WdCanceled    == "Canceled"
WdProcessing  == "Processing"
WdComplete    == "Complete"
WdStates == {WdNone, WdInitialized, WdCanceled, WdProcessing, WdComplete}

\* Engine job states
JobIdle    == "Idle"
JobWaiting == "Waiting"
JobDone    == "Done"
JobStates == {JobIdle, JobWaiting, JobDone}

\* Challenge broadcast outcome
ChNone   == "No"
ChInTime == "InTime"
ChLate   == "Late"
ChOutcomes == {ChNone, ChInTime, ChLate}

VARIABLES
    net,                \* frozen: network whose shipped values are used ("sweep" in sweep mode)
    connectorA,         \* frozen: connector_a CSV (blocks)
    spvConfirms,        \* frozen: BTC_BLOCK_CONFIRMS
    spvLag,             \* frozen: bound on extra SPV lag
    inclusion,          \* frozen: blocks for a broadcast tx to confirm
    reaction,           \* frozen: honest reaction window (blocks)
    syncStall,          \* frozen: bound on the Goat history-sync stall
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
    challengeOutcome,   \* Challenge broadcast outcome
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
\* ---- parameter conditions
\* Design is safe: the Challenge confirms before Take1 whenever needed.
ParamsOK == connectorA >= reaction + inclusion + 1
\* Design leaves an honest withdraw unchallenged (proceedWithdraw lands first).
ParamsLive == connectorA >= spvConfirms + spvLag + 2 * reaction + inclusion + 3
\* Current code challenges in time whenever it must (no late init, no stall).
C6Safe == connectorA >= spvConfirms + spvLag + 2 * reaction + inclusion + 3

InRegion ==
    CASE Region = "all"      -> TRUE
      [] Region = "ok"       -> ParamsOK
      [] Region = "notok"    -> ~ParamsOK
      [] Region = "live"     -> ParamsOK /\ ParamsLive
      [] Region = "notlive"  -> ParamsOK /\ ~ParamsLive
      [] Region = "c6safe"   -> C6Safe
      [] Region = "c6unsafe" -> ~C6Safe

\* Latest kickoff tip: by then every spv offset, pre-kickoff withdraw state and
\* stall phase is reachable, so later kickoffs only shift explored states.
KickLatest == spvConfirms + spvLag + syncStall + 1
Horizon == KickLatest + Max(connectorA, spvConfirms + spvLag + 1) + 1

Kicked == kickoffHeight > 0
\* Last tip at which a broadcast Challenge still confirms before Take1 is valid.
Deadline == kickoffHeight + connectorA - 1 - inclusion
\* The design wakes `reaction` blocks earlier, so a late look still sends by Deadline.
FixWake == Deadline - reaction
\* proceedWithdraw would pass the KickoffHeightLow check (pegBTC still burnable).
Burnable == withdrawStatus = WdInitialized /\ ~withdrawPoisoned
\* The kickoff block is covered by the SPV, so a merkle proof of it exists.
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
\* ---- honest-node reaction windows
ScanGated   == ~FixScan /\ historySyncing
ScanDue     == Kicked /\ ~ScanGated /\ (challengeJob = JobIdle \/ relayerJob = JobIdle)
ChallengeDue == challengeJob = JobWaiting /\ btcTip >= challengeWake
RelayerDue  == relayerJob = JobWaiting /\ btcTip >= relayerWake

\* Action: a Bitcoin block is mined. Allowed only while the SPV lag and the
\* sync stall stay within their bounds and no honest action has used up its
\* reaction window - this is how honest timeliness is encoded (no fairness).
\* Time stops once Take1 or an in-time Challenge confirmed, or at Horizon.
\* Source: Bitcoin consensus (environment); reaction bound = ReactionBlocks in
\* protocol_timing_budget() crates/bitvm-gc/src/timelocks.rs:142
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

\* Action: the SPV updater posts one more header to GOAT, at most up to
\* tip - BTC_BLOCK_CONFIRMS (several steps in one tip model a batch).
\* Source: spv_header_hash_update() in node/src/scheduled_tasks/spv_maintenance_tasks.rs:10-40
SpvAdvance ==
    /\ spvHeight + 1 <= btcTip - spvConfirms
    /\ LazySpv => btcTip - spvConfirms - spvHeight > spvLag
    /\ spvHeight' = spvHeight + 1
    /\ UNCHANGED <<params, btcTip, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the local Gateway event watcher falls behind GOAT finality (one
\* stall episode); while it lasts the current code skips the chain scan.
\* Source: is_processing_gateway_history_events() in node/src/scheduled_tasks/event_watch/mod.rs:604-621
SyncStallStart ==
    /\ syncStall > 0 /\ ~historySyncing /\ ~stallUsed
    /\ historySyncing' = TRUE /\ syncStartTip' = btcTip /\ stallUsed' = TRUE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the history sync catches up; the scan runs again.
\* Source: is_processing_gateway_history_events() in node/src/scheduled_tasks/event_watch/mod.rs:604-621
SyncStallEnd ==
    /\ historySyncing /\ historySyncing' = FALSE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncStartTip, stallUsed, cancelHappened, scanLate, challengeVars,
                   relayerVars, take1Done, take1Authorized>>

\* Action: the (possibly adversarial) operator's Kickoff confirms at the tip,
\* creating connector_a: Take1 after connectorA blocks, Challenge any time.
\* Source: environment (operator); connector_a leaves in the goat crate
\* (connectors/connector_a.rs), CSV = timelock_config.connector_a
Kickoff ==
    /\ ~Kicked /\ btcTip >= 1 /\ btcTip <= KickLatest
    /\ LazySpv => btcTip = KickLatest
    /\ kickoffHeight' = btcTip
    /\ scanLate' = 0
    /\ UNCHANGED <<params, btcTip, spvHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* Action: the operator locks pegBTC for the withdraw; the contract records
\* the current SPV height, which poisons the withdraw if it already covers
\* the kickoff (proceedWithdraw will revert KickoffHeightLow).
\* Source: Gateway.sol initWithdraw() 428-457 (454 btcBlockHeightAtWithdraw)
InitWithdraw ==
    /\ withdrawStatus \in {WdNone, WdCanceled} /\ ~take1Done
    /\ EnableLateInit \/ ~Kicked
    /\ withdrawStatus' = WdInitialized
    /\ withdrawPoisoned' = (Kicked /\ spvHeight >= kickoffHeight)
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, syncVars, cancelHappened,
                   scanLate, challengeVars, relayerVars, take1Done, take1Authorized>>

\* Action: the operator's Take1 confirms once connector_a's CSV has elapsed
\* and no in-time Challenge took the connector; records whether the pegBTC
\* was burned or still burnable at that moment.
\* Source: Bitcoin consensus (connector_a CSV leaf; Take1 vs Challenge race)
Take1 ==
    /\ Kicked /\ ~take1Done /\ challengeOutcome # ChInTime
    /\ btcTip >= kickoffHeight + connectorA
    /\ take1Done' = TRUE
    /\ take1Authorized' = (withdrawStatus = WdProcessing \/ Burnable)
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawStatus, withdrawPoisoned,
                   syncVars, cancelHappened, scanLate, challengeVars, relayerVars>>

\* Action: the committee cancels an Initialized withdraw and refunds the lock
\* (manual; the node never sends it). The design rejects it once the kickoff
\* is provable through the SPV.
\* Source: Gateway.sol committeeCancelWithdraw() 475-489; caller-less
\* gateway_cancel_withdraw() in crates/client/src/goat_chain/evmchain.rs:193
CommitteeCancel ==
    /\ withdrawStatus = WdInitialized
    /\ ~(FixCancel /\ KickoffProvable)
    /\ withdrawStatus' = WdCanceled /\ cancelHappened' = TRUE
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawPoisoned, syncVars,
                   scanLate, challengeVars, relayerVars, take1Done, take1Authorized>>

\* Action: the chain scan sees the kickoff and emits KickoffSent, queueing
\* the verifier's challenge job and the relayer's proceed job. The jobs
\* inherit the scan's lateness (one reaction window). Skipped while the
\* history sync is in progress unless FixScan.
\* Source: scan_graphs_on_chain() in node/src/aggregates/graph_scan.rs:131,
\* stage_signals() 436-445; route_signal() in node/src/aggregates/graph_pegout.rs:253,263-264;
\* gated in node/src/scheduled_tasks/mod.rs:229-255
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

\* Action: the relayer's proceed job looks: waits after_blocks(kick - spv)
\* while the SPV does not cover the kickoff, then sends proceedWithdraw
\* (Processing + burn, or a KickoffHeightLow revert -> Permanent, job done);
\* retries while the withdraw is None; finishes on Canceled/Processing+.
\* Source: proceed_withdraw() in node/src/aggregates/graph_pegout_jobs.rs:1648-1694,
\* withdraw_missing() 1612-1619; Gateway.sol proceedWithdraw() 492-521;
\* FailureClass::Permanent in node/src/aggregates/graph_jobs.rs:130-134
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
\* Source: finish_happy() in node/src/aggregates/graph_pegout_jobs.rs:1715;
\* Gateway.sol _finalizeWithdraw() 213-236
FinishHappy ==
    /\ take1Done /\ withdrawStatus = WdProcessing /\ withdrawStatus' = WdComplete
    /\ UNCHANGED <<params, btcTip, spvHeight, kickoffHeight, withdrawPoisoned, syncVars,
                   cancelHappened, scanLate, challengeVars, relayerVars,
                   take1Done, take1Authorized>>

\* ---- the challenge job's step outcomes (sub-steps of ChallengeLook)
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

\* blocks argument of the SPV-lag after_blocks (kickoff_height - spv_height)
SpvWait == IF kickoffHeight >= spvHeight THEN kickoffHeight - spvHeight ELSE 0

\* CURRENT gate, challenge_kickoff() 595-647.
GateCurrent ==
    CASE take1Done \/ challengeOutcome = ChInTime                       -> StopJob
      [] withdrawStatus \in {WdNone, WdCanceled} /\ kickoffHeight >= spvHeight -> WaitBlocks(SpvWait)
      [] withdrawStatus \in {WdNone, WdCanceled}                        -> SendChallenge
      [] withdrawStatus = WdInitialized                                 -> WaitBlocks(1)
      [] OTHER                                                          -> StopJob

\* DESIGN gate: contest unless the withdraw is Processing by the wake.
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

\* Action: the verifier's challenge job looks (first look right after the
\* scan, then on each after_blocks retry): it challenges, retries later, or
\* stops - by the current gate, or by the design gate when FixGate.
\* Source: challenge_kickoff() in node/src/aggregates/graph_pegout_jobs.rs:595-647,
\* after_blocks() 171-173
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

\* No fairness: every property is safety. Honest timeliness is not a fairness
\* assumption but a guard on MineBlock (the reaction windows).
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* ==== Safety invariants

\* Take1 is only taken while the operator's pegBTC is burned (Processing) or
\* still burnable (Initialized, not poisoned) - the honest order whenever
\* Take1 (kickoff+ca) precedes SPV coverage (kickoff+sc).
NoUnauthorizedTake1 == take1Done => take1Authorized

\* Once Take1 pays out BTC, the operator's pegBTC is locked or burned, never
\* back with the operator (violated by Take1 against None or a cancel refund).
NoDoublePayment == take1Done => withdrawStatus \in {WdInitialized, WdProcessing, WdComplete}

\* Strict reading: Take1 only after the pegBTC is burned (design configs only;
\* where ca <= sc an honest Take1 precedes proceedWithdraw on current code).
Take1OnlyAfterBurn == take1Done => withdrawStatus \in {WdProcessing, WdComplete}

\* Cost of the design: an honest withdraw (never cancelled, not poisoned,
\* burnable or burned) is not challenged.
HonestWithdraw ==
    /\ withdrawStatus \in {WdInitialized, WdProcessing, WdComplete}
    /\ ~withdrawPoisoned /\ ~cancelHappened
NoHonestChallenge == challengeOutcome # ChNone => ~HonestWithdraw

\* ==== Safety properties (temporal)

\* The timing parameters are frozen: no action changes them.
ParamsFrozen == [][UNCHANGED params]_vars

\* Take1 and a broadcast Challenge are final: once on chain they stay.
OutcomesFinal ==
    [][/\ take1Done => take1Done'
       /\ challengeOutcome # ChNone => challengeOutcome' = challengeOutcome]_vars

\* ==== Liveness
\* None: the questions are about which transaction wins connector_a, which is
\* safety; the model is bounded by Horizon and has no fairness.

=============================================================================
