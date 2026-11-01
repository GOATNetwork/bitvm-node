---- MODULE GatewayWithdrawLifecycle ----
(***************************************************************************)
(* Purpose: the L2 Gateway withdraw lifecycle of ONE peg-in instance with  *)
(* NGraphs operator graphs, plus the node relayer that mirrors Bitcoin     *)
(* facts onto the Gateway. Checks that peg-out money is conserved and paid *)
(* once, that a disproved operator is slashed, that a disprove cannot      *)
(* strand the instance, and that slashes cover rewards.                    *)
(*                                                                         *)
(* Code scope:                                                             *)
(*   contract: localnet/contracts @ 3a679bf (the submodule pin of dev      *)
(*     60562f8), src/Gateway.sol (and StakeManagement.sol,                 *)
(*     CommitteeManagement.sol). Bare ":NNN" below = Gateway.sol line.     *)
(*   node (dev 60562f8):                                                   *)
(*     node/src/aggregates/graph_pegout.rs:253-284 route_signal: the       *)
(*       relayer's jobs per Bitcoin signal (:263 KickoffSent ->            *)
(*       proceed_withdraw, :264 -> challenge_kickoff, :277 DisproveSent -> *)
(*       finish_disproved, :279/:281 Take1/Take2Sent -> finish_happy/      *)
(*       finish_unhappy).                                                  *)
(*     node/src/aggregates/graph_pegout_jobs.rs: the job bodies (cited per *)
(*       action as "jobs.rs:NNN").                                         *)
(*     node/src/scheduled_tasks/event_watch/gateway.rs: the Gateway event  *)
(*       watcher ("gateway.rs:NNN").                                       *)
(*   goat crate bab46c2 (Cargo.lock) for the Bitcoin connector exclusivity.*)
(*                                                                         *)
(* State machines (IGateway.sol:47-64):                                    *)
(*   pegin   Pending -> Withdrawable -> Locked -> Claimed                  *)
(*           (:383 postPeginData, :443 initWithdraw, :235                  *)
(*            _finalizeWithdraw, :487 committeeCancelWithdraw)             *)
(*   withdrawStatus[g]  None/Canceled -> Initialized (:451) -> Processing  *)
(*           (:515) -> Complete (:236) | Initialized -> Canceled (:485)    *)
(*           | anything-but-Disproved -> Disproved (:555-557, :638)        *)
(* Bitcoin is a nondeterministic environment: per graph the kickoff        *)
(* connector is "unspent", "kicked" (Kickoff confirmed) or "skipped"       *)
(* (consumed by ForceSkip etc.), and a kicked graph resolves to exactly    *)
(* ONE of Take1 / Take2 / Disprove. That exclusivity is real (goat         *)
(* bab46c2 transactions/): Take1 spends kickoff A,B,C,guardian + pegin     *)
(* connector_0 (take1.rs:70-83); Take2 spends connector_0, D, F, guardian  *)
(* (take2.rs:67-77); every disprove-type finish tx needs guardian          *)
(* (QuickChallenge / ChallengeIncompleteKickoff, prekickoff.rs:414,549),   *)
(* D (Disprove / PubinDisprove, assert.rs:323-327,575-577; D is an output  *)
(* of OperatorAssert, which spends C) or F/E/ack (NACK / CommitTimeout,    *)
(* watchtower_challenge.rs:550-554,721-725; outputs of WatchtowerChallenge-*)
(* Init, which spends B). So a Take and a disprove of the same graph can   *)
(* never both confirm; only one Take per instance (connector_0).           *)
(* A Take is only possible for a kickoff made while this graph's withdraw  *)
(* was Initialized/Processing (`kickoffAuthorized`) and only while it is   *)
(* not Canceled: otherwise the verifier challenges (challenge_kickoff,     *)
(* jobs.rs:594-647; it challenges on None/Canceled, :623, waits on         *)
(* Initialized, :626-631) and we let that defense win - generous to the    *)
(* current code. Whether that defense itself works is                      *)
(* ChallengeKickoffGate.tla's subject.                                     *)
(*                                                                         *)
(* FINDINGS (each has its own *.cfg):                                      *)
(*                                                                         *)
(* H1  An operator who kicks off WITHOUT initWithdraw and is disproved is  *)
(*     never slashed. The contract explicitly accepts withdraw None:       *)
(*        Gateway.sol:554  // Malicious operator may skip initWithdraw &   *)
(*        Gateway.sol:555  if (withdrawData.status == WithdrawStatus.Disproved) revert *)
(*     but the only caller, the relayer job, treats None as "lagging Goat":*)
(*        jobs.rs:1799  WithdrawStatus::None => {                          *)
(*        jobs.rs:1800    return withdraw_missing(deps, graph_id, "finishWithdrawDisproved", attempts); *)
(*        jobs.rs:1613  if attempts < WITHDRAW_LAG_RETRIES { (=30, :1604)  *)
(*        jobs.rs:1618  Step::ignore(... "skipped")  // job ends for good  *)
(*     finishWithdrawDisproved is onlyCommittee (:550) and has no other    *)
(*     caller (grep gateway_finish_withdraw_disproved), so no slash, no    *)
(*     challenger reward. Second half: even if submitted, withdrawData of a*)
(*     never-initialised graph has instanceId 0 (:553), the                *)
(*     WithdrawDisproved event carries it (:657-659), and the watcher      *)
(*     drops it:                                                           *)
(*        gateway.rs:438  if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? { continue; } *)
(*        gateway.rs:336  Some(graph) if graph.instance_id == instance_id => Ok(true), *)
(*     so the node records no WithdrawDisproved, no rewards, and the Graph *)
(*     aggregate never sees the Goat settlement (gateway.rs:465-507).      *)
(*     -> GatewayWithdrawLifecycle/H1.cfg (DisprovedOperatorSlashed),       *)
(*        GatewayWithdrawLifecycle/H1Node.cfg (NodeTracksDisprove).         *)
(*                                                                         *)
(* M1  finishWithdrawDisproved never touches peginData (:638-668). If the  *)
(*     disproved graph held the lock (Initialized/Processing) the pegin    *)
(*     stays Locked; the only writes back to Withdrawable are :383 (from   *)
(*     Pending) and :487 (cancel, needs that graph Initialized) and        *)
(*     initWithdraw needs Withdrawable (:434) -> no other graph can ever   *)
(*     initWithdraw the instance (peg-in stranded). If disprove lands while*)
(*     Initialized, the lockAmount transferred at :447 is never burned nor *)
(*     refunded (cancel needs Initialized, :482).                          *)
(*     -> GatewayWithdrawLifecycle/M1.cfg (PegInRecoverable, liveness),     *)
(*        GatewayWithdrawLifecycle/M1Escrow.cfg (EscrowAccounted).          *)
(*                                                                         *)
(* C5  committeeCancelWithdraw (:475-489) checks only Initialized. The     *)
(*     digest is CANCEL_WITHDRAW(address contract, bytes16 graphId) (:45,  *)
(*     :166) + a free nonce (CommitteeManagement.sol:164-169, :277-280):   *)
(*     it binds neither the withdraw attempt (initWithdraw re-opens a      *)
(*     Canceled graph, :430) nor any Bitcoin state, has no expiry          *)
(*     (cancelWithdrawTimelock :57 is only read by the commented-out       *)
(*     cancelWithdraw :465), and anyone may submit it (no onlyCommittee).  *)
(*     While proceedWithdraw has not landed, a kickoff + Take1 can already *)
(*     be on Bitcoin (the verifier stands down on Initialized,             *)
(*     jobs.rs:626-631); a cancel then refunds the pegBTC (:486) although  *)
(*     the peg-in BTC was paid out. The node never sends this call (only   *)
(*     the adaptor exists, crates/client/src/goat_chain/goat_adaptor.rs:   *)
(*     1209; proceed_withdraw jobs.rs:1668-1671 "handled by hand"), so     *)
(*     this is a contract defense-in-depth gap gated on a committee-signed *)
(*     cancel existing.                                                    *)
(*     -> GatewayWithdrawLifecycle/C5.cfg (NoDoublePayment),                *)
(*        GatewayWithdrawLifecycle/C5Stale.cfg (CancelBoundToAttempt).      *)
(*                                                                         *)
(* F4  initWithdraw (:428-457) is permissionless and records msg.sender as *)
(*     operatorAddress (:450): anyone with pegBTC can lock the instance    *)
(*     through any posted graph. The node neither filters InitWithdraw by  *)
(*     sender (gateway.rs:186-222) nor checks it before kicking off        *)
(*     (jobs.rs:266-272 checks operator_pubkey and, via                    *)
(*     step_unless_withdraw_live :243-255, the status only).               *)
(*     -> GatewayWithdrawLifecycle/F4.cfg (OnlyGraphOperatorLocks).         *)
(*                                                                         *)
(* F9  NOT A BUG: finishWithdrawDisproved accepts Complete (:555) but a    *)
(*     Complete graph's Take and any disprove-type tx of the same graph    *)
(*     double-spend a connector (see above), so the state is unreachable;  *)
(*     None/Canceled MUST stay accepted (H1, kickoff after a cancel).      *)
(*     FixF9 (reject Complete only) is kept as harmless defense-in-depth.  *)
(*                                                                         *)
(* ECON  Stake is checked only at postGraphData (:406, lockedStake >=      *)
(*     minStakeAmount = 2*minSlashAmount, :83/:86) and never reserved per  *)
(*     graph, so one stake backs any number of posted graphs; the slash is *)
(*     clamped to the remaining stake (:643-646) but minChallengerReward is*)
(*     paid in full (:648-652, whenever a ChallengeStart tx exists, always *)
(*     for the Disprove type) out of the Gateway's pool of OTHER           *)
(*     operators' slashes (StakeManagement.sol:55); with an empty pool the *)
(*     transfer reverts the whole finishWithdrawDisproved.                 *)
(*     docs/incentives.md:90-100 relies on "at most two graphs" which      *)
(*     nothing on L2 enforces.                                             *)
(*     -> GatewayWithdrawLifecycle/Econ.cfg (RewardsCoveredBySlash).        *)
(*                                                                         *)
(* Units for ECON: 1 = 0.0025 stakeToken, so minStakeAmount 24, minSlash   *)
(* 12, minChallengerReward 5 (Gateway.sol:83-86). The disprover reward     *)
(* (:85) is only paid for QuickChallenge/ChallengeIncompleteKickoff and is *)
(* left out.                                                               *)
(*                                                                         *)
(* Configs / tiers (Fix* constants select fix designs; all FALSE = the     *)
(* current code):                                                          *)
(*   live:   H1, H1Node, M1, M1Escrow, C5, C5Stale, F4, Econ               *)
(*   design: H1Fixed, M1Fixed, C5Fixed, F4Fixed, EconFixed, AllFixed       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    NGraphs,          \* graphs posted for the instance
    Actors,           \* GOAT accounts holding pegBTC ("op1","op2","mal")
    SharedOperator,   \* TRUE: every graph belongs to op1 (ECON)
    InitBal,          \* pegBTC per actor, in units of one lockAmount
    MaxAttempt,       \* bound on initWithdraw calls per graph
    MaxSigs,          \* bound on committee cancel signature sets per attempt
    MinStake,         \* minStakeAmount (:83), in ECON units
    MinSlash,         \* minSlashAmount (:86), in ECON units
    ChallengerReward, \* minChallengerReward (:84), in ECON units
    FixH1Relayer,     \* fix design: relayer submits finishWithdrawDisproved for withdraw None
    FixH1Node,        \* fix design: watcher keys WithdrawDisproved by graph, not (instance, graph)
    FixM1,            \* fix design: disprove of the lock holder releases the pegin (+ escrow)
    FixC5,            \* fix design: cancel needs proof the kickoff can no longer happen + digest bound to attempt
    FixF4,            \* fix design: initWithdraw only from the graph's operator address
    FixF9,            \* fix design: finishWithdrawDisproved rejects Complete (defense in depth)
    FixEcon           \* fix design: per-graph stake reservation + rewards capped by the slash

Graphs   == 1..NGraphs
Owner(g) == IF SharedOperator \/ g = 1 THEN "op1" ELSE "op2"   \* graph g's operator account
Ops      == {Owner(g) : g \in Graphs}
Nobody   == "nobody"                                           \* operatorAddress of a never-initialised withdraw

PeginStatuses    == {"Pending", "Withdrawable", "Locked", "Claimed"}           \* IGateway.PeginStatus (subset)
WithdrawStatuses == {"None", "Initialized", "Canceled", "Processing", "Complete", "Disproved"}
Live             == {"Initialized", "Processing"}                              \* withdraw holds the pegin lock
KickoffStates    == {"unspent", "kicked", "skipped"}                           \* Bitcoin kickoff connector
Takes            == {"Take1", "Take2"}
Outcomes         == Takes \cup {"Disprove"}                                    \* how a kicked graph settles
NoOutcome        == "none"
RelayStates      == {"ready", "gaveup"}                                        \* finish_disproved job

ASSUME Owner(1) \in Actors /\ Ops \subseteq Actors

VARIABLES
    pegin,                \* peginDataMap[instance].status
    posted,               \* postGraphData done for g
    withdrawStatus,       \* withdrawDataMap[g].status
    withdrawOperator,     \* withdrawDataMap[g].operatorAddress (msg.sender of initWithdraw)
    withdrawAttempt,      \* number of initWithdraw calls on g (withdraw attempt id)
    withdrawHasInstance,  \* withdrawDataMap[g].instanceId != 0
    kickoffConn,          \* Bitcoin: g's kickoff connector, one of KickoffStates
    kickoffAuthorized,    \* kickoff confirmed while withdrawStatus[g] \in Live (verifier stands down)
    btcOutcome,           \* Bitcoin: NoOutcome or the Outcome that settled g
    peginPaidOut,         \* peg-in BTC paid out on Bitcoin (connector_0 spent): 0..1
    relayJob,             \* g's finish_disproved job, one of RelayStates
    nodeRecordedDisprove, \* node recorded the WithdrawDisproved event for g
    cancelSigs,           \* cancelSigs[g][k]: unused committee cancel signature sets made during attempt k
    staleCancel,          \* some cancel executed with a signature made for an older attempt
    bal,                  \* pegBTC balances
    escrow,               \* pegBTC held by the Gateway as lockAmount
    burned,               \* pegBTC burned by proceedWithdraw
    stake,                \* StakeManagement stakes (= lockedStakes in this model)
    reserved,             \* FixEcon: stake reserved for posted graphs
    pool,                 \* Gateway stakeToken balance (slashes in, rewards out)
    slashed,              \* stake slashed by g's finishWithdrawDisproved
    paid                  \* rewards paid by g's finishWithdrawDisproved

graphVars  == <<posted, withdrawStatus, withdrawOperator, withdrawAttempt, withdrawHasInstance>>
btcVars    == <<kickoffConn, kickoffAuthorized, btcOutcome, peginPaidOut>>
nodeVars   == <<relayJob, nodeRecordedDisprove>>
cancelVars == <<cancelSigs, staleCancel>>
money      == <<bal, escrow, burned>>
econ       == <<stake, reserved, pool, slashed, paid>>
vars       == <<pegin, graphVars, btcVars, nodeVars, cancelVars, money, econ>>

RECURSIVE SumF(_, _)
SumF(f, S) == IF S = {} THEN 0
              ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumF(f, S \ {x})

TypeOk ==
    /\ pegin \in PeginStatuses
    /\ posted \in [Graphs -> BOOLEAN]
    /\ withdrawStatus \in [Graphs -> WithdrawStatuses]
    /\ withdrawOperator \in [Graphs -> Actors \cup {Nobody}]
    /\ withdrawAttempt \in [Graphs -> 0..MaxAttempt]
    /\ withdrawHasInstance \in [Graphs -> BOOLEAN]
    /\ kickoffConn \in [Graphs -> KickoffStates]
    /\ kickoffAuthorized \in [Graphs -> BOOLEAN]
    /\ btcOutcome \in [Graphs -> Outcomes \cup {NoOutcome}]
    /\ peginPaidOut \in 0..1
    /\ relayJob \in [Graphs -> RelayStates]
    /\ nodeRecordedDisprove \in [Graphs -> BOOLEAN]
    /\ cancelSigs \in [Graphs -> [1..MaxAttempt -> 0..MaxSigs]]
    /\ staleCancel \in BOOLEAN
    /\ bal \in [Actors -> Nat]
    /\ escrow \in Nat /\ burned \in Nat
    /\ stake \in [Ops -> Nat] /\ reserved \in [Ops -> Nat] /\ pool \in Nat
    /\ slashed \in [Graphs -> Nat] /\ paid \in [Graphs -> Nat]

Init ==
    /\ pegin = "Pending"
    /\ posted = [g \in Graphs |-> FALSE]
    /\ withdrawStatus = [g \in Graphs |-> "None"]
    /\ withdrawOperator = [g \in Graphs |-> Nobody]
    /\ withdrawAttempt = [g \in Graphs |-> 0]
    /\ withdrawHasInstance = [g \in Graphs |-> FALSE]
    /\ kickoffConn = [g \in Graphs |-> "unspent"]
    /\ kickoffAuthorized = [g \in Graphs |-> FALSE]
    /\ btcOutcome = [g \in Graphs |-> NoOutcome]
    /\ peginPaidOut = 0
    /\ relayJob = [g \in Graphs |-> "ready"]
    /\ nodeRecordedDisprove = [g \in Graphs |-> FALSE]
    /\ cancelSigs = [g \in Graphs |-> [k \in 1..MaxAttempt |-> 0]]
    /\ staleCancel = FALSE
    /\ bal = [a \in Actors |-> InitBal]
    /\ escrow = 0 /\ burned = 0
    /\ stake = [o \in Ops |-> MinStake]
    /\ reserved = [o \in Ops |-> 0]
    /\ pool = 0
    /\ slashed = [g \in Graphs |-> 0]
    /\ paid = [g \in Graphs |-> 0]

--------------------------------------------------------------------------
(* Gateway calls                                                           *)

\* Action: the committee posts the confirmed peg-in; the instance becomes
\* Withdrawable (the minted pegBTC is abstracted into InitBal).
\* Source: Gateway.sol postPeginData() :358-394 (Pending -> Withdrawable :383)
PostPeginData ==
    /\ pegin = "Pending"
    /\ pegin' = "Withdrawable"
    /\ UNCHANGED <<graphVars, btcVars, nodeVars, cancelVars, money, econ>>

\* Action: the committee posts graph g. Current code: the operator's locked
\* stake must be >= minStakeAmount, nothing is reserved per graph. FixEcon:
\* reserve minSlash per graph out of the unreserved stake.
\* Source: Gateway.sol postGraphData() :396-426 (stake :406, peginTxid :417)
PostGraphData(g) ==
    LET o == Owner(g) IN
    /\ ~posted[g]
    /\ pegin # "Pending"                           \* peginTxid known (:417)
    /\ IF FixEcon THEN stake[o] - reserved[o] >= MinSlash
                  ELSE stake[o] >= MinStake
    /\ posted' = [posted EXCEPT ![g] = TRUE]
    /\ reserved' = IF FixEcon THEN [reserved EXCEPT ![o] = @ + MinSlash] ELSE reserved
    /\ UNCHANGED <<pegin, withdrawStatus, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, money, stake, pool, slashed, paid>>

\* Action: account a locks the instance through graph g, escrowing one
\* lockAmount of pegBTC; msg.sender becomes the withdraw's operatorAddress.
\* Permissionless in the current code (F4).
\* Source: Gateway.sol initWithdraw() :428-457
InitWithdraw(a, g) ==
    /\ withdrawStatus[g] \in {"None", "Canceled"}                \* :430
    /\ pegin = "Withdrawable"                                    \* :434
    /\ posted[g]                                                 \* :438
    /\ bal[a] >= 1                                               \* transferFrom :447
    /\ withdrawAttempt[g] < MaxAttempt
    /\ FixF4 => a = Owner(g)
    /\ pegin' = "Locked"                                         \* :443
    /\ bal' = [bal EXCEPT ![a] = @ - 1]
    /\ escrow' = escrow + 1
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Initialized"]    \* :451
    /\ withdrawOperator' = [withdrawOperator EXCEPT ![g] = a]            \* :450
    /\ withdrawHasInstance' = [withdrawHasInstance EXCEPT ![g] = TRUE]   \* :452
    /\ withdrawAttempt' = [withdrawAttempt EXCEPT ![g] = @ + 1]
    /\ UNCHANGED <<posted, btcVars, nodeVars, cancelVars, burned, econ>>

\* Action: the committee signs a cancel for g during its current attempt.
\* Abstracts "a valid committee-signed cancel exists"; it is a bearer token
\* with no expiry.
\* Source: environment (off-chain, by hand: the node has no caller of
\*   gateway_cancel_withdraw); digest Gateway.sol :165-171.
SignCancel(g) ==
    /\ withdrawStatus[g] = "Initialized"
    /\ cancelSigs[g][withdrawAttempt[g]] < MaxSigs
    /\ cancelSigs' = [cancelSigs EXCEPT ![g][withdrawAttempt[g]] = @ + 1]
    /\ UNCHANGED <<pegin, graphVars, btcVars, nodeVars, staleCancel, money, econ>>

\* Action: anyone submits a signature set made during attempt k; the withdraw
\* is Canceled, the escrow refunded to its operatorAddress, the instance
\* Withdrawable again. Current code checks only Initialized (:482).
\* FixC5: digest bound to the attempt AND an SPV proof that g's kickoff
\* connector was consumed by a non-kickoff path (kickoff impossible).
\* Source: Gateway.sol committeeCancelWithdraw() :475-489 (nonce consumed by
\*   CommitteeManagement.sol _executeNoncedSignatures :164-169)
SubmitCancel(g, k) ==
    /\ cancelSigs[g][k] > 0
    /\ withdrawStatus[g] = "Initialized"
    /\ FixC5 => (k = withdrawAttempt[g] /\ kickoffConn[g] = "skipped")
    /\ cancelSigs' = [cancelSigs EXCEPT ![g][k] = @ - 1]          \* nonce consumed
    /\ staleCancel' = (staleCancel \/ k # withdrawAttempt[g])
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Canceled"]    \* :485
    /\ bal' = [bal EXCEPT ![withdrawOperator[g]] = @ + 1]             \* refund :486
    /\ escrow' = escrow - 1
    /\ pegin' = "Withdrawable"                                        \* :487
    /\ UNCHANGED <<posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, burned, econ>>

--------------------------------------------------------------------------
(* Bitcoin environment                                                     *)

\* Action: g's Kickoff confirms. Records whether the withdraw was live at that
\* moment (a later Take needs it). An honest operator only kicks off on
\* Initialized; a malicious one may kick off at any time.
\* Source: Bitcoin consensus; honest path kickoff() jobs.rs:261-300
\*   (step_unless_withdraw_live :243-255).
Kickoff(g) ==
    /\ posted[g] /\ kickoffConn[g] = "unspent"
    /\ kickoffConn' = [kickoffConn EXCEPT ![g] = "kicked"]
    /\ kickoffAuthorized' = [kickoffAuthorized EXCEPT ![g] = withdrawStatus[g] \in Live]
    /\ UNCHANGED <<pegin, graphVars, btcOutcome, peginPaidOut, nodeVars, cancelVars, money, econ>>

\* Action: g's kickoff connector is consumed by a non-kickoff path
\* (ForceSkipKickoff etc.); g can never kick off.
\* Source: Bitcoin consensus (goat prekickoff.rs:230 ForceSkipKickoffTransaction)
Skip(g) ==
    /\ posted[g] /\ kickoffConn[g] = "unspent"
    /\ kickoffConn' = [kickoffConn EXCEPT ![g] = "skipped"]
    /\ UNCHANGED <<pegin, graphVars, kickoffAuthorized, btcOutcome, peginPaidOut,
                   nodeVars, cancelVars, money, econ>>

\* Action: a kicked graph settles in exactly one outcome (connector
\* exclusivity, see header); a Take pays the peg-in BTC out. Generous to the
\* current code: a Take needs an authorized kickoff and a withdraw that is
\* not Canceled at that moment (otherwise the verifier challenges and we let
\* that defense win).
\* Source: Bitcoin consensus; verifier defense challenge_kickoff()
\*   jobs.rs:594-647 (:623 challenge on None/Canceled).
Resolve(g, o) ==
    /\ kickoffConn[g] = "kicked" /\ btcOutcome[g] = NoOutcome
    /\ o \in Takes => (kickoffAuthorized[g] /\ peginPaidOut = 0 /\ withdrawStatus[g] # "Canceled")
    /\ btcOutcome' = [btcOutcome EXCEPT ![g] = o]
    /\ peginPaidOut' = IF o \in Takes THEN peginPaidOut + 1 ELSE peginPaidOut
    /\ UNCHANGED <<pegin, graphVars, kickoffConn, kickoffAuthorized, nodeVars, cancelVars,
                   money, econ>>

--------------------------------------------------------------------------
(* Relayer (committee member) jobs and the Gateway calls they make         *)

\* Action: the relayer posts the confirmed kickoff; the withdraw becomes
\* Processing and the escrow is burned. The contract's KickoffHeightLow check
\* (:502-504, kickoff above the SPV height seen at initWithdraw) is not
\* modeled: SPV lag lets a pre-init kickoff pass it, so the model allows
\* proceed on any kicked graph (a superset).
\* Source: proceed_withdraw() jobs.rs:1648-1694 (routed graph_pegout.rs:263)
\*   -> Gateway.sol proceedWithdraw() :492-521 (burn :518)
Proceed(g) ==
    /\ withdrawStatus[g] = "Initialized" /\ kickoffConn[g] = "kicked"
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Processing"]
    /\ escrow' = escrow - 1
    /\ burned' = burned + 1
    /\ UNCHANGED <<pegin, posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, bal, econ>>

\* Action: the relayer posts the confirmed Take; withdraw Complete, pegin
\* Claimed.
\* Source: finish_happy()/finish_unhappy() jobs.rs:1715-1780 (routed
\*   graph_pegout.rs:279,281) -> Gateway.sol _finalizeWithdraw() :213-246
FinishTake(g) ==
    /\ btcOutcome[g] \in Takes /\ withdrawStatus[g] = "Processing"
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Complete"]
    /\ pegin' = "Claimed"
    /\ UNCHANGED <<posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, money, econ>>

\* Contract effect of finishWithdrawDisproved (used by RelaySubmit): withdraw
\* Disproved, operator slashed (clamped to its stake), challenger paid from
\* the Gateway pool; the WithdrawDisproved event carries withdrawData.
\* instanceId, which the node's watcher only accepts when it is set.
\* Source: Gateway.sol finishWithdrawDisproved() :542-669 (slash :643-646,
\*   reward :648-652, event :657-668); watcher
\*   handle_withdraw_disproved_events() gateway.rs:431-512 (:438).
ContractDisproved(g) ==
    LET o      == Owner(g)
        slash  == IF stake[o] < MinSlash THEN stake[o] ELSE MinSlash   \* :643-645
        reward == IF FixEcon /\ slash < ChallengerReward THEN slash ELSE ChallengerReward
    IN
    /\ withdrawStatus[g] # "Disproved"                          \* :555
    /\ FixF9 => withdrawStatus[g] # "Complete"
    /\ pool + slash >= reward                                   \* else :651 reverts everything
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Disproved"]   \* :638
    /\ stake' = [stake EXCEPT ![o] = @ - slash]                 \* :646
    /\ reserved' = IF FixEcon
                     THEN [reserved EXCEPT ![o] = IF @ >= MinSlash THEN @ - MinSlash ELSE 0]
                     ELSE reserved
    /\ pool' = pool + slash - reward
    /\ slashed' = [slashed EXCEPT ![g] = slash]
    /\ paid' = [paid EXCEPT ![g] = reward]
    \* event instanceId = withdrawData.instanceId (:553,:658): 0 unless initialised
    /\ nodeRecordedDisprove' = [nodeRecordedDisprove EXCEPT ![g] = withdrawHasInstance[g] \/ FixH1Node]
    /\ IF FixM1 /\ withdrawStatus[g] \in Live
         THEN /\ pegin' = "Withdrawable"
              /\ IF withdrawStatus[g] = "Initialized"
                   THEN /\ escrow' = escrow - 1
                        /\ bal' = [bal EXCEPT ![withdrawOperator[g]] = @ + 1]
                   ELSE UNCHANGED <<escrow, bal>>
         ELSE UNCHANGED <<pegin, escrow, bal>>                  \* current: pegin untouched
    /\ UNCHANGED <<posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, relayJob, cancelVars, burned>>

\* Action: the relayer's finish_disproved job sees withdraw None, waits
\* WITHDRAW_LAG_RETRIES runs for a "lagging" Goat node, then ignores the job
\* for good (H1). Not taken under FixH1Relayer.
\* Source: finish_disproved() jobs.rs:1783-1839, None branch :1799-1801
\*   -> withdraw_missing() :1612-1619 (routed graph_pegout.rs:277)
RelayGiveUp(g) ==
    /\ ~FixH1Relayer
    /\ btcOutcome[g] = "Disprove" /\ relayJob[g] = "ready" /\ withdrawStatus[g] = "None"
    /\ relayJob' = [relayJob EXCEPT ![g] = "gaveup"]
    /\ UNCHANGED <<pegin, graphVars, btcVars, nodeRecordedDisprove, cancelVars, money, econ>>

\* Action: the relayer's finish_disproved job submits finishWithdrawDisproved
\* for any status but None (Disproved is ignored, :1798); under
\* FixH1Relayer for None too.
\* Source: finish_disproved() jobs.rs:1783-1839 (submit :1824-1834)
RelaySubmit(g) ==
    /\ btcOutcome[g] = "Disprove" /\ relayJob[g] = "ready"
    /\ withdrawStatus[g] = "None" => FixH1Relayer
    /\ ContractDisproved(g)

FinishDisproved(g) == RelayGiveUp(g) \/ RelaySubmit(g)

--------------------------------------------------------------------------
Next ==
    \/ PostPeginData
    \/ \E g \in Graphs :
        \/ PostGraphData(g)
        \/ \E a \in Actors : InitWithdraw(a, g)
        \/ SignCancel(g)
        \/ \E k \in 1..MaxAttempt : SubmitCancel(g, k)
        \/ Kickoff(g) \/ Skip(g)
        \/ \E o \in Outcomes : Resolve(g, o)
        \/ Proceed(g) \/ FinishTake(g) \/ FinishDisproved(g)

\* Safety-only configs (live safety findings, Econ/F4/C5 designs).
Spec == Init /\ [][Next]_vars

\* Weak fairness, each justified by the code:
\*  - Proceed, FinishTake, FinishDisproved: relayer jobs are queued once per
\*    signal (graph_pegout.rs:263,277,279,281) and retried every block until
\*    they send or ignore (jobs.rs after_blocks); the relayer is honest.
\*  - Resolve: a kicked graph's Bitcoin game always ends (every branch has a
\*    CSV-bounded timeout tx, goat bab46c2 connectors/).
\*  - Kickoff or Skip of an Initialized graph: the operator kicks off
\*    (kickoff() jobs.rs:261) or verifiers force-skip its slot
\*    (enforce_previous_slot, graph_pegout.rs:262).
\*  - SignCancel / SubmitCancel: models "the committee eventually signs and
\*    someone submits a pending cancel" (by hand; no node caller) - the most
\*    favourable assumption for PegInRecoverable.
Fairness ==
    \A g \in Graphs :
        /\ WF_vars(Proceed(g))
        /\ WF_vars(FinishTake(g))
        /\ WF_vars(FinishDisproved(g))
        /\ WF_vars(\E o \in Outcomes : Resolve(g, o))
        /\ WF_vars(withdrawStatus[g] = "Initialized" /\ (Kickoff(g) \/ Skip(g)))
        /\ WF_vars(SignCancel(g))
        /\ \A k \in 1..MaxAttempt : WF_vars(SubmitCancel(g, k))

\* Liveness configs (H1, H1Fixed, M1, M1Fixed, AllFixed).
FairSpec == Spec /\ Fairness

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* pegBTC is never created or destroyed except by burn.
Conservation == SumF(bal, Actors) + escrow + burned = InitBal * Cardinality(Actors)

\* C5: every peg-in BTC paid out on Bitcoin is matched by pegBTC taken out
\* of circulation (burned, or still escrowed). A refund after a Take pays
\* the same withdraw twice.
NoDoublePayment == peginPaidOut <= burned + escrow

\* C5: a cancel only applies to the attempt the committee signed it for.
CancelBoundToAttempt == ~staleCancel

\* F4: only the graph's operator can lock the instance through its graph.
OnlyGraphOperatorLocks ==
    \A g \in Graphs : withdrawStatus[g] \in Live \cup {"Complete"} => withdrawOperator[g] = Owner(g)

\* M1: the Gateway holds exactly the lockAmounts of Initialized withdraws.
EscrowAccounted == escrow = Cardinality({g \in Graphs : withdrawStatus[g] = "Initialized"})

\* M1 (safety form): a Locked instance always has a live lock holder.
LockHasHolder == pegin = "Locked" => \E g \in Graphs : withdrawStatus[g] \in Live

\* H1 (node half): every on-chain Disproved is recorded by the node.
NodeTracksDisprove == \A g \in Graphs : withdrawStatus[g] = "Disproved" => nodeRecordedDisprove[g]

\* ECON: a disprove never pays out more than it slashed from the operator.
RewardsCoveredBySlash == \A g \in Graphs : paid[g] <= slashed[g]

\* ECON: an operator's stake covers a full slash on every open posted graph.
StakeCoversExposure ==
    \A o \in Ops :
        stake[o] >= MinSlash * Cardinality({g \in Graphs :
                        posted[g] /\ Owner(g) = o /\ withdrawStatus[g] # "Disproved"})

\* Sanity: a Withdrawable instance still has its BTC on Bitcoin.
PeginBacked == pegin = "Withdrawable" => peginPaidOut = 0

--------------------------------------------------------------------------
(* Liveness                                                                *)

\* H1: a disprove confirmed on Bitcoin is eventually executed on L2
\* (stake slashed, challenger rewarded).
DisprovedOperatorSlashed ==
    \A g \in Graphs : (btcOutcome[g] = "Disprove") ~> (withdrawStatus[g] = "Disproved")

\* M1: a Locked instance is eventually Claimed or Withdrawable again.
PegInRecoverable == (pegin = "Locked") ~> (pegin \in {"Withdrawable", "Claimed"})

====
