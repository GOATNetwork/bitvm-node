---- MODULE GatewayWithdrawLifecycle ----
(***************************************************************************)
(* Gateway withdraw lifecycle of one peg-in with NGraphs graphs            *)
(* (localnet/contracts src/Gateway.sol; ":NNN" = Gateway.sol line), the    *)
(* relayer jobs that mirror Bitcoin onto it                                *)
(* (node/src/aggregates/graph_pegout_jobs.rs) and the Gateway event        *)
(* watcher (node/src/scheduled_tasks/event_watch/gateway.rs). Bitcoin is   *)
(* the environment: a graph's kickoff connector is unspent, kicked or      *)
(* skipped; a kicked graph settles in exactly one of Take1/Take2/Disprove  *)
(* (goat bab46c2: any two double-spend a connector). A Take needs a        *)
(* kickoff made while the withdraw was live and not Canceled; otherwise    *)
(* challenge_kickoff wins (checked in ChallengeKickoffGate.tla).           *)
(* Findings (current code = every Fix* FALSE):                             *)
(*   H1 finish_disproved gives up on withdraw None: a disproved operator   *)
(*      that skipped initWithdraw is never slashed; its WithdrawDisproved  *)
(*      has instanceId 0 and the watcher drops it.                         *)
(*   M1 finishWithdrawDisproved leaves the pegin Locked and an Initialized *)
(*      escrow unrefunded.                                                 *)
(*   C5 committeeCancelWithdraw checks only Initialized and its digest     *)
(*      binds no attempt: a cancel after kickoff + Take1 refunds pegBTC;   *)
(*      an old signature cancels a re-init.                                *)
(*   F4 initWithdraw is permissionless.                                    *)
(*   Econ one stake backs any number of graphs; the challenger reward is   *)
(*      paid in full when the slash is clamped to 0.                       *)
(*   F9 (not a bug) a Complete graph cannot be disproved (connectors).     *)
(* Fixes: one Fix* constant each. No timing, so no ParamsOK.               *)
(* Exhaustiveness: each finding needs at most two graphs and one attacker; *)
(* two attempts expose a stale cancel; Econ needs three graphs on one      *)
(* stake (24 covers two slashes of 12, the third slashes 0).               *)
(* Configs: configs/contracts/GatewayWithdrawLifecycle/, tiers in          *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    NGraphs,          \* graphs posted for the instance
    Actors,           \* GOAT accounts holding pegBTC ("op1", "op2", "mal")
    SharedOperator,   \* TRUE: every graph belongs to op1 (Econ)
    InitBal,          \* pegBTC per actor, in lockAmounts
    MaxAttempt,       \* model bound on initWithdraw calls per graph
    MaxSigs,          \* model bound on committee cancel signature sets per attempt
    MinStake,         \* minStakeAmount (:83), unit 0.0025 stakeToken
    MinSlash,         \* minSlashAmount (:86), same unit
    ChallengerReward, \* minChallengerReward (:84), same unit
    FixH1Relayer,     \* fix: relayer submits finishWithdrawDisproved for withdraw None
    FixH1Node,        \* fix: watcher keys WithdrawDisproved by graph, not (instance, graph)
    FixM1,            \* fix: disprove of the lock holder reopens the pegin and refunds the escrow
    FixC5,            \* fix: cancel needs proof the kickoff is impossible, digest bound to the attempt
    FixF4,            \* fix: initWithdraw only from the graph's operator
    FixF9,            \* fix: finishWithdrawDisproved rejects Complete (defence in depth)
    FixEcon           \* fix: per-graph stake reservation, reward capped by the slash

Graphs   == 1..NGraphs
Owner(g) == IF SharedOperator \/ g = 1 THEN "op1" ELSE "op2"   \* graph g's operator
Ops      == {Owner(g) : g \in Graphs}
Nobody   == "nobody"                                           \* operatorAddress of a never-initialised withdraw

PeginStatuses    == {"Pending", "Withdrawable", "Locked", "Claimed"}           \* IGateway.sol:47-55 (subset)
WithdrawStatuses == {"None", "Initialized", "Canceled", "Processing", "Complete", "Disproved"}
Live             == {"Initialized", "Processing"}                              \* withdraw holds the pegin lock
KickoffStates    == {"unspent", "kicked", "skipped"}                           \* Bitcoin kickoff connector
Takes            == {"Take1", "Take2"}
Outcomes         == Takes \cup {"Disprove"}                                    \* how a kicked graph settles
NoOutcome        == "none"
RelayStates      == {"ready", "gaveup"}                                        \* relayer's finish_disproved job

ASSUME Owner(1) \in Actors /\ Ops \subseteq Actors

VARIABLES
    pegin,                \* peginDataMap[instance].status
    posted,               \* postGraphData done for g
    withdrawStatus,       \* withdrawDataMap[g].status
    withdrawOperator,     \* withdrawDataMap[g].operatorAddress (msg.sender of initWithdraw)
    withdrawAttempt,      \* initWithdraw calls on g so far (attempt id)
    withdrawHasInstance,  \* withdrawDataMap[g].instanceId != 0
    kickoffConn,          \* Bitcoin: g's kickoff connector, one of KickoffStates
    kickoffAuthorized,    \* kickoff confirmed while withdrawStatus[g] \in Live (verifier stands down)
    btcOutcome,           \* Bitcoin: NoOutcome or the Outcome that settled g
    peginPaidOut,         \* peg-in BTC paid out on Bitcoin (connector_0 spent by a Take): 0..1
    relayJob,             \* g's finish_disproved job, one of RelayStates
    nodeRecordedDisprove, \* node recorded the WithdrawDisproved event for g
    cancelSigs,           \* cancelSigs[g][k]: unused cancel signature sets made during attempt k
    staleCancel,          \* a cancel executed with a signature made for an older attempt
    bal,                  \* pegBTC balances
    escrow,               \* pegBTC held by the Gateway as lockAmount
    burned,               \* pegBTC burned by proceedWithdraw
    stake,                \* StakeManagement stake per operator (locked = total here)
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
\* Action: committee posts the peg-in; the instance becomes Withdrawable
\* (minted pegBTC is abstracted into InitBal).
\* Source: Gateway.sol postPeginData (358-394, status at 383)
PostPeginData ==
    /\ pegin = "Pending"
    /\ pegin' = "Withdrawable"
    /\ UNCHANGED <<graphVars, btcVars, nodeVars, cancelVars, money, econ>>

\* Action: committee posts graph g; needs locked stake >= minStakeAmount
\* (FixEcon: reserves minSlash of unreserved stake per graph).
\* Source: Gateway.sol postGraphData (396-426, stake check at 406)
PostGraphData(g) ==
    LET o == Owner(g) IN
    /\ ~posted[g]
    /\ pegin # "Pending"                           \* peginTxid known (:416-418)
    /\ IF FixEcon THEN stake[o] - reserved[o] >= MinSlash
                  ELSE stake[o] >= MinStake
    /\ posted' = [posted EXCEPT ![g] = TRUE]
    /\ reserved' = IF FixEcon THEN [reserved EXCEPT ![o] = @ + MinSlash] ELSE reserved
    /\ UNCHANGED <<pegin, withdrawStatus, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, money, stake, pool, slashed, paid>>

\* Action: any account a (F4) locks the instance through graph g, escrowing one
\* lockAmount; a becomes the withdraw's operatorAddress.
\* Source: Gateway.sol initWithdraw (428-457)
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

\* Action: committee signs off-chain a cancel for g's current attempt (a bearer
\* token with no expiry; the node never does this).
\* Source: environment (digest: Gateway.sol 165-171)
SignCancel(g) ==
    /\ withdrawStatus[g] = "Initialized"
    /\ cancelSigs[g][withdrawAttempt[g]] < MaxSigs
    /\ cancelSigs' = [cancelSigs EXCEPT ![g][withdrawAttempt[g]] = @ + 1]
    /\ UNCHANGED <<pegin, graphVars, btcVars, nodeVars, staleCancel, money, econ>>

\* Action: anyone submits a cancel signed during attempt k: withdraw Canceled,
\* escrow refunded, pegin Withdrawable. Code checks only Initialized (:482);
\* FixC5 also needs k current and g's kickoff connector skipped.
\* Source: Gateway.sol committeeCancelWithdraw (475-489); CommitteeManagement.sol:164-169 (nonce)
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
\* Action: g's Kickoff confirms (a malicious operator may kick off any time);
\* records whether the withdraw was live.
\* Source: Bitcoin consensus; honest operator node/src/aggregates/graph_pegout_jobs.rs:261-303
\*         (live check 243-255)
Kickoff(g) ==
    /\ posted[g] /\ kickoffConn[g] = "unspent"
    /\ kickoffConn' = [kickoffConn EXCEPT ![g] = "kicked"]
    /\ kickoffAuthorized' = [kickoffAuthorized EXCEPT ![g] = withdrawStatus[g] \in Live]
    /\ UNCHANGED <<pegin, graphVars, btcOutcome, peginPaidOut, nodeVars, cancelVars, money, econ>>

\* Action: g's kickoff connector is spent by a non-kickoff tx (e.g. ForceSkipKickoff).
\* Source: Bitcoin consensus
Skip(g) ==
    /\ posted[g] /\ kickoffConn[g] = "unspent"
    /\ kickoffConn' = [kickoffConn EXCEPT ![g] = "skipped"]
    /\ UNCHANGED <<pegin, graphVars, kickoffAuthorized, btcOutcome, peginPaidOut,
                   nodeVars, cancelVars, money, econ>>

\* Action: a kicked graph settles in one outcome; a Take pays the peg-in out
\* and needs an authorized kickoff and a withdraw not Canceled.
\* Source: Bitcoin consensus; verifier defence node/src/aggregates/graph_pegout_jobs.rs:595-647
\*         (challenges on None/Canceled at 622-623)
Resolve(g, o) ==
    /\ kickoffConn[g] = "kicked" /\ btcOutcome[g] = NoOutcome
    /\ o \in Takes => (kickoffAuthorized[g] /\ peginPaidOut = 0 /\ withdrawStatus[g] # "Canceled")
    /\ btcOutcome' = [btcOutcome EXCEPT ![g] = o]
    /\ peginPaidOut' = IF o \in Takes THEN peginPaidOut + 1 ELSE peginPaidOut
    /\ UNCHANGED <<pegin, graphVars, kickoffConn, kickoffAuthorized, nodeVars, cancelVars,
                   money, econ>>

--------------------------------------------------------------------------
\* Action: relayer posts the kickoff: withdraw Processing, escrow burned
\* (KickoffHeightLow, :502-504, not modelled: SPV lag lets any kickoff pass).
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1648-1694 (routed at graph_pegout.rs:263);
\*         Gateway.sol proceedWithdraw (492-521, burn at 518)
Proceed(g) ==
    /\ withdrawStatus[g] = "Initialized" /\ kickoffConn[g] = "kicked"
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Processing"]
    /\ escrow' = escrow - 1
    /\ burned' = burned + 1
    /\ UNCHANGED <<pegin, posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, bal, econ>>

\* Action: relayer posts the Take: withdraw Complete, pegin Claimed.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1715-1780 (routed at graph_pegout.rs:279,281);
\*         Gateway.sol _finalizeWithdraw (213-246)
FinishTake(g) ==
    /\ btcOutcome[g] \in Takes /\ withdrawStatus[g] = "Processing"
    /\ withdrawStatus' = [withdrawStatus EXCEPT ![g] = "Complete"]
    /\ pegin' = "Claimed"
    /\ UNCHANGED <<posted, withdrawOperator, withdrawAttempt, withdrawHasInstance,
                   btcVars, nodeVars, cancelVars, money, econ>>

\* Effect of finishWithdrawDisproved: withdraw Disproved, slash clamped to the
\* stake, full reward from the pool; the watcher records the event only if
\* withdrawData.instanceId is set (or FixH1Node).
\* Source: Gateway.sol finishWithdrawDisproved (542-669; slash 643-646, reward 648-652);
\*         node/src/scheduled_tasks/event_watch/gateway.rs:431-513 (instance check at 438, 336)
ContractDisproved(g) ==
    LET o      == Owner(g)
        slash  == IF stake[o] < MinSlash THEN stake[o] ELSE MinSlash   \* :643-645
        reward == IF FixEcon /\ slash < ChallengerReward THEN slash ELSE ChallengerReward
    IN
    /\ withdrawStatus[g] # "Disproved"                          \* :555
    /\ FixF9 => withdrawStatus[g] # "Complete"
    /\ pool + slash >= reward                                   \* else the transfer at :651 reverts
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

\* Action: relayer's finish_disproved sees withdraw None and gives up after
\* WITHDRAW_LAG_RETRIES = 30 runs (H1; not under FixH1Relayer).
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1783-1839 (None at 1799-1801), 1612-1619
\*         (routed at graph_pegout.rs:277)
RelayGiveUp(g) ==
    /\ ~FixH1Relayer
    /\ btcOutcome[g] = "Disprove" /\ relayJob[g] = "ready" /\ withdrawStatus[g] = "None"
    /\ relayJob' = [relayJob EXCEPT ![g] = "gaveup"]
    /\ UNCHANGED <<pegin, graphVars, btcVars, nodeRecordedDisprove, cancelVars, money, econ>>

\* Action: relayer submits finishWithdrawDisproved for any status but None
\* (None too under FixH1Relayer).
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1783-1839 (submit at 1824-1834)
RelaySubmit(g) ==
    /\ btcOutcome[g] = "Disprove" /\ relayJob[g] = "ready"
    /\ withdrawStatus[g] = "None" => FixH1Relayer
    /\ ContractDisproved(g)

\* The relayer's finish_disproved job for g.
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

\* For safety-only configs.
Spec == Init /\ [][Next]_vars

\* Weak fairness: relayer jobs (Proceed, FinishTake, FinishDisproved) retry every
\* block until they send or ignore; a kicked graph's Bitcoin game ends (CSV
\* timeouts); an Initialized graph is kicked off or force-skipped
\* (graph_pegout.rs:262); the committee eventually signs and someone submits a
\* cancel (most favourable for PegInRecoverable).
Fairness ==
    \A g \in Graphs :
        /\ WF_vars(Proceed(g))
        /\ WF_vars(FinishTake(g))
        /\ WF_vars(FinishDisproved(g))
        /\ WF_vars(\E o \in Outcomes : Resolve(g, o))
        /\ WF_vars(withdrawStatus[g] = "Initialized" /\ (Kickoff(g) \/ Skip(g)))
        /\ WF_vars(SignCancel(g))
        /\ \A k \in 1..MaxAttempt : WF_vars(SubmitCancel(g, k))

\* For configs that check liveness.
FairSpec == Spec /\ Fairness

--------------------------------------------------------------------------
\* pegBTC is never created or destroyed except by burn.
Conservation == SumF(bal, Actors) + escrow + burned = InitBal * Cardinality(Actors)

\* C5: peg-in BTC paid out is matched by pegBTC burned or escrowed (no refund after a Take).
NoDoublePayment == peginPaidOut <= burned + escrow

\* C5: a cancel applies only to the attempt it was signed for.
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

\* Econ: a disprove never pays more than it slashed.
RewardsCoveredBySlash == \A g \in Graphs : paid[g] <= slashed[g]

\* Econ: an operator's stake covers a full slash on every open posted graph.
StakeCoversExposure ==
    \A o \in Ops :
        stake[o] >= MinSlash * Cardinality({g \in Graphs :
                        posted[g] /\ Owner(g) = o /\ withdrawStatus[g] # "Disproved"})

\* A Withdrawable instance still has its BTC on Bitcoin.
PeginBacked == pegin = "Withdrawable" => peginPaidOut = 0

--------------------------------------------------------------------------
\* H1: a disprove confirmed on Bitcoin is eventually executed on the Gateway.
DisprovedOperatorSlashed ==
    \A g \in Graphs : (btcOutcome[g] = "Disprove") ~> (withdrawStatus[g] = "Disproved")

\* M1: a Locked instance is eventually Claimed or Withdrawable again.
PegInRecoverable == (pegin = "Locked") ~> (pegin \in {"Withdrawable", "Claimed"})

====
