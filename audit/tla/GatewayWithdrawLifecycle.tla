---- MODULE GatewayWithdrawLifecycle ----
(***************************************************************************)
(* L2 Gateway withdraw lifecycle of ONE peg-in instance with NGraphs        *)
(* operator graphs, plus the node relayer that mirrors Bitcoin facts onto   *)
(* the Gateway. Contract: localnet/contracts @ 3a679bf (the submodule pin   *)
(* of dev 60562f8), src/Gateway.sol. Node: node/src @ 60562f8.             *)
(*                                                                         *)
(* State machines (IGateway.sol:47-64):                                    *)
(*   pegin   Pending -> Withdrawable -> Locked -> Claimed                  *)
(*           (Gateway.sol:383 postPeginData, :443 initWithdraw,            *)
(*            :235 _finalizeWithdraw, :487 committeeCancelWithdraw)        *)
(*   ws[g]   None/Canceled -> Initialized (:451) -> Processing (:515)      *)
(*           -> Complete (:236) | Initialized -> Canceled (:485)           *)
(*           | anything-but-Disproved -> Disproved (:555-557, :638)        *)
(* Bitcoin is a nondeterministic environment: per graph the kickoff         *)
(* connector is "unspent", "kicked" (Kickoff confirmed) or "skipped"        *)
(* (consumed by ForceSkip etc.), and a kicked graph resolves to exactly     *)
(* ONE of Take1 / Take2 / Disprove. That exclusivity is real (goat          *)
(* bab46c2 transactions/): Take1 spends kickoff A,B,C,guardian + pegin      *)
(* connector_0 (take1.rs:70-83); Take2 spends connector_0, D, F, guardian   *)
(* (take2.rs:68-77); every disprove-type finish tx needs guardian           *)
(* (QuickChallenge / ChallengeIncompleteKickoff, prekickoff.rs:414,549),    *)
(* D (Disprove / PubinDisprove, assert.rs:324-327,577; D is an output of    *)
(* OperatorAssert, which spends C) or F/E/ack (NACK / CommitTimeout,        *)
(* watchtower_challenge.rs:551-554,722-725; outputs of WatchtowerChallenge- *)
(* Init, which spends B). So a Take and a disprove of the same graph can    *)
(* never both confirm; only one Take per instance (connector_0).           *)
(* A Take is only possible for a kickoff made while this graph's withdraw   *)
(* was Initialized/Processing (`auth`) and only while it is not Canceled:   *)
(* otherwise the verifier challenges (challenge_kickoff, graph_pegout_jobs. *)
(* rs:622-646, checked by VerifierKickoffFailOpen*.cfg) and we let that     *)
(* defense win - generous to the current code.                             *)
(*                                                                         *)
(* FINDINGS (each has its own *.cfg):                                       *)
(*                                                                         *)
(* H1  An operator who kicks off WITHOUT initWithdraw and is disproved is   *)
(*     never slashed. The contract explicitly accepts ws=None:              *)
(*        Gateway.sol:554  // Malicious operator may skip initWithdraw &   *)
(*        Gateway.sol:555  if (withdrawData.status == WithdrawStatus.Disproved) revert *)
(*     but the only caller, the relayer job, treats None as "lagging Goat": *)
(*        graph_pegout_jobs.rs:1799  WithdrawStatus::None => {             *)
(*        graph_pegout_jobs.rs:1800    return withdraw_missing(deps, graph_id, "finishWithdrawDisproved", attempts); *)
(*        graph_pegout_jobs.rs:1613  if attempts < WITHDRAW_LAG_RETRIES { (=30, :1604) *)
(*        graph_pegout_jobs.rs:1618  Step::ignore(... "skipped")  // job ends for good *)
(*     finishWithdrawDisproved is onlyCommittee (:550) and has no other     *)
(*     caller (grep gateway_finish_withdraw_disproved), so no slash, no     *)
(*     challenger reward. Second half: even if submitted, withdrawData of a *)
(*     never-initialised graph has instanceId 0 (:553), the WithdrawDisproved*)
(*     event carries it (:657-659), and the watcher drops it:               *)
(*        event_watch/gateway.rs:438  if !graph_belongs_to_instance(storage_processor, instance_id, graph_id).await? { continue; } *)
(*        event_watch/gateway.rs:336  Some(graph) if graph.instance_id == instance_id => Ok(true), *)
(*     -> GatewayWithdrawLifecycleH1.cfg (DisprovedOperatorSlashed),        *)
(*        GatewayWithdrawLifecycleH1Node.cfg (NodeTracksDisprove).          *)
(*                                                                         *)
(* M1  finishWithdrawDisproved never touches peginData (:638-668). If the   *)
(*     disproved graph held the lock (ws Initialized/Processing) the pegin  *)
(*     stays Locked; the only writes back to Withdrawable are :383 (from    *)
(*     Pending) and :487 (cancel, needs ws=Initialized of that graph) and   *)
(*     initWithdraw needs Withdrawable (:434) -> no other graph can ever    *)
(*     initWithdraw the instance (peg-in stranded). If disprove lands while *)
(*     Initialized, the lockAmount transferred at :447 is never burned nor  *)
(*     refunded (cancel needs Initialized, :482).                           *)
(*     -> GatewayWithdrawLifecycleM1.cfg (PegInRecoverable, liveness),      *)
(*        GatewayWithdrawLifecycleM1Escrow.cfg (EscrowAccounted).           *)
(*                                                                         *)
(* C5  committeeCancelWithdraw (:475-489) checks only ws=Initialized. The   *)
(*     digest is CANCEL_WITHDRAW(address contract, bytes16 graphId) (:46,   *)
(*     :166) + a free nonce (CommitteeManagement.sol:164-169, :277-280): it *)
(*     binds neither the withdraw attempt (initWithdraw re-opens a Canceled *)
(*     graph, :430) nor any Bitcoin state, has no expiry (cancelWithdraw-   *)
(*     Timelock :57 is only read by the commented-out cancelWithdraw :465), *)
(*     and anyone may submit it (no onlyCommittee). While proceedWithdraw   *)
(*     has not landed, a kickoff + Take1 can already be on Bitcoin (the     *)
(*     verifier stands down on Initialized, graph_pegout_jobs.rs:626-631);  *)
(*     a cancel then refunds the pegBTC (:486) although the peg-in BTC was  *)
(*     paid out. The node never sends this call (only the adaptor exists,   *)
(*     goat_adaptor.rs:1209; proceed_withdraw :1668-1671 "handled by        *)
(*     hand"), so this is a contract defense-in-depth gap gated on a        *)
(*     committee-signed cancel existing.                                    *)
(*     -> GatewayWithdrawLifecycleC5.cfg (NoDoublePayment),                 *)
(*        GatewayWithdrawLifecycleC5Stale.cfg (CancelBoundToAttempt).       *)
(*                                                                         *)
(* F4  initWithdraw (:428-457) is permissionless and records msg.sender as  *)
(*     operatorAddress (:450): anyone with pegBTC can lock the instance     *)
(*     through any posted graph. The node neither filters InitWithdraw by   *)
(*     sender (event_watch/gateway.rs:186-205) nor checks it before         *)
(*     kicking off (graph_pegout_jobs.rs:266-272 checks operator_pubkey and *)
(*     status only). -> GatewayWithdrawLifecycleF4.cfg (OnlyGraphOperatorLocks).*)
(*                                                                         *)
(* F9  NOT A BUG: finishWithdrawDisproved accepts Complete (:555) but a     *)
(*     Complete graph's Take and any disprove-type tx of the same graph     *)
(*     double-spend a connector (see above), so the state is unreachable;   *)
(*     None/Canceled MUST stay accepted (H1, kickoff after a cancel).       *)
(*     FixF9 (reject Complete only) is kept as harmless defense-in-depth.   *)
(*                                                                         *)
(* ECON  Stake is checked only at postGraphData (:406, lockedStake >=       *)
(*     minStakeAmount = 2*minSlashAmount, :83/:86) and never reserved per   *)
(*     graph, so one stake backs any number of posted graphs; the slash is  *)
(*     clamped to the remaining stake (:643-646) but minChallengerReward is *)
(*     paid in full (:648-652) out of the Gateway's pool of OTHER operators'*)
(*     slashes (StakeManagement.sol:55); with an empty pool the transfer    *)
(*     reverts the whole finishWithdrawDisproved. docs/incentives.md:91-100 *)
(*     relies on "at most two graphs" which nothing on L2 enforces.         *)
(*     -> GatewayWithdrawLifecycleEcon.cfg (RewardsCoveredBySlash).         *)
(*                                                                         *)
(* Units for ECON: 1 = 0.0025 stakeToken, so minStakeAmount 24, minSlash 12,*)
(* minChallengerReward 5 (Gateway.sol:83-86). The disprover reward (:85) is *)
(* only paid for QuickChallenge/ChallengeIncompleteKickoff and is left out. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    NGraphs,          \* graphs posted for the instance
    Actors,           \* GOAT accounts holding pegBTC ("op1","op2","mal")
    SharedOperator,   \* TRUE: every graph belongs to op1 (ECON)
    InitBal,          \* pegBTC per actor, in units of one lockAmount
    MaxAttempt,       \* bound on initWithdraw calls per graph
    MaxSigs,          \* bound on committee cancel signature sets per attempt
    MinStake, MinSlash, ChallengerReward,
    FixH1Relayer,     \* relayer submits finishWithdrawDisproved for ws=None
    FixH1Node,        \* watcher keys WithdrawDisproved by graph, not (instance, graph)
    FixM1,            \* disprove of the lock holder releases the pegin (+ escrow)
    FixC5,            \* cancel needs proof the kickoff can no longer happen + digest bound to attempt
    FixF4,            \* initWithdraw only from the graph's operator address
    FixF9,            \* finishWithdrawDisproved rejects Complete (defense in depth)
    FixEcon           \* per-graph stake reservation + rewards capped by the slash

Graphs   == 1..NGraphs
Owner(g) == IF SharedOperator \/ g = 1 THEN "op1" ELSE "op2"
Ops      == {Owner(g) : g \in Graphs}
Takes    == {"Take1", "Take2"}
Outcomes == Takes \cup {"Disprove"}
Live     == {"Initialized", "Processing"}
WStatus  == {"None", "Initialized", "Canceled", "Processing", "Complete", "Disproved"}
Nobody   == "nobody"

ASSUME Owner(1) \in Actors /\ Ops \subseteq Actors

VARIABLES
    pegin,       \* peginDataMap[instance].status
    posted,      \* postGraphData done for g
    ws,          \* withdrawDataMap[g].status
    locker,      \* withdrawDataMap[g].operatorAddress (msg.sender of initWithdraw)
    attempt,     \* number of initWithdraw calls on g (withdraw attempt id)
    wInst,       \* withdrawDataMap[g].instanceId != 0
    kst,         \* Bitcoin: g's kickoff connector "unspent" | "kicked" | "skipped"
    auth,        \* kickoff confirmed while ws[g] \in Live (verifier stands down)
    btc,         \* Bitcoin: "none" | Take1 | Take2 | Disprove for g
    takes,       \* peg-in BTC paid out on Bitcoin (connector_0 spent): 0..1
    relay,       \* finish_disproved job: "ready" | "gaveup"
    nodeRec,     \* node recorded the WithdrawDisproved event for g
    sigs,        \* sigs[g][k]: unused committee cancel signature sets made during attempt k
    staleCancel, \* some cancel executed with a signature made for an older attempt
    bal,         \* pegBTC balances
    escrow,      \* pegBTC held by the Gateway as lockAmount
    burned,      \* pegBTC burned by proceedWithdraw
    stake,       \* StakeManagement stakes (= lockedStakes in this model)
    reserved,    \* FixEcon: stake reserved for posted graphs
    pool,        \* Gateway stakeToken balance (slashes in, rewards out)
    slashed,     \* stake slashed by g's finishWithdrawDisproved
    paid         \* rewards paid by g's finishWithdrawDisproved

gvars  == <<posted, ws, locker, attempt, wInst>>
bvars  == <<kst, auth, btc, takes>>
nvars  == <<relay, nodeRec>>
cvars  == <<sigs, staleCancel>>
money  == <<bal, escrow, burned>>
econ   == <<stake, reserved, pool, slashed, paid>>
vars   == <<pegin, gvars, bvars, nvars, cvars, money, econ>>

RECURSIVE SumF(_, _)
SumF(f, S) == IF S = {} THEN 0
              ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumF(f, S \ {x})

TypeOK ==
    /\ pegin \in {"Pending", "Withdrawable", "Locked", "Claimed"}
    /\ posted \in [Graphs -> BOOLEAN]
    /\ ws \in [Graphs -> WStatus]
    /\ locker \in [Graphs -> Actors \cup {Nobody}]
    /\ attempt \in [Graphs -> 0..MaxAttempt]
    /\ wInst \in [Graphs -> BOOLEAN]
    /\ kst \in [Graphs -> {"unspent", "kicked", "skipped"}]
    /\ auth \in [Graphs -> BOOLEAN]
    /\ btc \in [Graphs -> Outcomes \cup {"none"}]
    /\ takes \in 0..1
    /\ relay \in [Graphs -> {"ready", "gaveup"}]
    /\ nodeRec \in [Graphs -> BOOLEAN]
    /\ sigs \in [Graphs -> [1..MaxAttempt -> 0..MaxSigs]]
    /\ staleCancel \in BOOLEAN
    /\ bal \in [Actors -> Nat]
    /\ escrow \in Nat /\ burned \in Nat
    /\ stake \in [Ops -> Nat] /\ reserved \in [Ops -> Nat] /\ pool \in Nat
    /\ slashed \in [Graphs -> Nat] /\ paid \in [Graphs -> Nat]

Init ==
    /\ pegin = "Pending"
    /\ posted = [g \in Graphs |-> FALSE]
    /\ ws = [g \in Graphs |-> "None"]
    /\ locker = [g \in Graphs |-> Nobody]
    /\ attempt = [g \in Graphs |-> 0]
    /\ wInst = [g \in Graphs |-> FALSE]
    /\ kst = [g \in Graphs |-> "unspent"]
    /\ auth = [g \in Graphs |-> FALSE]
    /\ btc = [g \in Graphs |-> "none"]
    /\ takes = 0
    /\ relay = [g \in Graphs |-> "ready"]
    /\ nodeRec = [g \in Graphs |-> FALSE]
    /\ sigs = [g \in Graphs |-> [k \in 1..MaxAttempt |-> 0]]
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

\* postPeginData (Gateway.sol:358-394): Pending -> Withdrawable (:383).
PostPeginData ==
    /\ pegin = "Pending"
    /\ pegin' = "Withdrawable"
    /\ UNCHANGED <<gvars, bvars, nvars, cvars, money, econ>>

\* postGraphData (:396-426). Current code: lockedStakeOf >= minStakeAmount
\* (:406) and nothing reserved. FixEcon: reserve minSlash per graph.
PostGraphData(g) ==
    LET o == Owner(g) IN
    /\ ~posted[g]
    /\ pegin # "Pending"                           \* peginTxid known (:417)
    /\ IF FixEcon THEN stake[o] - reserved[o] >= MinSlash
                  ELSE stake[o] >= MinStake
    /\ posted' = [posted EXCEPT ![g] = TRUE]
    /\ reserved' = IF FixEcon THEN [reserved EXCEPT ![o] = @ + MinSlash] ELSE reserved
    /\ UNCHANGED <<pegin, ws, locker, attempt, wInst, bvars, nvars, cvars, money,
                   stake, pool, slashed, paid>>

\* initWithdraw (:428-457): permissionless; msg.sender becomes operatorAddress.
InitWithdraw(a, g) ==
    /\ ws[g] \in {"None", "Canceled"}                    \* :430
    /\ pegin = "Withdrawable"                            \* :434
    /\ posted[g]                                         \* :438
    /\ bal[a] >= 1                                       \* transferFrom :447
    /\ attempt[g] < MaxAttempt
    /\ FixF4 => a = Owner(g)
    /\ pegin' = "Locked"                                 \* :443
    /\ bal' = [bal EXCEPT ![a] = @ - 1]
    /\ escrow' = escrow + 1
    /\ ws' = [ws EXCEPT ![g] = "Initialized"]            \* :451
    /\ locker' = [locker EXCEPT ![g] = a]                \* :450
    /\ wInst' = [wInst EXCEPT ![g] = TRUE]               \* :452
    /\ attempt' = [attempt EXCEPT ![g] = @ + 1]
    /\ UNCHANGED <<posted, bvars, nvars, cvars, burned, econ>>

\* The committee signs a cancel for g (off-chain, by hand: the node has no
\* caller). Abstracts "a valid committee-signed cancel exists"; it is a
\* bearer token with no expiry.
SignCancel(g) ==
    /\ ws[g] = "Initialized"
    /\ sigs[g][attempt[g]] < MaxSigs
    /\ sigs' = [sigs EXCEPT ![g][attempt[g]] = @ + 1]
    /\ UNCHANGED <<pegin, gvars, bvars, nvars, staleCancel, money, econ>>

\* committeeCancelWithdraw (:475-489), submitted by anyone with a signature
\* set made during attempt k. Current: only ws = Initialized (:482).
\* FixC5: digest bound to the attempt AND an SPV proof that g's kickoff
\* connector was consumed by a non-kickoff path (kickoff impossible).
SubmitCancel(g, k) ==
    /\ sigs[g][k] > 0
    /\ ws[g] = "Initialized"
    /\ FixC5 => (k = attempt[g] /\ kst[g] = "skipped")
    /\ sigs' = [sigs EXCEPT ![g][k] = @ - 1]             \* nonce consumed
    /\ staleCancel' = (staleCancel \/ k # attempt[g])
    /\ ws' = [ws EXCEPT ![g] = "Canceled"]               \* :485
    /\ bal' = [bal EXCEPT ![locker[g]] = @ + 1]          \* refund :486
    /\ escrow' = escrow - 1
    /\ pegin' = "Withdrawable"                           \* :487
    /\ UNCHANGED <<posted, locker, attempt, wInst, bvars, nvars, burned, econ>>

--------------------------------------------------------------------------
(* Bitcoin environment (no fairness except where stated)                   *)

Kickoff(g) ==
    /\ posted[g] /\ kst[g] = "unspent"
    /\ kst' = [kst EXCEPT ![g] = "kicked"]
    /\ auth' = [auth EXCEPT ![g] = ws[g] \in Live]
    /\ UNCHANGED <<pegin, gvars, btc, takes, nvars, cvars, money, econ>>

Skip(g) ==
    /\ posted[g] /\ kst[g] = "unspent"
    /\ kst' = [kst EXCEPT ![g] = "skipped"]
    /\ UNCHANGED <<pegin, gvars, auth, btc, takes, nvars, cvars, money, econ>>

\* A kicked graph ends in exactly one outcome (connector exclusivity).
\* Generous to the current code: a Take needs an authorized kickoff and a
\* withdraw that is not Canceled at that moment (on Canceled the verifier
\* challenges, graph_pegout_jobs.rs:623, and we let that defense win).
Resolve(g, o) ==
    /\ kst[g] = "kicked" /\ btc[g] = "none"
    /\ o \in Takes => (auth[g] /\ takes = 0 /\ ws[g] # "Canceled")
    /\ btc' = [btc EXCEPT ![g] = o]
    /\ takes' = IF o \in Takes THEN takes + 1 ELSE takes
    /\ UNCHANGED <<pegin, gvars, kst, auth, nvars, cvars, money, econ>>

--------------------------------------------------------------------------
(* Relayer (committee member) jobs                                         *)

\* proceed_withdraw (graph_pegout_jobs.rs:1648-1694) -> proceedWithdraw
\* (:492-521): burns the escrow (:518).
Proceed(g) ==
    /\ ws[g] = "Initialized" /\ kst[g] = "kicked"
    /\ ws' = [ws EXCEPT ![g] = "Processing"]
    /\ escrow' = escrow - 1
    /\ burned' = burned + 1
    /\ UNCHANGED <<pegin, posted, locker, attempt, wInst, bvars, nvars, cvars, bal, econ>>

\* finish_happy / finish_unhappy (:1715-1780) -> _finalizeWithdraw (:213-246).
FinishTake(g) ==
    /\ btc[g] \in Takes /\ ws[g] = "Processing"
    /\ ws' = [ws EXCEPT ![g] = "Complete"]
    /\ pegin' = "Claimed"
    /\ UNCHANGED <<posted, locker, attempt, wInst, bvars, nvars, cvars, money, econ>>

\* finishWithdrawDisproved (:542-669).
ContractDisproved(g) ==
    LET o      == Owner(g)
        slash  == IF stake[o] < MinSlash THEN stake[o] ELSE MinSlash   \* :643-645
        reward == IF FixEcon /\ slash < ChallengerReward THEN slash ELSE ChallengerReward
    IN
    /\ ws[g] # "Disproved"                                \* :555
    /\ FixF9 => ws[g] # "Complete"
    /\ pool + slash >= reward                             \* else :651 reverts everything
    /\ ws' = [ws EXCEPT ![g] = "Disproved"]               \* :638
    /\ stake' = [stake EXCEPT ![o] = @ - slash]           \* :646
    /\ reserved' = IF FixEcon
                     THEN [reserved EXCEPT ![o] = IF @ >= MinSlash THEN @ - MinSlash ELSE 0]
                     ELSE reserved
    /\ pool' = pool + slash - reward
    /\ slashed' = [slashed EXCEPT ![g] = slash]
    /\ paid' = [paid EXCEPT ![g] = reward]
    \* event instanceId = withdrawData.instanceId (:553,:658): 0 unless initialised
    /\ nodeRec' = [nodeRec EXCEPT ![g] = wInst[g] \/ FixH1Node]
    /\ IF FixM1 /\ ws[g] \in Live
         THEN /\ pegin' = "Withdrawable"
              /\ IF ws[g] = "Initialized"
                   THEN /\ escrow' = escrow - 1
                        /\ bal' = [bal EXCEPT ![locker[g]] = @ + 1]
                   ELSE UNCHANGED <<escrow, bal>>
         ELSE UNCHANGED <<pegin, escrow, bal>>            \* current: pegin untouched
    /\ UNCHANGED <<posted, locker, attempt, wInst, bvars, relay, cvars, burned>>

\* finish_disproved (:1783-1839), ws = None branch (:1799-1801): after
\* WITHDRAW_LAG_RETRIES the job is ignored for good (:1612-1619).
RelayGiveUp(g) ==
    /\ ~FixH1Relayer
    /\ btc[g] = "Disprove" /\ relay[g] = "ready" /\ ws[g] = "None"
    /\ relay' = [relay EXCEPT ![g] = "gaveup"]
    /\ UNCHANGED <<pegin, gvars, bvars, nodeRec, cvars, money, econ>>

RelaySubmit(g) ==
    /\ btc[g] = "Disprove" /\ relay[g] = "ready"
    /\ ws[g] = "None" => FixH1Relayer
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

Spec == Init /\ [][Next]_vars

\* Relayer jobs run; the Bitcoin game always ends; an Initialized operator
\* eventually kicks off or its slot is force-skipped; the committee
\* eventually signs and someone submits a pending cancel.
Fairness ==
    \A g \in Graphs :
        /\ WF_vars(Proceed(g))
        /\ WF_vars(FinishTake(g))
        /\ WF_vars(FinishDisproved(g))
        /\ WF_vars(\E o \in Outcomes : Resolve(g, o))
        /\ WF_vars(ws[g] = "Initialized" /\ (Kickoff(g) \/ Skip(g)))
        /\ WF_vars(SignCancel(g))
        /\ \A k \in 1..MaxAttempt : WF_vars(SubmitCancel(g, k))

FairSpec == Spec /\ Fairness

--------------------------------------------------------------------------
(* Properties                                                              *)

\* pegBTC is never created or destroyed except by burn.
Conservation == SumF(bal, Actors) + escrow + burned = InitBal * Cardinality(Actors)

\* C5: every peg-in BTC paid out on Bitcoin is matched by pegBTC taken out
\* of circulation (burned, or still escrowed). A refund after a Take pays
\* the same withdraw twice.
NoDoublePayment == takes <= burned + escrow

\* C5: a cancel only applies to the attempt the committee signed it for.
CancelBoundToAttempt == ~staleCancel

\* F4: only the graph's operator can lock the instance through its graph.
OnlyGraphOperatorLocks ==
    \A g \in Graphs : ws[g] \in Live \cup {"Complete"} => locker[g] = Owner(g)

\* M1: the Gateway holds exactly the lockAmounts of Initialized withdraws.
EscrowAccounted == escrow = Cardinality({g \in Graphs : ws[g] = "Initialized"})

\* M1 (safety form): a Locked instance always has a live lock holder.
LockHasHolder == pegin = "Locked" => \E g \in Graphs : ws[g] \in Live

\* H1 (node half): every on-chain Disproved is recorded by the node.
NodeTracksDisprove == \A g \in Graphs : ws[g] = "Disproved" => nodeRec[g]

\* ECON: a disprove never pays out more than it slashed from the operator.
RewardsCoveredBySlash == \A g \in Graphs : paid[g] <= slashed[g]

\* ECON: an operator's stake covers a full slash on every open posted graph.
StakeCoversExposure ==
    \A o \in Ops :
        stake[o] >= MinSlash * Cardinality({g \in Graphs :
                        posted[g] /\ Owner(g) = o /\ ws[g] # "Disproved"})

\* Sanity: a Withdrawable instance still has its BTC on Bitcoin.
PeginBacked == pegin = "Withdrawable" => takes = 0

\* H1: a disprove confirmed on Bitcoin is eventually executed on L2
\* (stake slashed, challenger rewarded).
DisprovedOperatorSlashed == \A g \in Graphs : (btc[g] = "Disprove") ~> (ws[g] = "Disproved")

\* M1: a Locked instance is eventually Claimed or Withdrawable again.
PegInRecoverable == (pegin = "Locked") ~> (pegin \in {"Withdrawable", "Claimed"})

====
