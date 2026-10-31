---- MODULE ChallengeKickoffGate ----
(***************************************************************************)
(* The verifier's Challenge gate for a confirmed Kickoff, as it stands on  *)
(* dev @ 60562f8 (after #476 moved the #429 logic out of handle.rs into an *)
(* engine job). Successor of VerifierKickoffFailOpen.tla (#429): that      *)
(* model's Fixed config ASSUMED GOAT SPV always covers the kickoff before  *)
(* connector_a expires (fairness). This module drops that assumption and   *)
(* models heights explicitly.                                              *)
(*                                                                         *)
(* THE GATE, node/src/aggregates/graph_pegout_jobs.rs challenge_kickoff:   *)
(*   595  async fn challenge_kickoff(deps, graph) -> Result<Step> {        *)
(*   599    let Some(kickoff_height) = btc.get_tx_status(..).block_height  *)
(*   605-621  connector already spent (confirmed) -> Step::ignore           *)
(*   622    match gateway_get_withdraw_data(&graph_id).status {             *)
(*   623      None | Canceled => {}                                         *)
(*   626      Initialized => return after_blocks(deps, "..waiting for       *)
(*   627-631                     proceedWithdraw or a cancel", 1),          *)
(*   633      other => return Step::ignore(..) }   // Processing/Complete   *)
(*   635    let spv_height = goat_client.btc_spv_latest_height() as u32;    *)
(*   636    if kickoff_height >= spv_height {                               *)
(*   637-641  return after_blocks(deps, "..not available through GOAT SPV",*)
(*                                 kickoff_height - spv_height) }           *)
(*   644    let txid = send_challenge_tx(btc, graph).await?;                *)
(* after_blocks (171-173) = Step::retry(block_secs * blocks.max(1)): a     *)
(* retry, so the job never consumes-and-drops (the #429 bug is gone), but  *)
(* nothing bounds the wait by the connector_a deadline.                    *)
(*                                                                         *)
(* CONTRACT (localnet/contracts/src/Gateway.sol):                          *)
(*   initWithdraw 428-457: allowed from None/Canceled, NO kickoff check,   *)
(*     454 btcBlockHeightAtWithdraw = bitcoinSPV.latestHeight();           *)
(*   committeeCancelWithdraw 475-489: only `status == Initialized` (482);  *)
(*     digest = (TYPEHASH, gateway, graphId) (165-167) - no kickoff check, *)
(*     refunds lockAmount to the operator (486).                           *)
(*   proceedWithdraw 492-521: 502 `if (btcBlockHeightAtWithdraw >=        *)
(*     kickoffProof.height) revert KickoffHeightLow();` then Processing +  *)
(*     burn (515-518). _finalizeWithdraw 224 requires Processing.          *)
(* Relayer proceed_withdraw (graph_pegout_jobs.rs 1648-1694) sends it once *)
(* SPV >= kickoff (1683-1690); a revert is FailureClass::Permanent ->      *)
(* "peg-out action rejected", job finished (graph_jobs.rs 130-134). The    *)
(* cancel is never sent by the node (gateway_cancel_withdraw has no caller;*)
(* 1669 "a cancelled withdraw is handled by hand").                        *)
(*                                                                         *)
(* SPV FEED (spv_maintenance_tasks.rs 14-21): the updater posts at most up *)
(* to btc_height - BTC_BLOCK_CONFIRMS; default confirms (crates/util/src/  *)
(* lib.rs 13-21) Bitcoin 6, Testnet4 10, Signet 6, Regtest 1. connector_a  *)
(* (crates/bitvm-gc/src/timelocks.rs 12/22/32/45): 144 / 6 / 6 / 2;        *)
(* validate_timelock_config only requires connector_a >= action_window     *)
(* (201-202, testnet 2+2+2 = 6), which ignores BTC_BLOCK_CONFIRMS.          *)
(*                                                                         *)
(* SIGNAL SOURCE: the KickoffSent signal that queues JOB_CHALLENGE_KICKOFF *)
(* (graph_pegout.rs 264) and JOB_PROCEED_WITHDRAW (263) comes only from    *)
(* scan_graphs_on_chain (graph_scan.rs 131-155, 443-445), which            *)
(* scheduled_tasks/mod.rs 229-255 skips while                              *)
(* is_processing_gateway_history_events (event_watch/mod.rs 604-621: the   *)
(* local Gateway event watcher is > gap behind GOAT finalized, or status   *)
(* Syncing) is true - or when that check errors (DeferredHistorySync-      *)
(* Unknown, 242). Jobs already queued keep running.                        *)
(*                                                                         *)
(* FINDINGS (cfgs):                                                        *)
(*  C5 (ChallengeKickoffGateC5.cfg): operator kicks off with no withdraw,  *)
(*     waits until SPV latestHeight >= kickoff height, then initWithdraw - *)
(*     btcBlockHeightAtWithdraw >= kickoff height, so proceedWithdraw      *)
(*     reverts KickoffHeightLow forever. The gate checks status FIRST and  *)
(*     on Initialized waits forever; Take1 lands unchallenged; a manual    *)
(*     committeeCancelWithdraw then refunds the locked pegBTC.             *)
(*  C6 (ChallengeKickoffGateC6.cfg): GOAT SPV lags (bounded, but >= the    *)
(*     connector_a window); the gate waits for SPV with no deadline.       *)
(*  C6 shipped (ChallengeKickoffGateC6Testnet4.cfg): with the real Testnet4*)
(*     values (confirms 10 > connector_a 6) the SPV can NEVER cover the    *)
(*     kickoff in time, even with zero extra lag.                          *)
(*  H4 (ChallengeKickoffGateH4.cfg): a Goat history-sync stall that covers *)
(*     the kickoff's confirmation means the job is never queued.           *)
(*  Fixed (ChallengeKickoffGateFixed.cfg): poisoned-Initialized challenged;*)
(*     deadline challenge regardless of SPV unless Processing; scan not    *)
(*     gated on the history sync; cancel rejected once kickoff provable.   *)
(*                                                                         *)
(* ABSTRACTIONS: one graph, one kickoff, an adversarial operator. Time is  *)
(* the Bitcoin tip `btc`. A Challenge broadcast at tip t confirms at       *)
(* t+Inclusion and wins connector_a iff t+Inclusion < kickH+ConnectorA     *)
(* (Take1's earliest block; a tie goes to the operator). The dispute game  *)
(* after a winning Challenge is assumed sound (as in #429's model). The    *)
(* honest challenger/relayer/scanner are TIMELY: a due job or scan runs    *)
(* before the next block (Tick guard) - generous to the current code. One  *)
(* sync stall episode; the SPV trails by at least SpvConfirms and at most  *)
(* SpvConfirms+MaxSpvLag(+1 transiently, between a block and its post).   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    ConnectorA,      \* Take1 CSV on connector_a, blocks (timelocks.rs)
    SpvConfirms,     \* BTC_BLOCK_CONFIRMS: SPV latestHeight <= btc - SpvConfirms
    MaxSpvLag,       \* extra SPV lag beyond SpvConfirms (environment, bounded)
    Inclusion,       \* blocks for a broadcast Challenge to confirm (>= 1)
    MaxSyncStall,    \* longest Goat history-sync stall, blocks (0 = none)
    EnableLateInit,  \* TRUE: initWithdraw is allowed after the kickoff (contract allows it)
    FixGate,         \* challenge_kickoff fix: poisoned-Initialized + connector_a deadline
    FixScan,         \* scan_graphs_on_chain not gated on the history sync
    FixCancel,       \* contract: cancel rejected once the kickoff is provable via SPV
    MaxH             \* model bound on the Bitcoin height

ASSUME ConnectorA >= 1 /\ Inclusion >= 1 /\ MaxH > SpvConfirms

WdStates == {"None", "Initialized", "Canceled", "Processing", "Complete"}
JobStates == {"Idle", "Waiting", "Done"}

VARIABLES
    btc,        \* Bitcoin tip height
    spv,        \* GOAT bitcoinSPV.latestHeight()
    kickH,      \* kickoff confirmation height, 0 = not broadcast
    wd,         \* Gateway withdrawDataMap[graphId].status
    wdH,        \* btcBlockHeightAtWithdraw
    sync,       \* Goat history sync "in progress" on the verifier/relayer nodes
    syncSince,  \* tip when the current stall began
    stallUsed,  \* the one modeled stall episode happened
    chJob,      \* JOB_CHALLENGE_KICKOFF
    chWake,     \* tip at which the challenge job's after_blocks retry is due
    chSent,     \* "No" | "InTime" | "Late" - Challenge broadcast outcome
    relJob,     \* JOB_PROCEED_WITHDRAW (relayer)
    take1,      \* operator's Take1 confirmed (connector_a taken uncontested)
    take1Auth   \* at Take1 time the withdraw was burned or still burnable

vars == <<btc, spv, kickH, wd, wdH, sync, syncSince, stallUsed,
          chJob, chWake, chSent, relJob, take1, take1Auth>>

Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

TypeOK ==
    /\ btc \in 0..MaxH /\ spv \in 0..MaxH /\ kickH \in 0..MaxH
    /\ wd \in WdStates /\ wdH \in 0..MaxH
    /\ sync \in BOOLEAN /\ syncSince \in 0..MaxH /\ stallUsed \in BOOLEAN
    /\ chJob \in JobStates /\ chWake \in Nat /\ chSent \in {"No", "InTime", "Late"}
    /\ relJob \in JobStates /\ take1 \in BOOLEAN /\ take1Auth \in BOOLEAN

Kicked == kickH > 0
\* Last tip at which a broadcast Challenge still confirms before Take1 is valid.
Deadline == kickH + ConnectorA - 1 - Inclusion
\* proceedWithdraw would pass the KickoffHeightLow check (pegBTC still burnable).
Burnable == wd = "Initialized" /\ wdH < kickH
\* The kickoff block is covered by the SPV, so a merkle proof of it exists.
KickoffProvable == Kicked /\ kickH <= spv

Init ==
    /\ btc = SpvConfirms /\ spv = 0 /\ kickH = 0
    /\ wd = "None" /\ wdH = 0
    /\ sync = FALSE /\ syncSince = 0 /\ stallUsed = FALSE
    /\ chJob = "Idle" /\ chWake = 0 /\ chSent = "No"
    /\ relJob = "Idle" /\ take1 = FALSE /\ take1Auth = FALSE

--------------------------------------------------------------------------
\* ---- honest-node timeliness (the "a due job runs before the next block" assumption)
ScanGated == ~FixScan /\ sync
ScanDue  == Kicked /\ ~ScanGated /\ (chJob = "Idle" \/ relJob = "Idle")
ChDue    == chJob = "Waiting" /\ btc >= chWake
RelDue   == relJob = "Waiting" /\
            (wd \in {"Canceled", "Processing", "Complete"} \/ (wd = "Initialized" /\ spv >= kickH))

\* ---- environment
Tick ==
    /\ btc < MaxH
    /\ btc - SpvConfirms - spv <= MaxSpvLag          \* SPV lag stays bounded
    /\ ~(sync /\ btc + 1 - syncSince > MaxSyncStall)  \* stall bounded
    /\ ~ScanDue /\ ~ChDue /\ ~RelDue
    /\ btc' = btc + 1
    /\ UNCHANGED <<spv, kickH, wd, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* spv_header_hash_update: posts up to btc_height - BTC_BLOCK_CONFIRMS.
SpvAdvance ==
    /\ spv + 1 <= btc - SpvConfirms
    /\ spv' = spv + 1
    /\ UNCHANGED <<btc, kickH, wd, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

SyncStart ==
    /\ MaxSyncStall > 0 /\ ~sync /\ ~stallUsed
    /\ sync' = TRUE /\ syncSince' = btc /\ stallUsed' = TRUE
    /\ UNCHANGED <<btc, spv, kickH, wd, wdH, chJob, chWake, chSent, relJob, take1, take1Auth>>

SyncEnd ==
    /\ sync /\ sync' = FALSE
    /\ UNCHANGED <<btc, spv, kickH, wd, wdH, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* ---- operator (possibly adversarial)
Kickoff ==
    /\ ~Kicked /\ btc >= 1
    /\ kickH' = btc
    /\ UNCHANGED <<btc, spv, wd, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* Gateway.initWithdraw: from None/Canceled, records SPV latestHeight (454).
InitWithdraw ==
    /\ wd \in {"None", "Canceled"} /\ ~take1
    /\ EnableLateInit \/ ~Kicked
    /\ wd' = "Initialized" /\ wdH' = spv
    /\ UNCHANGED <<btc, spv, kickH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* Take1: connector_a CSV elapsed, connector not taken by a Challenge.
Take1 ==
    /\ Kicked /\ ~take1 /\ chSent # "InTime"
    /\ btc >= kickH + ConnectorA
    /\ take1' = TRUE
    /\ take1Auth' = (wd = "Processing" \/ Burnable)
    /\ UNCHANGED <<btc, spv, kickH, wd, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob>>

\* ---- committee (manual) cancel: Gateway.committeeCancelWithdraw 475-489
CommitteeCancel ==
    /\ wd = "Initialized"
    /\ ~(FixCancel /\ KickoffProvable)
    /\ wd' = "Canceled"
    /\ UNCHANGED <<btc, spv, kickH, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* ---- scan_graphs_on_chain -> KickoffSent -> queue the role jobs
Scan ==
    /\ ScanDue
    /\ chJob' = IF chJob = "Idle" THEN "Waiting" ELSE chJob
    /\ chWake' = IF chJob = "Idle" THEN btc ELSE chWake
    /\ relJob' = IF relJob = "Idle" THEN "Waiting" ELSE relJob
    /\ UNCHANGED <<btc, spv, kickH, wd, wdH, sync, syncSince, stallUsed,
                   chSent, take1, take1Auth>>

\* ---- relayer proceed_withdraw (1648-1694) + finish_happy
RelayerStep ==
    /\ RelDue
    /\ relJob' = "Done"
    /\ wd' = IF wd = "Initialized" /\ wdH < kickH THEN "Processing" ELSE wd
        \* Initialized with wdH >= kickH: KickoffHeightLow revert -> Permanent, job done
    /\ UNCHANGED <<btc, spv, kickH, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, take1, take1Auth>>

FinishHappy ==
    /\ take1 /\ wd = "Processing" /\ wd' = "Complete"
    /\ UNCHANGED <<btc, spv, kickH, wdH, sync, syncSince, stallUsed,
                   chJob, chWake, chSent, relJob, take1, take1Auth>>

\* ---- the challenger job
SendChallenge ==
    /\ chJob' = "Done"
    /\ chSent' = IF btc + Inclusion < kickH + ConnectorA THEN "InTime" ELSE "Late"
    /\ UNCHANGED chWake

WaitBlocks(n) ==
    /\ chJob' = "Waiting"
    /\ chWake' = IF FixGate /\ btc < Deadline
                 THEN Min(btc + Max(1, n), Deadline)   \* fix: never sleep past the deadline
                 ELSE btc + Max(1, n)                  \* after_blocks: blocks.max(1)
    /\ UNCHANGED chSent

\* blocks argument of the SPV-lag after_blocks (kickoff_height - spv_height)
SpvWait == IF kickH >= spv THEN kickH - spv ELSE 0

\* CURRENT challenge_kickoff 595-647.
ChLookBuggy ==
    CASE take1 \/ chSent = "InTime"            -> chJob' = "Done" /\ UNCHANGED <<chWake, chSent>>
      [] wd \in {"None", "Canceled"} /\ kickH >= spv -> WaitBlocks(SpvWait)
      [] wd \in {"None", "Canceled"}            -> SendChallenge
      [] wd = "Initialized"                     -> WaitBlocks(1)
      [] OTHER                                  -> chJob' = "Done" /\ UNCHANGED <<chWake, chSent>>

\* FIXED gate: contest unless the withdraw is provably Processing by the deadline.
Contest ==
    \/ wd = "Initialized" /\ wdH >= kickH          \* poisoned: proceedWithdraw can never succeed
    \/ wd \in {"None", "Canceled"} /\ spv > kickH  \* current rule
    \/ btc >= Deadline                             \* connector_a deadline, regardless of SPV

ChLookFixed ==
    CASE take1 \/ chSent = "InTime"            -> chJob' = "Done" /\ UNCHANGED <<chWake, chSent>>
      [] wd \in {"Processing", "Complete"}      -> chJob' = "Done" /\ UNCHANGED <<chWake, chSent>>
      [] Contest                                -> SendChallenge
      [] wd = "Initialized"                     -> WaitBlocks(1)
      [] OTHER                                  -> WaitBlocks(SpvWait)

ChLook ==
    /\ ChDue
    /\ IF FixGate THEN ChLookFixed ELSE ChLookBuggy
    /\ UNCHANGED <<btc, spv, kickH, wd, wdH, sync, syncSince, stallUsed, relJob, take1, take1Auth>>

Next ==
    \/ Tick \/ SpvAdvance \/ SyncStart \/ SyncEnd
    \/ Kickoff \/ InitWithdraw \/ Take1 \/ CommitteeCancel
    \/ Scan \/ RelayerStep \/ FinishHappy \/ ChLook

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
\* Take1 is only taken while the operator's pegBTC is burned (Processing) or
\* still burnable (Initialized with btcBlockHeightAtWithdraw < kickoff height,
\* i.e. the relayer's proceedWithdraw can still succeed - the normal honest
\* order on Testnet4, where Take1 (kickoff+6) precedes SPV coverage (+10)).
NoUnauthorizedTake1 == take1 => take1Auth

\* Once BTC is paid out by Take1, the operator's pegBTC is not back in the
\* operator's hands: it is locked in the Gateway or burned. Violated by a
\* Take1 against None (never locked) or by a cancel refund after Take1.
NoDoublePayment == take1 => wd \in {"Initialized", "Processing", "Complete"}

\* Strict reading ("Take1 only after pegBTC burned"); holds under the fixed
\* gate (it contests unless Processing by the deadline). Not used for the bug
\* cfgs: with the Testnet4 values an honest Take1 (kickoff+6) precedes the
\* relayer's proceedWithdraw (needs SPV >= kickoff, i.e. tip >= kickoff+10),
\* so this reading would also flag honest withdrawals there.
Take1OnlyAfterBurn == take1 => wd \in {"Processing", "Complete"}

====
