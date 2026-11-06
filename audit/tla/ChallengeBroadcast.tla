---- MODULE ChallengeBroadcast ----
(***************************************************************************)
(* When a challenger broadcasts the Challenge against a Kickoff, checked   *)
(* against the Take1 race on Connector-A (C4).                             *)
(*                                                                         *)
(* Connector-A is created by the Kickoff. Take1 spends its operator leaf   *)
(* after CSV(connector_a); Challenge spends its n-of-n leaf with no CSV    *)
(* and SINGLE|ANYONECANPAY, so a challenger can fund it as soon as it      *)
(* decides to. Whichever confirms first wins. TransactionGraph.tla checks  *)
(* connector_a against the action window; this model checks the           *)
(* challenger's decision and timing against it.                            *)
(*                                                                         *)
(* Ground truth: node/src/aggregates/graph_pegout_jobs.rs,                 *)
(* challenge_kickoff and kickoff_challenge_preflight. The challenger       *)
(* broadcasts once Kickoff is confirmed, Connector-A is unspent and the    *)
(* GOAT withdraw status is None or Canceled. Initialized retries next      *)
(* block (proceedWithdraw or a cancel decides it); Processing, Complete    *)
(* and Disproved are ignored; an unconfirmed Connector-A spend retries, a  *)
(* confirmed one ends the job. The GOAT SPV client is NOT consulted.       *)
(* Before the fix the broadcast also waited until the SPV tip was above    *)
(* the Kickoff block (an SPV error propagated and was retried), so a       *)
(* lagging or unavailable SPV let Take1 win; that gate is kept as          *)
(* gate = "Spv" (SpvGateSpec), which fails UnbackedKickoffChallenged. SPV  *)
(* evidence is still needed for the L2 settlement finishWithdrawDisproved  *)
(* (finish_disproved -> spv_covered: SPV tip >= evidence block); that is a *)
(* separate Settle step that never gates the Bitcoin Challenge. Its real   *)
(* evidence is the later challenge-finish transaction; the model uses the  *)
(* Challenge block as a stand-in, which only matters for when Settle can   *)
(* happen.                                                                 *)
(*                                                                         *)
(* Heights are relative to the Kickoff block (height 0). Take1 is valid    *)
(* from height connector_a; a Challenge wins only if it confirms strictly  *)
(* before that (a same-block tie goes to Take1). The challenger first      *)
(* looks within reaction_blocks - 1 blocks of the Kickoff (one block is    *)
(* needed to include anything), then every block (after_blocks(1)); a      *)
(* broadcast at tip p confirms in p + 1 .. p + 1 + inclusion_blocks. The   *)
(* SPV tip is environment and only matters through two monotone facts: it  *)
(* is above the Kickoff block (the pre-fix broadcast gate) and it covers   *)
(* the evidence block (settlement). Each may become true at any later      *)
(* block or never (a lag of any length, also longer than connector_a), and *)
(* the SPV query may fail in any block. connector_a is checked at the      *)
(* shipped value and at the smallest value validate_timelock_config        *)
(* accepts (the action window); the latter only on networks with a safety  *)
(* block, since regtest's minimum leaves a same-block tie.                 *)
(***************************************************************************)
EXTENDS Integers, ShippedTimelockValues

\* ProtocolTimingBudget in crates/bitvm-gc/src/timelocks.rs ("Testnet4"
\* covers Network::Testnet and Network::Testnet4, which share one budget).
ReactionBlocks  == [Bitcoin |-> 6, Testnet4 |-> 2, Signet |-> 1, Regtest |-> 1]
InclusionBlocks == [Bitcoin |-> 6, Testnet4 |-> 2, Signet |-> 1, Regtest |-> 0]
SafetyBlocks    == [Bitcoin |-> 6, Testnet4 |-> 2, Signet |-> 1, Regtest |-> 0]

Statuses == {"None", "Initialized", "Processing", "Canceled", "Complete", "Disproved"}
Unbacked == {"None", "Canceled"}           \* no live withdraw behind the Kickoff
Settled  == {"Processing", "Complete", "Disproved"}
NoHeight == -1

\* spvKick: SPV tip above the Kickoff block; spvEvid: SPV tip at or above
\* the evidence block; spvUp: the SPV query succeeds this block.
VARIABLES net, mode, gate, r, st0, status, h, spvKick, spvEvid, spvUp, polled, chal, chalAt, spent, settled
vars == <<net, mode, gate, r, st0, status, h, spvKick, spvEvid, spvUp, polled, chal, chalAt, spent, settled>>

CA == IF mode = "Shipped" THEN ConnectorA[net] ELSE ActionWindow[net]
Horizon == CA + 1

\* kickoff_challenge_preflight (gate "NoSpv") and its pre-fix version
\* (gate "Spv"). conn: Connector-A "Unspent" / "SpentUnconfirmed" /
\* "SpentConfirmed". sv: SPV view of the Kickoff block, "Covered" /
\* "Behind" / "Down" (query error: propagated, the job is retried).
Preflight(g, kc, conn, st, sv) ==
    IF ~kc THEN "Retry"
    ELSE IF conn = "SpentUnconfirmed" THEN "Retry"
    ELSE IF conn = "SpentConfirmed" THEN "Ignore"
    ELSE IF st = "Initialized" THEN "Retry"
    ELSE IF st \notin Unbacked THEN "Ignore"
    ELSE IF g = "NoSpv" \/ sv = "Covered" THEN "Broadcast"
    ELSE "Retry"

\* Pre-fix: waited while kickoff_height >= spv_height, i.e. needed the SPV
\* tip strictly above the Kickoff block.
SpvView == IF ~spvUp THEN "Down" ELSE IF spvKick THEN "Covered" ELSE "Behind"

InitWith(g) ==
    /\ gate = g
    /\ mode \in {"Shipped", "Minimal"}
    /\ net \in IF mode = "Minimal" THEN {n \in Networks : SafetyBlocks[n] > 0} ELSE Networks
    /\ r \in 0..(ReactionBlocks[net] - 1)
    /\ st0 \in Statuses
    /\ status = st0
    /\ h = 0
    /\ spvKick = FALSE         \* the SPV tip cannot be above the BTC tip
    /\ spvEvid = FALSE
    /\ spvUp \in BOOLEAN
    /\ polled = FALSE
    /\ chal = "Idle"
    /\ chalAt = NoHeight
    /\ spent = "None"
    /\ settled = FALSE

\* The challenger looks at every block from its first look on, until it
\* broadcast, dropped the graph, or Connector-A is spent.
PollDue == chal = "Idle" /\ spent = "None" /\ h >= r /\ ~polled

Poll ==
    /\ PollDue
    /\ polled' = TRUE
    /\ LET d == Preflight(gate, TRUE, "Unspent", status, SpvView) IN
         CASE d = "Broadcast" ->
                /\ chal' = "Sent"
                /\ chalAt' \in (h + 1)..(h + 1 + InclusionBlocks[net])
           [] d = "Ignore" -> chal' = "Dropped" /\ UNCHANGED chalAt
           [] OTHER -> UNCHANGED <<chal, chalAt>>
    /\ UNCHANGED <<net, mode, gate, r, st0, status, h, spvKick, spvEvid, spvUp, spent, settled>>

NextStatus(s) == IF s = "Initialized" THEN {"Initialized", "Processing", "Canceled"} ELSE {s}

\* One Bitcoin block. Take1 (the operator's, honest or not) is mined as soon
\* as its CSV allows; a Challenge mined at the same height loses.
Block ==
    /\ ~PollDue
    /\ h < Horizon
    /\ spent # "Take1"
    /\ ~settled
    /\ h' = h + 1
    /\ spent' = IF spent # "None" THEN spent
                ELSE IF chal = "Sent" /\ chalAt = h' /\ h' < CA THEN "Challenge"
                ELSE IF h' >= CA THEN "Take1"
                ELSE "None"
    /\ spvKick' \in IF spvKick THEN {TRUE} ELSE BOOLEAN
    /\ spvEvid' \in IF spvEvid THEN {TRUE}
                    ELSE IF spent' = "Challenge" /\ spvKick' THEN BOOLEAN ELSE {FALSE}
    /\ spvUp' \in BOOLEAN
    /\ status' \in NextStatus(status)
    /\ polled' = FALSE
    /\ UNCHANGED <<net, mode, gate, r, st0, chal, chalAt, settled>>

\* Relayer's finishWithdrawDisproved: needs the evidence block in GOAT SPV.
Settle ==
    /\ spent = "Challenge"
    /\ ~settled
    /\ spvUp /\ spvEvid
    /\ settled' = TRUE
    /\ UNCHANGED <<net, mode, gate, r, st0, status, h, spvKick, spvEvid, spvUp, polled, chal, chalAt, spent>>

Init == InitWith("NoSpv")
Next == Poll \/ Block \/ Settle
Spec == Init /\ [][Next]_vars
SpvGateSpec == InitWith("Spv") /\ [][Next]_vars

\* ---------------------------------------------------------------------
\* C4 invariants.

ConnStates == {"Unspent", "SpentUnconfirmed", "SpentConfirmed"}
SpvViews == {"Covered", "Behind", "Down"}

\* The two decision-table checks below read only gate, which never changes;
\* they are checked in the initial states (h = 0) to keep TLC fast.

\* The broadcast decision never reads the SPV client (nor any other GOAT
\* height): same answer whatever the SPV view.
ChallengeIgnoresSpv ==
    h = 0 => \A kc \in BOOLEAN, c \in ConnStates, s \in Statuses, v1, v2 \in SpvViews :
        Preflight(gate, kc, c, s, v1) = Preflight(gate, kc, c, s, v2)

\* Broadcast exactly when Kickoff is confirmed, Connector-A unspent and the
\* withdraw status None/Canceled; Initialized and pending spends retry;
\* Processing/Complete/Disproved and a confirmed spend end the job.
ChallengePreflightTable ==
    h = 0 => \A kc \in BOOLEAN, c \in ConnStates, s \in Statuses, v \in SpvViews :
        LET d == Preflight(gate, kc, c, s, v) IN
        /\ (d = "Broadcast") <=> (kc /\ c = "Unspent" /\ s \in Unbacked)
        /\ (~kc \/ c = "SpentUnconfirmed") => d = "Retry"
        /\ (kc /\ c = "SpentConfirmed") => d = "Ignore"
        /\ (kc /\ c = "Unspent" /\ s = "Initialized") => d = "Retry"
        /\ (kc /\ c = "Unspent" /\ s \in Settled) => d = "Ignore"

\* Main race property: a Kickoff with no live withdraw behind it is always
\* challenged before Take1 becomes valid, however far the SPV lags (also
\* past connector_a) and even if the SPV is down throughout.
UnbackedKickoffChallenged == st0 \in Unbacked => spent # "Take1"

\* No Challenge against a withdraw that is (or became) Processing etc.
ChallengeOnlyWhenUnbacked == chal = "Sent" => status \in Unbacked

\* Initialized is retried, never dropped.
DroppedOnlyWhenSettled == chal = "Dropped" => status \in Settled

\* L2 settlement still needs SPV evidence, and only follows a Challenge.
SettlementNeedsSpvEvidence == settled => (spent = "Challenge" /\ spvEvid)

====
