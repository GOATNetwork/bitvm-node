---- MODULE DisputeObligations ----
(***************************************************************************)
(* After a Challenge: can the operator reach Take-2 with an invalid proof  *)
(*   or without committing its pubin, and does every honest watchtower's   *)
(*   challenge land? Chain (goat crate @ bab46c2): Take-2 needs ConnectorD *)
(*   (CSV cd from the Assert) and ConnectorF (CSV cf from WCI). Defenders  *)
(*   stop it with a NACK_i or Commit-Timeout on F, or a Disprove on D      *)
(*   after the verifier's ChallengeAssert. The operator alone sends the    *)
(*   Assert (any time), ACK_i (hashlock, before any challenge),            *)
(*   Commit-Pubin and WC-Timeout_i.                                        *)
(* Code: watchtower_flow (node/src/aggregates/graph_scan.rs:573-697),      *)
(*   verifier_assert (graph_pegout_jobs.rs:736-884), the AssertSent job    *)
(*   cancel (graph_pegout.rs:608-621).                                     *)
(* C1: a watchtower that never challenges and is never timed out keeps     *)
(*   all_resolved false: no NACK for it, no Commit-Timeout, and            *)
(*   verifier_assert waits for connector-E; an invalid proof reaches       *)
(*   Take-2. C1LateCommit and C1NoPubin isolate the connector-E gate and   *)
(*   the all_resolved gate.                                                *)
(* C2: an Assert before the watchtowers' proofs are ready cancels every    *)
(*   JOB_WATCHTOWER_CHALLENGE for good and silences every honest           *)
(*   watchtower.                                                           *)
(* Fix (design): FixCommitTimeout, FixNackAll, FixUngateAssert,            *)
(*   FixNoCancel (see CONSTANTS). Each property needs its flag; FixNackAll *)
(*   is defence in depth.                                                  *)
(* Parameters (record params): wc, ack, commit, cf = CSVs from WCI; cd     *)
(*   from the Assert; pc from the ChallengeAssert; wtp = watchtower proof  *)
(*   blocks; r = honest delay; sl = is_timelock_ready lag (1 as shipped).  *)
(* ParamsOK (exact; one conjunct per property):                            *)
(*    wc >= wtp + r + 2           (OnlineWatchtowerChallengeLands)         *)
(*    cf >= commit + sl + r + 1   (NoTake2WithoutPubin)                    *)
(*    cd >= 2r + pc + sl + 2      (NoTake2WithInvalidProof)                *)
(* Shipped values meet ParamsOK on Bitcoin and Testnet4, not on Signet     *)
(*   (wc) or Regtest (wc, cf, cd). validate_timelock_config                *)
(*   (crates/bitvm-gc/src/timelocks.rs:173-239) accepts tuples outside it. *)
(* Exhaustive (Fixed.cfg, every margin 0): wc, cf, cd appear only in       *)
(*   operator guards, so margin 0 dominates every larger margin; a larger  *)
(*   r only widens the honest landing window; ack and commit only time     *)
(*   defender actions; pc and sl enter only as pc + sl; the ranges cover   *)
(*   every order of cd vs cf and of 1 + wtp vs the WCI-rooted heights.     *)
(*   FixedBoundary.cfg: margin -1.                                         *)
(* Time: h is the block being built and nodes see h - 1; an honest action  *)
(*   due from block s lands in s..s+r (adversary's choice); WCI confirms   *)
(*   at 0; one honest verifier stands for the 1-of-M set; the operator's   *)
(*   pubin matches its Assert (a mismatch only adds a Pubin-Disprove).     *)
(* Configs: configs/node/aggregates/graph/DisputeObligations/, tiers in    *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC, ShippedTimelockValues

\* ---- model shape
CONSTANTS
    Watchtowers,      \* watchtower slots of the graph (outputs WC_i / Ack_i of WCI)
    Faulty,           \* watchtowers that may be offline or collude with the operator
    ProofValidity     \* operator's choices for the asserted proof: subset of BOOLEAN

\* ---- design switches (all FALSE = the current code)
CONSTANTS
    FixCommitTimeout, \* Commit-Timeout at operator_commit whatever the watchtower branches
    FixNackAll,       \* NACK every unspent Ack_i after operator_ack
    FixUngateAssert,  \* challenge an invalid proof at once; only "valid, skip" waits for commit-pubin
    FixNoCancel       \* AssertSent cancels neither the watchtower's challenge job nor its proof

\* ---- parameter source
CONSTANTS
    UseShipped,       \* TRUE: parameters from ShippedTimelockValues (NetSet)
    NetSet,           \* networks whose shipped values are explored
    ShippedDelay,     \* r for UseShipped: subset of {"action_window", "reaction_inclusion", "zero"}
    RepairTimelocks,  \* UseShipped: raise wc / cf / cd to the least values meeting ParamsOK
    WCRange,          \* swept CSV watchtower_challenge (from WCI)
    ACKRange,         \* swept CSV operator_ack (from WCI)
    COMMITRange,      \* swept CSV operator_commit (from WCI)
    CFRange,          \* swept CSV connector_f (from WCI)
    CDRange,          \* swept CSV connector_d (from the Assert)
    PCRange,          \* swept CSV prover_connector (from the ChallengeAssert)
    WtProofRange,     \* swept watchtower proof preparation blocks
    RRange,           \* swept honest delay
    ScanLagRange,     \* swept is_timelock_ready lag (1 as shipped, 0 = one block earlier)
    Region,           \* parameter region explored (see InRegion)
    UseValidator,     \* TRUE: the tuples validate_timelock_config accepts (ValidatorParams)
    ReactionRange,    \* swept budget reaction_blocks
    InclusionRange,   \* swept budget inclusion_blocks
    SafetyRange,      \* swept budget safety_blocks
    EvidenceRange,    \* swept budget evidence_confirmations
    SlackRange        \* UseValidator: extra blocks over each validator minimum

\* ---- exploration controls
CONSTANTS
    EveryCase,        \* run the parameter cases one after another (see NextCase)
    BugProp,          \* EveryCase: "invalid" | "nopubin" | "wtlands" | "any"
    CoarseTime,       \* Tick jumps to the next relevant height (restricts the adversary: failing cfgs only)
    AssertAtWCIOnly   \* the Assert only in WCI's block (restricts the adversary: failing cfgs only)

--------------------------------------------------------------------------
\* State names.
Unspent      == "open"        \* any connector / output still unspent
Challenged   == "chal"        \* WC_i: Watchtower-Challenge confirmed
TimedOut     == "tout"        \* WC_i / Ack_i: WC-Timeout; E / F: Commit-Timeout
Acked        == "ack"         \* Ack_i: operator's hashlock ACK
Nacked       == "nack"        \* Ack_i / F: Operator-Challenge-NACK
PubinCommitted == "pubin"     \* E: Operator-Commit-Pubin
Take2Spent   == "take2"       \* D / F: Take-2
Disproved    == "disprove"    \* D: Disprove
JobLive      == "live"        \* JOB_WATCHTOWER_CHALLENGE may still run
JobCancelled == "cancelled"   \* JOB_WATCHTOWER_CHALLENGE cancelled (terminal)

WCStates   == {Unspent, Challenged, TimedOut}
AckStates  == {Unspent, Acked, Nacked, TimedOut}
EStates    == {Unspent, PubinCommitted, TimedOut}
FStates    == {Unspent, Nacked, TimedOut, Take2Spent}
DStates    == {Unspent, Disproved, Take2Spent}
JobStates  == {JobLive, JobCancelled}

NONE == -1000000                  \* "no height yet"
WCI  == 0                         \* WCI confirmation height (see header)

Max2(a, b) == IF a >= b THEN a ELSE b

--------------------------------------------------------------------------
\* Parameters, margins and regions.

\* Margins of the fix design (ParamsOK = all >= 0). The watchtower challenge
\* lands by 1 + wtp + r and must precede the earliest WC-Timeout (wc).
MarginWt(q)       == q.wc - (q.wtp + q.r + 2)
\* Commit-Timeout lands by commit + sl + r; Take-2 can be in block cf.
MarginCommit(q)   == q.cf - (q.commit + q.sl + q.r + 1)
\* ChallengeAssert by Assert + 1 + r, Disprove by that + pc + sl + r; Take-2 can
\* be in block Assert + cd.
MarginDisprove(q) == q.cd - (2 * q.r + q.pc + q.sl + 2)
ParamsOK(q) == MarginWt(q) >= 0 /\ MarginCommit(q) >= 0 /\ MarginDisprove(q) >= 0
Margins(q)  == {MarginWt(q), MarginCommit(q), MarginDisprove(q)}

\* That margin exactly -1, the other two in Others.
BadWt(q, Others)       == MarginWt(q) = -1 /\ {MarginCommit(q), MarginDisprove(q)} \subseteq Others
BadCommit(q, Others)   == MarginCommit(q) = -1 /\ {MarginWt(q), MarginDisprove(q)} \subseteq Others
BadDisprove(q, Others) == MarginDisprove(q) = -1 /\ {MarginWt(q), MarginCommit(q)} \subseteq Others

\* Parameter points a config explores: "ok_edge" = every margin 0 or 1, "ok_zero"
\* = every margin 0, "boundary" = one margin -1 and the others 0, "bad_*" = that
\* margin -1 and the others 0 or 1.
InRegion(q) ==
    CASE Region = "all"          -> TRUE
      [] Region = "ok"           -> ParamsOK(q)
      [] Region = "notok"        -> ~ParamsOK(q)
      [] Region = "ok_edge"      -> Margins(q) \subseteq {0, 1}
      [] Region = "ok_zero"      -> Margins(q) = {0}
      [] Region = "boundary"     -> \/ BadWt(q, {0})
                                    \/ BadCommit(q, {0})
                                    \/ BadDisprove(q, {0})
      [] Region = "bad_wt"       -> BadWt(q, {0, 1})
      [] Region = "bad_commit"   -> BadCommit(q, {0, 1})
      [] Region = "bad_disprove" -> BadDisprove(q, {0, 1})

\* Plain sweep. Budget fields (rx reaction, inc inclusion, saf safety, ev
\* evidence) matter only for UseShipped / UseValidator.
SweptParams ==
    [net: {"swept"}, wc: WCRange, ack: ACKRange, commit: COMMITRange, cf: CFRange,
     cd: CDRange, pc: PCRange, wtp: WtProofRange, r: RRange, sl: ScanLagRange,
     rx: {0}, inc: {0}, saf: {0}, ev: {0}]

\* Honest delay r of a shipped network ("zero" is a subset of every larger r).
DelayOf(n, d) == CASE d = "action_window"      -> ActionWindow[n]
                   [] d = "reaction_inclusion" -> ReactionBlocks[n] + InclusionBlocks[n]
                   [] d = "zero"               -> 0

AsShipped(n, d) ==
    [net |-> n, wc |-> WatchtowerChallenge[n], ack |-> OperatorAck[n],
     commit |-> OperatorCommit[n], cf |-> ConnectorF[n], cd |-> ConnectorD[n],
     pc |-> ProverConnector[n], wtp |-> WatchtowerProofBlocks[n],
     r |-> DelayOf(n, d), sl |-> 1,
     rx |-> ReactionBlocks[n], inc |-> InclusionBlocks[n], saf |-> SafetyBlocks[n],
     ev |-> EvidenceConfirmations[n]]

\* validate_timelock_config (crates/bitvm-gc/src/timelocks.rs:173-239) for budget
\* q.rx / q.inc / q.saf / q.ev / q.wtp, without connector_a and connector_z.
\* ensure_gap_at_least (saturating_sub) always holds when req = 0.
ActionWindowOf(q)    == q.rx + q.inc + q.saf
ConfirmedWindowOf(q) == q.ev + q.inc + q.saf
GapOK(left, right, req) == req = 0 \/ right >= left + req
Validated(q) ==
    /\ \A v \in {q.wc, q.ack, q.commit, q.cf, q.cd, q.pc} : v >= q.rx
    /\ q.wc >= q.wtp + ActionWindowOf(q)
    /\ GapOK(q.wc, q.ack, ActionWindowOf(q))
    /\ GapOK(Max2(q.wc, q.ack), q.commit, ConfirmedWindowOf(q))
    /\ q.pc >= ActionWindowOf(q)
    /\ GapOK(q.pc, q.cd, ActionWindowOf(q))
    /\ GapOK(q.commit, q.cf, ConfirmedWindowOf(q))

\* Least value the validator accepts after `left` with gap req (>= reaction_blocks).
MinAfter(left, req, rx) == Max2(rx, IF req = 0 THEN 0 ELSE left + req)

\* Every tuple the validator accepts within SlackRange of its minimum, for every
\* budget in the ranges; r = action_window, sl = 1.
ValidatorParams ==
    {q \in
      {LET aw  == rx + inc + saf
           caw == ev + inc + saf
           wc0 == Max2(rx, wtp + aw) + s1
           ack0 == MinAfter(wc0, aw, rx) + s2
           cm0 == MinAfter(Max2(wc0, ack0), caw, rx) + s3
           pc0 == Max2(rx, aw) + s5
       IN [net |-> "validator", wc |-> wc0, ack |-> ack0, commit |-> cm0,
           cf |-> MinAfter(cm0, caw, rx) + s4, cd |-> MinAfter(pc0, aw, rx) + s6,
           pc |-> pc0, wtp |-> wtp, r |-> aw, sl |-> 1,
           rx |-> rx, inc |-> inc, saf |-> saf, ev |-> ev] :
         rx \in ReactionRange, inc \in InclusionRange, saf \in SafetyRange,
         ev \in EvidenceRange, wtp \in WtProofRange,
         s1 \in SlackRange, s2 \in SlackRange, s3 \in SlackRange,
         s4 \in SlackRange, s5 \in SlackRange, s6 \in SlackRange} :
     Validated(q)}

\* Least raise of wc / cf / cd that meets ParamsOK.
Repair(q) ==
    [q EXCEPT !.wc = Max2(@, q.wtp + q.r + 2),
              !.cf = Max2(@, q.commit + q.sl + q.r + 1),
              !.cd = Max2(@, 2 * q.r + q.pc + q.sl + 2)]

ShippedParams ==
    {IF RepairTimelocks THEN Repair(AsShipped(n, d)) ELSE AsShipped(n, d) :
        n \in NetSet, d \in ShippedDelay}

Params == {q \in (IF UseValidator THEN ValidatorParams
                  ELSE IF UseShipped THEN ShippedParams ELSE SweptParams) : InRegion(q)}

\* EveryCase: the parameter cases in a fixed (lexicographic) order.
NetIdx(n) == CASE n = "swept" -> 0 [] n = "Regtest" -> 1 [] n = "Signet" -> 2
               [] n = "Testnet4" -> 3 [] n = "Bitcoin" -> 4 [] n = "validator" -> 5
Tup(q) == <<NetIdx(q.net), q.r, q.sl, q.wtp, q.pc, q.commit, q.ack, q.wc, q.cf, q.cd,
            q.rx, q.inc, q.saf, q.ev>>
RECURSIVE LexLT(_, _, _)
LexLT(a, b, i) == /\ i <= 14
                  /\ \/ a[i] < b[i]
                     \/ a[i] = b[i] /\ LexLT(a, b, i + 1)
NCases == Cardinality(Params)
RankOf == [q \in Params |-> Cardinality({o \in Params : LexLT(Tup(o), Tup(q), 1)}) + 1]
Cases  == [i \in 1 .. NCases |-> CHOOSE q \in Params : RankOf[q] = i]

\* First height explored: an Assert this early already matures connector_d by cf.
Start(q) == -Max2(0, q.cd - q.cf)

--------------------------------------------------------------------------
VARIABLES
    params,     \* frozen parameters (chosen in Init; only NextCase changes them)
    casesDone,  \* EveryCase: number of cases already reproduced (0 otherwise)
    h,          \* height of the block being built
    proofValid, \* the operator's choice: is the asserted Groth16 proof valid?
    assertH,    \* height the operator's Assert confirmed, or NONE
    online,     \* honest, online watchtowers (Watchtowers minus a subset of Faulty)
    wc,         \* WC_i:  Unspent | Challenged | TimedOut
    ack,        \* Ack_i: Unspent | Acked | Nacked | TimedOut
    E,          \* connector E: Unspent | PubinCommitted | TimedOut
    eSeen,      \* the spend of connector E is in an earlier block (visible to nodes)
    F,          \* connector F: Unspent | Nacked | TimedOut | Take2Spent
    D,          \* connector D: Unspent | Disproved | Take2Spent
    vaH,        \* height the honest verifier's ChallengeAssert confirmed, or NONE
    answered,   \* operator answered the ChallengeAssert with Wrongly-Challenged
    job,        \* watchtower i's JOB_WATCHTOWER_CHALLENGE: JobLive | JobCancelled
    sinceChal,  \* per watchtower: first block the challenge guard held, or NONE
    sinceCancel,\* per watchtower: first block the job-cancel guard held, or NONE
    sinceNack,  \* per watchtower: first block the NACK guard held, or NONE
    sinceCT,    \* first block the Commit-Timeout guard held, or NONE
    sinceCA,    \* first block the ChallengeAssert guard held, or NONE
    sinceDP     \* first block the Disprove guard held, or NONE

vars == <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F, D,
          vaH, answered, job, sinceChal, sinceCancel, sinceNack, sinceCT, sinceCA,
          sinceDP>>

\* The frozen parameters under their protocol names.
WC      == params.wc       \* CSV watchtower_challenge
ACK     == params.ack      \* CSV operator_ack
COMMIT  == params.commit   \* CSV operator_commit
CF      == params.cf       \* CSV connector_f
CD      == params.cd       \* CSV connector_d
PC      == params.pc       \* CSV prover_connector
WtProof == params.wtp      \* watchtower proof preparation blocks
R       == params.r        \* honest delay
ScanLag == params.sl       \* is_timelock_ready lag

\* Latest Assert height explored: every WCI-rooted guard and deadline has passed,
\* so a later Assert is a time shift of this one.
AssertMax == Max2(Max2(Max2(WC, ACK + ScanLag + R), Max2(COMMIT + ScanLag + R, CF)),
                  WtProof + 1 + R) + 1
MaxH == AssertMax + CD

Heights == {NONE} \cup (Start(params) .. MaxH)

ParamFields == {"wc", "ack", "commit", "cf", "cd", "pc", "wtp", "r", "sl",
                "rx", "inc", "saf", "ev"}

\* params is typed field by field (membership in Params is slow); ParamsFrozen
\* checks it does not change within a case.
TypeOk ==
    /\ params.net \in Networks \cup {"swept", "validator"}
    /\ \A fld \in ParamFields : params[fld] \in Nat
    /\ casesDone \in Nat
    /\ h \in Start(params) .. MaxH
    /\ proofValid \in BOOLEAN
    /\ assertH \in Heights
    /\ online \subseteq Watchtowers
    /\ wc  \in [Watchtowers -> WCStates]
    /\ ack \in [Watchtowers -> AckStates]
    /\ E \in EStates
    /\ eSeen \in BOOLEAN
    /\ F \in FStates
    /\ D \in DStates
    /\ vaH \in Heights
    /\ answered \in BOOLEAN
    /\ job \in [Watchtowers -> JobStates]
    /\ sinceChal \in [Watchtowers -> Heights]
    /\ sinceCancel \in [Watchtowers -> Heights]
    /\ sinceNack \in [Watchtowers -> Heights]
    /\ {sinceCT, sinceCA, sinceDP} \subseteq Heights

--------------------------------------------------------------------------
\* Helpers.

\* An honest node sees a tx confirmed at c from block c + 1; is_timelock_ready
\* (graph_scan.rs:474) holds from block c + n + sl.
Seen(c)     == c # NONE /\ h >= c + 1
Ready(c, n) == c # NONE /\ h >= c + n + ScanLag

\* all_resolved (graph_scan.rs:617-671): each WC_i is timed out, or challenged
\* with Ack_i spent (by ACK or NACK).
AllResolved == \A i \in Watchtowers :
                  \/ wc[i] = TimedOut
                  \/ wc[i] = Challenged /\ ack[i] # Unspent

\* verifier_assert (graph_pegout_jobs.rs:766-866) sends a ChallengeAssert once
\* connector-E is spent and seen, after a Commit-Timeout or for an invalid proof.
\* Fix: an invalid proof at once.
WantsChallenge ==
    IF FixUngateAssert
    THEN ~proofValid \/ E = TimedOut
    ELSE eSeen /\ (~proofValid \/ E = TimedOut)

\* Guards of the honest actions (Fix* flags select the fix design).
GChal(i)   == /\ i \in online /\ wc[i] = Unspent /\ job[i] = JobLive
              /\ h >= WCI + 1 + WtProof
GCancel(i) == /\ ~FixNoCancel /\ i \in online /\ job[i] = JobLive /\ Seen(assertH)
GNack(i)   == /\ ack[i] = Unspent /\ F = Unspent /\ Ready(WCI, ACK)
              /\ (FixNackAll \/ wc[i] = Challenged)
GCT        == /\ E = Unspent /\ F = Unspent /\ Ready(WCI, COMMIT)
              /\ (FixCommitTimeout \/ AllResolved)
GCA        == /\ D = Unspent /\ vaH = NONE /\ Seen(assertH) /\ WantsChallenge
GDP        == /\ D = Unspent /\ ~answered /\ Ready(vaH, PC)

\* First block an obligation's guard held, after a step (gNext = guard in the new state).
Since(gNext, s) == IF gNext THEN (IF s = NONE THEN h' ELSE s) ELSE NONE

\* Recompute every obligation's start after a step.
UpdateSince ==
    /\ sinceChal'   = [i \in Watchtowers |-> Since((GChal(i))', sinceChal[i])]
    /\ sinceCancel' = [i \in Watchtowers |-> Since((GCancel(i))', sinceCancel[i])]
    /\ sinceNack'   = [i \in Watchtowers |-> Since((GNack(i))', sinceNack[i])]
    /\ sinceCT' = Since(GCT', sinceCT)
    /\ sinceCA' = Since(GCA', sinceCA)
    /\ sinceDP' = Since(GDP', sinceDP)

Overdue(s)    == s # NONE /\ h >= s + R
OverdueNow(s) == s # NONE /\ h >= s

\* CoarseTime: the next height at which a guard or deadline can change; one block
\* at a time while an obligation is pending.
Pending == \E s \in {sinceCT, sinceCA, sinceDP} \cup
                   {sinceChal[i] : i \in Watchtowers} \cup
                   {sinceNack[i] : i \in Watchtowers} : s # NONE
Thresholds ==
    {WCI, WCI + 1 + WtProof, WCI + ACK + ScanLag, WCI + COMMIT + ScanLag,
     WCI + WC, WCI + CF, AssertMax, MaxH}
    \cup (IF assertH # NONE THEN {assertH + 1, assertH + CD} ELSE {})
    \cup (IF vaH # NONE THEN {vaH + 1, vaH + PC + ScanLag} ELSE {})
    \cup (IF Pending \/ (E # Unspent /\ ~eSeen) THEN {h + 1} ELSE {})
NextHeight ==
    IF ~CoarseTime THEN h + 1
    ELSE LET later == {t \in Thresholds : t > h}
         IN  CHOOSE t \in later : \A u \in later : t <= u

\* Take-2 can no longer happen (D or F spent by a defender).
Settled == D = Disproved \/ F \in {Nacked, TimedOut}

\* The bad outcomes the properties exclude.
Take2Done          == D = Take2Spent
InvalidProofTake2  == Take2Done /\ ~proofValid
UnboundTake2       == Take2Done /\ E # PubinCommitted
SilencedWatchtower == \E i \in online : h >= WCI + WC /\ wc[i] # Challenged

\* EveryCase: the outcome the cfg must reproduce on every case.
BugHolds ==
    CASE BugProp = "invalid" -> InvalidProofTake2
      [] BugProp = "nopubin" -> UnboundTake2
      [] BugProp = "wtlands" -> SilencedWatchtower
      [] BugProp = "any"     -> InvalidProofTake2 \/ UnboundTake2 \/ SilencedWatchtower
LastCase == ~EveryCase \/ casesDone + 1 = NCases

\* Initial protocol state of a case.
CaseInit(q) ==
    /\ h = Start(q)
    /\ proofValid \in ProofValidity
    /\ assertH = NONE
    /\ online \in {Watchtowers \ S : S \in SUBSET Faulty}
    /\ wc  = [i \in Watchtowers |-> Unspent]
    /\ ack = [i \in Watchtowers |-> Unspent]
    /\ E = Unspent /\ eSeen = FALSE /\ F = Unspent /\ D = Unspent
    /\ vaH = NONE /\ answered = FALSE
    /\ job = [i \in Watchtowers |-> JobLive]
    /\ sinceChal = [i \in Watchtowers |-> NONE]
    /\ sinceCancel = [i \in Watchtowers |-> NONE]
    /\ sinceNack = [i \in Watchtowers |-> NONE]
    /\ sinceCT = NONE /\ sinceCA = NONE /\ sinceDP = NONE

--------------------------------------------------------------------------
Init ==
    /\ params \in IF EveryCase THEN {Cases[1]} ELSE Params
    /\ casesDone = 0
    /\ CaseInit(params)

--------------------------------------------------------------------------
\* Actions: environment.

\* Action: a block is mined; disabled while an honest obligation is at its deadline, and once Take-2 is impossible and the watchtower window is over.
\* Source: Bitcoin consensus; r = protocol_timing_budget() in crates/bitvm-gc/src/timelocks.rs:142
Tick ==
    /\ h < MaxH
    /\ ~(Settled /\ h >= WCI + WC)
    /\ \A i \in Watchtowers :
          ~Overdue(sinceChal[i]) /\ ~OverdueNow(sinceCancel[i]) /\ ~Overdue(sinceNack[i])
    /\ ~Overdue(sinceCT) /\ ~Overdue(sinceCA) /\ ~Overdue(sinceDP)
    /\ h' = NextHeight
    /\ eSeen' = (E # Unspent)
    /\ UNCHANGED <<params, casesDone, proofValid, assertH, online, wc, ack, E, F, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: EveryCase only: once BugHolds, start the next parameter case, so ReproducesOnEveryCase fails iff every case reproduces.
\* Source: environment (model-checking harness)
NextCase ==
    /\ EveryCase /\ BugHolds /\ ~LastCase
    /\ casesDone' = casesDone + 1
    /\ params' = Cases[casesDone + 2]
    \* CaseInit(params'), written out primed:
    /\ h' = Start(params')
    /\ proofValid' \in ProofValidity
    /\ assertH' = NONE
    /\ online' \in {Watchtowers \ S : S \in SUBSET Faulty}
    /\ wc'  = [i \in Watchtowers |-> Unspent]
    /\ ack' = [i \in Watchtowers |-> Unspent]
    /\ E' = Unspent /\ eSeen' = FALSE /\ F' = Unspent /\ D' = Unspent
    /\ vaH' = NONE /\ answered' = FALSE
    /\ job' = [i \in Watchtowers |-> JobLive]
    /\ sinceChal' = [i \in Watchtowers |-> NONE]
    /\ sinceCancel' = [i \in Watchtowers |-> NONE]
    /\ sinceNack' = [i \in Watchtowers |-> NONE]
    /\ sinceCT' = NONE /\ sinceCA' = NONE /\ sinceDP' = NONE

--------------------------------------------------------------------------
\* Actions: operator (adversary), any transaction the scripts allow. The outputs
\* of WCI (Ack_i, E, F, WC_i) exist from block WCI on.

\* Action: the operator's Assert confirms, at any height up to AssertMax (even before WCI).
\* Source: environment; goat connectors/connector_c.rs:45 (leaf 1: WOTS only, no CSV)
OpAssert ==
    /\ assertH = NONE /\ h <= AssertMax
    /\ AssertAtWCIOnly => h = WCI
    /\ assertH' = h
    /\ UNCHANGED <<params, casesDone, h, proofValid, online, wc, ack, E, eSeen, F, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: the operator's ACK_i spends Ack_i through its hashlock leaf, possible before any challenge.
\* Source: environment; goat connectors/watchtower_connectors.rs:128 (leaf 1: hashlock, no signature or CSV)
OpAck(i) ==
    /\ h >= WCI /\ ack[i] = Unspent
    /\ ack' = [ack EXCEPT ![i] = Acked]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, E, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the operator's WC-Timeout_i (operator key + CSV wc) spends WC_i and Ack_i.
\* Source: environment; goat transactions/watchtower_challenge.rs:359-393
OpWCTimeout(i) ==
    /\ wc[i] = Unspent /\ ack[i] = Unspent
    /\ h >= WCI + WC
    /\ wc'  = [wc  EXCEPT ![i] = TimedOut]
    /\ ack' = [ack EXCEPT ![i] = TimedOut]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, E, eSeen, F, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: the operator's Commit-Pubin spends connector E (WOTS only, any time).
\* Source: environment; goat connectors/connector_e.rs:48
OpCommitPubin ==
    /\ h >= WCI /\ E = Unspent
    /\ E' = PubinCommitted
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the operator answers the ChallengeAssert with Wrongly-Challenged; needs a valid proof.
\* Source: environment; goat transactions/assert.rs:599-626
OpWronglyChallenged ==
    /\ proofValid /\ vaH # NONE /\ ~answered /\ D # Disproved
    /\ answered' = TRUE
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, vaH, job>>
    /\ UpdateSince

\* Action: Take-2 spends D (CSV cd after the Assert) and F (CSV cf after WCI): the operator is paid.
\* Source: environment; goat transactions/take2.rs:56-90
OpTake2 ==
    /\ D = Unspent /\ F = Unspent /\ assertH # NONE
    /\ h >= assertH + CD /\ h >= WCI + CF /\ h >= WCI
    /\ D' = Take2Spent /\ F' = Take2Spent
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen,
                   vaH, answered, job>>
    /\ UpdateSince

--------------------------------------------------------------------------
\* Actions: honest nodes, as the code does them (Fix* = fix design).

\* Action: an online watchtower with its proof ready sends its Watchtower-Challenge (WC_i leaf 0, no CSV), unless its job was cancelled.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:1548-1588 (watchtower_challenge); job from graph_pegout.rs:266
WtChallenge(i) ==
    /\ GChal(i)
    /\ wc' = [wc EXCEPT ![i] = Challenged]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, ack, E, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the first scan that sees the Assert cancels the watchtower's JOB_WATCHTOWER_CHALLENGE for good (C2).
\* Source: node/src/aggregates/graph_pegout.rs:608-621; crates/engine/src/worker.rs:313-365 (inserts, then cancels)
WtJobCancelled(i) ==
    /\ GCancel(i)
    /\ job' = [job EXCEPT ![i] = JobCancelled]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, vaH, answered>>
    /\ UpdateSince

\* Action: a verifier sends the pre-signed NACK_i (Ack_i leaf 2 + F leaf 1); current code only for a watchtower that challenged.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:654-709 (challenge_nack); graph_scan.rs:642-657 (NackReady)
Nack(i) ==
    /\ GNack(i)
    /\ ack' = [ack EXCEPT ![i] = Nacked]
    /\ F' = Nacked
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, E, eSeen, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: a verifier sends the pre-signed Commit-Timeout (E leaf 1 + F leaf 1); current code only once all_resolved.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:712-732 (commit_timeout); graph_scan.rs:679-687
CommitTimeout ==
    /\ GCT
    /\ E' = TimedOut /\ F' = TimedOut
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, eSeen, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the verifier's ChallengeAssert confirms; current code only after connector-E is spent and seen.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:736-884 (verifier_assert; gate 766-779, proof check 861)
ChallengeAssert ==
    /\ GCA
    /\ vaH' = h
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, answered, job>>
    /\ UpdateSince

\* Action: a verifier's Disprove (D leaf 1 + ProverConnector leaf 1) confirms after an unanswered prover_connector CSV.
\* Source: node/src/aggregates/graph_pegout_jobs.rs:983-1023 (disprove); graph_scan.rs:742-788 (wrongly_challenge_timeout)
Disprove ==
    /\ GDP
    /\ D' = Disproved
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   vaH, answered, job>>
    /\ UpdateSince

--------------------------------------------------------------------------
Next ==
    \/ Tick
    \/ NextCase
    \/ OpAssert
    \/ \E i \in Watchtowers : OpAck(i)
    \/ \E i \in Watchtowers : OpWCTimeout(i)
    \/ OpCommitPubin
    \/ OpWronglyChallenged
    \/ OpTake2
    \/ \E i \in Watchtowers : WtChallenge(i)
    \/ \E i \in Watchtowers : WtJobCancelled(i)
    \/ \E i \in Watchtowers : Nack(i)
    \/ CommitTimeout
    \/ ChallengeAssert
    \/ Disprove

\* No fairness: every property is safety; Tick waits for overdue honest obligations.
Spec == Init /\ [][Next]_vars

WatchtowerSymmetry == Permutations(Watchtowers)

--------------------------------------------------------------------------
\* Safety invariants.

\* With an honest online verifier, an invalid proof never reaches Take-2.
NoTake2WithInvalidProof == ~InvalidProofTake2

\* Take-2 only after the operator committed its pubin.
NoTake2WithoutPubin == ~UnboundTake2

\* Every honest online watchtower's challenge lands before WC-Timeout is possible.
OnlineWatchtowerChallengeLands == ~SilencedWatchtower

\* EveryCase cfgs: violated iff BugHolds is reached on every case of Params.
ReproducesOnEveryCase == ~(BugHolds /\ LastCase)

--------------------------------------------------------------------------
\* Safety properties.

\* The parameters do not change within a case.
ParamsFrozen == [][params' = params \/ casesDone' # casesDone]_vars

--------------------------------------------------------------------------
\* Liveness: none (see Spec).

====
