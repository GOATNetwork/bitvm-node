---- MODULE DisputeObligations ----
(***************************************************************************)
(* PURPOSE. Challenge-path obligations of the honest nodes after a         *)
(* Challenge: can an operator reach Take-2 with an invalid proof, or       *)
(* without committing its pubin, and does every honest watchtower's        *)
(* challenge land? Findings C1 (the watchtower branches and the            *)
(* commit-pubin gate block every honest response) and C2 (an early Assert  *)
(* cancels every watchtower's challenge job), and the timing margins their *)
(* fix needs - over EVERY timelock / delay combination and over the        *)
(* shipped per-network values.                                             *)
(*                                                                         *)
(* CODE SCOPE: dev @ 60562f8 (node = #476 event-sourced aggregates on      *)
(* crates/engine); chain scripts = goat crate @ bab46c2 (goat/src/).       *)
(*                                                                         *)
(* CHAIN. Take-2 (transactions/take2.rs:56-90) spends ConnectorD leaf0     *)
(* (operator + CSV connector_d from the Assert, connectors/connector_d.rs: *)
(* 61) AND ConnectorF leaf0 (operator + CSV connector_f from WCI =         *)
(* Watchtower-Challenge-Init, connectors/connector_f.rs:38). It is stopped *)
(* only if an honest tx spends D or F first:                               *)
(*  F leaf1 (n-of-n, no CSV, connector_f.rs:49) is spent by                *)
(*   - Operator-Challenge-NACK_i = Ack_i leaf2 (n-of-n + CSV operator_ack  *)
(*     from WCI, connectors/watchtower_connectors.rs:156) + F leaf1        *)
(*     (transactions/watchtower_challenge.rs:544-575). Fully pre-signed,   *)
(*     so it is valid for ANY unspent Ack_i, whether or not watchtower i   *)
(*     challenged;                                                         *)
(*   - Operator-Commit-Timeout = E leaf1 (n-of-n + CSV operator_commit     *)
(*     from WCI, connectors/connector_e.rs:56) + F leaf1                   *)
(*     (watchtower_challenge.rs:715-746). Fully pre-signed.                *)
(*  D leaf1 (n-of-n) is spent by Disprove = D leaf1 + ProverConnector leaf1*)
(*   (n-of-n + CSV prover_connector from the verifier's ChallengeAssert),  *)
(*   transactions/assert.rs:317-357. The operator answers a ChallengeAssert*)
(*   of a VALID proof with Wrongly-Challenged (ProverConnector leaf0,      *)
(*   assert.rs:599-626), which an invalid proof cannot produce.            *)
(* The operator alone controls: WCI (ConnectorB, operator key, no CSV,     *)
(* connector_b.rs:27); the Assert (ConnectorC leaf1, WOTS only, no CSV and *)
(* no ordering w.r.t. WCI, assert.rs:68-74, connector_c.rs:45); ACK_i      *)
(* (Ack_i leaf1: hashlock only, no signature or CSV,                       *)
(* watchtower_connectors.rs:128 - so it can be spent BEFORE any challenge);*)
(* Commit-Pubin (E leaf0, WOTS only, connector_e.rs:48); and               *)
(* WC-Timeout_i = WC_i leaf1 (OPERATOR key + CSV watchtower_challenge,     *)
(* watchtower_connectors.rs:49) + Ack_i leaf0 (watchtower_challenge.rs:    *)
(* 359-393): only the operator can time a watchtower out. A watchtower     *)
(* challenge spends WC_i leaf0 (watchtower key, NO CSV,                    *)
(* watchtower_connectors.rs:40): valid until WC_i is spent, in particular  *)
(* after the Assert has spent ConnectorC.                                  *)
(*                                                                         *)
(* NODE (current code; re-checked against 60562f8, every line below holds):*)
(*  node/src/aggregates/graph_scan.rs watchtower_flow (573-697):           *)
(*   - an unchallenged WC_i (`None =>`, 659-670) sets all_resolved = false *)
(*     and raises only WatchtowerChallengeTimeout, routed to the OWNING    *)
(*     OPERATOR (graph_pegout.rs:269); a malicious operator ignores it;    *)
(*   - NackReady (654) is pushed only in the `Some(_) if !timed_out` arm   *)
(*     (642-657), i.e. only for watchtowers that DID challenge;            *)
(*   - OperatorCommitPubinTimeout (679-687) requires all_resolved.         *)
(*  node/src/aggregates/graph_pegout_jobs.rs verifier_assert (736-884):    *)
(*   767-779 waits ("operator commit-pubin is not on chain yet") until     *)
(*   connector-E is spent, BEFORE the proof is even checked (861). This is *)
(*   not a data dependency: when E is spent by Commit-Timeout the same job *)
(*   builds the ChallengeAssert from the assert witness alone.             *)
(*  node/src/aggregates/graph_pegout.rs apply_chain_scan (606-622): every  *)
(*   scan that carries AssertSent makes the watchtower role cancel its     *)
(*   JOB_WATCHTOWER_CHALLENGE. crates/engine/src/worker.rs:313-365 inserts *)
(*   a scan's jobs (INSERT OR IGNORE, crates/store/src/engine/mod.rs:1282) *)
(*   and THEN applies its cancels; a Cancelled job id is never run again   *)
(*   (worker.rs:336-342; rows are purged only after 15 days,               *)
(*   crates/engine/src/config.rs:101). assert_flow (graph_scan.rs:700-738) *)
(*   re-emits AssertSent on every scan, so once the Assert is confirmed    *)
(*   every (re-)enqueued watchtower challenge job is cancelled in the same *)
(*   transaction that inserts it. The same AssertSent also starts          *)
(*   JOB_WATCHTOWER_PROOF_TIMEOUT for the watchtower (graph_pegout.rs:267, *)
(*   watchtower_proof_timeout graph_pegout_jobs.rs:1591-1597 ->            *)
(*   notify_watchtower_proof_timeout node/src/utils/proof_client.rs:560),  *)
(*   which tells the proof builder to stop that watchtower's proof: a      *)
(*   second way the Assert silences it (subsumed here by the job cancel).  *)
(*  Low: graph_scan.rs:474 is_timelock_ready(c, n, tip) = c + n <= tip, so *)
(*   an honest CSV-gated tx lands in block c+n+1 at the earliest, one block*)
(*   after the operator's (ScanLag, swept as sl in {0, 1}).                *)
(*                                                                         *)
(* FINDINGS (live cfgs; each reproduces on ALL FOUR networks with the      *)
(* shipped timelocks and r = action_window - ReproducesOnEveryCase):       *)
(*  C1 (C1.cfg): one watchtower that never challenges (offline or          *)
(*   colluding) and that the operator never times out keeps all_resolved   *)
(*   false forever: no NACK, no Commit-Timeout, and verifier_assert never  *)
(*   gets past the connector-E gate -> Take-2 with an invalid proof. No    *)
(*   defender action is ever enabled, so this holds for every parameter.   *)
(*  C1 (a) (C1LateCommit.cfg): the connector-E gate alone, with every      *)
(*   branch resolved and the shipped margins repaired: the operator        *)
(*   commits pubin just before Commit-Timeout lands, the ChallengeAssert   *)
(*   starts only then, and the Disprove lands at the earliest by           *)
(*   commit + 2 sl + 3 r + pc + 1 >= cf on every network (even with        *)
(*   r = sl = 0: commit + pc + 1 >= cf, e.g. mainnet 432 + 144 + 1 > 576). *)
(*  C1 (b) (C1NoPubin.cfg): ChallengeAssert ungated but Commit-Timeout     *)
(*   still gated on all_resolved: a VALID proof reaches Take-2 without any *)
(*   commit-pubin (the operator spends Ack_i through its hashlock leaf, so *)
(*   NACK-every-Ack does not close it). Parameter independent.             *)
(*  C2 (C2.cfg): an Assert confirmed before the watchtowers' proofs are    *)
(*   ready (e.g. in WCI's block) cancels every honest watchtower's job:    *)
(*   C1 with every watchtower honest. Parameter independent (the cancel is *)
(*   immediate; with wtp = 0 the adversary orders it first).               *)
(*  C2 alone (C2Silenced.cfg, C1 fixed, margins repaired): still keeps     *)
(*   every honest watchtower's evidence off chain.                         *)
(*                                                                         *)
(* FIX DESIGN (design cfgs; each flag switchable on its own):              *)
(*  FixCommitTimeout: OperatorCommitPubinTimeout at operator_commit        *)
(*   whenever E and F are unspent, whatever the watchtower branches;       *)
(*  FixNackAll: NackReady for EVERY unspent Ack_i after operator_ack;      *)
(*  FixUngateAssert: an invalid proof is challenged as soon as the Assert  *)
(*   is seen; only the "valid proof, skip" decision waits for commit-pubin *)
(*   (an inconsistent pubin is then answered by Pubin-Disprove, D leaf2,   *)
(*   which has no CSV);                                                    *)
(*  FixNoCancel: AssertSent neither cancels JOB_WATCHTOWER_CHALLENGE nor   *)
(*   stops the watchtower's proof (JOB_WATCHTOWER_PROOF_TIMEOUT).          *)
(* Without FixCommitTimeout NoTake2WithoutPubin fails, without             *)
(* FixUngateAssert NoTake2WithInvalidProof fails, without FixNoCancel      *)
(* OnlineWatchtowerChallengeLands fails; FixNackAll is defence in depth.   *)
(* ParamsOK (exact; each conjunct is necessary and sufficient for its      *)
(* property, Boundary cfg):                                                *)
(*   wc >= wtp + r + 2           (OnlineWatchtowerChallengeLands)          *)
(*   cf >= commit + sl + r + 1   (NoTake2WithoutPubin)                     *)
(*   cd >= 2 r + pc + sl + 2     (NoTake2WithInvalidProof)                 *)
(* The node's validate_timelock_config (crates/bitvm-gc/src/timelocks.rs:  *)
(* 173-241) checks only wc >= wtp + action_window, cf - commit >=          *)
(* confirmed_action_window, cd - pc >= action_window: it is off by 2 for   *)
(* the watchtower window and by r + sl + 2 for the Disprove race. As       *)
(* shipped (r = action_window, sl = 1) ParamsOK holds on Bitcoin and       *)
(* Testnet4, NOT on Signet (wc 6 < 7) nor Regtest (wc 1 < 3, cf 4 < 6,     *)
(* cd 3 < 6): the fix needs those timelocks raised (FixedShipped.cfg with  *)
(* RepairTimelocks; FixedShippedBoundary.cfg shows the shipped values      *)
(* fail).                                                                  *)
(*                                                                         *)
(* TIME is Bitcoin block height; h is the block being built. The operator's*)
(* CSV-n spend of an output confirmed at c can be in block c+n. An honest  *)
(* node sees the tip h-1: it sees a tx confirmed at c from block c+1 (the  *)
(* physical minimum - the block must exist before anyone reacts to it),    *)
(* and its is_timelock_ready guard holds from block c+n+sl. An honest      *)
(* action whose code guard holds from block s lands in SOME block of       *)
(* s..s+r, chosen by the adversary (r = honest delay beyond the first      *)
(* possible block: reaction + inclusion (+ safety)); Tick is disabled while*)
(* one is overdue. Only the sum matters (the model's honest actions are    *)
(* atomic), so reaction and inclusion are one parameter. The job cancel is *)
(* a local DB effect of the first scan that sees the Assert, so it happens *)
(* in the block it becomes enabled (the adversary may still order it       *)
(* before a same-block challenge). WCI confirms at height 0; the Assert    *)
(* (no on-chain ordering w.r.t. WCI) may confirm from height               *)
(* -max(0, cd - cf) on: an earlier Assert is equivalent for Take-2 (gated  *)
(* by cf anyway) and only lets the verifier react earlier; an Assert after *)
(* AssertMax (every WCI-rooted deadline passed) is a time shift of one at  *)
(* AssertMax. One honest online verifier stands for the 1-of-M verifier    *)
(* set (every response above is pre-signed n-of-n or is that verifier's    *)
(* own ChallengeAssert). The operator's pubin is consistent with its       *)
(* Assert (an inconsistent one only adds Pubin-Disprove). Blocks stop once *)
(* a defender has spent D or F and the watchtower window is over. Not      *)
(* modelled: the 1-block visibility lag of the branch-resolving txs before *)
(* all_resolved holds (it can only delay the current-code Commit-Timeout). *)
(*                                                                         *)
(* PARAMETERS are frozen variables (record params, chosen in Init, never   *)
(* changed except by NextCase): wc, ack, commit, cf (CSV from WCI), cd     *)
(* (from the Assert), pc (from the ChallengeAssert), wtp (watchtower proof *)
(* blocks), r (honest delay), sl (ScanLag). UseShipped takes them from     *)
(* ShippedTimelockValues for each network in NetSet (sl = 1 as shipped);   *)
(* otherwise every combination of the *Range sets inside Region.           *)
(* UseValidator: every tuple validate_timelock_config accepts (Validated)  *)
(* for budgets from the Reaction/Inclusion/Safety/Evidence ranges.         *)
(* EXHAUSTIVENESS of the sweep (Fixed.cfg, Region "ok_zero": every margin  *)
(* exactly 0, wtp in 0..1, r in 0..2, sl in 0..1, pc in 1..2, commit in    *)
(* {1, 3}, ack = 2): (1) wc, cf and cd appear only in OPERATOR guards      *)
(* (WC-Timeout, Take-2) and in the horizon, so lowering one only adds      *)
(* operator behaviours - margin 0 dominates every margin > 0; (2) r only   *)
(* widens the honest landing window (behaviours(r) include behaviours of   *)
(* every smaller r); (3) ack and commit set when NACK / Commit-Timeout,    *)
(* pure defender actions that spend only F, E, Ack_i, become due - they    *)
(* can only remove Take-2 / WC-Timeout options; commit enters a property   *)
(* only through the cf margin; (4) pc and sl enter the Disprove race only  *)
(* as pc + sl; (5) the sweep contains every ordering of cd vs cf (so the   *)
(* pre-WCI Assert window), of the challenge readiness 1 + wtp vs the       *)
(* other WCI-rooted heights, and the r classes 0 (instant), 1, 2 (two      *)
(* chained honest actions straddle). The Boundary cfg covers margin -1 of  *)
(* each conjunct with the others at 0 or 1 (by (1)/(2) every lower margin  *)
(* fails too).                                                             *)
(*                                                                         *)
(* CONFIGS -> TIERS (audit/tla/specs.txt):                                 *)
(*  live:     C1, C1LateCommit, C1NoPubin, C2, C2Silenced (shipped values, *)
(*            all networks, EveryCase - fail iff the bug reproduces on     *)
(*            every network);                                              *)
(*  design:   Fixed (sweep over ParamsOK), FixedShipped (shipped values,   *)
(*            Testnet4/Signet/Regtest, RepairTimelocks);                   *)
(*  boundary: FixedBoundary (margin -1 sweep, EveryCase - fails iff EVERY  *)
(*            point fails), FixedShippedBoundary (fix on the as-shipped    *)
(*            Signet/Regtest timelocks).                                   *)
(*  live:     ValidateGap (fix design over every tuple the CURRENT         *)
(*            validate_timelock_config accepts at its minimum for budgets  *)
(*            reaction 1..2, inclusion/safety/evidence/wtp 0..2, restricted*)
(*            to ~ParamsOK: the validator admits graphs the fixed protocol *)
(*            loses; becomes pass once the validator requires ParamsOK).   *)
(* Mainnet is in the bug cfgs (CoarseTime) but not in FixedShipped: its    *)
(* full state space at 576-block scale is too large for the CI budget; its *)
(* margins are 100 / 124 / 249 (all >= 0), covered by the sweep argument.  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC, ShippedTimelockValues

\* ---- model shape
CONSTANTS
    Watchtowers,      \* watchtower slots of the graph (outputs WC_i / Ack_i of WCI)
    Faulty,           \* watchtowers that may be offline or collude with the operator
    ProofValidity     \* operator's choices for the asserted proof: subset of BOOLEAN

\* ---- design switches (all FALSE = the current code)
CONSTANTS
    FixCommitTimeout, \* Commit-Timeout at operator_commit whatever the branches
    FixNackAll,       \* NACK every unspent Ack_i after operator_ack
    FixUngateAssert,  \* challenge an invalid proof without waiting for connector-E
    FixNoCancel       \* AssertSent no longer stops the watchtower's challenge

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
    UseValidator,     \* TRUE: every tuple validate_timelock_config accepts for
                      \*   a budget from the four ranges below (ValidatorParams)
    ReactionRange,    \* swept budget reaction_blocks
    InclusionRange,   \* swept budget inclusion_blocks
    SafetyRange,      \* swept budget safety_blocks
    EvidenceRange,    \* swept budget evidence_confirmations
    SlackRange        \* UseValidator: extra blocks over each validator minimum

\* ---- exploration controls
CONSTANTS
    EveryCase,        \* run the parameter cases one after another (see NextCase)
    BugProp,          \* EveryCase: "invalid" | "nopubin" | "wtlands" | "any"
    CoarseTime,       \* Tick jumps to the next height where a guard or deadline changes
                      \*   (restricts the adversary: only for cfgs that must FAIL)
    AssertAtWCIOnly   \* the Assert only in WCI's block (restricts the adversary:
                      \*   only for cfgs that must FAIL)

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

\* Margins of the fix design (ParamsOK = all >= 0; exact, see header).
\* Watchtower challenge ready at 1 + wtp, lands by 1 + wtp + r, must be in a
\* block before WC-Timeout can be (wc).
MarginWt(q)       == q.wc - (q.wtp + q.r + 2)
\* Commit-Timeout lands by commit + sl + r; Take-2 can be in block cf.
MarginCommit(q)   == q.cf - (q.commit + q.sl + q.r + 1)
\* ChallengeAssert by Assert + 1 + r, Disprove by that + pc + sl + r; Take-2
\* can be in block Assert + cd.
MarginDisprove(q) == q.cd - (2 * q.r + q.pc + q.sl + 2)
ParamsOK(q) == MarginWt(q) >= 0 /\ MarginCommit(q) >= 0 /\ MarginDisprove(q) >= 0
Margins(q)  == {MarginWt(q), MarginCommit(q), MarginDisprove(q)}

\* That margin exactly -1 (the first failing class), the other two in Others.
BadWt(q, Others)       == MarginWt(q) = -1 /\ {MarginCommit(q), MarginDisprove(q)} \subseteq Others
BadCommit(q, Others)   == MarginCommit(q) = -1 /\ {MarginWt(q), MarginDisprove(q)} \subseteq Others
BadDisprove(q, Others) == MarginDisprove(q) = -1 /\ {MarginWt(q), MarginCommit(q)} \subseteq Others

\* "all" every combination; "ok" / "notok" ParamsOK or not; "ok_edge" every
\* margin 0 or 1; "ok_zero" every margin 0; "boundary" one margin -1, the
\* others 0; "bad_wt" / "bad_commit" / "bad_disprove" that margin -1, the
\* others 0 or 1.
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

\* Budget fields (rx reaction, inc inclusion, saf safety, ev evidence) are
\* only meaningful for UseShipped / UseValidator; 0 for the plain sweep.
SweptParams ==
    [net: {"swept"}, wc: WCRange, ack: ACKRange, commit: COMMITRange, cf: CFRange,
     cd: CDRange, pc: PCRange, wtp: WtProofRange, r: RRange, sl: ScanLagRange,
     rx: {0}, inc: {0}, saf: {0}, ev: {0}]

\* "zero" (honest nodes always in the first possible block) is a subset of
\* the behaviours of any larger r: a counterexample with it is one for every r.
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

\* validate_timelock_config() in crates/bitvm-gc/src/timelocks.rs:173-241 as
\* shipped, for budget q.rx / q.inc / q.saf / q.ev / q.wtp (connector_a and
\* connector_z are not in this model). ensure_gap_at_least uses
\* saturating_sub: right - left >= req, which always holds when req = 0.
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

\* Least value the validator accepts for `right` after `left` (gap req),
\* never below reaction_blocks.
MinAfter(left, req, rx) == Max2(rx, IF req = 0 THEN 0 ELSE left + req)

\* Every tuple the validator accepts within SlackRange of its minimum, for
\* every budget of the ranges; honest delay r = action_window, sl = 1.
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

\* The least change to the shipped timelocks that meets ParamsOK.
Repair(q) ==
    [q EXCEPT !.wc = Max2(@, q.wtp + q.r + 2),
              !.cf = Max2(@, q.commit + q.sl + q.r + 1),
              !.cd = Max2(@, 2 * q.r + q.pc + q.sl + 2)]

ShippedParams ==
    {IF RepairTimelocks THEN Repair(AsShipped(n, d)) ELSE AsShipped(n, d) :
        n \in NetSet, d \in ShippedDelay}

Params == {q \in (IF UseValidator THEN ValidatorParams
                  ELSE IF UseShipped THEN ShippedParams ELSE SweptParams) : InRegion(q)}

\* EveryCase: the cases in lexicographic order (constant, evaluated once).
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

\* First height explored (an Assert this early already matures connector_d
\* by cf, header).
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

\* Last height an Assert is explored at: every WCI-rooted guard and deadline
\* has passed; a later Assert is a time shift of this one.
AssertMax == Max2(Max2(Max2(WC, ACK + ScanLag + R), Max2(COMMIT + ScanLag + R, CF)),
                  WtProof + 1 + R) + 1
MaxH == AssertMax + CD

Heights == {NONE} \cup (Start(params) .. MaxH)

ParamFields == {"wc", "ack", "commit", "cf", "cd", "pc", "wtp", "r", "sl",
                "rx", "inc", "saf", "ev"}

\* (params is typed field by field: membership in the large Params set would
\* dominate the run time; it never changes within a case, ParamsFrozen.)
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

\* What an honest node can see / its is_timelock_ready guard.
Seen(c)     == c # NONE /\ h >= c + 1
Ready(c, n) == c # NONE /\ h >= c + n + ScanLag

\* graph_scan.rs:617-670: a branch is resolved iff WC_i was timed out, or it
\* was challenged and Ack_i is spent (ACK and NACK both spend it).
AllResolved == \A i \in Watchtowers :
                  \/ wc[i] = TimedOut
                  \/ wc[i] = Challenged /\ ack[i] # Unspent

\* verifier_assert's decision to send a ChallengeAssert. Current code
\* (767-866): only once connector-E is spent and seen; then always after a
\* Commit-Timeout (pubin_consistent = false), else iff the proof is invalid.
\* Fix: an invalid proof at once; a valid one only after a Commit-Timeout.
WantsChallenge ==
    IF FixUngateAssert
    THEN ~proofValid \/ E = TimedOut
    ELSE eSeen /\ (~proofValid \/ E = TimedOut)

\* Honest guards (current code; Fix* flags switch to the fix design).
GChal(i)   == /\ i \in online /\ wc[i] = Unspent /\ job[i] = JobLive
              /\ h >= WCI + 1 + WtProof
GCancel(i) == /\ ~FixNoCancel /\ i \in online /\ job[i] = JobLive /\ Seen(assertH)
GNack(i)   == /\ ack[i] = Unspent /\ F = Unspent /\ Ready(WCI, ACK)
              /\ (FixNackAll \/ wc[i] = Challenged)
GCT        == /\ E = Unspent /\ F = Unspent /\ Ready(WCI, COMMIT)
              /\ (FixCommitTimeout \/ AllResolved)
GCA        == /\ D = Unspent /\ vaH = NONE /\ Seen(assertH) /\ WantsChallenge
GDP        == /\ D = Unspent /\ ~answered /\ Ready(vaH, PC)

\* Start of an obligation after a step: gNext is its guard in the new state.
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

\* CoarseTime: the next height at which some guard or deadline can change.
\* While an obligation is pending, time still moves one block at a time.
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

\* The per-case state every run of the protocol starts from (unprimed).
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

\* Action: a block is mined; nodes see the previous one. Disabled while an
\*   honest obligation is at its deadline (the adversary picks the landing
\*   block inside the window, never past it) and once Take-2 is impossible
\*   and the watchtower window is over (nothing left to check).
\* Source: Bitcoin consensus; honest delay = protocol_timing_budget() in
\*   crates/bitvm-gc/src/timelocks.rs:142 (reaction + inclusion + safety).
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

\* Action: EveryCase only - once the outcome BugProp names holds for the
\*   current case, start over with the next case (fixed order), so
\*   ReproducesOnEveryCase fails iff it holds for EVERY case.
\* Source: environment (model-checking harness, no code).
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
\* Actions: operator (adversary) - any transaction the scripts allow, at any
\* time. Outputs of WCI (Ack_i, E, F, WC_i) exist from block WCI on.

\* Action: the operator's Assert confirms (any block, even WCI's or before).
\* Source: environment; ConnectorC leaf1 (goat connectors/connector_c.rs:45,
\*   WOTS only, no CSV); honest path prover_assert() in
\*   node/src/aggregates/graph_pegout_jobs.rs:1237.
OpAssert ==
    /\ assertH = NONE /\ h <= AssertMax
    /\ AssertAtWCIOnly => h = WCI
    /\ assertH' = h
    /\ UNCHANGED <<params, casesDone, h, proofValid, online, wc, ack, E, eSeen, F, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: Operator-Challenge-ACK_i spends Ack_i through its hashlock leaf -
\*   possible before (or without) any challenge.
\* Source: environment; Ack_i leaf1 (goat watchtower_connectors.rs:128);
\*   honest path challenge_ack() in graph_pegout_jobs.rs:1065.
OpAck(i) ==
    /\ h >= WCI /\ ack[i] = Unspent
    /\ ack' = [ack EXCEPT ![i] = Acked]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, E, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: Watchtower-Challenge-Timeout_i (operator key + CSV
\*   watchtower_challenge) spends WC_i and Ack_i.
\* Source: environment; goat watchtower_challenge.rs:359-393; honest path
\*   watchtower_timeout() in graph_pegout_jobs.rs:1127.
OpWCTimeout(i) ==
    /\ wc[i] = Unspent /\ ack[i] = Unspent
    /\ h >= WCI + WC
    /\ wc'  = [wc  EXCEPT ![i] = TimedOut]
    /\ ack' = [ack EXCEPT ![i] = TimedOut]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, E, eSeen, F, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: Operator-Commit-Pubin spends connector E (WOTS only, any time).
\* Source: environment; E leaf0 (goat connector_e.rs:48); honest path
\*   commit_pubin() in graph_pegout_jobs.rs:1177.
OpCommitPubin ==
    /\ h >= WCI /\ E = Unspent
    /\ E' = PubinCommitted
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: Wrongly-Challenged answers a ChallengeAssert; needs a valid proof.
\* Source: environment; ProverConnector leaf0 (goat assert.rs:599-626);
\*   honest path wrongly_challenged() in graph_pegout_jobs.rs:1327.
OpWronglyChallenged ==
    /\ proofValid /\ vaH # NONE /\ ~answered /\ D # Disproved
    /\ answered' = TRUE
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, vaH, job>>
    /\ UpdateSince

\* Action: Take-2 spends D leaf0 (CSV connector_d after the Assert) AND
\*   F leaf0 (CSV connector_f after WCI): the operator is reimbursed.
\* Source: environment; goat take2.rs:56-90; honest path take2() in
\*   graph_pegout_jobs.rs:1500 (take2_ready() graph_scan.rs:792).
OpTake2 ==
    /\ D = Unspent /\ F = Unspent /\ assertH # NONE
    /\ h >= assertH + CD /\ h >= WCI + CF /\ h >= WCI
    /\ D' = Take2Spent /\ F' = Take2Spent
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen,
                   vaH, answered, job>>
    /\ UpdateSince

--------------------------------------------------------------------------
\* Actions: honest nodes - exactly what the code does (Fix* = fix design).

\* Action: an online watchtower whose proof commitment is ready broadcasts
\*   its Watchtower-Challenge (WC_i leaf0, no CSV), unless its job was
\*   cancelled.
\* Source: watchtower_challenge() in node/src/aggregates/graph_pegout_jobs.rs:1548-1589
\*   (job from WatchtowerChallengeInitSent, graph_pegout.rs:266).
WtChallenge(i) ==
    /\ GChal(i)
    /\ wc' = [wc EXCEPT ![i] = Challenged]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, ack, E, eSeen, F, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the first scan that sees the Assert cancels the watchtower's
\*   JOB_WATCHTOWER_CHALLENGE for good (C2; FixNoCancel removes it).
\* Source: apply_chain_scan() in node/src/aggregates/graph_pegout.rs:606-622;
\*   commit order in crates/engine/src/worker.rs:313-365.
WtJobCancelled(i) ==
    /\ GCancel(i)
    /\ job' = [job EXCEPT ![i] = JobCancelled]
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, vaH, answered>>
    /\ UpdateSince

\* Action: a verifier broadcasts the pre-signed Operator-Challenge-NACK_i
\*   (Ack_i leaf2 + F leaf1), burning connector F. Current code: only for a
\*   watchtower that challenged (FixNackAll: every unspent Ack_i).
\* Source: challenge_nack() in graph_pegout_jobs.rs:654-709; NackReady in
\*   watchtower_flow() node/src/aggregates/graph_scan.rs:642-657.
Nack(i) ==
    /\ GNack(i)
    /\ ack' = [ack EXCEPT ![i] = Nacked]
    /\ F' = Nacked
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, E, eSeen, D, vaH,
                   answered, job>>
    /\ UpdateSince

\* Action: a verifier broadcasts the pre-signed Operator-Commit-Timeout
\*   (E leaf1 + F leaf1), burning connector F. Current code: only once every
\*   branch is resolved (FixCommitTimeout: always).
\* Source: commit_timeout() in graph_pegout_jobs.rs:712-733;
\*   OperatorCommitPubinTimeout in watchtower_flow() graph_scan.rs:679-687.
CommitTimeout ==
    /\ GCT
    /\ E' = TimedOut /\ F' = TimedOut
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, eSeen, D,
                   vaH, answered, job>>
    /\ UpdateSince

\* Action: the honest verifier's ChallengeAssert confirms. Current code:
\*   only after connector-E is spent and seen (FixUngateAssert: an invalid
\*   proof at once).
\* Source: verifier_assert() in graph_pegout_jobs.rs:736-884 (gate 767-779,
\*   proof check 861).
ChallengeAssert ==
    /\ GCA
    /\ vaH' = h
    /\ UNCHANGED <<params, casesDone, h, proofValid, assertH, online, wc, ack, E, eSeen, F,
                   D, answered, job>>
    /\ UpdateSince

\* Action: a verifier's Disprove (D leaf1 + ProverConnector leaf1) confirms
\*   once prover_connector has passed unanswered: Take-2 is stopped.
\* Source: disprove() in graph_pegout_jobs.rs:983-1023;
\*   wrongly_challenge_timeout() in graph_scan.rs:742-790.
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

\* No fairness: every property is safety. Honest progress is forced by the
\* obligation deadlines (Tick is disabled while one is overdue), not by WF.
Spec == Init /\ [][Next]_vars

WatchtowerSymmetry == Permutations(Watchtowers)

--------------------------------------------------------------------------
\* Safety invariants.

\* Every state is well typed.
\* (TypeOk above.)

\* With an honest online verifier, an invalid proof never reaches Take-2.
NoTake2WithInvalidProof == ~InvalidProofTake2

\* Take-2 only after the operator committed its pubin (the commitment that
\* binds the proof to the watchtowers' evidence).
NoTake2WithoutPubin == ~UnboundTake2

\* Every honest online watchtower's challenge lands before the operator may
\* time it out.
OnlineWatchtowerChallengeLands == ~SilencedWatchtower

\* EveryCase cfgs: violated iff BugHolds is reached on EVERY case, i.e. the
\* finding reproduces for every network / parameter point of Params.
ReproducesOnEveryCase == ~(BugHolds /\ LastCase)

--------------------------------------------------------------------------
\* Safety properties.

\* The parameters stay frozen within a case.
ParamsFrozen == [][params' = params \/ casesDone' # casesDone]_vars

--------------------------------------------------------------------------
\* Liveness: none (see Spec).

====
