---- MODULE AssertFrontRun ----
(***************************************************************************)
(* Witness-copy front-running of the two assert txs, pi2/pi3 malleability  *)
(*   and the assert-stage timing margins.                                  *)
(* Code: goat bab46c2 assert scripts and txs (goat/src/assert_scripts.rs,  *)
(*   transactions/assert.rs); node verifier_assert, disprove,              *)
(*   wrongly_challenged and take2                                          *)
(*   (node/src/aggregates/graph_pegout_jobs.rs) with their triggers        *)
(*   (graph_scan.rs).                                                      *)
(* Findings:                                                               *)
(*  C3: VerifierConnector leaf 0 has no CHECKSIG: the operator copies the  *)
(*    ChallengeAssert witness into a tx with other outputs; Disprove_j     *)
(*    (bound to the canonical outpoint) is dead and Take2 follows.         *)
(*  C4: ConnectorC leaf 1 has no CHECKSIG: a watcher redirects             *)
(*    OperatorAssert, ConnectorD never exists, the operator cannot settle. *)
(*  pi: pi2/pi3 are unsigned OP_2DROP items outside the txid; a swapped    *)
(*    copy confirms, the verifier challenges, the operator node rebuilds   *)
(*    the proof from the chain and is Disproved. A CHECKSIG does not help. *)
(*  ValidateGap: validate_timelock_config (timelocks.rs:222-229) accepts   *)
(*    configs outside ParamsOK: it counts one action window between the    *)
(*    two CSVs where CondDisprove needs two. Regtest: the shipped values   *)
(*    are outside ParamsOK.                                                *)
(* Parameters: see CONSTANTS. Assumed: ChallengeAssert fires on            *)
(*   OperatorAssert's confirmation (its commit-pubin gate is               *)
(*   DisputeObligations.tla's C1); ConnectorF has matured. Model: one      *)
(*   verifier slot j; the attacker outbids honest txs and wins same-block  *)
(*   ties; Disprove, Take2 and Wrongly-Challenged confirm atomically       *)
(*   (their pinning is DefenderTxPinning.tla).                             *)
(* ParamsOK (fix designs, exact - Exact.cfg) == CondWC /\ CondDisprove.    *)
(* Exhaustive: guards compare `now` with event heights plus linear forms   *)
(*   of the parameters. C3/C4 win for every tuple (AllParams.cfg); the fix *)
(*   verdict depends only on CondWC and CondDisprove (Exact.cfg). The      *)
(*   sweep (react 1..2, incl 0..1, eval 0..1, dcsv 1..6, t2csv 1..15) puts *)
(*   each margin at <= -1, 0 and >= +1 for every zero/non-zero split.      *)
(* Configs: configs/crates/bitvm-gc/AssertFrontRun/, tiers in              *)
(*   audit/tla/checks.txt.                                                 *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    ProofValidity,         \* subset of BOOLEAN: is the operator's asserted Groth16 proof valid?
    VerifierLeafChecksig,  \* FIX C3: n-of-n SIGHASH_ALL CHECKSIG on VerifierConnector leaf 0, presigned
    ConnCLeafChecksig,     \* FIX C4: operator SIGHASH_ALL CHECKSIG on ConnectorC leaf 1
    PiCommitted,           \* FIX pi: pi2/pi3 bound to signed data (e.g. an OperatorAssert output)
    UseShipped,            \* parameters from ShippedTimelockValues (per net in NetSet), eval from its range
    NetSet,                \* subset of Networks swept when UseShipped
    DisproveCSVRange,      \* ProverConnector leaf 1 CSV (timelock_config.prover_connector)
    Take2CSVRange,         \* ConnectorD leaf 0 CSV (timelock_config.connector_d)
    ReactionRange,         \* reaction blocks (>= 1, counts the next block)
    InclusionRange,        \* extra blocks to get a broadcast tx mined
    SafetyRange,           \* safety blocks (only used by ValidateOK)
    EvalVRange,            \* verifier proof check + challenge witness build, blocks (not in the node's budget)
    EvalORange,            \* operator GC evaluation for Wrongly-Challenged, blocks (not in the node's budget)
    ParamSel,              \* Init filter: "all" | "ok" | "notOK" | "validNotOK"
    Script                 \* worst-case run: honest at its deadline, attacker earliest (subset of behaviours)

VARIABLES
    net,         \* frozen: network name ("abstract" for the sweep)
    dcsv,        \* frozen: prover_connector CSV
    t2csv,       \* frozen: connector_d CSV
    react,       \* frozen: reaction blocks
    incl,        \* frozen: inclusion blocks
    safety,      \* frozen: safety blocks (ValidateOK only)
    evalV,       \* frozen: verifier evaluation blocks
    evalO,       \* frozen: operator GC evaluation blocks
    proofValid,  \* frozen: the asserted proof is valid (honest operator)
    now,         \* chain tip height
    memC,        \* mempool candidates spending ConnectorC
    cState,      \* ConnectorC: "unspent" | "canon" (canonical OperatorAssert) | "foreign"
    piBad,       \* the CONFIRMED OperatorAssert carries swapped/malformed pi2/pi3
    assertAt,    \* height the canonical OperatorAssert confirmed
    memV,        \* mempool candidates spending VerifierConnector_j
    vBcastAt,    \* tip at which the canonical VerifierAssert was broadcast
    vState,      \* VerifierConnector_j: "none" | "unspent" | "canon" | "foreign"
    vaAt,        \* height the canonical VerifierAssert confirmed
    pState,      \* ProverConnector_j: "none" | "unspent" | "wronglyChallenged" | "disprove"
    dState,      \* ConnectorD: "none" | "unspent" | "take2" | "disprove"
    challenged   \* a ChallengeAssert (VerifierAssert) was broadcast

params == <<net, dcsv, t2csv, react, incl, safety, evalV, evalO, proofValid>>
vars == <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt, vState,
          vaAt, pState, dState, challenged>>

CCands == {"canonGood", "canonBadPi", "foreign"}
VCands == {"canon", "foreign"}

\* Every event of interest has happened by then.
Horizon == 2 + incl + t2csv + dcsv + 3 * (react + incl) + evalV + evalO
Done == now = Horizon

TypeOk ==
    /\ dcsv \in Nat /\ t2csv \in Nat /\ react \in Nat /\ react >= 1
    /\ incl \in Nat /\ safety \in Nat /\ evalV \in Nat /\ evalO \in Nat
    /\ now \in 0..Horizon
    /\ proofValid \in BOOLEAN
    /\ memC \subseteq CCands
    /\ cState \in {"unspent", "canon", "foreign"}
    /\ piBad \in BOOLEAN
    /\ assertAt \in 0..Horizon
    /\ memV \subseteq VCands
    /\ vBcastAt \in 0..Horizon
    /\ vState \in {"none", "unspent", "canon", "foreign"}
    /\ vaAt \in 0..Horizon
    /\ pState \in {"none", "unspent", "wronglyChallenged", "disprove"}
    /\ dState \in {"none", "unspent", "take2", "disprove"}
    /\ challenged \in BOOLEAN

---------------------------------------------------------------------------
(* Parameter conditions.                                                   *)

\* Wrongly-Challenged (by vaAt + react + evalO + incl) lands strictly before a malicious Disprove (vaAt + dcsv).
CondWC       == react + incl + evalO + 1 <= dcsv
\* ChallengeAssert, then the node's Disprove (two action windows) lands strictly before Take2 (assertAt + t2csv).
CondDisprove == dcsv + 2 * (react + incl) + evalV + 1 <= t2csv
ParamsOK     == CondWC /\ CondDisprove

\* validate_timelock_config on these CSVs (timelocks.rs:186, :222-229); Gap is saturating_sub.
Gap(a, b) == IF b >= a THEN b - a ELSE 0
ValidateOK ==
    /\ dcsv >= react /\ t2csv >= react
    /\ dcsv >= react + incl + safety
    /\ Gap(dcsv, t2csv) >= react + incl + safety

Selected ==
    CASE ParamSel = "all"        -> TRUE
      [] ParamSel = "ok"         -> ParamsOK
      [] ParamSel = "notOK"      -> ~ParamsOK
      [] ParamSel = "validNotOK" -> ValidateOK /\ ~ParamsOK

\* The operator has just broadcast OperatorAssert (tip 0) with honest pi2/pi3.
Init ==
    /\ IF UseShipped
         THEN \E n \in NetSet :
                /\ net = n
                /\ dcsv = ProverConnector[n]
                /\ t2csv = ConnectorD[n]
                /\ react = ReactionBlocks[n]
                /\ incl = InclusionBlocks[n]
                /\ safety = SafetyBlocks[n]
         ELSE /\ net = "abstract"
              /\ dcsv \in DisproveCSVRange
              /\ t2csv \in Take2CSVRange
              /\ react \in ReactionRange
              /\ incl \in InclusionRange
              /\ safety \in SafetyRange
    /\ evalV \in EvalVRange
    /\ evalO \in EvalORange
    /\ proofValid \in ProofValidity
    /\ Selected
    /\ now = 0
    /\ memC = {"canonGood"}
    /\ cState = "unspent"
    /\ piBad = FALSE
    /\ assertAt = 0
    /\ memV = {}
    /\ vBcastAt = 0
    /\ vState = "none"
    /\ vaAt = 0
    /\ pState = "none"
    /\ dState = "none"
    /\ challenged = FALSE

---------------------------------------------------------------------------
(* Enabling conditions, shared by actions, deadlines and Script.           *)

\* What verify_operator_assert_proof sees: the confirmed witness.
VerifierJudgesInvalid == ~proofValid \/ piBad

RedirectEn ==
    /\ ~ConnCLeafChecksig
    /\ cState = "unspent"
    /\ memC \cap {"canonGood", "canonBadPi"} # {}
    /\ "foreign" \notin memC
MalleateEn ==
    /\ ~PiCommitted
    /\ cState = "unspent"
    /\ "canonGood" \in memC
    /\ "canonBadPi" \notin memC
FrontRunEn ==
    /\ ~VerifierLeafChecksig
    /\ vState = "unspent"
    /\ "canon" \in memV
    /\ "foreign" \notin memV
\* The verifier job stops once ConnectorD is spent (node/src/aggregates/graph_pegout_jobs.rs:755-765).
ChallengeEn ==
    /\ vState = "unspent"
    /\ memV = {}
    /\ ~challenged
    /\ dState = "unspent"
\* Disprove is valid in block vaAt + dcsv (CSV); the action lands in now+1.
DisproveEn ==
    /\ pState = "unspent"
    /\ dState = "unspent"
    /\ now + 1 >= vaAt + dcsv
WCEn ==
    /\ pState = "unspent"
    /\ proofValid
    /\ ~piBad
Take2En ==
    /\ dState = "unspent"
    /\ now + 1 >= assertAt + t2csv

\* Attacker moves in Script mode: a watcher against a valid proof, the
\* cheating operator against an invalid one.
AttackEn ==
    IF proofValid
    THEN \/ RedirectEn \/ MalleateEn
         \/ ChallengeEn /\ ~VerifierJudgesInvalid
         \/ DisproveEn /\ ~VerifierJudgesInvalid
    ELSE FrontRunEn \/ Take2En

(* Honest deadlines. An action at tip `now` lands in block now+1; a CSV-k  *)
(* output created in block c is spendable from block c+k, and the node     *)
(* fires at tip >= c+k (is_timelock_ready, node/src/aggregates/            *)
(* graph_scan.rs:474-476). Mine is blocked while a deadline is due.        *)

\* Verifier: broadcast ChallengeAssert at tip <= assertAt + react + evalV - 1.
ChallengeDue ==
    /\ ChallengeEn /\ VerifierJudgesInvalid
    /\ now >= assertAt + react + evalV - 1
\* Operator: Wrongly-Challenged in block <= vaAt + react + evalO + incl.
WCDue ==
    /\ WCEn
    /\ now + 1 >= vaAt + react + evalO + incl
\* Verifier node: fires at tip >= vaAt + dcsv, mined by +react+incl.
DisproveDue ==
    /\ DisproveEn /\ challenged /\ VerifierJudgesInvalid
    /\ now + 1 >= vaAt + dcsv + react + incl
\* Honest operator node: Take2 at tip >= assertAt + t2csv, mined by +react+incl.
Take2Due ==
    /\ Take2En /\ proofValid
    /\ now + 1 >= assertAt + t2csv + react + incl

HonestDue == ChallengeDue \/ WCDue \/ DisproveDue \/ Take2Due

\* Script mode: an honest action happens exactly at its deadline, after
\* every attacker move possible at this tip.
HonestSlot(due) == Script => (due /\ ~AttackEn)


---------------------------------------------------------------------------
(* Attacker moves (a third-party watcher, or the operator itself for C3).  *)

\* Action: C4 - a watcher copies OperatorAssert's WOTS witness into its own higher-fee tx spending ConnectorC.
\* Source: environment; ConnectorC leaf 1 has no OP_CHECKSIG: goat connector_c.rs:45-47, assert_scripts.rs:52-60.
RedirectConnectorC ==
    /\ RedirectEn
    /\ Script => proofValid
    /\ memC' = memC \cup {"foreign"}
    /\ UNCHANGED <<params, now, cState, piBad, assertAt, memV, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

\* Action: a same-txid OperatorAssert with swapped pi2/pi3 competes for the miner slot.
\* Source: environment (relay or miner); unsigned OP_2DROP items of goat assert_scripts.rs:52-60, crates/bitvm-gc/src/babe_adapter.rs:384-388.
MalleatePi ==
    /\ MalleateEn
    /\ Script => proofValid
    /\ memC' = memC \cup {"canonBadPi"}
    /\ UNCHANGED <<params, now, cState, piBad, assertAt, memV, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

\* Action: C3 - the operator copies the ChallengeAssert witness into a higher-fee tx with other outputs, killing Disprove_j.
\* Source: environment; VerifierConnector leaf 0 has no OP_CHECKSIG: goat assert_connectors.rs:41-44, assert_scripts.rs:69-101.
FrontRunVerifierAssert ==
    /\ FrontRunEn
    /\ Script => ~proofValid
    /\ memV' = memV \cup {"foreign"}
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

---------------------------------------------------------------------------
(* Verifier.                                                               *)

\* Action: the verifier broadcasts its ChallengeAssert; due if it judges the proof invalid, a malicious move otherwise.
\* Source: verifier_assert(), node/src/aggregates/graph_pegout_jobs.rs:736-884 (proof check :857-864, broadcast :888-980).
Challenge ==
    /\ ChallengeEn
    /\ VerifierJudgesInvalid => HonestSlot(ChallengeDue)
    /\ memV' = {"canon"}
    /\ vBcastAt' = now
    /\ challenged' = TRUE
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, vState, vaAt,
                   pState, dState>>

\* Action: presigned Disprove_j (ProverConnector_j leaf 1 + ConnectorD leaf 1) confirms; any committee member may send it from block vaAt + dcsv.
\* Source: disprove(), node/src/aggregates/graph_pegout_jobs.rs:983-1023; trigger node/src/aggregates/graph_scan.rs:742-788 (:780).
Disprove ==
    /\ DisproveEn
    /\ VerifierJudgesInvalid => HonestSlot(DisproveDue)
    /\ pState' = "disprove"
    /\ dState' = "disprove"
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt,
                   vState, vaAt, challenged>>

---------------------------------------------------------------------------
(* Operator.                                                               *)

\* Action: the operator answers a challenge of a valid proof (ProverConnector_j leaf 0); needs intact on-chain pi2/pi3.
\* Source: wrongly_challenged(), node/src/aggregates/graph_pegout_jobs.rs:1327-1465 (on-chain pi2/pi3 :1384, :1417-1423).
WronglyChallenged ==
    /\ WCEn
    /\ HonestSlot(WCDue)
    /\ pState' = "wronglyChallenged"
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt,
                   vState, vaAt, dState, challenged>>

\* Action: Take2 via ConnectorD leaf 0 confirms: settlement for an honest operator, the payout for a cheater.
\* Source: take2(), node/src/aggregates/graph_pegout_jobs.rs:1500-1537; trigger take2_ready(), node/src/aggregates/graph_scan.rs:792-843.
Take2 ==
    /\ Take2En
    /\ proofValid => HonestSlot(Take2Due)
    /\ dState' = "take2"
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt,
                   vState, vaAt, pState, challenged>>

---------------------------------------------------------------------------
(* Miner.                                                                  *)

CForced == cState = "unspent" /\ memC \cap {"canonGood", "canonBadPi"} # {} /\ now >= incl
CBest == IF "foreign" \in memC THEN {"foreign"} ELSE memC
CPicks ==
    IF cState # "unspent" \/ memC = {} THEN {"none"}
    ELSE IF Script THEN (IF "foreign" \in memC \/ CForced THEN CBest ELSE {"none"})
    ELSE CBest \cup (IF CForced THEN {} ELSE {"none"})

VForced == vState = "unspent" /\ "canon" \in memV /\ now >= vBcastAt + incl
VBest == IF "foreign" \in memV THEN "foreign" ELSE "canon"
VPicks ==
    IF vState # "unspent" \/ memV = {} THEN {"none"}
    ELSE IF Script THEN (IF "foreign" \in memV \/ VForced THEN {VBest} ELSE {"none"})
    ELSE {VBest} \cup (IF VForced THEN {} ELSE {"none"})

\* Busy: something can act or is in a mempool. When idle, Mine jumps to the
\* next CSV maturity; the skipped blocks only change `now` (sound).
Busy ==
    \/ cState = "unspent" /\ memC # {}
    \/ vState = "unspent" /\ memV # {}
    \/ RedirectEn \/ MalleateEn \/ FrontRunEn \/ ChallengeEn
    \/ DisproveEn \/ WCEn \/ Take2En
Min(S) == CHOOSE m \in S : \A x \in S : m <= x
NextMaturity ==
    Min({Horizon}
        \cup (IF pState = "unspent" /\ dState = "unspent" THEN {vaAt + dcsv - 1} ELSE {})
        \cup (IF dState = "unspent" THEN {assertAt + t2csv - 1} ELSE {}))

\* Action: one block; per outpoint a foreign copy outbids the canonical tx, an honest tx is mined within incl blocks.
\* Source: Bitcoin consensus and miner fee policy.
Mine ==
    /\ now < Horizon
    /\ ~HonestDue
    /\ Script => ~AttackEn
    /\ now' = IF Busy THEN now + 1 ELSE NextMaturity
    /\ \E cp \in CPicks, vp \in VPicks :
        /\ cState' = CASE cp = "none" -> cState
                       [] cp = "foreign" -> "foreign"
                       [] OTHER -> "canon"
        /\ piBad' = (piBad \/ cp = "canonBadPi")
        /\ memC' = IF cp = "none" THEN memC ELSE {}
        /\ assertAt' = IF cp \in {"canonGood", "canonBadPi"} THEN now + 1 ELSE assertAt
        /\ dState' = IF cp \in {"canonGood", "canonBadPi"} THEN "unspent" ELSE dState
        /\ vState' = IF cp \in {"canonGood", "canonBadPi"} THEN "unspent"
                     ELSE CASE vp = "none" -> vState
                            [] vp = "foreign" -> "foreign"
                            [] OTHER -> "canon"
        /\ memV' = IF vp = "none" THEN memV ELSE {}
        /\ pState' = IF vp = "canon" THEN "unspent" ELSE pState
        /\ vaAt' = IF vp = "canon" THEN now + 1 ELSE vaAt
    /\ UNCHANGED <<params, vBcastAt, challenged>>

\* Action: stutter at the horizon (not a deadlock).
\* Source: model bound.
Halt == Done /\ UNCHANGED vars

Next ==
    \/ RedirectConnectorC
    \/ MalleatePi
    \/ FrontRunVerifierAssert
    \/ Challenge
    \/ Disprove
    \/ WronglyChallenged
    \/ Take2
    \/ Mine
    \/ Halt

\* No fairness: honest progress is forced by the deadline guards on Mine.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* An invalid proof is never paid out by Take2.
NoTake2WithInvalidProof == ~(~proofValid /\ dState = "take2")

\* A challenging verifier's connector is never spent by a foreign tx, so Disprove_j stays valid.
HonestVerifierCanDisprove == (~proofValid /\ challenged) => vState # "foreign"

\* An honest operator never loses ConnectorC to a foreign tx and is never Disproved.
HonestOperatorCanSettle ==
    proofValid => (cState # "foreign" /\ dState # "disprove")

\* Script run, current scripts: C4 beats a valid proof; Take2 pays an invalid one, under ParamsOK only via C3.
AttackWinsForAllParams ==
    Done =>
      /\ proofValid => ~HonestOperatorCanSettle
      /\ ~proofValid => /\ dState = "take2"
                        /\ ParamsOK => (challenged /\ vState = "foreign")

\* Script run, fix design: invalid proof paid iff ~CondDisprove; given CondDisprove, honest operator Disproved iff ~CondWC.
MarginExact ==
    Done =>
      /\ (proofValid /\ CondDisprove) => (HonestOperatorCanSettle <=> CondWC)
      /\ ~proofValid => (NoTake2WithInvalidProof <=> CondDisprove)

====
