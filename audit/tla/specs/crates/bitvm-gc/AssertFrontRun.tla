---- MODULE AssertFrontRun ----
(***************************************************************************)
(* Witness-copy front-running of the two assert transactions (audit C3,    *)
(* C4), pi2/pi3 witness malleability, and the timing margins the assert    *)
(* stage needs (Wrongly-Challenged vs Disprove, Disprove vs Take2) over    *)
(* EVERY timelock / delay combination, not one hand-picked point.          *)
(*                                                                         *)
(* Ground truth: external goat crate, checkout bab46c2 (goat/src/...):     *)
(*                                                                         *)
(*  VerifierConnector leaf 0 (connectors/assert_connectors.rs:41-44) =     *)
(*  verify_verifier_assert_script_768_wire (assert_scripts.rs:69-101):     *)
(*  768 x {OP_HASH160 <true|false label hash> OP_EQUAL...} then            *)
(*  Wots96::checksig_verify(operator WOTS pk) ... OP_TRUE. NO OP_CHECKSIG  *)
(*  over the spending tx. VerifierAssert (transactions/assert.rs:211-245)  *)
(*  is version 2, carries NO signature at all (verifier_publish_labels,    *)
(*  assert.rs:247-264, only pushes labels + the operator's WOTS witness),  *)
(*  outputs = [ProverConnector_j, P2A]. The presigned Disprove_j           *)
(*  (assert.rs:316-355, SIGHASH_NONE n-of-n, assert.rs:364/407) spends     *)
(*  ProverConnector_j leaf 1 + ConnectorD leaf 1, and every taproot        *)
(*  sighash (NONE included) commits to all input OUTPOINTS. So Disprove_j  *)
(*  is valid only if ProverConnector_j exists at <canonical VerifierAssert *)
(*  txid>:0. Witness data is not part of the txid, but outputs are.        *)
(*                                                                         *)
(*  => C3: once the honest verifier's ChallengeAssert (= VerifierAssert,   *)
(*  node/src/aggregates/graph_pegout_jobs.rs:977 broadcast_tx_with_cpfp)   *)
(*  is in the mempool, its labels + WOTS witness are public; anyone (the   *)
(*  cheating operator) builds tx' spending the same VerifierConnector_j    *)
(*  outpoint with the copied witness and DIFFERENT outputs at a higher     *)
(*  fee. Miners take tx'. ProverConnector_j never exists, Disprove_j is    *)
(*  permanently invalid; the node's disprove job (graph_pegout_jobs.rs:    *)
(*  983-1022) polls get_tx(challenge_assert_txid) forever. After the       *)
(*  ConnectorD CSV the operator takes Take2 with an INVALID proof.         *)
(*                                                                         *)
(*  ConnectorC leaf 1 (connectors/connector_c.rs:45-47) =                  *)
(*  verify_prover_assert_script_768_wire (assert_scripts.rs:52-60):        *)
(*    OP_2DROP  Wots96::checksig_verify_and_clear_stack  OP_TRUE           *)
(*  again NO OP_CHECKSIG. OperatorAssert (assert.rs:67-117, v2, unsigned   *)
(*  apart from the WOTS witness, assert.rs:119-142) outputs =              *)
(*  [VerifierConnector_0..n-1, ConnectorD, P2A].                           *)
(*                                                                         *)
(*  => C4: any watcher copies the honest operator's OperatorAssert witness *)
(*  into tx'' spending ConnectorC with arbitrary outputs (it even pockets  *)
(*  C's value, operator_assert_input_amount, base.rs:99-104). ConnectorD   *)
(*  is never created -> Take2 (take2.rs:56-77, ConnectorD leaf 0) is       *)
(*  impossible; Take1 (take1.rs:79-80, ConnectorC leaf 0) is dead because  *)
(*  C is spent. The honest operator can never settle.                      *)
(*                                                                         *)
(*  pi2/pi3: the two items under OP_2DROP are the Groth16 B and C points   *)
(*  (bitvm-gc babe_adapter.rs:384-388); they are not covered by the WOTS   *)
(*  signature nor by any sighash (sighashes never cover witness), and      *)
(*  swapping them does NOT change the txid. The node reads them back from  *)
(*  the CONFIRMED witness in two places:                                   *)
(*   - verifier: extract_operator_assert_witness_for_challenge             *)
(*     (crates/bitvm-gc/src/verifier/api.rs:226-244, malformed -> empty)   *)
(*     then verify_operator_assert_proof (graph_pegout_jobs.rs:862): bad   *)
(*     pi => "invalid proof" => the honest verifier challenges;            *)
(*   - operator: wrongly_challenged (graph_pegout_jobs.rs:1327-1420) calls *)
(*     extract_operator_assert_witness on the ON-CHAIN tx (:1384, api.rs:  *)
(*     205-225 bails on malformed pi) and recovers the proof from it       *)
(*     (:1416-1422), not from its locally stored pi2/pi3.                  *)
(*  So a swapped pi2/pi3 that wins the race to a miner (Core keeps the     *)
(*  first-seen wtxid; an attacker can deliver its variant directly to a    *)
(*  miner, and the miner itself can swap) makes an honest operator lose to *)
(*  Disprove. Adding a CHECKSIG to C leaf 1 does NOT fix this (a sighash   *)
(*  does not cover witness items) - see AssertFrontRun/PiMalleable.cfg.     *)
(*                                                                         *)
(* Fix designs (constants):                                                *)
(*  VerifierLeafChecksig: VerifierConnector leaf 0 additionally requires   *)
(*    <n-of-n> OP_CHECKSIGVERIFY, presigned at graph setup with            *)
(*    SIGHASH_ALL (NOT ...|ANYONECANPAY: adding an input changes the txid) *)
(*    over the canonical VerifierAssert -> the witness is bound to that    *)
(*    exact tx, a copy in any other tx fails. Fee bump stays via P2A CPFP. *)
(*  ConnCLeafChecksig: ConnectorC leaf 1 additionally requires             *)
(*    <operator> OP_CHECKSIGVERIFY with SIGHASH_ALL over OperatorAssert.   *)
(*  PiCommitted: pi2/pi3 are bound to signed data (e.g. carried in a data  *)
(*    output of OperatorAssert, covered by the operator's SIGHASH_ALL      *)
(*    signature) instead of free OP_2DROP witness items. (A node-only      *)
(*    alternative for the operator side is to use the locally stored       *)
(*    pi2/pi3 in wrongly_challenged; the verifier would still challenge    *)
(*    wrongly, which then fails, at the verifier's own cost.)              *)
(*                                                                         *)
(* Timing (node, dev 60562f8). All heights are block heights; `now` is the *)
(* chain tip and an action taken at tip `now` lands in block now+1. A      *)
(* CSV-k output created in block c is spendable in block >= c+k.           *)
(*  - The node fires a timelocked defence when tip >= c + k                *)
(*    (graph_scan.rs:474-476 is_timelock_ready, :780 Wrongly-Challenge-    *)
(*    Timeout -> disprove job graph_pegout_jobs.rs:1006), i.e. one block   *)
(*    after the mempool would accept it; an attacker uses block c+k.       *)
(*  - Honest reaction: an event confirmed in block e is answered by a tx   *)
(*    in block <= e + react + eval + incl, where react >= 1 counts the     *)
(*    next block (ReactionBlocks), incl = extra blocks to be mined         *)
(*    (InclusionBlocks) and eval = local GC/proof work before the tx can   *)
(*    be built: evalV = verifier verify_operator_assert_proof +            *)
(*    build_real_challenge_assert_witness (graph_pegout_jobs.rs:860-955),  *)
(*    evalO = operator recover_real_wrongly_challenged_witness (GC         *)
(*    evaluation, :1438). eval is NOT part of the node's                   *)
(*    ProtocolTimingBudget (timelocks.rs:83-95); the shipped configs use   *)
(*    eval = 0 and the report gives the eval each network tolerates.       *)
(*  - ChallengeAssert is assumed UNGATED (fires on OperatorAssert          *)
(*    confirmation): today it waits for commit-pubin (graph_pegout_jobs.rs:*)
(*    766-778), which is DisputeObligations.tla's C1 finding, not this     *)
(*    module's. ConnectorF is assumed matured (Take2 = ConnectorD race).   *)
(*                                                                         *)
(* Margins (derived from the semantics above, checked exact by             *)
(* AssertFrontRun/Exact.cfg):                                               *)
(*  CondWC:  react + incl + evalO + 1 <= dcsv                              *)
(*     honest Wrongly-Challenged (block <= vaAt+react+evalO+incl) strictly *)
(*     before a malicious verifier's Disprove can be mined (vaAt+dcsv; a   *)
(*     same-block tie goes to the attacker).                               *)
(*  CondDisprove:  dcsv + 2*(react+incl) + evalV + 1 <= t2csv              *)
(*     ChallengeAssert (block <= assertAt+react+evalV+incl), then the      *)
(*     node's Disprove (block <= vaAt+dcsv+react+incl) strictly before     *)
(*     Take2 (block assertAt+t2csv). Two action windows, not one.          *)
(*  ParamsOK == CondWC /\ CondDisprove.                                    *)
(*  The node's own acceptance check (timelocks.rs:213-226,                 *)
(*  validate_timelock_config) is ValidateOK: dcsv >= react+incl+safety and *)
(*  t2csv - dcsv >= react+incl+safety. It counts ONE action window between *)
(*  prover_connector and connector_d and no strict-tie block, so it does   *)
(*  NOT imply ParamsOK (AssertFrontRun/ValidateGap.cfg).                    *)
(*                                                                         *)
(* Parameters are FROZEN variables chosen in Init, either from the swept   *)
(* ranges (UseShipped = FALSE) or from ShippedTimelockValues for each net  *)
(* in NetSet (UseShipped = TRUE: dcsv = ProverConnector, t2csv =           *)
(* ConnectorD, react/incl/safety = Reaction/Inclusion/SafetyBlocks).       *)
(* ParamSel restricts Init: "all" | "ok" (ParamsOK) | "notOK" |            *)
(* "validNotOK" (ValidateOK /\ ~ParamsOK).                                 *)
(* Why the sweep ranges are exhaustive: every guard compares `now` with an *)
(* event height (0, assertAt, vBcastAt, vaAt) plus a non-negative linear   *)
(* form of the parameters; honest actors pick any time in their window,    *)
(* the attacker its earliest. For the fix designs the verdict of every     *)
(* property is decided by CondDisprove (invalid proof) and CondWC (valid   *)
(* proof, given CondDisprove) alone - AssertFrontRun/Exact.cfg proves       *)
(* "violated iff the margin fails" for every swept tuple; C3/C4 do not     *)
(* depend on the parameters at all (AssertFrontRun/AllParams.cfg). So the   *)
(* sweep only has to realise both margins at every class (margin <= -1,    *)
(* = 0, >= +1), all four combinations, for every zero/non-zero split of    *)
(* the delay over react                                                    *)
(* (which also opens the front-run window), incl and eval:                 *)
(* react 1..2, incl 0..1, evalV/evalO 0..1 (LHS of CondWC 2..5), dcsv 1..6 *)
(* (brackets 2..5 by one on each side), t2csv 1..15 (LHS of CondDisprove   *)
(* 4..14, bracketed). The shipped configs check the real numbers directly. *)
(*                                                                         *)
(* Script = TRUE turns the model into a per-tuple worst-case run: every    *)
(* honest action happens exactly at its deadline, every attacker move of   *)
(* the scenario's strategy as early as possible. Script runs are a subset  *)
(* of the normal behaviours (extra guards only), so an invariant of the    *)
(* form Done => Bad proves the attack succeeds for EVERY parameter tuple   *)
(* (TLC's ordinary counterexample only shows one tuple). CHECK_DEADLOCK    *)
(* makes sure every tuple actually reaches Done.                           *)
(*                                                                         *)
(* Abstractions: one verifier slot j; Bitcoin is "mempool candidates per   *)
(* outpoint + Mine picks"; a copied-witness tx is only constructible when  *)
(* the leaf has no CHECKSIG over the tx; the attacker (stake = the whole   *)
(* peg-in) always outbids the honest fixed-fee VerifierAssert + CPFP and   *)
(* wins every same-block tie; the honest OperatorAssert / VerifierAssert   *)
(* are mined within incl blocks of their broadcast unless outbid.          *)
(* Disprove/Take2/Wrongly-Challenged are atomic broadcast+confirm with     *)
(* honest deadlines (pinning of those is DefenderTxPinning.tla's job).     *)
(* Reorgs (SafetyBlocks) are not modeled; safety only enters ValidateOK.   *)
(*                                                                         *)
(* Code scope (current tree): node/src/aggregates/graph_pegout_jobs.rs     *)
(* (verifier_assert, broadcast_verifier_challenge_assert_tx, disprove,     *)
(* prover_assert, wrongly_challenged, take2), node/src/aggregates/         *)
(* graph_scan.rs (is_timelock_ready, wrongly_challenge_timeout,            *)
(* take2_ready), node/src/aggregates/graph_pegout.rs (job dispatch),       *)
(* crates/bitvm-gc/src/verifier/api.rs (witness extraction),               *)
(* crates/bitvm-gc/src/timelocks.rs (budget, validate_timelock_config),    *)
(* goat bab46c2 scripts/transactions as cited above.                       *)
(*                                                                         *)
(* Configs and tiers (checks.txt):                                         *)
(*  live     AssertFrontRun(.cfg|Shipped)  C3 on current scripts           *)
(*           AssertFrontRunC4(.cfg|Shipped)  C4 on current scripts         *)
(*           AssertFrontRunPiMalleable(.cfg|Shipped)  pi2/pi3 residual     *)
(*           (both CHECKSIG fixes on, pi still free)                       *)
(*  pass     AssertFrontRunAllParams  current scripts: C3/C4 win for every *)
(*           parameter tuple (Script lemma)                                *)
(*  design   AssertFrontRunFixed, ...C4Fixed (fix over all of ParamsOK),   *)
(*           ...C4FixedShipped (Bitcoin/Testnet4/Signet), ...Exact         *)
(*           (ParamsOK is exact)                                           *)
(*  boundary AssertFrontRunBoundary (outside ParamsOK), ...Regtest         *)
(*           (shipped Regtest values), ...ValidateGap (accepted by the     *)
(*           node's validate_timelock_config, outside ParamsOK)            *)
(***************************************************************************)
EXTENDS Naturals, ShippedTimelockValues

CONSTANTS
    ProofValidity,         \* subset of BOOLEAN: is the operator's asserted Groth16 proof valid?
    VerifierLeafChecksig,  \* FIX C3: n-of-n CHECKSIG on VerifierConnector leaf 0
    ConnCLeafChecksig,     \* FIX C4: operator CHECKSIG on ConnectorC leaf 1
    PiCommitted,           \* FIX pi: pi2/pi3 bound to signed data
    UseShipped,            \* parameters from ShippedTimelockValues (per net in NetSet)
    NetSet,                \* subset of Networks swept when UseShipped
    DisproveCSVRange,      \* ProverConnector leaf 1 CSV (timelock_config.prover_connector)
    Take2CSVRange,         \* ConnectorD leaf 0 CSV (timelock_config.connector_d)
    ReactionRange,         \* reaction blocks (>= 1, counts the next block)
    InclusionRange,        \* extra blocks to get a broadcast tx mined
    SafetyRange,           \* safety blocks (only used by ValidateOK)
    EvalVRange,            \* verifier proof check + challenge witness build, blocks
    EvalORange,            \* operator GC evaluation for Wrongly-Challenged, blocks
    ParamSel,              \* Init filter: "all" | "ok" | "notOK" | "validNotOK"
    Script                 \* worst-case scripted run (see header)

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

\* Every event of interest has happened by then (see Script runs).
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
(* Parameter conditions (over the frozen parameters).                      *)

CondWC       == react + incl + evalO + 1 <= dcsv
CondDisprove == dcsv + 2 * (react + incl) + evalV + 1 <= t2csv
ParamsOK     == CondWC /\ CondDisprove

\* timelocks.rs validate_timelock_config, the two checks on these CSVs
\* (plus the reaction floor every timelock gets); gap uses saturating_sub.
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

\* The operator has just broadcast OperatorAssert (tip 0, after a Challenge
\* on ConnectorA) with its honestly encoded pi2/pi3.
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
(* Enabling conditions (state predicates), shared by actions, deadlines    *)
(* and the Script scheduler.                                               *)

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
\* The verifier job stops once ConnectorD is spent (graph_pegout_jobs.rs:755-764).
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

\* Attacker moves of the scripted strategy: a watcher against an honest
\* operator (valid proof), the cheating operator itself (invalid proof).
AttackEn ==
    IF proofValid
    THEN \/ RedirectEn \/ MalleateEn
         \/ ChallengeEn /\ ~VerifierJudgesInvalid
         \/ DisproveEn /\ ~VerifierJudgesInvalid
    ELSE FrontRunEn \/ Take2En

(* Honest deadlines. Mine (tip now -> now+1) is blocked while one is due.  *)

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

\* In Script mode an honest action happens exactly at its deadline and only
\* after the attacker has made every move it can make at this tip.
HonestSlot(due) == Script => (due /\ ~AttackEn)

---------------------------------------------------------------------------
(* Attacker moves (third-party watcher, or the operator itself for C3).    *)

\* Action: C4 - a watcher copies the honest OperatorAssert's WOTS witness
\* (public once in the mempool) into a higher-fee tx spending ConnectorC
\* with its own outputs; possible only while ConnectorC leaf 1 has no
\* CHECKSIG over the spending tx.
\* Source: environment (any mempool observer); script: verify_prover_assert_
\* script_768_wire() in goat assert_scripts.rs:52-60 (ConnectorC leaf 1,
\* connector_c.rs:45-47) has no OP_CHECKSIG.
RedirectConnectorC ==
    /\ RedirectEn
    /\ Script => proofValid
    /\ memC' = memC \cup {"foreign"}
    /\ UNCHANGED <<params, now, cState, piBad, assertAt, memV, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

\* Action: pi2/pi3 swap - a variant of the honest OperatorAssert with
\* swapped/malformed pi2/pi3 (same txid, other wtxid) competes for the
\* same miner slot.
\* Source: environment (relay / miner); the OP_2DROP items of
\* verify_prover_assert_script_768_wire() in goat assert_scripts.rs:52-60
\* are not covered by any signature (build_assert_witness() in
\* crates/bitvm-gc/src/babe_adapter.rs:384-388 writes them).
MalleatePi ==
    /\ MalleateEn
    /\ Script => proofValid
    /\ memC' = memC \cup {"canonBadPi"}
    /\ UNCHANGED <<params, now, cState, piBad, assertAt, memV, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

\* Action: C3 - the cheating operator copies the honest verifier's
\* ChallengeAssert witness (labels + operator WOTS sig) into a higher-fee
\* tx spending VerifierConnector_j with other outputs, so ProverConnector_j
\* never exists at the canonical txid and Disprove_j is dead.
\* Source: environment (the operator); script: verify_verifier_assert_
\* script_768_wire() in goat assert_scripts.rs:69-101 (VerifierConnector
\* leaf 0, assert_connectors.rs:41-44) has no OP_CHECKSIG.
FrontRunVerifierAssert ==
    /\ FrontRunEn
    /\ Script => ~proofValid
    /\ memV' = memV \cup {"foreign"}
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, vBcastAt, vState,
                   vaAt, pState, dState, challenged>>

---------------------------------------------------------------------------
(* Verifier.                                                               *)

\* Action: the verifier broadcasts its ChallengeAssert (canonical
\* VerifierAssert) into the mempool. Mandatory within its deadline when it
\* judges the confirmed proof invalid; a malicious verifier may also
\* challenge a valid proof at any time (an attacker move in Script mode).
\* Source: verifier_assert() in node/src/aggregates/graph_pegout_jobs.rs:736
\* (proof check :857-864), broadcast_verifier_challenge_assert_tx() :888-980
\* (broadcast_tx_with_cpfp :977); scheduled on AssertSent,
\* node/src/aggregates/graph_pegout.rs:274.
Challenge ==
    /\ ChallengeEn
    /\ VerifierJudgesInvalid => HonestSlot(ChallengeDue)
    /\ memV' = {"canon"}
    /\ vBcastAt' = now
    /\ challenged' = TRUE
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, vState, vaAt,
                   pState, dState>>

\* Action: presigned Disprove_j (ProverConnector_j leaf 1, n-of-n + CSV, and
\* ConnectorD leaf 1) lands; needs ProverConnector_j at the canonical
\* VerifierAssert outpoint. Any committee member may send it from block
\* vaAt + dcsv on; the honest verifier node is bounded by DisproveDue.
\* Source: disprove() in node/src/aggregates/graph_pegout_jobs.rs:983-1023,
\* scheduled by wrongly_challenge_timeout() in node/src/aggregates/
\* graph_scan.rs:742-788 (tip >= vaAt + dcsv, :780) via graph_pegout.rs:276.
Disprove ==
    /\ DisproveEn
    /\ VerifierJudgesInvalid => HonestSlot(DisproveDue)
    /\ pState' = "disprove"
    /\ dState' = "disprove"
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt,
                   vState, vaAt, challenged>>

---------------------------------------------------------------------------
(* Operator.                                                               *)

\* Action: Wrongly-Challenged (ProverConnector_j leaf 0 with the GC output
\* label preimage) lands, answering a challenge of a valid proof. Only
\* possible for a valid proof whose ON-CHAIN pi2/pi3 are intact: the node
\* rebuilds the proof from the confirmed witness.
\* Source: wrongly_challenged() in node/src/aggregates/graph_pegout_jobs.rs:
\* 1327-1465 (on-chain witness :1384, proof recovery :1416-1422, GC eval
\* :1432); scheduled on ChallengeAssertSent, graph_pegout.rs:275.
WronglyChallenged ==
    /\ WCEn
    /\ HonestSlot(WCDue)
    /\ pState' = "wronglyChallenged"
    /\ UNCHANGED <<params, now, memC, cState, piBad, assertAt, memV, vBcastAt,
                   vState, vaAt, dState, challenged>>

\* Action: Take2 via ConnectorD leaf 0 after its CSV (ConnectorF assumed
\* matured) lands: settlement for an honest operator, the payout of the
\* attack for a cheating one.
\* Source: take2() in node/src/aggregates/graph_pegout_jobs.rs:1500-1537
\* (is_take2_timelock_expired, node/src/utils/btc.rs:34-46), scheduled by
\* take2_ready() in node/src/aggregates/graph_scan.rs:792; a cheating
\* operator signs it itself.
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

\* Time abstraction (sound, stuttering only): when no action is enabled or
\* can become enabled before a CSV matures and no tx is waiting in a
\* mempool, every block until the next maturity changes nothing but `now`,
\* so Mine jumps there in one step. Nothing in between can act, no deadline
\* can pass (deadlines need an enabled action) and no invariant mentions
\* `now` except through Done (Horizon is a jump target).
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

\* Action: one block. Per outpoint the highest-fee candidate wins (a
\* foreign copy outbids the fixed-fee canonical tx; the two canonical
\* wtxids tie, so either may be mined); an honest tx is mined at the latest
\* incl blocks after its broadcast (in Script mode exactly then, a foreign
\* copy at once). Blocked while an honest deadline is due.
\* Source: Bitcoin consensus + miner fee policy (first-seen / highest-fee).
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

\* Action: end of the horizon - stutter (not a deadlock).
\* Source: model bound (no code).
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

\* No fairness: every property is a safety invariant; honest progress is
\* forced by the deadline guards on Mine, not by WF/SF.
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Safety invariants.                                                      *)

\* C3 / fix timing: an invalid proof is never paid through Take2 while an
\* honest verifier watches.
NoTake2WithInvalidProof == ~(~proofValid /\ dState = "take2")

\* C3: the honest verifier's Disprove stays constructible - its verifier
\* connector is never consumed by a non-canonical tx.
HonestVerifierCanDisprove == (~proofValid /\ challenged) => vState # "foreign"

\* C4 / pi / WC timing: an honest operator with a valid proof is never left
\* unable to settle (ConnectorC taken by a foreign tx) nor Disproved.
HonestOperatorCanSettle ==
    proofValid => (cState # "foreign" /\ dState # "disprove")

\* Script lemma (current scripts): the attack wins for EVERY parameter
\* tuple - C4 against a valid proof; Take2 for an invalid one and, under
\* ParamsOK, only because the in-time ChallengeAssert was front-run (C3).
AttackWinsForAllParams ==
    Done =>
      /\ proofValid => ~HonestOperatorCanSettle
      /\ ~proofValid => /\ dState = "take2"
                        /\ ParamsOK => (challenged /\ vState = "foreign")

\* Script lemma (fix design): the worst-case run fails exactly when its
\* margin fails - Take2 with an invalid proof iff ~CondDisprove; given
\* CondDisprove, the honest operator Disproved iff ~CondWC (with a shorter
\* connector_d its own Take2 lands first). Hence ParamsOK is exact.
MarginExact ==
    Done =>
      /\ (proofValid /\ CondDisprove) => (HonestOperatorCanSettle <=> CondWC)
      /\ ~proofValid => (NoTake2WithInvalidProof <=> CondDisprove)

(* Safety properties (temporal): none.                                     *)
(* Liveness: none (bounded-horizon model; progress is forced by deadlines).*)

====
