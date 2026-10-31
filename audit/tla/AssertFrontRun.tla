---- MODULE AssertFrontRun ----
(***************************************************************************)
(* Witness-copy front-running of the two assert transactions (audit C3,   *)
(* C4) and pi2/pi3 witness malleability.                                  *)
(*                                                                         *)
(* Ground truth: external goat crate, checkout bab46c2 (goat/src/...):     *)
(*                                                                         *)
(*  VerifierConnector leaf 0 (connectors/assert_connectors.rs:247-250) =   *)
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
(*     (:1419-1421), not from its locally stored pi2/pi3.                  *)
(*  So a swapped pi2/pi3 that wins the race to a miner (Core keeps the     *)
(*  first-seen wtxid; an attacker can deliver its variant directly to a    *)
(*  miner, and the miner itself can swap) makes an honest operator lose to *)
(*  Disprove. Adding a CHECKSIG to C leaf 1 does NOT fix this (a sighash   *)
(*  does not cover witness items) - see AssertFrontRunPiMalleable.cfg.     *)
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
(* Abstractions: one verifier slot j; Bitcoin is "mempool candidates per   *)
(* outpoint + Mine picks the highest-fee candidate"; a copied-witness tx   *)
(* is only constructible when the leaf has no CHECKSIG over the tx; the    *)
(* attacker (stake = the whole peg-in) always outbids the honest fixed-fee *)
(* VerifierAssert + CPFP; honest actors act before the next block (the     *)
(* timelock margin itself is Take2DisproveRace.tla's job, so here          *)
(* DisproveCSV + reaction < Take2CSV). Disprove/Take2/Wrongly-Challenged   *)
(* are modeled as atomic broadcast+confirm (pinning of those is            *)
(* DefenderTxPinning.tla's job).                                           *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    ProofValidity,         \* subset of BOOLEAN: is the operator's asserted Groth16 proof valid?
    VerifierLeafChecksig,  \* FIX C3
    ConnCLeafChecksig,     \* FIX C4
    PiCommitted,           \* FIX pi2/pi3 malleability
    DisproveCSV,           \* ProverConnector leaf 1 CSV (timelock_config.prover_connector)
    Take2CSV,              \* ConnectorD leaf 0 CSV (timelock_config.connector_d)
    MaxT

ASSUME DisproveCSV + 1 < Take2CSV   \* the margin Take2DisproveRace.tla verifies

VARIABLES
    now,
    proofValid,  \* chosen once in Init
    memC,        \* mempool candidates spending ConnectorC
    cState,      \* "unspent" | "canon" (canonical OperatorAssert) | "foreign"
    piBad,       \* the CONFIRMED OperatorAssert carries swapped/malformed pi2/pi3
    assertAt,    \* height the canonical OperatorAssert confirmed
    memV,        \* mempool candidates spending VerifierConnector_j
    vState,      \* "none" | "unspent" | "canon" (canonical VerifierAssert) | "foreign"
    vaAt,        \* height the canonical VerifierAssert confirmed
    pState,      \* ProverConnector_j @ canonical VerifierAssert txid: "none" | "unspent" | "wronglyChallenged" | "disprove"
    dState,      \* ConnectorD @ canonical OperatorAssert txid: "none" | "unspent" | "take2" | "disprove"
    challenged   \* the verifier broadcast a ChallengeAssert (VerifierAssert)

vars == <<now, proofValid, memC, cState, piBad, assertAt, memV, vState, vaAt,
          pState, dState, challenged>>

CCands == {"canonGood", "canonBadPi", "foreign"}
VCands == {"canon", "foreign"}

TypeOK ==
    /\ now \in 0..MaxT
    /\ proofValid \in BOOLEAN
    /\ memC \subseteq CCands
    /\ cState \in {"unspent", "canon", "foreign"}
    /\ piBad \in BOOLEAN
    /\ assertAt \in 0..MaxT
    /\ memV \subseteq VCands
    /\ vState \in {"none", "unspent", "canon", "foreign"}
    /\ vaAt \in 0..MaxT
    /\ pState \in {"none", "unspent", "wronglyChallenged", "disprove"}
    /\ dState \in {"none", "unspent", "take2", "disprove"}
    /\ challenged \in BOOLEAN

\* The operator has just broadcast OperatorAssert (after a Challenge on
\* ConnectorA) with its honestly encoded pi2/pi3.
Init ==
    /\ now = 0
    /\ proofValid \in ProofValidity
    /\ memC = {"canonGood"}
    /\ cState = "unspent"
    /\ piBad = FALSE
    /\ assertAt = 0
    /\ memV = {}
    /\ vState = "none"
    /\ vaAt = 0
    /\ pState = "none"
    /\ dState = "none"
    /\ challenged = FALSE

---------------------------------------------------------------------------
(* Attacker moves (third-party watcher, or the operator itself for C3).   *)

\* C4: copy the OperatorAssert WOTS witness into a tx with other outputs.
\* Only possible because ConnectorC leaf 1 has no CHECKSIG over the tx.
RedirectConnectorC ==
    /\ ~ConnCLeafChecksig
    /\ cState = "unspent"
    /\ memC \cap {"canonGood", "canonBadPi"} # {}
    /\ "foreign" \notin memC
    /\ memC' = memC \cup {"foreign"}
    /\ UNCHANGED <<now, proofValid, cState, piBad, assertAt, memV, vState, vaAt,
                   pState, dState, challenged>>

\* pi2/pi3 swap: same txid (witness only), different wtxid; reaches a miner
\* in competition with the honest wtxid.
MalleatePi ==
    /\ ~PiCommitted
    /\ cState = "unspent"
    /\ "canonGood" \in memC
    /\ "canonBadPi" \notin memC
    /\ memC' = memC \cup {"canonBadPi"}
    /\ UNCHANGED <<now, proofValid, cState, piBad, assertAt, memV, vState, vaAt,
                   pState, dState, challenged>>

\* C3: copy the VerifierAssert witness (labels + operator WOTS sig) into a
\* tx with other outputs. Only possible because VerifierConnector leaf 0 has
\* no CHECKSIG over the tx.
FrontRunVerifierAssert ==
    /\ ~VerifierLeafChecksig
    /\ vState = "unspent"
    /\ "canon" \in memV
    /\ "foreign" \notin memV
    /\ memV' = memV \cup {"foreign"}
    /\ UNCHANGED <<now, proofValid, memC, cState, piBad, assertAt, vState, vaAt,
                   pState, dState, challenged>>

---------------------------------------------------------------------------
(* Verifier (graph_pegout_jobs.rs:840-880 challenge decision; 983-1022     *)
(* disprove).                                                              *)

\* What verify_operator_assert_proof sees: the confirmed witness.
VerifierJudgesInvalid == ~proofValid \/ piBad

\* Broadcast ChallengeAssert. Mandatory (see HonestDue) when the verifier
\* judges the proof invalid; a malicious verifier may also challenge a valid
\* proof, so the action itself is unguarded by the judgement.
Challenge ==
    /\ vState = "unspent"
    /\ memV = {}
    /\ ~challenged
    /\ memV' = {"canon"}
    /\ challenged' = TRUE
    /\ UNCHANGED <<now, proofValid, memC, cState, piBad, assertAt, vState, vaAt,
                   pState, dState>>

\* Presigned Disprove_j: ProverConnector_j leaf 1 (n-of-n + CSV) + ConnectorD
\* leaf 1. Needs ProverConnector_j at the canonical VerifierAssert outpoint.
Disprove ==
    /\ pState = "unspent"
    /\ dState = "unspent"
    /\ now >= vaAt + DisproveCSV
    /\ pState' = "disprove"
    /\ dState' = "disprove"
    /\ UNCHANGED <<now, proofValid, memC, cState, piBad, assertAt, memV, vState,
                   vaAt, challenged>>

---------------------------------------------------------------------------
(* Operator.                                                               *)

\* wrongly_challenged (graph_pegout_jobs.rs:1327): ProverConnector_j leaf 0
\* with the GC output-label preimage. Recoverable only for a valid proof,
\* and the node rebuilds the proof from the ON-CHAIN pi2/pi3 (:1384,:1419).
WronglyChallenged ==
    /\ pState = "unspent"
    /\ proofValid
    /\ ~piBad
    /\ pState' = "wronglyChallenged"
    /\ UNCHANGED <<now, proofValid, memC, cState, piBad, assertAt, memV, vState,
                   vaAt, dState, challenged>>

\* Take2 via ConnectorD leaf 0 after its CSV (ConnectorF assumed matured).
Take2 ==
    /\ dState = "unspent"
    /\ now >= assertAt + Take2CSV
    /\ dState' = "take2"
    /\ UNCHANGED <<now, proofValid, memC, cState, piBad, assertAt, memV, vState,
                   vaAt, pState, challenged>>

---------------------------------------------------------------------------
(* Miner: one block. Per outpoint, the highest-fee candidate wins; a       *)
(* foreign copy outbids the fixed-fee canonical tx; the two canonical      *)
(* wtxids (good / swapped pi) tie on fee, so either may be mined.          *)

CPicks == IF cState # "unspent" \/ memC = {} THEN {"none"}
          ELSE IF "foreign" \in memC THEN {"foreign"} ELSE memC

VPick == IF vState # "unspent" \/ memV = {} THEN "none"
         ELSE IF "foreign" \in memV THEN "foreign" ELSE "canon"

\* Honest obligations that must be met before time advances.
HonestDue ==
    \/ vState = "unspent" /\ memV = {} /\ ~challenged /\ VerifierJudgesInvalid
    \/ pState = "unspent" /\ proofValid /\ ~piBad
    \/ pState = "unspent" /\ dState = "unspent" /\ now >= vaAt + DisproveCSV

Mine ==
    /\ now < MaxT
    /\ ~HonestDue
    /\ now' = now + 1
    /\ \E pick \in CPicks :
        /\ cState' = CASE pick = "none" -> cState
                       [] pick = "foreign" -> "foreign"
                       [] OTHER -> "canon"
        /\ piBad' = (piBad \/ pick = "canonBadPi")
        /\ memC' = IF pick = "none" THEN memC ELSE {}
        /\ assertAt' = IF pick \in {"canonGood", "canonBadPi"} THEN now + 1 ELSE assertAt
        /\ dState' = IF pick \in {"canonGood", "canonBadPi"} THEN "unspent" ELSE dState
        /\ vState' = IF pick \in {"canonGood", "canonBadPi"} THEN "unspent"
                     ELSE CASE VPick = "none" -> vState
                            [] VPick = "foreign" -> "foreign"
                            [] OTHER -> "canon"
    /\ memV' = IF VPick = "none" THEN memV ELSE {}
    /\ pState' = IF VPick = "canon" THEN "unspent" ELSE pState
    /\ vaAt' = IF VPick = "canon" THEN now + 1 ELSE vaAt
    /\ UNCHANGED <<proofValid, challenged>>

Next ==
    \/ RedirectConnectorC \/ MalleatePi \/ FrontRunVerifierAssert
    \/ Challenge \/ Disprove
    \/ WronglyChallenged \/ Take2
    \/ Mine

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* C3: an honest verifier who broadcast a valid ChallengeAssert against an *)
(* invalid proof must never see the operator take Take2.                   *)
NoTake2AfterValidChallenge == ~(~proofValid /\ challenged /\ dState = "take2")

\* ... equivalently its Disprove must stay constructible: the verifier
\* connector must not be consumed by a non-canonical tx.
HonestVerifierCanDisprove == (~proofValid /\ challenged) => vState # "foreign"

\* C4 / pi: an honest operator with a valid proof must never be put in a
\* state where settlement is impossible (ConnectorC consumed by a foreign tx
\* => no ConnectorD, no Take1) or where it is Disproved.
HonestOperatorCanSettle ==
    proofValid => (cState # "foreign" /\ dState # "disprove")

====
