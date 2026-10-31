---- MODULE DisputeObligations ----
(***************************************************************************)
(* Challenge-path obligations of the honest nodes after a Challenge, on     *)
(* dev @ 60562f8 (the #476 refactor into event-sourced aggregates):        *)
(* finding C1 (the watchtower branches and commit-pubin gate every honest  *)
(* response) and finding C2 (an early Assert cancels every watchtower's    *)
(* challenge job).                                                         *)
(*                                                                         *)
(* CHAIN (goat crate @ bab46c2, goat/src/). Take-2 (transactions/take2.rs: *)
(* 56-90) spends ConnectorD leaf0 (operator + CSV connector_d from the     *)
(* Assert, connectors/connector_d.rs:61) AND ConnectorF leaf0 (operator +  *)
(* CSV connector_f from WCI = Watchtower-Challenge-Init,                   *)
(* connectors/connector_f.rs:38). It is stopped only if an honest tx spends *)
(* D or F first:                                                           *)
(*  F leaf1 (n-of-n, no CSV, connector_f.rs:49) is spent by                *)
(*   - Operator-Challenge-NACK_i = Ack_i leaf2 (n-of-n + CSV operator_ack  *)
(*     from WCI, connectors/watchtower_connectors.rs:156) + F leaf1        *)
(*     (transactions/watchtower_challenge.rs:544-575). Fully pre-signed,   *)
(*     so it is valid for ANY unspent Ack_i, whether or not watchtower i   *)
(*     challenged;                                                         *)
(*   - Operator-Commit-Timeout = E leaf1 (n-of-n + CSV operator_commit     *)
(*     from WCI, connectors/connector_e.rs:56) + F leaf1                   *)
(*     (watchtower_challenge.rs:715-746). Fully pre-signed.                *)
(*  D leaf1 (n-of-n) is spent by Disprove = D leaf1 + ProverConnector leaf1 *)
(*   (n-of-n + CSV prover_connector from the verifier's ChallengeAssert),  *)
(*   transactions/assert.rs:317-357. The operator answers a ChallengeAssert *)
(*   of a VALID proof with Wrongly-Challenged (ProverConnector leaf0,      *)
(*   assert.rs:599-626), which an invalid proof cannot produce.            *)
(* The operator alone controls: WCI (ConnectorB, operator key, no CSV,     *)
(* connector_b.rs:27); the Assert (ConnectorC leaf1, WOTS only, no CSV and *)
(* no ordering w.r.t. WCI, assert.rs:68-74, connector_c.rs:45); ACK_i      *)
(* (Ack_i leaf1: hashlock only, no signature or CSV,                       *)
(* watchtower_connectors.rs:128 - so it can be spent BEFORE any challenge); *)
(* Commit-Pubin (E leaf0, WOTS only, connector_e.rs:48); and               *)
(* WC-Timeout_i = WC_i leaf1 (OPERATOR key + CSV watchtower_challenge,     *)
(* watchtower_connectors.rs:49) + Ack_i leaf0 (watchtower_challenge.rs:    *)
(* 359-393): only the operator can time a watchtower out. A watchtower     *)
(* challenge spends WC_i leaf0 (watchtower key, NO CSV,                    *)
(* watchtower_connectors.rs:40): valid until WC_i is spent, in particular  *)
(* after the Assert has spent ConnectorC.                                  *)
(*                                                                         *)
(* NODE (current code = the bug cfgs).                                     *)
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
(*   transaction that inserts it.                                          *)
(*  Low: graph_scan.rs:474 is_timelock_ready(c, n, tip) = c + n <= tip, so *)
(*   an honest CSV-gated tx lands in block c+n+1 at the earliest, one block *)
(*   after the operator's (ScanLag). It does not flip any result here.     *)
(*                                                                         *)
(* FINDINGS (see the cfgs):                                                *)
(*  C1: one watchtower that never challenges (offline or colluding) and    *)
(*   that the operator never times out keeps all_resolved false forever:   *)
(*   no NACK, no Commit-Timeout, and verifier_assert never gets past the   *)
(*   connector-E gate -> Take-2 with an invalid proof (C1.cfg). Two        *)
(*   refinements the model found: (a) the connector-E gate is exploitable  *)
(*   on its own, with every branch resolved: the operator commits pubin in *)
(*   the last blocks before Commit-Timeout, and a Disprove started after   *)
(*   that can never beat Take-2, because operator_commit + prover_connector*)
(*   >= connector_f on every shipped network (testnet4 42+16 > 56, mainnet *)
(*   432+144 = 576, signet 18+6 = 24, regtest 3+1 = 4) (C1LateCommit.cfg);  *)
(*   (b) with the gate removed but Commit-Timeout still gated on           *)
(*   all_resolved, a VALID proof reaches Take-2 without any commit-pubin,  *)
(*   i.e. never bound to the watchtowers' evidence - NACK-every-Ack does   *)
(*   not close this, because the operator can spend Ack_i through its      *)
(*   hashlock leaf without any challenge (C1NoPubin.cfg).                  *)
(*  C2: an Assert confirmed before the watchtowers' proofs are ready (e.g. *)
(*   in WCI's own block) silences every honest watchtower, recreating C1's *)
(*   unresolved branches with all watchtowers honest and online (C2.cfg);  *)
(*   with C1 fixed it still keeps every honest watchtower's evidence off   *)
(*   chain (C2Silenced.cfg).                                               *)
(*                                                                         *)
(* FIX DESIGN (Fixed cfg; each flag switchable on its own):                *)
(*  FixCommitTimeout: OperatorCommitPubinTimeout at operator_commit        *)
(*   whenever E and F are unspent, whatever the watchtower branches;       *)
(*  FixNackAll: NackReady for EVERY unspent Ack_i after operator_ack (an   *)
(*   honest operator has ACKed or timed out - WC-Timeout spends Ack_i too - *)
(*   every branch by then);                                                *)
(*  FixUngateAssert: an invalid proof is challenged as soon as the Assert  *)
(*   is seen; only the "valid proof, skip" decision waits for commit-pubin *)
(*   (an inconsistent pubin is then answered by Pubin-Disprove, D leaf2,   *)
(*   which has no CSV);                                                    *)
(*  FixNoCancel: AssertSent no longer cancels JOB_WATCHTOWER_CHALLENGE.    *)
(* Ablations of the Fixed cfg (one flag dropped at a time): without        *)
(* FixCommitTimeout NoTake2WithoutPubin fails, without FixUngateAssert     *)
(* NoTake2WithInvalidProof fails, without FixNoCancel                      *)
(* OnlineWatchtowerChallengeLands fails; without FixNackAll all three     *)
(* still hold - FixNackAll is defence in depth that aligns the node with   *)
(* what the chain allows, not needed for these properties. Margin: the     *)
(* fixed Disprove lands by Assert+30 (1 + R + PC + ScanLag + R) against    *)
(* Take-2 at Assert+32; connector_d = 30 fails with ScanLag = 1 and passes *)
(* with ScanLag = 0, so the Low finding costs one of the two spare blocks  *)
(* at testnet4 values and flips nothing as shipped.                        *)
(*                                                                         *)
(* TIME is Bitcoin block height; h is the block being built. The operator's *)
(* CSV-n spend of an output confirmed at c can be in block c+n. An honest  *)
(* node sees the tip h-1: it sees a tx confirmed at c from block c+1, and  *)
(* its is_timelock_ready guard holds from block c+n+ScanLag. An honest     *)
(* action whose code guard holds from block s MUST be in a block <= s+R    *)
(* (R = the network's action_window); Tick is disabled while one is        *)
(* overdue. The job cancel is a local effect of the first scan that sees   *)
(* the Assert, so it happens in the block it becomes enabled. WCI confirms *)
(* at height 0 WLOG: an Assert before WCI cancels the job exactly like a   *)
(* same-block Assert, and only starts connector_d earlier, which can only  *)
(* help the defenders. One honest online verifier stands for the 1-of-M    *)
(* verifier set (every response above is pre-signed n-of-n or is that     *)
(* verifier's own ChallengeAssert). The operator's pubin is consistent with*)
(* its Assert (an inconsistent one only adds Pubin-Disprove). Blocks stop  *)
(* once a defender has spent D or F and the watchtower window is over      *)
(* (nothing left to check). Not modelled: the 1-block visibility lag of    *)
(* the branch-resolving txs before all_resolved holds (it can only delay   *)
(* the bug-cfg Commit-Timeout).                                            *)
(***************************************************************************)
EXTENDS Integers, TLC

CONSTANTS
    Watchtowers,      \* watchtower slots of the graph (outputs WC_i / Ack_i of WCI)
    Faulty,           \* watchtowers that may be offline or collude with the operator
    WC, ACK, COMMIT,  \* CSV watchtower_challenge / operator_ack / operator_commit (from WCI)
    CF,               \* CSV connector_f (from WCI)
    CD,               \* CSV connector_d (from the Assert)
    PC,               \* CSV prover_connector (from the ChallengeAssert)
    WtProof,          \* blocks a watchtower needs to get its proof commitment ready
    R,                \* honest action window (reaction + inclusion + safety)
    ScanLag,          \* 1 = is_timelock_ready (c+n <= tip); 0 = act one block earlier
    MaxH,             \* height bound of the exploration
    ProofValidity,    \* operator's choices for the asserted proof: subset of BOOLEAN
    FixCommitTimeout, FixNackAll, FixUngateAssert, FixNoCancel

NONE == -1
WCI  == 0                         \* WCI confirmation height (WLOG, see header)

VARIABLES
    h,          \* height of the block being built
    proofValid, \* the operator's choice: is the asserted Groth16 proof valid?
    assertH,    \* height the operator's Assert confirmed, or NONE
    online,     \* honest, online watchtowers (Watchtowers minus a subset of Faulty)
    wc,         \* WC_i:  "open" | "chal" (watchtower challenge) | "tout" (WC-Timeout)
    ack,        \* Ack_i: "open" | "ack" | "nack" | "tout" (WC-Timeout)
    E,          \* connector E: "open" | "pubin" | "tout" (Commit-Timeout)
    eSeen,      \* the spend of connector E is in an earlier block (visible to nodes)
    F,          \* connector F: "open" | "nack" | "tout" | "take2"
    D,          \* connector D: "open" | "disprove" | "take2"
    vaH,        \* height the honest verifier's ChallengeAssert confirmed, or NONE
    answered,   \* operator answered the ChallengeAssert with Wrongly-Challenged
    job,        \* watchtower i's JOB_WATCHTOWER_CHALLENGE: "live" | "cancelled"
    sinceChal, sinceCancel, sinceNack,  \* per-watchtower obligations: first block
    sinceCT, sinceCA, sinceDP           \*   the code guard held, or NONE

vars == <<h, proofValid, assertH, online, wc, ack, E, eSeen, F, D, vaH, answered, job,
          sinceChal, sinceCancel, sinceNack, sinceCT, sinceCA, sinceDP>>
chain == <<proofValid, assertH, online, wc, ack, E, F, D, vaH, answered, job>>

Heights == NONE .. MaxH

TypeOK ==
    /\ h \in 0..MaxH
    /\ proofValid \in BOOLEAN
    /\ assertH \in Heights
    /\ online \subseteq Watchtowers
    /\ wc  \in [Watchtowers -> {"open", "chal", "tout"}]
    /\ ack \in [Watchtowers -> {"open", "ack", "nack", "tout"}]
    /\ E \in {"open", "pubin", "tout"}
    /\ eSeen \in BOOLEAN
    /\ F \in {"open", "nack", "tout", "take2"}
    /\ D \in {"open", "disprove", "take2"}
    /\ vaH \in Heights
    /\ answered \in BOOLEAN
    /\ job \in [Watchtowers -> {"live", "cancelled"}]
    /\ sinceChal \in [Watchtowers -> Heights]
    /\ sinceCancel \in [Watchtowers -> Heights]
    /\ sinceNack \in [Watchtowers -> Heights]
    /\ {sinceCT, sinceCA, sinceDP} \subseteq Heights

--------------------------------------------------------------------------
\* What an honest node can see / its is_timelock_ready guard.
Seen(c)     == c # NONE /\ h >= c + 1
Ready(c, n) == c # NONE /\ h >= c + n + ScanLag

\* graph_scan.rs:617-670: a branch is resolved iff WC_i was timed out, or it
\* was challenged and Ack_i is spent (ACK and NACK both spend it).
AllResolved == \A i \in Watchtowers :
                  \/ wc[i] = "tout"
                  \/ wc[i] = "chal" /\ ack[i] # "open"

\* verifier_assert's decision to send a ChallengeAssert. Current code
\* (767-866): only once connector-E is spent and seen; then always after a
\* Commit-Timeout (pubin_consistent = false), else iff the proof is invalid.
\* Fix: an invalid proof at once; a valid one only after a Commit-Timeout.
WantsChallenge ==
    IF FixUngateAssert
    THEN ~proofValid \/ E = "tout"
    ELSE eSeen /\ (~proofValid \/ E = "tout")

\* Honest guards (code of the bug cfgs; Fix* flags switch to the fix design).
GChal(i)   == /\ i \in online /\ wc[i] = "open" /\ job[i] = "live"
              /\ h >= WCI + 1 + WtProof
GCancel(i) == /\ ~FixNoCancel /\ i \in online /\ job[i] = "live" /\ Seen(assertH)
GNack(i)   == /\ ack[i] = "open" /\ F = "open" /\ Ready(WCI, ACK)
              /\ (FixNackAll \/ wc[i] = "chal")
GCT        == /\ E = "open" /\ F = "open" /\ Ready(WCI, COMMIT)
              /\ (FixCommitTimeout \/ AllResolved)
GCA        == /\ D = "open" /\ vaH = NONE /\ Seen(assertH) /\ WantsChallenge
GDP        == /\ D = "open" /\ ~answered /\ Ready(vaH, PC)

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

Init ==
    /\ h = 0
    /\ proofValid \in ProofValidity
    /\ assertH = NONE
    /\ online \in {Watchtowers \ S : S \in SUBSET Faulty}
    /\ wc  = [i \in Watchtowers |-> "open"]
    /\ ack = [i \in Watchtowers |-> "open"]
    /\ E = "open" /\ eSeen = FALSE /\ F = "open" /\ D = "open"
    /\ vaH = NONE /\ answered = FALSE
    /\ job = [i \in Watchtowers |-> "live"]
    /\ sinceChal = [i \in Watchtowers |-> NONE]
    /\ sinceCancel = [i \in Watchtowers |-> NONE]
    /\ sinceNack = [i \in Watchtowers |-> NONE]
    /\ sinceCT = NONE /\ sinceCA = NONE /\ sinceDP = NONE

--------------------------------------------------------------------------
\* Take-2 can no longer happen (D or F spent by a defender): nothing left to
\* check once the watchtower window is over too, so stop producing blocks.
Settled == D = "disprove" \/ F \in {"nack", "tout"}

\* Block production; blocked while an honest obligation is at its deadline.
Tick ==
    /\ h < MaxH
    /\ ~(Settled /\ h >= WCI + WC)
    /\ \A i \in Watchtowers :
          ~Overdue(sinceChal[i]) /\ ~OverdueNow(sinceCancel[i]) /\ ~Overdue(sinceNack[i])
    /\ ~Overdue(sinceCT) /\ ~Overdue(sinceCA) /\ ~Overdue(sinceDP)
    /\ h' = h + 1
    /\ eSeen' = (E # "open")
    /\ UNCHANGED chain
    /\ UpdateSince

--------------------------------------------------------------------------
\* Operator (adversary): any transaction the scripts allow, at any time.

\* Operator-Assert (ConnectorC leaf1, WOTS only): any block, even WCI's.
OpAssert ==
    /\ assertH = NONE
    /\ assertH' = h
    /\ UNCHANGED <<h, proofValid, online, wc, ack, E, eSeen, F, D, vaH, answered, job>>
    /\ UpdateSince

\* Operator-Challenge-ACK_i (Ack_i leaf1, hashlock): any time Ack_i is unspent.
OpAck(i) ==
    /\ ack[i] = "open"
    /\ ack' = [ack EXCEPT ![i] = "ack"]
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, E, eSeen, F, D, vaH, answered, job>>
    /\ UpdateSince

\* Watchtower-Challenge-Timeout_i: operator key + CSV watchtower_challenge.
OpWCTimeout(i) ==
    /\ wc[i] = "open" /\ ack[i] = "open"
    /\ h >= WCI + WC
    /\ wc'  = [wc  EXCEPT ![i] = "tout"]
    /\ ack' = [ack EXCEPT ![i] = "tout"]
    /\ UNCHANGED <<h, proofValid, assertH, online, E, eSeen, F, D, vaH, answered, job>>
    /\ UpdateSince

\* Operator-Commit-Pubin (E leaf0, WOTS): any time E is unspent.
OpCommitPubin ==
    /\ E = "open"
    /\ E' = "pubin"
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, eSeen, F, D, vaH, answered, job>>
    /\ UpdateSince

\* Wrongly-Challenged (ProverConnector leaf0): needs a valid proof.
OpWronglyChallenged ==
    /\ proofValid /\ vaH # NONE /\ ~answered /\ D # "disprove"
    /\ answered' = TRUE
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, E, eSeen, F, D, vaH, job>>
    /\ UpdateSince

\* Take-2: D leaf0 after CSV connector_d AND F leaf0 after CSV connector_f.
OpTake2 ==
    /\ D = "open" /\ F = "open" /\ assertH # NONE
    /\ h >= assertH + CD /\ h >= WCI + CF
    /\ D' = "take2" /\ F' = "take2"
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, E, eSeen, vaH, answered, job>>
    /\ UpdateSince

--------------------------------------------------------------------------
\* Honest nodes: exactly what the code does (Fix* flags: the fix design).

\* graph_pegout_jobs.rs watchtower_challenge (1548-1589): proof ready -> broadcast.
WtChallenge(i) ==
    /\ GChal(i)
    /\ wc' = [wc EXCEPT ![i] = "chal"]
    /\ UNCHANGED <<h, proofValid, assertH, online, ack, E, eSeen, F, D, vaH, answered, job>>
    /\ UpdateSince

\* graph_pegout.rs:606-622: AssertSent cancels JOB_WATCHTOWER_CHALLENGE (terminal).
WtJobCancelled(i) ==
    /\ GCancel(i)
    /\ job' = [job EXCEPT ![i] = "cancelled"]
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, E, eSeen, F, D, vaH, answered>>
    /\ UpdateSince

\* graph_pegout_jobs.rs challenge_nack (654-709): pre-signed NACK_i.
Nack(i) ==
    /\ GNack(i)
    /\ ack' = [ack EXCEPT ![i] = "nack"]
    /\ F' = "nack"
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, E, eSeen, D, vaH, answered, job>>
    /\ UpdateSince

\* graph_pegout_jobs.rs commit_timeout (712-733): pre-signed Commit-Timeout.
CommitTimeout ==
    /\ GCT
    /\ E' = "tout" /\ F' = "tout"
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, eSeen, D, vaH, answered, job>>
    /\ UpdateSince

\* graph_pegout_jobs.rs verifier_assert (736-884): the ChallengeAssert.
ChallengeAssert ==
    /\ GCA
    /\ vaH' = h
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, E, eSeen, F, D, answered, job>>
    /\ UpdateSince

\* graph_scan.rs:780 WronglyChallengeTimeout -> disprove job (983-1023).
Disprove ==
    /\ GDP
    /\ D' = "disprove"
    /\ UNCHANGED <<h, proofValid, assertH, online, wc, ack, E, eSeen, F, vaH, answered, job>>
    /\ UpdateSince

Next ==
    \/ Tick
    \/ OpAssert \/ OpCommitPubin \/ OpWronglyChallenged \/ OpTake2
    \/ \E i \in Watchtowers : OpAck(i) \/ OpWCTimeout(i)
    \/ \E i \in Watchtowers : WtChallenge(i) \/ WtJobCancelled(i) \/ Nack(i)
    \/ CommitTimeout \/ ChallengeAssert \/ Disprove

Spec == Init /\ [][Next]_vars

WatchtowerSymmetry == Permutations(Watchtowers)

--------------------------------------------------------------------------
Take2 == D = "take2"

\* With an honest online verifier, an invalid proof never reaches Take-2.
NoTake2WithInvalidProof == Take2 => proofValid

\* Take-2 only after the operator committed its pubin (the commitment that
\* binds the proof to the watchtowers' evidence); otherwise Commit-Timeout
\* must have burnt connector F.
NoTake2WithoutPubin == Take2 => E = "pubin"

\* Every honest online watchtower's challenge lands before its WC window
\* closes (from then on the operator may time it out).
OnlineWatchtowerChallengeLands ==
    \A i \in online : h >= WCI + WC => wc[i] = "chal"

====
