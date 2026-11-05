---- MODULE WatchtowerGenesisBinding ----
(***************************************************************************)
(* Which watchtower challenges constrain the operator proof, after the     *)
(* watchtower proof was bound to a genesis (audit C7, commit e229880).     *)
(* Exhaustive check over Init, same idiom as TransactionGraph.tla.         *)
(*                                                                         *)
(* Ground truth (circuits/crates/bitcoin-light-client-circuit/src/lib.rs   *)
(* unless noted):                                                          *)
(*   - Guest circuits/watchtower-proof/guest/src/main.rs commits work,     *)
(*     height and genesis_sequencer_commit_txid; watch_longest_chain       *)
(*     asserts that genesis equals the verified commit-chain genesis. The  *)
(*     public output is 68 bytes (work BE, height LE, genesis);            *)
(*     decode_watchtower_public_outputs rejects every other length, so a   *)
(*     legacy 36-byte commitment fails parse_watchtower_commitment.        *)
(*   - Node: get_watchtower_challenge_info (node/src/utils/proof_client.rs) *)
(*     sets included[i] iff connector i of the challenge init tx is spent  *)
(*     by a confirmed tx that is not the presigned timeout. It never looks *)
(*     at the commitment. gen_watchtower_commitment (same file) and        *)
(*     mock_proof_builder.rs only emit the 68-byte layout.                 *)
(*   - Operator guest, propose_longest_chain: validate_watchtower_         *)
(*     challenge_indices forces the supplied challenges to equal the       *)
(*     included bitmap (a public input checked against the ACKs on         *)
(*     Bitcoin). Each supplied challenge must pass SPV and its signature.  *)
(*     Then a claim whose commitment does not extract or parse, whose      *)
(*     Groth16 proof fails, whose program is not authorized.watchtower or  *)
(*     whose graph_id differs is skipped (`continue`), but its bit stays.  *)
(*     The rest go through check_watchtower_claim_against_operator: a      *)
(*     different genesis is Ok, the same genesis must have work <= and     *)
(*     height <= the operator's, otherwise the guest panics.               *)
(*                                                                         *)
(* GenesisBound = FALSE models the pre-fix code: 36-byte output without    *)
(* genesis, every usable claim compared. The watchtower's chain still has  *)
(* a genesis (its private input), so a claim built on a foreign commit     *)
(* chain with more work defeats an honest operator                         *)
(* (HonestOperatorCanProve fails).                                         *)
(*                                                                         *)
(* Soundness assumption: a valid proof of the authorized watchtower        *)
(* program over the operator's genesis attests a real chain from that      *)
(* genesis, so its work and height are at most the best chain's            *)
(* (CanonWork, CanonHeight), which the honest operator proves. A claim     *)
(* over another genesis, or one that is not usable, may carry anything.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS GenesisBound, Slots, MaxValue, CanonWork, CanonHeight

\* The genesis bound into the graph (hash_operator_constant) and the
\* operator's commit chain; "Foreign" is any other commit-chain genesis.
OpGenesis == "Own"
Geneses == {"Own", "Foreign"}
Values == 0..MaxValue

\* The 68-byte layout is the only one the current decoder accepts; the
\* pre-fix decoder accepted only the 36-byte one. "Unparsable" covers
\* missing commitment outputs, truncated or extra bytes, bad version length.
CurrentLayout == IF GenesisBound THEN "Genesis68" ELSE "Legacy36"

\* What the operator's proof reads of a challenge tx; meaningful only when
\* spend = "Challenge".
ChallengeClaims ==
    { c \in [spend: {"Challenge"},
             layout: {"Genesis68", "Legacy36", "Unparsable"},
             proof: {"Authorized", "OtherProgram", "Invalid"},
             graph: {"Same", "Other"},
             genesis: Geneses,
             work: Values,
             height: Values] :
        (c.proof = "Authorized" /\ c.genesis = OpGenesis)
            => (c.work <= CanonWork /\ c.height <= CanonHeight) }

NoClaim(s) == [spend |-> s, layout |-> "Unparsable", proof |-> "Invalid",
               graph |-> "Other", genesis |-> "Foreign", work |-> 0, height |-> 0]

\* Connector i: unspent, spent by the timeout tx, or spent by a challenge.
SlotSpace == {NoClaim("Unspent"), NoClaim("Timeout")} \cup ChallengeClaims

VARIABLES slot, opWork, opHeight

vars == <<slot, opWork, opHeight>>

Init ==
    /\ slot \in [Slots -> SlotSpace]
    /\ opWork \in Values
    /\ opHeight \in Values

Next == FALSE
Spec == Init /\ [][Next]_vars

Honest == opWork = CanonWork /\ opHeight = CanonHeight

\* Challenge txs confirmed on Bitcoin: each needs an ACK, and the operator's
\* public bitmap is checked against the ACKs.
OnChainChallenges == { i \in Slots : slot[i].spend = "Challenge" }

\* get_watchtower_challenge_info: a confirmed spend that is not the
\* timeout tx. Content of the commitment plays no part.
Bitmap == { i \in Slots : slot[i].spend \notin {"Unspent", "Timeout"} }

\* The checks before `continue` in propose_longest_chain.
Usable(i) ==
    /\ slot[i].spend = "Challenge"
    /\ slot[i].layout = CurrentLayout
    /\ slot[i].proof = "Authorized"
    /\ slot[i].graph = "Same"

\* check_watchtower_claim_against_operator (pre-fix: the bare asserts).
Constrains(i) == Usable(i) /\ (GenesisBound => slot[i].genesis = OpGenesis)
ClaimOk(i) ==
    ~Constrains(i) \/ (slot[i].work <= opWork /\ slot[i].height <= opHeight)

\* The operator guest succeeds with supplied challenge set S and public
\* bitmap B; the proof is only accepted on chain if B matches the ACKs.
GuestOk(S, B) == S = B /\ S \subseteq OnChainChallenges /\ \A i \in S : ClaimOk(i)
AckConsistent(B) == B = OnChainChallenges

----
\* C7: an honest operator can always prove with the full bitmap, whatever
\* foreign-genesis or unusable claims were included.
HonestOperatorCanProve ==
    Honest => (GuestOk(Bitmap, Bitmap) /\ AckConsistent(Bitmap))

\* A valid same-genesis claim for this graph still binds work and height:
\* no accepted proof exists while one exceeds the operator's chain, and
\* supplying fewer challenges than the bitmap (or a smaller bitmap) does
\* not get around it.
SameGenesisClaimsStillBind ==
    \A S \in SUBSET Slots :
        (GuestOk(S, S) /\ AckConsistent(S)) =>
            \A i \in S :
                (Usable(i) /\ slot[i].genesis = OpGenesis)
                    => slot[i].work <= opWork /\ slot[i].height <= opHeight

\* Ignoring a claim never clears its bit: the bitmap is tx inclusion, and
\* only included, usable, own-genesis claims are compared.
IgnoringKeepsIncludedBit ==
    /\ Bitmap = OnChainChallenges
    /\ \A i \in Slots :
          Constrains(i) => (i \in Bitmap /\ (GenesisBound => slot[i].genesis = OpGenesis))

\* The legacy 36-byte format gets no compatibility path after the fix.
LegacyLayoutNeverConstrains ==
    GenesisBound => \A i \in Slots : slot[i].layout = "Legacy36" => ~Constrains(i)

====
