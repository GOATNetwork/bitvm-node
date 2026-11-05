---- MODULE ChallengeInputLayout ----
(***************************************************************************)
(* Input layout of a Watchtower-Challenge transaction (audit C3).          *)
(*                                                                         *)
(* The watchtower spends its connector of Watchtower-Challenge-Init (WCI)  *)
(* through the leaf <watchtower key> OP_CHECKSIG, which accepts any        *)
(* BIP341 sighash type and an optional annex. The watchtower may lay the   *)
(* transaction out with fee inputs before or after the connector, and once *)
(* it is signed with ANYONECANPAY any fee payer may still insert inputs    *)
(* anywhere (for SINGLE|ANYONECANPAY together with the paired output).     *)
(* A transaction is only mined if its signature still verifies, so every   *)
(* mined challenge is a legitimate one. Such a challenge must:             *)
(*   - be recognised by the connector outpoint it spends,                  *)
(*   - trigger the operator ACK,                                           *)
(*   - be accepted by the operator proof (circuit), so the honest operator *)
(*     can still prove.                                                    *)
(*                                                                         *)
(* Ground truth (branch audit/4-circuit-challenge-input):                  *)
(*   - Recognition: watchtower_flow (node/src/aggregates/graph_scan.rs)    *)
(*     signals WatchtowerChallengeSent when the WCI watchtower connector   *)
(*     is spent by a confirmed transaction other than its timeout, and     *)
(*     get_watchtower_challenge_info (node/src/utils/proof_client.rs) puts *)
(*     the spender in the operator proof request with its included bit.    *)
(*     Neither looks at the input index.                                   *)
(*   - ACK: challenge_ack (node/src/aggregates/graph_pegout_jobs.rs) finds *)
(*     the spender with outpoint_spent_txin; the fix drops the old         *)
(*     `vin != 0` ignore.                                                  *)
(*   - Host: fetch_target_block_and_watchtower_tx                          *)
(*     (circuits/operator-proof/host/src/lib.rs) fetches one previous      *)
(*     transaction per input and checks them with                          *)
(*     checked_transaction_prevouts.                                       *)
(*   - Circuit: propose_longest_chain                                      *)
(*     (circuits/crates/bitcoin-light-client-circuit/src/lib.rs) finds the *)
(*     input whose previous_output is (WCI txid, node_index * 2), binds    *)
(*     all prevouts with checked_transaction_prevouts, and                 *)
(*     verify_taproot_leaf_schnorr_signature (src/signature.rs) strips an  *)
(*     annex, takes the sighash type from the signature and recomputes the *)
(*     BIP341 message with Prevouts::All at that input index.              *)
(*                                                                         *)
(* PreFix = TRUE models the code before the fix: the circuit requires the  *)
(* connector at input 0, only ALL|ANYONECANPAY, and reads the last witness *)
(* element as the control block (so an annex fails); challenge_ack ignores *)
(* a spend at input index != 0.                                            *)
(*                                                                         *)
(* Abstraction: inputs are outpoint ids (Conn = the watchtower connector,  *)
(* other ids are fee inputs), outputs are output ids. The BIP341 message   *)
(* is reduced to the parts the layout can change: hash type, annex,        *)
(* committed inputs and input index (not ANYONECANPAY) or this input's     *)
(* outpoint (ANYONECANPAY), and committed outputs (all / none / the one at *)
(* the input index). Commitment payload, SPV and the watchtower proof are  *)
(* out of scope; the host's previous transactions are assumed available    *)
(* for a mined challenge, so the prevouts it passes are the real ones.     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS MaxInputs, MaxOutputs, PreFix

ASSUME MaxInputs \in Nat /\ MaxInputs >= 1 /\ MaxOutputs \in Nat /\ MaxOutputs >= 1
ASSUME PreFix \in BOOLEAN

Conn == 0

SighashTypes ==
    {"DEFAULT", "ALL", "NONE", "SINGLE", "ALL|ACP", "NONE|ACP", "SINGLE|ACP"}
AcpTypes == {"ALL|ACP", "NONE|ACP", "SINGLE|ACP"}
Base(t) ==
    CASE t \in {"DEFAULT", "ALL", "ALL|ACP"} -> "ALL"
      [] t \in {"NONE", "NONE|ACP"} -> "NONE"
      [] OTHER -> "SINGLE"

VARIABLES
    ins,        \* inputs of the challenge, as outpoint ids
    outs,       \* outputs of the challenge, as output ids
    nextId,     \* next fresh fee-input / output id
    sigType,    \* sighash type the watchtower signs with
    annex,      \* whether the connector witness carries an annex
    phase,      \* "Build" -> "Signed" -> "Mined"
    sig,        \* the message the watchtower signed
    signedIdx   \* connector input index at signing time

vars == <<ins, outs, nextId, sigType, annex, phase, sig, signedIdx>>

\* Index of the connector input (Iterator::position in propose_longest_chain;
\* an outpoint is spent at most once, so it is unique).
ConnIdx == CHOOSE k \in 1..Len(ins) : ins[k] = Conn

\* BIP341: SIGHASH_SINGLE without an output at the input index is invalid.
Signable(i, o, idx, t) == Base(t) = "SINGLE" => idx <= Len(o)

\* The parts of the BIP341 signature message the layout can change.
Msg(i, o, idx, t, a) ==
    [ type    |-> t,
      annex   |-> a,
      inputs  |-> IF t \in AcpTypes THEN <<>> ELSE i,
      self    |-> IF t \in AcpTypes THEN <<i[idx]>> ELSE <<idx>>,
      outputs |-> CASE Base(t) = "ALL" -> o
                    [] Base(t) = "NONE" -> <<>>
                    [] OTHER -> <<o[idx]>> ]

NoSig == [type |-> "none", annex |-> FALSE, inputs |-> <<>>, self |-> <<>>, outputs |-> <<>>]

InsertAt(s, p, x) == SubSeq(s, 1, p - 1) \o <<x>> \o SubSeq(s, p, Len(s))

Init ==
    /\ ins = <<Conn>>
    /\ outs = <<1>>          \* the commitment output
    /\ nextId = 2
    /\ sigType \in SighashTypes
    /\ annex \in BOOLEAN
    /\ phase = "Build"
    /\ sig = NoSig
    /\ signedIdx = 0

\* The watchtower (before signing) or any fee payer (after signing) adds a
\* fee input at any position. After signing this only keeps the signature
\* valid under ANYONECANPAY; otherwise the transaction can no longer be mined.
AddInput(p) ==
    /\ phase \in {"Build", "Signed"}
    /\ Len(ins) < MaxInputs
    /\ ins' = InsertAt(ins, p, nextId)
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<outs, sigType, annex, phase, sig, signedIdx>>

\* Same for an output (change, or the output paired with a shifted
\* SINGLE|ANYONECANPAY input).
AddOutput(p) ==
    /\ phase \in {"Build", "Signed"}
    /\ Len(outs) < MaxOutputs
    /\ outs' = InsertAt(outs, p, nextId)
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<ins, sigType, annex, phase, sig, signedIdx>>

Sign ==
    /\ phase = "Build"
    /\ Signable(ins, outs, ConnIdx, sigType)
    /\ sig' = Msg(ins, outs, ConnIdx, sigType, annex)
    /\ signedIdx' = ConnIdx
    /\ phase' = "Signed"
    /\ UNCHANGED <<ins, outs, nextId, sigType, annex>>

\* Bitcoin consensus: the connector input's signature verifies at the index
\* it actually sits at.
ConsensusValid ==
    /\ phase # "Build"
    /\ Signable(ins, outs, ConnIdx, sigType)
    /\ Msg(ins, outs, ConnIdx, sigType, annex) = sig

Mine ==
    /\ phase = "Signed"
    /\ ConsensusValid
    /\ phase' = "Mined"
    /\ UNCHANGED <<ins, outs, nextId, sigType, annex, sig, signedIdx>>

Next ==
    \/ \E p \in 1..(Len(ins) + 1) : AddInput(p)
    \/ \E p \in 1..(Len(outs) + 1) : AddOutput(p)
    \/ Sign
    \/ Mine

Spec == Init /\ [][Next]_vars

Mined == phase = "Mined"

\* watchtower_flow / get_watchtower_challenge_info: the WCI watchtower
\* connector is spent by a confirmed transaction that is not its timeout.
ScanRecognises == Mined /\ \E k \in 1..Len(ins) : ins[k] = Conn

\* challenge_ack, which runs on the scan's WatchtowerChallengeSent signal.
AckSent == ScanRecognises /\ (PreFix => ConnIdx = 1)

\* The operator proof accepts the challenge's signature.
CircuitAccepts ==
    /\ Mined
    /\ IF PreFix
         \* tx.input.first() must be the connector; only ALL|ANYONECANPAY;
         \* witness[len-2] / witness[len-1] read as script / control block,
         \* which an annex shifts; Prevouts::One at input 0.
         THEN /\ ins[1] = Conn
              /\ sigType = "ALL|ACP"
              /\ ~annex
              /\ Msg(ins, outs, 1, "ALL|ACP", FALSE) = sig
         \* Connector found by outpoint; one checked prevout per input; annex
         \* stripped and committed; type from the signature; Prevouts::All.
         ELSE LET idx == ConnIdx IN
              /\ Signable(ins, outs, idx, sigType)
              /\ Msg(ins, outs, idx, sigType, annex) = sig

\* A mined challenge is recognised by the connector outpoint it spends,
\* whatever its input index, sighash type or annex.
ChallengeRecognisedByOutpoint == Mined => ScanRecognises

\* A mined challenge triggers the operator ACK.
ValidChallengeTriggersAck == Mined => AckSent

\* The operator can still prove with any mined challenge included.
ValidChallengeProvable == Mined => CircuitAccepts

\* Sanity of the sighash abstraction: without ANYONECANPAY nobody can move
\* the connector after signing (the fee input has to be there before).
NonAcpLayoutFrozen ==
    (Mined /\ sigType \notin AcpTypes) => ConnIdx = signedIdx

====
