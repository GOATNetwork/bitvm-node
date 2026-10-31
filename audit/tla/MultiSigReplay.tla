---- MODULE MultiSigReplay ----
(***************************************************************************)
(* Owner rotation of MultiSigVerifier (base of CommitteeManagement, i.e.   *)
(* the committee that authorises every Gateway call).                      *)
(* localnet/contracts @ 3a679bf, src/MultiSigVerifier.sol:                 *)
(*                                                                         *)
(*   175  function updateOwners(address[] calldata newOwners,              *)
(*            uint256 newRequired, bytes[] calldata signatures) external { *)
(*   179      bytes32 digest = keccak256(abi.encodePacked(nonce, newOwners, newRequired)); *)
(*   181      require(verify(digest, signatures), "No enough valid owner sigs"); *)
(*   183      _applyOwners(newOwners, newRequired);                        *)
(*   185      nonce += 1;                                                  *)
(*                                                                         *)
(* The digest has no contract address and no chain id, unlike every other  *)
(* committee digest (CommitteeManagement.sol:277-280 getNoncedDigest binds *)
(* address(this); StakeManagement.sol:91 binds address(this) and chainid). *)
(* `nonce` starts at 0 in every deployment (:156) and only counts rotations,*)
(* so two deployments with the same owner keys (testnet/mainnet, a          *)
(* redeploy, a second proxy) are at the same nonce until they diverge. A    *)
(* rotation the owners signed for deployment A is then a valid, permission- *)
(* less updateOwners call on deployment B: anyone can replay it.           *)
(*                                                                         *)
(* Bug cfg  MultiSigReplay.cfg      (DomainSeparated = FALSE): FAILS         *)
(*          NoCrossDeploymentReplay.                                       *)
(* Fix cfg  MultiSigReplayFixed.cfg (digest also binds address(this) and    *)
(*          block.chainid): PASS.                                          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Deployments,      \* e.g. {"A", "B"}
    KeySets,          \* abstract owner sets, e.g. {"K0", "K1", "K2"}
    InitKeys,         \* owner set every deployment starts with
    MaxNonce,
    DomainSeparated   \* digest binds (contract, chain)

VARIABLES
    owners,   \* owners[d]: current owner set of deployment d
    nonce,    \* nonce[d]
    signed,   \* rotation messages the owners of msg.dep signed FOR msg.dep
    applied   \* rotations executed: [at |-> deployment, msg |-> message]

vars == <<owners, nonce, signed, applied>>

Msgs == [dep : Deployments, n : 0..MaxNonce, signer : KeySets, new : KeySets]

TypeOK ==
    /\ owners \in [Deployments -> KeySets]
    /\ nonce \in [Deployments -> 0..MaxNonce]
    /\ signed \subseteq Msgs
    /\ applied \subseteq [at : Deployments, msg : Msgs]

Init ==
    /\ owners = [d \in Deployments |-> InitKeys]
    /\ nonce = [d \in Deployments |-> 0]
    /\ signed = {}
    /\ applied = {}

\* The current owners of d sign a rotation intended for d at d's nonce.
Sign(d, new) ==
    /\ nonce[d] < MaxNonce
    /\ new # owners[d]
    /\ signed' = signed \cup {[dep |-> d, n |-> nonce[d], signer |-> owners[d], new |-> new]}
    /\ UNCHANGED <<owners, nonce, applied>>

\* Anyone submits updateOwners(m.new, ..., sigs) to deployment d.
\* digest(:179) = (nonce, newOwners, newRequired): equal iff n and new match,
\* plus the domain when DomainSeparated. verify(:160-172) recovers the
\* signers and checks them against d's CURRENT owners.
Apply(d, m) ==
    /\ m \in signed
    /\ m.n = nonce[d]
    /\ DomainSeparated => m.dep = d
    /\ m.signer = owners[d]
    /\ owners' = [owners EXCEPT ![d] = m.new]
    /\ nonce' = [nonce EXCEPT ![d] = @ + 1]
    /\ applied' = applied \cup {[at |-> d, msg |-> m]}
    /\ UNCHANGED signed

Next ==
    \/ \E d \in Deployments, k \in KeySets : Sign(d, k)
    \/ \E d \in Deployments, m \in signed : Apply(d, m)

Spec == Init /\ [][Next]_vars

\* A deployment's owner set only changes by rotations its owners signed for it.
NoCrossDeploymentReplay == \A x \in applied : x.msg.dep = x.at

====
