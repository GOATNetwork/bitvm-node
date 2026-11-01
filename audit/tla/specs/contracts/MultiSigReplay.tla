---- MODULE MultiSigReplay ----
(***************************************************************************)
(* Purpose: owner rotation of MultiSigVerifier, the base of               *)
(* CommitteeManagement (the committee that authorises every Gateway call). *)
(* Can a rotation the owners signed for one deployment be replayed on      *)
(* another deployment that shares the owner keys?                          *)
(*                                                                         *)
(* Code scope: localnet/contracts @ 3a679bf (submodule pin of dev 60562f8),*)
(* src/MultiSigVerifier.sol:                                               *)
(*    54  function updateOwners(address[] calldata newOwners,              *)
(*            uint256 newRequired, bytes[] calldata signatures) external { *)
(*    58      bytes32 digest = keccak256(abi.encodePacked(nonce, newOwners, newRequired)); *)
(*    60      require(verify(digest, signatures), "No enough valid owner sigs"); *)
(*    62      _applyOwners(newOwners, newRequired);                        *)
(*    64      nonce += 1;                                                  *)
(* The digest has no contract address and no chain id, unlike every other  *)
(* committee digest (CommitteeManagement.sol:277-280 getNoncedDigest binds *)
(* address(this); StakeManagement.sol:91 binds address(this) and chainid). *)
(* `nonce` starts at 0 in every deployment (:35) and only counts rotations,*)
(* so two deployments with the same owner keys (testnet/mainnet, a         *)
(* redeploy, a second proxy) are at the same nonce until they diverge. A   *)
(* rotation signed for deployment A is then a valid, permissionless        *)
(* updateOwners call on deployment B: anyone can replay it.                *)
(* The node never calls updateOwners (no caller in node/ or crates/);      *)
(* rotations are made by hand.                                             *)
(*                                                                         *)
(* Configs / tiers:                                                        *)
(*   MultiSigReplay/Replay.cfg (live, DomainSeparated = FALSE): current contract, *)
(*     FAILS NoCrossDeploymentReplay.                                      *)
(*   MultiSigReplay/Fixed.cfg (design, DomainSeparated = TRUE): digest also *)
(*     binds address(this) and block.chainid; PASS.                        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Deployments,      \* contract deployments sharing the initial owner keys, e.g. {"A", "B"}
    KeySets,          \* abstract owner sets (owner list + threshold), e.g. {"K0", "K1", "K2"}
    InitKeys,         \* owner set every deployment is initialised with
    MaxNonce,         \* bound on rotations per deployment (model-checking bound)
    DomainSeparated   \* TRUE: the updateOwners digest binds (contract, chain) - the fix design

ASSUME InitKeys \in KeySets /\ MaxNonce \in Nat /\ DomainSeparated \in BOOLEAN

\* A signed rotation: intended deployment, nonce signed, signing owner set, new owner set.
Msgs == [dep : Deployments, n : 0..MaxNonce, signer : KeySets, new : KeySets]

VARIABLES
    owners,   \* owners[d]: current owner set of deployment d (isOwner / ownerList / requiredSignatures)
    nonce,    \* nonce[d]: MultiSigVerifier.nonce of deployment d
    signed,   \* rotation messages the owners of msg.dep signed FOR msg.dep
    applied   \* executed rotations: [at |-> deployment, msg |-> message]

vars == <<owners, nonce, signed, applied>>

TypeOk ==
    /\ owners \in [Deployments -> KeySets]
    /\ nonce \in [Deployments -> 0..MaxNonce]
    /\ signed \subseteq Msgs
    /\ applied \subseteq [at : Deployments, msg : Msgs]

\* Every deployment starts with the same owners and nonce 0.
\* Source: __MultiSigVerifier_init_unchained() in MultiSigVerifier.sol:30-36
Init ==
    /\ owners = [d \in Deployments |-> InitKeys]
    /\ nonce = [d \in Deployments |-> 0]
    /\ signed = {}
    /\ applied = {}

--------------------------------------------------------------------------
\* Action: the current owners of d sign a rotation to `new`, intended for d,
\* at d's current nonce (off-chain). The signature is a bearer token: anyone
\* who sees it can submit it.
\* Source: environment (off-chain signing by the owners); the digest they
\*   sign is MultiSigVerifier.sol:58.
Sign(d, new) ==
    /\ nonce[d] < MaxNonce
    /\ new # owners[d]
    /\ signed' = signed \cup {[dep |-> d, n |-> nonce[d], signer |-> owners[d], new |-> new]}
    /\ UNCHANGED <<owners, nonce, applied>>

\* Action: anyone submits updateOwners(m.new, ..., sigs) to deployment d. The
\* digest (nonce, newOwners, newRequired) matches iff the nonce and new owner
\* set match (plus the deployment under DomainSeparated); verify() recovers
\* the signers and checks them against d's CURRENT owners. On success the
\* owner set is replaced and the nonce incremented.
\* Source: updateOwners() in MultiSigVerifier.sol:54-66 (verify :39-51,
\*   _applyOwners :86-104).
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

\* Safety only: no fairness.
Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Safety invariants                                                       *)

\* A deployment's owner set only changes by rotations its owners signed for
\* that deployment.
NoCrossDeploymentReplay == \A x \in applied : x.msg.dep = x.at

====
