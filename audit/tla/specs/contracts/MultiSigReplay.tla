---- MODULE MultiSigReplay ----
(***************************************************************************)
(* Owner rotation of MultiSigVerifier (base of CommitteeManagement), in    *)
(* localnet/contracts src/MultiSigVerifier.sol updateOwners (54-66).       *)
(* Finding: the digest keccak256(abi.encodePacked(nonce, newOwners,        *)
(* newRequired)) (:58) binds no contract address or chain id, and nonce    *)
(* starts at 0 in every deployment (:35), so a rotation signed for one     *)
(* deployment replays on another with the same owner keys. Other committee *)
(* digests are bound (CommitteeManagement.sol:277-280 address(this);       *)
(* StakeManagement.sol:91 address(this) and chainid). The node never calls *)
(* updateOwners; rotations are manual.                                     *)
(* Parameters: Deployments, KeySets (abstract owner sets), InitKeys,       *)
(* MaxNonce (model bound); DomainSeparated = TRUE models the fix (digest   *)
(* also binds address(this) and block.chainid).                            *)
(* Two deployments and two rotations each suffice: a replay needs one      *)
(* rotation signed on A and applied on B at the same nonce.                *)
(* Configs: configs/contracts/MultiSigReplay/, tiers in                    *)
(* audit/tla/checks.txt.                                                   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Deployments,      \* contract deployments sharing the initial owner keys, e.g. {"A", "B"}
    KeySets,          \* abstract owner sets (owner list + threshold), e.g. {"K0", "K1", "K2"}
    InitKeys,         \* owner set every deployment is initialised with
    MaxNonce,         \* model bound on rotations per deployment
    DomainSeparated   \* TRUE: fix design, the digest binds contract and chain

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
\* Source: localnet/contracts/src/MultiSigVerifier.sol:30-36
Init ==
    /\ owners = [d \in Deployments |-> InitKeys]
    /\ nonce = [d \in Deployments |-> 0]
    /\ signed = {}
    /\ applied = {}

--------------------------------------------------------------------------
\* Action: owners of d sign off-chain a rotation to new for d at d's nonce
\* (anyone who sees the signatures can submit them).
\* Source: environment (digest: MultiSigVerifier.sol:58)
Sign(d, new) ==
    /\ nonce[d] < MaxNonce
    /\ new # owners[d]
    /\ signed' = signed \cup {[dep |-> d, n |-> nonce[d], signer |-> owners[d], new |-> new]}
    /\ UNCHANGED <<owners, nonce, applied>>

\* Action: anyone submits signed rotation m to d; it applies iff the nonce
\* matches (and the deployment, if DomainSeparated) and m's signers are d's owners.
\* Source: MultiSigVerifier.sol updateOwners 54-66 (verify 39-51, _applyOwners 86-104)
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
\* Every applied rotation was signed for the deployment it was applied on.
NoCrossDeploymentReplay == \A x \in applied : x.msg.dep = x.at

====
