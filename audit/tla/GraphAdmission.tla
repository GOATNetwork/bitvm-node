---- MODULE GraphAdmission ----
(***************************************************************************)
(* Graph admission at its four boundaries, and what a malformed graph      *)
(* message does to the engine's poison backoff (audit H9).                 *)
(*                                                                         *)
(* Boundaries and the Rust code each one mirrors:                          *)
(*   Create       committee_ingest_graph -> validate_init_graph_base       *)
(*                (node/src/aggregates/graph_jobs.rs,                      *)
(*                 node/src/utils/graph_validate.rs)                       *)
(*   Finalized    ingest_finalized -> validate_finalized_graph             *)
(*   VerifierRecv verifier_validate_graph (graph_jobs.rs)                  *)
(*   Pull         fetch_graph -> validate_and_store                        *)
(*                (node/src/aggregates/graph_fetch.rs)                     *)
(*                                                                         *)
(* Each boundary runs an ordered list of checks (Checks below); the first  *)
(* one that does not pass decides the message:                             *)
(*   Preflight  validate_graph_preflight: BitvmGcGraphParameters::         *)
(*              validate_basic (crates/bitvm-gc/src/types.rs) plus         *)
(*              validate_graph_policy. Local and side-effect-free: no      *)
(*              backend call, no store write. Error is                     *)
(*              SpecialError::InvalidGraph, i.e. FailureClass::Permanent.  *)
(*   Member     local membership (local_member / find_verifier_index_     *)
(*              by_pubkey); not a member -> Step::ignore.                  *)
(*   Bind       validate_graph_instance_parameters: read the instance from *)
(*              GoatChain (read_instance_info_from_goat, whose committee   *)
(*              key now goes through checked_committee_key) and Bitcoin.   *)
(*              Backend failure -> retry; mismatch or an empty on-chain    *)
(*              committee -> InvalidGraph / InvalidPeginData (permanent).  *)
(*   Construct  BitvmGcGraph::from_simplified -> generate_bitvm_graph,     *)
(*              which now calls validate_basic itself (defence in depth).  *)
(*   Sigs       operator / committee pre-signature checks (InvalidGraph).  *)
(*   Apply      the rest of the job. A genuine bug may panic here.         *)
(*                                                                         *)
(* Engine (crates/engine/src/jobs.rs record_job_finish,                    *)
(* crates/store/src/engine/mod.rs mark_engine_aggregate_poisoned /         *)
(* claim_due_engine_jobs): a job that panics is Poisoned (terminal) and    *)
(* bumps the poison count of (graph, action); the n-th consecutive poison  *)
(* blocks later jobs of that action for poison_backoff(n) =                *)
(* 0, 600, 3600, ... seconds (scaled to PoisonBackoff below). Any other    *)
(* finish (done, rejected, retry) releases the poison.                     *)
(*                                                                         *)
(* PreFix = TRUE models the code before the fix: no preflight, the graph   *)
(* was rebuilt first (empty committee and u64 amounts panicked inside      *)
(* musig2 key aggregation and Amount addition), the verifier did no chain  *)
(* binding, and read_instance_info_from_goat panicked on an empty          *)
(* on-chain committee.                                                     *)
(*                                                                         *)
(* Not modelled: the H13 setup budget and the other identity/protocol      *)
(* admission rules. Nothing here is a liveness claim for graph setup.      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    PreFix,     \* TRUE: code before the fix
    QueueLen,   \* messages for one (graph, action) in the process model
    MaxTime     \* clock bound for the process model

Boundaries == {"Create", "Finalized", "VerifierRecv", "Pull"}

(* Malformed input the preflight targets (validate_basic):                 *)
(*   EmptyCommittee  committee_pubkeys empty (checked_committee_key)       *)
(*   AmountOverflow  peg-in / fee / input / prekickoff amounts that        *)
(*                   overflow or exceed MAX_MONEY (checked_money_sum)      *)
(*   LengthMismatch  watchtower hashlocks, verifier slots, final-message   *)
(*                   hashlocks or replenish inputs vs prev-outs            *)
Defects == {"EmptyCommittee", "AmountOverflow", "LengthMismatch"}
\* Defects in the instance parameters (the part compared with GoatChain).
InstanceDefects == {"EmptyCommittee", "AmountOverflow"}
\* Defects that panicked in reconstruction before the fix (the admission
\* tests' catch_unwind cases); a length mismatch already returned an error.
PreFixPanicDefects == {"EmptyCommittee", "AmountOverflow"}

Messages == [defect : Defects \cup {"None"},
             bind   : {"Bound", "Mismatch", "ChainCommitteeEmpty"},
             sigs   : {"Valid", "Invalid"},
             member : BOOLEAN,
             bug    : BOOLEAN]

Backends == {"Up", "Down"}

WellFormed(m) == m.defect = "None"

--------------------------------------------------------------------------
(* Admission decision                                                      *)

Checks(b) ==
    IF PreFix THEN
        CASE b = "Create"       -> <<"Member", "Construct", "Sigs", "Bind", "Apply">>
          [] b = "Finalized"    -> <<"Construct", "Sigs", "Bind", "Apply">>
          [] b = "VerifierRecv" -> <<"Member", "Construct", "Sigs", "Apply">>
          [] b = "Pull"         -> <<"Construct", "Sigs", "Bind", "Apply">>
    ELSE
        CASE b = "Create"       -> <<"Member", "Preflight", "Bind", "Construct", "Sigs", "Apply">>
          [] b = "Finalized"    -> <<"Preflight", "Bind", "Construct", "Sigs", "Apply">>
          [] b = "VerifierRecv" -> <<"Preflight", "Member", "Bind", "Construct", "Sigs", "Apply">>
          [] b = "Pull"         -> <<"Preflight", "Bind", "Construct", "Sigs", "Apply">>

\* Result of one check: "Pass", or the message's outcome.
Step(c, m, be) ==
    CASE c = "Member"    -> IF m.member THEN "Pass" ELSE "Ignore"
      [] c = "Preflight" -> IF WellFormed(m) THEN "Pass" ELSE "Reject"
      [] c = "Bind"      ->
            IF be = "Down" THEN "Retry"
            ELSE IF m.bind = "ChainCommitteeEmpty" THEN (IF PreFix THEN "Panic" ELSE "Reject")
            ELSE IF m.bind = "Mismatch" \/ m.defect \in InstanceDefects THEN "Reject"
            ELSE "Pass"
      [] c = "Construct" ->
            IF WellFormed(m) THEN "Pass"
            ELSE IF PreFix /\ m.defect \in PreFixPanicDefects THEN "Panic"
            ELSE "Reject"
      [] c = "Sigs"      -> IF m.sigs = "Valid" THEN "Pass" ELSE "Reject"
      [] c = "Apply"     -> IF m.bug THEN "Panic" ELSE "Pass"

Min(S) == CHOOSE i \in S : \A j \in S : i <= j

FirstStop(b, m, be) ==
    {i \in 1..Len(Checks(b)) : Step(Checks(b)[i], m, be) # "Pass"}

Run(b, m, be) ==
    IF FirstStop(b, m, be) = {} THEN "Accept"
    ELSE Step(Checks(b)[Min(FirstStop(b, m, be))], m, be)

\* Check c is executed for this message.
Reached(b, m, be, c) ==
    \E i \in 1..Len(Checks(b)) :
        /\ Checks(b)[i] = c
        /\ \A j \in 1..(i - 1) : Step(Checks(b)[j], m, be) = "Pass"

--------------------------------------------------------------------------
(* Decision properties, over every boundary, message and backend state.   *)
(* They do not depend on the process state below.                          *)

\* The panicking construction step and the signature checks only ever see
\* a structurally valid graph whose instance is bound to both chains.
ConstructOnlyAfterPreflightAndBinding ==
    \A b \in Boundaries, m \in Messages, be \in Backends :
        (Reached(b, m, be, "Construct") \/ Reached(b, m, be, "Sigs"))
            => WellFormed(m) /\ be = "Up" /\ m.bind = "Bound"

\* No input, malformed or not, makes admission panic: only a genuine bug.
OnlyBugsPanic ==
    \A b \in Boundaries, m \in Messages, be \in Backends :
        Run(b, m, be) = "Panic" => m.bug

\* Malformed input is rejected for good, with or without the backend: the
\* preflight never waits for a chain read. (Create checks membership first;
\* a non-member ignores the message.)
MalformedRejectedPermanently ==
    \A b \in Boundaries, m \in Messages, be \in Backends :
        ~WellFormed(m) => Run(b, m, be) \in {"Reject", "Ignore"}

\* A well-formed message is never judged while the backend is down.
BackendDownIsRetry ==
    \A b \in Boundaries, m \in Messages :
        (WellFormed(m) /\ Run(b, m, "Down") # "Ignore") => Run(b, m, "Down") = "Retry"

\* A well-formed message whose instance does not match the chains is
\* rejected for good (not retried, not panicking).
BindingMismatchRejected ==
    \A b \in Boundaries, m \in Messages :
        (WellFormed(m) /\ m.bind # "Bound" /\ Run(b, m, "Up") # "Ignore")
            => Run(b, m, "Up") = "Reject"

\* Acceptance needs every check: well-formed, bound, signed, backend up.
AcceptOnlyWhenChecked ==
    \A b \in Boundaries, m \in Messages, be \in Backends :
        Run(b, m, be) = "Accept"
            => WellFormed(m) /\ m.bind = "Bound" /\ m.sigs = "Valid" /\ be = "Up" /\ ~m.bug

\* A genuine panic in a fully admitted message still reaches the engine,
\* so the poison mechanism stays in force for real bugs.
GenuinePanicSurfaces ==
    \A b \in Boundaries, m \in Messages :
        (WellFormed(m) /\ m.bind = "Bound" /\ m.sigs = "Valid" /\ m.member /\ m.bug)
            => Run(b, m, "Up") = "Panic"

--------------------------------------------------------------------------
(* Process model: the jobs of one (graph, action) run one at a time        *)
(* through the engine, with its poison backoff.                            *)

\* Message shapes in the queue (named so traces read well).
Shape(name) ==
    CASE name = "Good"       -> [defect |-> "None", bind |-> "Bound", sigs |-> "Valid", member |-> TRUE, bug |-> FALSE]
      [] name = "Bug"        -> [defect |-> "None", bind |-> "Bound", sigs |-> "Valid", member |-> TRUE, bug |-> TRUE]
      [] name = "BadSig"     -> [defect |-> "None", bind |-> "Bound", sigs |-> "Invalid", member |-> TRUE, bug |-> FALSE]
      [] name = "Unbound"    -> [defect |-> "None", bind |-> "Mismatch", sigs |-> "Valid", member |-> TRUE, bug |-> FALSE]
      [] name = "ChainEmpty" -> [defect |-> "None", bind |-> "ChainCommitteeEmpty", sigs |-> "Valid", member |-> TRUE, bug |-> FALSE]
      [] name \in Defects    -> [defect |-> name, bind |-> "Bound", sigs |-> "Valid", member |-> TRUE, bug |-> FALSE]
Names == {"Good", "Bug", "BadSig", "Unbound", "ChainEmpty"} \cup Defects

\* poison_backoff Steps(0, 600, 3600, ...) scaled: the first poison holds
\* nothing back, later ones do.
PoisonBackoff(n) == IF n <= 1 THEN 0 ELSE IF n = 2 THEN 2 ELSE 3

Outcomes == {"Accept", "Reject", "Ignore", "Retry", "Panic"}

VARIABLES
    boundary,     \* which admission boundary these jobs go through
    queue,        \* names of the pending messages; head runs next
    now,
    backend,
    poisonCount,  \* engine_aggregate_poison.poison_count of (graph, action)
    blockedUntil, \* engine_aggregate_poison.blocked_until
    causes,       \* "Bug" / "Input": what caused the current poison streak
    processed     \* finished messages: [name, outcome]

vars == <<boundary, queue, now, backend, poisonCount, blockedUntil, causes, processed>>

TypeOK ==
    /\ boundary \in Boundaries
    /\ queue \in Seq(Names)
    /\ now \in 0..MaxTime
    /\ backend \in Backends
    /\ poisonCount \in 0..QueueLen
    /\ blockedUntil \in 0..(MaxTime + 3)
    /\ causes \subseteq {"Bug", "Input"}
    /\ \A i \in 1..Len(processed) :
           processed[i].name \in Names /\ processed[i].outcome \in Outcomes

Init ==
    /\ boundary \in Boundaries
    /\ queue \in [1..QueueLen -> Names]
    /\ now = 0
    /\ backend \in Backends
    /\ poisonCount = 0
    /\ blockedUntil = 0
    /\ causes = {}
    /\ processed = <<>>

\* claim_due_engine_jobs skips the job while blocked_until > now.
Claimable == queue # <<>> /\ blockedUntil <= now

RunHead ==
    /\ Claimable
    /\ LET name == Head(queue)
           m == Shape(name)
           o == Run(boundary, m, backend)
       IN
       IF o = "Retry" THEN
           \* Transient: the job stays pending; the clean finish releases poison.
           /\ poisonCount' = 0
           /\ blockedUntil' = 0
           /\ causes' = {}
           /\ UNCHANGED <<queue, processed>>
       ELSE IF o = "Panic" THEN
           \* Poisoned: terminal for this job, backoff for the action.
           /\ poisonCount' = poisonCount + 1
           /\ blockedUntil' = now + PoisonBackoff(poisonCount + 1)
           /\ causes' = causes \cup {IF m.bug THEN "Bug" ELSE "Input"}
           /\ queue' = Tail(queue)
           /\ processed' = Append(processed, [name |-> name, outcome |-> o])
       ELSE
           \* Accept / Reject / Ignore: the job ran to a result.
           /\ poisonCount' = 0
           /\ blockedUntil' = 0
           /\ causes' = {}
           /\ queue' = Tail(queue)
           /\ processed' = Append(processed, [name |-> name, outcome |-> o])
    /\ UNCHANGED <<boundary, now, backend>>

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<boundary, queue, backend, poisonCount, blockedUntil, causes, processed>>

BackendFlip ==
    /\ backend' \in Backends \ {backend}
    /\ UNCHANGED <<boundary, queue, now, poisonCount, blockedUntil, causes, processed>>

Next == RunHead \/ Tick \/ BackendFlip

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------
(* Process properties                                                      *)

\* Only a genuine panic counts towards the (graph, action) poison.
PoisonOnlyFromGenuinePanics == causes \subseteq {"Bug"}

\* A well-formed message waiting behind a poison backoff is only ever held
\* back by a genuine panic, never by malformed messages sent before it.
GoodNotBlockedByMalformed ==
    (queue # <<>> /\ WellFormed(Shape(Head(queue))) /\ blockedUntil > now)
        => "Bug" \in causes

\* Every finished message got the outcome its class calls for: malformed
\* input is rejected, a well-formed and bound graph is accepted, and a
\* genuine bug is poisoned.
OutcomesByClass ==
    \A i \in 1..Len(processed) :
        LET name == processed[i].name
            o == processed[i].outcome
        IN /\ name \in Defects => o = "Reject"
           /\ name = "Good" => o = "Accept"
           /\ name = "Bug" => o = "Panic"
           /\ name \in {"BadSig", "Unbound", "ChainEmpty"} => o = "Reject"

====
