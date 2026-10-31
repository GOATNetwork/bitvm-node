---- MODULE PegoutPoolCapacity ----
(***************************************************************************)
(* H5: an honest operator answers ChallengeAsserts one at a time, so with  *)
(* N verifiers challenging and E blocks of GC evaluation per answer, the   *)
(* last Wrongly-Challenged is broadcast at ~N*E blocks - past              *)
(* prover_connector (T2) when N*E > T2 - Incl, and that verifier          *)
(* disproves an honest operator. Checked against dev @ 60562f8.            *)
(*                                                                         *)
(* THE CODE:                                                               *)
(*  - graph_scan.rs:700-738 assert_flow emits one                          *)
(*    ChallengeAssertSent{challenge_assert_txid, verifier_index} per       *)
(*    confirmed Verifier-Assert; graph_pegout.rs:275 routes each to        *)
(*    JOB_WRONGLY_CHALLENGED, one job per verifier (distinct params).      *)
(*  - graph_pegout.rs:87-96 pegout_job_pool: JOB_WRONGLY_CHALLENGED =>     *)
(*    JobPool::Pegout. config.rs:97-99 defaults cpu_pool_slots: 1,         *)
(*    pegout_pool_slots: 1, network_pool_slots: 4; jobs.rs:66-70 makes     *)
(*    each a Semaphore of that many permits (shared by ALL graphs).        *)
(*  - store engine/mod.rs:1336-1393 claim_due_engine_jobs skips "every job *)
(*    of an aggregate that already has a job running under a live lease, *)
(*    in any pool" (:1350-1353 NOT EXISTS ... r.state = 'Running' AND     *)
(*    r.lease_until > ?). All N answers belong to ONE graph aggregate, so *)
(*    they are serialized even if pegout_pool_slots were raised.          *)
(*  - graph_pegout_jobs.rs:1327-1464 wrongly_challenged runs the BABE GC   *)
(*    evaluation inline (babe_adapter.rs:653 prover.check_compute_msg:    *)
(*    the base instance, then up to BABE_M_CC-1 = 6 more finalized        *)
(*    instances of a ~3.4e9-gate circuit, bitvm-gc README benchmark       *)
(*    table), then broadcasts and goes back to Pending for one block      *)
(*    (broadcast_pending, :230) - that re-run is cheap and not modelled.  *)
(*  - graph_scan.rs:742-788: once ChallengeAssert has prover_connector     *)
(*    confirmations unanswered, the verifier's disprove job fires.        *)
(*  - timelocks.rs:222 validates only                                      *)
(*      ensure_at_least("prover_connector", .., action_window)            *)
(*    (reaction + inclusion + safety = 6 on testnet4; 18 on mainnet) -     *)
(*    no term for N answers of E blocks each. Testnet4 ships              *)
(*    prover_connector = 16 (timelocks.rs:20-29), 5-minute blocks.         *)
(*                                                                         *)
(* Worst case: all N ChallengeAsserts confirm in the same block (colluding *)
(* verifiers can arrange it), height 0 here. Time is in blocks; a job     *)
(* that can be claimed is claimed before the next block (urgency).        *)
(*                                                                         *)
(* FIX CHOSEN (PegoutPoolCapacityFixed.cfg): a timelock budget. Graph      *)
(* validation (validate_timelock_config / graph build, where |gc_data| = N *)
(* is known) requires                                                      *)
(*     prover_connector >= Reaction + N * E_max + Incl                     *)
(* Rejected alternative - parallel answers (lift the per-aggregate gate   *)
(* for independent wrongly_challenged jobs AND pegout_pool_slots >= N):   *)
(* each evaluation holds a flat GC of billions of gates in memory (the    *)
(* README's dv_snark row peaks at 374G for garbling), so N concurrent     *)
(* evaluations on one operator host is not a realistic default, and the   *)
(* Pegout slots are also shared with every other graph of the operator.   *)
(* PegoutPoolCapacitySlotsOnly.cfg shows that raising pegout_pool_slots   *)
(* alone does NOT help, because of the per-aggregate gate.                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,                   \* verifiers whose ChallengeAssert the operator must answer
    E,                   \* blocks of GC evaluation per Wrongly-Challenged
    T2,                  \* prover_connector (disprove timelock) in blocks
    Incl,                \* blocks a broadcast needs to confirm (inclusion budget)
    Reaction,            \* blocks before the scan has queued the jobs
    Slots,               \* pegout_pool_slots
    PerAggregateSerial   \* claim_due_engine_jobs: one Running job per aggregate

ASSUME N \in Nat /\ N >= 1
ASSUME E \in Nat /\ E >= 1
ASSUME {T2, Incl, Reaction} \subseteq Nat /\ T2 > Incl
ASSUME Slots \in Nat /\ Slots >= 1
ASSUME PerAggregateSerial \in BOOLEAN

Verifiers == 1..N
\* Last height at which a Wrongly-Challenged may be broadcast and still
\* confirm before the verifier's Disprove becomes valid.
LastBroadcast == T2 - Incl

VARIABLES
    h,      \* blocks since the ChallengeAsserts confirmed
    st,     \* per verifier: "Queued" | "Running" | "Answered"
    left    \* blocks of evaluation left for a Running answer

vars == <<h, st, left>>

TypeOK ==
    /\ h \in 0..LastBroadcast
    /\ st \in [Verifiers -> {"Queued", "Running", "Answered"}]
    /\ left \in [Verifiers -> 0..E]

Init ==
    /\ h = 0
    /\ st = [i \in Verifiers |-> "Queued"]
    /\ left = [i \in Verifiers |-> E]

Running == {i \in Verifiers : st[i] = "Running"}

-----------------------------------------------------------------------------
\* The executor claims a due Pegout job: a free pool permit, and (current
\* code) no other job of the same graph aggregate running.
Claim(i) ==
    /\ h >= Reaction
    /\ st[i] = "Queued"
    /\ Cardinality(Running) < Slots
    /\ PerAggregateSerial => Running = {}
    /\ st' = [st EXCEPT ![i] = "Running"]
    /\ UNCHANGED <<h, left>>

\* A block passes; every running evaluation advances one block and a
\* finished one is broadcast at the new height.
Tick ==
    /\ h < LastBroadcast
    /\ ~\E i \in Verifiers : ENABLED Claim(i)
    /\ h' = h + 1
    /\ left' = [i \in Verifiers |->
                  IF st[i] = "Running" THEN left[i] - 1 ELSE left[i]]
    /\ st' = [i \in Verifiers |->
                IF st[i] = "Running" /\ left[i] = 1 THEN "Answered" ELSE st[i]]

Next == (\E i \in Verifiers : Claim(i)) \/ Tick

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* By the last useful broadcast height every ChallengeAssert is answered.
HonestOperatorAnswersAll ==
    h = LastBroadcast => \A i \in Verifiers : st[i] = "Answered"

\* The arithmetic the chosen fix enforces at graph validation.
TimelockBudgetCoversAnswers == T2 >= Reaction + N * E + Incl

====
