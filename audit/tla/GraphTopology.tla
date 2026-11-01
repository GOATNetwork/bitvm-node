---- MODULE GraphTopology ----
(***************************************************************************)
(* The Graph.status vocabulary and the code's status-transition table,     *)
(* shared by GraphLifecycle.tla and GraphLifecycleFineGrainedFixed.tla so   *)
(* the two specs cannot drift from each other or from the code.             *)
(*                                                                         *)
(* Code scope (dev after #476):                                            *)
(*   - GraphStatus, GraphStatusSource, GraphStatus::get_closed_status and   *)
(*     GraphStatus::allowed_transition_from in crates/store/src/schema.rs:  *)
(*     348-510. Every Graph.status write goes through                       *)
(*     StorageProcessor::transition_graph_status                           *)
(*     (crates/store/src/localdb/graph.rs:450), one conditional             *)
(*     `UPDATE graph SET status = target ... WHERE status IN                *)
(*     allowed_transition_from(target, source)`.                            *)
(*   - The protocol order of the stages that scan_graph_chain_state         *)
(*     (node/src/utils/graph_chain_state.rs:222) derives from Bitcoin and   *)
(*     the Goat gateway.                                                    *)
(*                                                                         *)
(* No variables: this module only defines constants and operators.         *)
(***************************************************************************)

\* Graph.status values (GraphStatus, crates/store/src/schema.rs:348).
OperatorPresigned  == "OperatorPresigned"
CommitteePresigned == "CommitteePresigned"
OperatorDataPushed == "OperatorDataPushed"
PreKickoff         == "PreKickoff"
OperatorKickOff    == "OperatorKickOff"
Challenge          == "Challenge"
Disprove           == "Disprove"
Obsoleted          == "Obsoleted"
Skipped            == "Skipped"
OperatorTake1      == "OperatorTake1"
OperatorTake2      == "OperatorTake2"

AllStatuses == {
    OperatorPresigned, CommitteePresigned, OperatorDataPushed,
    PreKickoff, OperatorKickOff, Challenge,
    OperatorTake1, OperatorTake2, Skipped, Obsoleted, Disprove
}

\* GraphStatus::get_closed_status (schema.rs:384). Obsoleted is NOT closed: a
\* graph retired before its Pre-Kickoff becomes live again once the chain shows
\* its Pre-Kickoff, Kickoff or a later transaction.
TerminalStatuses == {OperatorTake1, OperatorTake2, Skipped, Disprove}

\* The evidence behind a write (GraphStatusSource, schema.rs:369).
SourceDefinition     == "Definition"
SourceGoatEvent      == "GoatEvent"
SourceChainReconcile == "ChainReconcile"
Sources == {SourceDefinition, SourceGoatEvent, SourceChainReconcile}

\* Protocol order of the chain-derived stages: the stages strictly before
\* `stage` on the protocol DAG. Pre-Kickoff, Kickoff, Skip-Kickoff, Take-1,
\* Challenge, Take-2 and Disprove are Bitcoin transactions whose spends decide
\* the branch (Bitcoin consensus); OperatorDataPushed is the Goat GraphData.
StagesBefore(stage) ==
    CASE stage = OperatorPresigned  -> {}
      [] stage = CommitteePresigned -> {OperatorPresigned}
      [] stage = OperatorDataPushed -> {OperatorPresigned, CommitteePresigned}
      [] stage = PreKickoff         -> {OperatorPresigned, CommitteePresigned, OperatorDataPushed}
      [] stage \in {OperatorKickOff, Skipped} ->
            {OperatorPresigned, CommitteePresigned, OperatorDataPushed, PreKickoff}
      [] stage \in {Challenge, OperatorTake1} ->
            {OperatorPresigned, CommitteePresigned, OperatorDataPushed, PreKickoff,
             OperatorKickOff}
      [] stage \in {OperatorTake2, Disprove} ->
            {OperatorPresigned, CommitteePresigned, OperatorDataPushed, PreKickoff,
             OperatorKickOff, Challenge}
      [] OTHER -> {}

\* GraphStatus::allowed_transition_from (schema.rs:438-509): the statuses from
\* which `target` may be written with evidence `source`. The sets contain
\* transitive predecessors (one chain scan may observe several confirmed
\* transactions at once) and never a closed status.
AllowedFrom(target, source) ==
    LET Early           == {OperatorPresigned, CommitteePresigned}
        EarlyOrObsolete == {OperatorPresigned, CommitteePresigned, Obsoleted}
        PreKickoffFrom  == {OperatorPresigned, CommitteePresigned, OperatorDataPushed, Obsoleted}
        KickoffFrom     == PreKickoffFrom \cup {PreKickoff}
        ChallengeFrom   == KickoffFrom \cup {OperatorKickOff}
        Take2From       == ChallengeFrom \cup {Challenge}
        ObsoletedFrom   == {OperatorPresigned, CommitteePresigned, OperatorDataPushed,
                            PreKickoff, OperatorKickOff, Challenge}
    IN CASE source = SourceDefinition ->
              IF target = CommitteePresigned THEN {OperatorPresigned} ELSE {}
         [] source = SourceGoatEvent ->
              CASE target = OperatorDataPushed -> Early
                [] target = OperatorTake1 -> ChallengeFrom
                [] target \in {OperatorTake2, Disprove} -> Take2From
                [] OTHER -> {}
         [] source = SourceChainReconcile ->
              CASE target = CommitteePresigned -> {OperatorPresigned}
                [] target = OperatorDataPushed -> EarlyOrObsolete
                [] target = Obsoleted -> ObsoletedFrom
                [] target = PreKickoff -> PreKickoffFrom
                [] target = OperatorKickOff -> KickoffFrom
                [] target = Challenge -> ChallengeFrom
                [] target = OperatorTake1 -> ChallengeFrom
                [] target \in {OperatorTake2, Disprove} -> Take2From
                [] target = Skipped -> KickoffFrom
                [] OTHER -> {}
         [] OTHER -> {}

\* The status after one transition_graph_status call: the conditional UPDATE
\* writes `target` iff the current status is in its allowed set, otherwise the
\* row is left unchanged (AlreadyCurrent / Rejected).
Transition(current, target, source) ==
    IF current \in AllowedFrom(target, source) THEN target ELSE current

\* The targets a source can write at all (non-empty allowed set).
TargetsOf(source) == {t \in AllStatuses : AllowedFrom(t, source) # {}}

====
