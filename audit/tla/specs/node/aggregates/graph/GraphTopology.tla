---- MODULE GraphTopology ----
(***************************************************************************)
(* Graph.status values and the status-transition table of the code, shared *)
(* by GraphLifecycle and GraphLifecycleFineGrainedFixed.                   *)
(* Code: GraphStatus, GraphStatusSource, get_closed_status and             *)
(*   allowed_transition_from in crates/store/src/schema.rs:348-509. Every  *)
(*   Graph.status write is transition_graph_status                         *)
(*   (crates/store/src/localdb/graph.rs:450): one conditional UPDATE ...   *)
(*   WHERE status IN allowed_transition_from(target, source).              *)
(* Constants and operators only: no variables, no configs.                 *)
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

\* Closed statuses (get_closed_status, schema.rs:384). Obsoleted is not closed:
\* the graph becomes live again once its Pre-Kickoff confirms.
TerminalStatuses == {OperatorTake1, OperatorTake2, Skipped, Disprove}

\* The evidence behind a write (GraphStatusSource, schema.rs:369).
SourceDefinition     == "Definition"
SourceGoatEvent      == "GoatEvent"
SourceChainReconcile == "ChainReconcile"
Sources == {SourceDefinition, SourceGoatEvent, SourceChainReconcile}

\* The stages strictly before `stage` in protocol order. OperatorDataPushed is
\* the Goat GraphData; the stages from PreKickoff on are Bitcoin transactions.
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

\* Statuses from which `target` may be written with evidence `source`
\* (allowed_transition_from, schema.rs:438-509). Includes transitive
\* predecessors (one scan may see several new transactions), never a closed status.
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

\* Status after one transition_graph_status call: `target` iff the current
\* status is in its allowed set, else unchanged (AlreadyCurrent / Rejected).
Transition(current, target, source) ==
    IF current \in AllowedFrom(target, source) THEN target ELSE current

\* Targets a source can write at all (non-empty allowed set).
TargetsOf(source) == {t \in AllStatuses : AllowedFrom(t, source) # {}}

====
