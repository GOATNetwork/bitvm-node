---- MODULE GraphTopology ----
(***************************************************************************)
(* The real Graph.status state machine, shared by every spec that models   *)
(* it (GraphLifecycle.tla, GraphLifecycleFineGrained.tla,                  *)
(* GraphLifecycleFineGrainedFixed.tla) - a single source of truth for the  *)
(* status set and the real transition edge set, instead of three          *)
(* independent copies that could silently drift out of sync with each     *)
(* other and with the real code.                                          *)
(*                                                                         *)
(* Ground truth: scan_graph_chain_state, node/src/utils.rs:1328-1681.      *)
(***************************************************************************)

AllStatuses == {
    "OperatorPresigned", "CommitteePresigned", "OperatorDataPushed",
    "PreKickoff", "OperatorKickOff", "Challenge",
    "OperatorTake1", "OperatorTake2", "Skipped", "Obsoleted", "Disprove"
}

\* Obsoleted is NOT terminal in the real code. utils.rs:1418-1434 re-checks
\* `matches!(current_status, PreKickoff | Obsoleted)` and can move an
\* Obsoleted graph to OperatorKickOff or Skipped if a kickoff tx is later
\* observed on-chain.
TerminalStatuses == {"OperatorTake1", "OperatorTake2", "Skipped", "Disprove"}

\* The real edge set from scan_graph_chain_state - used directly by
\* GraphLifecycleCoreOnly.cfg to check the chain-scan state machine is
\* internally sound in isolation, and by NoStatusSkipping in GraphLifecycle.tla.
AllowedTransitions == {
    <<"OperatorPresigned", "CommitteePresigned">>,
    <<"CommitteePresigned", "OperatorDataPushed">>,
    <<"OperatorDataPushed", "PreKickoff">>,
    <<"OperatorPresigned", "Obsoleted">>,
    <<"CommitteePresigned", "Obsoleted">>,
    <<"OperatorDataPushed", "Obsoleted">>,
    <<"PreKickoff", "OperatorKickOff">>,
    <<"Obsoleted", "OperatorKickOff">>,
    <<"PreKickoff", "Skipped">>,
    <<"Obsoleted", "Skipped">>,
    <<"OperatorKickOff", "OperatorTake1">>,
    <<"OperatorKickOff", "Challenge">>,
    <<"OperatorKickOff", "Disprove">>,
    <<"Challenge", "OperatorTake2">>,
    <<"Challenge", "Disprove">>
}

====
