---- MODULE GraphLifecycleFineGrainedFixed ----
(***************************************************************************)
(* Companion to GraphLifecycleFineGrained.tla, which demonstrated that      *)
(* splitting the guard-check from the write into two separate steps (read,  *)
(* then later write - exactly what a `SELECT` followed by an `UPDATE` in    *)
(* application code does) leaves a real gap, even with the correct guard    *)
(* logic on both sides.                                                    *)
(*                                                                         *)
(* The actual fix (node/src/utils.rs + crates/store/src/localdb.rs) moves  *)
(* the guard into the SQL statement itself: `GraphUpdate::only_if_status_in` *)
(* becomes a `WHERE status IN (...)` clause on the same `UPDATE` that sets  *)
(* the new status, so the read-the-current-value-and-decide step and the   *)
(* write happen as ONE indivisible database statement - there is no gap    *)
(* for another writer's statement to land inside.                          *)
(*                                                                         *)
(* This module models exactly that: each writer's read+decide+write is ONE *)
(* PlusCal label (one atomic step), reusing the identical guard and target  *)
(* sets from GraphLifecycleFineGrained.tla. If the properties that failed   *)
(* there hold here, that confirms the SQL-level fix - not just the         *)
(* application-level guard logic - is what actually closes the gap.        *)
(***************************************************************************)
EXTENDS GraphTopology

GoatTargets == {"OperatorDataPushed", "OperatorTake1", "OperatorTake2", "Disprove"}

GuardOK(current, target) ==
    /\ ~(current \in TerminalStatuses /\ current # target)
    /\ (target = "OperatorDataPushed" =>
          current \in {"OperatorPresigned", "CommitteePresigned", "OperatorDataPushed"})

(*--algorithm GraphWriteRaceFixed
variables status = "OperatorPresigned";

process ChainScan = "ChainScan"
variables csTarget = "";
begin
  CSStep:
    while TRUE do
        with t \in ({t2 \in AllStatuses : <<status, t2>> \in AllowedTransitions} \cup {status}) do
            csTarget := t;
        end with;
        if GuardOK(status, csTarget) then
            status := csTarget;
        end if;
    end while;
end process;

process GoatRace = "GoatRace"
variables grTarget = "";
begin
  GRStep:
    while TRUE do
        with t \in GoatTargets do
            grTarget := t;
        end with;
        if GuardOK(status, grTarget) then
            status := grTarget;
        end if;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES status, csTarget, grTarget

vars == << status, csTarget, grTarget >>

ProcSet == {"ChainScan"} \cup {"GoatRace"}

Init == (* Global variables *)
        /\ status = "OperatorPresigned"
        (* Process ChainScan *)
        /\ csTarget = ""
        (* Process GoatRace *)
        /\ grTarget = ""

ChainScan == /\ \E t \in ({t2 \in AllStatuses : <<status, t2>> \in AllowedTransitions} \cup {status}):
                  csTarget' = t
             /\ IF GuardOK(status, csTarget')
                   THEN /\ status' = csTarget'
                   ELSE /\ TRUE
                        /\ UNCHANGED status
             /\ UNCHANGED grTarget

GoatRace == /\ \E t \in GoatTargets:
                 grTarget' = t
            /\ IF GuardOK(status, grTarget')
                  THEN /\ status' = grTarget'
                  ELSE /\ TRUE
                       /\ UNCHANGED status
            /\ UNCHANGED csTarget

Next == ChainScan \/ GoatRace

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

TypeOK == status \in AllStatuses

TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

NoConflictingWithdrawal ==
    /\ [][(status = "OperatorTake1" => status' # "OperatorTake2")]_status
    /\ [][(status = "OperatorTake2" => status' # "OperatorTake1")]_status

====
