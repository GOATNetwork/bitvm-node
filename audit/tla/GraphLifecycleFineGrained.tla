---- MODULE GraphLifecycleFineGrained ----
(***************************************************************************)
(* GraphLifecycle.tla / GraphLifecycleFixed.cfg model update_graph_status_guarded's *)
(* guard-check-then-write as ONE atomic TLA+ step. The real function is NOT *)
(* atomic: `find_graph(...).await` (the read) and `update_graph(...).await` *)
(* (the write) are two separate yield points (node/src/utils.rs). This     *)
(* module exposes that gap explicitly with PlusCal: each writer reads a    *)
(* snapshot, decides using the SAME guard logic as the real fix, and only  *)
(* writes later - so TLC can explore another writer's full read-decide-    *)
(* write completing in between.                                            *)
(***************************************************************************)
EXTENDS GraphTopology

GoatTargets == {"OperatorDataPushed", "OperatorTake1", "OperatorTake2", "Disprove"}

(* The exact guard from node/src/utils.rs's update_graph_status_guarded,
   applied to a (possibly stale) `current` reading. *)
GuardOK(current, target) ==
    /\ ~(current \in TerminalStatuses /\ current # target)
    /\ (target = "OperatorDataPushed" =>
          current \in {"OperatorPresigned", "CommitteePresigned", "OperatorDataPushed"})

(*--algorithm GraphWriteRace
variables status = "OperatorPresigned";

process ChainScan = "ChainScan"
variables csSnap = "", csTarget = "";
begin
  CSRead:
    while TRUE do
        csSnap := status;
        with t \in ({t2 \in AllStatuses : <<csSnap, t2>> \in AllowedTransitions} \cup {csSnap}) do
            csTarget := t;
        end with;
  CSWrite:
        if GuardOK(csSnap, csTarget) then
            status := csTarget;
        end if;
    end while;
end process;

process GoatRace = "GoatRace"
variables grSnap = "", grTarget = "";
begin
  GRRead:
    while TRUE do
        grSnap := status;
        with t \in GoatTargets do
            grTarget := t;
        end with;
  GRWrite:
        if GuardOK(grSnap, grTarget) then
            status := grTarget;
        end if;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES status, pc, csSnap, csTarget, grSnap, grTarget

vars == << status, pc, csSnap, csTarget, grSnap, grTarget >>

ProcSet == {"ChainScan"} \cup {"GoatRace"}

Init == (* Global variables *)
        /\ status = "OperatorPresigned"
        (* Process ChainScan *)
        /\ csSnap = ""
        /\ csTarget = ""
        (* Process GoatRace *)
        /\ grSnap = ""
        /\ grTarget = ""
        /\ pc = [self \in ProcSet |-> CASE self = "ChainScan" -> "CSRead"
                                        [] self = "GoatRace" -> "GRRead"]

CSRead == /\ pc["ChainScan"] = "CSRead"
          /\ csSnap' = status
          /\ \E t \in ({t2 \in AllStatuses : <<csSnap', t2>> \in AllowedTransitions} \cup {csSnap'}):
               csTarget' = t
          /\ pc' = [pc EXCEPT !["ChainScan"] = "CSWrite"]
          /\ UNCHANGED << status, grSnap, grTarget >>

CSWrite == /\ pc["ChainScan"] = "CSWrite"
           /\ IF GuardOK(csSnap, csTarget)
                 THEN /\ status' = csTarget
                 ELSE /\ TRUE
                      /\ UNCHANGED status
           /\ pc' = [pc EXCEPT !["ChainScan"] = "CSRead"]
           /\ UNCHANGED << csSnap, csTarget, grSnap, grTarget >>

ChainScan == CSRead \/ CSWrite

GRRead == /\ pc["GoatRace"] = "GRRead"
          /\ grSnap' = status
          /\ \E t \in GoatTargets:
               grTarget' = t
          /\ pc' = [pc EXCEPT !["GoatRace"] = "GRWrite"]
          /\ UNCHANGED << status, csSnap, csTarget >>

GRWrite == /\ pc["GoatRace"] = "GRWrite"
           /\ IF GuardOK(grSnap, grTarget)
                 THEN /\ status' = grTarget
                 ELSE /\ TRUE
                      /\ UNCHANGED status
           /\ pc' = [pc EXCEPT !["GoatRace"] = "GRRead"]
           /\ UNCHANGED << csSnap, csTarget, grSnap, grTarget >>

GoatRace == GRRead \/ GRWrite

Next == ChainScan \/ GoatRace

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

TypeOK == status \in AllStatuses

TerminalStatusesAreAbsorbing == [][(status \in TerminalStatuses => status' = status)]_status

NoConflictingWithdrawal ==
    /\ [][(status = "OperatorTake1" => status' # "OperatorTake2")]_status
    /\ [][(status = "OperatorTake2" => status' # "OperatorTake1")]_status

====
