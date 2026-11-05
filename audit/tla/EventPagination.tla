---- MODULE EventPagination ----
(***************************************************************************)
(* How the event watcher reads and commits one block window [From, To] of  *)
(* subgraph events. Ground truth:                                          *)
(*   - GraphQueryClient::get_events (crates/client/src/graphs/mod.rs):     *)
(*     every entity kind is paged on its own `id_gt` cursor, ordered by    *)
(*     id, PAGE_SIZE rows per page. A full page means read on; a short or  *)
(*     empty page means that kind is done. An RPC error, a missing event   *)
(*     array, an oversized page, a missing/empty id, an unparsable or      *)
(*     out-of-range blockNumber, and a duplicate or non-advancing id are   *)
(*     all errors, never an early "done". After the last page the kind's   *)
(*     events are stably sorted by block, so ID paging order is not the    *)
(*     processing order.                                                   *)
(*   - fetch_and_handle_gateway_events / fetch_and_handle_bridge_out_events*)
(*     (node/src/scheduled_tasks/event_watch/{gateway,bridge_out}.rs): the *)
(*     typed decode and the handlers run after every kind is read, one     *)
(*     category after another in their existing fixed order.              *)
(*   - fetch_history_events / monitor_events_item                          *)
(*     (node/src/scheduled_tasks/event_watch/mod.rs): the handlers write   *)
(*     into one DB transaction, which also upserts the next block cursor   *)
(*     (from_height = To + 1); any `?` error drops the transaction, so the *)
(*     cursor stays at From and the window is read again from scratch.     *)
(*                                                                         *)
(* The indexer is assumed to page honestly (its rows are the real events); *)
(* a misbehaving response is only modelled as one the reader detects and   *)
(* rejects. Out of scope: whether the indexer is trustworthy or complete,  *)
(* the transaction boundary of the handlers themselves (M21), on-chain     *)
(* confirmation of terminal states (M32), and whether a failed history     *)
(* sync is restarted or its error reported (L30) - a failed window is     *)
(* simply assumed to be tried again.                                       *)
(*                                                                         *)
(* Each entity kind is its own category here, kinds 1..NumKinds in their   *)
(* existing processing order. The indexer's data is chosen in Init: every  *)
(* kind holds 0..MaxEvents events, event i of a kind has ID i, and each    *)
(* lands in any block of the window - so a single block can hold more     *)
(* events than one page, and ID order can disagree with block order.       *)
(*                                                                         *)
(* Mode:                                                                   *)
(*   "Fixed"  - the reader on this branch.                                 *)
(*   "PreFix" - the old reader: one query per kind, ordered by block with  *)
(*              the indexer's default page size, then the cursor advances *)
(*              (expected to violate NoEventLost).                         *)
(*   "NoSort" - the fixed reader without the final per-kind block sort     *)
(*              (expected to violate BlockOrderWithinCategory).            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS NumKinds, NumBlocks, PageSize, MaxEvents, MaxFaults, Mode

ASSUME Mode \in {"Fixed", "PreFix", "NoSort"}
ASSUME PageSize >= 1 /\ NumBlocks >= 1

Kinds  == 1..NumKinds
From   == 1
To     == NumBlocks
Blocks == From..To

\* Errors the reader or the handlers raise; each one aborts the window.
FetchErrors   == {"RpcError", "MissingArray", "OversizedPage", "MalformedId",
                  "MalformedBlock", "OutOfRange", "NonAdvancingId"}
ProcessErrors == {"DecodeError", "HandlerError", "CommitError"}

VARIABLES
    data,        \* [Kinds -> Seq(Blocks)]: what the indexer holds (fixed)
    phase,       \* "Fetch" | "Process" | "Done"
    kind,        \* kind being paged (NumKinds + 1 once all are read)
    idCursor,    \* last ID read for `kind`, 0 before its first page
    fetched,     \* [Kinds -> SUBSET Nat]: IDs read in this attempt (memory)
    processed,   \* handler writes in the open transaction, in order
    db,          \* events committed to the database
    blockCursor, \* committed from_height: From, or To + 1 after the commit
    faults,      \* errors injected so far
    lastError

vars == <<data, phase, kind, idCursor, fetched, processed, db, blockCursor,
          faults, lastError>>

Ev(k, i)    == [k |-> k, id |-> i]
Block(e)    == data[e.k][e.id]
IdsOf(k)    == 1..Len(data[k])
AllEvents   == UNION {{Ev(k, i) : i \in IdsOf(k)} : k \in Kinds}
Range(s)    == {s[j] : j \in 1..Len(s)}

\* Stable sort by block: same block keeps ID order.
BlockBefore(k, i, j) == data[k][i] < data[k][j] \/ (data[k][i] = data[k][j] /\ i < j)

TypeOK ==
    /\ phase \in {"Fetch", "Process", "Done"}
    /\ kind \in 1..(NumKinds + 1)
    /\ idCursor \in 0..MaxEvents
    /\ \A k \in Kinds : fetched[k] \subseteq IdsOf(k)
    /\ Range(processed) \subseteq AllEvents
    /\ db \subseteq AllEvents
    /\ blockCursor \in {From, To + 1}
    /\ faults \in 0..MaxFaults

Init ==
    /\ data \in [Kinds -> UNION {[1..n -> Blocks] : n \in 0..MaxEvents}]
    /\ phase = "Fetch"
    /\ kind = 1
    /\ idCursor = 0
    /\ fetched = [k \in Kinds |-> {}]
    /\ processed = <<>>
    /\ db = {}
    /\ blockCursor = From
    /\ faults = 0
    /\ lastError = "None"

-----------------------------------------------------------------------------
(* Reading. *)

\* Honest page after the ID cursor: `orderBy: id, id_gt: cursor, first: PageSize`.
IdPage(k, after) == {i \in IdsOf(k) : after < i /\ i <= after + PageSize}

\* Old query: `orderBy: blockNumber`, no cursor, the indexer's default `first`.
BlockFirstPage(k) ==
    {i \in IdsOf(k) : Cardinality({j \in IdsOf(k) : BlockBefore(k, j, i)}) < PageSize}

FetchPage ==
    /\ phase = "Fetch"
    /\ kind <= NumKinds
    /\ IF Mode = "PreFix"
          THEN /\ fetched' = [fetched EXCEPT ![kind] = BlockFirstPage(kind)]
               /\ kind' = kind + 1
               /\ idCursor' = 0
          ELSE LET page == IdPage(kind, idCursor) IN
               /\ fetched' = [fetched EXCEPT ![kind] = @ \cup page]
               /\ IF Cardinality(page) < PageSize
                     THEN kind' = kind + 1 /\ idCursor' = 0   \* short/empty page: kind done
                     ELSE kind' = kind /\ idCursor' = idCursor + PageSize
    /\ UNCHANGED <<data, phase, processed, db, blockCursor, faults, lastError>>

AllKindsRead ==
    /\ phase = "Fetch"
    /\ kind = NumKinds + 1
    /\ phase' = "Process"
    /\ UNCHANGED <<data, kind, idCursor, fetched, processed, db, blockCursor,
                   faults, lastError>>

-----------------------------------------------------------------------------
(* Processing, inside the window's transaction. *)

Unprocessed(k) == {i \in fetched[k] : Ev(k, i) \notin Range(processed)}

\* Categories run one after another in their fixed order.
CurrentKind == CHOOSE k \in Kinds :
                  Unprocessed(k) # {} /\ \A k2 \in Kinds : k2 < k => Unprocessed(k2) = {}

\* Inside a category: block order (stable), or raw ID order without the sort.
Earlier(k, i, j) == IF Mode = "NoSort" THEN i < j ELSE BlockBefore(k, i, j)

ProcessNext ==
    /\ phase = "Process"
    /\ \E k \in Kinds : Unprocessed(k) # {}
    /\ LET k == CurrentKind
           i == CHOOSE i \in Unprocessed(k) :
                    \A j \in Unprocessed(k) \ {i} : Earlier(k, i, j)
       IN processed' = Append(processed, Ev(k, i))
    /\ UNCHANGED <<data, phase, kind, idCursor, fetched, db, blockCursor,
                   faults, lastError>>

\* Events and the next block cursor land in one commit.
Commit ==
    /\ phase = "Process"
    /\ \A k \in Kinds : Unprocessed(k) = {}
    /\ db' = db \cup Range(processed)
    /\ blockCursor' = To + 1
    /\ phase' = "Done"
    /\ UNCHANGED <<data, kind, idCursor, fetched, processed, faults, lastError>>

-----------------------------------------------------------------------------
(* Failures: the transaction is dropped, nothing of the window is kept, and *)
(* the window is read again from the unchanged block cursor.                *)

Abort(err) ==
    /\ faults < MaxFaults
    /\ phase' = "Fetch"
    /\ kind' = 1
    /\ idCursor' = 0
    /\ fetched' = [k \in Kinds |-> {}]
    /\ processed' = <<>>
    /\ faults' = faults + 1
    /\ lastError' = err
    /\ UNCHANGED <<data, db, blockCursor>>

\* Any page, including a later page of a kind whose first page succeeded.
FetchFails ==
    /\ phase = "Fetch"
    /\ kind <= NumKinds
    /\ \E err \in FetchErrors : Abort(err)

\* Typed decode of a field, a handler, or the commit itself fails.
ProcessFails ==
    /\ phase = "Process"
    /\ \E err \in ProcessErrors : Abort(err)

Progress == FetchPage \/ AllKindsRead \/ ProcessNext \/ Commit

Next == Progress \/ FetchFails \/ ProcessFails

Spec == Init /\ [][Next]_vars /\ WF_vars(Progress)

-----------------------------------------------------------------------------
(* Properties. *)

\* Once the block cursor moves past the window, every event of the window is
\* committed - also when one block holds more events than a page.
NoEventLost == blockCursor = To + 1 => db = AllEvents

\* Nothing of the window is committed while the cursor still points at it.
NoPartialCommit == blockCursor = From => db = {}

\* A kind is only left behind after it has been read to the end.
FinishedKindsFullyRead ==
    \A k \in Kinds :
        (k < kind \/ phase # "Fetch") => fetched[k] = IdsOf(k)

\* Handlers run in the existing category order ...
CategoryOrder ==
    \A a, b \in 1..Len(processed) : a < b => processed[a].k <= processed[b].k

\* ... and in block order inside a category, whatever the ID order.
BlockOrderWithinCategory ==
    \A a, b \in 1..Len(processed) :
        (a < b /\ processed[a].k = processed[b].k) => Block(processed[a]) <= Block(processed[b])

\* Each event is handled at most once per attempt.
NoDuplicateHandling == Cardinality(Range(processed)) = Len(processed)

\* With finitely many errors the window is eventually committed.
EventuallyCommitted == <>(blockCursor = To + 1)

====
