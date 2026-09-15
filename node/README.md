# BitVM Node

The main node implementation for GOAT Network's BitVM bridge protocol. This module handles P2P networking, message processing, scheduled tasks, and RPC services for secure cross-chain asset transfers between Bitcoin and GOAT L2.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Actor System](#actor-system)
- [Core Workflows](#core-workflows)
  - [Peg-in (Bridge-In)](#peg-in-bridge-in)
  - [Peg-out (Bridge-Out)](#peg-out-bridge-out)
  - [Challenge Process](#challenge-process)
- [Graph State Machine](#graph-state-machine)
- [Graph Storage & Synchronization](#graph-storage--synchronization)
- [Message System](#message-system)
- [Scheduled Tasks](#scheduled-tasks)
- [Module Structure](#module-structure)
- [Build & Run](#build--run)
- [Configuration](#configuration)
- [RPC API](#rpc-api)

---

## Overview

The BitVM Node (`bitvm-noded`) is a multi-role distributed node that participates in the BitVM cross-chain bridge protocol. It enables trustless Bitcoin-to-L2 transfers through a combination of:

- **Multi-signature Consensus**: Committee-based transaction presigning
- **Optimistic Verification**: Watchtower monitoring with dispute resolution
- **ZK Proofs**: Cryptographic verification of state transitions
- **P2P Graph Distribution**: Decentralized graph data synchronization via relayer nodes

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **P2P Communication** | libp2p-based gossip network (Kademlia DHT + Gossipsub) |
| **Chain Monitoring** | Bitcoin and GOAT L2 event watching |
| **Graph Management** | Transaction graph creation, signing, and lifecycle tracking |
| **Graph Synchronization** | P2P-based graph distribution with relayer node support |
| **Challenge Processing** | Watchtower challenges and dispute resolution |
| **Proof Coordination** | ZK proof generation via proof-builder-rpc |

---

## Architecture

### Fig-01-1-System-Architecture

```mermaid
flowchart TB
    subgraph External["External Systems"]
        BTC["Bitcoin Network"]
        GOAT["GOAT L2 Chain"]
        PB["Proof Builder RPC"]
    end

    subgraph Node["bitvm-noded"]
        subgraph Input["Input Layer"]
            EW["Event Watch Task"]
            P2P["P2P Swarm (libp2p)"]
            RPC["RPC Service (Axum)"]
        end

        subgraph Core["Core Processing"]
            MH["Message Handler"]
            DISP["Role Dispatcher"]
        end

        subgraph Tasks["Background Tasks"]
            GM["Graph Maintenance"]
            IM["Instance Maintenance"]
            NM["Node Maintenance"]
            SPV["SPV Maintenance"]
        end

        subgraph Storage["Persistence Layer"]
            DB[(SQLite Database)]
            GD[("graph_raw_data\n(Graph JSON)")]
            GM_TBL[("graph\n(Metadata)")]
        end
    end

    BTC --> EW
    GOAT --> EW
    EW --> MH
    P2P --> MH
    RPC --> MH
    MH --> DISP
    DISP --> GM
    DISP --> IM
    GM --> DB
    IM --> DB
    NM --> DB
    SPV --> DB
    GM --> GD
    GM --> GM_TBL
    GM --> PB
```

**Description**: The system employs a three-layer architecture. The Input Layer receives events from external chains, P2P network messages, and RPC requests. The Core Processing Layer dispatches messages to role-specific handlers. The Background Tasks Layer manages graph state machines, instance lifecycles, node health, and SPV header chain updates. All state is persisted to SQLite database, with graph data stored in a dedicated `graph_raw_data` table.

### Fig-01-2-Component-Interaction

```mermaid
flowchart LR
    subgraph Actors["Actor Roles"]
        C["Committee"]
        O["Operator"]
        V["Verifier"]
        W["Watchtower"]
        R["Relayer\n(Committee + Flag)"]
    end

    subgraph Network["P2P Topics"]
        TC["/goat/topic/Committee"]
        TO["/goat/topic/Operator"]
        TV["/goat/topic/Verifier"]
        TW["/goat/topic/Watchtower"]
        TA["/goat/topic/All"]
    end

    C <--> TC
    O <--> TO
    V <--> TV
    W <--> TW
    C & O & V & W & R <--> TA
    R -.->|"SyncGraph"| TA
```

**Description**: Each role subscribes to its corresponding gossipsub topic for message exchange. All roles subscribe to the `/All` topic for broadcast messages. Relayer nodes (Committee members with `ENABLE_RELAYER=true`) respond to graph synchronization requests and distribute graph data across the network.

---

## Actor System

BitVM employs four primary actor roles plus an optional relayer capability:

### Fig-02-1-Actor-Roles

```mermaid
classDiagram
    class Actor {
        <<enumeration>>
        Committee
        Operator
        Verifier
        Watchtower
        All
    }

    class Committee {
        +generate_nonces()
        +presign_transactions()
        +endorse_graph()
        +confirm_pegin()
    }

    class Operator {
        +create_graph()
        +push_data_to_l2()
        +broadcast_kickoff()
        +send_take1_take2()
    }

    class Verifier {
        +monitor_timeouts()
        +submit_disprove()
    }

    class Watchtower {
        +monitor_block_headers()
        +submit_challenge()
        +ack_nack_response()
    }

    class Relayer {
        +respond_sync_request()
        +distribute_graph_data()
        +cache_all_graphs()
    }

    Actor <|-- Committee
    Actor <|-- Operator
    Actor <|-- Verifier
    Actor <|-- Watchtower
    Committee <|-- Relayer : ENABLE_RELAYER=true
```

**Description**: The class diagram shows the inheritance relationship between the Actor enumeration and role implementations. Relayer is a special mode of Committee nodes enabled via environment variable.

### Role Responsibilities

| Role | Responsibilities | Key Messages |
|------|------------------|--------------|
| **Committee** | Multi-sig committee member, responsible for presigning and graph endorsement | `NonceGeneration`, `CommitteePresign`, `EndorseGraph` |
| **Operator** | Bridge operator, creates graphs and executes withdrawal transactions | `CreateGraph`, `KickoffSent`, `Take1Sent`, `Take2Sent` |
| **Verifier** | Dispute verifier, monitors timeouts and submits disproofs | `DisproveReady`, `DisproveSent` |
| **Watchtower** | Chain monitor, validates block headers and submits challenges | `WatchtowerChallengeSent` |
| **Relayer** | Graph data distributor, responds to sync requests | `SyncGraphRequest`, `SyncGraph` |

---

## Core Workflows

### Peg-in (Bridge-In)

Users deposit BTC into the bridge contract and receive equivalent assets on GOAT L2.

#### Fig-03-1-Pegin-Sequence

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant GOAT as GOAT L2
    participant EW as Event Watch
    participant Committee
    participant Operator
    participant BTC as Bitcoin
    participant DB as SQLite DB

    User->>GOAT: Initiate BridgeInRequest
    GOAT-->>EW: Trigger BridgeInRequest event
    EW->>Committee: PeginRequest message

    Committee->>Committee: Validate fees and availability
    Committee->>Operator: ConfirmInstance

    Operator->>Operator: Create SimplifiedbitvmGraph
    Operator->>DB: Store graph_raw_data (JSON)
    Operator->>Committee: CreateGraph (with graph data)

    loop Multi-sig rounds
        Committee->>Committee: NonceGeneration
        Committee->>Committee: CommitteePresign
    end

    Committee->>Operator: EndorseGraph (graph endorsement)
    Operator->>GOAT: PostGraphData
    Operator->>BTC: Broadcast PreKickoff transaction
    BTC-->>EW: PreKickoff confirmed

    Note over User,DB: Peg-in complete, user receives assets on L2
```

**Description**: The Peg-in flow consists of three phases: (1) Request Phase - user initiates request on L2, committee validates; (2) Graph Construction Phase - Operator creates transaction graph (stored locally in SQLite), committee performs MuSig2 multi-signing; (3) Confirmation Phase - data posted to L2, PreKickoff transaction confirms to complete the process.

#### Fig-03-2-Instance-BridgeIn-Status

```mermaid
stateDiagram-v2
    [*] --> UserIniting: User initiates request
    UserIniting --> UserInited: Event detected
    UserInited --> CommitteesAnswered: Enough committee responses
    UserInited --> NoEnoughCommitteesAnswered: Window timeout
    UserInited --> UserDiscarded: UTXO spent

    CommitteesAnswered --> UserBroadcastPeginPrepare: User broadcasts
    UserBroadcastPeginPrepare --> Presigned: All committees signed
    UserBroadcastPeginPrepare --> PresignedFailed: Signing failed

    Presigned --> RelayerL1Broadcasted: Relayer broadcasts
    RelayerL1Broadcasted --> RelayerL2Minted: L2 minting success
    RelayerL1Broadcasted --> RelayerL2MintedFailed: L2 minting failed

    UserBroadcastPeginPrepare --> Timeout: Timeout
    Timeout --> UserCanceled: User cancels

    RelayerL2Minted --> [*]
    UserCanceled --> [*]
```

**Description**: This state diagram shows the complete lifecycle of a bridge-in instance, from initial request through committee validation, signing, and final minting on L2.

### Peg-out (Bridge-Out)

Users initiate withdrawal on GOAT L2 and receive BTC on Bitcoin. Two paths exist:

#### Fig-03-3-Pegout-Happy-Path

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant GOAT as GOAT L2
    participant Operator
    participant BTC as Bitcoin

    User->>GOAT: InitWithdraw (withdrawal request)
    GOAT-->>Operator: Withdrawal event detected

    Operator->>BTC: Broadcast Kickoff transaction
    Note over Operator,BTC: Wait for Timelock expiry

    alt No challenge (Happy Path)
        Operator->>BTC: Broadcast Take1 transaction
        BTC->>User: BTC transferred to user address
    end
```

**Description**: The Happy Path is the simplest route - when no Watchtower challenges the Operator's claim, the Operator completes the withdrawal via Take1 transaction after the Timelock expires.

#### Fig-03-4-Pegout-Challenge-Path

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant GOAT as GOAT L2
    participant Operator
    participant Watchtower
    participant Verifier
    participant BTC as Bitcoin

    User->>GOAT: InitWithdraw
    Operator->>BTC: Kickoff transaction

    rect rgb(255, 240, 240)
        Note over Operator,Watchtower: Challenge Phase
        Operator->>BTC: WatchtowerChallengeInitTx

        loop For each Watchtower index
            Watchtower->>BTC: WatchtowerChallengeTx
            alt Operator accepts
                Operator->>BTC: ACK response
            else Operator rejects
                Operator->>BTC: NACK response
                Verifier->>BTC: DisproveTx
            end
        end

        Operator->>BTC: CommitBlockHashTx
        Operator->>BTC: AssertInitTx
        Operator->>BTC: AssertCommitTx
    end

    alt All challenges passed
        Operator->>BTC: Take2 transaction
        BTC->>User: BTC transferred to user address
    else Challenge failed
        Verifier->>BTC: DisproveTx
        Note over User,BTC: User funds safe, Operator penalized
    end
```

**Description**: The Challenge Path is triggered when Watchtowers detect anomalies. It contains three sub-phases: (1) Watchtower Challenge - watchers submit challenges; (2) BlockHash Commit - Operator commits block hash; (3) Assert Commit - Operator commits assertion proofs. Failure in any phase triggers Disprove.

### Challenge Process

#### Fig-03-5-Challenge-Substatus

```mermaid
flowchart TB
    subgraph WTC["Watchtower Challenge Phase"]
        WTC1["OperatorInit"] --> WTC2{"Watchtower response?"}
        WTC2 -->|"Submit challenge"| WTC3["Challenge"]
        WTC2 -->|"Timeout"| WTC4["ChallengeTimeout"]
        WTC3 --> WTC5{"Operator response?"}
        WTC5 -->|"ACK"| WTC6["OperatorACK"]
        WTC5 -->|"NACK"| WTC7["OperatorNACK"]
        WTC5 -->|"Timeout"| WTC8["ACKTimeout"]
    end

    subgraph CBH["CommitBlockHash Phase"]
        CBH1["WatchtowerChallengeProcessed"]
        CBH2["OperatorCommit"]
        CBH3["OperatorCommitTimeout"]
        CBH1 --> CBH2
        CBH1 --> CBH3
    end

    subgraph AC["Assert Commit Phase"]
        AC1["OperatorInit"]
        AC2["OperatorCommit"]
        AC3["OperatorCommitTimeout"]
        AC1 --> AC2
        AC1 --> AC3
    end

    WTC6 --> CBH1
    CBH2 --> AC1
    AC2 --> TAKE2["Take2 Success"]

    WTC4 & WTC7 & WTC8 & CBH3 & AC3 --> DISP["Disprove"]
```

**Description**: The challenge process tracks three parallel state machines. Any timeout or failure in sub-phases triggers the Disprove path, ensuring system security.

---

## Graph State Machine

Graph is the core data structure in BitVM, representing a set of presigned Bitcoin transactions.

### Fig-04-1-Graph-Lifecycle

```mermaid
stateDiagram-v2
    [*] --> OperatorPresigned: Operator creates graph

    OperatorPresigned --> CommitteePresigned: Collected enough committee signatures
    OperatorPresigned --> Obsoleted: PreKickoff on-chain but data not posted

    CommitteePresigned --> OperatorDataPushed: Operator pushes L2 data
    CommitteePresigned --> Obsoleted: PreKickoff on-chain but data not posted

    OperatorDataPushed --> PreKickoff: PreKickoff tx confirmed
    OperatorDataPushed --> Obsoleted: Pegin not withdrawable and no withdrawal request

    PreKickoff --> OperatorKickOff: Kickoff tx broadcast
    PreKickoff --> Skipped: Guardian intervention or force skip

    Obsoleted --> OperatorKickOff: Kickoff tx observed on-chain after all
    Obsoleted --> Skipped: Guardian intervention or force skip

    OperatorKickOff --> OperatorTake1: Timelock expired without challenge
    OperatorKickOff --> Challenge: WatchtowerChallengeInit confirmed
    OperatorKickOff --> Disprove: Guardian disprove detected before any Challenge opened

    Challenge --> OperatorTake2: Take2 tx confirmed and no disprove detected
    Challenge --> Disprove: Guardian disprove, watchtower-flow disprove, verifier disprove, or unrecognized connector-D spend

    OperatorTake1 --> [*]: Happy Path complete
    OperatorTake2 --> [*]: Challenge Path complete
    Skipped --> [*]: Graph skipped
    Disprove --> [*]: Dispute resolved
```

**Description**: Graph goes through 9 main states. The normal flow starts from `OperatorPresigned`, proceeds through signature collection, data publishing, and Kickoff, finally completing via Take1 (Happy Path) or Take2 (Challenge Path). `Skipped` and `Disprove` are terminal.

**`Obsoleted` is not terminal.** It is a provisional status: the local node marks a graph `Obsoleted` when it observes the PreKickoff tx on-chain before graph data was posted (or the pegin becomes non-withdrawable), but if it later observes the actual kickoff tx confirm, the graph resumes into `OperatorKickOff` exactly as if it had come from `PreKickoff` — see `scan_graph_chain_state`, `node/src/utils.rs:1418-1434`, which checks `matches!(current_status, GraphStatus::PreKickoff | GraphStatus::Obsoleted)` for both the kickoff and force-skip cases.

`OperatorKickOff --> Disprove` is a direct edge, distinct from the `Challenge --> Disprove` edge below: a guardian can detect and prove operator misbehavior (`detect_guardian_disprove`, `node/src/utils.rs:1237-1262`) before a watchtower ever opens a `Challenge` at all (`node/src/utils.rs:1448-1461`).

### Fig-04-2-Graph-Status-Transitions

| Source State | Target State | Trigger Condition |
|--------------|--------------|-------------------|
| `OperatorPresigned` | `CommitteePresigned` | Received enough committee presignatures |
| `OperatorPresigned` | `Obsoleted` | PreKickoff on-chain but graph data not posted |
| `CommitteePresigned` | `OperatorDataPushed` | Operator successfully pushed data to L2 |
| `OperatorDataPushed` | `PreKickoff` | PreKickoff tx confirmed on Bitcoin |
| `OperatorDataPushed` | `Obsoleted` | Pegin not withdrawable and no withdrawal request |
| `PreKickoff` | `OperatorKickOff` | Kickoff tx broadcast successfully |
| `PreKickoff` | `Skipped` | Guardian intervention or force skip |
| `Obsoleted` | `OperatorKickOff` | Kickoff tx broadcast successfully (Obsoleted is provisional, not terminal) |
| `Obsoleted` | `Skipped` | Guardian intervention or force skip |
| `OperatorKickOff` | `OperatorTake1` | Connector-A spent by the take1 tx |
| `OperatorKickOff` | `Challenge` | Connector-A spent by anything other than the take1 tx |
| `OperatorKickOff` | `Disprove` | Guardian disprove detected (bypasses `Challenge`) |
| `Challenge` | `OperatorTake2` | Take2 tx observed on-chain and no disprove detector fired |
| `Challenge` | `Disprove` | Any of: guardian disprove, watchtower-flow disprove (operator-challenge-nack or operator-commit-timeout tx), a verifier's assert answered by its matching disprove tx, or an unrecognized connector-D spend |

Source: `scan_graph_chain_state`, `node/src/utils.rs:1328-1681` (the sole writer of these edges; verified by full read, 2026-07-17).

### Fig-04-3-Challenge-SubStatus

`ChallengeSubStatus` is **not** three parallel single-value status enums as earlier revisions of this document claimed — that shape does not exist in the code. The actual struct (`node/src/scheduled_tasks/graph_maintenance_tasks.rs:52-58`) is:

```rust
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: Vec<bool>,                  // per-watchtower: true once that watchtower's challenge connector is spent
    pub verifier_challenge_status: Vec<VerifierChallengeStatus>, // per-verifier progress
    pub disprove_type: Option<DisproveTxType>,
    pub disprove_index: i32,
}

pub enum VerifierChallengeStatus { None, VerifierAsserted, ProverAnswered, Disproved }

pub enum DisproveTxType { Disprove, QuickChallenge, ChallengeIncompleteKickoff, PubinDisprove, OperatorChallengeNack, OperatorCommitTimeout }
```

`watchtower_challenge_status` and `verifier_challenge_status` are **observational bookkeeping only** — they are recorded for the frontend/API (`node/src/rpc_service/bitvm.rs:672-693`, collapsed there into a simpler `SimpleChallengeSubStatus{None, WatchtowerChallenge, Assert}` view) but are never read by anything that decides `GraphStatus`. In particular, `ChallengeSubStatus::is_watchtower_challenge_success` (`graph_maintenance_tasks.rs:98-105`) has no call sites anywhere in the repo. The real `Challenge --> OperatorTake2` gate is purely `tx_on_chain(take2_txid)` after none of the four disprove detectors fired (`node/src/utils.rs:1661-1670`); the operator's actual authorization to broadcast take2 is enforced by Bitcoin-script timelocks (`detect_take2`, `graph_maintenance_tasks.rs:1089-1233`), not by any application-level quorum over watchtower or verifier counts.

### Known gap: no ordering guarantee between chain-scan and L2-event writers

`GraphStatus` is written from two independently-scheduled places with no inherent coordination between them:
- `scan_graph_chain_state` above (Bitcoin-poll derived), and
- the GoatChain L2-event watcher, `node/src/scheduled_tasks/event_watch_task.rs:392-502`, which writes `OperatorDataPushed`/`OperatorTake1`/`OperatorTake2`/`Disprove` directly via `StorageProcessor::update_graph` with no precondition on the graph's current status.

Both currently go through a raw `UPDATE graph SET status = ?` (`crates/store/src/localdb.rs`) with no guard preventing a closed/terminal status (`GraphStatus::is_closed()`: `OperatorTake1`, `OperatorTake2`, `Skipped`, `Disprove`) from being overwritten by a later, differently-ordered write from the other subsystem — e.g. a `Disprove` status can be silently reverted by a stale `PostGraphDataEvent` replay. **This is an open bug, not yet fixed in code.**

`node/tla/GraphLifecycle.tla` / `GraphLifecycle.cfg` has the machine-checked counterexample (`OperatorTake1 -> OperatorTake2` in 2 steps). A verified fix design exists and is formally proven correct — `GraphLifecycleFixed.cfg` (atomic guard: fold the check into the `UPDATE`'s `WHERE status IN (...)` clause rather than a separate read-then-decide-then-write) passes all safety and liveness properties, and `GraphLifecycleFineGrainedFixed.tla` additionally proves that atomicity is necessary (a naive read-then-write version of the same guard, modeled in `GraphLifecycleFineGrained.tla`, still fails). Applying that design to `node/src/utils.rs`/`crates/store/src/localdb.rs` is tracked as follow-up work, not part of this audit pass.

---

## Graph Storage & Synchronization

Graph data is stored locally in SQLite and distributed via P2P messaging.

### Fig-05-1-Graph-Storage-Architecture

```mermaid
flowchart TB
    subgraph Storage["SQLite Database"]
        GT[("graph table\n(Metadata, TxIDs, Status)")]
        GRD[("graph_raw_data table\n(Serialized JSON)")]
    end

    subgraph Operations["Graph Operations"]
        CREATE["store_graph()"]
        READ["get_graph()"]
        PARSE["parse_graph_raw_data()"]
        SERIALIZE["serialize_graph_raw_data()"]
    end

    subgraph P2P["P2P Synchronization"]
        REQ["SyncGraphRequest"]
        RESP["SyncGraph"]
        RELAY["Relayer Nodes"]
    end

    CREATE -->|"Atomic Transaction"| GT
    CREATE -->|"JSON Serialization"| GRD
    READ --> GT
    READ --> GRD
    PARSE -->|"spawn_blocking"| GRD
    SERIALIZE -->|"spawn_blocking"| GRD

    REQ -->|"Broadcast to All"| RELAY
    RELAY -->|"Lookup Local DB"| GRD
    RELAY -->|"Respond with Graph"| RESP
```

**Description**: Graph storage uses a two-table approach: `graph` for metadata/transaction IDs and `graph_raw_data` for full serialized graph JSON. Large graph serialization uses `spawn_blocking` to prevent async runtime blocking. P2P synchronization enables nodes to request missing graphs from relayer nodes.

### Fig-05-2-Graph-Sync-Sequence

```mermaid
sequenceDiagram
    autonumber
    participant NodeA as Node A (Missing Graph)
    participant P2P as P2P Network
    participant Relayer as Relayer Node
    participant DB as Relayer DB

    NodeA->>NodeA: Check local DB for graph
    Note over NodeA: Graph NOT FOUND

    NodeA->>P2P: SyncGraphRequest(instance_id, graph_id)
    P2P->>Relayer: Broadcast to All topic

    Relayer->>Relayer: is_relayer() check
    Note over Relayer: ENABLE_RELAYER=true

    Relayer->>DB: Query graph_raw_data
    DB-->>Relayer: Return serialized graph

    Relayer->>P2P: SyncGraph(instance_id, graph_id, graph_data)
    P2P->>NodeA: Deliver response

    NodeA->>NodeA: Validate graph_id on GOAT chain
    NodeA->>NodeA: store_graph() locally
    Note over NodeA: Graph synchronized!
```

**Description**: When a node lacks required graph data, it broadcasts a `SyncGraphRequest`. Relayer nodes (Committee members with `ENABLE_RELAYER=true`) respond with the full graph data via `SyncGraph` message. The requesting node validates and stores the graph locally.

### Graph Data Tables

#### graph table (Metadata)

| Column | Type | Description |
|--------|------|-------------|
| `graph_id` | UUID | Primary key |
| `instance_id` | UUID | Associated bridge instance |
| `status` | String | Current GraphStatus |
| `sub_status` | String | Challenge sub-status JSON |
| `operator_pubkey` | String | Operator's public key |
| `*_txid` | Txid | Transaction IDs for all graph transactions |
| `created_at`, `updated_at` | i64 | Timestamps |

#### graph_raw_data table (Full Graph)

| Column | Type | Description |
|--------|------|-------------|
| `graph_id` | UUID | Primary key (FK to graph) |
| `raw_data` | TEXT | JSON-serialized SimplifiedbitvmGraph |
| `created_at`, `updated_at` | i64 | Timestamps |

---

## Message System

### Fig-06-1-Message-Structure

```mermaid
classDiagram
    class GOATMessage {
        +Actor actor
        +GOATMessageContent content
        +serialize_message() Vec~u8~
        +deserialize_message() GOATMessage
    }

    class GOATMessageContent {
        <<enumeration>>
        PeginRequest
        CreateGraph
        ConfirmInstance
        NonceGeneration
        CommitteePresign
        EndorseGraph
        GraphFinalize
        KickoffReady
        KickoffSent
        ChallengeSent
        DisproveReady
        DisproveSent
        Take1Sent
        Take2Sent
        SyncGraphRequest
        SyncGraph
        ...
    }

    class Actor {
        <<enumeration>>
        Committee
        Operator
        Verifier
        Watchtower
        All
    }

    GOATMessage --> Actor : target
    GOATMessage --> GOATMessageContent : payload
```

**Description**: The message system uses role-based addressing. Each message specifies a target role and content type, broadcast via Gossipsub to the corresponding topic. Messages are serialized using `serde_json` with `spawn_blocking` for large payloads.

### Message Categories

#### Peg-in Messages

| Message | Sender | Receiver | Description |
|---------|--------|----------|-------------|
| `PeginRequest` | EventWatch | Committee | Peg-in request notification |
| `ConfirmInstance` | Committee | Operator | Instance creation confirmation |
| `CreateGraph` | Operator | Committee | Graph creation request (includes full graph) |
| `NonceGeneration` | Committee | Committee/Operator | MuSig2 nonce broadcast |
| `CommitteePresign` | Committee | Committee/Operator | Presignature broadcast |
| `EndorseGraph` | Committee | Operator | Graph endorsement |
| `GraphFinalize` | Operator | All | Graph completion notification |

#### Peg-out Messages

| Message | Sender | Receiver | Description |
|---------|--------|----------|-------------|
| `KickoffReady` | System | Operator | Kickoff ready notification |
| `KickoffSent` | Operator | All | Kickoff transaction broadcast |
| `Take1Ready` | System | Operator | Take1 ready (Happy Path) |
| `Take1Sent` | Operator | All | Take1 transaction broadcast |
| `Take2Ready` | System | Operator | Take2 ready (Challenge Path) |
| `Take2Sent` | Operator | All | Take2 transaction broadcast |

#### Challenge Messages

| Message | Sender | Receiver | Description |
|---------|--------|----------|-------------|
| `WatchtowerChallengeInitSent` | Operator | Watchtower | WT challenge initialization |
| `WatchtowerChallengeSent` | Watchtower | Operator | WT challenge submission |
| `WatchtowerChallengeTimeout` | System | Operator | WT challenge timeout |
| `OperatorAckTimeout` | System | Verifier | Operator ACK timeout |
| `DisproveReady` | System | Verifier | Disprove ready |
| `DisproveSent` | Verifier | All | Disprove transaction broadcast |

#### Synchronization Messages

| Message | Sender | Receiver | Description |
|---------|--------|----------|-------------|
| `SyncGraphRequest` | Any Node | All | Request missing graph data |
| `SyncGraph` | Relayer | All | Respond with full graph data |

---

## Scheduled Tasks

### Fig-07-1-Task-Overview

```mermaid
flowchart TB
    subgraph EventWatch["Event Watch Task (Continuous)"]
        EW1["fetch_and_handle_gateway_events"]
        EW2["fetch_and_handle_bridge_out_events"]
        EW1 --> MSG1["PeginRequest"]
        EW2 --> MSG2["InitWithdraw detection"]
    end

    subgraph GraphMaint["Graph Maintenance (20s interval)"]
        GM1["detect_init_withdraw_call"]
        GM2["detect_kickoff"]
        GM3["detect_take1_or_challenge"]
        GM4["process_graph_challenge"]

        GM1 -->|"KickoffReady"| GM2
        GM2 -->|"Status update"| GM3
        GM3 -->|"Challenge"| GM4
        GM3 -->|"Take1Ready"| T1["Take1 processing"]
        GM4 -->|"Take2Ready"| T2["Take2 processing"]
        GM4 -->|"DisproveReady"| DP["Disprove processing"]
    end

    subgraph InstMaint["Instance Maintenance (20s interval)"]
        IM1["instance_answers_monitor"]
        IM2["instance_window_expiration_monitor"]
        IM3["instance_btc_tx_monitor"]
        IM4["swap_escrow_timeout_monitor"]
        IM5["instance_committee_key_cleanup_monitor"]
    end

    subgraph Other["Other Tasks"]
        NM["Node Maintenance"]
        SPV["SPV Header Updates"]
    end

    EventWatch --> GraphMaint
    GraphMaint --> InstMaint
```

**Description**: The system runs 5 types of background tasks. Event Watch continuously monitors chain events; Graph Maintenance executes graph state machine transitions every 20 seconds; Instance Maintenance manages instance lifecycles; Node Maintenance maintains node health; SPV Maintenance updates the Bitcoin header chain.

### Task Responsibilities

| Task | Interval | Responsibility |
|------|----------|----------------|
| `run_watch_event_task` | Continuous | Monitor GOAT L2 and Bitcoin events |
| `detect_init_withdraw_call` | 20s | Detect withdrawal requests, send KickoffReady |
| `detect_kickoff` | 20s | Monitor Kickoff transaction confirmations |
| `detect_take1_or_challenge` | 20s | Check Happy Path or Challenge |
| `process_graph_challenge` | 20s | Process Challenge sub-phases |
| `instance_answers_monitor` | 20s | Track committee responses |
| `instance_window_expiration_monitor` | 20s | Handle response window timeouts |
| `instance_btc_tx_monitor` | 20s | Track pegin/confirm/cancel BTC transaction confirmations |
| `swap_escrow_timeout_monitor` | 20s | Mark swap escrows past their refund deadline as timed out |
| `instance_committee_key_cleanup_monitor` | 20s | Scan `cache/committee-instance-keys/` and delete expired key envelopes after configurable pegin-confirm timelock |
| `spv_header_hash_update` | Periodic | Update SPV header hashes |

---

## Module Structure

```
node/src/
├── main.rs                          # Entry point, starts 4 async tasks
├── lib.rs                           # Module exports
├── action.rs                        # Message type definitions (45+ types)
├── handle.rs                        # Message dispatch and role handlers
├── p2p_msg_handler.rs              # P2P message processing interface
├── env.rs                           # Environment configuration (40+ variables)
├── utils.rs                         # Graph state management & storage utilities
├── error.rs                         # Error types
├── vk.rs                           # Verification key management
├── metrics_service.rs              # Prometheus metrics
├── rpc_service/                    # REST API implementation
│   ├── mod.rs                      # Service orchestration
│   ├── bitvm.rs                   # BitVM-specific endpoints
│   ├── routes.rs                   # HTTP route definitions
│   ├── validation.rs               # Input validation
│   └── handler/                    # Request handlers
├── middleware/                     # P2P network layer
│   ├── swarm.rs                    # BitvmNetworkManager, libp2p configuration
│   └── behaviour.rs                # Kademlia + Gossipsub behavior
└── scheduled_tasks/                # Background tasks
    ├── mod.rs                      # Task exports
    ├── event_watch_task.rs         # Chain event monitoring (51KB)
    ├── graph_maintenance_tasks.rs  # Graph state machine (72KB)
    ├── instance_maintenance_tasks.rs # Instance lifecycle
    ├── node_maintenance_tasks.rs   # Node health
    └── spv_maintenance_tasks.rs    # SPV updates
```

---

## Build & Run

### Prerequisites

- Rust nightly-2025-06-30+
- ZKM toolchain (optional, for proof generation)

### Build Commands

```bash
# Build for regtest
BITCOIN_NETWORK=regtest cargo build -r

# Build for testnet4
BITCOIN_NETWORK=testnet4 cargo build -r

# Build only the node binary
cargo build -r -p bitvm-noded
```

### Generate Node Keys

```bash
# Generate P2P peer key
bitvm-noded key peer
# Output:
# PEER_KEY=<base64-encoded-key>
# PEER_ID=<peer-id>

# Generate funding address (for Operator/Verifier)
bitvm-noded key funding-address
# Output:
# Funding P2WSH address: bc1q...
```

### Start Node

```bash
bitvm-noded \
  --rpc-addr 0.0.0.0:8080 \
  --metrics-addr 127.0.0.1:9108 \
  --db-path ./node.db \
  --p2p-port 4001 \
  --bootnodes /ip4/x.x.x.x/tcp/4001/p2p/<peer_id>
```

### Start Local Mock RPC

Use this when you only need to test HTTP interfaces. It starts the RPC routes without
P2P, chain watchers, or maintenance tasks, and seeds a local SQLite database with
mock nodes, instances, graphs, and overview data.

```bash
cargo run -p bitvm-noded --bin mock-rpc -- --rpc-addr 127.0.0.1:18080
```

Useful test calls:

```bash
curl http://127.0.0.1:18080/v1/nodes/overview
curl http://127.0.0.1:18080/v1/instances
curl http://127.0.0.1:18080/v1/swaps
curl http://127.0.0.1:18080/v1/graphs
```

The mock binary prints seeded instance and graph IDs on startup. Endpoints that
require real `graph_raw_data`, such as graph transaction hex export, still need
real graph raw data in the database.

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--rpc-addr` | RPC service bind address | `0.0.0.0:8080` |
| `--db-path` | SQLite database path | `sqlite:/tmp/bitvm-node.db` |
| `--p2p-port` | P2P listen port | `0` (random) |
| `--bootnodes` | Bootstrap node addresses | - |
| `--metrics-addr` | Dedicated Prometheus listener address | Disabled |
| `--metrics-path` | Path served by the dedicated metrics listener | `/metrics` |
| `--enable-kademlia` | Enable Kademlia DHT | `true` |

---

## Configuration

### Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `ACTOR` | Yes | Node role: `Committee`, `Operator`, `Verifier`, `Watchtower` | `Verifier` |
| `BITCOIN_NETWORK` | Yes | Bitcoin network: `bitcoin`, `testnet4`, `signet`, `regtest` | `testnet4` |
| `GOAT_NETWORK` | Yes | GOAT network: `main`, `test` | `test` |
| `GOAT_CHAIN_URL` | Yes | GOAT L2 RPC endpoint | - |
| `GOAT_GATEWAY_CONTRACT_ADDRESS` | Yes | Gateway contract address | - |
| `BITVM_SECRET` | Yes | Node private key or seed (`seed:xxx` format) | - |
| `PEER_KEY` | Yes | libp2p node key (Base64 encoded) | - |
| `GOAT_PRIVATE_KEY` | Conditional | GOAT chain private key (required for Committee) | - |
| `GOAT_ADDRESS` | Conditional | GOAT address (required for Operator/Verifier) | - |
| `ENABLE_RELAYER` | No | Enable relayer mode for Committee nodes | `false` |
| `ENABLE_BABE_SETUP_STATE_CLEANUP` | No | Enable scheduled BABE setup state cleanup for Operator/Verifier nodes | `false` |
| `BTC_CHAIN_URL` | No | Bitcoin Esplora API endpoint | Public Esplora |
| `GOAT_PROOF_BUILD_URL` | No | Proof Builder RPC endpoint | - |
| `NODE_NAME` | No | Node display name | `ZKM` |
| `OPERATOR_NODE_SERVICE_FEE` | No | Operator service fee rate | `0.001` |
| `ENABLE_COMMITTEE_INSTANCE_KEY_DELETE` | No | Enable scheduled deletion of committee instance key envelopes | `false` |
| `COMMITTEE_INSTANCE_KEY_DELETE_TIMELOCK_BLOCKS` | No | Number of BTC blocks to wait after pegin-confirm confirmation before deleting key envelope | `32` |

### Relayer Configuration

To run a Committee node as a graph data relayer:

```bash
export ACTOR=Committee
export ENABLE_RELAYER=true
export GOAT_PRIVATE_KEY=<private_key>
# ... other required variables
```

Relayer nodes should:
- Run 24/7 for network reliability
- Have sufficient storage for all graph data
- Be geographically distributed for redundancy

---

## RPC API

Prometheus metrics are not served by the business RPC listener. Set
`--metrics-addr` to a private, process-unique address and scrape
`http://<metrics-addr>/metrics`; `GET /metrics` on `--rpc-addr` returns `404`.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/node` | GET | Get current node information |
| `/nodes` | GET | List connected nodes |
| `/nodes/overview` | GET | Node statistics overview |
| `/instances` | GET | List all instances |
| `/instance/:id` | GET | Get instance details |
| `/instances/overview` | GET | Instance statistics overview |
| `/v1/graphs` | GET | List all graphs |
| `/v1/graphs/:id` | GET | Get graph details |
| `/v1/graphs/:id/txn?cursor=0` | GET | Get graph transaction list |
| `/v1/graphs/:id/tx?tx_name=cur-pre-kickoff.hex` | GET | Get specific transaction hex |
| `/v1/graphs/ready-to-kickoff` | GET | Get graphs ready for kickoff |
| `/bridge_in_request` | POST | Initiate Bridge-In request |
| `/v1/swaps` | GET | List swap bridge-out escrows |
| `/v1/swaps/:escrow_hash` | GET | Get swap escrow details |
| `/challenge` | POST | Submit challenge |
| `/metrics` | GET | Prometheus metrics (dedicated metrics listener only) |

---

## Related Documentation

- [Architecture Document](../docs/ARCHITECTURE.md) - Full system architecture
- [Circuits README](../circuits/README.md) - ZK proof generation
- [Deployment Guide](../deployment/README.md) - Deployment instructions
- [Incentives](../docs/incentives.md) - Incentives
