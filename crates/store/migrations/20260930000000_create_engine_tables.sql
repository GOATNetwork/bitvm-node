-- Persist input events, aggregate state, outgoing P2P messages and leased jobs.

CREATE TABLE IF NOT EXISTS engine_inbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Producer-supplied dedup key: content id, chain event id, height key,
    -- or job result id. Arrival of a known id never creates a second row.
    event_id TEXT NOT NULL UNIQUE,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    -- Stable hash of (aggregate_kind, aggregate_id); workers own shard_key % K.
    shard_key BIGINT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    -- Cleared once the event is Applied; kept while Pending, Waiting or Failed.
    payload BLOB,
    payload_size BIGINT NOT NULL DEFAULT 0,
    -- Pending | Applied | Failed | Poisoned
    state TEXT NOT NULL DEFAULT 'Pending',
    attempts BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    -- Set while the event is Pending because a dependency is missing.
    waiting_ref TEXT,
    waiting_detail TEXT,
    -- Heavy messages: who to ACK once the material is durably applied or parked.
    ack_peer TEXT,
    ack_delivery_id TEXT,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    applied_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_engine_inbox_runnable
    ON engine_inbox (state, next_at, shard_key, seq);
CREATE INDEX IF NOT EXISTS idx_engine_inbox_waiting
    ON engine_inbox (state, waiting_ref);
CREATE INDEX IF NOT EXISTS idx_engine_inbox_aggregate
    ON engine_inbox (aggregate_kind, aggregate_id, seq);

CREATE TABLE IF NOT EXISTS engine_aggregate (
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT '',
    -- Opaque state owned by the aggregate handler (JSON).
    state TEXT,
    waiting_ref TEXT,
    waiting_detail TEXT,
    waiting_since BIGINT,
    -- Set by a panic or invariant violation; isolates jobs with poison_action
    -- until the next successful apply or a manual clear.
    poisoned INTEGER NOT NULL DEFAULT 0,
    poison_action TEXT,
    poison_reason TEXT,
    version BIGINT NOT NULL DEFAULT 0,
    last_event_id TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (aggregate_kind, aggregate_id)
);

CREATE INDEX IF NOT EXISTS idx_engine_aggregate_waiting
    ON engine_aggregate (waiting_ref);

CREATE TABLE IF NOT EXISTS engine_outbox (
    outbox_id TEXT NOT NULL PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    -- The phase whose terminal predicate closes a small message.
    phase_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    topic TEXT NOT NULL,
    payload BLOB NOT NULL,
    -- Heavy messages: JSON object of outstanding recipient peer id -> delivery id.
    -- NULL for small messages, which close on receiver-side evidence instead.
    ack_set TEXT,
    -- Open | Closed
    state TEXT NOT NULL DEFAULT 'Open',
    close_reason TEXT,
    publish_count BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    closed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_engine_outbox_due
    ON engine_outbox (state, next_at);
CREATE INDEX IF NOT EXISTS idx_engine_outbox_phase
    ON engine_outbox (aggregate_kind, aggregate_id, phase_ref, state);

CREATE TABLE IF NOT EXISTS engine_job (
    -- Stable id H(aggregate ‖ phase ‖ action ‖ params hash); re-creation is a no-op.
    job_id TEXT NOT NULL PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    action TEXT NOT NULL,
    -- cpu | network
    pool TEXT NOT NULL,
    params BLOB,
    -- Pending | Running | Done | Failed | Cancelled | Poisoned
    state TEXT NOT NULL DEFAULT 'Pending',
    -- Incremented on every claim; a completion with a stale generation is fenced.
    generation BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0,
    attempts BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    deadline_at BIGINT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    result BLOB,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    finished_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_engine_job_due
    ON engine_job (state, next_at, lease_until);
CREATE INDEX IF NOT EXISTS idx_engine_job_aggregate
    ON engine_job (aggregate_kind, aggregate_id, phase, state);
