-- Remove unused message queues, debug records and graph compensation markers.
DROP TABLE IF EXISTS message;
DROP TABLE IF EXISTS message_debug_reason;
DROP TABLE IF EXISTS p2p_inbox;
DROP TABLE IF EXISTS p2p_outbox;
DROP TABLE IF EXISTS graph_compensation_marker;

-- Admission meters what it stores in the engine inbox: the sender class the
-- author had when the event was admitted. Empty for local, chain and job
-- events.
ALTER TABLE engine_inbox ADD COLUMN admission_class TEXT NOT NULL DEFAULT '';

-- Covering index for the per-class and per-author quota queries.
CREATE INDEX IF NOT EXISTS idx_engine_inbox_admission
    ON engine_inbox (source, state, admission_class, author, payload_size);
