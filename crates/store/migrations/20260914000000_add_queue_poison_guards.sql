-- Poison-message guards for the two durable work queues.
--
-- Both queues previously had no way to tell "the handler returned Err and asked
-- for a retry" apart from "the attempt never finished because the process died".
-- Only the latter indicates a message that reproducibly takes the node down, so
-- it needs its own counter and a much smaller ceiling: a transient RPC or SQLite
-- outage must not push legitimate messages toward quarantine.
--
-- `abandon_count` is incremented when an expired `Processing` lease is reclaimed,
-- so the next worker durably records that the previous dispatch never finished.

ALTER TABLE p2p_inbox ADD COLUMN abandon_count BIGINT NOT NULL DEFAULT 0;

ALTER TABLE message ADD COLUMN attempt_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE message ADD COLUMN abandon_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE message ADD COLUMN last_error TEXT;

CREATE INDEX IF NOT EXISTS idx_message_claimable ON message (state, lock_time_until, created_at);
