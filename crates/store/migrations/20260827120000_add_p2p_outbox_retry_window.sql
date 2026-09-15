ALTER TABLE p2p_outbox ADD COLUMN retry_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE p2p_outbox ADD COLUMN retry_interval_secs BIGINT NOT NULL DEFAULT 0;
ALTER TABLE p2p_outbox ADD COLUMN ack_peer_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_p2p_outbox_retry_window
    ON p2p_outbox (state, retry_until, next_retry_at);
