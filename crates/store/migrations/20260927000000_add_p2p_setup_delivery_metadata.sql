ALTER TABLE p2p_outbox ADD COLUMN delivery_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_p2p_outbox_delivery_id
    ON p2p_outbox (delivery_id, state);
