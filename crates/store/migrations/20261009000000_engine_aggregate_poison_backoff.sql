-- Track repeated aggregate failures for recovery backoff. Manual clearing resets the
-- count.
ALTER TABLE engine_aggregate ADD COLUMN poison_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE engine_aggregate ADD COLUMN poisoned_at BIGINT;
