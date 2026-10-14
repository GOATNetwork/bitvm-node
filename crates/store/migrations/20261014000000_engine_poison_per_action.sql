-- Poison is tracked per (aggregate, action): the job action or event kind that
-- panicked. The row blocks that action until `blocked_until`; a clean run of the
-- action removes it, a manual clear removes every row of the aggregate. The
-- aggregate row no longer mirrors waits or poison: parked inbox rows carry the
-- wait themselves.
CREATE TABLE IF NOT EXISTS engine_aggregate_poison (
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    poison_count INTEGER NOT NULL,
    poisoned_at BIGINT NOT NULL,
    blocked_until BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (aggregate_kind, aggregate_id, action)
);

DROP INDEX IF EXISTS idx_engine_aggregate_waiting;
ALTER TABLE engine_aggregate DROP COLUMN waiting_ref;
ALTER TABLE engine_aggregate DROP COLUMN waiting_detail;
ALTER TABLE engine_aggregate DROP COLUMN waiting_since;
ALTER TABLE engine_aggregate DROP COLUMN poisoned;
ALTER TABLE engine_aggregate DROP COLUMN poison_action;
ALTER TABLE engine_aggregate DROP COLUMN poison_reason;
ALTER TABLE engine_aggregate DROP COLUMN poison_count;
ALTER TABLE engine_aggregate DROP COLUMN poisoned_at;
