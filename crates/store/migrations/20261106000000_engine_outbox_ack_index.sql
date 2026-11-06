-- ACK lookups read only these columns, so they never touch the (large)
-- payload of the open rows they scan.
CREATE INDEX idx_engine_outbox_ack
    ON engine_outbox (state, ack_set, outbox_id)
    WHERE ack_set IS NOT NULL;
