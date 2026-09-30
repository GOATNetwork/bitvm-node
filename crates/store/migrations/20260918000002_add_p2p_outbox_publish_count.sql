-- Successful publishes of an outbox row. Signing-round rows are re-published for
-- as long as their round is open, and back off by this count. `attempt_count`
-- cannot serve: it also counts claims whose publish failed, so a node that came
-- up without peers would reach the slowest tier before delivering anything.
ALTER TABLE p2p_outbox ADD COLUMN publish_count BIGINT NOT NULL DEFAULT 0;
