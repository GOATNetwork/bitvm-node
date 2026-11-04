-- Watchtower keys are stored compressed with even parity ("02" + x-only), the
-- form used by the Operator's graph list, so each key has one spelling.
UPDATE watchtower_proof
SET public_key = '02' || lower(public_key)
WHERE length(public_key) = 64;

UPDATE watchtower_proof
SET public_key = '02' || lower(substr(public_key, 3))
WHERE length(public_key) = 66;

-- Keep the oldest task per key.
DELETE FROM watchtower_proof
WHERE id NOT IN (
    SELECT min(id) FROM watchtower_proof GROUP BY instance_id, graph_id, public_key
);

CREATE UNIQUE INDEX idx_watchtower_proof_key
    ON watchtower_proof (instance_id, graph_id, public_key);
