-- Rebuilt with AUTOINCREMENT: the Operator task deletes tasks outside the
-- graph's Watchtower list, and a reused id would let a worker still proving a
-- deleted task record its proof on a newer one.
CREATE TABLE watchtower_proof_new
(
    `id`                           INTEGER PRIMARY KEY AUTOINCREMENT,
    `instance_id`                  TEXT   NOT NULL,
    `graph_id`                     TEXT   NOT NULL,
    `public_key`                   TEXT   NOT NULL,
    `challenge_txid`               TEXT   NOT NULL,
    `challenge_init_txid`          TEXT   NOT NULL,
    `execution_layer_block_number` BIGINT NOT NULL DEFAULT 0,
    `path_to_proof`                TEXT,
    `proof_size`                   BIGINT NOT NULL DEFAULT 0,
    `public_value_hex`             TEXT,
    `cycles`                       BIGINT NOT NULL DEFAULT 0,
    `proof_state`                  BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `total_time_to_proof`          BIGINT NOT NULL DEFAULT 0,
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL DEFAULT '',
    `node_index`                   INTEGER NOT NULL DEFAULT 0,
    `included`                     BOOLEAN NOT NULL DEFAULT 0,
    `extra`                        TEXT,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0
);

-- Watchtower keys are stored compressed with even parity ("02" + x-only), the
-- form used by the Operator's graph list, so each key has one spelling. The API
-- accepted x-only, compressed and uncompressed keys; the last two carry x right
-- after the one-byte prefix.
-- One task per key: a proven task wins, then an unfinished one, then the oldest.
INSERT INTO watchtower_proof_new
SELECT id, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid,
       execution_layer_block_number, path_to_proof, proof_size, public_value_hex, cycles,
       proof_state, total_time_to_proof, proving_time, zkm_version, node_index, included,
       extra, created_at, updated_at
FROM (
    SELECT *, row_number() OVER (
        PARTITION BY instance_id, graph_id, public_key
        ORDER BY CASE proof_state WHEN 2 THEN 0 WHEN 3 THEN 2 ELSE 1 END, id
    ) AS key_rank
    FROM (
        SELECT id, instance_id, graph_id,
               CASE
                   WHEN length(public_key) = 64 THEN '02' || lower(public_key)
                   WHEN length(public_key) IN (66, 130) THEN '02' || lower(substr(public_key, 3, 64))
                   ELSE public_key
               END AS public_key,
               challenge_txid, challenge_init_txid, execution_layer_block_number, path_to_proof,
               proof_size, public_value_hex, cycles, proof_state, total_time_to_proof,
               proving_time, zkm_version, node_index, included, extra, created_at, updated_at
        FROM watchtower_proof
    )
)
WHERE key_rank = 1;

DROP TABLE watchtower_proof;
ALTER TABLE watchtower_proof_new RENAME TO watchtower_proof;

CREATE UNIQUE INDEX idx_watchtower_proof_key
    ON watchtower_proof (instance_id, graph_id, public_key);
