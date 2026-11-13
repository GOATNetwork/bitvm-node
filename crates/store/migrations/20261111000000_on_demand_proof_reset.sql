-- Operator and Watchtower tasks gain:
-- * state 4 (Cancelled): the task is no longer wanted (its request timed out, or
--   the Watchtower never asked for a proof before the Operator task fixed the list);
-- * reset_count: how often the task owner restarted the failed task;
-- * invalid_reason: set when the task inputs can never be proven, which a restart
--   with the same inputs cannot repair;
-- * input_hash (Operator only): the request inputs, to tell a resubmission with new
--   inputs from a plain retry.
-- SQLite cannot change a CHECK constraint in place, so both tables are rebuilt.

CREATE TABLE operator_proof_new
(
    `id`                           INTEGER PRIMARY KEY,
    `instance_id`                  TEXT   NOT NULL,
    `graph_id`                     TEXT   NOT NULL,
    `execution_layer_block_number` BIGINT NOT NULL DEFAULT 0,
    `path_to_proof`                TEXT,
    `proof_size`                   BIGINT NOT NULL DEFAULT 0,
    `public_value_hex`             TEXT,
    `cycles`                       BIGINT NOT NULL DEFAULT 0,
    `proof_state`                  BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3, 4)),
    `total_time_to_proof`          BIGINT NOT NULL DEFAULT 0,
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL DEFAULT '',
    `operator_committed_blockhash` TEXT   NOT NULL,
    `reset_count`                  BIGINT NOT NULL DEFAULT 0,
    `invalid_reason`               TEXT,
    `input_hash`                   TEXT,
    `extra`                        TEXT,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0
);

-- One task per graph: a proven task wins, then an unfinished one, then the oldest.
INSERT INTO operator_proof_new
    (id, instance_id, graph_id, execution_layer_block_number, path_to_proof, proof_size,
     public_value_hex, cycles, proof_state, total_time_to_proof, proving_time, zkm_version,
     operator_committed_blockhash, extra, created_at, updated_at)
SELECT id, instance_id, graph_id, execution_layer_block_number, path_to_proof, proof_size,
       public_value_hex, cycles, proof_state, total_time_to_proof, proving_time, zkm_version,
       operator_committed_blockhash, extra, created_at, updated_at
FROM (
    SELECT *, row_number() OVER (
        PARTITION BY instance_id, graph_id
        ORDER BY CASE proof_state WHEN 2 THEN 0 WHEN 3 THEN 2 ELSE 1 END, id
    ) AS graph_rank
    FROM operator_proof
)
WHERE graph_rank = 1;

DROP TABLE operator_proof;
ALTER TABLE operator_proof_new RENAME TO operator_proof;

CREATE UNIQUE INDEX idx_operator_proof_graph
    ON operator_proof (instance_id, graph_id);

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
    `proof_state`                  BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3, 4)),
    `total_time_to_proof`          BIGINT NOT NULL DEFAULT 0,
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL DEFAULT '',
    `node_index`                   INTEGER NOT NULL DEFAULT 0,
    `included`                     BOOLEAN NOT NULL DEFAULT 0,
    `reset_count`                  BIGINT NOT NULL DEFAULT 0,
    `invalid_reason`               TEXT,
    `extra`                        TEXT,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0
);

INSERT INTO watchtower_proof_new
    (id, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid,
     execution_layer_block_number, path_to_proof, proof_size, public_value_hex, cycles,
     proof_state, total_time_to_proof, proving_time, zkm_version, node_index, included,
     extra, created_at, updated_at)
SELECT id, instance_id, graph_id, public_key, challenge_txid, challenge_init_txid,
       execution_layer_block_number, path_to_proof, proof_size, public_value_hex, cycles,
       proof_state, total_time_to_proof, proving_time, zkm_version, node_index, included,
       extra, created_at, updated_at
FROM watchtower_proof;

DROP TABLE watchtower_proof;
ALTER TABLE watchtower_proof_new RENAME TO watchtower_proof;

CREATE UNIQUE INDEX idx_watchtower_proof_key
    ON watchtower_proof (instance_id, graph_id, public_key);
