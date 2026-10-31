-- Tables of proof-builder-rpc (crates/store/src/localdb/proof.rs). The node does not use them; they
-- share the store migrations because proof-builder-rpc opens its database through store::create_local_db.
-- Same definitions as the dev migrations 20251215023559 / 20251215023612 / 20251215024440, including the
-- header-chain 0..116000 seed proof.

CREATE TABLE operator_proof
(
    `id`                           INTEGER PRIMARY KEY,
    `instance_id`                  TEXT   NOT NULL,
    `graph_id`                     TEXT   NOT NULL,
    `execution_layer_block_number` BIGINT NOT NULL DEFAULT 0,
    `path_to_proof`                TEXT,
    `proof_size`                   BIGINT NOT NULL DEFAULT 0,
    `public_value_hex`             TEXT,
    `cycles`                       BIGINT NOT NULL DEFAULT 0,
    `proof_state`                  BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `total_time_to_proof`          BIGINT NOT NULL DEFAULT 0,
    `proving_time`                 BIGINT NOT NULL DEFAULT 0,
    `zkm_version`                  TEXT   NOT NULL DEFAULT '',
    `operator_committed_blockhash` TEXT   NOT NULL,
    `extra`                        TEXT,
    `created_at`                   BIGINT NOT NULL DEFAULT 0,
    `updated_at`                   BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE watchtower_proof
(
    `id`                           INTEGER PRIMARY KEY,
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

CREATE TABLE long_running_task_proof
(
    `id`                  INTEGER PRIMARY KEY,
    `block_start`         BIGINT NOT NULL DEFAULT 0,
    `block_end`           BIGINT NOT NULL DEFAULT 0,
    `chain_name`          TEXT   NOT NULL CHECK ( chain_name in ('header-chain', 'state-chain', 'commit-chain') ),
    `path_to_proof`       TEXT,
    `cycles`              BIGINT NOT NULL DEFAULT 0,
    `proof_state`         INT    NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `proof_size`          BIGINT NOT NULL DEFAULT 0,
    `public_value_hex`    TEXT,
    `total_time_to_proof` BIGINT NOT NULL DEFAULT 0,
    `proving_time`        BIGINT NOT NULL DEFAULT 0,
    `zkm_version`         TEXT   NOT NULL DEFAULT '',
    `extra`               TEXT,
    `created_at`          BIGINT NOT NULL DEFAULT 0,
    `updated_at`          BIGINT NOT NULL DEFAULT 0
);

INSERT INTO long_running_task_proof (block_start, block_end, chain_name, path_to_proof, cycles, proof_state,
                                     total_time_to_proof, proving_time, zkm_version, extra)
VALUES (0, 116000, 'header-chain', '../circuits/data/header-chain/0-116000.bin', 3147770424, 2, 637403, 637403,
        'v1.2.3', '');
