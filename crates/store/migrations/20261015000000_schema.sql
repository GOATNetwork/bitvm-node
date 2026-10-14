-- Baseline schema. Nodes are deployed on a fresh database, so the earlier
-- incremental migrations are folded into this one file.

-- ------------------------------------------------------------ peg-in / graphs

CREATE TABLE instance
(
    `instance_id`        TEXT            NOT NULL DEFAULT '',
    `network`            TEXT            NOT NULL DEFAULT 'test',
    `from_addr`          TEXT            NOT NULL DEFAULT '',
    `to_addr`            TEXT            NOT NULL DEFAULT '',
    `amount`             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `fees`               TEXT            NOT NULL DEFAULT '[0, 0, 0]',
    `status`             TEXT            NOT NULL DEFAULT '',
    `input_utxos`        TEXT            NOT NULL DEFAULT '',
    `goat_tx_hash`       TEXT            NOT NULL DEFAULT '',
    `goat_tx_height`     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `user_xonly_pubkey`  TEXT            NOT NULL DEFAULT '[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]',
    `user_change_addr`   TEXT            NOT NULL DEFAULT '',
    `user_refund_addr`   TEXT            NOT NULL DEFAULT '',
    `btc_txid`           TEXT,
    `pegin_confirm_txid` TEXT,
    `pegin_cancel_txid`  TEXT,
    `committees_answers` TEXT            NOT NULL DEFAULT '{}',
    `pegin_data_tx_hash` TEXT            NOT NULL DEFAULT '',
    `btc_height`         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `parameters`         TEXT,
    `post_pegin_txhash`  TEXT,
    `status_updated_at`  BIGINT          NOT NULL DEFAULT 0,
    `created_at`         BIGINT          NOT NULL DEFAULT 0,
    `updated_at`         BIGINT          NOT NULL DEFAULT 0,
    -- The committee's instance key was deleted after the peg-in settled.
    `key_deleted`        INTEGER         NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`)
);

CREATE TABLE graph
(
    `graph_id`                           TEXT            NOT NULL DEFAULT '',
    `instance_id`                        TEXT            NOT NULL,
    `kickoff_index`                      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `from_addr`                          TEXT            NOT NULL DEFAULT '',
    `to_addr`                            TEXT            NOT NULL DEFAULT '',
    `amount`                             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `challenge_amount`                   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `status`                             TEXT            NOT NULL DEFAULT '',
    `sub_status`                         TEXT            NOT NULL DEFAULT '',
    `operator_pubkey`                    TEXT            NOT NULL DEFAULT '',
    `cur_prekickoff_txid`                TEXT,
    `next_prekickoff`                    TEXT,
    `force_skip_kickoff_txid`            TEXT,
    `quick_challenge_txid`               TEXT,
    `challenge_incomplete_kickoff_txid`  TEXT,
    `pegin_txid`                         TEXT,
    `kickoff_txid`                       TEXT,
    `take1_txid`                         TEXT,
    `challenge_txid`                     TEXT,
    `take2_txid`                         TEXT,
    `watchtower_challenge_init_txid`     TEXT,
    `operator_assert_txid`               TEXT,
    `verifier_assert_txids`              TEXT            NOT NULL DEFAULT '[]',
    `disprove_txids`                     TEXT            NOT NULL DEFAULT '[]',
    `init_withdraw_tx_hash`              TEXT,
    `bridge_out_start_at`                BIGINT          NOT NULL DEFAULT 0,
    `status_updated_at`                  BIGINT          NOT NULL DEFAULT 0,
    `proceed_withdraw_height`            BIGINT          NOT NULL DEFAULT 0,
    `created_at`                         BIGINT          NOT NULL DEFAULT 0,
    `updated_at`                         BIGINT          NOT NULL DEFAULT 0,
    `watchtower_challenge_timeout_txids` TEXT            NOT NULL DEFAULT '[]',
    `operator_challenge_nack_txids`      TEXT            NOT NULL DEFAULT '[]',
    `operator_commit_timeout_txid`       TEXT,
    -- Hash of the stored definition; a replay with another hash is refused.
    `definition_hash`                    TEXT            NOT NULL DEFAULT '',
    PRIMARY KEY (`graph_id`)
);
-- One graph per operator slot.
CREATE UNIQUE INDEX idx_graph_operator_slot
    ON graph (operator_pubkey, kickoff_index);

CREATE TABLE graph_raw_data
(
    `graph_id`   TEXT   NOT NULL,
    `raw_data`   TEXT   NOT NULL DEFAULT '',
    `created_at` BIGINT NOT NULL DEFAULT 0,
    `updated_at` BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);

-- An operator's graph setup in progress: one per (instance, operator).
CREATE TABLE pending_graph_init
(
    `instance_id`     TEXT   NOT NULL,
    `operator_pubkey` TEXT   NOT NULL,
    `graph_id`        TEXT   NOT NULL UNIQUE,
    `created_at`      BIGINT NOT NULL DEFAULT 0,
    `updated_at`      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`, `operator_pubkey`)
);

CREATE TABLE pegin_instance_process_data
(
    `instance_id`      TEXT   NOT NULL,
    `process_data` TEXT   NOT NULL DEFAULT '',
    `created_at`       BIGINT NOT NULL DEFAULT 0,
    `updated_at`       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`)
);

CREATE TABLE pegin_graph_process_data
(
    `graph_id`     TEXT    NOT NULL,
    `instance_id`  TEXT    NOT NULL,
    `process_data` TEXT    NOT NULL DEFAULT '',
    `is_endorsed`  BOOLEAN NOT NULL DEFAULT 0,
    `created_at`   BIGINT  NOT NULL DEFAULT 0,
    `updated_at`   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);

-- Confirmed graph transactions whose outputs the chain scan watches.
CREATE TABLE `graph_btc_tx_vout_monitor`
(
    `graph_id`     TEXT   NOT NULL,
    `tx_name`      TEXT   NOT NULL,
    `txid`         TEXT   NOT NULL,
    `height`       BIGINT NOT NULL DEFAULT 0,
    `vout_len`     BIGINT NOT NULL DEFAULT 0,
    `monitor_data` TEXT   NOT NULL DEFAULT '',
    `created_at`   BIGINT NOT NULL DEFAULT 0,
    `updated_at`   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`, `txid`)
);

-- Each signing nonce is bound to one transcript before it signs.
CREATE TABLE signing_authorization (
    nonce_id TEXT NOT NULL PRIMARY KEY,
    -- graph | instance
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    transcript_digest TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- ------------------------------------------------------------------- Goat

CREATE TABLE goat_tx_record
(
    `instance_id`       TEXT   NOT NULL,
    `graph_id`          TEXT   NOT NULL,
    `tx_type`           TEXT   NOT NULL DEFAULT 'Normal',
    `tx_hash`           TEXT   NOT NULL DEFAULT '',
    `height`            BIGINT NOT NULL DEFAULT 0,
    `is_local`          BOOL   NOT NULL DEFAULT 1,
    `extra`             TEXT,
    `created_at`        BIGINT NOT NULL DEFAULT 0,
    `processing_status` TEXT   NOT NULL DEFAULT 'Skipped',
    PRIMARY KEY (`instance_id`, `graph_id`, `tx_type`)
);
CREATE INDEX id_goat_tx_hash ON goat_tx_record (`tx_hash`);

CREATE TABLE watch_contract
(
    `contract_addr` TEXT   NOT NULL DEFAULT '',
    `gap`           BIGINT NOT NULL DEFAULT 0,
    `from_height`   BIGINT NOT NULL DEFAULT 0,
    `the_graph_url` TEXT   NOT NULL DEFAULT '',
    `status`        TEXT   NOT NULL DEFAULT 'UnSync',
    `extra`         TEXT,
    `updated_at`    BIGINT NOT NULL DEFAULT 0,
    `created_at`    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`contract_addr`)
);

CREATE TABLE commit_info
(
    `txid`                  TEXT   NOT NULL,
    `threshold`             BIGINT NOT NULL DEFAULT 0,
    `publisher_public_keys` TEXT   NOT NULL,
    `commit_proof_id`       BIGINT NOT NULL DEFAULT 0,
    `created_at`            BIGINT NOT NULL DEFAULT 0,
    `updated_at`            BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`txid`)
);

CREATE TABLE bridge_out_global_stats
(
    `id`             INTEGER PRIMARY KEY,
    `initial_txn`    BIGINT NOT NULL DEFAULT 0,
    `initial_amount` TEXT   NOT NULL DEFAULT '0',
    `claim_txn`      BIGINT NOT NULL DEFAULT 0,
    `claim_amount`   TEXT   NOT NULL DEFAULT '0',
    `refund_txn`     BIGINT NOT NULL DEFAULT 0,
    `refund_amount`  TEXT   NOT NULL DEFAULT '0',
    `created_at`     BIGINT NOT NULL DEFAULT 0,
    `updated_at`     BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE swap_escrow
(
    `escrow_hash`       TEXT   NOT NULL,             -- 0x-prefixed 32-byte hex, lowercase
    `network`           TEXT   NOT NULL DEFAULT '',
    `status`            TEXT   NOT NULL DEFAULT '',  -- SwapEscrowStatus
    `offerer_addr`      TEXT   NOT NULL DEFAULT '',  -- GOAT account funding the escrow
    `claimer_addr`      TEXT   NOT NULL DEFAULT '',  -- GOAT account entitled to claim
    `btc_addr`          TEXT   NOT NULL DEFAULT '',  -- BTC address receiving the payout
    `token`             TEXT   NOT NULL DEFAULT '',  -- escrow token contract address
    `amount`            TEXT   NOT NULL DEFAULT '0', -- escrow amount, U256 decimal string
    `refund_deadline`   BIGINT NOT NULL DEFAULT 0,   -- unix secs after which refund is possible
    `escrow_data`       TEXT,                        -- hex abi-encoded EscrowData from Initialize tx
    `init_tx_hash`      TEXT   NOT NULL DEFAULT '',  -- swap Initialize GOAT tx
    `init_tx_height`    BIGINT NOT NULL DEFAULT 0,
    `claim_tx_hash`     TEXT   NOT NULL DEFAULT '',  -- swap Claim GOAT tx
    `claim_btc_txid`    TEXT,                        -- BTC payout tx committed by the claim
    `refund_tx_hash`    TEXT   NOT NULL DEFAULT '',  -- swap Refund GOAT tx
    `status_updated_at` BIGINT NOT NULL DEFAULT 0,
    `created_at`        BIGINT NOT NULL DEFAULT 0,
    `updated_at`        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`escrow_hash`)
);

CREATE TABLE sequencer_set_hash_changes
(
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cosmos_block_height BIGINT NOT NULL UNIQUE,
    goat_block_height   BIGINT NOT NULL,
    validators_hash     TEXT   NOT NULL,
    created_at          BIGINT NOT NULL DEFAULT 0,
    updated_at          BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX idx_sequencer_set_hash_changes_goat_block_height
    ON sequencer_set_hash_changes (goat_block_height);

CREATE TABLE sequencer_set_scan_state
(
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    next_cosmos_block_height BIGINT NOT NULL,
    latest_goat_block_height BIGINT NOT NULL,
    latest_validators_hash   TEXT   NOT NULL,
    created_at               BIGINT NOT NULL DEFAULT 0,
    updated_at               BIGINT NOT NULL DEFAULT 0
);

-- -------------------------------------------------------------------- P2P

CREATE TABLE node
(
    `peer_id`          TEXT   NOT NULL DEFAULT '',
    `actor`            TEXT   NOT NULL DEFAULT '',
    `goat_addr`        TEXT   NOT NULL DEFAULT '',
    `btc_pub_key`      TEXT   NOT NULL DEFAULT '',
    socket_addr        TEXT   NOT NULL DEFAULT '',
    `node_name`        TEXT   NOT NULL DEFAULT '',
    `service_fee_rate` REAL   NOT NULL DEFAULT 0.0,
    `available_peg_btc`
                       TEXT   NOT NULL DEFAULT '0',
    `reward`
                       TEXT   NOT NULL DEFAULT '0',
    `created_at`       BIGINT NOT NULL DEFAULT 0,
    `updated_at`       BIGINT NOT NULL DEFAULT 0,
    -- The peer's signature binding `btc_pub_key` to `peer_id`, and when it was issued.
    binding_sig        TEXT   NOT NULL DEFAULT '',
    binding_issued_at  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`peer_id`)
);

-- Peers whose on-chain registration this node confirmed (committee, operator).
CREATE TABLE p2p_registered_peer
(
    peer_id     TEXT   NOT NULL,
    kind        TEXT   NOT NULL,
    pubkey      TEXT   NOT NULL DEFAULT '',
    verified_at BIGINT NOT NULL,
    PRIMARY KEY (peer_id, kind)
);
CREATE INDEX idx_p2p_registered_peer_pubkey
    ON p2p_registered_peer (kind, pubkey);

-- ----------------------------------------------------------- execution engine

CREATE TABLE engine_inbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Producer-supplied dedup key: content id, chain event id, height key,
    -- or job result id. Arrival of a known id never creates a second row.
    event_id TEXT NOT NULL UNIQUE,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    -- Stable hash of (aggregate_kind, aggregate_id); workers own shard_key % K.
    shard_key BIGINT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    -- Cleared once the event is Applied; kept while Pending, Waiting or Failed.
    payload BLOB,
    payload_size BIGINT NOT NULL DEFAULT 0,
    -- Pending | Applied | Failed | Poisoned
    state TEXT NOT NULL DEFAULT 'Pending',
    attempts BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    -- Set while the event is Pending because a dependency is missing.
    waiting_ref TEXT,
    waiting_detail TEXT,
    -- Heavy messages: who to ACK once the material is durably applied or parked.
    ack_peer TEXT,
    ack_delivery_id TEXT,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    applied_at BIGINT,
    -- The sender class the author had when a network event was admitted;
    -- empty for local, chain and job events. Meters the inbox quotas.
    admission_class TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_engine_inbox_runnable
    ON engine_inbox (state, next_at, shard_key, seq);
CREATE INDEX idx_engine_inbox_waiting
    ON engine_inbox (state, waiting_ref);
CREATE INDEX idx_engine_inbox_admission
    ON engine_inbox (source, state, admission_class, author, payload_size);

CREATE TABLE engine_aggregate (
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT '',
    -- Opaque state owned by the aggregate handler (JSON).
    state TEXT,
    version BIGINT NOT NULL DEFAULT 0,
    last_event_id TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (aggregate_kind, aggregate_id)
);

-- A job action or event kind that panicked on an aggregate: held back until
-- `blocked_until`, released by a clean run or a manual clear.
CREATE TABLE engine_aggregate_poison (
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

CREATE TABLE engine_outbox (
    outbox_id TEXT NOT NULL PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    -- The phase whose terminal predicate closes a small message.
    phase_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    topic TEXT NOT NULL,
    payload BLOB NOT NULL,
    -- Heavy messages: JSON object of outstanding recipient peer id -> delivery id.
    -- NULL for small messages, which close on receiver-side evidence instead.
    ack_set TEXT,
    -- Open | Closed
    state TEXT NOT NULL DEFAULT 'Open',
    close_reason TEXT,
    publish_count BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    closed_at BIGINT
);
CREATE INDEX idx_engine_outbox_due
    ON engine_outbox (state, next_at);
CREATE INDEX idx_engine_outbox_phase
    ON engine_outbox (aggregate_kind, aggregate_id, phase_ref, state);

CREATE TABLE engine_job (
    -- Stable id H(aggregate ‖ phase ‖ action ‖ params hash); re-creation is a no-op.
    job_id TEXT NOT NULL PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    action TEXT NOT NULL,
    -- cpu | pegout | network
    pool TEXT NOT NULL,
    params BLOB,
    -- Pending | Running | Done | Failed | Cancelled | Poisoned
    state TEXT NOT NULL DEFAULT 'Pending',
    -- Incremented on every claim; a completion with a stale generation is fenced.
    generation BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0,
    attempts BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL DEFAULT 0,
    deadline_at BIGINT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    result BLOB,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    finished_at BIGINT
);
CREATE INDEX idx_engine_job_due
    ON engine_job (state, next_at, lease_until);
CREATE INDEX idx_engine_job_aggregate
    ON engine_job (aggregate_kind, aggregate_id, phase, state);
