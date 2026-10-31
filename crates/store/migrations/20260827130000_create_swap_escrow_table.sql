-- Swap-based bridge-out escrows, keyed by the on-chain escrow hash.
-- Fully independent of the BitVM `instance`/`graph` flow.
DROP TABLE IF EXISTS `swap_escrow`;
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
