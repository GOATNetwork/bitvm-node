-- The Gateway an operator task proves its withdrawal from; part of the graph constant.
ALTER TABLE operator_proof ADD COLUMN `gateway_address` TEXT NOT NULL DEFAULT '';

-- Every withdrawal the proven state chain accumulated, in leaf order. Rebuilt from
-- `block_number` on when a batch is proven again.
CREATE TABLE state_chain_withdrawal
(
    `leaf_index`      BIGINT PRIMARY KEY,
    `block_number`    BIGINT NOT NULL,
    `gateway_address` TEXT   NOT NULL,
    `graph_id`        TEXT   NOT NULL
);
CREATE INDEX idx_state_chain_withdrawal_block ON state_chain_withdrawal (block_number);
CREATE INDEX idx_state_chain_withdrawal_graph ON state_chain_withdrawal (gateway_address, graph_id);
