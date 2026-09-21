-- Peers this node confirmed on chain as registered senders: committee members
-- (peer id registry) and operators (staked master key bound to the peer id).
--
-- The admission registry is an in-memory cache filled by chain lookups, and
-- first-time lookups are budgeted so a flood of fresh identities cannot turn
-- into a flood of RPC calls. Without this table a restart would send every real
-- member back through that budget, competing with the flood.
--
-- `pubkey` is the hex x-only master key the confirmation was made for (empty for
-- committee rows). A registration is only as good as the key that was checked:
-- a peer that re-binds to another key must not inherit it, and a key that moves
-- to another peer id takes its row along. Rows are written only after a positive
-- chain answer, removed on a negative one, and an operator key holds at most one
-- row, so the table is bounded by the on-chain registries, not by who connects.
CREATE TABLE IF NOT EXISTS p2p_registered_peer
(
    peer_id     TEXT   NOT NULL,
    kind        TEXT   NOT NULL,
    pubkey      TEXT   NOT NULL DEFAULT '',
    verified_at BIGINT NOT NULL,
    PRIMARY KEY (peer_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_p2p_registered_peer_pubkey
    ON p2p_registered_peer (kind, pubkey);

-- Highest gossipsub sequence number admitted per registered author. Replay
-- protection keeps a window per author in memory; this mark is what survives a
-- restart, so messages captured before it cannot be replayed into a node that
-- has just come back up. One row per registered author.
CREATE TABLE IF NOT EXISTS p2p_replay_mark
(
    peer_id TEXT   NOT NULL PRIMARY KEY,
    highest BIGINT NOT NULL
);
