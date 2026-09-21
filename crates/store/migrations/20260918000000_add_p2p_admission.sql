-- Admission control for externally received gossip.
--
-- Inbound P2P messages are persisted before any business validation, so the
-- node must bound what an arbitrary peer can make it store, and must be able to
-- tell an authenticated sender apart from an anonymous one.

-- p2p_inbox: how the sender was classified when a row was admitted, and a digest
-- used to collapse an identical payload the same sender re-publishes with a fresh
-- gossip id. `admission_class` is `Committee`, `Registered`, or `Unregistered`.
ALTER TABLE p2p_inbox ADD COLUMN admission_class TEXT NOT NULL DEFAULT 'Unregistered';
ALTER TABLE p2p_inbox ADD COLUMN content_hash BLOB;

-- Covering index for the per-sender quota query. `content` is a large blob and
-- `content_size` follows it, so reading usage from the table would walk every
-- overflow page of every queued row. `state` leads so the partial working set is
-- scanned directly.
CREATE INDEX IF NOT EXISTS idx_p2p_inbox_admission
    ON p2p_inbox (state, admission_class, from_peer, content_size);

CREATE INDEX IF NOT EXISTS idx_p2p_inbox_content_hash
    ON p2p_inbox (from_peer, content_hash);

-- node: the sender's proof that the on-chain-registered key `btc_pub_key`
-- authorised this `peer_id`. gossipsub authenticates the peer id; this Schnorr
-- signature (by the node master key over the peer id) is what lets a receiver
-- trust the mapping and grant the registered sender class. `binding_issued_at`
-- orders re-bindings so one key maps to a single peer id at a time.
ALTER TABLE node ADD COLUMN binding_sig TEXT NOT NULL DEFAULT '';
ALTER TABLE node ADD COLUMN binding_issued_at BIGINT NOT NULL DEFAULT 0;
