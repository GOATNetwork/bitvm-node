-- Allow only one graph definition per operator slot.
CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_operator_slot
    ON graph (operator_pubkey, kickoff_index);

-- Signing authorization: a nonce is authorized for exactly one transcript,
-- and the record is written before the signature is produced. A retry recovers
-- the same authorization; a different transcript for the same nonce is refused.
CREATE TABLE IF NOT EXISTS signing_authorization (
    nonce_id TEXT NOT NULL PRIMARY KEY,
    -- graph | instance
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    transcript_digest TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signing_authorization_scope
    ON signing_authorization (scope_kind, scope_id);
