-- Record committee key deletion so recovery does not regenerate the key.
ALTER TABLE instance ADD COLUMN key_deleted INTEGER NOT NULL DEFAULT 0;
