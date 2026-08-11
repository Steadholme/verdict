CREATE TABLE IF NOT EXISTS policy_projection_source (
    source_grant_id TEXT PRIMARY KEY,
    source_version BIGINT NOT NULL CHECK (source_version > 0),
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    projection_epoch BIGINT NOT NULL CHECK (projection_epoch > 0),
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_policy_projection_source_version
    ON policy_projection_source(source_version);
