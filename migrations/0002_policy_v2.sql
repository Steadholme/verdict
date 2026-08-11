CREATE TABLE IF NOT EXISTS policy_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    epoch BIGINT NOT NULL CHECK (epoch >= 0),
    updated_at BIGINT NOT NULL
);

INSERT INTO policy_state(id, epoch, updated_at)
VALUES (1, 0, EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS policy_edges_v2 (
    edge_id TEXT PRIMARY KEY,
    projection_key TEXT NOT NULL UNIQUE,
    source_grant_id TEXT NOT NULL,
    object TEXT NOT NULL,
    relation TEXT NOT NULL CHECK (relation = 'grantee'),
    subject TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    resource_selector JSONB NOT NULL DEFAULT '{"v":1,"type":"any","id":"*"}'::jsonb,
    condition JSONB,
    not_before BIGINT,
    expires_at BIGINT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    projection_epoch BIGINT NOT NULL CHECK (projection_epoch >= 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CHECK (object LIKE 'permission:%'),
    CHECK (expires_at IS NULL OR not_before IS NULL OR expires_at > not_before)
);

CREATE INDEX IF NOT EXISTS ix_policy_edges_v2_lookup
    ON policy_edges_v2(object, relation, active);
CREATE INDEX IF NOT EXISTS ix_policy_edges_v2_subject
    ON policy_edges_v2(subject, active);
CREATE INDEX IF NOT EXISTS ix_policy_edges_v2_source
    ON policy_edges_v2(source_grant_id);
CREATE INDEX IF NOT EXISTS ix_policy_edges_v2_expiry
    ON policy_edges_v2(expires_at) WHERE expires_at IS NOT NULL;
