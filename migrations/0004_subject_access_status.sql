CREATE TABLE IF NOT EXISTS policy_subject_status (
    subject TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('active', 'frozen', 'terminated')),
    source_event_id TEXT NOT NULL,
    source_version BIGINT NOT NULL CHECK (source_version > 0),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
    updated_at BIGINT NOT NULL,
    CHECK (subject LIKE 'user:%'),
    CHECK (length(subject) <= 512 AND length(source_event_id) BETWEEN 1 AND 256)
);

CREATE INDEX IF NOT EXISTS ix_policy_subject_status_state
    ON policy_subject_status(state, updated_at);
