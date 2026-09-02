CREATE TABLE IF NOT EXISTS policy_application_subject_status (
    application_sub TEXT PRIMARY KEY,
	state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'revoked', 'expired')),
    source_event_id TEXT NOT NULL,
    subject_version BIGINT NOT NULL CHECK (subject_version > 0),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch > 0),
    revocation_epoch BIGINT NOT NULL CHECK (revocation_epoch > 0),
    updated_at BIGINT NOT NULL,
    CHECK (application_sub ~ '^application:[A-Za-z0-9_-]{16,128}$'),
    CHECK (length(source_event_id) BETWEEN 1 AND 256)
);

CREATE INDEX IF NOT EXISTS ix_policy_application_subject_state
    ON policy_application_subject_status(state, updated_at);

CREATE TABLE IF NOT EXISTS policy_application_decisions_v2 (
    decision_id TEXT PRIMARY KEY,
    decision_digest TEXT NOT NULL UNIQUE CHECK (decision_digest ~ '^[0-9a-f]{64}$'),
    application_sub TEXT NOT NULL,
    permission TEXT NOT NULL,
    resource JSONB NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('Allow', 'Deny', 'Indeterminate')),
    reason TEXT NOT NULL,
    request_v2 JSONB NOT NULL,
    evidence JSONB NOT NULL,
    policy_version BIGINT NOT NULL CHECK (policy_version >= 0),
    subject_version BIGINT NOT NULL CHECK (subject_version >= 0),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 0),
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at = issued_at + 30),
    FOREIGN KEY (application_sub) REFERENCES policy_application_subject_status(application_sub)
);

CREATE INDEX IF NOT EXISTS ix_policy_application_decisions_subject_time
    ON policy_application_decisions_v2(application_sub, issued_at DESC);
