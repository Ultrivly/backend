



CREATE TABLE jobs (
    id           uuid PRIMARY KEY,
    
    org_id       uuid REFERENCES organizations (id),
    kind         text NOT NULL,
    payload      jsonb NOT NULL DEFAULT '{}',
    state        text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'dead')),
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 10 CHECK (max_attempts > 0),
    run_at       timestamptz NOT NULL DEFAULT now(),
    locked_by    text,
    locked_until timestamptz,
    last_error   text,
    dedupe_key   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE INDEX jobs_claim_idx ON jobs (run_at) WHERE state = 'queued';
CREATE INDEX jobs_running_idx ON jobs (locked_until) WHERE state = 'running';
CREATE INDEX jobs_dead_idx ON jobs (org_id, updated_at DESC) WHERE state = 'dead';

CREATE UNIQUE INDEX jobs_dedupe_key ON jobs (kind, dedupe_key)
    WHERE dedupe_key IS NOT NULL AND state IN ('queued', 'running');

CREATE TRIGGER jobs_updated_at BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


CREATE TABLE domain_events (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations (id),
    kind           text NOT NULL,
    subject_type   text NOT NULL,
    subject_id     uuid NOT NULL,
    data           jsonb NOT NULL DEFAULT '{}',
    
    causation_id   uuid,
    depth          integer NOT NULL DEFAULT 0 CHECK (depth >= 0),
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    dispatched_at  timestamptz
);

CREATE INDEX domain_events_undispatched_idx ON domain_events (occurred_at) WHERE dispatched_at IS NULL;
CREATE INDEX domain_events_subject_idx ON domain_events (org_id, subject_type, subject_id);


CREATE TABLE audit_events (
    id          uuid PRIMARY KEY,
    
    org_id      uuid REFERENCES organizations (id),
    actor_kind  text NOT NULL CHECK (actor_kind IN ('user', 'contact', 'api_credential', 'system', 'workflow', 'plugin', 'ai', 'operator')),
    actor_id    uuid,
    action      text NOT NULL,
    target_type text,
    target_id   uuid,
    request_id  text,
    ip_address  inet,
    user_agent  text,
    metadata    jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(metadata) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_idx ON audit_events (org_id, occurred_at DESC);
CREATE INDEX audit_events_target_idx ON audit_events (org_id, target_type, target_id);


CREATE TABLE idempotency_keys (
    org_id          uuid NOT NULL REFERENCES organizations (id),
    
    principal_id    uuid NOT NULL,
    key             text NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    
    request_hash    bytea NOT NULL,
    response_status smallint,
    response_body   jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, principal_id, key)
);

CREATE INDEX idempotency_keys_expires_idx ON idempotency_keys (expires_at);
