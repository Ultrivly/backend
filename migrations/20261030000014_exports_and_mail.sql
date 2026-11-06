CREATE TABLE data_exports (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('organization', 'contact')),
    contact_id   uuid,
    requested_by uuid REFERENCES users (id) ON DELETE SET NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'ready', 'failed')),
    storage_key  text CHECK (storage_key LIKE 'org/' || org_id::text || '/exports/%'),
    size_bytes   bigint,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at   timestamptz,
    UNIQUE (org_id, id),
    CHECK ((kind = 'contact') = (contact_id IS NOT NULL)),
    FOREIGN KEY (org_id, contact_id) REFERENCES contacts (org_id, id) ON DELETE CASCADE
);

CREATE INDEX data_exports_org_idx ON data_exports (org_id, id DESC);
CREATE INDEX data_exports_expiry_idx ON data_exports (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE email_suppressions (
    email      text PRIMARY KEY CHECK (email = lower(email)),
    reason     text NOT NULL CHECK (reason IN ('bounce', 'complaint', 'manual')),
    detail     text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mail_domains (
    id                        uuid PRIMARY KEY,
    org_id                    uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain                    text NOT NULL CHECK (domain = lower(domain) AND domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'),
    selector                  text NOT NULL,
    dkim_private_key_ciphertext bytea NOT NULL,
    dkim_public_key           text NOT NULL,
    verified_at               timestamptz,
    last_checked_at           timestamptz,
    created_at                timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, domain)
);

ALTER TABLE idempotency_keys DROP COLUMN response_body;
ALTER TABLE idempotency_keys ADD COLUMN response_ciphertext bytea;

CREATE INDEX domain_events_dispatched_idx ON domain_events (dispatched_at) WHERE dispatched_at IS NOT NULL;
CREATE INDEX webhook_deliveries_created_idx ON webhook_deliveries (created_at) WHERE status <> 'pending';
CREATE INDEX workflow_runs_created_idx ON workflow_runs (created_at);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
