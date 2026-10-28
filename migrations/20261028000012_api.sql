ALTER TABLE workspaces ADD COLUMN portal_enabled boolean NOT NULL DEFAULT false;

INSERT INTO role_permissions (org_id, role_id, permission)
SELECT org_id, id, 'organization.manage' FROM roles WHERE key = 'admin' AND is_builtin
ON CONFLICT DO NOTHING;

CREATE TABLE api_credentials (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    token_prefix text NOT NULL,
    permissions  text[] NOT NULL,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    UNIQUE (org_id, id)
);

CREATE INDEX api_credentials_org_idx ON api_credentials (org_id, created_at DESC);

CREATE TABLE webhook_endpoints (
    id                uuid PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url               text NOT NULL,
    description       text NOT NULL DEFAULT '',
    events            text[] NOT NULL,
    secret_ciphertext bytea NOT NULL,
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);

CREATE TRIGGER webhook_endpoints_updated_at BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webhook_deliveries (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    endpoint_id     uuid NOT NULL,
    event_id        uuid NOT NULL,
    event_kind      text NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    response_status integer,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    UNIQUE (endpoint_id, event_id),
    FOREIGN KEY (org_id, endpoint_id) REFERENCES webhook_endpoints (org_id, id) ON DELETE CASCADE
);

CREATE INDEX webhook_deliveries_endpoint_idx ON webhook_deliveries (endpoint_id, created_at DESC);

CREATE TABLE kb_categories (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    position    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);

CREATE UNIQUE INDEX kb_categories_name_key ON kb_categories (org_id, lower(name));

CREATE TABLE kb_articles (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    category_id  uuid,
    title        text NOT NULL CHECK (length(trim(title)) BETWEEN 1 AND 300),
    slug         text NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,118}[a-z0-9])?$'),
    body         text NOT NULL DEFAULT '',
    visibility   text NOT NULL CHECK (visibility IN ('public', 'internal')),
    state        text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'archived')),
    author_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    published_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple', title || ' ' || body)) STORED,
    UNIQUE (org_id, id),
    UNIQUE (org_id, slug),
    FOREIGN KEY (org_id, category_id) REFERENCES kb_categories (org_id, id) ON DELETE SET NULL (category_id)
);

CREATE INDEX kb_articles_search_idx ON kb_articles USING gin (search_vector);
CREATE INDEX kb_articles_state_idx ON kb_articles (org_id, state, visibility);

CREATE TRIGGER kb_articles_updated_at BEFORE UPDATE ON kb_articles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE workflows (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    workspace_id uuid,
    name         text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    enabled      boolean NOT NULL DEFAULT false,
    published_version_id uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id) ON DELETE CASCADE
);

CREATE TRIGGER workflows_updated_at BEFORE UPDATE ON workflows
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE workflow_versions (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL,
    workflow_id uuid NOT NULL,
    version     integer NOT NULL,
    definition  jsonb NOT NULL,
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (workflow_id, version),
    FOREIGN KEY (org_id, workflow_id) REFERENCES workflows (org_id, id) ON DELETE CASCADE
);

ALTER TABLE workflows ADD CONSTRAINT workflows_published_version_fkey
    FOREIGN KEY (org_id, published_version_id) REFERENCES workflow_versions (org_id, id)
    DEFERRABLE INITIALLY IMMEDIATE;

CREATE TABLE workflow_runs (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    workflow_id uuid NOT NULL,
    version_id  uuid NOT NULL,
    event_id    uuid NOT NULL,
    case_id     uuid,
    status      text NOT NULL CHECK (status IN ('skipped', 'succeeded', 'failed')),
    steps       jsonb NOT NULL DEFAULT '[]',
    error       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (version_id, event_id),
    FOREIGN KEY (org_id, workflow_id) REFERENCES workflows (org_id, id) ON DELETE CASCADE
);

CREATE INDEX workflow_runs_workflow_idx ON workflow_runs (workflow_id, created_at DESC);
CREATE INDEX workflow_runs_org_idx ON workflow_runs (org_id, created_at DESC);
