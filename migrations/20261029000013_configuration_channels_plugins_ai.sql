CREATE TABLE custom_field_definitions (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,49}$'),
    label       text NOT NULL CHECK (length(trim(label)) BETWEEN 1 AND 100),
    field_type  text NOT NULL CHECK (field_type IN ('text', 'number', 'boolean', 'date', 'select')),
    options     text[] NOT NULL DEFAULT '{}',
    required    boolean NOT NULL DEFAULT false,
    position    integer NOT NULL DEFAULT 0,
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, key)
);

CREATE TABLE channels (
    id                uuid PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    workspace_id      uuid NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('email', 'chat', 'social')),
    name              text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    address           text,
    secret_ciphertext bytea NOT NULL,
    allowed_origins   text[] NOT NULL DEFAULT '{}',
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id) ON DELETE CASCADE
);

CREATE TRIGGER channels_updated_at BEFORE UPDATE ON channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE cases
    ADD COLUMN custom_fields jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(custom_fields) = 'object'),
    ADD COLUMN first_response_due_at timestamptz,
    ADD COLUMN resolution_due_at timestamptz,
    ADD COLUMN sla_breached_at timestamptz,
    ADD COLUMN channel_id uuid,
    ADD COLUMN channel_thread_id text,
    ADD COLUMN requester_unverified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT cases_org_id_channel_id_fkey FOREIGN KEY (org_id, channel_id)
        REFERENCES channels (org_id, id) ON DELETE SET NULL (channel_id);

CREATE UNIQUE INDEX cases_channel_thread_key ON cases (org_id, channel_id, channel_thread_id)
    WHERE channel_thread_id IS NOT NULL;
CREATE INDEX cases_sla_open_idx ON cases (org_id)
    WHERE sla_breached_at IS NULL AND (first_response_due_at IS NOT NULL OR resolution_due_at IS NOT NULL);

CREATE TABLE sla_policies (
    id                     uuid PRIMARY KEY,
    org_id                 uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    workspace_id           uuid,
    priority_id            uuid NOT NULL,
    first_response_minutes integer CHECK (first_response_minutes > 0),
    resolution_minutes     integer CHECK (resolution_minutes > 0),
    created_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE NULLS NOT DISTINCT (org_id, workspace_id, priority_id),
    CHECK (first_response_minutes IS NOT NULL OR resolution_minutes IS NOT NULL),
    FOREIGN KEY (org_id, priority_id) REFERENCES case_priorities (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id) ON DELETE CASCADE
);

CREATE TABLE saved_views (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL,
    name       text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    filter     jsonb NOT NULL CHECK (jsonb_typeof(filter) = 'object'),
    shared     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES memberships (org_id, user_id) ON DELETE CASCADE
);

CREATE TRIGGER saved_views_updated_at BEFORE UPDATE ON saved_views
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE contact_identities (
    org_id      uuid NOT NULL,
    contact_id  uuid NOT NULL,
    platform    text NOT NULL CHECK (platform ~ '^[a-z][a-z0-9_]{0,29}$'),
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 200),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, platform, external_id),
    FOREIGN KEY (org_id, contact_id) REFERENCES contacts (org_id, id) ON DELETE CASCADE
);

CREATE TABLE chat_sessions (
    token_hash   bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    org_id       uuid NOT NULL,
    channel_id   uuid NOT NULL,
    case_id      uuid NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    FOREIGN KEY (org_id, channel_id) REFERENCES channels (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, case_id) REFERENCES cases (org_id, id) ON DELETE CASCADE
);

CREATE INDEX chat_sessions_expires_idx ON chat_sessions (expires_at);

CREATE TABLE plugin_installs (
    id                  uuid PRIMARY KEY,
    org_id              uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (kind IN ('builtin', 'webhook')),
    plugin_key          text NOT NULL CHECK (plugin_key ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    name                text NOT NULL,
    base_url            text,
    manifest            jsonb NOT NULL,
    config_ciphertext   bytea,
    secret_ciphertext   bytea NOT NULL,
    permissions         text[] NOT NULL DEFAULT '{}',
    api_credential_id   uuid REFERENCES api_credentials (id) ON DELETE SET NULL,
    webhook_endpoint_id uuid REFERENCES webhook_endpoints (id) ON DELETE SET NULL,
    enabled             boolean NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, plugin_key),
    CHECK ((kind = 'webhook') = (base_url IS NOT NULL))
);

CREATE TRIGGER plugin_installs_updated_at BEFORE UPDATE ON plugin_installs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_settings (
    org_id             uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled            boolean NOT NULL DEFAULT false,
    provider           text NOT NULL CHECK (provider IN ('openai', 'openai_compatible')),
    model              text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
    base_url           text,
    api_key_ciphertext bytea,
    features           text[] NOT NULL DEFAULT '{}',
    include_internal_notes boolean NOT NULL DEFAULT false,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER ai_settings_updated_at BEFORE UPDATE ON ai_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE idempotency_keys ADD COLUMN completed boolean NOT NULL DEFAULT false;
