



CREATE TABLE contacts (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id),
    email        text,
    display_name text NOT NULL,
    user_id      uuid REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);

CREATE UNIQUE INDEX contacts_email_key ON contacts (org_id, lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX contacts_user_key ON contacts (org_id, user_id) WHERE user_id IS NOT NULL;

CREATE TRIGGER contacts_updated_at BEFORE UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();



CREATE TABLE case_statuses (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id),
    key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    label       text NOT NULL,
    category    text NOT NULL CHECK (category IN ('new', 'open', 'pending', 'resolved', 'closed')),
    position    integer NOT NULL DEFAULT 0,
    is_default  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, key)
);

CREATE UNIQUE INDEX case_statuses_one_default ON case_statuses (org_id) WHERE is_default;

CREATE TABLE case_priorities (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id),
    key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    label       text NOT NULL,
    
    rank        integer NOT NULL,
    is_default  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, key)
);

CREATE UNIQUE INDEX case_priorities_one_default ON case_priorities (org_id) WHERE is_default;



CREATE TABLE case_number_counters (
    org_id      uuid PRIMARY KEY REFERENCES organizations (id),
    last_value  bigint NOT NULL DEFAULT 0
);

CREATE TABLE cases (
    id                   uuid PRIMARY KEY,
    org_id               uuid NOT NULL REFERENCES organizations (id),
    workspace_id         uuid NOT NULL,
    number               bigint NOT NULL CHECK (number > 0),
    subject              text NOT NULL CHECK (length(trim(subject)) > 0),
    description          text NOT NULL DEFAULT '',
    status_id            uuid NOT NULL,
    priority_id          uuid NOT NULL,
    category             text,
    tags                 text[] NOT NULL DEFAULT '{}',
    requester_contact_id uuid NOT NULL,
    team_id              uuid,
    
    assignee_user_id     uuid,
    source_channel       text NOT NULL CHECK (source_channel IN ('web', 'email', 'chat', 'api', 'social')),
    first_response_at    timestamptz,
    resolved_at          timestamptz,
    closed_at            timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    search_vector        tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', subject || ' ' || description)
    ) STORED,
    UNIQUE (org_id, id),
    UNIQUE (org_id, number),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id),
    FOREIGN KEY (org_id, status_id) REFERENCES case_statuses (org_id, id),
    FOREIGN KEY (org_id, priority_id) REFERENCES case_priorities (org_id, id),
    FOREIGN KEY (org_id, requester_contact_id) REFERENCES contacts (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id),
    FOREIGN KEY (org_id, assignee_user_id) REFERENCES memberships (org_id, user_id)
);


CREATE INDEX cases_workspace_created_idx ON cases (org_id, workspace_id, created_at DESC);
CREATE INDEX cases_status_idx ON cases (org_id, status_id);
CREATE INDEX cases_assignee_idx ON cases (org_id, assignee_user_id) WHERE assignee_user_id IS NOT NULL;
CREATE INDEX cases_team_idx ON cases (org_id, team_id) WHERE team_id IS NOT NULL;
CREATE INDEX cases_requester_idx ON cases (org_id, requester_contact_id);
CREATE INDEX cases_tags_idx ON cases USING gin (tags);
CREATE INDEX cases_search_idx ON cases USING gin (search_vector);

CREATE TRIGGER cases_updated_at BEFORE UPDATE ON cases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


CREATE TABLE case_messages (
    id                  uuid PRIMARY KEY,
    org_id              uuid NOT NULL,
    case_id             uuid NOT NULL,
    visibility          text NOT NULL CHECK (visibility IN ('public', 'internal')),
    author_kind         text NOT NULL CHECK (author_kind IN ('user', 'contact', 'system', 'workflow', 'plugin', 'ai')),
    author_user_id      uuid REFERENCES users (id),
    author_contact_id   uuid,
    body                text NOT NULL,
    body_format         text NOT NULL DEFAULT 'markdown' CHECK (body_format IN ('text', 'markdown', 'html')),
    source_channel      text NOT NULL CHECK (source_channel IN ('web', 'email', 'chat', 'api', 'social')),
    
    external_message_id text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    edited_at           timestamptz,
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, case_id) REFERENCES cases (org_id, id),
    FOREIGN KEY (org_id, author_contact_id) REFERENCES contacts (org_id, id),
    CHECK ((author_kind = 'user') = (author_user_id IS NOT NULL)),
    CHECK ((author_kind = 'contact') = (author_contact_id IS NOT NULL)),
    
    CHECK (NOT (author_kind = 'contact' AND visibility = 'internal'))
);

CREATE INDEX case_messages_case_idx ON case_messages (org_id, case_id, created_at);
CREATE UNIQUE INDEX case_messages_external_id_key ON case_messages (org_id, source_channel, external_message_id)
    WHERE external_message_id IS NOT NULL;


CREATE TABLE case_events (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL,
    case_id     uuid NOT NULL,
    kind        text NOT NULL,
    actor_kind  text NOT NULL CHECK (actor_kind IN ('user', 'contact', 'api_credential', 'system', 'workflow', 'plugin', 'ai')),
    actor_id    uuid,
    data        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, case_id) REFERENCES cases (org_id, id)
);

CREATE INDEX case_events_case_idx ON case_events (org_id, case_id, occurred_at);

CREATE TABLE attachments (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL,
    case_id      uuid NOT NULL,
    message_id   uuid,
    file_name    text NOT NULL,
    content_type text NOT NULL,
    size_bytes   bigint NOT NULL CHECK (size_bytes >= 0),
    sha256       bytea NOT NULL CHECK (length(sha256) = 32),
    
    storage_key  text NOT NULL UNIQUE CHECK (storage_key LIKE 'org/' || org_id::text || '/%'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, case_id) REFERENCES cases (org_id, id),
    FOREIGN KEY (org_id, message_id) REFERENCES case_messages (org_id, id)
);

CREATE INDEX attachments_case_idx ON attachments (org_id, case_id);

CREATE TABLE case_links (
    org_id         uuid NOT NULL,
    case_id        uuid NOT NULL,
    linked_case_id uuid NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('related', 'duplicate_of')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, linked_case_id, kind),
    CHECK (case_id <> linked_case_id),
    FOREIGN KEY (org_id, case_id) REFERENCES cases (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, linked_case_id) REFERENCES cases (org_id, id) ON DELETE CASCADE
);

CREATE INDEX case_links_linked_idx ON case_links (linked_case_id);
