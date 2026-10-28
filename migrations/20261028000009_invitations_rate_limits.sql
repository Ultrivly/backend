

CREATE TABLE invitations (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email        text NOT NULL,
    role_id      uuid NOT NULL,
    
    workspace_id uuid,
    
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    invited_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    accepted_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    revoked_at   timestamptz,
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, role_id) REFERENCES roles (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id) ON DELETE CASCADE
);


CREATE UNIQUE INDEX invitations_open_key ON invitations (org_id, lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;



CREATE TABLE rate_limits (
    key          text NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);

CREATE INDEX rate_limits_window_idx ON rate_limits (window_start);
