




CREATE TABLE users (
    id                uuid PRIMARY KEY,
    email             text NOT NULL CHECK (position('@' IN email) > 1),
    email_verified_at timestamptz,
    display_name      text NOT NULL,
    
    password_hash     text,
    disabled_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_key ON users (lower(email));

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


CREATE TABLE auth_identities (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    
    issuer      text NOT NULL,
    subject     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE (issuer, subject)
);

CREATE INDEX auth_identities_user_id_idx ON auth_identities (user_id);

CREATE TABLE mfa_factors (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind              text NOT NULL CHECK (kind IN ('totp', 'webauthn')),
    label             text NOT NULL,
    
    secret_ciphertext bytea NOT NULL,
    confirmed_at      timestamptz,
    last_used_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX mfa_factors_user_id_idx ON mfa_factors (user_id);

CREATE TABLE sessions (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    
    token_hash      bytea NOT NULL UNIQUE,
    mfa_verified_at timestamptz,
    ip_address      inet,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE memberships (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id),
    user_id     uuid NOT NULL REFERENCES users (id),
    status      text NOT NULL CHECK (status IN ('invited', 'active', 'suspended')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    
    UNIQUE (org_id, user_id)
);

CREATE INDEX memberships_user_id_idx ON memberships (user_id);

CREATE TRIGGER memberships_updated_at BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();



CREATE TABLE roles (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id),
    key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    name        text NOT NULL,
    is_builtin  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, key)
);

CREATE TRIGGER roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


CREATE TABLE role_permissions (
    org_id      uuid NOT NULL,
    role_id     uuid NOT NULL,
    permission  text NOT NULL CHECK (permission ~ '^[a-z_]+\.[a-z_]+$'),
    PRIMARY KEY (role_id, permission),
    FOREIGN KEY (org_id, role_id) REFERENCES roles (org_id, id) ON DELETE CASCADE
);


CREATE TABLE membership_roles (
    org_id        uuid NOT NULL,
    membership_id uuid NOT NULL,
    role_id       uuid NOT NULL,
    workspace_id  uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (membership_id, role_id, workspace_id),
    FOREIGN KEY (org_id, membership_id) REFERENCES memberships (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, role_id) REFERENCES roles (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id) ON DELETE CASCADE
);

CREATE INDEX membership_roles_role_id_idx ON membership_roles (role_id);
