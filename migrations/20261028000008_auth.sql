




CREATE TABLE login_throttles (
    email_key    text PRIMARY KEY CHECK (email_key = lower(email_key)),
    failures     integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);




CREATE TABLE auth_tokens (
    token_hash  bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    purpose     text NOT NULL CHECK (purpose IN ('email_verification', 'password_reset', 'mfa_challenge')),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    
    email       text,
    
    data        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object'),
    attempts    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

CREATE INDEX auth_tokens_user_idx ON auth_tokens (user_id, purpose);
CREATE INDEX auth_tokens_expires_idx ON auth_tokens (expires_at);

ALTER TABLE users ADD COLUMN password_changed_at timestamptz;


ALTER TABLE organizations
    ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;



CREATE TABLE sso_connections (
    id                       uuid PRIMARY KEY,
    org_id                   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name                     text NOT NULL CHECK (length(trim(name)) > 0),
    issuer_url               text NOT NULL,
    client_id                text NOT NULL,
    
    client_secret_ciphertext bytea NOT NULL,
    
    
    email_domains            text[] NOT NULL DEFAULT '{}',
    enabled                  boolean NOT NULL DEFAULT true,
    
    enforced                 boolean NOT NULL DEFAULT false,
    
    jit_provisioning         boolean NOT NULL DEFAULT false,
    default_role_id          uuid,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, default_role_id) REFERENCES roles (org_id, id) ON DELETE SET NULL (default_role_id)
);

CREATE UNIQUE INDEX sso_connections_name_key ON sso_connections (org_id, lower(name));

CREATE TRIGGER sso_connections_updated_at BEFORE UPDATE ON sso_connections
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE auth_identities
    ADD COLUMN email text,
    ADD COLUMN sso_connection_id uuid REFERENCES sso_connections (id) ON DELETE CASCADE;


ALTER TABLE sessions
    ADD COLUMN auth_method text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'sso', 'social')),
    ADD COLUMN sso_connection_id uuid REFERENCES sso_connections (id) ON DELETE CASCADE,
    ADD CONSTRAINT sessions_sso_check CHECK ((auth_method = 'sso') = (sso_connection_id IS NOT NULL));

CREATE INDEX sessions_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;


CREATE TABLE oidc_login_states (
    state             text PRIMARY KEY,
    nonce             text NOT NULL,
    pkce_verifier     text NOT NULL,
    
    sso_connection_id uuid REFERENCES sso_connections (id) ON DELETE CASCADE,
    social_provider   text,
    
    link_user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    redirect_to       text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    CHECK ((sso_connection_id IS NULL) <> (social_provider IS NULL))
);

CREATE INDEX oidc_login_states_expires_idx ON oidc_login_states (expires_at);


ALTER TABLE mfa_factors ADD COLUMN last_used_step bigint;

CREATE TABLE mfa_recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL CHECK (length(code_hash) = 32),
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, code_hash)
);
