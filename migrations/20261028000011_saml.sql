ALTER TABLE sso_connections
    ADD COLUMN protocol text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'saml')),
    ADD COLUMN idp_metadata_xml text,
    ALTER COLUMN issuer_url DROP NOT NULL,
    ALTER COLUMN client_id DROP NOT NULL,
    ALTER COLUMN client_secret_ciphertext DROP NOT NULL,
    ADD CONSTRAINT sso_connections_protocol_fields CHECK (
        (protocol = 'oidc' AND issuer_url IS NOT NULL AND client_id IS NOT NULL
            AND client_secret_ciphertext IS NOT NULL AND idp_metadata_xml IS NULL)
        OR (protocol = 'saml' AND idp_metadata_xml IS NOT NULL AND issuer_url IS NULL
            AND client_id IS NULL AND client_secret_ciphertext IS NULL)
    );

CREATE TABLE saml_requests (
    id                text PRIMARY KEY,
    sso_connection_id uuid NOT NULL REFERENCES sso_connections (id) ON DELETE CASCADE,
    link_user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    redirect_to       text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL
);

CREATE INDEX saml_requests_expires_idx ON saml_requests (expires_at);

CREATE TABLE saml_assertions_used (
    sso_connection_id uuid NOT NULL REFERENCES sso_connections (id) ON DELETE CASCADE,
    assertion_id      text NOT NULL,
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (sso_connection_id, assertion_id)
);

CREATE INDEX saml_assertions_used_expires_idx ON saml_assertions_used (expires_at);
