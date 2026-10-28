



ALTER TABLE mfa_factors ADD COLUMN credential_id bytea;
CREATE UNIQUE INDEX mfa_factors_credential_key ON mfa_factors (credential_id) WHERE credential_id IS NOT NULL;



CREATE TABLE webauthn_ceremonies (
    id               uuid PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose          text NOT NULL CHECK (purpose IN ('registration', 'authentication')),
    label            text,
    state_ciphertext bytea NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL
);

CREATE INDEX webauthn_ceremonies_expires_idx ON webauthn_ceremonies (expires_at);
