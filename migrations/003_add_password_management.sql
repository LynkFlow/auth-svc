ALTER TABLE auth_settings
    ADD COLUMN password_reset_token_validity_minutes INTEGER NOT NULL DEFAULT 30
        CHECK (password_reset_token_validity_minutes BETWEEN 5 AND 1440),
    ADD COLUMN terminate_sessions_on_password_reset BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN terminate_other_sessions_on_password_change BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (used_at IS NULL OR used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (used_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX password_reset_tokens_user_id_idx
    ON password_reset_tokens(user_id);

CREATE INDEX password_reset_tokens_active_expiry_idx
    ON password_reset_tokens(expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;
