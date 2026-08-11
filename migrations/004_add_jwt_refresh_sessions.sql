ALTER TABLE auth_sessions
    ADD COLUMN refresh_generation INTEGER NOT NULL DEFAULT 0
        CHECK (refresh_generation >= 0),
    ADD COLUMN is_persistent BOOLEAN NOT NULL DEFAULT FALSE;

-- Existing cookies use the previous opaque-session format and cannot be
-- safely upgraded to rotating refresh tokens. Force a one-time re-login.
UPDATE auth_sessions
SET revoked_at = NOW()
WHERE revoked_at IS NULL;

CREATE TABLE auth_refresh_token_history (
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id, generation)
);

CREATE INDEX auth_refresh_token_history_expiry_idx
    ON auth_refresh_token_history(expires_at);
