ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL,
    ADD COLUMN full_name VARCHAR(200),
    ADD COLUMN organization_name VARCHAR(200),
    ADD COLUMN terms_accepted_at TIMESTAMPTZ,
    ADD COLUMN terms_version VARCHAR(32),
    ADD COLUMN privacy_policy_accepted_at TIMESTAMPTZ,
    ADD COLUMN privacy_policy_version VARCHAR(32),
    ADD CONSTRAINT users_non_pending_password_check
        CHECK (account_status = 'pending_activation' OR password_hash IS NOT NULL);

ALTER TABLE auth_settings
    ADD COLUMN activation_token_validity_hours INTEGER NOT NULL DEFAULT 24
        CHECK (activation_token_validity_hours BETWEEN 1 AND 720),
    ADD COLUMN password_min_length INTEGER NOT NULL DEFAULT 12
        CHECK (password_min_length BETWEEN 8 AND 128),
    ADD COLUMN password_max_length INTEGER NOT NULL DEFAULT 128
        CHECK (password_max_length BETWEEN 8 AND 256),
    ADD COLUMN password_require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN password_require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN password_require_number BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN password_require_symbol BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN current_terms_version VARCHAR(32) NOT NULL DEFAULT '1.0',
    ADD COLUMN current_privacy_policy_version VARCHAR(32) NOT NULL DEFAULT '1.0',
    ADD CONSTRAINT auth_settings_password_length_check
        CHECK (password_max_length >= password_min_length);

CREATE TABLE account_activation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX account_activation_tokens_user_id_idx
    ON account_activation_tokens(user_id);

CREATE INDEX account_activation_tokens_active_expiry_idx
    ON account_activation_tokens(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE auth_outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(128) NOT NULL,
    aggregate_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    delivery_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (delivery_attempts >= 0),
    last_error TEXT
);

CREATE INDEX auth_outbox_events_unpublished_idx
    ON auth_outbox_events(created_at)
    WHERE published_at IS NULL;
