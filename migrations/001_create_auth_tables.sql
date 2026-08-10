CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE roles (
    id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE role_permissions (
    role_id SMALLINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role_id SMALLINT NOT NULL REFERENCES roles(id),
    account_status VARCHAR(32) NOT NULL DEFAULT 'pending_activation'
        CHECK (account_status IN ('pending_activation', 'active', 'inactive', 'suspended')),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX users_account_status_idx ON users(account_status);
CREATE INDEX users_locked_until_idx ON users(locked_until) WHERE locked_until IS NOT NULL;

CREATE TABLE auth_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    session_idle_timeout_minutes INTEGER NOT NULL DEFAULT 30
        CHECK (session_idle_timeout_minutes BETWEEN 1 AND 1440),
    session_absolute_timeout_minutes INTEGER NOT NULL DEFAULT 480
        CHECK (session_absolute_timeout_minutes BETWEEN 5 AND 10080),
    remember_me_absolute_timeout_days INTEGER NOT NULL DEFAULT 30
        CHECK (remember_me_absolute_timeout_days BETWEEN 1 AND 365),
    lockout_threshold INTEGER NOT NULL DEFAULT 5
        CHECK (lockout_threshold BETWEEN 3 AND 20),
    lockout_duration_minutes INTEGER NOT NULL DEFAULT 15
        CHECK (lockout_duration_minutes BETWEEN 1 AND 1440),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO auth_settings (singleton) VALUES (TRUE);

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent VARCHAR(512),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (idle_expires_at <= expires_at)
);

CREATE INDEX auth_sessions_user_id_idx ON auth_sessions(user_id);
CREATE INDEX auth_sessions_active_expiry_idx
    ON auth_sessions(expires_at)
    WHERE revoked_at IS NULL;

INSERT INTO roles (code, name) VALUES
    ('platform_administrator', 'Platform Administrator'),
    ('developer_administrator', 'Developer Administrator'),
    ('internal_user', 'Internal User'),
    ('brokerage_administrator', 'Brokerage Administrator'),
    ('broker_agent', 'Broker Agent'),
    ('network_partner_administrator', 'Network Partner Administrator');
