-- Per business-domain.md's audit-trail requirement (user, timestamp,
-- operation, module, entity, previous/new value) plus auth-specific IP
-- address, browser, and device -- see backend-conventions.md's "Audit
-- trail" section. Each service owns its own audit_log table; this is
-- never shared across services (architecture.md).
CREATE TABLE audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id UUID,
    operation TEXT NOT NULL,
    module TEXT NOT NULL,
    entity TEXT,
    previous_value JSONB,
    new_value JSONB,
    ip_address TEXT,
    user_agent TEXT,
    request_id TEXT
);

CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at);
CREATE INDEX audit_log_user_id_idx ON audit_log (user_id);
