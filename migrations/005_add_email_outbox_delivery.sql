ALTER TABLE auth_outbox_events
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN locked_at TIMESTAMPTZ,
    ADD COLUMN locked_by VARCHAR(128),
    ADD COLUMN failed_at TIMESTAMPTZ,
    ADD COLUMN idempotency_generation INTEGER NOT NULL DEFAULT 0
        CHECK (idempotency_generation >= 0),
    ADD CONSTRAINT auth_outbox_events_lock_pair_check CHECK (
        (locked_at IS NULL) = (locked_by IS NULL)
    );

DROP INDEX auth_outbox_events_unpublished_idx;

CREATE INDEX auth_outbox_events_delivery_idx
    ON auth_outbox_events(next_attempt_at, created_at, id)
    WHERE published_at IS NULL AND failed_at IS NULL;

CREATE INDEX auth_outbox_events_stale_lock_idx
    ON auth_outbox_events(locked_at)
    WHERE published_at IS NULL
      AND failed_at IS NULL
      AND locked_at IS NOT NULL;
