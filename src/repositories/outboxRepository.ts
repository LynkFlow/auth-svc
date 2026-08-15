import type { PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool.js";

export interface OutboxEvent {
  id: string;
  eventType: string;
  aggregateId: string;
  payload: unknown;
  deliveryAttempts: number;
  idempotencyGeneration: number;
}

interface OutboxEventRow extends OutboxEvent, QueryResultRow {}

export async function enqueueEvent(
  client: PoolClient,
  eventType: string,
  aggregateId: string,
  payload: Record<string, unknown>,
): Promise<void> {
  await client.query(
    `
            INSERT INTO auth_outbox_events (
                event_type,
                aggregate_id,
                payload
            ) VALUES ($1, $2, $3::jsonb)
        `,
    [eventType, aggregateId, JSON.stringify(payload)],
  );
}

export async function claimPendingEvents(
  workerId: string,
  batchSize: number,
  lockTimeoutSeconds: number,
): Promise<OutboxEvent[]> {
  const { rows } = await pool.query<OutboxEventRow>(
    `
            WITH candidates AS (
                SELECT id
                FROM auth_outbox_events
                WHERE published_at IS NULL
                  AND failed_at IS NULL
                  AND next_attempt_at <= NOW()
                  AND (
                      locked_at IS NULL
                      OR locked_at < NOW() - make_interval(secs => $3)
                  )
                ORDER BY next_attempt_at, created_at, id
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            UPDATE auth_outbox_events AS outbox
            SET
                locked_at = NOW(),
                locked_by = $1,
                delivery_attempts = outbox.delivery_attempts + 1
            FROM candidates
            WHERE outbox.id = candidates.id
            RETURNING
                outbox.id,
                outbox.event_type AS "eventType",
                outbox.aggregate_id AS "aggregateId",
                outbox.payload,
                outbox.delivery_attempts AS "deliveryAttempts",
                outbox.idempotency_generation AS "idempotencyGeneration"
        `,
    [workerId, batchSize, lockTimeoutSeconds],
  );

  return rows;
}

export async function markPublished(
  eventId: string,
  workerId: string,
): Promise<boolean> {
  const result = await pool.query(
    `
            UPDATE auth_outbox_events
            SET
                published_at = NOW(),
                payload = payload - 'token',
                locked_at = NULL,
                locked_by = NULL,
                last_error = NULL
            WHERE id = $1
              AND locked_by = $2
              AND published_at IS NULL
              AND failed_at IS NULL
        `,
    [eventId, workerId],
  );

  return result.rowCount === 1;
}

export interface DeliveryFailure {
  eventId: string;
  workerId: string;
  error: string;
  nextAttemptAt: Date;
  permanentlyFailed: boolean;
  advanceIdempotencyGeneration: boolean;
}

export async function markDeliveryFailed({
  eventId,
  workerId,
  error,
  nextAttemptAt,
  permanentlyFailed,
  advanceIdempotencyGeneration,
}: DeliveryFailure): Promise<boolean> {
  const result = await pool.query(
    `
            UPDATE auth_outbox_events
            SET
                next_attempt_at = $3,
                locked_at = NULL,
                locked_by = NULL,
                last_error = $4,
                failed_at = CASE WHEN $5 THEN NOW() ELSE NULL END,
                idempotency_generation = idempotency_generation +
                    CASE WHEN $6 THEN 1 ELSE 0 END,
                payload = CASE
                    WHEN $5 THEN payload - 'token'
                    ELSE payload
                END
            WHERE id = $1
              AND locked_by = $2
              AND published_at IS NULL
              AND failed_at IS NULL
        `,
    [
      eventId,
      workerId,
      nextAttemptAt,
      error.slice(0, 2_000),
      permanentlyFailed,
      advanceIdempotencyGeneration,
    ],
  );

  return result.rowCount === 1;
}
