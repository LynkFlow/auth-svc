import { sql } from "kysely";
import type { Db } from "../db/schema.js";

export interface OutboxEvent {
  id: string;
  eventType: string;
  aggregateId: string;
  payload: unknown;
  deliveryAttempts: number;
  idempotencyGeneration: number;
}

export interface DeliveryFailure {
  eventId: string;
  workerId: string;
  error: string;
  nextAttemptAt: Date;
  permanentlyFailed: boolean;
  advanceIdempotencyGeneration: boolean;
}

export class OutboxRepository {
  constructor(private readonly db: Db) {}

  async enqueueEvent(
    db: Db,
    eventType: string,
    aggregateId: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await db
      .insertInto("authOutboxEvents")
      .values({
        eventType,
        aggregateId,
        payload: sql`${JSON.stringify(payload)}::jsonb`,
      })
      .execute();
  }

  /**
   * Runs outside any caller-managed transaction -- claiming is itself the
   * unit of work (the worker commits its own claim before it starts
   * delivering). The `FOR UPDATE SKIP LOCKED` candidate CTE, so multiple
   * worker processes can claim disjoint batches concurrently without
   * blocking each other, doesn't map onto the query builder -- kept as a
   * raw statement, see backend-conventions.md's Kysely section.
   */
  async claimPendingEvents(
    workerId: string,
    batchSize: number,
    lockTimeoutSeconds: number,
  ): Promise<OutboxEvent[]> {
    const result = await sql<OutboxEvent>`
      WITH candidates AS (
          SELECT id
          FROM auth_outbox_events
          WHERE published_at IS NULL
            AND failed_at IS NULL
            AND next_attempt_at <= NOW()
            AND (
                locked_at IS NULL
                OR locked_at < NOW() - make_interval(secs => ${lockTimeoutSeconds})
            )
          ORDER BY next_attempt_at, created_at, id
          LIMIT ${batchSize}
          FOR UPDATE SKIP LOCKED
      )
      UPDATE auth_outbox_events AS outbox
      SET
          locked_at = NOW(),
          locked_by = ${workerId},
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
    `.execute(this.db);

    return result.rows;
  }

  /**
   * The `payload - 'token'` JSONB key-deletion operator has no query
   * builder equivalent -- kept as a raw statement, see
   * backend-conventions.md's Kysely section.
   */
  async markPublished(eventId: string, workerId: string): Promise<boolean> {
    const result = await sql`
      UPDATE auth_outbox_events
      SET
          published_at = NOW(),
          payload = payload - 'token',
          locked_at = NULL,
          locked_by = NULL,
          last_error = NULL
      WHERE id = ${eventId}
        AND locked_by = ${workerId}
        AND published_at IS NULL
        AND failed_at IS NULL
    `.execute(this.db);

    return result.numAffectedRows === 1n;
  }

  /**
   * Same JSONB-operator escape hatch as markPublished, plus a dynamic
   * CASE per field (only advance idempotency_generation / set failed_at /
   * strip the token when this attempt is the terminal one) -- kept as a
   * raw statement, see backend-conventions.md's Kysely section.
   */
  async markDeliveryFailed({
    eventId,
    workerId,
    error,
    nextAttemptAt,
    permanentlyFailed,
    advanceIdempotencyGeneration,
  }: DeliveryFailure): Promise<boolean> {
    const result = await sql`
      UPDATE auth_outbox_events
      SET
          next_attempt_at = ${nextAttemptAt},
          locked_at = NULL,
          locked_by = NULL,
          last_error = ${error.slice(0, 2_000)},
          failed_at = CASE WHEN ${permanentlyFailed} THEN NOW() ELSE NULL END,
          idempotency_generation = idempotency_generation +
              CASE WHEN ${advanceIdempotencyGeneration} THEN 1 ELSE 0 END,
          payload = CASE
              WHEN ${permanentlyFailed} THEN payload - 'token'
              ELSE payload
          END
      WHERE id = ${eventId}
        AND locked_by = ${workerId}
        AND published_at IS NULL
        AND failed_at IS NULL
    `.execute(this.db);

    return result.numAffectedRows === 1n;
  }
}
