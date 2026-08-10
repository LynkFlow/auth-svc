import type { PoolClient } from "pg";

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
