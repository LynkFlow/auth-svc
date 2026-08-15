import { createTestDb } from "../test/testDb.js";
import { OutboxRepository } from "./OutboxRepository.js";

describe("OutboxRepository", () => {
  it("claimPendingEvents maps claimed rows to camelCase", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({
      command: "UPDATE",
      rowCount: 1,
      rows: [
        {
          id: "e1",
          event_type: "account.activated",
          aggregate_id: "u1",
          payload: { userId: "u1" },
          delivery_attempts: 1,
          idempotency_generation: 0,
        },
      ],
    });
    const repository = new OutboxRepository(db);

    await expect(repository.claimPendingEvents("worker-1", 10, 30)).resolves.toEqual([
      {
        id: "e1",
        eventType: "account.activated",
        aggregateId: "u1",
        payload: { userId: "u1" },
        deliveryAttempts: 1,
        idempotencyGeneration: 0,
      },
    ]);

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("FOR UPDATE SKIP LOCKED");
  });

  it("markPublished returns true when exactly one row was updated", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 1, rows: [] });
    const repository = new OutboxRepository(db);

    await expect(repository.markPublished("e1", "worker-1")).resolves.toBe(true);

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("payload - 'token'");
  });

  it("markPublished returns false when the lock no longer matches", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new OutboxRepository(db);

    await expect(repository.markPublished("e1", "worker-1")).resolves.toBe(false);
  });

  it("markDeliveryFailed truncates the error message to 2000 characters", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 1, rows: [] });
    const repository = new OutboxRepository(db);

    await repository.markDeliveryFailed({
      eventId: "e1",
      workerId: "worker-1",
      error: "x".repeat(3_000),
      nextAttemptAt: new Date(),
      permanentlyFailed: true,
      advanceIdempotencyGeneration: true,
    });

    const [, params] = query.mock.calls[0] as [string, unknown[]];
    expect((params[1] as string).length).toBe(2_000);
  });
});
