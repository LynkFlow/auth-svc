import { createTestDb } from "../test/testDb.js";
import { HealthRepository } from "./HealthRepository.js";

describe("HealthRepository", () => {
  it("returns true when the query reports reachable = 1", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 1, rows: [{ reachable: 1 }] });
    const repository = new HealthRepository(db);

    await expect(repository.databaseIsReachable()).resolves.toBe(true);
  });

  it("returns false when the query reports a different value", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 1, rows: [{ reachable: 0 }] });
    const repository = new HealthRepository(db);

    await expect(repository.databaseIsReachable()).resolves.toBe(false);
  });

  it("returns false when the query returns no rows", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new HealthRepository(db);

    await expect(repository.databaseIsReachable()).resolves.toBe(false);
  });
});
