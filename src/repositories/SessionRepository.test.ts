import { createTestDb } from "../test/testDb.js";
import { SessionRepository } from "./SessionRepository.js";

describe("SessionRepository", () => {
  it("revokeUserSessions omits the exception clause when no session is excepted", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 3, rows: [] });
    const repository = new SessionRepository(db);

    await expect(repository.revokeUserSessions(db, "u1")).resolves.toBe(3);

    const [sql, params] = query.mock.calls[0] as [string, unknown[]];
    expect(sql).not.toContain("<>");
    expect(params).toEqual(["u1"]);
  });

  it("revokeUserSessions adds the exception clause when a session is excepted", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 1, rows: [] });
    const repository = new SessionRepository(db);

    await expect(repository.revokeUserSessions(db, "u1", "s1")).resolves.toBe(1);

    const [sql, params] = query.mock.calls[0] as [string, unknown[]];
    expect(sql).toContain("<>");
    expect(params).toEqual(["u1", "s1"]);
  });

  it("revokeSession returns false when no active session matched", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new SessionRepository(db);

    await expect(repository.revokeSession("s1", db)).resolves.toBe(false);
  });

  it("wasRefreshTokenUsed returns true when a matching history row exists", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({
      command: "SELECT",
      rowCount: 1,
      rows: [{ session_id: "s1" }],
    });
    const repository = new SessionRepository(db);

    await expect(
      repository.wasRefreshTokenUsed(db, "s1", Buffer.from("hash")),
    ).resolves.toBe(true);
  });

  it("wasRefreshTokenUsed returns false when no history row matches", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new SessionRepository(db);

    await expect(
      repository.wasRefreshTokenUsed(db, "s1", Buffer.from("hash")),
    ).resolves.toBe(false);
  });

  it("rotateRefreshToken returns false when the generation no longer matches", async () => {
    const { db, query } = createTestDb();
    query
      .mockResolvedValueOnce({ command: "INSERT", rowCount: 1, rows: [] })
      .mockResolvedValueOnce({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new SessionRepository(db);

    await expect(
      repository.rotateRefreshToken(db, "s1", 0, Buffer.from("next-hash")),
    ).resolves.toBe(false);

    expect(query).toHaveBeenCalledTimes(2);
  });
});
