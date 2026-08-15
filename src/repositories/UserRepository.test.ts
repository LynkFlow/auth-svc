import { createTestDb } from "../test/testDb.js";
import { UserRepository } from "./UserRepository.js";

describe("UserRepository", () => {
  it("maps a found row into a UserRecord", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({
      command: "SELECT",
      rowCount: 1,
      rows: [
        {
          id: "u1",
          email: "a@b.com",
          password_hash: "hash",
          account_status: "active",
          failed_login_attempts: 0,
          locked_until: null,
          activated_at: null,
          last_login_at: null,
          role_code: "broker_agent",
          role_name: "Broker Agent",
          permissions: ["leads.view"],
        },
      ],
    });
    const repository = new UserRepository(db);

    await expect(repository.findByEmail("a@b.com")).resolves.toEqual({
      id: "u1",
      email: "a@b.com",
      passwordHash: "hash",
      accountStatus: "active",
      failedLoginAttempts: 0,
      lockedUntil: null,
      activatedAt: null,
      lastLoginAt: null,
      roleCode: "broker_agent",
      roleName: "Broker Agent",
      permissions: ["leads.view"],
    });

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("WHERE u.email = $1");
  });

  it("returns null when no user matches", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new UserRepository(db);

    await expect(repository.findByEmail("missing@b.com")).resolves.toBeNull();
  });

  it("findByIdForUpdate locks the row it selects", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new UserRepository(db);

    await repository.findByIdForUpdate(db, "u1");

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("FOR UPDATE OF u");
  });

  it("recordFailedLogin returns the updated attempt count and lock", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({
      command: "UPDATE",
      rowCount: 1,
      rows: [{ failed_login_attempts: 5, locked_until: null }],
    });
    const repository = new UserRepository(db);

    await expect(repository.recordFailedLogin("u1", 5, 15)).resolves.toEqual({
      failedLoginAttempts: 5,
      lockedUntil: null,
    });

    const [sql, params] = query.mock.calls[0] as [string, unknown[]];
    expect(sql).toContain("make_interval(mins =>");
    expect(params).toContain(5);
    expect(params).toContain(15);
  });

  it("updatePassword returns false when no active user matched", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new UserRepository(db);

    await expect(repository.updatePassword(db, "u1", "newHash")).resolves.toBe(false);
  });
});
