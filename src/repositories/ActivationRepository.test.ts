import { createTestDb } from "../test/testDb.js";
import { ActivationRepository } from "./ActivationRepository.js";

describe("ActivationRepository", () => {
  it("omits the locking clause by default", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new ActivationRepository(db);

    await repository.findByTokenHash(Buffer.from("hash"));

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).not.toContain("FOR UPDATE");
  });

  it("adds the locking clause when lock=true", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new ActivationRepository(db);

    await repository.findByTokenHash(Buffer.from("hash"), db, true);

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("FOR UPDATE OF activation, users");
  });

  it("maps a found activation row to camelCase", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({
      command: "SELECT",
      rowCount: 1,
      rows: [
        {
          id: "a1",
          user_id: "u1",
          email: "a@b.com",
          full_name: "A B",
          organization_name: "Acme",
          account_status: "pending_activation",
          has_password: false,
          expires_at: new Date("2026-01-01T00:00:00Z"),
          consumed_at: null,
          revoked_at: null,
        },
      ],
    });
    const repository = new ActivationRepository(db);

    await expect(repository.findByTokenHash(Buffer.from("hash"))).resolves.toEqual({
      id: "a1",
      userId: "u1",
      email: "a@b.com",
      fullName: "A B",
      organizationName: "Acme",
      accountStatus: "pending_activation",
      hasPassword: false,
      expiresAt: new Date("2026-01-01T00:00:00Z"),
      consumedAt: null,
      revokedAt: null,
    });
  });

  it("consumeTokenAndRevokeOthers throws when the token could not be consumed", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new ActivationRepository(db);

    await expect(
      repository.consumeTokenAndRevokeOthers(db, "a1", "u1"),
    ).rejects.toThrow("The activation token could not be consumed.");
  });
});
