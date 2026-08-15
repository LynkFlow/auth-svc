import { createTestDb } from "../test/testDb.js";
import { PasswordResetRepository } from "./PasswordResetRepository.js";

describe("PasswordResetRepository", () => {
  it("adds the locking clause when lock=true", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new PasswordResetRepository(db);

    await repository.findByTokenHash(Buffer.from("hash"), db, true);

    const [sql] = query.mock.calls[0] as [string];
    expect(sql).toContain("FOR UPDATE OF reset, users");
  });

  it("useTokenAndRevokeOthers throws when the token could not be consumed", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "UPDATE", rowCount: 0, rows: [] });
    const repository = new PasswordResetRepository(db);

    await expect(
      repository.useTokenAndRevokeOthers(db, "r1", "u1"),
    ).rejects.toThrow("The password reset token could not be consumed.");
  });

  it("createToken returns the new token's id", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "INSERT", rowCount: 1, rows: [{ id: "r1" }] });
    const repository = new PasswordResetRepository(db);

    await expect(
      repository.createToken(db, "u1", Buffer.from("hash"), new Date()),
    ).resolves.toBe("r1");
  });
});
