import { createTestDb } from "../test/testDb.js";
import { AuditLogRepository } from "./AuditLogRepository.js";

describe("AuditLogRepository", () => {
  it("inserts an entry with optional fields defaulted to null", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "INSERT", rowCount: 1, rows: [] });
    const repository = new AuditLogRepository(db);

    await repository.insert({ operation: "auth.login.succeeded", module: "auth" });

    const [sql, params] = query.mock.calls[0] as [string, unknown[]];
    expect(sql).toContain("insert into \"audit_log\"");
    expect(params).toEqual([
      null,
      "auth.login.succeeded",
      "auth",
      null,
      null,
      null,
      null,
      null,
      null,
    ]);
  });
});
