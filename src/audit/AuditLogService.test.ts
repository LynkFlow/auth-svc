import type { Logger } from "pino";
import { AuditLogService } from "./AuditLogService.js";
import type { AuditLogRepository } from "./AuditLogRepository.js";

function mockLogger(): Logger {
  return { error: jest.fn() } as unknown as Logger;
}

function mockRepository(insert: jest.Mock): AuditLogRepository {
  return { insert } as unknown as AuditLogRepository;
}

describe("AuditLogService", () => {
  it("inserts the entry via the repository", async () => {
    const insert = jest.fn().mockResolvedValue(undefined);
    const logger = mockLogger();
    const service = new AuditLogService(mockRepository(insert), logger);
    const entry = { operation: "auth.login.succeeded", module: "auth" };

    await service.record(entry);

    expect(insert).toHaveBeenCalledWith(entry);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it("swallows a repository failure and logs it instead of throwing", async () => {
    const insertError = new Error("connection lost");
    const insert = jest.fn().mockRejectedValue(insertError);
    const logger = mockLogger();
    const service = new AuditLogService(mockRepository(insert), logger);
    const entry = { operation: "auth.login.succeeded", module: "auth" };

    await expect(service.record(entry)).resolves.toBeUndefined();
    expect(logger.error).toHaveBeenCalledWith(
      { err: insertError, entry },
      "failed to write audit log entry",
    );
  });
});
