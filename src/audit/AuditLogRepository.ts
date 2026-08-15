import type { Db } from "../db/schema.js";
import type { AuditLogEntry } from "./AuditLogEntry.js";

export class AuditLogRepository {
  constructor(private readonly db: Db) {}

  async insert(entry: AuditLogEntry): Promise<void> {
    await this.db
      .insertInto("auditLog")
      .values({
        userId: entry.userId ?? null,
        operation: entry.operation,
        module: entry.module,
        entity: entry.entity ?? null,
        previousValue: entry.previousValue ?? null,
        newValue: entry.newValue ?? null,
        ipAddress: entry.ipAddress ?? null,
        userAgent: entry.userAgent ?? null,
        requestId: entry.requestId ?? null,
      })
      .execute();
  }
}
