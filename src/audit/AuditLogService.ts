import type { Logger } from "pino";
import type { AuditLogEntry } from "./AuditLogEntry.js";
import type { AuditLogRepository } from "./AuditLogRepository.js";

/**
 * Never throws. A failed audit write is worth alerting on (hence the
 * error-level log), but it must never take down the business operation
 * that triggered it -- e.g. a login should not fail because the audit
 * insert did.
 */
export class AuditLogService {
  constructor(
    private readonly auditLogRepository: AuditLogRepository,
    private readonly logger: Logger,
  ) {}

  async record(entry: AuditLogEntry): Promise<void> {
    try {
      await this.auditLogRepository.insert(entry);
    } catch (error) {
      this.logger.error({ err: error, entry }, "failed to write audit log entry");
    }
  }
}
