export interface AuditLogEntry {
  userId?: string;
  operation: string;
  module: string;
  entity?: string;
  previousValue?: unknown;
  newValue?: unknown;
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
}
