import type { Generated, Kysely, Transaction } from "kysely";
import type { AccountStatus } from "../models/userModel.js";

// Camel-cased on purpose, even though the real Postgres columns are
// snake_case -- paired with CamelCasePlugin in container.ts, see
// backend-conventions.md's "SQL query layer: Kysely" section. Kept in sync
// by hand with migrations/*.sql.

export interface RolesTable {
  id: Generated<number>;
  code: string;
  name: string;
  createdAt: Generated<Date>;
}

export interface PermissionsTable {
  id: Generated<number>;
  code: string;
  description: string | null;
  createdAt: Generated<Date>;
}

export interface RolePermissionsTable {
  roleId: number;
  permissionId: number;
}

export interface UsersTable {
  id: Generated<string>;
  email: string;
  passwordHash: string | null;
  roleId: number;
  accountStatus: Generated<AccountStatus>;
  failedLoginAttempts: Generated<number>;
  lockedUntil: Date | null;
  activatedAt: Date | null;
  lastLoginAt: Date | null;
  createdAt: Generated<Date>;
  updatedAt: Generated<Date>;
  fullName: string | null;
  organizationName: string | null;
  termsAcceptedAt: Date | null;
  termsVersion: string | null;
  privacyPolicyAcceptedAt: Date | null;
  privacyPolicyVersion: string | null;
}

export interface AuthSettingsTable {
  singleton: Generated<boolean>;
  sessionIdleTimeoutMinutes: Generated<number>;
  sessionAbsoluteTimeoutMinutes: Generated<number>;
  rememberMeAbsoluteTimeoutDays: Generated<number>;
  lockoutThreshold: Generated<number>;
  lockoutDurationMinutes: Generated<number>;
  updatedAt: Generated<Date>;
  activationTokenValidityHours: Generated<number>;
  passwordMinLength: Generated<number>;
  passwordMaxLength: Generated<number>;
  passwordRequireUppercase: Generated<boolean>;
  passwordRequireLowercase: Generated<boolean>;
  passwordRequireNumber: Generated<boolean>;
  passwordRequireSymbol: Generated<boolean>;
  currentTermsVersion: Generated<string>;
  currentPrivacyPolicyVersion: Generated<string>;
  passwordResetTokenValidityMinutes: Generated<number>;
  terminateSessionsOnPasswordReset: Generated<boolean>;
  terminateOtherSessionsOnPasswordChange: Generated<boolean>;
}

export interface AuthSessionsTable {
  id: Generated<string>;
  userId: string;
  tokenHash: Buffer;
  expiresAt: Date;
  idleExpiresAt: Date;
  lastSeenAt: Generated<Date>;
  ipAddress: string | null;
  userAgent: string | null;
  revokedAt: Date | null;
  createdAt: Generated<Date>;
  refreshGeneration: Generated<number>;
  isPersistent: Generated<boolean>;
}

export interface AuthRefreshTokenHistoryTable {
  sessionId: string;
  generation: number;
  tokenHash: Buffer;
  usedAt: Generated<Date>;
  expiresAt: Date;
}

export interface AccountActivationTokensTable {
  id: Generated<string>;
  userId: string;
  tokenHash: Buffer;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
  createdAt: Generated<Date>;
}

export interface PasswordResetTokensTable {
  id: Generated<string>;
  userId: string;
  tokenHash: Buffer;
  expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
  createdAt: Generated<Date>;
}

export interface AuthOutboxEventsTable {
  id: Generated<string>;
  eventType: string;
  aggregateId: string;
  payload: unknown;
  createdAt: Generated<Date>;
  publishedAt: Date | null;
  deliveryAttempts: Generated<number>;
  lastError: string | null;
  nextAttemptAt: Generated<Date>;
  lockedAt: Date | null;
  lockedBy: string | null;
  failedAt: Date | null;
  idempotencyGeneration: Generated<number>;
}

export interface AuditLogTable {
  id: Generated<number>;
  occurredAt: Generated<Date>;
  userId: string | null;
  operation: string;
  module: string;
  entity: string | null;
  previousValue: unknown;
  newValue: unknown;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
}

export interface Database {
  roles: RolesTable;
  permissions: PermissionsTable;
  rolePermissions: RolePermissionsTable;
  users: UsersTable;
  authSettings: AuthSettingsTable;
  authSessions: AuthSessionsTable;
  authRefreshTokenHistory: AuthRefreshTokenHistoryTable;
  accountActivationTokens: AccountActivationTokensTable;
  passwordResetTokens: PasswordResetTokensTable;
  authOutboxEvents: AuthOutboxEventsTable;
  auditLog: AuditLogTable;
}

/** A repository method that may run inside an existing transaction accepts this instead of a bare `Kysely<Database>`. */
export type Db = Kysely<Database> | Transaction<Database>;
