import { sql } from "kysely";
import type { Db } from "../db/schema.js";
import type { UserRecord } from "../models/userModel.js";

export interface LoginFailure {
  failedLoginAttempts: number;
  lockedUntil: Date | null;
}

interface LoginSuccessRow {
  lastLoginAt: Date;
}

interface UpdatedPasswordRow {
  id: string;
}

interface CreatedUserRow {
  id: string;
  email: string;
}

export interface PendingRegistration {
  email: string;
  passwordHash: string;
  roleCode: string;
  fullName: string;
  organizationName: string;
}

export interface CreatedUser {
  id: string;
  email: string;
}

// Joins + the permissions ARRAY() subquery don't map cleanly onto Kysely's
// typed builder, so every method below composes this shared fragment into a
// full `sql` tagged statement rather than reaching for .selectFrom() --
// see backend-conventions.md's "SQL query layer: Kysely" escape hatch.
const USER_SELECT = `
    SELECT
        u.id,
        u.email::text AS email,
        u.password_hash AS "passwordHash",
        u.account_status AS "accountStatus",
        u.failed_login_attempts AS "failedLoginAttempts",
        u.locked_until AS "lockedUntil",
        u.activated_at AS "activatedAt",
        u.last_login_at AS "lastLoginAt",
        r.code AS "roleCode",
        r.name AS "roleName",
        ARRAY(
            SELECT p.code
            FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = r.id
            ORDER BY p.code
        ) AS permissions
    FROM users u
    JOIN roles r ON r.id = u.role_id
`;

export class UserRepository {
  constructor(private readonly db: Db) {}

  async findByEmail(email: string, db: Db = this.db): Promise<UserRecord | null> {
    const result = await sql<UserRecord>`
      ${sql.raw(USER_SELECT)} WHERE u.email = ${email}
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async findByIdForUpdate(db: Db, userId: string): Promise<UserRecord | null> {
    const result = await sql<UserRecord>`
      ${sql.raw(USER_SELECT)} WHERE u.id = ${userId} FOR UPDATE OF u
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async createPendingRegistration(
    db: Db,
    registration: PendingRegistration,
  ): Promise<CreatedUser | null> {
    const result = await sql<CreatedUserRow>`
      INSERT INTO users (
          email,
          password_hash,
          role_id,
          account_status,
          full_name,
          organization_name
      )
      SELECT
          ${registration.email},
          ${registration.passwordHash},
          roles.id,
          'pending_activation',
          ${registration.fullName},
          ${registration.organizationName}
      FROM roles
      WHERE roles.code = ${registration.roleCode}
      RETURNING id, email::text AS email
    `.execute(db);

    return result.rows[0] ?? null;
  }

  /**
   * Runs outside any caller-managed transaction, unlike this repository's
   * other write methods -- the failed-login counter must persist even when
   * the overall login attempt is about to be rejected. The nested CASE
   * (reset to 1 once a previous lockout has expired, otherwise increment;
   * lock again once the threshold is hit) re-uses its own result inside
   * the second CASE, which doesn't get clearer forced into the query
   * builder's .set() -- kept as one raw statement, see
   * backend-conventions.md's Kysely section.
   */
  async recordFailedLogin(
    userId: string,
    threshold: number,
    lockoutMinutes: number,
  ): Promise<LoginFailure | null> {
    const result = await sql<LoginFailure>`
      UPDATE users
      SET
          failed_login_attempts = CASE
              WHEN locked_until IS NOT NULL AND locked_until <= NOW() THEN 1
              ELSE failed_login_attempts + 1
          END,
          locked_until = CASE
              WHEN (
                  CASE
                      WHEN locked_until IS NOT NULL AND locked_until <= NOW() THEN 1
                      ELSE failed_login_attempts + 1
                  END
              ) >= ${threshold}
              THEN NOW() + make_interval(mins => ${lockoutMinutes})
              ELSE NULL
          END,
          updated_at = NOW()
      WHERE id = ${userId}
      RETURNING failed_login_attempts AS "failedLoginAttempts", locked_until AS "lockedUntil"
    `.execute(this.db);

    return result.rows[0] ?? null;
  }

  async recordSuccessfulLogin(db: Db, userId: string): Promise<LoginSuccessRow | null> {
    const result = await sql<LoginSuccessRow>`
      UPDATE users
      SET
          failed_login_attempts = 0,
          locked_until = NULL,
          last_login_at = NOW(),
          updated_at = NOW()
      WHERE id = ${userId}
      RETURNING last_login_at AS "lastLoginAt"
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async updatePassword(db: Db, userId: string, passwordHash: string): Promise<boolean> {
    const result = await sql<UpdatedPasswordRow>`
      UPDATE users
      SET
          password_hash = ${passwordHash},
          failed_login_attempts = 0,
          locked_until = NULL,
          updated_at = NOW()
      WHERE id = ${userId}
        AND account_status = 'active'
      RETURNING id
    `.execute(db);

    return result.rows.length === 1;
  }
}
