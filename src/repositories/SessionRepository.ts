import { sql } from "kysely";
import type { Db } from "../db/schema.js";
import type { AccountStatus } from "../models/userModel.js";

export interface NewSession {
  id: string;
  userId: string;
  refreshTokenHash: Buffer;
  expiresAt: Date;
  idleExpiresAt: Date;
  isPersistent: boolean;
  ipAddress: string | null;
  userAgent: string | null;
}

export interface AuthenticatedSession {
  sessionId: string;
  expiresAt: Date;
  userId: string;
  email: string;
  roleCode: string;
  permissions: string[];
}

export interface RefreshSession extends AuthenticatedSession {
  refreshTokenHash: Buffer;
  refreshGeneration: number;
  isPersistent: boolean;
  idleExpiresAt: Date;
  revokedAt: Date | null;
  accountStatus: AccountStatus;
  lockedUntil: Date | null;
}

export class SessionRepository {
  constructor(private readonly db: Db) {}

  async createSession(db: Db, session: NewSession): Promise<{ id: string }> {
    const created = await db
      .insertInto("authSessions")
      .values({
        id: session.id,
        userId: session.userId,
        tokenHash: session.refreshTokenHash,
        expiresAt: session.expiresAt,
        idleExpiresAt: session.idleExpiresAt,
        refreshGeneration: 0,
        isPersistent: session.isPersistent,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
      })
      .returning("id")
      .executeTakeFirst();

    if (!created) {
      throw new Error("The authentication session could not be created.");
    }

    return created;
  }

  /**
   * Runs outside any caller-managed transaction (this repository's only
   * other method that does) -- touching last-seen/idle-expiry on every
   * authenticated request has nothing to roll back. The CTE (touch the
   * session, then join out the principal it belongs to in one round trip)
   * and the permissions ARRAY() subquery don't map onto the query builder
   * cleanly -- kept as a raw statement, see backend-conventions.md's
   * Kysely section.
   */
  async findActiveSessionById(
    sessionId: string,
    userId: string,
  ): Promise<AuthenticatedSession | null> {
    const result = await sql<AuthenticatedSession>`
      WITH touched_session AS (
          UPDATE auth_sessions s
          SET
              last_seen_at = NOW(),
              idle_expires_at = LEAST(
                  s.expires_at,
                  NOW() + make_interval(
                      mins => (
                          SELECT session_idle_timeout_minutes
                          FROM auth_settings
                          WHERE singleton = TRUE
                      )
                  )
              )
          FROM users u
          WHERE
              s.id = ${sessionId}
              AND s.user_id = ${userId}
              AND s.user_id = u.id
              AND s.revoked_at IS NULL
              AND s.expires_at > NOW()
              AND s.idle_expires_at > NOW()
              AND u.account_status = 'active'
              AND (u.locked_until IS NULL OR u.locked_until <= NOW())
          RETURNING s.id, s.user_id, s.expires_at
      )
      SELECT
          touched.id AS "sessionId",
          touched.expires_at AS "expiresAt",
          users.id AS "userId",
          users.email::text AS email,
          roles.code AS "roleCode",
          ARRAY(
              SELECT permissions.code
              FROM role_permissions
              JOIN permissions
                  ON permissions.id = role_permissions.permission_id
              WHERE role_permissions.role_id = roles.id
              ORDER BY permissions.code
          ) AS permissions
      FROM touched_session touched
      JOIN users ON users.id = touched.user_id
      JOIN roles ON roles.id = users.role_id
    `.execute(this.db);

    return result.rows[0] ?? null;
  }

  async findRefreshSessionForUpdate(
    db: Db,
    sessionId: string,
  ): Promise<RefreshSession | null> {
    const result = await sql<RefreshSession>`
      SELECT
          sessions.id AS "sessionId",
          sessions.expires_at AS "expiresAt",
          sessions.idle_expires_at AS "idleExpiresAt",
          sessions.revoked_at AS "revokedAt",
          sessions.token_hash AS "refreshTokenHash",
          sessions.refresh_generation AS "refreshGeneration",
          sessions.is_persistent AS "isPersistent",
          users.id AS "userId",
          users.email::text AS email,
          users.account_status AS "accountStatus",
          users.locked_until AS "lockedUntil",
          roles.code AS "roleCode",
          ARRAY(
              SELECT permissions.code
              FROM role_permissions
              JOIN permissions
                  ON permissions.id = role_permissions.permission_id
              WHERE role_permissions.role_id = roles.id
              ORDER BY permissions.code
          ) AS permissions
      FROM auth_sessions sessions
      JOIN users ON users.id = sessions.user_id
      JOIN roles ON roles.id = users.role_id
      WHERE sessions.id = ${sessionId}
      FOR UPDATE OF sessions, users
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async rotateRefreshToken(
    db: Db,
    sessionId: string,
    expectedGeneration: number,
    refreshTokenHash: Buffer,
  ): Promise<boolean> {
    await sql`
      INSERT INTO auth_refresh_token_history (
          session_id,
          generation,
          token_hash,
          expires_at
      )
      SELECT id, refresh_generation, token_hash, expires_at
      FROM auth_sessions
      WHERE id = ${sessionId}
        AND refresh_generation = ${expectedGeneration}
    `.execute(db);

    const result = await sql`
      UPDATE auth_sessions
      SET
          token_hash = ${refreshTokenHash},
          refresh_generation = refresh_generation + 1,
          last_seen_at = NOW(),
          idle_expires_at = LEAST(
              expires_at,
              NOW() + make_interval(
                  mins => (
                      SELECT session_idle_timeout_minutes
                      FROM auth_settings
                      WHERE singleton = TRUE
                  )
              )
          )
      WHERE id = ${sessionId}
        AND refresh_generation = ${expectedGeneration}
        AND revoked_at IS NULL
        AND expires_at > NOW()
        AND idle_expires_at > NOW()
    `.execute(db);

    return result.numAffectedRows === 1n;
  }

  async wasRefreshTokenUsed(
    db: Db,
    sessionId: string,
    refreshTokenHash: Buffer,
  ): Promise<boolean> {
    const found = await db
      .selectFrom("authRefreshTokenHistory")
      .select("sessionId")
      .where("sessionId", "=", sessionId)
      .where("tokenHash", "=", refreshTokenHash)
      .executeTakeFirst();

    return found !== undefined;
  }

  async revokeSession(sessionId: string, db: Db = this.db): Promise<boolean> {
    const result = await db
      .updateTable("authSessions")
      .set({ revokedAt: sql`NOW()` })
      .where("id", "=", sessionId)
      .where("revokedAt", "is", null)
      .executeTakeFirst();

    return result.numUpdatedRows === 1n;
  }

  async revokeUserSessions(
    db: Db,
    userId: string,
    exceptSessionId?: string,
  ): Promise<number> {
    const result = await db
      .updateTable("authSessions")
      .set({ revokedAt: sql`NOW()` })
      .where("userId", "=", userId)
      .where("revokedAt", "is", null)
      .$if(exceptSessionId !== undefined, (qb) =>
        qb.where("id", "<>", exceptSessionId as string),
      )
      .executeTakeFirst();

    return Number(result.numUpdatedRows);
  }
}
