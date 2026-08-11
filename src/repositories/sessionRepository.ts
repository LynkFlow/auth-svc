import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";
import type { AccountStatus } from "../models/userModel";

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

interface CreatedSessionRow extends QueryResultRow {
    id: string;
}

export interface AuthenticatedSession {
    sessionId: string;
    expiresAt: Date;
    userId: string;
    email: string;
    roleCode: string;
    permissions: string[];
}

interface AuthenticatedSessionRow
    extends AuthenticatedSession,
        QueryResultRow {}

export interface RefreshSession extends AuthenticatedSession {
    refreshTokenHash: Buffer;
    refreshGeneration: number;
    isPersistent: boolean;
    idleExpiresAt: Date;
    revokedAt: Date | null;
    accountStatus: AccountStatus;
    lockedUntil: Date | null;
}

interface RefreshSessionRow extends RefreshSession, QueryResultRow {}

export async function createSession(
    client: PoolClient,
    session: NewSession,
): Promise<CreatedSessionRow> {
    const { rows } = await client.query<CreatedSessionRow>(
        `
            INSERT INTO auth_sessions (
                id,
                user_id,
                token_hash,
                expires_at,
                idle_expires_at,
                refresh_generation,
                is_persistent,
                ip_address,
                user_agent
            )
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8)
            RETURNING id
        `,
        [
            session.id,
            session.userId,
            session.refreshTokenHash,
            session.expiresAt,
            session.idleExpiresAt,
            session.isPersistent,
            session.ipAddress,
            session.userAgent,
        ],
    );

    const createdSession = rows[0];
    if (!createdSession) {
        throw new Error("The authentication session could not be created.");
    }

    return createdSession;
}

export async function findActiveSessionById(
    sessionId: string,
    userId: string,
): Promise<AuthenticatedSession | null> {
    const { rows } = await pool.query<AuthenticatedSessionRow>(
        `
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
                    s.id = $1
                    AND s.user_id = $2
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
        `,
        [sessionId, userId],
    );

    return rows[0] ?? null;
}

export async function findRefreshSessionForUpdate(
    client: PoolClient,
    sessionId: string,
): Promise<RefreshSession | null> {
    const { rows } = await client.query<RefreshSessionRow>(
        `
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
            WHERE sessions.id = $1
            FOR UPDATE OF sessions, users
        `,
        [sessionId],
    );

    return rows[0] ?? null;
}

export async function rotateRefreshToken(
    client: PoolClient,
    sessionId: string,
    expectedGeneration: number,
    refreshTokenHash: Buffer,
): Promise<boolean> {
    await client.query(
        `
            INSERT INTO auth_refresh_token_history (
                session_id,
                generation,
                token_hash,
                expires_at
            )
            SELECT id, refresh_generation, token_hash, expires_at
            FROM auth_sessions
            WHERE id = $1
              AND refresh_generation = $2
        `,
        [sessionId, expectedGeneration],
    );

    const result = await client.query(
        `
            UPDATE auth_sessions
            SET
                token_hash = $3,
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
            WHERE id = $1
              AND refresh_generation = $2
              AND revoked_at IS NULL
              AND expires_at > NOW()
              AND idle_expires_at > NOW()
        `,
        [sessionId, expectedGeneration, refreshTokenHash],
    );

    return result.rowCount === 1;
}

export async function wasRefreshTokenUsed(
    client: PoolClient,
    sessionId: string,
    refreshTokenHash: Buffer,
): Promise<boolean> {
    const { rowCount } = await client.query(
        `
            SELECT 1
            FROM auth_refresh_token_history
            WHERE session_id = $1
              AND token_hash = $2
        `,
        [sessionId, refreshTokenHash],
    );

    return rowCount === 1;
}

export async function revokeSession(
    sessionId: string,
    db: Pool | PoolClient = pool,
): Promise<boolean> {
    const result = await db.query(
        `
            UPDATE auth_sessions
            SET revoked_at = NOW()
            WHERE id = $1
              AND revoked_at IS NULL
        `,
        [sessionId],
    );

    return result.rowCount === 1;
}

export async function revokeUserSessions(
    client: PoolClient,
    userId: string,
    exceptSessionId?: string,
): Promise<number> {
    const parameters: string[] = [userId];
    let exceptionClause = "";

    if (exceptSessionId !== undefined) {
        parameters.push(exceptSessionId);
        exceptionClause = "AND id <> $2";
    }

    const result = await client.query(
        `
            UPDATE auth_sessions
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND revoked_at IS NULL
              ${exceptionClause}
        `,
        parameters,
    );

    return result.rowCount ?? 0;
}
