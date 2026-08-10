import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";

export interface NewSession {
    userId: string;
    tokenHash: Buffer;
    expiresAt: Date;
    idleExpiresAt: Date;
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

export async function createSession(
    client: PoolClient,
    session: NewSession,
): Promise<CreatedSessionRow> {
    const { rows } = await client.query<CreatedSessionRow>(
        `
            INSERT INTO auth_sessions (
                user_id,
                token_hash,
                expires_at,
                idle_expires_at,
                ip_address,
                user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        `,
        [
            session.userId,
            session.tokenHash,
            session.expiresAt,
            session.idleExpiresAt,
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

export async function findActiveSession(
    tokenHash: Buffer,
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
                    s.token_hash = $1
                    AND s.user_id = u.id
                    AND s.revoked_at IS NULL
                    AND s.expires_at > NOW()
                    AND s.idle_expires_at > NOW()
                    AND u.account_status = 'active'
                    AND (u.locked_until IS NULL OR u.locked_until <= NOW())
                RETURNING s.id, s.user_id, s.expires_at
            )
            SELECT
                ts.id AS "sessionId",
                ts.expires_at AS "expiresAt",
                u.id AS "userId",
                u.email::text AS email,
                r.code AS "roleCode",
                ARRAY(
                    SELECT p.code
                    FROM role_permissions rp
                    JOIN permissions p ON p.id = rp.permission_id
                    WHERE rp.role_id = r.id
                    ORDER BY p.code
                ) AS permissions
            FROM touched_session ts
            JOIN users u ON u.id = ts.user_id
            JOIN roles r ON r.id = u.role_id
        `,
        [tokenHash],
    );

    return rows[0] ?? null;
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
