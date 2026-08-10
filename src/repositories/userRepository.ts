import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";
import type { UserRecord } from "../models/userModel";

interface UserRow extends UserRecord, QueryResultRow {}

export interface LoginFailure {
    failedLoginAttempts: number;
    lockedUntil: Date | null;
}

interface LoginFailureRow extends LoginFailure, QueryResultRow {}

interface LoginSuccessRow extends QueryResultRow {
    lastLoginAt: Date;
}

interface UpdatedPasswordRow extends QueryResultRow {
    id: string;
}

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

export async function findByEmail(
    email: string,
    db: Pool | PoolClient = pool,
): Promise<UserRecord | null> {
    const { rows } = await db.query<UserRow>(
        `${USER_SELECT} WHERE u.email = $1`,
        [email],
    );

    return rows[0] ?? null;
}

export async function findByIdForUpdate(
    client: PoolClient,
    userId: string,
): Promise<UserRecord | null> {
    const { rows } = await client.query<UserRow>(
        `${USER_SELECT} WHERE u.id = $1 FOR UPDATE OF u`,
        [userId],
    );

    return rows[0] ?? null;
}

export async function recordFailedLogin(
    userId: string,
    threshold: number,
    lockoutMinutes: number,
): Promise<LoginFailure | null> {
    const { rows } = await pool.query<LoginFailureRow>(
        `
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
                    ) >= $2
                    THEN NOW() + make_interval(mins => $3)
                    ELSE NULL
                END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING failed_login_attempts AS "failedLoginAttempts", locked_until AS "lockedUntil"
        `,
        [userId, threshold, lockoutMinutes],
    );

    return rows[0] ?? null;
}

export async function recordSuccessfulLogin(
    client: PoolClient,
    userId: string,
): Promise<LoginSuccessRow | null> {
    const { rows } = await client.query<LoginSuccessRow>(
        `
            UPDATE users
            SET
                failed_login_attempts = 0,
                locked_until = NULL,
                last_login_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            RETURNING last_login_at AS "lastLoginAt"
        `,
        [userId],
    );

    return rows[0] ?? null;
}

export async function updatePassword(
    client: PoolClient,
    userId: string,
    passwordHash: string,
): Promise<boolean> {
    const { rows } = await client.query<UpdatedPasswordRow>(
        `
            UPDATE users
            SET
                password_hash = $2,
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND account_status = 'active'
            RETURNING id
        `,
        [userId, passwordHash],
    );

    return rows.length === 1;
}
