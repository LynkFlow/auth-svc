import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";
import type { AccountStatus } from "../models/userModel";

export interface PasswordResetRecord {
    id: string;
    userId: string;
    email: string;
    fullName: string | null;
    passwordHash: string | null;
    accountStatus: AccountStatus;
    expiresAt: Date;
    usedAt: Date | null;
    revokedAt: Date | null;
}

interface PasswordResetRow extends PasswordResetRecord, QueryResultRow {}

interface CreatedTokenRow extends QueryResultRow {
    id: string;
}

const PASSWORD_RESET_SELECT = `
    SELECT
        reset.id,
        reset.user_id AS "userId",
        users.email::text AS email,
        users.full_name AS "fullName",
        users.password_hash AS "passwordHash",
        users.account_status AS "accountStatus",
        reset.expires_at AS "expiresAt",
        reset.used_at AS "usedAt",
        reset.revoked_at AS "revokedAt"
    FROM password_reset_tokens reset
    JOIN users ON users.id = reset.user_id
`;

export async function findByTokenHash(
    tokenHash: Buffer,
    db: Pool | PoolClient = pool,
    lock = false,
): Promise<PasswordResetRecord | null> {
    const lockClause = lock ? "FOR UPDATE OF reset, users" : "";
    const { rows } = await db.query<PasswordResetRow>(
        `${PASSWORD_RESET_SELECT}
         WHERE reset.token_hash = $1
         ${lockClause}`,
        [tokenHash],
    );

    return rows[0] ?? null;
}

export async function revokeUnusedTokens(
    client: PoolClient,
    userId: string,
): Promise<void> {
    await client.query(
        `
            UPDATE password_reset_tokens
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND used_at IS NULL
              AND revoked_at IS NULL
        `,
        [userId],
    );
}

export async function createToken(
    client: PoolClient,
    userId: string,
    tokenHash: Buffer,
    expiresAt: Date,
): Promise<string> {
    const { rows } = await client.query<CreatedTokenRow>(
        `
            INSERT INTO password_reset_tokens (
                user_id,
                token_hash,
                expires_at
            ) VALUES ($1, $2, $3)
            RETURNING id
        `,
        [userId, tokenHash, expiresAt],
    );

    const createdToken = rows[0];
    if (!createdToken) {
        throw new Error("The password reset token could not be created.");
    }

    return createdToken.id;
}

export async function useTokenAndRevokeOthers(
    client: PoolClient,
    resetId: string,
    userId: string,
): Promise<void> {
    const result = await client.query(
        `
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE id = $1
              AND used_at IS NULL
              AND revoked_at IS NULL
        `,
        [resetId],
    );

    if (result.rowCount !== 1) {
        throw new Error("The password reset token could not be consumed.");
    }

    await client.query(
        `
            UPDATE password_reset_tokens
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND id <> $2
              AND used_at IS NULL
              AND revoked_at IS NULL
        `,
        [userId, resetId],
    );
}
