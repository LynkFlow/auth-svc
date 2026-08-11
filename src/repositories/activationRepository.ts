import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";
import type { AccountStatus } from "../models/userModel";

export interface ActivationRecord {
    id: string;
    userId: string;
    email: string;
    fullName: string | null;
    organizationName: string | null;
    accountStatus: AccountStatus;
    hasPassword: boolean;
    expiresAt: Date;
    consumedAt: Date | null;
    revokedAt: Date | null;
}
interface ActivationRow extends ActivationRecord, QueryResultRow {}

interface CreatedTokenRow extends QueryResultRow {
    id: string;
}

interface UpdatedUserRow extends QueryResultRow {
    id: string;
}

const ACTIVATION_SELECT = `
    SELECT
        activation.id,
        activation.user_id AS "userId",
        users.email::text AS email,
        users.full_name AS "fullName",
        users.organization_name AS "organizationName",
        users.account_status AS "accountStatus",
        users.password_hash IS NOT NULL AS "hasPassword",
        activation.expires_at AS "expiresAt",
        activation.consumed_at AS "consumedAt",
        activation.revoked_at AS "revokedAt"
    FROM account_activation_tokens activation
    JOIN users ON users.id = activation.user_id
`;

export async function findByTokenHash(
    tokenHash: Buffer,
    db: Pool | PoolClient = pool,
    lock = false,
): Promise<ActivationRecord | null> {
    const lockClause = lock ? "FOR UPDATE OF activation, users" : "";
    const { rows } = await db.query<ActivationRow>(
        `${ACTIVATION_SELECT}
         WHERE activation.token_hash = $1
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
            UPDATE account_activation_tokens
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND consumed_at IS NULL
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
            INSERT INTO account_activation_tokens (
                user_id,
                token_hash,
                expires_at
            ) VALUES ($1, $2, $3)
            RETURNING id
        `,
        [userId, tokenHash, expiresAt],
    );

    const token = rows[0];
    if (!token) {
        throw new Error("The activation token could not be created.");
    }

    return token.id;
}

export async function activateUser(
    client: PoolClient,
    userId: string,
    passwordHash: string | null,
    termsVersion: string,
    privacyPolicyVersion: string,
): Promise<boolean> {
    const { rows } = await client.query<UpdatedUserRow>(
        `
            UPDATE users
            SET
                password_hash = COALESCE($2::text, password_hash),
                account_status = 'active',
                activated_at = NOW(),
                terms_accepted_at = NOW(),
                terms_version = $3,
                privacy_policy_accepted_at = NOW(),
                privacy_policy_version = $4,
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND account_status = 'pending_activation'
              AND (password_hash IS NOT NULL OR $2::text IS NOT NULL)
            RETURNING id
        `,
        [userId, passwordHash, termsVersion, privacyPolicyVersion],
    );

    return rows.length === 1;
}

export async function consumeTokenAndRevokeOthers(
    client: PoolClient,
    activationId: string,
    userId: string,
): Promise<void> {
    const result = await client.query(
        `
            UPDATE account_activation_tokens
            SET consumed_at = NOW()
            WHERE id = $1
              AND consumed_at IS NULL
              AND revoked_at IS NULL
        `,
        [activationId],
    );

    if (result.rowCount !== 1) {
        throw new Error("The activation token could not be consumed.");
    }

    await client.query(
        `
            UPDATE account_activation_tokens
            SET revoked_at = NOW()
            WHERE user_id = $1
              AND id <> $2
              AND consumed_at IS NULL
              AND revoked_at IS NULL
        `,
        [userId, activationId],
    );
}
