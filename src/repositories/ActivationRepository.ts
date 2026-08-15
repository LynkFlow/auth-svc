import { sql } from "kysely";
import type { Db } from "../db/schema.js";
import type { AccountStatus } from "../models/userModel.js";

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

// The users join (for account status / hasPassword) doesn't map onto the
// query builder cleanly alongside the conditional locking clause below --
// kept as a raw statement, see backend-conventions.md's Kysely section.
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

export class ActivationRepository {
  constructor(private readonly db: Db) {}

  async findByTokenHash(
    tokenHash: Buffer,
    db: Db = this.db,
    lock = false,
  ): Promise<ActivationRecord | null> {
    const lockClause = lock ? "FOR UPDATE OF activation, users" : "";
    const result = await sql<ActivationRecord>`
      ${sql.raw(ACTIVATION_SELECT)}
      WHERE activation.token_hash = ${tokenHash}
      ${sql.raw(lockClause)}
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async revokeUnusedTokens(db: Db, userId: string): Promise<void> {
    await db
      .updateTable("accountActivationTokens")
      .set({ revokedAt: sql`NOW()` })
      .where("userId", "=", userId)
      .where("consumedAt", "is", null)
      .where("revokedAt", "is", null)
      .execute();
  }

  async createToken(
    db: Db,
    userId: string,
    tokenHash: Buffer,
    expiresAt: Date,
  ): Promise<string> {
    const created = await db
      .insertInto("accountActivationTokens")
      .values({ userId, tokenHash, expiresAt })
      .returning("id")
      .executeTakeFirst();

    if (!created) {
      throw new Error("The activation token could not be created.");
    }

    return created.id;
  }

  /**
   * The conditional `password_hash` coalesce (skip the column entirely
   * when no new password was supplied) and the compound WHERE guard don't
   * simplify by moving into the builder -- kept as a raw statement, see
   * backend-conventions.md's Kysely section.
   */
  async activateUser(
    db: Db,
    userId: string,
    passwordHash: string | null,
    termsVersion: string,
    privacyPolicyVersion: string,
  ): Promise<boolean> {
    const result = await sql<{ id: string }>`
      UPDATE users
      SET
          password_hash = COALESCE(${passwordHash}::text, password_hash),
          account_status = 'active',
          activated_at = NOW(),
          terms_accepted_at = NOW(),
          terms_version = ${termsVersion},
          privacy_policy_accepted_at = NOW(),
          privacy_policy_version = ${privacyPolicyVersion},
          failed_login_attempts = 0,
          locked_until = NULL,
          updated_at = NOW()
      WHERE id = ${userId}
        AND account_status = 'pending_activation'
        AND (password_hash IS NOT NULL OR ${passwordHash}::text IS NOT NULL)
      RETURNING id
    `.execute(db);

    return result.rows.length === 1;
  }

  async consumeTokenAndRevokeOthers(
    db: Db,
    activationId: string,
    userId: string,
  ): Promise<void> {
    const consumed = await db
      .updateTable("accountActivationTokens")
      .set({ consumedAt: sql`NOW()` })
      .where("id", "=", activationId)
      .where("consumedAt", "is", null)
      .where("revokedAt", "is", null)
      .executeTakeFirst();

    if (consumed.numUpdatedRows !== 1n) {
      throw new Error("The activation token could not be consumed.");
    }

    await db
      .updateTable("accountActivationTokens")
      .set({ revokedAt: sql`NOW()` })
      .where("userId", "=", userId)
      .where("id", "<>", activationId)
      .where("consumedAt", "is", null)
      .where("revokedAt", "is", null)
      .execute();
  }
}
