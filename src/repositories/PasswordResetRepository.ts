import { sql } from "kysely";
import type { Db } from "../db/schema.js";
import type { AccountStatus } from "../models/userModel.js";

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

// Same shape as ActivationRepository's ACTIVATION_SELECT -- the users join
// plus a conditional locking clause doesn't map onto the query builder
// cleanly, kept as a raw statement, see backend-conventions.md's Kysely
// section.
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

export class PasswordResetRepository {
  constructor(private readonly db: Db) {}

  async findByTokenHash(
    tokenHash: Buffer,
    db: Db = this.db,
    lock = false,
  ): Promise<PasswordResetRecord | null> {
    const lockClause = lock ? "FOR UPDATE OF reset, users" : "";
    const result = await sql<PasswordResetRecord>`
      ${sql.raw(PASSWORD_RESET_SELECT)}
      WHERE reset.token_hash = ${tokenHash}
      ${sql.raw(lockClause)}
    `.execute(db);

    return result.rows[0] ?? null;
  }

  async revokeUnusedTokens(db: Db, userId: string): Promise<void> {
    await db
      .updateTable("passwordResetTokens")
      .set({ revokedAt: sql`NOW()` })
      .where("userId", "=", userId)
      .where("usedAt", "is", null)
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
      .insertInto("passwordResetTokens")
      .values({ userId, tokenHash, expiresAt })
      .returning("id")
      .executeTakeFirst();

    if (!created) {
      throw new Error("The password reset token could not be created.");
    }

    return created.id;
  }

  async useTokenAndRevokeOthers(db: Db, resetId: string, userId: string): Promise<void> {
    const used = await db
      .updateTable("passwordResetTokens")
      .set({ usedAt: sql`NOW()` })
      .where("id", "=", resetId)
      .where("usedAt", "is", null)
      .where("revokedAt", "is", null)
      .executeTakeFirst();

    if (used.numUpdatedRows !== 1n) {
      throw new Error("The password reset token could not be consumed.");
    }

    await db
      .updateTable("passwordResetTokens")
      .set({ revokedAt: sql`NOW()` })
      .where("userId", "=", userId)
      .where("id", "<>", resetId)
      .where("usedAt", "is", null)
      .where("revokedAt", "is", null)
      .execute();
  }
}
