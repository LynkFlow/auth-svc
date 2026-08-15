import { createHash, randomBytes } from "node:crypto";
import type { Db } from "../db/schema.js";
import AppError from "../errors/AppError.js";
import {
  CurrentPasswordIncorrectError,
  PasswordPolicyViolationError,
  PasswordResetTokenExpiredError,
  PasswordResetTokenInvalidError,
  PasswordUnchangedError,
} from "../errors/PasswordErrors.js";
import { SessionExpiredError } from "../errors/TokenErrors.js";
import { ACCOUNT_STATUS } from "../models/userModel.js";
import type { OutboxRepository } from "../repositories/OutboxRepository.js";
import type {
  PasswordResetRecord,
  PasswordResetRepository,
} from "../repositories/PasswordResetRepository.js";
import type { SessionRepository } from "../repositories/SessionRepository.js";
import type { AuthSettings, SettingsRepository } from "../repositories/SettingsRepository.js";
import type { UserRepository } from "../repositories/UserRepository.js";
import * as passwordService from "./passwordService.js";

interface ChangePasswordParameters {
  userId: string;
  sessionId: string;
  currentPassword: string;
  newPassword: string;
}

export interface CompletedPasswordReset {
  loginPath: string;
  userId: string;
}

type ValidPasswordResetRecord = PasswordResetRecord & {
  passwordHash: string;
};

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function invalidResetTokenError(): AppError {
  return new PasswordResetTokenInvalidError();
}

function expiredResetTokenError(): AppError {
  return new PasswordResetTokenExpiredError();
}

function unchangedPasswordError(): AppError {
  return new PasswordUnchangedError();
}

function assertValidReset(
  reset: PasswordResetRecord | null,
  now = new Date(),
): asserts reset is ValidPasswordResetRecord {
  if (
    !reset ||
    reset.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
    reset.passwordHash === null ||
    reset.usedAt !== null ||
    reset.revokedAt !== null
  ) {
    throw invalidResetTokenError();
  }

  if (reset.expiresAt <= now) {
    throw expiredResetTokenError();
  }
}

function enforcePasswordPolicy(password: string, settings: AuthSettings): void {
  const violations = passwordService.passwordPolicyViolations(password, {
    minimumLength: settings.passwordMinLength,
    maximumLength: settings.passwordMaxLength,
    requireUppercase: settings.passwordRequireUppercase,
    requireLowercase: settings.passwordRequireLowercase,
    requireNumber: settings.passwordRequireNumber,
    requireSymbol: settings.passwordRequireSymbol,
  });

  if (violations.length > 0) {
    throw new PasswordPolicyViolationError(violations);
  }
}

export class PasswordManagementService {
  constructor(
    private readonly db: Db,
    private readonly outboxRepository: OutboxRepository,
    private readonly passwordResetRepository: PasswordResetRepository,
    private readonly sessionRepository: SessionRepository,
    private readonly settingsRepository: SettingsRepository,
    private readonly userRepository: UserRepository,
  ) {}

  async requestPasswordReset(email: string): Promise<void> {
    const [user, settings] = await Promise.all([
      this.userRepository.findByEmail(email),
      this.settingsRepository.getAuthSettings(),
    ]);

    if (
      !user ||
      user.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
      user.passwordHash === null
    ) {
      return;
    }

    const token = randomBytes(32).toString("base64url");
    const tokenHash = hashToken(token);
    const expiresAt = new Date(
      Date.now() + settings.passwordResetTokenValidityMinutes * 60 * 1000,
    );

    await this.db.transaction().execute(async (trx) => {
      const currentUser = await this.userRepository.findByIdForUpdate(trx, user.id);

      if (
        !currentUser ||
        currentUser.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
        currentUser.passwordHash === null
      ) {
        // Nothing has been written yet on this path -- returning here
        // commits an empty transaction, which is behaviorally identical
        // to the raw-SQL version's explicit early ROLLBACK.
        return;
      }

      await this.passwordResetRepository.revokeUnusedTokens(trx, currentUser.id);
      await this.passwordResetRepository.createToken(
        trx,
        currentUser.id,
        tokenHash,
        expiresAt,
      );
      await this.outboxRepository.enqueueEvent(
        trx,
        "password.reset.requested",
        currentUser.id,
        {
          userId: currentUser.id,
          email: currentUser.email,
          token,
          expiresAt: expiresAt.toISOString(),
          channel: "email",
        },
      );
    });
  }

  async validatePasswordResetToken(token: string): Promise<{ expiresAt: string }> {
    const reset = await this.passwordResetRepository.findByTokenHash(hashToken(token));

    assertValidReset(reset);
    return { expiresAt: reset.expiresAt.toISOString() };
  }

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<CompletedPasswordReset> {
    const tokenHash = hashToken(token);
    const [reset, settings] = await Promise.all([
      this.passwordResetRepository.findByTokenHash(tokenHash),
      this.settingsRepository.getAuthSettings(),
    ]);

    assertValidReset(reset);
    enforcePasswordPolicy(newPassword, settings);

    if (await passwordService.verifyPassword(reset.passwordHash, newPassword)) {
      throw unchangedPasswordError();
    }

    const newPasswordHash = await passwordService.hashPassword(newPassword);

    return this.db.transaction().execute(async (trx) => {
      const currentReset = await this.passwordResetRepository.findByTokenHash(
        tokenHash,
        trx,
        true,
      );
      assertValidReset(currentReset);

      if (await passwordService.verifyPassword(currentReset.passwordHash, newPassword)) {
        throw unchangedPasswordError();
      }

      const updated = await this.userRepository.updatePassword(
        trx,
        currentReset.userId,
        newPasswordHash,
      );
      if (!updated) {
        throw invalidResetTokenError();
      }

      await this.passwordResetRepository.useTokenAndRevokeOthers(
        trx,
        currentReset.id,
        currentReset.userId,
      );

      if (settings.terminateSessionsOnPasswordReset) {
        await this.sessionRepository.revokeUserSessions(trx, currentReset.userId);
      }

      await this.outboxRepository.enqueueEvent(
        trx,
        "password.reset.completed",
        currentReset.userId,
        {
          userId: currentReset.userId,
          email: currentReset.email,
          fullName: currentReset.fullName,
          channel: "email",
        },
      );

      return { loginPath: "/login", userId: currentReset.userId };
    });
  }

  async changePassword({
    userId,
    sessionId,
    currentPassword,
    newPassword,
  }: ChangePasswordParameters): Promise<void> {
    const settings = await this.settingsRepository.getAuthSettings();

    await this.db.transaction().execute(async (trx) => {
      const user = await this.userRepository.findByIdForUpdate(trx, userId);

      if (
        !user ||
        user.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
        user.passwordHash === null
      ) {
        throw new SessionExpiredError();
      }

      const currentPasswordMatches = await passwordService.verifyPassword(
        user.passwordHash,
        currentPassword,
      );
      if (!currentPasswordMatches) {
        throw new CurrentPasswordIncorrectError();
      }

      enforcePasswordPolicy(newPassword, settings);

      if (await passwordService.verifyPassword(user.passwordHash, newPassword)) {
        throw unchangedPasswordError();
      }

      const newPasswordHash = await passwordService.hashPassword(newPassword);
      const updated = await this.userRepository.updatePassword(
        trx,
        user.id,
        newPasswordHash,
      );
      if (!updated) {
        throw new Error("The password could not be changed.");
      }

      await this.passwordResetRepository.revokeUnusedTokens(trx, user.id);

      if (settings.terminateOtherSessionsOnPasswordChange) {
        await this.sessionRepository.revokeUserSessions(trx, user.id, sessionId);
      }

      await this.outboxRepository.enqueueEvent(trx, "password.changed", user.id, {
        userId: user.id,
        email: user.email,
        channel: "email",
      });
    });
  }
}
