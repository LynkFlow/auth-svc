import { createHash, randomBytes } from "node:crypto";
import type { Db } from "../db/schema.js";
import AppError from "../errors/AppError.js";
import {
  ActivationPasswordRequiredError,
  ActivationTokenExpiredError,
  ActivationTokenInvalidError,
} from "../errors/ActivationErrors.js";
import {
  AccountAlreadyActiveError,
  AccountNotActivatableError,
} from "../errors/AccountStateErrors.js";
import { PasswordPolicyViolationError } from "../errors/PasswordErrors.js";
import { ACCOUNT_STATUS } from "../models/userModel.js";
import type { ActivationRecord, ActivationRepository } from "../repositories/ActivationRepository.js";
import type { OutboxRepository } from "../repositories/OutboxRepository.js";
import type { AuthSettings, SettingsRepository } from "../repositories/SettingsRepository.js";
import type { UserRepository } from "../repositories/UserRepository.js";
import * as passwordService from "./passwordService.js";

export interface ActivationDetails {
  account: {
    organizationName: string | null;
    fullName: string | null;
    email: string;
  };
  agreements: {
    termsVersion: string;
    privacyPolicyVersion: string;
  };
  expiresAt: string;
}

export interface IssuedActivationToken {
  token: string;
  expiresAt: Date;
}

export interface CompletedActivation {
  loginPath: string;
  userId: string;
}

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function invalidTokenError(): AppError {
  return new ActivationTokenInvalidError();
}

function expiredTokenError(): AppError {
  return new ActivationTokenExpiredError();
}

function alreadyActivatedError(): AppError {
  return new AccountAlreadyActiveError();
}

function passwordRequiredError(): AppError {
  return new ActivationPasswordRequiredError();
}

function assertActivatable(
  activation: ActivationRecord | null,
  now = new Date(),
): asserts activation is ActivationRecord {
  if (!activation) {
    throw invalidTokenError();
  }

  if (activation.accountStatus === ACCOUNT_STATUS.ACTIVE) {
    throw alreadyActivatedError();
  }

  if (
    activation.accountStatus !== ACCOUNT_STATUS.PENDING_ACTIVATION ||
    activation.consumedAt !== null ||
    activation.revokedAt !== null
  ) {
    throw invalidTokenError();
  }

  if (activation.expiresAt <= now) {
    throw expiredTokenError();
  }
}

function toActivationDetails(
  activation: ActivationRecord,
  settings: AuthSettings,
): ActivationDetails {
  return {
    account: {
      organizationName: activation.organizationName,
      fullName: activation.fullName,
      email: activation.email,
    },
    agreements: {
      termsVersion: settings.currentTermsVersion,
      privacyPolicyVersion: settings.currentPrivacyPolicyVersion,
    },
    expiresAt: activation.expiresAt.toISOString(),
  };
}

export class ActivationService {
  constructor(
    private readonly db: Db,
    private readonly activationRepository: ActivationRepository,
    private readonly outboxRepository: OutboxRepository,
    private readonly settingsRepository: SettingsRepository,
    private readonly userRepository: UserRepository,
  ) {}

  async validateActivationToken(token: string): Promise<ActivationDetails> {
    const [activation, settings] = await Promise.all([
      this.activationRepository.findByTokenHash(hashToken(token)),
      this.settingsRepository.getAuthSettings(),
    ]);

    assertActivatable(activation);
    return toActivationDetails(activation, settings);
  }

  async completeActivation(
    token: string,
    password?: string,
  ): Promise<CompletedActivation> {
    const tokenHash = hashToken(token);
    const [activation, settings] = await Promise.all([
      this.activationRepository.findByTokenHash(tokenHash),
      this.settingsRepository.getAuthSettings(),
    ]);

    assertActivatable(activation);

    if (password === undefined && !activation.hasPassword) {
      throw passwordRequiredError();
    }

    let passwordHash: string | null = null;
    if (password !== undefined) {
      const policyViolations = passwordService.passwordPolicyViolations(password, {
        minimumLength: settings.passwordMinLength,
        maximumLength: settings.passwordMaxLength,
        requireUppercase: settings.passwordRequireUppercase,
        requireLowercase: settings.passwordRequireLowercase,
        requireNumber: settings.passwordRequireNumber,
        requireSymbol: settings.passwordRequireSymbol,
      });

      if (policyViolations.length > 0) {
        throw new PasswordPolicyViolationError(policyViolations);
      }

      passwordHash = await passwordService.hashPassword(password);
    }

    return this.db.transaction().execute(async (trx) => {
      const currentActivation = await this.activationRepository.findByTokenHash(
        tokenHash,
        trx,
        true,
      );
      assertActivatable(currentActivation);

      if (passwordHash === null && !currentActivation.hasPassword) {
        throw passwordRequiredError();
      }

      const activated = await this.activationRepository.activateUser(
        trx,
        currentActivation.userId,
        passwordHash,
        settings.currentTermsVersion,
        settings.currentPrivacyPolicyVersion,
      );
      if (!activated) {
        throw alreadyActivatedError();
      }

      await this.activationRepository.consumeTokenAndRevokeOthers(
        trx,
        currentActivation.id,
        currentActivation.userId,
      );
      await this.outboxRepository.enqueueEvent(
        trx,
        "account.activated",
        currentActivation.userId,
        {
          userId: currentActivation.userId,
          email: currentActivation.email,
          fullName: currentActivation.fullName,
          channel: "email",
        },
      );

      return { loginPath: "/login", userId: currentActivation.userId };
    });
  }

  async issueActivationToken(userId: string): Promise<IssuedActivationToken> {
    const settings = await this.settingsRepository.getAuthSettings();
    const token = randomBytes(32).toString("base64url");
    const tokenHash = hashToken(token);
    const expiresAt = new Date(
      Date.now() + settings.activationTokenValidityHours * 60 * 60 * 1000,
    );

    await this.db.transaction().execute(async (trx) => {
      const user = await this.userRepository.findByIdForUpdate(trx, userId);

      if (!user || user.accountStatus !== ACCOUNT_STATUS.PENDING_ACTIVATION) {
        if (user?.accountStatus === ACCOUNT_STATUS.ACTIVE) {
          throw alreadyActivatedError();
        }

        throw new AccountNotActivatableError();
      }

      await this.activationRepository.revokeUnusedTokens(trx, userId);
      await this.activationRepository.createToken(trx, userId, tokenHash, expiresAt);
    });

    return { token, expiresAt };
  }
}
