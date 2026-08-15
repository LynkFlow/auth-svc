import { createHash, randomBytes } from "node:crypto";
import type { Db } from "../db/schema.js";
import AppError from "../errors/AppError.js";
import { EmailAlreadyRegisteredError } from "../errors/CredentialErrors.js";
import { PasswordPolicyViolationError } from "../errors/PasswordErrors.js";
import { ACCOUNT_STATUS } from "../models/userModel.js";
import type { ActivationRepository } from "../repositories/ActivationRepository.js";
import type { OutboxRepository } from "../repositories/OutboxRepository.js";
import type { AuthSettings, SettingsRepository } from "../repositories/SettingsRepository.js";
import type { UserRepository } from "../repositories/UserRepository.js";
import * as passwordService from "./passwordService.js";

export const ACCOUNT_TYPE = Object.freeze({
  REAL_ESTATE_DEVELOPER: "real_estate_developer",
  BROKERAGE_COMPANY: "brokerage_company",
  SALES_AGENT: "sales_agent",
} as const);

export type AccountType = (typeof ACCOUNT_TYPE)[keyof typeof ACCOUNT_TYPE];

const ACCOUNT_TYPE_ROLE_CODE: Readonly<Record<AccountType, string>> = {
  [ACCOUNT_TYPE.REAL_ESTATE_DEVELOPER]: "developer_administrator",
  [ACCOUNT_TYPE.BROKERAGE_COMPANY]: "brokerage_administrator",
  [ACCOUNT_TYPE.SALES_AGENT]: "broker_agent",
};

interface SignupParameters {
  accountType: AccountType;
  fullName: string;
  email: string;
  company: string;
  password: string;
}

export interface SignupResult {
  userId: string;
  email: string;
  accountStatus: typeof ACCOUNT_STATUS.PENDING_ACTIVATION;
  activationExpiresAt: string;
}

interface PostgreSqlError {
  code?: string;
  constraint?: string;
}

function duplicateEmailError(): AppError {
  return new EmailAlreadyRegisteredError();
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

function isDuplicateEmailError(error: unknown): boolean {
  const databaseError = error as PostgreSqlError;
  return (
    databaseError.code === "23505" && databaseError.constraint === "users_email_key"
  );
}

export class SignupService {
  constructor(
    private readonly db: Db,
    private readonly activationRepository: ActivationRepository,
    private readonly outboxRepository: OutboxRepository,
    private readonly settingsRepository: SettingsRepository,
    private readonly userRepository: UserRepository,
  ) {}

  async signup({
    accountType,
    fullName,
    email,
    company,
    password,
  }: SignupParameters): Promise<SignupResult> {
    const settings = await this.settingsRepository.getAuthSettings();
    enforcePasswordPolicy(password, settings);

    const passwordHash = await passwordService.hashPassword(password);
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest();
    const expiresAt = new Date(
      Date.now() + settings.activationTokenValidityHours * 60 * 60 * 1000,
    );

    try {
      return await this.db.transaction().execute(async (trx) => {
        const user = await this.userRepository.createPendingRegistration(trx, {
          email,
          passwordHash,
          roleCode: ACCOUNT_TYPE_ROLE_CODE[accountType],
          fullName,
          organizationName: company,
        });

        if (!user) {
          throw new Error(
            `The configured role for account type '${accountType}' does not exist.`,
          );
        }

        await this.activationRepository.createToken(trx, user.id, tokenHash, expiresAt);
        await this.outboxRepository.enqueueEvent(
          trx,
          "account.activation.requested",
          user.id,
          {
            userId: user.id,
            email: user.email,
            fullName,
            organizationName: company,
            accountType,
            token,
            expiresAt: expiresAt.toISOString(),
            channel: "email",
          },
        );

        return {
          userId: user.id,
          email: user.email,
          accountStatus: ACCOUNT_STATUS.PENDING_ACTIVATION,
          activationExpiresAt: expiresAt.toISOString(),
        };
      });
    } catch (error) {
      if (isDuplicateEmailError(error)) {
        throw duplicateEmailError();
      }

      throw error;
    }
  }
}
