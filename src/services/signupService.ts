import { createHash, randomBytes } from "node:crypto";
import pool from "../db/pool.js";
import AppError from "../errors/AppError.js";
import { ACCOUNT_STATUS } from "../models/userModel.js";
import * as activationRepository from "../repositories/activationRepository.js";
import * as outboxRepository from "../repositories/outboxRepository.js";
import * as settingsRepository from "../repositories/settingsRepository.js";
import * as userRepository from "../repositories/userRepository.js";
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
  return new AppError(
    409,
    "AUTH_EMAIL_ALREADY_REGISTERED",
    "An account with this email address already exists.",
    { loginPath: "/login" },
  );
}

function enforcePasswordPolicy(
  password: string,
  settings: settingsRepository.AuthSettings,
): void {
  const violations = passwordService.passwordPolicyViolations(password, {
    minimumLength: settings.passwordMinLength,
    maximumLength: settings.passwordMaxLength,
    requireUppercase: settings.passwordRequireUppercase,
    requireLowercase: settings.passwordRequireLowercase,
    requireNumber: settings.passwordRequireNumber,
    requireSymbol: settings.passwordRequireSymbol,
  });

  if (violations.length > 0) {
    throw new AppError(
      400,
      "AUTH_PASSWORD_POLICY_VIOLATION",
      "Password does not comply with the password policy.",
      violations,
    );
  }
}

function isDuplicateEmailError(error: unknown): boolean {
  const databaseError = error as PostgreSqlError;
  return (
    databaseError.code === "23505" && databaseError.constraint === "users_email_key"
  );
}

export async function signup({
  accountType,
  fullName,
  email,
  company,
  password,
}: SignupParameters): Promise<SignupResult> {
  const settings = await settingsRepository.getAuthSettings();
  enforcePasswordPolicy(password, settings);

  const passwordHash = await passwordService.hashPassword(password);
  const token = randomBytes(32).toString("base64url");
  const tokenHash = createHash("sha256").update(token).digest();
  const expiresAt = new Date(
    Date.now() + settings.activationTokenValidityHours * 60 * 60 * 1000,
  );
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const user = await userRepository.createPendingRegistration(client, {
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

    await activationRepository.createToken(client, user.id, tokenHash, expiresAt);
    await outboxRepository.enqueueEvent(
      client,
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

    await client.query("COMMIT");
    return {
      userId: user.id,
      email: user.email,
      accountStatus: ACCOUNT_STATUS.PENDING_ACTIVATION,
      activationExpiresAt: expiresAt.toISOString(),
    };
  } catch (error) {
    await client.query("ROLLBACK");

    if (isDuplicateEmailError(error)) {
      throw duplicateEmailError();
    }

    throw error;
  } finally {
    client.release();
  }
}
