import type { Db } from "../db/schema.js";

export interface AuthSettings {
  sessionIdleTimeoutMinutes: number;
  sessionAbsoluteTimeoutMinutes: number;
  rememberMeAbsoluteTimeoutDays: number;
  lockoutThreshold: number;
  lockoutDurationMinutes: number;
  activationTokenValidityHours: number;
  passwordMinLength: number;
  passwordMaxLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireNumber: boolean;
  passwordRequireSymbol: boolean;
  currentTermsVersion: string;
  currentPrivacyPolicyVersion: string;
  passwordResetTokenValidityMinutes: number;
  terminateSessionsOnPasswordReset: boolean;
  terminateOtherSessionsOnPasswordChange: boolean;
}

export class SettingsRepository {
  constructor(private readonly db: Db) {}

  async getAuthSettings(db: Db = this.db): Promise<AuthSettings> {
    const settings = await db
      .selectFrom("authSettings")
      .select([
        "sessionIdleTimeoutMinutes",
        "sessionAbsoluteTimeoutMinutes",
        "rememberMeAbsoluteTimeoutDays",
        "lockoutThreshold",
        "lockoutDurationMinutes",
        "activationTokenValidityHours",
        "passwordMinLength",
        "passwordMaxLength",
        "passwordRequireUppercase",
        "passwordRequireLowercase",
        "passwordRequireNumber",
        "passwordRequireSymbol",
        "currentTermsVersion",
        "currentPrivacyPolicyVersion",
        "passwordResetTokenValidityMinutes",
        "terminateSessionsOnPasswordReset",
        "terminateOtherSessionsOnPasswordChange",
      ])
      .where("singleton", "=", true)
      .executeTakeFirst();

    if (!settings) {
      throw new Error("Authentication settings have not been initialized.");
    }

    return settings;
  }
}
