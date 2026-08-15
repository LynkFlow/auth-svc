import { createTestDb } from "../test/testDb.js";
import { SettingsRepository } from "./SettingsRepository.js";

const ROW = {
  session_idle_timeout_minutes: 30,
  session_absolute_timeout_minutes: 480,
  remember_me_absolute_timeout_days: 30,
  lockout_threshold: 5,
  lockout_duration_minutes: 15,
  activation_token_validity_hours: 24,
  password_min_length: 12,
  password_max_length: 128,
  password_require_uppercase: true,
  password_require_lowercase: true,
  password_require_number: true,
  password_require_symbol: true,
  current_terms_version: "1.0",
  current_privacy_policy_version: "1.0",
  password_reset_token_validity_minutes: 30,
  terminate_sessions_on_password_reset: true,
  terminate_other_sessions_on_password_change: true,
};

describe("SettingsRepository", () => {
  it("maps the singleton settings row to camelCase", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 1, rows: [ROW] });
    const repository = new SettingsRepository(db);

    await expect(repository.getAuthSettings()).resolves.toEqual({
      sessionIdleTimeoutMinutes: 30,
      sessionAbsoluteTimeoutMinutes: 480,
      rememberMeAbsoluteTimeoutDays: 30,
      lockoutThreshold: 5,
      lockoutDurationMinutes: 15,
      activationTokenValidityHours: 24,
      passwordMinLength: 12,
      passwordMaxLength: 128,
      passwordRequireUppercase: true,
      passwordRequireLowercase: true,
      passwordRequireNumber: true,
      passwordRequireSymbol: true,
      currentTermsVersion: "1.0",
      currentPrivacyPolicyVersion: "1.0",
      passwordResetTokenValidityMinutes: 30,
      terminateSessionsOnPasswordReset: true,
      terminateOtherSessionsOnPasswordChange: true,
    });
  });

  it("throws if the settings singleton row is missing", async () => {
    const { db, query } = createTestDb();
    query.mockResolvedValue({ command: "SELECT", rowCount: 0, rows: [] });
    const repository = new SettingsRepository(db);

    await expect(repository.getAuthSettings()).rejects.toThrow(
      "Authentication settings have not been initialized.",
    );
  });
});
