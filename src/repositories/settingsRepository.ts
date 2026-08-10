import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";

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
}

interface AuthSettingsRow extends AuthSettings, QueryResultRow {}

export async function getAuthSettings(
    db: Pool | PoolClient = pool,
): Promise<AuthSettings> {
    const { rows } = await db.query<AuthSettingsRow>(`
        SELECT
            session_idle_timeout_minutes AS "sessionIdleTimeoutMinutes",
            session_absolute_timeout_minutes AS "sessionAbsoluteTimeoutMinutes",
            remember_me_absolute_timeout_days AS "rememberMeAbsoluteTimeoutDays",
            lockout_threshold AS "lockoutThreshold",
            lockout_duration_minutes AS "lockoutDurationMinutes",
            activation_token_validity_hours AS "activationTokenValidityHours",
            password_min_length AS "passwordMinLength",
            password_max_length AS "passwordMaxLength",
            password_require_uppercase AS "passwordRequireUppercase",
            password_require_lowercase AS "passwordRequireLowercase",
            password_require_number AS "passwordRequireNumber",
            password_require_symbol AS "passwordRequireSymbol",
            current_terms_version AS "currentTermsVersion",
            current_privacy_policy_version AS "currentPrivacyPolicyVersion"
        FROM auth_settings
        WHERE singleton = TRUE
    `);

    const settings = rows[0];
    if (!settings) {
        throw new Error("Authentication settings have not been initialized.");
    }

    return settings;
}
