import type { Pool, PoolClient, QueryResultRow } from "pg";
import pool from "../db/pool";

export interface AuthSettings {
    sessionIdleTimeoutMinutes: number;
    sessionAbsoluteTimeoutMinutes: number;
    rememberMeAbsoluteTimeoutDays: number;
    lockoutThreshold: number;
    lockoutDurationMinutes: number;
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
            lockout_duration_minutes AS "lockoutDurationMinutes"
        FROM auth_settings
        WHERE singleton = TRUE
    `);

    const settings = rows[0];
    if (!settings) {
        throw new Error("Authentication settings have not been initialized.");
    }

    return settings;
}
