import { createHash, randomBytes } from "node:crypto";
import pool from "../db/pool";
import AppError from "../errors/AppError";
import { ACCOUNT_STATUS } from "../models/userModel";
import * as outboxRepository from "../repositories/outboxRepository";
import * as passwordResetRepository from "../repositories/passwordResetRepository";
import type { PasswordResetRecord } from "../repositories/passwordResetRepository";
import * as sessionRepository from "../repositories/sessionRepository";
import * as settingsRepository from "../repositories/settingsRepository";
import * as userRepository from "../repositories/userRepository";
import * as passwordService from "./passwordService";

interface ChangePasswordParameters {
    userId: string;
    sessionId: string;
    currentPassword: string;
    newPassword: string;
}

type ValidPasswordResetRecord = PasswordResetRecord & {
    passwordHash: string;
};

function hashToken(token: string): Buffer {
    return createHash("sha256").update(token).digest();
}

function invalidResetTokenError(): AppError {
    return new AppError(
        400,
        "AUTH_PASSWORD_RESET_TOKEN_INVALID",
        "Password reset link is invalid.",
    );
}

function expiredResetTokenError(): AppError {
    return new AppError(
        410,
        "AUTH_PASSWORD_RESET_TOKEN_EXPIRED",
        "Password reset link has expired.",
    );
}

function unchangedPasswordError(): AppError {
    return new AppError(
        400,
        "AUTH_PASSWORD_UNCHANGED",
        "Your new password cannot be the same as your current password.",
    );
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

export async function requestPasswordReset(email: string): Promise<void> {
    const [user, settings] = await Promise.all([
        userRepository.findByEmail(email),
        settingsRepository.getAuthSettings(),
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
        Date.now() +
            settings.passwordResetTokenValidityMinutes * 60 * 1000,
    );
    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        const currentUser = await userRepository.findByIdForUpdate(
            client,
            user.id,
        );

        if (
            !currentUser ||
            currentUser.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
            currentUser.passwordHash === null
        ) {
            await client.query("ROLLBACK");
            return;
        }

        await passwordResetRepository.revokeUnusedTokens(
            client,
            currentUser.id,
        );
        await passwordResetRepository.createToken(
            client,
            currentUser.id,
            tokenHash,
            expiresAt,
        );
        await outboxRepository.enqueueEvent(
            client,
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

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}

export async function validatePasswordResetToken(
    token: string,
): Promise<{ expiresAt: string }> {
    const reset = await passwordResetRepository.findByTokenHash(
        hashToken(token),
    );

    assertValidReset(reset);
    return { expiresAt: reset.expiresAt.toISOString() };
}

export async function resetPassword(
    token: string,
    newPassword: string,
): Promise<{ loginPath: string }> {
    const tokenHash = hashToken(token);
    const [reset, settings] = await Promise.all([
        passwordResetRepository.findByTokenHash(tokenHash),
        settingsRepository.getAuthSettings(),
    ]);

    assertValidReset(reset);
    enforcePasswordPolicy(newPassword, settings);

    if (
        await passwordService.verifyPassword(reset.passwordHash, newPassword)
    ) {
        throw unchangedPasswordError();
    }

    const newPasswordHash = await passwordService.hashPassword(newPassword);
    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        const currentReset = await passwordResetRepository.findByTokenHash(
            tokenHash,
            client,
            true,
        );
        assertValidReset(currentReset);

        if (
            await passwordService.verifyPassword(
                currentReset.passwordHash,
                newPassword,
            )
        ) {
            throw unchangedPasswordError();
        }

        const updated = await userRepository.updatePassword(
            client,
            currentReset.userId,
            newPasswordHash,
        );
        if (!updated) {
            throw invalidResetTokenError();
        }

        await passwordResetRepository.useTokenAndRevokeOthers(
            client,
            currentReset.id,
            currentReset.userId,
        );

        if (settings.terminateSessionsOnPasswordReset) {
            await sessionRepository.revokeUserSessions(
                client,
                currentReset.userId,
            );
        }

        await outboxRepository.enqueueEvent(
            client,
            "password.reset.completed",
            currentReset.userId,
            {
                userId: currentReset.userId,
                email: currentReset.email,
                fullName: currentReset.fullName,
                channel: "email",
            },
        );

        await client.query("COMMIT");
        return { loginPath: "/login" };
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}

export async function changePassword({
    userId,
    sessionId,
    currentPassword,
    newPassword,
}: ChangePasswordParameters): Promise<void> {
    const settings = await settingsRepository.getAuthSettings();

    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        const user = await userRepository.findByIdForUpdate(client, userId);

        if (
            !user ||
            user.accountStatus !== ACCOUNT_STATUS.ACTIVE ||
            user.passwordHash === null
        ) {
            throw new AppError(
                401,
                "AUTH_SESSION_EXPIRED",
                "Your session has expired. Please log in again.",
            );
        }

        const currentPasswordMatches = await passwordService.verifyPassword(
            user.passwordHash,
            currentPassword,
        );
        if (!currentPasswordMatches) {
            throw new AppError(
                400,
                "AUTH_CURRENT_PASSWORD_INCORRECT",
                "Current password is incorrect.",
            );
        }

        enforcePasswordPolicy(newPassword, settings);

        if (
            await passwordService.verifyPassword(
                user.passwordHash,
                newPassword,
            )
        ) {
            throw unchangedPasswordError();
        }

        const newPasswordHash = await passwordService.hashPassword(
            newPassword,
        );
        const updated = await userRepository.updatePassword(
            client,
            user.id,
            newPasswordHash,
        );
        if (!updated) {
            throw new Error("The password could not be changed.");
        }

        await passwordResetRepository.revokeUnusedTokens(client, user.id);

        if (settings.terminateOtherSessionsOnPasswordChange) {
            await sessionRepository.revokeUserSessions(
                client,
                user.id,
                sessionId,
            );
        }

        await outboxRepository.enqueueEvent(
            client,
            "password.changed",
            user.id,
            {
                userId: user.id,
                email: user.email,
                channel: "email",
            },
        );

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}
