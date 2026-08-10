import { createHash, randomBytes } from "node:crypto";
import pool from "../db/pool";
import AppError from "../errors/AppError";
import { ACCOUNT_STATUS } from "../models/userModel";
import * as activationRepository from "../repositories/activationRepository";
import type { ActivationRecord } from "../repositories/activationRepository";
import * as settingsRepository from "../repositories/settingsRepository";
import * as userRepository from "../repositories/userRepository";
import * as passwordService from "./passwordService";

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

function hashToken(token: string): Buffer {
    return createHash("sha256").update(token).digest();
}

function invalidTokenError(): AppError {
    return new AppError(
        400,
        "AUTH_ACTIVATION_TOKEN_INVALID",
        "The activation link is invalid.",
    );
}

function expiredTokenError(): AppError {
    return new AppError(
        410,
        "AUTH_ACTIVATION_TOKEN_EXPIRED",
        "The activation link has expired.",
    );
}

function alreadyActivatedError(): AppError {
    return new AppError(
        409,
        "AUTH_ACCOUNT_ALREADY_ACTIVE",
        "This account has already been activated.",
        { loginPath: "/login" },
    );
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
    settings: settingsRepository.AuthSettings,
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

export async function validateActivationToken(
    token: string,
): Promise<ActivationDetails> {
    const [activation, settings] = await Promise.all([
        activationRepository.findByTokenHash(hashToken(token)),
        settingsRepository.getAuthSettings(),
    ]);

    assertActivatable(activation);
    return toActivationDetails(activation, settings);
}

export async function completeActivation(
    token: string,
    password: string,
): Promise<{ loginPath: string }> {
    const tokenHash = hashToken(token);
    const [activation, settings] = await Promise.all([
        activationRepository.findByTokenHash(tokenHash),
        settingsRepository.getAuthSettings(),
    ]);

    assertActivatable(activation);

    const policyViolations = passwordService.passwordPolicyViolations(
        password,
        {
            minimumLength: settings.passwordMinLength,
            maximumLength: settings.passwordMaxLength,
            requireUppercase: settings.passwordRequireUppercase,
            requireLowercase: settings.passwordRequireLowercase,
            requireNumber: settings.passwordRequireNumber,
            requireSymbol: settings.passwordRequireSymbol,
        },
    );

    if (policyViolations.length > 0) {
        throw new AppError(
            400,
            "AUTH_PASSWORD_POLICY_VIOLATION",
            "Password does not comply with the password policy.",
            policyViolations,
        );
    }

    const passwordHash = await passwordService.hashPassword(password);
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const currentActivation = await activationRepository.findByTokenHash(
            tokenHash,
            client,
            true,
        );
        assertActivatable(currentActivation);

        const activated = await activationRepository.activateUser(
            client,
            currentActivation.userId,
            passwordHash,
            settings.currentTermsVersion,
            settings.currentPrivacyPolicyVersion,
        );
        if (!activated) {
            throw alreadyActivatedError();
        }

        await activationRepository.consumeTokenAndRevokeOthers(
            client,
            currentActivation.id,
            currentActivation.userId,
        );
        await activationRepository.enqueueActivatedNotification(
            client,
            currentActivation,
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

export async function issueActivationToken(
    userId: string,
): Promise<IssuedActivationToken> {
    const settings = await settingsRepository.getAuthSettings();
    const token = randomBytes(32).toString("base64url");
    const tokenHash = hashToken(token);
    const expiresAt = new Date(
        Date.now() + settings.activationTokenValidityHours * 60 * 60 * 1000,
    );
    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        const user = await userRepository.findByIdForUpdate(client, userId);

        if (!user || user.accountStatus !== ACCOUNT_STATUS.PENDING_ACTIVATION) {
            if (user?.accountStatus === ACCOUNT_STATUS.ACTIVE) {
                throw alreadyActivatedError();
            }

            throw new AppError(
                409,
                "AUTH_ACCOUNT_NOT_ACTIVATABLE",
                "This account cannot be activated.",
            );
        }

        await activationRepository.revokeUnusedTokens(client, userId);
        await activationRepository.createToken(
            client,
            userId,
            tokenHash,
            expiresAt,
        );
        await client.query("COMMIT");

        return { token, expiresAt };
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}
