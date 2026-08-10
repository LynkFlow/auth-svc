import { createHash, randomBytes } from "node:crypto";
import pool from "../db/pool";
import * as userRepository from "../repositories/userRepository";
import * as sessionRepository from "../repositories/sessionRepository";
import * as settingsRepository from "../repositories/settingsRepository";
import AppError from "../errors/AppError";
import {
    ACCOUNT_STATUS,
    toPublicUser,
    type PublicUser,
    type UserRecord,
} from "../models/userModel";
import * as passwordService from "./passwordService";

interface LoginParameters {
    email: string;
    password: string;
    rememberMe: boolean;
    ipAddress: string | null;
    userAgent: string | null;
}

export interface LoginResult {
    user: PublicUser;
    session: {
        token: string;
        expiresAt: Date;
    };
}

const dummyHashPromise = passwordService.hashPassword(
    randomBytes(32).toString("base64url"),
);

function isCurrentlyLocked(user: UserRecord): boolean {
    return user.lockedUntil !== null && user.lockedUntil > new Date();
}

function statusErrorFor(user: UserRecord): AppError | null {
    switch (user.accountStatus) {
        case ACCOUNT_STATUS.PENDING_ACTIVATION:
            return new AppError(
                403,
                "AUTH_ACCOUNT_NOT_ACTIVATED",
                "Your account has not been activated.",
            );
        case ACCOUNT_STATUS.SUSPENDED:
            return new AppError(
                403,
                "AUTH_ACCOUNT_SUSPENDED",
                "Your account has been suspended. Please contact your administrator.",
            );
        case ACCOUNT_STATUS.INACTIVE:
            return new AppError(
                403,
                "AUTH_ACCOUNT_INACTIVE",
                "Your account is inactive. Please contact your administrator.",
            );
        case ACCOUNT_STATUS.ACTIVE:
            return null;
    }
}

function lockedError(lockedUntil: Date): AppError {
    return new AppError(
        423,
        "AUTH_ACCOUNT_LOCKED",
        "Your account has been locked due to multiple unsuccessful login attempts. Please try again later or reset your password.",
        { lockedUntil: lockedUntil.toISOString() },
    );
}

function invalidCredentialsError(): AppError {
    return new AppError(
        401,
        "AUTH_INVALID_CREDENTIALS",
        "Invalid email address or password.",
    );
}

function addMinutes(date: Date, minutes: number): Date {
    return new Date(date.getTime() + minutes * 60 * 1000);
}

function addDays(date: Date, days: number): Date {
    return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

export async function login({
    email,
    password,
    rememberMe,
    ipAddress,
    userAgent,
}: LoginParameters): Promise<LoginResult> {
    const [settings, user] = await Promise.all([
        settingsRepository.getAuthSettings(),
        userRepository.findByEmail(email),
    ]);

    const passwordHash = user?.passwordHash ?? (await dummyHashPromise);
    const passwordMatches = await passwordService.verifyPassword(
        passwordHash,
        password,
    );

    if (!user || !passwordMatches) {
        if (user && !isCurrentlyLocked(user)) {
            const failure = await userRepository.recordFailedLogin(
                user.id,
                settings.lockoutThreshold,
                settings.lockoutDurationMinutes,
            );

            if (failure?.lockedUntil) {
                throw lockedError(failure.lockedUntil);
            }
        }

        throw invalidCredentialsError();
    }

    if (isCurrentlyLocked(user)) {
        throw lockedError(user.lockedUntil as Date);
    }

    const accountStatusError = statusErrorFor(user);
    if (accountStatusError) {
        throw accountStatusError;
    }

    const now = new Date();
    const expiresAt = rememberMe
        ? addDays(now, settings.rememberMeAbsoluteTimeoutDays)
        : addMinutes(now, settings.sessionAbsoluteTimeoutMinutes);
    const idleExpiresAt = new Date(
        Math.min(
            expiresAt.getTime(),
            addMinutes(now, settings.sessionIdleTimeoutMinutes).getTime(),
        ),
    );
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest();
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const currentUser = await userRepository.findByIdForUpdate(
            client,
            user.id,
        );

        if (!currentUser || currentUser.passwordHash !== user.passwordHash) {
            throw invalidCredentialsError();
        }

        if (isCurrentlyLocked(currentUser)) {
            throw lockedError(currentUser.lockedUntil as Date);
        }

        const currentStatusError = statusErrorFor(currentUser);
        if (currentStatusError) {
            throw currentStatusError;
        }

        const loginUpdate = await userRepository.recordSuccessfulLogin(
            client,
            currentUser.id,
        );
        if (!loginUpdate) {
            throw new Error("The successful login could not be recorded.");
        }

        await sessionRepository.createSession(client, {
            userId: currentUser.id,
            tokenHash,
            expiresAt,
            idleExpiresAt,
            ipAddress,
            userAgent,
        });

        await client.query("COMMIT");

        currentUser.lastLoginAt = loginUpdate.lastLoginAt;

        return {
            user: toPublicUser(currentUser),
            session: {
                token,
                expiresAt,
            },
        };
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}
