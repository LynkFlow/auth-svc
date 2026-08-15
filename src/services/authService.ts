import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import pool from "../db/pool.js";
import * as userRepository from "../repositories/userRepository.js";
import * as sessionRepository from "../repositories/sessionRepository.js";
import type { RefreshSession } from "../repositories/sessionRepository.js";
import * as settingsRepository from "../repositories/settingsRepository.js";
import AppError from "../errors/AppError.js";
import {
  ACCOUNT_STATUS,
  toPublicUser,
  type PublicUser,
  type UserRecord,
} from "../models/userModel.js";
import * as passwordService from "./passwordService.js";
import { issueAccessToken } from "./tokenService.js";
import type { IssuedAccessToken } from "./tokenService.js";

interface LoginParameters {
  email: string;
  password: string;
  rememberMe: boolean;
  ipAddress: string | null;
  userAgent: string | null;
}

interface RefreshTokenDetails {
  sessionId: string;
  generation: number;
}

interface RefreshCredential {
  token: string;
  expiresAt: Date;
  isPersistent: boolean;
}

export interface AuthenticationResult {
  accessToken: IssuedAccessToken;
  refreshToken: RefreshCredential;
}

export interface LoginResult extends AuthenticationResult {
  user: PublicUser;
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

function invalidRefreshTokenError(): AppError {
  return new AppError(
    401,
    "AUTH_REFRESH_TOKEN_INVALID",
    "Your refresh session is invalid or has expired. Please log in again.",
  );
}

function reusedRefreshTokenError(): AppError {
  return new AppError(
    401,
    "AUTH_REFRESH_TOKEN_REUSED",
    "Refresh token reuse was detected. Please log in again.",
  );
}

function addMinutes(date: Date, minutes: number): Date {
  return new Date(date.getTime() + minutes * 60 * 1_000);
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1_000);
}

function hashRefreshToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function createRefreshToken(sessionId: string, generation: number): string {
  return `${sessionId}.${generation}.${randomBytes(32).toString("base64url")}`;
}

function parseRefreshToken(token: string): RefreshTokenDetails | null {
  if (token.length > 160) {
    return null;
  }

  const [sessionId, generationText, secret, ...extra] = token.split(".");
  if (
    extra.length > 0 ||
    sessionId === undefined ||
    generationText === undefined ||
    secret === undefined ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      sessionId,
    ) ||
    !/^\d{1,10}$/.test(generationText) ||
    !/^[A-Za-z0-9_-]{43}$/.test(secret)
  ) {
    return null;
  }

  const generation = Number(generationText);
  if (!Number.isSafeInteger(generation) || generation > 2_147_483_647) {
    return null;
  }

  return { sessionId, generation };
}

function refreshSessionIsActive(session: RefreshSession, now = new Date()): boolean {
  return (
    session.revokedAt === null &&
    session.expiresAt > now &&
    session.idleExpiresAt > now &&
    session.accountStatus === ACCOUNT_STATUS.ACTIVE &&
    (session.lockedUntil === null || session.lockedUntil <= now)
  );
}

function hashesMatch(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
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
  const passwordMatches = await passwordService.verifyPassword(passwordHash, password);

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
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken(sessionId, 0);
  const refreshTokenHash = hashRefreshToken(refreshToken);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const currentUser = await userRepository.findByIdForUpdate(client, user.id);

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
      id: sessionId,
      userId: currentUser.id,
      refreshTokenHash,
      expiresAt,
      idleExpiresAt,
      isPersistent: rememberMe,
      ipAddress,
      userAgent,
    });
    const accessToken = await issueAccessToken({
      userId: currentUser.id,
      sessionId,
      roleCode: currentUser.roleCode,
      permissions: currentUser.permissions,
    });

    await client.query("COMMIT");

    currentUser.lastLoginAt = loginUpdate.lastLoginAt;

    return {
      user: toPublicUser(currentUser),
      accessToken,
      refreshToken: {
        token: refreshToken,
        expiresAt,
        isPersistent: rememberMe,
      },
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function refreshAuthentication(
  refreshToken: string,
): Promise<AuthenticationResult> {
  const tokenDetails = parseRefreshToken(refreshToken);
  if (!tokenDetails) {
    throw invalidRefreshTokenError();
  }

  const tokenHash = hashRefreshToken(refreshToken);
  const client = await pool.connect();
  let transactionOpen = false;

  try {
    await client.query("BEGIN");
    transactionOpen = true;

    const session = await sessionRepository.findRefreshSessionForUpdate(
      client,
      tokenDetails.sessionId,
    );

    if (!session || !refreshSessionIsActive(session)) {
      if (session?.revokedAt === null) {
        await sessionRepository.revokeSession(tokenDetails.sessionId, client);
      }

      await client.query("COMMIT");
      transactionOpen = false;
      throw invalidRefreshTokenError();
    }

    const tokenIsCurrent =
      tokenDetails.generation === session.refreshGeneration &&
      hashesMatch(tokenHash, session.refreshTokenHash);

    if (!tokenIsCurrent) {
      const tokenWasUsed = await sessionRepository.wasRefreshTokenUsed(
        client,
        session.sessionId,
        tokenHash,
      );

      if (tokenWasUsed) {
        await sessionRepository.revokeSession(session.sessionId, client);
        await client.query("COMMIT");
        transactionOpen = false;
        throw reusedRefreshTokenError();
      }

      throw invalidRefreshTokenError();
    }

    const nextGeneration = session.refreshGeneration + 1;
    const nextRefreshToken = createRefreshToken(session.sessionId, nextGeneration);
    const rotated = await sessionRepository.rotateRefreshToken(
      client,
      session.sessionId,
      session.refreshGeneration,
      hashRefreshToken(nextRefreshToken),
    );
    if (!rotated) {
      throw invalidRefreshTokenError();
    }

    const accessToken = await issueAccessToken({
      userId: session.userId,
      sessionId: session.sessionId,
      roleCode: session.roleCode,
      permissions: session.permissions,
    });

    await client.query("COMMIT");
    transactionOpen = false;

    return {
      accessToken,
      refreshToken: {
        token: nextRefreshToken,
        expiresAt: session.expiresAt,
        isPersistent: session.isPersistent,
      },
    };
  } catch (error) {
    if (transactionOpen) {
      await client.query("ROLLBACK");
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function logout(refreshToken: string): Promise<void> {
  const tokenDetails = parseRefreshToken(refreshToken);
  if (!tokenDetails) {
    return;
  }

  const tokenHash = hashRefreshToken(refreshToken);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const session = await sessionRepository.findRefreshSessionForUpdate(
      client,
      tokenDetails.sessionId,
    );

    if (session) {
      const tokenIsCurrent =
        tokenDetails.generation === session.refreshGeneration &&
        hashesMatch(tokenHash, session.refreshTokenHash);
      const tokenWasUsed = tokenIsCurrent
        ? false
        : await sessionRepository.wasRefreshTokenUsed(
            client,
            session.sessionId,
            tokenHash,
          );

      if (tokenIsCurrent || tokenWasUsed) {
        await sessionRepository.revokeSession(session.sessionId, client);
      }
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
