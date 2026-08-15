import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { Db } from "../db/schema.js";
import AppError from "../errors/AppError.js";
import {
  AccountInactiveError,
  AccountLockedError,
  AccountNotActivatedError,
  AccountSuspendedError,
} from "../errors/AccountStateErrors.js";
import { InvalidCredentialsError } from "../errors/CredentialErrors.js";
import { RefreshTokenInvalidError, RefreshTokenReusedError } from "../errors/TokenErrors.js";
import {
  ACCOUNT_STATUS,
  toPublicUser,
  type PublicUser,
  type UserRecord,
} from "../models/userModel.js";
import type { UserRepository } from "../repositories/UserRepository.js";
import type {
  RefreshSession,
  SessionRepository,
} from "../repositories/SessionRepository.js";
import type { SettingsRepository } from "../repositories/SettingsRepository.js";
import * as passwordService from "./passwordService.js";
import type { IssuedAccessToken, TokenService } from "./TokenService.js";

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

/**
 * Outcome of the refresh transaction, resolved *after* the transaction has
 * committed -- see refreshAuthentication()'s own docblock for why this
 * can't just throw from inside the transaction callback for every failure
 * path.
 */
type RefreshOutcome =
  | { kind: "success"; session: RefreshSession; nextRefreshToken: string }
  | { kind: "invalid" }
  | { kind: "reused" };

function isCurrentlyLocked(user: UserRecord): boolean {
  return user.lockedUntil !== null && user.lockedUntil > new Date();
}

function statusErrorFor(user: UserRecord): AppError | null {
  switch (user.accountStatus) {
    case ACCOUNT_STATUS.PENDING_ACTIVATION:
      return new AccountNotActivatedError();
    case ACCOUNT_STATUS.SUSPENDED:
      return new AccountSuspendedError();
    case ACCOUNT_STATUS.INACTIVE:
      return new AccountInactiveError();
    case ACCOUNT_STATUS.ACTIVE:
      return null;
  }
}

function lockedError(lockedUntil: Date): AppError {
  return new AccountLockedError(lockedUntil);
}

function invalidCredentialsError(): AppError {
  return new InvalidCredentialsError();
}

function invalidRefreshTokenError(): AppError {
  return new RefreshTokenInvalidError();
}

function reusedRefreshTokenError(): AppError {
  return new RefreshTokenReusedError();
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

export class AuthService {
  private readonly dummyHashPromise: Promise<string>;

  constructor(
    private readonly db: Db,
    private readonly userRepository: UserRepository,
    private readonly sessionRepository: SessionRepository,
    private readonly settingsRepository: SettingsRepository,
    private readonly tokenService: TokenService,
  ) {
    this.dummyHashPromise = passwordService.hashPassword(
      randomBytes(32).toString("base64url"),
    );
  }

  async login({
    email,
    password,
    rememberMe,
    ipAddress,
    userAgent,
  }: LoginParameters): Promise<LoginResult> {
    const [settings, user] = await Promise.all([
      this.settingsRepository.getAuthSettings(),
      this.userRepository.findByEmail(email),
    ]);

    const passwordHash = user?.passwordHash ?? (await this.dummyHashPromise);
    const passwordMatches = await passwordService.verifyPassword(passwordHash, password);

    if (!user || !passwordMatches) {
      if (user && !isCurrentlyLocked(user)) {
        const failure = await this.userRepository.recordFailedLogin(
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

    return this.db.transaction().execute(async (trx) => {
      const currentUser = await this.userRepository.findByIdForUpdate(trx, user.id);

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

      const loginUpdate = await this.userRepository.recordSuccessfulLogin(
        trx,
        currentUser.id,
      );
      if (!loginUpdate) {
        throw new Error("The successful login could not be recorded.");
      }

      await this.sessionRepository.createSession(trx, {
        id: sessionId,
        userId: currentUser.id,
        refreshTokenHash,
        expiresAt,
        idleExpiresAt,
        isPersistent: rememberMe,
        ipAddress,
        userAgent,
      });
      const accessToken = await this.tokenService.issueAccessToken({
        userId: currentUser.id,
        sessionId,
        roleCode: currentUser.roleCode,
        permissions: currentUser.permissions,
      });

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
    });
  }

  /**
   * Two failure paths here (session gone/inactive, or a refresh token that
   * was already used once before) must still *persist* a session revoke
   * even though the call ultimately reports failure to the caller -- the
   * original raw-SQL version did this by committing the transaction and
   * only then throwing. Kysely's `transaction().execute()` always rolls
   * back on a thrown error, so those two paths instead resolve to a
   * discriminated outcome and commit normally; the actual AppError is
   * thrown after the transaction has settled, based on that outcome. The
   * one path that must NOT persist anything (a stale, not-reused refresh
   * token) still throws directly from inside the callback, which rolls
   * back exactly as before.
   */
  async refreshAuthentication(refreshToken: string): Promise<AuthenticationResult> {
    const tokenDetails = parseRefreshToken(refreshToken);
    if (!tokenDetails) {
      throw invalidRefreshTokenError();
    }

    const tokenHash = hashRefreshToken(refreshToken);

    const outcome = await this.db.transaction().execute(
      async (trx): Promise<RefreshOutcome> => {
        const session = await this.sessionRepository.findRefreshSessionForUpdate(
          trx,
          tokenDetails.sessionId,
        );

        if (!session || !refreshSessionIsActive(session)) {
          if (session?.revokedAt === null) {
            await this.sessionRepository.revokeSession(tokenDetails.sessionId, trx);
          }

          return { kind: "invalid" };
        }

        const tokenIsCurrent =
          tokenDetails.generation === session.refreshGeneration &&
          hashesMatch(tokenHash, session.refreshTokenHash);

        if (!tokenIsCurrent) {
          const tokenWasUsed = await this.sessionRepository.wasRefreshTokenUsed(
            trx,
            session.sessionId,
            tokenHash,
          );

          if (tokenWasUsed) {
            await this.sessionRepository.revokeSession(session.sessionId, trx);
            return { kind: "reused" };
          }

          throw invalidRefreshTokenError();
        }

        const nextGeneration = session.refreshGeneration + 1;
        const nextRefreshToken = createRefreshToken(session.sessionId, nextGeneration);
        const rotated = await this.sessionRepository.rotateRefreshToken(
          trx,
          session.sessionId,
          session.refreshGeneration,
          hashRefreshToken(nextRefreshToken),
        );
        if (!rotated) {
          throw invalidRefreshTokenError();
        }

        return { kind: "success", session, nextRefreshToken };
      },
    );

    if (outcome.kind === "invalid") {
      throw invalidRefreshTokenError();
    }
    if (outcome.kind === "reused") {
      throw reusedRefreshTokenError();
    }

    const accessToken = await this.tokenService.issueAccessToken({
      userId: outcome.session.userId,
      sessionId: outcome.session.sessionId,
      roleCode: outcome.session.roleCode,
      permissions: outcome.session.permissions,
    });

    return {
      accessToken,
      refreshToken: {
        token: outcome.nextRefreshToken,
        expiresAt: outcome.session.expiresAt,
        isPersistent: outcome.session.isPersistent,
      },
    };
  }

  /**
   * Returns the affected user's ID when a valid/revocable session was
   * found, or null otherwise -- logout is idempotent and always succeeds
   * from the caller's perspective either way, but the controller needs
   * the userId (when there is one) to attach to its audit-log entry.
   */
  async logout(refreshToken: string): Promise<string | null> {
    const tokenDetails = parseRefreshToken(refreshToken);
    if (!tokenDetails) {
      return null;
    }

    const tokenHash = hashRefreshToken(refreshToken);

    return this.db.transaction().execute(async (trx) => {
      const session = await this.sessionRepository.findRefreshSessionForUpdate(
        trx,
        tokenDetails.sessionId,
      );

      let userId: string | null = null;

      if (session) {
        const tokenIsCurrent =
          tokenDetails.generation === session.refreshGeneration &&
          hashesMatch(tokenHash, session.refreshTokenHash);
        const tokenWasUsed = tokenIsCurrent
          ? false
          : await this.sessionRepository.wasRefreshTokenUsed(
              trx,
              session.sessionId,
              tokenHash,
            );

        if (tokenIsCurrent || tokenWasUsed) {
          await this.sessionRepository.revokeSession(session.sessionId, trx);
          userId = session.userId;
        }
      }

      return userId;
    });
  }
}
