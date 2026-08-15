import type { Request } from "express";
import AppError from "../errors/AppError.js";
import {
  AccessTokenExpiredError,
  AccessTokenInvalidError,
  SessionExpiredError,
} from "../errors/TokenErrors.js";
import {
  AccessTokenVerificationError,
  type TokenService,
  type VerifiedAccessToken,
} from "../services/TokenService.js";
import type { SessionRepository } from "../repositories/SessionRepository.js";
import type { Guard } from "./Guard.js";

function bearerToken(req: Request): string | null {
  const authorization = req.get("authorization");
  if (!authorization || authorization.length > 8_192) {
    return null;
  }

  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  return match?.[1] ?? null;
}

function accessTokenError(expired: boolean): AppError {
  return expired ? new AccessTokenExpiredError() : new AccessTokenInvalidError();
}

/**
 * Class-based replacement for the old middleware/authenticate.ts. Denial
 * paths that need a *specific* AppError (an expired vs. invalid token, an
 * expired session) throw it directly from canActivate() -- useGuard()'s
 * .catch(next) delivers it unchanged, exactly like the old
 * next(accessTokenError(...))/next(sessionExpiredError()) calls did.
 * onDenied() only covers the generic "no token at all" case, where
 * canActivate() returns false rather than throwing.
 */
export class AuthGuard implements Guard {
  constructor(
    private readonly tokenService: TokenService,
    private readonly sessionRepository: SessionRepository,
  ) {}

  async canActivate(req: Request): Promise<boolean> {
    const token = bearerToken(req);
    if (!token) {
      return false;
    }

    let principal: VerifiedAccessToken;
    try {
      principal = await this.tokenService.verifyAccessToken(token);
    } catch (error) {
      if (error instanceof AccessTokenVerificationError) {
        throw accessTokenError(error.reason === "expired");
      }
      throw error;
    }

    const session = await this.sessionRepository.findActiveSessionById(
      principal.sessionId,
      principal.userId,
    );

    if (!session) {
      throw new SessionExpiredError();
    }

    req.auth = session;
    return true;
  }

  onDenied(): AppError {
    return accessTokenError(false);
  }
}
