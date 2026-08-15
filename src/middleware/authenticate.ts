import type { NextFunction, Request, Response } from "express";
import { findActiveSessionById } from "../repositories/sessionRepository.js";
import AppError from "../errors/AppError.js";
import {
  AccessTokenVerificationError,
  verifyAccessToken,
} from "../services/tokenService.js";

function accessTokenError(expired = false): AppError {
  return new AppError(
    401,
    expired ? "AUTH_ACCESS_TOKEN_EXPIRED" : "AUTH_ACCESS_TOKEN_INVALID",
    expired
      ? "Your access token has expired. Refresh it and try again."
      : "A valid Bearer access token is required.",
  );
}

function sessionExpiredError(): AppError {
  return new AppError(
    401,
    "AUTH_SESSION_EXPIRED",
    "Your session has expired. Please log in again.",
  );
}

function bearerToken(req: Request): string | null {
  const authorization = req.get("authorization");
  if (!authorization || authorization.length > 8_192) {
    return null;
  }

  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  return match?.[1] ?? null;
}

export default async function authenticate(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  const token = bearerToken(req);
  if (!token) {
    next(accessTokenError());
    return;
  }

  try {
    const principal = await verifyAccessToken(token);
    const session = await findActiveSessionById(principal.sessionId, principal.userId);

    if (!session) {
      next(sessionExpiredError());
      return;
    }

    req.auth = session;
    next();
  } catch (error) {
    if (error instanceof AccessTokenVerificationError) {
      next(accessTokenError(error.reason === "expired"));
      return;
    }

    next(error);
  }
}
