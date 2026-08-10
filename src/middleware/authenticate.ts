import { createHash } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import config from "../config/env";
import sessionCookieOptions from "../config/sessionCookie";
import { findActiveSession } from "../repositories/sessionRepository";
import AppError from "../errors/AppError";

export default async function authenticate(
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void> {
    const token: unknown = req.cookies[config.sessionCookieName];

    if (typeof token !== "string" || token.length === 0) {
        next(
            new AppError(
                401,
                "AUTH_SESSION_EXPIRED",
                "Your session has expired. Please log in again.",
            ),
        );
        return;
    }

    const tokenHash = createHash("sha256").update(token).digest();
    const session = await findActiveSession(tokenHash);

    if (!session) {
        res.clearCookie(config.sessionCookieName, sessionCookieOptions());
        next(
            new AppError(
                401,
                "AUTH_SESSION_EXPIRED",
                "Your session has expired. Please log in again.",
            ),
        );
        return;
    }

    req.auth = session;
    next();
}
