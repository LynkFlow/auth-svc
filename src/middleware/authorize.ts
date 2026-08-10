import type { NextFunction, Request, RequestHandler, Response } from "express";
import AppError from "../errors/AppError";

export function requirePermission(permission: string): RequestHandler {
    return function authorize(
        req: Request,
        _res: Response,
        next: NextFunction,
    ): void {
        if (!req.auth?.permissions.includes(permission)) {
            next(
                new AppError(
                    403,
                    "AUTH_FORBIDDEN",
                    "You do not have permission to perform this action.",
                ),
            );
            return;
        }

        next();
    };
}
