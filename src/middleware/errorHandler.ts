import type { NextFunction, Request, Response } from "express";
import AppError from "../errors/AppError";

interface RequestBodyError extends Error {
    type?: string;
}

export function notFoundHandler(_req: Request, res: Response): void {
    res.status(404).json({
        success: false,
        error: {
            code: "ROUTE_NOT_FOUND",
            message: "Route not found.",
        },
    });
}

export function errorHandler(
    error: unknown,
    req: Request,
    res: Response,
    next: NextFunction,
): Response | void {
    if (res.headersSent) {
        next(error);
        return;
    }

    if (error instanceof AppError) {
        const payload: {
            success: false;
            error: {
                code: string;
                message: string;
                details?: unknown;
            };
        } = {
            success: false,
            error: {
                code: error.code,
                message: error.message,
            },
        };

        if (error.details !== undefined) {
            payload.error.details = error.details;
        }

        return res.status(error.statusCode).json(payload);
    }

    const requestBodyError = error as RequestBodyError;
    if (requestBodyError.type === "entity.parse.failed") {
        return res.status(400).json({
            success: false,
            error: {
                code: "INVALID_JSON",
                message: "The request body contains invalid JSON.",
            },
        });
    }

    if (requestBodyError.type === "entity.too.large") {
        return res.status(413).json({
            success: false,
            error: {
                code: "PAYLOAD_TOO_LARGE",
                message: "The request body is too large.",
            },
        });
    }

    console.error("Unhandled request error.", {
        method: req.method,
        path: req.originalUrl,
        error: error instanceof Error ? error.message : "Unknown error",
    });

    return res.status(500).json({
        success: false,
        error: {
            code: "INTERNAL_SERVER_ERROR",
            message: "An unexpected error occurred.",
        },
    });
}
