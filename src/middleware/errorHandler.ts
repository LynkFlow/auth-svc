import type { NextFunction, Request, Response } from "express";
import type { ApiError } from "@lynkflow/types";
import AppError from "../errors/AppError.js";

interface RequestBodyError extends Error {
  type?: string;
}

export function notFoundHandler(_req: Request, res: Response): void {
  res.status(404).json({
    success: false,
    error: {
      code: "ROUTE_NOT_FOUND",
      status: 404,
      message: "Route not found.",
    } satisfies ApiError,
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

  // Polymorphic -- every AppError subclass shapes its own ApiError via
  // toApiError() (backend-conventions.md's "AppError: a class hierarchy"
  // section).
  if (error instanceof AppError) {
    return res
      .status(error.statusCode)
      .json({ success: false, error: error.toApiError() });
  }

  const requestBodyError = error as RequestBodyError;
  if (requestBodyError.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      error: {
        code: "INVALID_JSON",
        status: 400,
        message: "The request body contains invalid JSON.",
      } satisfies ApiError,
    });
  }

  if (requestBodyError.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      error: {
        code: "PAYLOAD_TOO_LARGE",
        status: 413,
        message: "The request body is too large.",
      } satisfies ApiError,
    });
  }

  req.log.error(
    { method: req.method, path: req.originalUrl, err: error },
    "unhandled request error",
  );

  return res.status(500).json({
    success: false,
    error: {
      code: "INTERNAL_SERVER_ERROR",
      status: 500,
      message: "An unexpected error occurred.",
    } satisfies ApiError,
  });
}
