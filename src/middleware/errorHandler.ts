import type { NextFunction, Request, Response } from "express";
import type { ApiError } from "@lynkflow/types";
import AppError from "../errors/AppError.js";

interface RequestBodyError extends Error {
  type?: string;
}

// AppError's `details` carries either a flat string[] (e.g. password-policy
// violations) or a field-keyed record (validate.ts's VALIDATION_ERROR) --
// this routes each shape onto ApiError's matching field rather than assuming
// one or the other.
function isFieldErrors(value: unknown): value is Record<string, string> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every((entry) => typeof entry === "string")
  );
}

function toApiError(error: AppError): ApiError {
  const apiError: ApiError = {
    code: error.code,
    status: error.statusCode,
    message: error.message,
  };

  if (Array.isArray(error.details)) {
    apiError.details = error.details as string[];
  } else if (isFieldErrors(error.details)) {
    apiError.fieldErrors = error.details;
  }

  return apiError;
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

  if (error instanceof AppError) {
    return res
      .status(error.statusCode)
      .json({ success: false, error: toApiError(error) });
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

  console.error("Unhandled request error.", {
    method: req.method,
    path: req.originalUrl,
    error: error instanceof Error ? error.message : "Unknown error",
  });

  return res.status(500).json({
    success: false,
    error: {
      code: "INTERNAL_SERVER_ERROR",
      status: 500,
      message: "An unexpected error occurred.",
    } satisfies ApiError,
  });
}
