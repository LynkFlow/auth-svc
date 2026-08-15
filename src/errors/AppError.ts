import type { ApiError } from "@lynkflow/types";

// A class hierarchy, not one class carrying a code string -- every
// distinct error is its own small named subclass (backend-conventions.md's
// "AppError: a class hierarchy, not one class with a code string").
abstract class AppError extends Error {
  abstract readonly statusCode: number;
  abstract readonly code: string;
  readonly isOperational = true;

  constructor(
    message: string,
    readonly details?: string[],
    readonly fieldErrors?: Record<string, string>,
  ) {
    super(message);
    this.name = new.target.name;
  }

  toApiError(): ApiError {
    return {
      code: this.code,
      status: this.statusCode,
      message: this.message,
      ...(this.details ? { details: this.details } : {}),
      ...(this.fieldErrors ? { fieldErrors: this.fieldErrors } : {}),
    };
  }
}

export default AppError;
