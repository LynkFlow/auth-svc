import AppError from "./AppError.js";

export class ValidationError extends AppError {
  readonly statusCode = 400;
  readonly code = "VALIDATION_ERROR";

  constructor(fieldErrors: Record<string, string>) {
    super("The request is invalid.", undefined, fieldErrors);
  }
}
