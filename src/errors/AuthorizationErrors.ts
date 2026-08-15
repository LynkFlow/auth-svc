import AppError from "./AppError.js";

/** useGuard()'s generic fallback when a Guard denies with no onDenied(). */
export class ForbiddenError extends AppError {
  readonly statusCode = 403;
  readonly code = "FORBIDDEN";

  constructor() {
    super("You do not have permission to perform this action.");
  }
}

/** PermissionGuard's specific denial -- distinct code from ForbiddenError's generic useGuard() fallback. */
export class AuthForbiddenError extends AppError {
  readonly statusCode = 403;
  readonly code = "AUTH_FORBIDDEN";

  constructor() {
    super("You do not have permission to perform this action.");
  }
}
