import AppError from "./AppError.js";

export class AccountInactiveError extends AppError {
  readonly statusCode = 403;
  readonly code = "AUTH_ACCOUNT_INACTIVE";

  constructor() {
    super("Your account is inactive. Please contact your administrator.");
  }
}

/**
 * Carries lockedUntil as a field-keyed error, matching the previous
 * AppError's `{ lockedUntil }` details object, which the old errorHandler's
 * isFieldErrors() check (every value a string) already routed onto
 * ApiError.fieldErrors -- not ApiError.details. Preserved here explicitly
 * rather than switched to the array `details` slot.
 */
export class AccountLockedError extends AppError {
  readonly statusCode = 423;
  readonly code = "AUTH_ACCOUNT_LOCKED";

  constructor(lockedUntil: Date) {
    super(
      "Your account has been locked due to multiple unsuccessful login attempts. Please try again later or reset your password.",
      undefined,
      { lockedUntil: lockedUntil.toISOString() },
    );
  }
}

export class AccountNotActivatedError extends AppError {
  readonly statusCode = 403;
  readonly code = "AUTH_ACCOUNT_NOT_ACTIVATED";

  constructor() {
    super("Your account has not been activated.");
  }
}

export class AccountSuspendedError extends AppError {
  readonly statusCode = 403;
  readonly code = "AUTH_ACCOUNT_SUSPENDED";

  constructor() {
    super("Your account has been suspended. Please contact your administrator.");
  }
}

/**
 * Carries loginPath as a field-keyed error, matching the previous
 * AppError's `{ loginPath }` details object, which the old errorHandler's
 * isFieldErrors() check already routed onto ApiError.fieldErrors --
 * test/auth.activation.test.ts asserts
 * `error.fieldErrors.loginPath === "/login"` directly, so this shape is
 * load-bearing, not incidental.
 */
export class AccountAlreadyActiveError extends AppError {
  readonly statusCode = 409;
  readonly code = "AUTH_ACCOUNT_ALREADY_ACTIVE";

  constructor() {
    super("This account has already been activated.", undefined, { loginPath: "/login" });
  }
}

export class AccountNotActivatableError extends AppError {
  readonly statusCode = 409;
  readonly code = "AUTH_ACCOUNT_NOT_ACTIVATABLE";

  constructor() {
    super("This account cannot be activated.");
  }
}
