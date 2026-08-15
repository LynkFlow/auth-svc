import AppError from "./AppError.js";

export class AccessTokenExpiredError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_ACCESS_TOKEN_EXPIRED";

  constructor() {
    super("Your access token has expired. Refresh it and try again.");
  }
}

export class AccessTokenInvalidError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_ACCESS_TOKEN_INVALID";

  constructor() {
    super("A valid Bearer access token is required.");
  }
}

export class RefreshTokenInvalidError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_REFRESH_TOKEN_INVALID";

  constructor() {
    super("Your refresh session is invalid or has expired. Please log in again.");
  }
}

export class RefreshTokenReusedError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_REFRESH_TOKEN_REUSED";

  constructor() {
    super("Refresh token reuse was detected. Please log in again.");
  }
}

/** Shared by AuthGuard (no active session for a verified token) and PasswordManagementService.changePassword (stale session). */
export class SessionExpiredError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_SESSION_EXPIRED";

  constructor() {
    super("Your session has expired. Please log in again.");
  }
}
