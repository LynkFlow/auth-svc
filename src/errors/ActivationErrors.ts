import AppError from "./AppError.js";

export class ActivationPasswordRequiredError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_ACTIVATION_PASSWORD_REQUIRED";

  constructor() {
    super("A password is required to activate this account.");
  }
}

export class ActivationTokenExpiredError extends AppError {
  readonly statusCode = 410;
  readonly code = "AUTH_ACTIVATION_TOKEN_EXPIRED";

  constructor() {
    super("The activation link has expired.");
  }
}

export class ActivationTokenInvalidError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_ACTIVATION_TOKEN_INVALID";

  constructor() {
    super("The activation link is invalid.");
  }
}
