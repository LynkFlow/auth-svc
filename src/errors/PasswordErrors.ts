import AppError from "./AppError.js";

export class CurrentPasswordIncorrectError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_CURRENT_PASSWORD_INCORRECT";

  constructor() {
    super("Current password is incorrect.");
  }
}

/** Shared by ActivationService, PasswordManagementService, and SignupService -- same code/status/message, only the violation list differs. */
export class PasswordPolicyViolationError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_PASSWORD_POLICY_VIOLATION";

  constructor(violations: string[]) {
    super("Password does not comply with the password policy.", violations);
  }
}

export class PasswordResetTokenExpiredError extends AppError {
  readonly statusCode = 410;
  readonly code = "AUTH_PASSWORD_RESET_TOKEN_EXPIRED";

  constructor() {
    super("Password reset link has expired.");
  }
}

export class PasswordResetTokenInvalidError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_PASSWORD_RESET_TOKEN_INVALID";

  constructor() {
    super("Password reset link is invalid.");
  }
}

export class PasswordUnchangedError extends AppError {
  readonly statusCode = 400;
  readonly code = "AUTH_PASSWORD_UNCHANGED";

  constructor() {
    super("Your new password cannot be the same as your current password.");
  }
}
