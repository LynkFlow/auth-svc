import AppError from "./AppError.js";

export class InvalidCredentialsError extends AppError {
  readonly statusCode = 401;
  readonly code = "AUTH_INVALID_CREDENTIALS";

  constructor() {
    super("Invalid email address or password.");
  }
}

/** Same field-keyed loginPath shape as AccountAlreadyActiveError -- see that class's docblock in AccountStateErrors.ts. */
export class EmailAlreadyRegisteredError extends AppError {
  readonly statusCode = 409;
  readonly code = "AUTH_EMAIL_ALREADY_REGISTERED";

  constructor() {
    super("An account with this email address already exists.", undefined, {
      loginPath: "/login",
    });
  }
}
