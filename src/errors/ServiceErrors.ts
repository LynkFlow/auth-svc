import AppError from "./AppError.js";

export class ServiceNotReadyError extends AppError {
  readonly statusCode = 503;
  readonly code = "SERVICE_NOT_READY";

  constructor() {
    super("The service is not ready to accept traffic.");
  }
}
