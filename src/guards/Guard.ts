import type { Request } from "express";
import type AppError from "../errors/AppError.js";

/**
 * A reusable, stateless allow/deny check against a request. See
 * backend-conventions.md's "Guards" section -- this is the class-based
 * replacement for one-off inline auth/permission middleware.
 */
export interface Guard {
  canActivate(req: Request): boolean | Promise<boolean>;
  /** Called when canActivate resolves false. Optional -- useGuard() defaults to a generic 403. */
  onDenied?(req: Request): AppError;
}
