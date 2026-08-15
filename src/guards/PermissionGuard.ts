import type { Request } from "express";
import { AuthForbiddenError } from "../errors/AuthorizationErrors.js";
import type { Guard } from "./Guard.js";

/**
 * Class-based replacement for the old requirePermission() middleware that
 * lived in middleware/authorize.ts. That function was already unused dead
 * code (nothing imported it) -- this Guard is equally unwired today, kept
 * ready as a correct, real implementation for the first permission-gated
 * route auth-svc adds, per backend-conventions.md's Guards section.
 */
export class PermissionGuard implements Guard {
  constructor(private readonly permission: string) {}

  canActivate(req: Request): boolean {
    return req.auth?.permissions.includes(this.permission) ?? false;
  }

  onDenied(): AuthForbiddenError {
    return new AuthForbiddenError();
  }
}
