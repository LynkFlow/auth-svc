import type { NextFunction, Request, RequestHandler, Response } from "express";
import { ForbiddenError } from "../errors/AuthorizationErrors.js";
import type { Guard } from "./Guard.js";

/**
 * The one adapter turning any Guard into Express middleware. Deliberately
 * the only place next()-calling and default-403-building logic lives --
 * every individual Guard only implements canActivate()/onDenied().
 */
export function useGuard(guard: Guard): RequestHandler {
  return function guardMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction,
  ): void {
    Promise.resolve(guard.canActivate(req))
      .then((allowed) => {
        if (allowed) {
          next();
          return;
        }

        next(guard.onDenied?.(req) ?? new ForbiddenError());
      })
      .catch(next);
  };
}
