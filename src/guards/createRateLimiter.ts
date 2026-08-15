import { rateLimit, type RateLimitRequestHandler } from "express-rate-limit";
import type { Request } from "express";

export interface RateLimiterOptions {
  windowMs: number;
  limit: number;
  keyGenerator?: (req: Request) => string;
  /**
   * Only count failed requests toward the limit -- e.g. the login limiter
   * deliberately doesn't penalize repeated successful logins, only
   * repeated failures. Not part of the original template-svc reference
   * (its example had no consumer that needed this), added here because
   * auth-svc's own loginLimiter relied on it before this factory existed
   * and preserving that behavior exactly is required.
   */
  skipSuccessfulRequests?: boolean;
}

/**
 * Rate limiting is NOT a Guard -- express-rate-limit is stateful (it
 * counts requests over a window), unlike a Guard's stateless per-request
 * canActivate() check. This factory exists purely to stop copy-pasting a
 * near-identical rateLimit({...}) block per route (see
 * backend-conventions.md's "Rate limiting is NOT a Guard" section for the
 * real example this fixed in auth-svc).
 */
export function createRateLimiter(
  code: string,
  message: string,
  options: RateLimiterOptions,
): RateLimitRequestHandler {
  return rateLimit({
    ...options,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({ success: false, error: { code, message } });
    },
  });
}
