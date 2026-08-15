import express, {
  type NextFunction,
  type Request,
  type Response,
  type Router,
} from "express";
import { rateLimit } from "express-rate-limit";
import type { AuthController } from "../controllers/AuthController.js";
import type { AuthGuard } from "../guards/AuthGuard.js";
import { createRateLimiter } from "../guards/createRateLimiter.js";
import { useGuard } from "../guards/useGuard.js";
import validate from "../middleware/validate.js";
import {
  changePasswordSchema,
  completeActivationSchema,
  forgotPasswordSchema,
  loginSchema,
  resetPasswordSchema,
  signupSchema,
  validateActivationSchema,
  validatePasswordResetSchema,
} from "../validators/authSchemas.js";
import type { ForgotPasswordInput } from "../validators/authSchemas.js";

export function createAuthRoutes(
  authController: AuthController,
  authGuard: AuthGuard,
): Router {
  const router = express.Router();

  router.use((_req: Request, res: Response, next: NextFunction) => {
    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    next();
  });

  const loginLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many login attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 20, skipSuccessfulRequests: true },
  );

  const signupLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many sign-up attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 10 },
  );

  const activationLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many activation attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 30 },
  );

  const refreshTokenLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many token refresh attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 60 },
  );

  const forgotPasswordIpLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many password reset requests. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 10 },
  );

  // Deliberately NOT createRateLimiter. This one keys per-email (not
  // per-IP) and, once the limit is hit, still returns the same 202 "if
  // this email exists..." response as a normal request -- not a 429. A
  // 429 here would itself leak that the email address is enumerable (an
  // attacker could tell a real account from a fake one purely by whether
  // they get rate-limited on repeated attempts), which is exactly what
  // forgotPassword's deliberately-ambiguous 202 response already exists to
  // avoid. createRateLimiter's handler always returns 429 -- reusing it
  // would silently reintroduce that leak, so this stays hand-written. See
  // backend-conventions.md's "Rate limiting is NOT a Guard" section.
  const forgotPasswordEmailLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 3,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    keyGenerator: (req: Request) => (req.validatedBody as ForgotPasswordInput).email,
    handler: (_req: Request, res: Response) => {
      res.status(202).json({
        success: true,
        message:
          "If the email address exists in our system, a password reset link has been sent.",
      });
    },
  });

  const passwordResetLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many password reset attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 20 },
  );

  const changePasswordLimiter = createRateLimiter(
    "AUTH_RATE_LIMITED",
    "Too many password change attempts. Please try again later.",
    { windowMs: 15 * 60 * 1000, limit: 10 },
  );

  router.post(
    "/signup",
    signupLimiter,
    validate(signupSchema),
    authController.signup,
  );
  router.post("/login", loginLimiter, validate(loginSchema), authController.login);
  router.post(
    "/token/refresh",
    refreshTokenLimiter,
    authController.refreshToken,
  );
  router.post("/token/logout", authController.logout);
  router.post(
    "/activation/validate",
    activationLimiter,
    validate(validateActivationSchema),
    authController.validateActivation,
  );
  router.post(
    "/activation/complete",
    activationLimiter,
    validate(completeActivationSchema),
    authController.completeActivation,
  );
  router.post(
    "/password/forgot",
    forgotPasswordIpLimiter,
    validate(forgotPasswordSchema),
    forgotPasswordEmailLimiter,
    authController.forgotPassword,
  );
  router.post(
    "/password/reset/validate",
    passwordResetLimiter,
    validate(validatePasswordResetSchema),
    authController.validatePasswordReset,
  );
  router.post(
    "/password/reset",
    passwordResetLimiter,
    validate(resetPasswordSchema),
    authController.resetPassword,
  );
  router.post(
    "/password/change",
    changePasswordLimiter,
    useGuard(authGuard),
    validate(changePasswordSchema),
    authController.changePassword,
  );

  return router;
}
