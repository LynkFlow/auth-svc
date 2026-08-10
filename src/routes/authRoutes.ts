import express, { type NextFunction, type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import {
    changePassword,
    completeActivation,
    forgotPassword,
    login,
    logout,
    resetPassword,
    validateActivation,
    validatePasswordReset,
} from "../controllers/authController";
import authenticate from "../middleware/authenticate";
import validate from "../middleware/validate";
import {
    changePasswordSchema,
    completeActivationSchema,
    forgotPasswordSchema,
    loginSchema,
    resetPasswordSchema,
    validateActivationSchema,
    validatePasswordResetSchema,
} from "../validators/authSchemas";
import type { ForgotPasswordInput } from "../validators/authSchemas";

const router = express.Router();

router.use((_req: Request, res: Response, next: NextFunction) => {
    res.set("Cache-Control", "no-store");
    res.set("Pragma", "no-cache");
    next();
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (_req: Request, res: Response) => {
        res.status(429).json({
            success: false,
            error: {
                code: "AUTH_RATE_LIMITED",
                message: "Too many login attempts. Please try again later.",
            },
        });
    },
});

const activationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
        res.status(429).json({
            success: false,
            error: {
                code: "AUTH_ACTIVATION_RATE_LIMITED",
                message:
                    "Too many activation attempts. Please try again later.",
            },
        });
    },
});

const forgotPasswordIpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
        res.status(429).json({
            success: false,
            error: {
                code: "AUTH_PASSWORD_RESET_RATE_LIMITED",
                message:
                    "Too many password reset requests. Please try again later.",
            },
        });
    },
});

const forgotPasswordEmailLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 3,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    keyGenerator: (req: Request) =>
        (req.validatedBody as ForgotPasswordInput).email,
    handler: (_req: Request, res: Response) => {
        res.status(202).json({
            success: true,
            message:
                "If the email address exists in our system, a password reset link has been sent.",
        });
    },
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
        res.status(429).json({
            success: false,
            error: {
                code: "AUTH_PASSWORD_RESET_RATE_LIMITED",
                message:
                    "Too many password reset attempts. Please try again later.",
            },
        });
    },
});

const changePasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
        res.status(429).json({
            success: false,
            error: {
                code: "AUTH_CHANGE_PASSWORD_RATE_LIMITED",
                message:
                    "Too many password change attempts. Please try again later.",
            },
        });
    },
});

router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/logout", authenticate, logout);
router.post(
    "/activation/validate",
    activationLimiter,
    validate(validateActivationSchema),
    validateActivation,
);
router.post(
    "/activation/complete",
    activationLimiter,
    validate(completeActivationSchema),
    completeActivation,
);
router.post(
    "/password/forgot",
    forgotPasswordIpLimiter,
    validate(forgotPasswordSchema),
    forgotPasswordEmailLimiter,
    forgotPassword,
);
router.post(
    "/password/reset/validate",
    passwordResetLimiter,
    validate(validatePasswordResetSchema),
    validatePasswordReset,
);
router.post(
    "/password/reset",
    passwordResetLimiter,
    validate(resetPasswordSchema),
    resetPassword,
);
router.post(
    "/password/change",
    changePasswordLimiter,
    authenticate,
    validate(changePasswordSchema),
    changePassword,
);

export default router;
