import express, { type NextFunction, type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import {
    completeActivation,
    login,
    validateActivation,
} from "../controllers/authController";
import validate from "../middleware/validate";
import {
    completeActivationSchema,
    loginSchema,
    validateActivationSchema,
} from "../validators/authSchemas";

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

router.post("/login", loginLimiter, validate(loginSchema), login);
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

export default router;
