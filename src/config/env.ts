import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const envPath = path.resolve(process.cwd(), ".env");
if (fs.existsSync(envPath)) {
    process.loadEnvFile(envPath);
}

function parseBoolean(value: unknown, defaultValue: boolean): unknown {
    if (value === undefined) {
        return defaultValue;
    }

    if (typeof value === "boolean") {
        return value;
    }

    if (value === "true") {
        return true;
    }

    if (value === "false") {
        return false;
    }

    return value;
}

function parseTrustProxy(value: string | undefined): boolean | number | string {
    if (value === undefined || value === "false") {
        return false;
    }

    if (value === "true") {
        return 1;
    }

    const numericValue = Number(value);
    return Number.isInteger(numericValue) && numericValue >= 0
        ? numericValue
        : value;
}

const envSchema = z
    .object({
        NODE_ENV: z
            .enum(["development", "test", "production"])
            .default("development"),
        PORT: z.coerce.number().int().min(1).max(65535).default(3000),
        DATABASE_URL: z
            .string()
            .min(1)
            .refine((value) => {
                try {
                    const url = new URL(value);
                    return ["postgres:", "postgresql:"].includes(url.protocol);
                } catch {
                    return false;
                }
            }, "DATABASE_URL must be a valid PostgreSQL URL"),
        REFRESH_COOKIE_NAME: z
            .string()
            .min(1)
            .max(64)
            .default("lf.refresh"),
        COOKIE_SECURE: z.preprocess(
            (value) =>
                parseBoolean(value, process.env.NODE_ENV === "production"),
            z.boolean(),
        ),
        COOKIE_SAME_SITE: z.enum(["strict", "lax"]).default("strict"),
        TRUST_PROXY: z.string().optional(),
        JWT_PRIVATE_KEY_PATH: z
            .string()
            .min(1)
            .default(".secrets/jwt-private.pem"),
        JWT_PUBLIC_KEY_PATH: z
            .string()
            .min(1)
            .default(".secrets/jwt-public.pem"),
        JWT_KEY_ID: z.string().min(1).max(128).default("lf-auth-rs256-v1"),
        JWT_ISSUER: z.string().min(1).default("lynkflow-auth"),
        JWT_AUDIENCE: z.string().min(1).default("lynkflow-api"),
        JWT_ACCESS_TOKEN_MINUTES: z.coerce
            .number()
            .int()
            .min(1)
            .max(60)
            .default(15),
        JWT_CLOCK_TOLERANCE_SECONDS: z.coerce
            .number()
            .int()
            .min(0)
            .max(60)
            .default(5),
        EMAIL_SERVICE_URL: z
            .string()
            .url()
            .default("http://localhost:3010/api/v1/emails/send"),
        EMAIL_LOCALE: z
            .string()
            .regex(/^[a-z]{2}(?:-[A-Z]{2})?$/)
            .default("en"),
        EMAIL_OUTBOX_POLL_INTERVAL_MS: z.coerce
            .number()
            .int()
            .min(250)
            .max(60_000)
            .default(2_000),
        EMAIL_OUTBOX_BATCH_SIZE: z.coerce
            .number()
            .int()
            .min(1)
            .max(100)
            .default(10),
        EMAIL_OUTBOX_MAX_ATTEMPTS: z.coerce
            .number()
            .int()
            .min(1)
            .max(100)
            .default(10),
        EMAIL_OUTBOX_LOCK_TIMEOUT_SECONDS: z.coerce
            .number()
            .int()
            .min(10)
            .max(3_600)
            .default(60),
        EMAIL_SERVICE_TIMEOUT_MS: z.coerce
            .number()
            .int()
            .min(500)
            .max(60_000)
            .default(10_000),
    })
    .superRefine((value, context) => {
        if (value.NODE_ENV === "production" && value.COOKIE_SECURE !== true) {
            context.addIssue({
                code: "custom",
                path: ["COOKIE_SECURE"],
                message: "COOKIE_SECURE must be true in production",
            });
        }

        if (
            value.EMAIL_OUTBOX_LOCK_TIMEOUT_SECONDS * 1_000 <=
            value.EMAIL_SERVICE_TIMEOUT_MS
        ) {
            context.addIssue({
                code: "custom",
                path: ["EMAIL_OUTBOX_LOCK_TIMEOUT_SECONDS"],
                message:
                    "EMAIL_OUTBOX_LOCK_TIMEOUT_SECONDS must exceed EMAIL_SERVICE_TIMEOUT_MS",
            });
        }
    });

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
    const names = parsed.error.issues
        .map((issue) => issue.path.join("."))
        .join(", ");
    throw new Error(`Invalid environment configuration: ${names}`);
}

const config = Object.freeze({
    nodeEnv: parsed.data.NODE_ENV,
    port: parsed.data.PORT,
    databaseUrl: parsed.data.DATABASE_URL,
    refreshCookieName: parsed.data.REFRESH_COOKIE_NAME,
    cookieSecure: parsed.data.COOKIE_SECURE,
    cookieSameSite: parsed.data.COOKIE_SAME_SITE,
    trustProxy: parseTrustProxy(parsed.data.TRUST_PROXY),
    jwtPrivateKeyPath: parsed.data.JWT_PRIVATE_KEY_PATH,
    jwtPublicKeyPath: parsed.data.JWT_PUBLIC_KEY_PATH,
    jwtKeyId: parsed.data.JWT_KEY_ID,
    jwtIssuer: parsed.data.JWT_ISSUER,
    jwtAudience: parsed.data.JWT_AUDIENCE,
    jwtAccessTokenMinutes: parsed.data.JWT_ACCESS_TOKEN_MINUTES,
    jwtClockToleranceSeconds: parsed.data.JWT_CLOCK_TOLERANCE_SECONDS,
    emailServiceUrl: parsed.data.EMAIL_SERVICE_URL,
    emailLocale: parsed.data.EMAIL_LOCALE,
    emailOutboxPollIntervalMs: parsed.data.EMAIL_OUTBOX_POLL_INTERVAL_MS,
    emailOutboxBatchSize: parsed.data.EMAIL_OUTBOX_BATCH_SIZE,
    emailOutboxMaxAttempts: parsed.data.EMAIL_OUTBOX_MAX_ATTEMPTS,
    emailOutboxLockTimeoutSeconds:
        parsed.data.EMAIL_OUTBOX_LOCK_TIMEOUT_SECONDS,
    emailServiceTimeoutMs: parsed.data.EMAIL_SERVICE_TIMEOUT_MS,
});

export default config;
