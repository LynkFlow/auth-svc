import type { CookieOptions } from "express";
import config from "./env";

export default function refreshCookieOptions(): CookieOptions {
    return {
        httpOnly: true,
        secure: config.cookieSecure,
        sameSite: config.cookieSameSite,
        path: "/api/v1/auth/token",
        priority: "high",
    };
}
