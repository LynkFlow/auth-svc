import type { CookieOptions } from "express";
import config from "./env";

export default function sessionCookieOptions(): CookieOptions {
    return {
        httpOnly: true,
        secure: config.cookieSecure,
        sameSite: config.cookieSameSite,
        path: "/",
        priority: "high",
    };
}
