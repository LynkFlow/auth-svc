import type { CookieOptions, Request, Response } from "express";
import { login as loginUser } from "../services/authService";
import config from "../config/env";
import type { LoginInput } from "../validators/authSchemas";

export async function login(req: Request, res: Response): Promise<Response> {
    const userAgent = req.get("user-agent");
    const body = req.validatedBody as LoginInput;

    const result = await loginUser({
        email: body.email,
        password: body.password,
        rememberMe: body.rememberMe,
        ipAddress: req.ip ?? null,
        userAgent: userAgent ? userAgent.slice(0, 512) : null,
    });

    const cookieOptions: CookieOptions = {
        httpOnly: true,
        secure: config.cookieSecure,
        sameSite: config.cookieSameSite,
        path: "/",
        priority: "high",
    };

    if (body.rememberMe) {
        cookieOptions.expires = result.session.expiresAt;
    }

    res.cookie(config.sessionCookieName, result.session.token, cookieOptions);

    return res.status(200).json({
        success: true,
        message: "Login successful.",
        data: {
            user: result.user,
            session: {
                expiresAt: result.session.expiresAt.toISOString(),
            },
        },
    });
}
