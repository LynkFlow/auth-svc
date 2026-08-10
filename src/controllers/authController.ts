import type { CookieOptions, Request, Response } from "express";
import {
    login as loginUser,
    logout as logoutUser,
} from "../services/authService";
import {
    completeActivation as activateAccount,
    validateActivationToken,
} from "../services/activationService";
import {
    changePassword as changeUserPassword,
    requestPasswordReset,
    resetPassword as resetUserPassword,
    validatePasswordResetToken,
} from "../services/passwordManagementService";
import config from "../config/env";
import sessionCookieOptions from "../config/sessionCookie";
import type {
    ChangePasswordInput,
    CompleteActivationInput,
    ForgotPasswordInput,
    LoginInput,
    ResetPasswordInput,
    ValidateActivationInput,
    ValidatePasswordResetInput,
} from "../validators/authSchemas";

export async function forgotPassword(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as ForgotPasswordInput;
    await requestPasswordReset(body.email);

    return res.status(202).json({
        success: true,
        message:
            "If the email address exists in our system, a password reset link has been sent.",
    });
}

export async function validatePasswordReset(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as ValidatePasswordResetInput;
    const reset = await validatePasswordResetToken(body.token);

    return res.status(200).json({
        success: true,
        message: "Password reset link is valid.",
        data: reset,
    });
}

export async function resetPassword(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as ResetPasswordInput;
    const result = await resetUserPassword(body.token, body.newPassword);

    res.clearCookie(config.sessionCookieName, sessionCookieOptions());
    return res.status(200).json({
        success: true,
        message:
            "Your password has been reset successfully. Please log in using your new password.",
        data: result,
    });
}

export async function changePassword(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as ChangePasswordInput;
    const session = req.auth;
    if (!session) {
        throw new Error("Authenticated session context is missing.");
    }

    await changeUserPassword({
        userId: session.userId,
        sessionId: session.sessionId,
        currentPassword: body.currentPassword,
        newPassword: body.newPassword,
    });

    return res.status(200).json({
        success: true,
        message: "Your password has been changed successfully.",
    });
}

export async function logout(req: Request, res: Response): Promise<Response> {
    const session = req.auth;
    if (!session) {
        throw new Error("Authenticated session context is missing.");
    }

    await logoutUser(session.sessionId);
    res.clearCookie(config.sessionCookieName, sessionCookieOptions());

    return res.status(200).json({
        success: true,
        message: "Logout successful.",
        data: {
            redirectPath: "/",
        },
    });
}

export async function validateActivation(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as ValidateActivationInput;
    const activation = await validateActivationToken(body.token);

    return res.status(200).json({
        success: true,
        message: "Activation link is valid.",
        data: activation,
    });
}

export async function completeActivation(
    req: Request,
    res: Response,
): Promise<Response> {
    const body = req.validatedBody as CompleteActivationInput;
    const result = await activateAccount(body.token, body.password);

    return res.status(200).json({
        success: true,
        message:
            "Your account has been activated successfully. Please log in to continue.",
        data: result,
    });
}

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

    const cookieOptions: CookieOptions = sessionCookieOptions();

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
