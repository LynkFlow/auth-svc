import type { CookieOptions, Request, Response } from "express";
import type { LoginResponse, ValidateActivationResponse } from "@lynkflow/types";
import {
  login as loginUser,
  logout as logoutUser,
  refreshAuthentication,
} from "../services/authService.js";
import type { AuthenticationResult } from "../services/authService.js";
import {
  completeActivation as activateAccount,
  validateActivationToken,
} from "../services/activationService.js";
import {
  changePassword as changeUserPassword,
  requestPasswordReset,
  resetPassword as resetUserPassword,
  validatePasswordResetToken,
} from "../services/passwordManagementService.js";
import { signup as registerUser } from "../services/signupService.js";
import config from "../config/env.js";
import refreshCookieOptions from "../config/refreshCookie.js";
import { getPublicJwks } from "../services/tokenService.js";
import type {
  ChangePasswordInput,
  CompleteActivationInput,
  ForgotPasswordInput,
  LoginInput,
  ResetPasswordInput,
  SignupInput,
  ValidateActivationInput,
  ValidatePasswordResetInput,
} from "../validators/authSchemas.js";

function setRefreshCookie(res: Response, authentication: AuthenticationResult): void {
  const cookieOptions: CookieOptions = refreshCookieOptions();

  if (authentication.refreshToken.isPersistent) {
    cookieOptions.expires = authentication.refreshToken.expiresAt;
  }

  res.cookie(
    config.refreshCookieName,
    authentication.refreshToken.token,
    cookieOptions,
  );
}

function authenticationData(authentication: AuthenticationResult) {
  return {
    accessToken: authentication.accessToken.token,
    tokenType: "Bearer" as const,
    expiresIn: authentication.accessToken.expiresInSeconds,
    accessTokenExpiresAt: authentication.accessToken.expiresAt.toISOString(),
    session: {
      expiresAt: authentication.refreshToken.expiresAt.toISOString(),
    },
  };
}

export async function jwks(_req: Request, res: Response): Promise<Response> {
  const keySet = await getPublicJwks();
  res.set("Cache-Control", "public, max-age=300");
  return res.status(200).json(keySet);
}

export async function signup(req: Request, res: Response): Promise<Response> {
  const body = req.validatedBody as SignupInput;
  const result = await registerUser(body);

  return res.status(201).json({
    success: true,
    message: "Account created. Check your email to activate your account.",
    data: result,
  });
}

export async function forgotPassword(req: Request, res: Response): Promise<Response> {
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

export async function resetPassword(req: Request, res: Response): Promise<Response> {
  const body = req.validatedBody as ResetPasswordInput;
  const result = await resetUserPassword(body.token, body.newPassword);

  res.clearCookie(config.refreshCookieName, refreshCookieOptions());
  return res.status(200).json({
    success: true,
    message:
      "Your password has been reset successfully. Please log in using your new password.",
    data: result,
  });
}

export async function changePassword(req: Request, res: Response): Promise<Response> {
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
  const candidate: unknown = req.cookies[config.refreshCookieName];
  await logoutUser(typeof candidate === "string" ? candidate : "");
  res.clearCookie(config.refreshCookieName, refreshCookieOptions());

  return res.status(200).json({
    success: true,
    message: "Logout successful.",
    data: {
      redirectPath: "/",
    },
  });
}

export async function refreshToken(req: Request, res: Response): Promise<Response> {
  const candidate: unknown = req.cookies[config.refreshCookieName];

  try {
    const result = await refreshAuthentication(
      typeof candidate === "string" ? candidate : "",
    );
    setRefreshCookie(res, result);

    return res.status(200).json({
      success: true,
      message: "Access token refreshed successfully.",
      data: authenticationData(result),
    });
  } catch (error) {
    res.clearCookie(config.refreshCookieName, refreshCookieOptions());
    throw error;
  }
}

export async function validateActivation(
  req: Request,
  res: Response,
): Promise<Response> {
  const body = req.validatedBody as ValidateActivationInput;
  const activation: ValidateActivationResponse = await validateActivationToken(
    body.token,
  );

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
    message: "Your account has been activated successfully. Please log in to continue.",
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

  setRefreshCookie(res, result);

  const data: LoginResponse = {
    // Spread into a fresh object literal rather than assigning
    // `result.user` (typed `PublicUser`) directly -- AuthUser's
    // `[key: string]: unknown` index signature is only satisfied by a
    // literal's inferred shape, not by a differently-named interface
    // with the same fields.
    user: { ...result.user },
    ...authenticationData(result),
  };

  return res.status(200).json({
    success: true,
    message: "Login successful.",
    data,
  });
}
