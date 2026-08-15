import type { CookieOptions, Request, Response } from "express";
import type { LoginResponse, ValidateActivationResponse } from "@lynkflow/types";
import config from "../config/env.js";
import refreshCookieOptions from "../config/refreshCookie.js";
import type { AuditLogEntry } from "../audit/AuditLogEntry.js";
import type { AuditLogService } from "../audit/AuditLogService.js";
import type { ActivationService } from "../services/ActivationService.js";
import type {
  AuthenticationResult,
  AuthService,
  LoginResult,
} from "../services/AuthService.js";
import type { PasswordManagementService } from "../services/PasswordManagementService.js";
import type { SignupService } from "../services/SignupService.js";
import type { TokenService } from "../services/TokenService.js";
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

// req.ip/req.get() are `string | undefined`, but AuditLogEntry's optional
// fields are typed plain `string` (exactOptionalPropertyTypes forbids an
// explicit `undefined` there, see forms.md's identical "conditional spread,
// not `x={undefined}`" pattern) -- this centralizes the omit-when-absent
// logic once instead of repeating a conditional spread at every call site.
function auditContext(
  req: Request,
  userAgent: string | undefined = req.get("user-agent"),
): Pick<AuditLogEntry, "ipAddress" | "userAgent" | "requestId"> {
  return {
    ...(req.ip !== undefined ? { ipAddress: req.ip } : {}),
    ...(userAgent !== undefined ? { userAgent } : {}),
    requestId: req.requestId,
  };
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

/**
 * HTTP-facing only: reads req, calls a service method, shapes the response
 * envelope, and (per backend-conventions.md's Audit trail section) records
 * the resulting AuditLogEntry -- the controller is the one layer that
 * already has req for ip/user-agent/request-id. Arrow-function class
 * fields, not prototype methods, so Express can call them as bare
 * references (router.post("/login", authController.login)) without losing
 * `this`.
 */
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly activationService: ActivationService,
    private readonly passwordManagementService: PasswordManagementService,
    private readonly signupService: SignupService,
    private readonly tokenService: TokenService,
    private readonly auditLogService: AuditLogService,
  ) {}

  jwks = async (_req: Request, res: Response): Promise<Response> => {
    const keySet = await this.tokenService.getPublicJwks();
    res.set("Cache-Control", "public, max-age=300");
    return res.status(200).json(keySet);
  };

  signup = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as SignupInput;
    const result = await this.signupService.signup(body);

    void this.auditLogService.record({
      operation: "auth.signup.succeeded",
      module: "auth",
      userId: result.userId,
      entity: `user:${result.userId}`,
      newValue: { email: result.email },
      ...auditContext(req),
    });

    return res.status(201).json({
      success: true,
      message: "Account created. Check your email to activate your account.",
      data: result,
    });
  };

  forgotPassword = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as ForgotPasswordInput;
    await this.passwordManagementService.requestPasswordReset(body.email);

    return res.status(202).json({
      success: true,
      message:
        "If the email address exists in our system, a password reset link has been sent.",
    });
  };

  validatePasswordReset = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as ValidatePasswordResetInput;
    const reset = await this.passwordManagementService.validatePasswordResetToken(
      body.token,
    );

    return res.status(200).json({
      success: true,
      message: "Password reset link is valid.",
      data: reset,
    });
  };

  resetPassword = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as ResetPasswordInput;
    const result = await this.passwordManagementService.resetPassword(
      body.token,
      body.newPassword,
    );

    res.clearCookie(config.refreshCookieName, refreshCookieOptions());

    void this.auditLogService.record({
      operation: "auth.password.reset",
      module: "auth",
      userId: result.userId,
      entity: `user:${result.userId}`,
      ...auditContext(req),
    });

    return res.status(200).json({
      success: true,
      message:
        "Your password has been reset successfully. Please log in using your new password.",
      data: { loginPath: result.loginPath },
    });
  };

  changePassword = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as ChangePasswordInput;
    const session = req.auth;
    if (!session) {
      throw new Error("Authenticated session context is missing.");
    }

    await this.passwordManagementService.changePassword({
      userId: session.userId,
      sessionId: session.sessionId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
    });

    void this.auditLogService.record({
      operation: "auth.password.changed",
      module: "auth",
      userId: session.userId,
      entity: `user:${session.userId}`,
      ...auditContext(req),
    });

    return res.status(200).json({
      success: true,
      message: "Your password has been changed successfully.",
    });
  };

  logout = async (req: Request, res: Response): Promise<Response> => {
    const candidate: unknown = req.cookies[config.refreshCookieName];
    const userId = await this.authService.logout(
      typeof candidate === "string" ? candidate : "",
    );
    res.clearCookie(config.refreshCookieName, refreshCookieOptions());

    void this.auditLogService.record({
      operation: "auth.logout.succeeded",
      module: "auth",
      ...(userId !== null ? { userId, entity: `user:${userId}` } : {}),
      ...auditContext(req),
    });

    return res.status(200).json({
      success: true,
      message: "Logout successful.",
      data: {
        redirectPath: "/",
      },
    });
  };

  refreshToken = async (req: Request, res: Response): Promise<Response> => {
    const candidate: unknown = req.cookies[config.refreshCookieName];

    try {
      const result = await this.authService.refreshAuthentication(
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
  };

  validateActivation = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as ValidateActivationInput;
    const activation: ValidateActivationResponse =
      await this.activationService.validateActivationToken(body.token);

    return res.status(200).json({
      success: true,
      message: "Activation link is valid.",
      data: activation,
    });
  };

  completeActivation = async (req: Request, res: Response): Promise<Response> => {
    const body = req.validatedBody as CompleteActivationInput;
    const result = await this.activationService.completeActivation(
      body.token,
      body.password,
    );

    void this.auditLogService.record({
      operation: "auth.activation.completed",
      module: "auth",
      userId: result.userId,
      entity: `user:${result.userId}`,
      ...auditContext(req),
    });

    return res.status(200).json({
      success: true,
      message:
        "Your account has been activated successfully. Please log in to continue.",
      data: { loginPath: result.loginPath },
    });
  };

  login = async (req: Request, res: Response): Promise<Response> => {
    const userAgent = req.get("user-agent");
    const body = req.validatedBody as LoginInput;

    let result: LoginResult;
    try {
      result = await this.authService.login({
        email: body.email,
        password: body.password,
        rememberMe: body.rememberMe,
        ipAddress: req.ip ?? null,
        userAgent: userAgent ? userAgent.slice(0, 512) : null,
      });
    } catch (error) {
      void this.auditLogService.record({
        operation: "auth.login.failed",
        module: "auth",
        newValue: { email: body.email },
        ...auditContext(req, userAgent),
      });
      throw error;
    }

    setRefreshCookie(res, result);

    void this.auditLogService.record({
      operation: "auth.login.succeeded",
      module: "auth",
      userId: result.user.id,
      entity: `user:${result.user.id}`,
      ...auditContext(req, userAgent),
    });

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
  };
}
