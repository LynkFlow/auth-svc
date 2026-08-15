import fs from "node:fs/promises";
import path from "node:path";
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { z } from "zod";
import config from "../config/env.js";

const ACCESS_TOKEN_TYPE = "at+jwt";
const ACCESS_TOKEN_ALGORITHM = "RS256";
// Under CommonJS this needed a `resolution-mode: import` type-only import
// attribute to resolve "jose"'s ESM types from a CJS context. Now that this
// package is ESM itself, "jose" resolves normally -- the attribute is gone.
type JoseModule = typeof import("jose");
type PrivateKeyLike = Awaited<ReturnType<JoseModule["importPKCS8"]>>;
type PublicKeyLike = Awaited<ReturnType<JoseModule["importSPKI"]>>;

export interface AccessTokenPrincipal {
  userId: string;
  sessionId: string;
  roleCode: string;
  permissions: string[];
}

export interface IssuedAccessToken {
  token: string;
  expiresAt: Date;
  expiresInSeconds: number;
}

export interface VerifiedAccessToken extends AccessTokenPrincipal {
  tokenId: string;
}

export class AccessTokenVerificationError extends Error {
  readonly reason: "expired" | "invalid";

  constructor(reason: "expired" | "invalid") {
    super(`Access token is ${reason}.`);
    this.name = "AccessTokenVerificationError";
    this.reason = reason;
  }
}

const accessTokenPayloadSchema = z.object({
  sub: z.string().uuid(),
  sid: z.string().uuid(),
  role: z.string().min(1),
  permissions: z.array(z.string()),
  jti: z.string().uuid(),
});

/**
 * Holds the process's JWT signing/verification key material. Key loading
 * is cached per-instance (not module-level state, per backend-conventions.md)
 * -- one instance is built in container.ts and injected wherever a token
 * needs issuing or verifying (AuthService, AuthGuard, index.ts's startup
 * check).
 */
export class TokenService {
  private joseModulePromise: Promise<JoseModule> | undefined;
  private privateKeyPromise: Promise<PrivateKeyLike> | undefined;
  private publicKeyPromise: Promise<PublicKeyLike> | undefined;

  private getJose(): Promise<JoseModule> {
    this.joseModulePromise ??= import("jose");
    return this.joseModulePromise;
  }

  private async readKey(filename: string, description: string): Promise<string> {
    const resolvedPath = path.resolve(process.cwd(), filename);

    try {
      return await fs.readFile(resolvedPath, "utf8");
    } catch {
      throw new Error(
        `${description} could not be read at '${resolvedPath}'. Run npm run jwt:keys:generate or configure the key path.`,
      );
    }
  }

  private async loadPrivateKey(): Promise<PrivateKeyLike> {
    const [{ importPKCS8 }, pem] = await Promise.all([
      this.getJose(),
      this.readKey(config.jwtPrivateKeyPath, "JWT private key"),
    ]);
    const key = createPrivateKey(pem);
    const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;

    if (key.asymmetricKeyType !== "rsa" || modulusLength < 2_048) {
      throw new Error("JWT private key must be an RSA key of at least 2048 bits.");
    }

    return importPKCS8(pem, ACCESS_TOKEN_ALGORITHM);
  }

  private async loadPublicKey(): Promise<PublicKeyLike> {
    const [{ importSPKI }, pem] = await Promise.all([
      this.getJose(),
      this.readKey(config.jwtPublicKeyPath, "JWT public key"),
    ]);
    const key = createPublicKey(pem);
    const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;

    if (key.asymmetricKeyType !== "rsa" || modulusLength < 2_048) {
      throw new Error("JWT public key must be an RSA key of at least 2048 bits.");
    }

    return importSPKI(pem, ACCESS_TOKEN_ALGORITHM);
  }

  private getPrivateKey(): Promise<PrivateKeyLike> {
    this.privateKeyPromise ??= this.loadPrivateKey();
    return this.privateKeyPromise;
  }

  private getPublicKey(): Promise<PublicKeyLike> {
    this.publicKeyPromise ??= this.loadPublicKey();
    return this.publicKeyPromise;
  }

  async initialize(): Promise<void> {
    const [privatePem, publicPem] = await Promise.all([
      this.readKey(config.jwtPrivateKeyPath, "JWT private key"),
      this.readKey(config.jwtPublicKeyPath, "JWT public key"),
    ]);
    const derivedPublicKey = createPublicKey(createPrivateKey(privatePem)).export({
      type: "spki",
      format: "der",
    });
    const configuredPublicKey = createPublicKey(publicPem).export({
      type: "spki",
      format: "der",
    });

    if (
      derivedPublicKey.length !== configuredPublicKey.length ||
      !timingSafeEqual(derivedPublicKey, configuredPublicKey)
    ) {
      throw new Error("The configured JWT private and public keys do not match.");
    }

    await Promise.all([this.getPrivateKey(), this.getPublicKey()]);
  }

  async issueAccessToken(principal: AccessTokenPrincipal): Promise<IssuedAccessToken> {
    const [{ SignJWT }, privateKey] = await Promise.all([
      this.getJose(),
      this.getPrivateKey(),
    ]);
    const issuedAt = Math.floor(Date.now() / 1_000);
    const expiresInSeconds = config.jwtAccessTokenMinutes * 60;
    const expiresAtSeconds = issuedAt + expiresInSeconds;
    const token = await new SignJWT({
      sid: principal.sessionId,
      role: principal.roleCode,
      permissions: principal.permissions,
    })
      .setProtectedHeader({
        alg: ACCESS_TOKEN_ALGORITHM,
        kid: config.jwtKeyId,
        typ: ACCESS_TOKEN_TYPE,
      })
      .setIssuer(config.jwtIssuer)
      .setAudience(config.jwtAudience)
      .setSubject(principal.userId)
      .setJti(randomUUID())
      .setIssuedAt(issuedAt)
      .setNotBefore(issuedAt)
      .setExpirationTime(expiresAtSeconds)
      .sign(privateKey);

    return {
      token,
      expiresAt: new Date(expiresAtSeconds * 1_000),
      expiresInSeconds,
    };
  }

  async verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
    try {
      const [{ jwtVerify }, publicKey] = await Promise.all([
        this.getJose(),
        this.getPublicKey(),
      ]);
      const { payload } = await jwtVerify(token, publicKey, {
        algorithms: [ACCESS_TOKEN_ALGORITHM],
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        typ: ACCESS_TOKEN_TYPE,
        clockTolerance: config.jwtClockToleranceSeconds,
      });
      const parsed = accessTokenPayloadSchema.safeParse(payload);

      if (!parsed.success) {
        throw new AccessTokenVerificationError("invalid");
      }

      return {
        userId: parsed.data.sub,
        sessionId: parsed.data.sid,
        roleCode: parsed.data.role,
        permissions: parsed.data.permissions,
        tokenId: parsed.data.jti,
      };
    } catch (error) {
      if (error instanceof AccessTokenVerificationError) {
        throw error;
      }

      const joseError = error as { code?: string };
      throw new AccessTokenVerificationError(
        joseError.code === "ERR_JWT_EXPIRED" ? "expired" : "invalid",
      );
    }
  }

  async getPublicJwks(): Promise<{ keys: Record<string, unknown>[] }> {
    const [{ exportJWK }, publicKey] = await Promise.all([
      this.getJose(),
      this.getPublicKey(),
    ]);
    const key = await exportJWK(publicKey);

    return {
      keys: [
        {
          ...key,
          alg: ACCESS_TOKEN_ALGORITHM,
          kid: config.jwtKeyId,
          use: "sig",
        },
      ],
    };
  }
}
