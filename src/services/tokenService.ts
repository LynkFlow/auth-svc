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

let joseModulePromise: Promise<JoseModule> | undefined;
let privateKeyPromise: ReturnType<typeof loadPrivateKey> | undefined;
let publicKeyPromise: ReturnType<typeof loadPublicKey> | undefined;

function getJose(): Promise<JoseModule> {
  joseModulePromise ??= import("jose");
  return joseModulePromise;
}

async function readKey(filename: string, description: string): Promise<string> {
  const resolvedPath = path.resolve(process.cwd(), filename);

  try {
    return await fs.readFile(resolvedPath, "utf8");
  } catch {
    throw new Error(
      `${description} could not be read at '${resolvedPath}'. Run npm run jwt:keys:generate or configure the key path.`,
    );
  }
}

async function loadPrivateKey() {
  const [{ importPKCS8 }, pem] = await Promise.all([
    getJose(),
    readKey(config.jwtPrivateKeyPath, "JWT private key"),
  ]);
  const key = createPrivateKey(pem);
  const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;

  if (key.asymmetricKeyType !== "rsa" || modulusLength < 2_048) {
    throw new Error("JWT private key must be an RSA key of at least 2048 bits.");
  }

  return importPKCS8(pem, ACCESS_TOKEN_ALGORITHM);
}

async function loadPublicKey() {
  const [{ importSPKI }, pem] = await Promise.all([
    getJose(),
    readKey(config.jwtPublicKeyPath, "JWT public key"),
  ]);
  const key = createPublicKey(pem);
  const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;

  if (key.asymmetricKeyType !== "rsa" || modulusLength < 2_048) {
    throw new Error("JWT public key must be an RSA key of at least 2048 bits.");
  }

  return importSPKI(pem, ACCESS_TOKEN_ALGORITHM);
}

function getPrivateKey() {
  privateKeyPromise ??= loadPrivateKey();
  return privateKeyPromise;
}

function getPublicKey() {
  publicKeyPromise ??= loadPublicKey();
  return publicKeyPromise;
}

export async function initializeTokenService(): Promise<void> {
  const [privatePem, publicPem] = await Promise.all([
    readKey(config.jwtPrivateKeyPath, "JWT private key"),
    readKey(config.jwtPublicKeyPath, "JWT public key"),
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

  await Promise.all([getPrivateKey(), getPublicKey()]);
}

export async function issueAccessToken(
  principal: AccessTokenPrincipal,
): Promise<IssuedAccessToken> {
  const [{ SignJWT }, privateKey] = await Promise.all([getJose(), getPrivateKey()]);
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

export async function verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
  try {
    const [{ jwtVerify }, publicKey] = await Promise.all([getJose(), getPublicKey()]);
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

export async function getPublicJwks(): Promise<{
  keys: Record<string, unknown>[];
}> {
  const [{ exportJWK }, publicKey] = await Promise.all([getJose(), getPublicKey()]);
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
