import fs from "node:fs/promises";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import type { QueryResultRow } from "pg";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

const { default: app } = require("../app") as typeof import("../app");
const { default: pool } = require("../src/db/pool") as typeof import("../src/db/pool");
const passwordService = require("../src/services/passwordService") as typeof import("../src/services/passwordService");
const tokenService = require("../src/services/tokenService") as typeof import("../src/services/tokenService");
const { default: config } = require("../src/config/env") as typeof import("../src/config/env");

interface RoleRow extends QueryResultRow {
    id: number;
}

interface TestUserRow extends QueryResultRow {
    id: string;
    email: string;
}

interface RefreshStateRow extends QueryResultRow {
    refreshGeneration: number;
    usedTokens: number;
    revokedAt: Date | null;
}

interface LoginResult {
    accessToken: string;
    refreshCookie: string;
    refreshToken: string;
}

const testRun = `jwt_test_${Date.now()}`;
const password = "JWT Test Password 42!";
let passwordHash = "";
let roleId = 0;

function emailFor(label: string): string {
    return `${testRun}_${label}@example.com`;
}

async function createUser(label: string): Promise<TestUserRow> {
    const { rows } = await pool.query<TestUserRow>(
        `
            INSERT INTO users (
                email,
                password_hash,
                role_id,
                account_status,
                activated_at
            ) VALUES ($1, $2, $3, 'active', NOW())
            RETURNING id, email::text AS email
        `,
        [emailFor(label), passwordHash, roleId],
    );
    const user = rows[0];
    assert.ok(user);
    return user;
}

function extractRefreshCookie(response: request.Response): {
    cookie: string;
    token: string;
} {
    const cookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(cookies);
    const refreshCookie = cookies.find((cookie) =>
        cookie.startsWith("lf.refresh="),
    );
    assert.ok(refreshCookie);
    const cookie = refreshCookie.split(";", 1)[0];
    assert.ok(cookie);
    const token = cookie.slice("lf.refresh=".length);
    assert.ok(token);
    return { cookie, token };
}

async function login(user: TestUserRow): Promise<LoginResult> {
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password });
    assert.equal(response.status, 200);
    const refresh = extractRefreshCookie(response);

    return {
        accessToken: response.body.data.accessToken,
        refreshCookie: refresh.cookie,
        refreshToken: refresh.token,
    };
}

async function refreshState(userId: string): Promise<RefreshStateRow> {
    const { rows } = await pool.query<RefreshStateRow>(
        `
            SELECT
                sessions.refresh_generation AS "refreshGeneration",
                sessions.revoked_at AS "revokedAt",
                count(history.session_id)::int AS "usedTokens"
            FROM auth_sessions sessions
            LEFT JOIN auth_refresh_token_history history
                ON history.session_id = sessions.id
            WHERE sessions.user_id = $1
            GROUP BY sessions.id
        `,
        [userId],
    );
    const state = rows[0];
    assert.ok(state);
    return state;
}

before(async () => {
    passwordHash = await passwordService.hashPassword(password);
    const { rows } = await pool.query<RoleRow>(
        "SELECT id FROM roles WHERE code = 'internal_user'",
    );
    const role = rows[0];
    assert.ok(role);
    roleId = role.id;
});

beforeEach(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [
        `${testRun}%`,
    ]);
});

after(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [
        `${testRun}%`,
    ]);
    await pool.end();
});

test("publishes the RSA public key without exposing private key material", async () => {
    const response = await request(app).get("/.well-known/jwks.json");

    assert.equal(response.status, 200);
    assert.equal(response.body.keys.length, 1);
    assert.equal(response.body.keys[0].kty, "RSA");
    assert.equal(response.body.keys[0].alg, "RS256");
    assert.equal(response.body.keys[0].kid, "lf-auth-rs256-v1");
    assert.equal(response.body.keys[0].use, "sig");
    assert.equal("d" in response.body.keys[0], false);
    const cacheControl = response.headers["cache-control"];
    assert.ok(cacheControl);
    assert.match(cacheControl, /public/);
});

test("issues a 15-minute access JWT with the expected identity claims", async () => {
    const user = await createUser("claims");
    const authentication = await login(user);
    const principal = await tokenService.verifyAccessToken(
        authentication.accessToken,
    );

    assert.equal(principal.userId, user.id);
    assert.equal(principal.roleCode, "internal_user");
    assert.deepEqual(principal.permissions, []);

    const [, encodedPayload] = authentication.accessToken.split(".");
    assert.ok(encodedPayload);
    const payload = JSON.parse(
        Buffer.from(encodedPayload, "base64url").toString("utf8"),
    ) as { exp: number; iat: number; iss: string; aud: string };
    assert.equal(payload.exp - payload.iat, 15 * 60);
    assert.equal(payload.iss, "lynkflow-auth");
    assert.equal(payload.aud, "lynkflow-api");
});

test("rotates the refresh token and records the used credential", async () => {
    const user = await createUser("rotate");
    const authentication = await login(user);

    const response = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);

    assert.equal(response.status, 200);
    assert.equal(response.body.data.expiresIn, 900);
    assert.notEqual(response.body.data.accessToken, authentication.accessToken);
    const rotated = extractRefreshCookie(response);
    assert.notEqual(rotated.token, authentication.refreshToken);

    const state = await refreshState(user.id);
    assert.equal(state.refreshGeneration, 1);
    assert.equal(state.usedTokens, 1);
    assert.equal(state.revokedAt, null);
});

test("rejects a forged refresh token without revoking the valid session", async () => {
    const user = await createUser("forged_refresh");
    const authentication = await login(user);
    const replacement = authentication.refreshToken.endsWith("A") ? "B" : "A";
    const forgedToken = `${authentication.refreshToken.slice(0, -1)}${replacement}`;

    const forgedResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", `lf.refresh=${forgedToken}`);
    assert.equal(forgedResponse.status, 401);
    assert.equal(
        forgedResponse.body.error.code,
        "AUTH_REFRESH_TOKEN_INVALID",
    );

    const validResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(validResponse.status, 200);
});

test("detects refresh-token reuse and revokes the token family", async () => {
    const user = await createUser("reuse");
    const authentication = await login(user);
    const firstRefresh = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(firstRefresh.status, 200);
    const rotated = extractRefreshCookie(firstRefresh);

    const replayResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(replayResponse.status, 401);
    assert.equal(
        replayResponse.body.error.code,
        "AUTH_REFRESH_TOKEN_REUSED",
    );

    const rotatedResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", rotated.cookie);
    assert.equal(rotatedResponse.status, 401);
    assert.equal(
        rotatedResponse.body.error.code,
        "AUTH_REFRESH_TOKEN_INVALID",
    );

    const accessResponse = await request(app)
        .post("/api/v1/auth/password/change")
        .set("Authorization", `Bearer ${firstRefresh.body.data.accessToken}`)
        .send({});
    assert.equal(accessResponse.status, 401);
    assert.equal(accessResponse.body.error.code, "AUTH_SESSION_EXPIRED");
});

test("a forged logout cookie cannot revoke a legitimate session", async () => {
    const user = await createUser("forged_logout");
    const authentication = await login(user);
    const replacement = authentication.refreshToken.endsWith("A") ? "B" : "A";
    const forgedToken = `${authentication.refreshToken.slice(0, -1)}${replacement}`;

    const logoutResponse = await request(app)
        .post("/api/v1/auth/token/logout")
        .set("Cookie", `lf.refresh=${forgedToken}`);
    assert.equal(logoutResponse.status, 200);

    const refreshResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(refreshResponse.status, 200);
});

test("logout with a previously rotated token revokes its token family", async () => {
    const user = await createUser("rotated_logout");
    const authentication = await login(user);
    const refreshResponse = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(refreshResponse.status, 200);
    const rotated = extractRefreshCookie(refreshResponse);

    const logoutResponse = await request(app)
        .post("/api/v1/auth/token/logout")
        .set("Cookie", authentication.refreshCookie);
    assert.equal(logoutResponse.status, 200);

    const afterLogout = await request(app)
        .post("/api/v1/auth/token/refresh")
        .set("Cookie", rotated.cookie);
    assert.equal(afterLogout.status, 401);
    assert.equal(
        afterLogout.body.error.code,
        "AUTH_REFRESH_TOKEN_INVALID",
    );
});

test("rejects expired and wrong-audience JWTs", async () => {
    const user = await createUser("invalid_claims");
    const authentication = await login(user);
    const principal = await tokenService.verifyAccessToken(
        authentication.accessToken,
    );
    const { SignJWT, importPKCS8 } = await import("jose");
    const privatePem = await fs.readFile(
        path.resolve(process.cwd(), config.jwtPrivateKeyPath),
        "utf8",
    );
    const privateKey = await importPKCS8(privatePem, "RS256");
    const now = Math.floor(Date.now() / 1_000);

    async function customToken(audience: string, expiresAt: number) {
        return new SignJWT({
            sid: principal.sessionId,
            role: principal.roleCode,
            permissions: principal.permissions,
        })
            .setProtectedHeader({
                alg: "RS256",
                kid: config.jwtKeyId,
                typ: "at+jwt",
            })
            .setIssuer(config.jwtIssuer)
            .setAudience(audience)
            .setSubject(user.id)
            .setJti("7ced8314-6ea7-48e7-b5ca-fd2727f685bc")
            .setIssuedAt(now - 120)
            .setNotBefore(now - 120)
            .setExpirationTime(expiresAt)
            .sign(privateKey);
    }

    const [expiredToken, wrongAudienceToken] = await Promise.all([
        customToken(config.jwtAudience, now - 60),
        customToken("another-api", now + 60),
    ]);
    const [expiredResponse, wrongAudienceResponse] = await Promise.all([
        request(app)
            .post("/api/v1/auth/password/change")
            .set("Authorization", `Bearer ${expiredToken}`)
            .send({}),
        request(app)
            .post("/api/v1/auth/password/change")
            .set("Authorization", `Bearer ${wrongAudienceToken}`)
            .send({}),
    ]);

    assert.equal(expiredResponse.status, 401);
    assert.equal(
        expiredResponse.body.error.code,
        "AUTH_ACCESS_TOKEN_EXPIRED",
    );
    assert.equal(wrongAudienceResponse.status, 401);
    assert.equal(
        wrongAudienceResponse.body.error.code,
        "AUTH_ACCESS_TOKEN_INVALID",
    );
});
