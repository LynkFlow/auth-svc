import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import type { QueryResultRow } from "pg";
import type { AccountStatus } from "../src/models/userModel.js";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

/* eslint-disable @typescript-eslint/no-require-imports */
const { default: app } = require("../app.js") as typeof import("../app.js");
const { default: pool } =
  require("../src/db/pool.js") as typeof import("../src/db/pool.js");
const passwordService =
  require("../src/services/passwordService.js") as typeof import("../src/services/passwordService.js");
const { errorHandler } =
  require("../src/middleware/errorHandler.js") as typeof import("../src/middleware/errorHandler.js");
const { useGuard } =
  require("../src/guards/useGuard.js") as typeof import("../src/guards/useGuard.js");
const { buildContainer } =
  require("../src/container.js") as typeof import("../src/container.js");
/* eslint-enable @typescript-eslint/no-require-imports */

// Real, wired instances from the same composition root app.ts uses --
// this test needs authGuard/tokenService directly rather than going
// through HTTP, which authenticate.ts's plain-middleware form used to
// allow but the class-based AuthGuard (wired via useGuard()) doesn't
// change the need for.
const container = buildContainer();
const tokenService = container.tokenService;

interface TestUserRow extends QueryResultRow {
  id: string;
  email: string;
}

interface RoleRow extends QueryResultRow {
  id: number;
}

interface SessionVerificationRow extends QueryResultRow {
  hasLastLogin: boolean;
  sessionCount: number;
  tokensAreHashed: boolean;
}

interface LogoutSessionVerificationRow extends QueryResultRow {
  activeSessions: number;
  revokedSessions: number;
}

const protectedApp = express();
protectedApp.get("/protected", useGuard(container.authGuard), (req, res) => {
  res.status(200).json({ auth: req.auth });
});
protectedApp.use(errorHandler);

const testRun = `auth_test_${Date.now()}`;
const password = "Correct horse battery staple 42!";
let passwordHash = "";
let roleId = 0;

function emailFor(label: string): string {
  return `${testRun}_${label}@example.com`;
}

async function createUser(
  label: string,
  accountStatus: AccountStatus = "active",
): Promise<TestUserRow> {
  const activatedAt = accountStatus === "pending_activation" ? null : new Date();
  const { rows } = await pool.query<TestUserRow>(
    `
            INSERT INTO users (email, password_hash, role_id, account_status, activated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email::text AS email
        `,
    [emailFor(label), passwordHash, roleId, accountStatus, activatedAt],
  );

  const user = rows[0];
  assert.ok(user);
  return user;
}

describe("auth login and logout", () => {
  beforeAll(async () => {
    passwordHash = await passwordService.hashPassword(password);
    const { rows } = await pool.query<RoleRow>(
      "SELECT id FROM roles WHERE code = 'internal_user'",
    );
    const role = rows[0];
    assert.ok(role);
    roleId = role.id;
  });

  beforeEach(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [`${testRun}%`]);
  });

  afterAll(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [`${testRun}%`]);
    await pool.end();
  });

  it("rejects malformed login input", async () => {
    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "not-an-email", password: "" });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "VALIDATION_ERROR");
  });

  it("rejects malformed JSON without leaking implementation details", async () => {
    const response = await request(app)
      .post("/api/v1/auth/login")
      .set("Content-Type", "application/json")
      .send('{"email":');

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "INVALID_JSON");
  });

  it("returns the same generic error for an unknown email and a wrong password", async () => {
    const user = await createUser("generic_error");

    const [unknownResponse, wrongPasswordResponse] = await Promise.all([
      request(app)
        .post("/api/v1/auth/login")
        .send({ email: emailFor("unknown"), password: "wrong" }),
      request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password: "wrong" }),
    ]);

    assert.equal(unknownResponse.status, 401);
    assert.equal(wrongPasswordResponse.status, 401);
    assert.deepEqual(unknownResponse.body, wrongPasswordResponse.body);
    assert.equal(
      wrongPasswordResponse.body.error.message,
      "Invalid email address or password.",
    );
  });

  it("denies a suspended account with the required status message", async () => {
    const user = await createUser("suspended", "suspended");
    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_SUSPENDED");
  });

  it("denies an account that has not been activated", async () => {
    const user = await createUser("pending", "pending_activation");
    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_NOT_ACTIVATED");
  });

  it("denies an inactive account", async () => {
    const user = await createUser("inactive", "inactive");
    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_INACTIVE");
  });

  it("locks an account after the configured number of failed attempts", async () => {
    const user = await createUser("lockout");
    let response: request.Response | undefined;

    for (let attempt = 0; attempt < 5; attempt += 1) {
      response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password: "wrong" });
    }

    assert.ok(response);
    assert.equal(response.status, 423);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_LOCKED");

    const lockedResponse = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: user.email, password });
    assert.equal(lockedResponse.status, 423);
  });

  it("authenticates an active user and establishes a server-side session", async () => {
    const user = await createUser("success");
    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: user.email.toUpperCase(), password, rememberMe: true });

    assert.equal(response.status, 200);
    assert.equal(response.body.message, "Login successful.");
    assert.equal(response.body.data.user.email, user.email);
    assert.equal(response.body.data.user.role.code, "internal_user");
    assert.deepEqual(response.body.data.user.permissions, []);
    assert.equal("passwordHash" in response.body.data.user, false);
    assert.equal(response.body.data.tokenType, "Bearer");
    assert.equal(response.body.data.expiresIn, 900);
    assert.equal(typeof response.body.data.accessToken, "string");

    const principal = await tokenService.verifyAccessToken(
      response.body.data.accessToken as string,
    );
    assert.equal(principal.userId, user.id);
    assert.equal(principal.roleCode, "internal_user");

    const cookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(cookies);
    const cookie = cookies[0];
    assert.ok(cookie);
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    assert.match(cookie, /Priority=High/i);
    assert.match(cookie, /Expires=/i);
    assert.match(cookie, /^lf\.refresh=/i);
    assert.match(cookie, /Path=\/api\/v1\/auth\/token/i);
    assert.equal(response.headers["cache-control"], "no-store");

    const { rows } = await pool.query<SessionVerificationRow>(
      `
            SELECT
                u.last_login_at IS NOT NULL AS "hasLastLogin",
                count(s.id)::int AS "sessionCount",
                bool_and(octet_length(s.token_hash) = 32) AS "tokensAreHashed"
            FROM users u
            LEFT JOIN auth_sessions s ON s.user_id = u.id
            WHERE u.id = $1
            GROUP BY u.id
        `,
      [user.id],
    );

    const verification = rows[0];
    assert.ok(verification);
    assert.equal(verification.hasLastLogin, true);
    assert.equal(verification.sessionCount, 1);
    assert.equal(verification.tokensAreHashed, true);

    const protectedResponse = await request(protectedApp)
      .get("/protected")
      .set("Authorization", `Bearer ${response.body.data.accessToken}`);
    assert.equal(protectedResponse.status, 200);
    assert.equal(protectedResponse.body.auth.userId, user.id);
    assert.equal(protectedResponse.body.auth.roleCode, "internal_user");
  });

  it("rejects access to protected handlers without a Bearer token", async () => {
    const response = await request(protectedApp).get("/protected");

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "AUTH_ACCESS_TOKEN_INVALID");
  });

  it("logout is idempotent when no refresh cookie is present", async () => {
    const response = await request(app).post("/api/v1/auth/token/logout");

    assert.equal(response.status, 200);
    assert.equal(response.body.message, "Logout successful.");
    const cookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(cookies);
    assert.match(cookies[0] ?? "", /^lf\.refresh=;/);
  });

  it("logs out only the current session and expires its cookie", async () => {
    const user = await createUser("logout");
    const [currentLogin, otherLogin] = await Promise.all([
      request(app).post("/api/v1/auth/login").send({ email: user.email, password }),
      request(app).post("/api/v1/auth/login").send({ email: user.email, password }),
    ]);

    assert.equal(currentLogin.status, 200);
    assert.equal(otherLogin.status, 200);

    const currentCookies = currentLogin.headers["set-cookie"] as string[] | undefined;
    const otherCookies = otherLogin.headers["set-cookie"] as string[] | undefined;
    assert.ok(currentCookies);
    assert.ok(otherCookies);
    const currentAccessToken = currentLogin.body.data.accessToken as string;
    const otherAccessToken = otherLogin.body.data.accessToken as string;

    const response = await request(app)
      .post("/api/v1/auth/token/logout")
      .set("Cookie", currentCookies);

    assert.equal(response.status, 200);
    assert.equal(response.body.message, "Logout successful.");
    assert.equal(response.body.data.redirectPath, "/");
    assert.equal(response.headers["cache-control"], "no-store");

    const clearedCookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(clearedCookies);
    const clearedRefreshCookie = clearedCookies[0];
    assert.ok(clearedRefreshCookie);
    assert.match(clearedRefreshCookie, /^lf\.refresh=;/);
    assert.match(clearedRefreshCookie, /Expires=Thu, 01 Jan 1970/i);
    assert.match(clearedRefreshCookie, /HttpOnly/i);
    assert.match(clearedRefreshCookie, /SameSite=Strict/i);
    assert.match(clearedRefreshCookie, /Priority=High/i);
    assert.match(clearedRefreshCookie, /Path=\/api\/v1\/auth\/token/i);

    const { rows } = await pool.query<LogoutSessionVerificationRow>(
      `
            SELECT
                count(*) FILTER (WHERE revoked_at IS NULL)::int AS "activeSessions",
                count(*) FILTER (WHERE revoked_at IS NOT NULL)::int AS "revokedSessions"
            FROM auth_sessions
            WHERE user_id = $1
        `,
      [user.id],
    );
    const verification = rows[0];
    assert.ok(verification);
    assert.equal(verification.activeSessions, 1);
    assert.equal(verification.revokedSessions, 1);

    const loggedOutRequest = await request(protectedApp)
      .get("/protected")
      .set("Authorization", `Bearer ${currentAccessToken}`);
    assert.equal(loggedOutRequest.status, 401);
    assert.equal(loggedOutRequest.body.error.code, "AUTH_SESSION_EXPIRED");

    const otherSessionRequest = await request(protectedApp)
      .get("/protected")
      .set("Authorization", `Bearer ${otherAccessToken}`);
    assert.equal(otherSessionRequest.status, 200);
    assert.equal(otherSessionRequest.body.auth.userId, user.id);
  });
});
