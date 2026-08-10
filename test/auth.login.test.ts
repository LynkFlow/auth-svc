import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import type { QueryResultRow } from "pg";
import type { AccountStatus } from "../src/models/userModel";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

const { default: app } = require("../app") as typeof import("../app");
const { default: pool } = require("../src/db/pool") as typeof import("../src/db/pool");
const passwordService = require("../src/services/passwordService") as typeof import("../src/services/passwordService");
const { default: authenticate } = require("../src/middleware/authenticate") as typeof import("../src/middleware/authenticate");
const { errorHandler } = require("../src/middleware/errorHandler") as typeof import("../src/middleware/errorHandler");

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

const protectedApp = express();
protectedApp.use(cookieParser());
protectedApp.get("/protected", authenticate, (req, res) => {
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
    const activatedAt =
        accountStatus === "pending_activation" ? null : new Date();
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

test("rejects malformed login input", async () => {
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: "not-an-email", password: "" });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "VALIDATION_ERROR");
});

test("rejects malformed JSON without leaking implementation details", async () => {
    const response = await request(app)
        .post("/api/v1/auth/login")
        .set("Content-Type", "application/json")
        .send('{"email":');

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "INVALID_JSON");
});

test("returns the same generic error for an unknown email and a wrong password", async () => {
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

test("denies a suspended account with the required status message", async () => {
    const user = await createUser("suspended", "suspended");
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_SUSPENDED");
});

test("denies an account that has not been activated", async () => {
    const user = await createUser("pending", "pending_activation");
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_NOT_ACTIVATED");
});

test("denies an inactive account", async () => {
    const user = await createUser("inactive", "inactive");
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password });

    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "AUTH_ACCOUNT_INACTIVE");
});

test("locks an account after the configured number of failed attempts", async () => {
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

test("authenticates an active user and establishes a server-side session", async () => {
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
    assert.equal("token" in response.body.data.session, false);

    const cookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(cookies);
    const cookie = cookies[0];
    assert.ok(cookie);
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    assert.match(cookie, /Priority=High/i);
    assert.match(cookie, /Expires=/i);
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
        .set("Cookie", cookies);
    assert.equal(protectedResponse.status, 200);
    assert.equal(protectedResponse.body.auth.userId, user.id);
    assert.equal(protectedResponse.body.auth.roleCode, "internal_user");
});

test("rejects access to protected handlers without an active session", async () => {
    const response = await request(protectedApp).get("/protected");

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "AUTH_SESSION_EXPIRED");
});
