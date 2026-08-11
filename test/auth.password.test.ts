import { createHash, randomBytes } from "node:crypto";
import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import type { QueryResultRow } from "pg";
import type { AccountStatus } from "../src/models/userModel";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

const { default: app } = require("../app") as typeof import("../app");
const { default: pool } = require("../src/db/pool") as typeof import("../src/db/pool");
const passwordService = require("../src/services/passwordService") as typeof import("../src/services/passwordService");

interface RoleRow extends QueryResultRow {
    id: number;
}

interface TestUserRow extends QueryResultRow {
    id: string;
    email: string;
}

interface OutboxTokenRow extends QueryResultRow {
    token: string;
}

interface ResetVerificationRow extends QueryResultRow {
    passwordHash: string;
    usedAt: Date | null;
    activeSessions: number;
    resetCompletedEvents: number;
}

interface ChangeVerificationRow extends QueryResultRow {
    passwordHash: string;
    activeSessions: number;
    revokedSessions: number;
    activeResetTokens: number;
    changedEvents: number;
}

interface TestAuthentication {
    accessToken: string;
    cookies: string[];
}

const testRun = `password_test_${Date.now()}`;
const currentPassword = "Current Password 42!";
const newPassword = "New Secure Password 84!";
let currentPasswordHash = "";
let roleId = 0;

function emailFor(label: string): string {
    return `${testRun}_${label}@example.com`;
}

async function createUser(
    label: string,
    accountStatus: AccountStatus = "active",
): Promise<TestUserRow> {
    const { rows } = await pool.query<TestUserRow>(
        `
            INSERT INTO users (
                email,
                password_hash,
                role_id,
                account_status,
                activated_at,
                full_name
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, email::text AS email
        `,
        [
            emailFor(label),
            currentPasswordHash,
            roleId,
            accountStatus,
            accountStatus === "pending_activation" ? null : new Date(),
            `Password Test ${label}`,
        ],
    );

    const user = rows[0];
    assert.ok(user);
    return user;
}

async function login(email: string): Promise<TestAuthentication> {
    const response = await request(app)
        .post("/api/v1/auth/login")
        .send({ email, password: currentPassword });
    assert.equal(response.status, 200);

    const cookies = response.headers["set-cookie"] as string[] | undefined;
    assert.ok(cookies);
    assert.equal(typeof response.body.data.accessToken, "string");
    return {
        accessToken: response.body.data.accessToken,
        cookies,
    };
}

async function requestResetAndGetToken(user: TestUserRow): Promise<string> {
    const response = await request(app)
        .post("/api/v1/auth/password/forgot")
        .send({ email: user.email });
    assert.equal(response.status, 202);

    const { rows } = await pool.query<OutboxTokenRow>(
        `
            SELECT payload->>'token' AS token
            FROM auth_outbox_events
            WHERE aggregate_id = $1
              AND event_type = 'password.reset.requested'
            ORDER BY created_at DESC
            LIMIT 1
        `,
        [user.id],
    );
    const event = rows[0];
    assert.ok(event);
    return event.token;
}

async function createExpiredResetToken(userId: string): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest();
    await pool.query(
        `
            INSERT INTO password_reset_tokens (
                user_id,
                token_hash,
                created_at,
                expires_at
            ) VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')
        `,
        [userId, tokenHash],
    );
    return token;
}

before(async () => {
    currentPasswordHash = await passwordService.hashPassword(currentPassword);
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

test("forgot password uses the same response for known and unknown emails", async () => {
    const user = await createUser("enumeration");
    const [knownResponse, unknownResponse] = await Promise.all([
        request(app)
            .post("/api/v1/auth/password/forgot")
            .send({ email: user.email.toUpperCase() }),
        request(app)
            .post("/api/v1/auth/password/forgot")
            .send({ email: emailFor("unknown") }),
    ]);

    assert.equal(knownResponse.status, 202);
    assert.equal(unknownResponse.status, 202);
    assert.deepEqual(knownResponse.body, unknownResponse.body);
    assert.equal(
        knownResponse.body.message,
        "If the email address exists in our system, a password reset link has been sent.",
    );

    const { rows } = await pool.query<{ tokenCount: number; eventCount: number } & QueryResultRow>(
        `
            SELECT
                count(DISTINCT reset.id)::int AS "tokenCount",
                count(DISTINCT outbox.id)::int AS "eventCount"
            FROM users
            LEFT JOIN password_reset_tokens reset ON reset.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'password.reset.requested'
            WHERE users.id = $1
        `,
        [user.id],
    );
    assert.equal(rows[0]?.tokenCount, 1);
    assert.equal(rows[0]?.eventCount, 1);
});

test("forgot password does not create tokens for non-active accounts", async () => {
    const user = await createUser("suspended", "suspended");
    const response = await request(app)
        .post("/api/v1/auth/password/forgot")
        .send({ email: user.email });

    assert.equal(response.status, 202);
    const result = await pool.query(
        "SELECT id FROM password_reset_tokens WHERE user_id = $1",
        [user.id],
    );
    assert.equal(result.rowCount, 0);
});

test("a newer forgot-password request invalidates the previous link", async () => {
    const user = await createUser("latest_link");
    const firstToken = await requestResetAndGetToken(user);
    const secondToken = await requestResetAndGetToken(user);

    const [firstResponse, secondResponse] = await Promise.all([
        request(app)
            .post("/api/v1/auth/password/reset/validate")
            .send({ token: firstToken }),
        request(app)
            .post("/api/v1/auth/password/reset/validate")
            .send({ token: secondToken }),
    ]);

    assert.equal(firstResponse.status, 400);
    assert.equal(
        firstResponse.body.error.code,
        "AUTH_PASSWORD_RESET_TOKEN_INVALID",
    );
    assert.equal(secondResponse.status, 200);
    assert.equal("token" in secondResponse.body.data, false);
});

test("rejects expired password-reset links", async () => {
    const user = await createUser("expired");
    const token = await createExpiredResetToken(user.id);
    const response = await request(app)
        .post("/api/v1/auth/password/reset/validate")
        .send({ token });

    assert.equal(response.status, 410);
    assert.equal(
        response.body.error.code,
        "AUTH_PASSWORD_RESET_TOKEN_EXPIRED",
    );
    assert.equal(
        response.body.error.message,
        "Password reset link has expired.",
    );
});

test("reset password requires matching, policy-compliant passwords", async () => {
    const user = await createUser("reset_validation");
    const token = await requestResetAndGetToken(user);

    const mismatchResponse = await request(app)
        .post("/api/v1/auth/password/reset")
        .send({
            token,
            newPassword,
            confirmPassword: `${newPassword}different`,
        });
    assert.equal(mismatchResponse.status, 400);
    assert.equal(mismatchResponse.body.error.code, "VALIDATION_ERROR");

    const policyResponse = await request(app)
        .post("/api/v1/auth/password/reset")
        .send({
            token,
            newPassword: "weakpassword",
            confirmPassword: "weakpassword",
        });
    assert.equal(policyResponse.status, 400);
    assert.equal(
        policyResponse.body.error.code,
        "AUTH_PASSWORD_POLICY_VIOLATION",
    );
});

test("reset password rejects the user's current password", async () => {
    const user = await createUser("reset_unchanged");
    const token = await requestResetAndGetToken(user);
    const response = await request(app)
        .post("/api/v1/auth/password/reset")
        .send({
            token,
            newPassword: currentPassword,
            confirmPassword: currentPassword,
        });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "AUTH_PASSWORD_UNCHANGED");
});

test("reset password updates credentials, consumes links, and revokes sessions", async () => {
    const user = await createUser("reset_success");
    await login(user.email);
    await login(user.email);
    const token = await requestResetAndGetToken(user);

    const response = await request(app)
        .post("/api/v1/auth/password/reset")
        .send({
            token,
            newPassword,
            confirmPassword: newPassword,
        });

    assert.equal(response.status, 200);
    assert.equal(
        response.body.message,
        "Your password has been reset successfully. Please log in using your new password.",
    );
    assert.equal(response.body.data.loginPath, "/login");

    const { rows } = await pool.query<ResetVerificationRow>(
        `
            SELECT
                users.password_hash AS "passwordHash",
                reset.used_at AS "usedAt",
                count(DISTINCT sessions.id) FILTER (
                    WHERE sessions.revoked_at IS NULL
                )::int AS "activeSessions",
                count(DISTINCT outbox.id)::int AS "resetCompletedEvents"
            FROM users
            JOIN password_reset_tokens reset ON reset.user_id = users.id
            LEFT JOIN auth_sessions sessions ON sessions.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'password.reset.completed'
            WHERE users.id = $1
              AND reset.token_hash = $2
            GROUP BY users.id, reset.id
        `,
        [user.id, createHash("sha256").update(token).digest()],
    );
    const verification = rows[0];
    assert.ok(verification);
    assert.ok(verification.usedAt);
    assert.equal(verification.activeSessions, 0);
    assert.equal(verification.resetCompletedEvents, 1);
    assert.equal(
        await passwordService.verifyPassword(
            verification.passwordHash,
            newPassword,
        ),
        true,
    );

    const reusedResponse = await request(app)
        .post("/api/v1/auth/password/reset/validate")
        .send({ token });
    assert.equal(reusedResponse.status, 400);

    const oldLogin = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password: currentPassword });
    assert.equal(oldLogin.status, 401);

    const newLogin = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password: newPassword });
    assert.equal(newLogin.status, 200);
});

test("change password requires an authenticated session", async () => {
    const response = await request(app)
        .post("/api/v1/auth/password/change")
        .send({
            currentPassword,
            newPassword,
            confirmPassword: newPassword,
        });

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "AUTH_ACCESS_TOKEN_INVALID");
});

test("change password rejects an incorrect current password", async () => {
    const user = await createUser("incorrect_current");
    const authentication = await login(user.email);
    const response = await request(app)
        .post("/api/v1/auth/password/change")
        .set("Authorization", `Bearer ${authentication.accessToken}`)
        .send({
            currentPassword: "Incorrect Password 42!",
            newPassword,
            confirmPassword: newPassword,
        });

    assert.equal(response.status, 400);
    assert.equal(
        response.body.error.code,
        "AUTH_CURRENT_PASSWORD_INCORRECT",
    );
});

test("change password rejects the existing password as the new password", async () => {
    const user = await createUser("change_unchanged");
    const authentication = await login(user.email);
    const response = await request(app)
        .post("/api/v1/auth/password/change")
        .set("Authorization", `Bearer ${authentication.accessToken}`)
        .send({
            currentPassword,
            newPassword: currentPassword,
            confirmPassword: currentPassword,
        });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "AUTH_PASSWORD_UNCHANGED");
});

test("change password preserves the current session and revokes other sessions and reset links", async () => {
    const user = await createUser("change_success");
    const currentAuthentication = await login(user.email);
    await login(user.email);
    const resetToken = await requestResetAndGetToken(user);

    const response = await request(app)
        .post("/api/v1/auth/password/change")
        .set("Authorization", `Bearer ${currentAuthentication.accessToken}`)
        .send({
            currentPassword,
            newPassword,
            confirmPassword: newPassword,
        });

    assert.equal(response.status, 200);
    assert.equal(
        response.body.message,
        "Your password has been changed successfully.",
    );

    const { rows } = await pool.query<ChangeVerificationRow>(
        `
            SELECT
                users.password_hash AS "passwordHash",
                count(DISTINCT sessions.id) FILTER (
                    WHERE sessions.revoked_at IS NULL
                )::int AS "activeSessions",
                count(DISTINCT sessions.id) FILTER (
                    WHERE sessions.revoked_at IS NOT NULL
                )::int AS "revokedSessions",
                count(DISTINCT reset.id) FILTER (
                    WHERE reset.used_at IS NULL AND reset.revoked_at IS NULL
                )::int AS "activeResetTokens",
                count(DISTINCT outbox.id)::int AS "changedEvents"
            FROM users
            LEFT JOIN auth_sessions sessions ON sessions.user_id = users.id
            LEFT JOIN password_reset_tokens reset ON reset.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'password.changed'
            WHERE users.id = $1
            GROUP BY users.id
        `,
        [user.id],
    );
    const verification = rows[0];
    assert.ok(verification);
    assert.equal(verification.activeSessions, 1);
    assert.equal(verification.revokedSessions, 1);
    assert.equal(verification.activeResetTokens, 0);
    assert.equal(verification.changedEvents, 1);
    assert.equal(
        await passwordService.verifyPassword(
            verification.passwordHash,
            newPassword,
        ),
        true,
    );

    const resetResponse = await request(app)
        .post("/api/v1/auth/password/reset/validate")
        .send({ token: resetToken });
    assert.equal(resetResponse.status, 400);

    const stillAuthenticated = await request(app)
        .post("/api/v1/auth/password/change")
        .set("Authorization", `Bearer ${currentAuthentication.accessToken}`)
        .send({
            currentPassword: newPassword,
            newPassword: "Another Secure Password 96!",
            confirmPassword: "Another Secure Password 96!",
        });
    assert.equal(stillAuthenticated.status, 200);
});
