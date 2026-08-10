import { createHash, randomBytes } from "node:crypto";
import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import type { QueryResultRow } from "pg";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

const { default: app } = require("../app") as typeof import("../app");
const { default: pool } = require("../src/db/pool") as typeof import("../src/db/pool");
const passwordService = require("../src/services/passwordService") as typeof import("../src/services/passwordService");
const activationService = require("../src/services/activationService") as typeof import("../src/services/activationService");

interface RoleRow extends QueryResultRow {
    id: number;
}

interface TestUserRow extends QueryResultRow {
    id: string;
    email: string;
}

interface ActivationVerificationRow extends QueryResultRow {
    accountStatus: string;
    passwordHash: string;
    activatedAt: Date | null;
    termsAcceptedAt: Date | null;
    termsVersion: string | null;
    privacyPolicyAcceptedAt: Date | null;
    privacyPolicyVersion: string | null;
    consumedAt: Date | null;
    outboxCount: number;
    eventPayload: {
        userId: string;
        email: string;
        fullName: string | null;
        channel: string;
    };
}

const testRun = `activation_test_${Date.now()}`;
const validPassword = "Secure Activation 42!";
let roleId = 0;

function emailFor(label: string): string {
    return `${testRun}_${label}@example.com`;
}

async function createPendingUser(label: string): Promise<TestUserRow> {
    const { rows } = await pool.query<TestUserRow>(
        `
            INSERT INTO users (
                email,
                password_hash,
                role_id,
                account_status,
                full_name,
                organization_name
            ) VALUES ($1, NULL, $2, 'pending_activation', $3, $4)
            RETURNING id, email::text AS email
        `,
        [emailFor(label), roleId, `Test User ${label}`, "Test Organization"],
    );

    const user = rows[0];
    assert.ok(user);
    return user;
}

async function createExpiredToken(userId: string): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest();

    await pool.query(
        `
            INSERT INTO account_activation_tokens (
                user_id,
                token_hash,
                created_at,
                expires_at
            ) VALUES ($1, $2, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day')
        `,
        [userId, tokenHash],
    );

    return token;
}

before(async () => {
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

test("returns account information for a valid activation token", async () => {
    const user = await createPendingUser("validate");
    const issued = await activationService.issueActivationToken(user.id);

    const response = await request(app)
        .post("/api/v1/auth/activation/validate")
        .send({ token: issued.token });

    assert.equal(response.status, 200);
    assert.equal(response.body.message, "Activation link is valid.");
    assert.equal(response.body.data.account.email, user.email);
    assert.equal(response.body.data.account.fullName, "Test User validate");
    assert.equal(
        response.body.data.account.organizationName,
        "Test Organization",
    );
    assert.equal(response.body.data.agreements.termsVersion, "1.0");
    assert.equal(response.body.data.agreements.privacyPolicyVersion, "1.0");
    assert.equal("token" in response.body.data, false);
    assert.equal(response.headers["cache-control"], "no-store");
});

test("rejects an invalid activation token", async () => {
    const response = await request(app)
        .post("/api/v1/auth/activation/validate")
        .send({ token: "not-a-valid-token" });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "AUTH_ACTIVATION_TOKEN_INVALID");
    assert.equal(response.body.error.message, "The activation link is invalid.");
});

test("rejects an expired activation token", async () => {
    const user = await createPendingUser("expired");
    const token = await createExpiredToken(user.id);

    const response = await request(app)
        .post("/api/v1/auth/activation/complete")
        .send({
            token,
            password: validPassword,
            confirmPassword: validPassword,
            termsAccepted: true,
            privacyPolicyAccepted: true,
        });

    assert.equal(response.status, 410);
    assert.equal(response.body.error.code, "AUTH_ACTIVATION_TOKEN_EXPIRED");
    assert.equal(
        response.body.error.message,
        "The activation link has expired.",
    );
});

test("requires matching passwords and both agreements", async () => {
    const user = await createPendingUser("validation");
    const issued = await activationService.issueActivationToken(user.id);

    const response = await request(app)
        .post("/api/v1/auth/activation/complete")
        .send({
            token: issued.token,
            password: validPassword,
            confirmPassword: `${validPassword}different`,
            termsAccepted: false,
            privacyPolicyAccepted: false,
        });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "VALIDATION_ERROR");
    assert.deepEqual(
        response.body.error.details.map(
            (detail: { field: string }) => detail.field,
        ),
        ["confirmPassword", "termsAccepted", "privacyPolicyAccepted"],
    );
});

test("enforces the configured password policy", async () => {
    const user = await createPendingUser("weak_password");
    const issued = await activationService.issueActivationToken(user.id);

    const response = await request(app)
        .post("/api/v1/auth/activation/complete")
        .send({
            token: issued.token,
            password: "weakpassword",
            confirmPassword: "weakpassword",
            termsAccepted: true,
            privacyPolicyAccepted: true,
        });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "AUTH_PASSWORD_POLICY_VIOLATION");
    assert.equal(
        response.body.error.message,
        "Password does not comply with the password policy.",
    );
    assert.ok(response.body.error.details.length >= 3);
});

test("activates the account, records consent, and queues notification", async () => {
    const user = await createPendingUser("complete");
    const issued = await activationService.issueActivationToken(user.id);

    const response = await request(app)
        .post("/api/v1/auth/activation/complete")
        .send({
            token: issued.token,
            password: validPassword,
            confirmPassword: validPassword,
            termsAccepted: true,
            privacyPolicyAccepted: true,
        });

    assert.equal(response.status, 200);
    assert.equal(
        response.body.message,
        "Your account has been activated successfully. Please log in to continue.",
    );
    assert.equal(response.body.data.loginPath, "/login");

    const { rows } = await pool.query<ActivationVerificationRow>(
        `
            SELECT
                users.account_status AS "accountStatus",
                users.password_hash AS "passwordHash",
                users.activated_at AS "activatedAt",
                users.terms_accepted_at AS "termsAcceptedAt",
                users.terms_version AS "termsVersion",
                users.privacy_policy_accepted_at AS "privacyPolicyAcceptedAt",
                users.privacy_policy_version AS "privacyPolicyVersion",
                activation.consumed_at AS "consumedAt",
                count(outbox.id)::int AS "outboxCount",
                (array_agg(outbox.payload))[1] AS "eventPayload"
            FROM users
            JOIN account_activation_tokens activation
                ON activation.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'account.activated'
            WHERE users.id = $1
            GROUP BY users.id, activation.id
        `,
        [user.id],
    );

    const verification = rows[0];
    assert.ok(verification);
    assert.equal(verification.accountStatus, "active");
    assert.ok(verification.activatedAt);
    assert.ok(verification.termsAcceptedAt);
    assert.equal(verification.termsVersion, "1.0");
    assert.ok(verification.privacyPolicyAcceptedAt);
    assert.equal(verification.privacyPolicyVersion, "1.0");
    assert.ok(verification.consumedAt);
    assert.equal(verification.outboxCount, 1);
    assert.equal(verification.eventPayload.userId, user.id);
    assert.equal(verification.eventPayload.email, user.email);
    assert.equal(verification.eventPayload.channel, "email");
    assert.notEqual(verification.passwordHash, validPassword);
    assert.equal(
        await passwordService.verifyPassword(
            verification.passwordHash,
            validPassword,
        ),
        true,
    );

    const loginResponse = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: user.email, password: validPassword });
    assert.equal(loginResponse.status, 200);

    const reusedResponse = await request(app)
        .post("/api/v1/auth/activation/validate")
        .send({ token: issued.token });
    assert.equal(reusedResponse.status, 409);
    assert.equal(
        reusedResponse.body.error.code,
        "AUTH_ACCOUNT_ALREADY_ACTIVE",
    );
    assert.equal(reusedResponse.body.error.details.loginPath, "/login");
});

test("allows only one concurrent activation attempt to succeed", async () => {
    const user = await createPendingUser("concurrent");
    const issued = await activationService.issueActivationToken(user.id);
    const payload = {
        token: issued.token,
        password: validPassword,
        confirmPassword: validPassword,
        termsAccepted: true,
        privacyPolicyAccepted: true,
    };

    const responses = await Promise.all([
        request(app).post("/api/v1/auth/activation/complete").send(payload),
        request(app).post("/api/v1/auth/activation/complete").send(payload),
    ]);
    const statuses = responses.map((response) => response.status).sort();

    assert.deepEqual(statuses, [200, 409]);
});
