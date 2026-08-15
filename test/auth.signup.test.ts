import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import request from "supertest";
import type { QueryResultRow } from "pg";

process.env.NODE_ENV = "test";
process.env.COOKIE_SECURE = "false";

/* eslint-disable @typescript-eslint/no-require-imports */
const { default: app } = require("../app.js") as typeof import("../app.js");
const { default: pool } =
  require("../src/db/pool.js") as typeof import("../src/db/pool.js");
const passwordService =
  require("../src/services/passwordService.js") as typeof import("../src/services/passwordService.js");
/* eslint-enable @typescript-eslint/no-require-imports */

interface SignupVerificationRow extends QueryResultRow {
  id: string;
  email: string;
  passwordHash: string;
  accountStatus: string;
  fullName: string;
  organizationName: string;
  roleCode: string;
  tokenHashHex: string;
  expiresAt: Date;
  eventCount: number;
  eventPayload: {
    userId: string;
    email: string;
    fullName: string;
    organizationName: string;
    accountType: string;
    token: string;
    expiresAt: string;
    channel: string;
  };
}

interface RoleVerificationRow extends QueryResultRow {
  roleCode: string;
}

interface CountRow extends QueryResultRow {
  userCount: number;
  tokenCount: number;
  eventCount: number;
}

const testRun = `signup_test_${Date.now()}`;
const validPassword = "Secure Signup 42!";

function emailFor(label: string): string {
  return `${testRun}_${label}@example.com`;
}

function signupPayload(label: string) {
  return {
    accountType: "real_estate_developer",
    fullName: `Signup User ${label}`,
    email: emailFor(label),
    company: "Signup Organization",
    password: validPassword,
  };
}

describe("signup", () => {
  beforeEach(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [`${testRun}%`]);
  });

  afterAll(async () => {
    await pool.query("DELETE FROM users WHERE email::text LIKE $1", [`${testRun}%`]);
    await pool.end();
  });

  it("creates a pending account and queues a usable activation token", async () => {
    const payload = signupPayload("complete");
    payload.email = payload.email.toUpperCase();
    payload.fullName = `  ${payload.fullName}  `;
    payload.company = `  ${payload.company}  `;

    const response = await request(app).post("/api/v1/auth/signup").send(payload);

    assert.equal(response.status, 201);
    assert.equal(response.body.success, true);
    assert.equal(response.body.data.email, payload.email.toLowerCase());
    assert.equal(response.body.data.accountStatus, "pending_activation");
    assert.equal("token" in response.body.data, false);
    assert.equal("activationToken" in response.body.data, false);
    assert.equal("activationPath" in response.body.data, false);

    const { rows } = await pool.query<SignupVerificationRow>(
      `
            SELECT
                users.id,
                users.email::text AS email,
                users.password_hash AS "passwordHash",
                users.account_status AS "accountStatus",
                users.full_name AS "fullName",
                users.organization_name AS "organizationName",
                roles.code AS "roleCode",
                encode(activation.token_hash, 'hex') AS "tokenHashHex",
                activation.expires_at AS "expiresAt",
                count(outbox.id)::int AS "eventCount",
                (array_agg(outbox.payload))[1] AS "eventPayload"
            FROM users
            JOIN roles ON roles.id = users.role_id
            JOIN account_activation_tokens activation
                ON activation.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'account.activation.requested'
            WHERE users.email = $1
            GROUP BY users.id, roles.id, activation.id
        `,
      [payload.email.toLowerCase()],
    );

    const verification = rows[0];
    assert.ok(verification);
    assert.equal(verification.accountStatus, "pending_activation");
    assert.equal(verification.fullName, payload.fullName.trim());
    assert.equal(verification.organizationName, payload.company.trim());
    assert.equal(verification.roleCode, "developer_administrator");
    assert.equal(verification.eventCount, 1);
    assert.equal(verification.eventPayload.userId, verification.id);
    assert.equal(verification.eventPayload.email, payload.email.toLowerCase());
    assert.equal(verification.eventPayload.channel, "email");
    assert.equal(verification.eventPayload.token.length, 43);
    assert.equal(
      verification.tokenHashHex,
      createHash("sha256").update(verification.eventPayload.token).digest("hex"),
    );
    assert.equal(
      await passwordService.verifyPassword(verification.passwordHash, validPassword),
      true,
    );

    const validateResponse = await request(app)
      .post("/api/v1/auth/activation/validate")
      .send({ token: verification.eventPayload.token });
    assert.equal(validateResponse.status, 200);

    const activationResponse = await request(app)
      .post("/api/v1/auth/activation/complete")
      .send({
        token: verification.eventPayload.token,
        termsAccepted: true,
        privacyPolicyAccepted: true,
      });
    assert.equal(activationResponse.status, 200);

    const loginResponse = await request(app).post("/api/v1/auth/login").send({
      email: payload.email,
      password: validPassword,
    });
    assert.equal(loginResponse.status, 200);
  });

  it("maps every supported account type to its business role", async () => {
    const mappings = [
      ["real_estate_developer", "developer_administrator"],
      ["brokerage_company", "brokerage_administrator"],
      ["sales_agent", "broker_agent"],
    ] as const;

    for (const [accountType, expectedRole] of mappings) {
      const payload = signupPayload(accountType);
      const response = await request(app)
        .post("/api/v1/auth/signup")
        .send({ ...payload, accountType });
      assert.equal(response.status, 201);

      const { rows } = await pool.query<RoleVerificationRow>(
        `
                SELECT roles.code AS "roleCode"
                FROM users
                JOIN roles ON roles.id = users.role_id
                WHERE users.email = $1
            `,
        [payload.email],
      );
      assert.equal(rows[0]?.roleCode, expectedRole);
    }
  });

  it("rejects duplicate email addresses without creating partial records", async () => {
    const payload = signupPayload("duplicate");

    const firstResponse = await request(app).post("/api/v1/auth/signup").send(payload);
    const secondResponse = await request(app)
      .post("/api/v1/auth/signup")
      .send({
        ...payload,
        email: payload.email.toUpperCase(),
      });

    assert.equal(firstResponse.status, 201);
    assert.equal(secondResponse.status, 409);
    assert.equal(secondResponse.body.error.code, "AUTH_EMAIL_ALREADY_REGISTERED");

    const { rows } = await pool.query<CountRow>(
      `
            SELECT
                count(DISTINCT users.id)::int AS "userCount",
                count(DISTINCT activation.id)::int AS "tokenCount",
                count(DISTINCT outbox.id)::int AS "eventCount"
            FROM users
            LEFT JOIN account_activation_tokens activation
                ON activation.user_id = users.id
            LEFT JOIN auth_outbox_events outbox
                ON outbox.aggregate_id = users.id
               AND outbox.event_type = 'account.activation.requested'
            WHERE users.email = $1
        `,
      [payload.email],
    );

    assert.deepEqual(rows[0], {
      userCount: 1,
      tokenCount: 1,
      eventCount: 1,
    });
  });

  it("rejects weak passwords before creating an account", async () => {
    const payload = signupPayload("weak");
    const response = await request(app)
      .post("/api/v1/auth/signup")
      .send({ ...payload, password: "weakpassword" });

    assert.equal(response.status, 400);
    assert.equal(response.body.error.code, "AUTH_PASSWORD_POLICY_VIOLATION");

    const { rows } = await pool.query<QueryResultRow>(
      "SELECT id FROM users WHERE email = $1",
      [payload.email],
    );
    assert.equal(rows.length, 0);
  });
});
