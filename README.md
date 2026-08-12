# LF Auth Backend

TypeScript/Express/PostgreSQL authentication microservice for LynkFlow.

## Setup

When working from the adjacent `base-fe` repository, the recommended setup is:

```powershell
cd ..\base-fe
npm.cmd run setup:local
npm.cmd run dev:stack
```

This uses an isolated PostgreSQL database on port 5433 and runs this service on
port 4000. The manual setup below remains available for standalone use.

1. Copy `.env.example` to `.env` and set `DATABASE_URL`. Percent-encode reserved characters in URL credentials.
2. Run `npm install`.
3. Run `npm run jwt:keys:generate` once to create ignored local development signing keys.
4. Run `npm run db:migrate`.
5. Run `npm run dev`.

The application validates its environment at startup and never logs the database URL.

## Development commands

- `npm run dev` compiles the TypeScript source, starts the service, and restarts it when a `.ts` file changes.
- `npm run typecheck` checks both application and test code with strict TypeScript settings without emitting files.
- `npm run build` emits production JavaScript and source maps to `dist/`.
- `npm start` starts the compiled production application from `dist/`.
- `npm test` applies migrations, compiles the test target, and runs the integration suite.
- `npm run db:migrate:production` applies migrations using an existing production build.
- `npm run jwt:keys:generate` creates a local RSA key pair in the ignored `.secrets` directory. Production keys must be supplied through a secret manager or mounted secret files.
- `npm run dev:email-worker` runs the email outbox worker with source watching in a second development terminal.
- `npm run email:worker` builds and runs the email outbox worker once as a long-running process.
- `npm run email:worker:production` runs the worker from an existing production build.

## Login API

`POST /api/v1/auth/login`

```json
{
  "email": "user@example.com",
  "password": "user password",
  "rememberMe": false
}
```

Successful authentication returns the safe user profile and a signed RS256 access JWT. The JWT expires after 15 minutes and is sent to protected APIs as `Authorization: Bearer <access-token>`.

The response also sets a rotating opaque refresh token in the HTTP-only `lf.refresh` cookie. Only its SHA-256 hash is stored in PostgreSQL. The cookie is scoped to `/api/v1/auth/token`, so it is not sent to normal application APIs.

Account status responses are returned only after the submitted password is verified. Unknown accounts and incorrect passwords receive the same generic error.

## Sign-up API

Create a self-service account with `POST /api/v1/auth/signup`:

```json
{
  "accountType": "real_estate_developer",
  "fullName": "Example User",
  "email": "user@example.com",
  "company": "Example Company",
  "password": "Secure Signup 42!"
}
```

Supported account types are `real_estate_developer`, `brokerage_company`, and `sales_agent`. They map to the existing Developer Administrator, Brokerage Administrator, and Broker Agent roles respectively.

A successful request creates a `pending_activation` user and atomically queues an `account.activation.requested` email event. Only the activation token's SHA-256 hash is stored in `account_activation_tokens`; the raw token is placed in the outbox payload for the future email worker and is never returned by the API.

## Logout API

An authenticated user can terminate their current session with:

```http
POST /api/v1/auth/token/logout
```

The request has no body. The browser automatically sends the HTTP-only refresh-token cookie. Logout revokes only that refresh session, expires its cookie, and returns `/` as the Welcome-page redirect target. Other active sessions for the same account are not affected.

Logout is idempotent: a missing, expired, invalid, or already-revoked cookie still receives a successful response and a cookie-clearing header. A forged cookie cannot revoke another session because its token hash must match either the current refresh credential or a credential previously issued within that token family.

## Token refresh API

Obtain a new access JWT with `POST /api/v1/auth/token/refresh`. The request has no body; the browser automatically sends the HTTP-only refresh-token cookie.

```json
{
  "success": true,
  "message": "Access token refreshed successfully.",
  "data": {
    "accessToken": "eyJ...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "accessTokenExpiresAt": "2026-08-12T12:15:00.000Z",
    "session": {
      "expiresAt": "2026-08-12T20:00:00.000Z"
    }
  }
}
```

Every successful refresh rotates the refresh token. Reusing an older token revokes that session family. A forged token does not revoke a legitimate session.

Other microservices can verify access tokens with the public JWKS endpoint at `GET /.well-known/jwks.json`. The private signing key is never exposed.

## Account activation API

Validate an activation link with `POST /api/v1/auth/activation/validate`:

```json
{
  "token": "43-character-base64url-token"
}
```

The response contains the invited account's read-only organization name, full name, email address, current agreement versions, and token expiry.

Complete activation with `POST /api/v1/auth/activation/complete`:

```json
{
  "token": "43-character-base64url-token",
  "password": "Secure Activation 42!",
  "confirmPassword": "Secure Activation 42!",
  "termsAccepted": true,
  "privacyPolicyAccepted": true
}
```

For accounts created through the sign-up endpoint, `password` and `confirmPassword` can be omitted from activation completion because the password was already securely hashed during sign-up. Invited accounts without a password must provide both fields.

Activation tokens are random 256-bit values. Only their SHA-256 hashes are stored. A successful activation atomically hashes the initial password with Argon2id, records the current agreement versions, marks the account active, consumes the token, revokes other outstanding activation tokens, and queues an `account.activated` email event in `auth_outbox_events`.

The password policy and 24-hour token validity default are stored in `auth_settings` so they can be changed without redeploying the service. The default password policy requires 12-128 characters containing uppercase, lowercase, numeric, and symbol characters.

## Password management API

Request a password reset with `POST /api/v1/auth/password/forgot`:

```json
{
  "email": "user@example.com"
}
```

The endpoint always returns the same accepted response for syntactically valid email addresses, whether or not an active account exists. For active accounts, it invalidates previous links, creates a one-time 256-bit token with a configurable 30-minute default lifetime, and queues a `password.reset.requested` email event.

Validate a reset link with `POST /api/v1/auth/password/reset/validate`:

```json
{
  "token": "password-reset-token"
}
```

Complete a reset with `POST /api/v1/auth/password/reset`:

```json
{
  "token": "password-reset-token",
  "newPassword": "New Secure Password 84!",
  "confirmPassword": "New Secure Password 84!"
}
```

A successful reset updates the Argon2id password hash, consumes the supplied token, invalidates every other reset token for the account, resets login-failure state, terminates all sessions by default, and queues a `password.reset.completed` email event.

An authenticated user can change their password with `POST /api/v1/auth/password/change`:

```json
{
  "currentPassword": "Current Password 42!",
  "newPassword": "New Secure Password 84!",
  "confirmPassword": "New Secure Password 84!"
}
```

The route operates only on the Bearer token's user account. It verifies the current password, rejects password reuse, enforces the configured policy, invalidates outstanding reset links, preserves the current refresh session, terminates other sessions by default, and queues a `password.changed` email event.

## Security defaults

- Argon2id password hashing (19 MiB memory, two iterations, one lane)
- Persistent account lockout after five failures for 15 minutes
- Per-IP login rate limiting
- RS256 access JWTs with explicit issuer, audience, type, key ID, and algorithm validation
- 15-minute access-token lifetime with a small configured clock tolerance
- Public JWKS endpoint for independent microservice verification
- Rotating random refresh tokens stored only as SHA-256 hashes
- Refresh-token reuse detection and session-family revocation
- 30-minute idle session timeout and 8-hour absolute timeout
- 30-day absolute timeout for remembered sessions
- HTTP-only, SameSite=Strict, path-scoped refresh-token cookie
- Secure cookies mandatory when `NODE_ENV=production`
- Parameterized PostgreSQL queries and strict request validation
- Helmet security headers and disabled Express fingerprinting
- Authentication responses marked `no-store`
- One-time, expiring account-activation tokens stored only as hashes
- Transactional agreement acceptance and activation notification outbox
- Generic forgot-password responses that prevent account enumeration
- Single-use password-reset tokens with configurable expiry
- Configurable session termination after password reset or change

Session and lockout values are stored in the singleton `auth_settings` row so a future Platform Administrator endpoint can update them without redeploying the service.

Migration `004_add_jwt_refresh_sessions.sql` revokes legacy opaque-cookie sessions once because their old format cannot be safely converted into rotating refresh credentials. Existing users must log in again after that migration.

## Email delivery worker

Auth transactions continue to insert durable events into `auth_outbox_events`. A separate worker sends those events to the notification service:

```http
POST http://localhost:3010/api/v1/emails/send
Content-Type: application/json
Idempotency-Key: auth-outbox:<event-id>:<generation>
```

Template codes match the outbox event types exactly:

- `account.activation.requested`
- `account.activated`
- `password.reset.requested`
- `password.reset.completed`
- `password.changed`

Run the API and worker in separate development terminals:

```bash
npm run dev
npm run dev:email-worker
```

The worker atomically claims batches with `FOR UPDATE SKIP LOCKED`, commits the claim before making the HTTP request, and marks successful events with `published_at`. Failures use exponential backoff with jitter and become dead-lettered in `failed_at` after the configured maximum attempts. A stable idempotency key protects ambiguous network retries; the generation advances only when the notification service reports an idempotency conflict.

After successful publication or permanent failure, sensitive `token` values are removed from the retained outbox payload. Monitor rows where `failed_at IS NOT NULL` and alert on a growing unpublished backlog.

Useful operational queries:

```sql
SELECT count(*)
FROM auth_outbox_events
WHERE published_at IS NULL AND failed_at IS NULL;

SELECT id, event_type, delivery_attempts, last_error, failed_at
FROM auth_outbox_events
WHERE failed_at IS NOT NULL
ORDER BY failed_at DESC;
```

## Database roles

The migration connection may own schema objects, but the deployed application must use a separate least-privilege login role. Grant that role only `CONNECT`, schema `USAGE`, and the required DML/sequence privileges; do not run the service as a PostgreSQL superuser.

## Tests

`npm test` applies pending migrations and runs the integration suite against the configured database. Test users and sessions are removed after the suite.
