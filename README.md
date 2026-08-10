# LF Auth Backend

TypeScript/Express/PostgreSQL authentication microservice for LynkFlow.

## Setup

1. Copy `.env.example` to `.env` and set `DATABASE_URL`. Percent-encode reserved characters in URL credentials.
2. Run `npm install`.
3. Run `npm run db:migrate`.
4. Run `npm run dev`.

The application validates its environment at startup and never logs the database URL.

## Development commands

- `npm run dev` compiles the TypeScript source, starts the service, and restarts it when a `.ts` file changes.
- `npm run typecheck` checks both application and test code with strict TypeScript settings without emitting files.
- `npm run build` emits production JavaScript and source maps to `dist/`.
- `npm start` starts the compiled production application from `dist/`.
- `npm test` applies migrations, compiles the test target, and runs the integration suite.
- `npm run db:migrate:production` applies migrations using an existing production build.

## Login API

`POST /api/v1/auth/login`

```json
{
  "email": "user@example.com",
  "password": "user password",
  "rememberMe": false
}
```

Successful authentication returns the safe user profile, role, permissions, and session expiry. The opaque session identifier is sent only in the HTTP-only `lf.sid` cookie and is stored in PostgreSQL only as a SHA-256 hash.

Account status responses are returned only after the submitted password is verified. Unknown accounts and incorrect passwords receive the same generic error.

## Logout API

An authenticated user can terminate their current session with:

```http
POST /api/v1/auth/logout
```

The request uses the HTTP-only session cookie and requires no request body. A successful logout revokes only the current database session, expires the session cookie, and returns `/` as the Welcome-page redirect target. Other active sessions for the same account are not affected. Frontend confirmation and navigation are handled by the client application.

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

The route operates only on the session user's account. It verifies the current password, rejects password reuse, enforces the configured policy, invalidates outstanding reset links, preserves the current session, terminates other sessions by default, and queues a `password.changed` email event.

## Security defaults

- Argon2id password hashing (19 MiB memory, two iterations, one lane)
- Persistent account lockout after five failures for 15 minutes
- Per-IP login rate limiting
- 30-minute idle session timeout and 8-hour absolute timeout
- 30-day absolute timeout for remembered sessions
- HTTP-only, SameSite=Strict, high-priority session cookie
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

## Database roles

The migration connection may own schema objects, but the deployed application must use a separate least-privilege login role. Grant that role only `CONNECT`, schema `USAGE`, and the required DML/sequence privileges; do not run the service as a PostgreSQL superuser.

## Tests

`npm test` applies pending migrations and runs the integration suite against the configured database. Test users and sessions are removed after the suite.
