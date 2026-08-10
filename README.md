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

Session and lockout values are stored in the singleton `auth_settings` row so a future Platform Administrator endpoint can update them without redeploying the service.

## Database roles

The migration connection may own schema objects, but the deployed application must use a separate least-privilege login role. Grant that role only `CONNECT`, schema `USAGE`, and the required DML/sequence privileges; do not run the service as a PostgreSQL superuser.

## Tests

`npm test` applies pending migrations and runs the integration suite against the configured database. Test users and sessions are removed after the suite.
