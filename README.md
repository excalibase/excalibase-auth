# Excalibase Auth

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue.svg)](https://www.postgresql.org/)

## Overview

Excalibase Auth is a **multi-tenant JWT authentication microservice** built in Go for the [Excalibase](https://github.com/excalibase) platform. It provides per-project user authentication with automatic schema migrations, issuing JWT access tokens that carry claims used by downstream services ([excalibase-graphql](https://github.com/excalibase/excalibase-graphql), excalibase-rest) to enforce **PostgreSQL Row-Level Security (RLS)**.

### How It Fits in the Platform

```
                          ┌────────────────────────────────────────────┐
                          │         excalibase-graphql                  │
┌──────────┐    JWT       │  1. verifies JWT (public key from vault)   │
│  Client   │────────────▶│  2. extracts userId, projectId, role       │
│           │◀────────────│  3. set_config('request.user_id', ...)     │
└──────────┘              │  4. executes query (RLS enforced)          │
     │                    └───────────────────────┬────────────────────┘
     │  register/login                            │
     ▼                                            ▼
┌──────────────────┐         credentials    ┌──────────┐
│ excalibase-auth   │◀──── vault API ──────▶│provisioning│
│ (this service)    │                       │ service    │
└──────────────────┘                        └──────────┘
```

### Features

- **Multi-tenant**: Each project gets isolated `auth` schema with its own users and tokens
- **Dynamic pool management**: Per-project PostgreSQL connection pools, cached with TTL, auto-refreshed on credential rotation
- **JWT (ECDSA ES256)**: Signing key fetched from provisioning vault at startup; tokens carry `userId`, `projectId`, `role` claims
- **Automatic migrations**: Embedded SQL migrations via [golang-migrate](https://github.com/golang-migrate/migrate) run on first connection per project
- **Refresh token rotation**: Old refresh tokens are revoked on use (single-use pattern)
- **Lightweight**: Single static Go binary (~15MB), 64MB memory baseline

## API Endpoints

All endpoints are scoped under `/auth/{orgSlug}/{projectName}/`:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/{orgSlug}/{projectName}/register` | Register a new user |
| `POST` | `/auth/{orgSlug}/{projectName}/login` | Authenticate and receive tokens |
| `POST` | `/auth/{orgSlug}/{projectName}/validate` | Validate a JWT and return claims |
| `POST` | `/auth/{orgSlug}/{projectName}/refresh` | Exchange refresh token for new token pair |
| `POST` | `/auth/{orgSlug}/{projectName}/logout` | Revoke a refresh token |
| `GET`  | `/auth/{orgSlug}/{projectName}/users` | List the project's accounts (user admin or service token) |
| `PUT`  | `/auth/{orgSlug}/{projectName}/users/{userId}/role` | Set an account's role and allowed roles (user admin or service token) |
| `GET`  | `/healthz` | Health check |

### Register

```bash
curl -X POST http://localhost:24000/auth/my-org/my-project/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123", "fullName": "Alice Smith"}'
```

**Response (201):**
```json
{
  "accessToken": "eyJhbGciOiJFUzI1NiIs...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "fullName": "Alice Smith"
  }
}
```

### Login

```bash
curl -X POST http://localhost:24000/auth/my-org/my-project/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

### Validate

```bash
curl -X POST http://localhost:24000/auth/my-org/my-project/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJFUzI1NiIs..."}'
```

**Response (200):**
```json
{
  "valid": true,
  "email": "alice@example.com",
  "userId": 1,
  "projectId": "my-org/my-project",
  "role": "user"
}
```

`userId` is absent for api-key tokens.

### Refresh

```bash
curl -X POST http://localhost:24000/auth/my-org/my-project/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "550e8400-e29b-41d4-a716-446655440000"}'
```

### Logout

```bash
curl -X POST http://localhost:24000/auth/my-org/my-project/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "550e8400-e29b-41d4-a716-446655440000"}'
```

### End-user roles

Two callers may use `/users`, both for the project in the path only:

- the control plane's **user-admin token**: `token_use: "user_admin"`, `aud: ["excalibase-auth:<projectId>"]`,
  `exp - iat` at most 60 s, and a non-empty `actor` claim naming the Studio platform user;
- the project's **secret-key token** (`role` and `scope` both `service`).

End-user, publishable-key (`anon`) and `key_admin` tokens are refused, and a `user_admin` token is refused
by `/api-keys`. No token or a bad one answers `401`; the wrong kind of token `403 insufficient_scope`; a
token for another project `403 token_project_mismatch`.

```bash
curl http://localhost:24000/auth/my-org/my-project/users?limit=100&offset=0 \
  -H "Authorization: Bearer $TOKEN"
# 200 {"users":[{"id":1,"email":"alice@example.com","role":"user","allowedRoles":["user"],"enabled":true,"emailVerified":true}]}

curl -X PUT http://localhost:24000/auth/my-org/my-project/users/1/role \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"role": "editor", "allowedRoles": ["editor", "user"]}'
# 200 {"id":1,"email":"alice@example.com","role":"editor","allowedRoles":["editor","user"],"enabled":true,"emailVerified":true}
```

- `GET /users` is ordered by id; `limit` defaults to 100 (1–500), `offset` to 0; others answer `400 invalid_pagination`.
- `allowedRoles` is optional (stored as `NULL`, read as `[role]`), must contain `role`, and holds at most 20 names.
- `PUT` answers `400` with `invalid_request`, `invalid_user_id`, `invalid_role`, `reserved_role`,
  `role_not_in_allowed_roles` or `too_many_allowed_roles`; `404 user_not_found`. It shares the `/token` per-IP rate limit.
- A change revokes every refresh token of the account in the same transaction, so the new roles apply at its
  next sign-in, and writes an `auth.role_changes` row whose `actor` is `studio:<actor>` or `service-key:<keyId>`.

## Quick Start

### Prerequisites

- Go 1.24+
- Docker (for tests and local development)

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/excalibase/excalibase-auth.git
cd excalibase-auth

# Set your provisioning service PAT
export PROVISIONING_PAT=your-pat-here

# Start auth service + PostgreSQL
make docker.up
```

The service will be available at `http://localhost:24000`.

### Option 2: Run Locally

```bash
git clone https://github.com/excalibase/excalibase-auth.git
cd excalibase-auth

# Required: provisioning service must be running
export PROVISIONING_PAT=your-pat-here
export PROVISIONING_URL=http://localhost:24005/api

make dev
```

### Option 3: Build Binary

```bash
make build
./bin/excalibase-auth
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROVISIONING_PAT` | — (required unless `PROVISIONING_PAT_FILE` is set) | Access token for vault API access |
| `PROVISIONING_PAT_FILE` | — | Path to a token file rotated in place; re-read on each provisioning call, no restart needed. If both this and `PROVISIONING_PAT` are set, the file wins; `PROVISIONING_PAT` is only the seed value used until the file is first read. With neither set, or a file that is empty/unreadable and has never yielded a value, startup and every provisioning call fail with an explicit error rather than sending an empty bearer token. |
| `PROVISIONING_URL` | `http://localhost:24005/api` | Provisioning service base URL |
| `PORT` | `24000` | HTTP server port |
| `ACCESS_TTL` | `3600` | Access token lifetime in seconds (the signed `exp` and the advertised `expires_in`) |
| `REFRESH_EXPIRATION` | `604800` | Refresh token TTL in seconds (default: 7d) |
| `RATE_LIMIT_ENABLED` | `true` | Throttle the credential endpoints (see below) |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window for the per-IP and per-project budgets |
| `RATE_LIMIT_REGISTER_PER_IP` | `5` | `/register` requests per client IP per window |
| `RATE_LIMIT_LOGIN_PER_IP` | `10` | `/login` requests per client IP per window |
| `RATE_LIMIT_TOKEN_PER_IP` | `30` | `/token` (and legacy `/refresh`) requests per client IP per window |
| `RATE_LIMIT_REGISTER_PER_PROJECT` | `60` | `/register` requests per project per window, across all IPs |
| `RATE_LIMIT_LOGIN_FAILURES` | `5` | Failed logins per identity before the identity is locked |
| `RATE_LIMIT_LOGIN_FAILURE_WINDOW_SECONDS` | `900` | Window over which login failures are counted |
| `TRUSTED_PROXY_CIDRS` | — (empty) | Comma-separated CIDRs allowed to set `X-Forwarded-For` |
| `TENANT_DB_SSLMODE` | `verify-full` | `disable` (docker AIO only: password login, no TLS) or a TLS mode. `require`, `verify-ca` and `verify-full` all mean verify-full with the client certificate from the vault record (`sslcert`/`sslkey`/`sslrootcert`); a record without them is refused. `prefer`/`allow` and anything else fail startup |

### Rate Limiting

`/register`, `/login`, `/token` and the legacy `/refresh` alias are throttled with keyed token buckets:

| Scope | Key | Default |
|-------|-----|---------|
| Per client IP | resolved address | 5/min register, 10/min login, 30/min token+refresh |
| Per project | `{projectId}` from the URL | 60/min register |
| Per identity | SHA-256 of the lower-cased email (never logged or stored in clear) | 5 failed logins per 15 min, on `/login` and `/token` with `grant_type=password`; a successful login clears the counter |

A throttled request gets `429` with a `Retry-After` header and the body:

```json
{"error": "rate_limited", "retryAfter": 12}
```

Every rejection increments `auth_rate_limited_total{route="register|login|token"}` on `/metrics`.

**Client address behind a proxy.** The TCP peer address is used unless it falls inside `TRUSTED_PROXY_CIDRS`, in which case `X-Forwarded-For` is walked from the right and the first hop that is not a trusted proxy wins. A client sending its own `X-Forwarded-For` therefore cannot pick its bucket. The forgot-password per-IP cap resolves the client the same way. Set the variable to the ingress or load-balancer address range only; leaving it empty is safe but collapses all clients behind a proxy into one bucket, and a malformed value fails startup.

**Multi-replica semantics.** Counters live in each pod's memory. The service has no shared store (its only database is the per-tenant pool the limiter is protecting), so with N replicas a client can spend up to N times each budget. Divide the values by the replica count when tuning, or put a coarse global limiter on the ingress.

## Architecture

### Project Structure

```
excalibase-auth/
├── cmd/server/          # Application entrypoint
├── internal/
│   ├── auth/            # JWT signing/verification (ECDSA ES256)
│   ├── config/          # Environment-based configuration
│   ├── domain/          # Domain types and DTOs
│   ├── handler/         # HTTP handlers (chi router)
│   ├── migrate/         # golang-migrate runner with embedded SQL
│   │   └── migrations/  # Versioned SQL migration files
│   └── pool/            # Multi-tenant connection pool manager
├── e2e/                 # End-to-end tests
├── helm/                # Kubernetes Helm chart
├── devbox/docker/       # Docker Compose for local dev
├── Dockerfile           # Multi-stage build
└── Makefile
```

### Multi-Tenant Connection Flow

1. Request arrives at `/auth/{orgSlug}/{projectName}/register`
2. `pool.Manager` checks cache for an existing pool for this project
3. If missing or expired (1h TTL, the ceiling), fetches credentials from provisioning vault:
   `GET {PROVISIONING_URL}/vault/secrets/projects/{projectId}/credentials/auth_admin`
4. Creates a new `pgxpool.Pool` (verify-full + the record's client certificate unless `TENANT_DB_SSLMODE=disable`) and runs golang-migrate migrations over that pool
5. If the record changed (rotated password, renewed certificate or CA), the old pool is closed and replaced
6. Handler executes queries against the per-tenant `auth` schema

### Database Schema

Each project gets an `auth` schema with two tables, managed by golang-migrate:

```sql
-- auth.users
id BIGSERIAL PRIMARY KEY
email VARCHAR(100) UNIQUE NOT NULL
password VARCHAR(255) NOT NULL        -- bcrypt hash
full_name VARCHAR(100) NOT NULL
role VARCHAR(63) DEFAULT 'user'
enabled BOOLEAN DEFAULT true
created_at TIMESTAMPTZ
updated_at TIMESTAMPTZ
last_login_at TIMESTAMPTZ

allowed_roles TEXT[]                  -- NULL = [role]

-- auth.role_changes (one row per role change)
id BIGSERIAL PRIMARY KEY
user_id BIGINT REFERENCES users(id) ON DELETE CASCADE
old_role, new_role TEXT NOT NULL
old_allowed_roles, new_allowed_roles TEXT[] NOT NULL
actor TEXT NOT NULL                   -- studio:<platform user id> | service-key:<api key id>
changed_at TIMESTAMPTZ

-- auth.refresh_tokens
id BIGSERIAL PRIMARY KEY
token_hash CHAR(64) UNIQUE NOT NULL  -- SHA-256 of the token; the plaintext is never stored
family_id UUID NOT NULL               -- one login; replaying a rotated token revokes the family
user_id BIGINT REFERENCES users(id) ON DELETE CASCADE
expiry_date TIMESTAMPTZ NOT NULL      -- set at login; rotation keeps it
created_at TIMESTAMPTZ
revoked BOOLEAN DEFAULT false
```

### JWT Claims

Tokens are signed with ECDSA P-256 (ES256). The private key is fetched from the provisioning vault at startup.

```json
{
  "sub": "alice@example.com",
  "userId": 1,
  "projectId": "my-org/my-project",
  "orgSlug": "my-org",
  "projectName": "my-project",
  "orgName": "My Org",
  "role": "user",
  "allowed_roles": ["user"],
  "scope": "authenticated",
  "email_verified": true,
  "token_use": "access",
  "aud": ["excalibase:my-org/my-project"],
  "iss": "excalibase",
  "iat": 1712200000,
  "exp": 1712286400
}
```

`role` is the default role the engine runs the request as; `allowed_roles` lists the roles the token
may act as and always contains `role`.

| Token | `role` / `allowed_roles` | `scope` | `userId` | `sub` |
|-------|--------------------------|---------|----------|-------|
| password login, registration, refresh | `users.role` / `users.allowed_roles` (or `[role]` when unset) | `authenticated` | the account id | email |
| publishable api key | `anon` / `["anon"]` | `public` | absent | `apikey:<id>` |
| secret api key | `service` / `["service"]` | `service` | absent | `apikey:<id>` |

An account's roles are read from `users.role` and `users.allowed_roles` at every login and refresh.
Every name must match `^[a-z][a-z0-9_]{0,62}$` and must not be reserved: `anon`, `service`, the platform
roles `postgres`, `auth_admin`, `excalibase_app`, `cdc_watcher`, `streaming_replica`,
`excalibase_docbrowser`, `app`, or any name starting with `pg_` or `excalibase_`; `role` must be one of
the allowed roles. Otherwise login and refresh answer `403 {"error": "invalid_account_role"}`.

excalibase-graphql fetches the public key from the provisioning vault, verifies the JWT directly, and uses the claims to set PostgreSQL RLS context:
```sql
SELECT set_config('request.user_id', '1', true);
-- RLS policies then filter rows based on current_setting('request.user_id')
```

## Testing

```bash
# Unit tests (no Docker required)
make test.unit

# Unit + integration tests (uses testcontainers — needs Docker)
make test

# E2E tests (starts docker-compose PostgreSQL + builds real binary)
make test.e2e

# Run a single test
go test ./internal/handler/ -run TestIntegration_FullAuthFlow -count=1
```

### Test Strategy

| Layer | Tool | Docker Required | What It Tests |
|-------|------|-----------------|---------------|
| Unit | `go test -short` | No | Input validation, error paths, JWT signing |
| Integration | testcontainers-go | Yes | Full auth flows against real PostgreSQL |
| Migration | testcontainers-go | Yes | Schema up/down/idempotent/roundtrip |
| E2E | docker-compose + binary | Yes | Real HTTP requests against running server |

## Deployment

### Docker

```bash
# Build image
make docker.build

# Run with docker-compose (auth + PostgreSQL)
make docker.up

# Stop
make docker.down
```

### Kubernetes (Helm)

```bash
helm install excalibase-auth ./helm/excalibase-auth \
  --set provisioning.url=http://excalibase-provisioning:24005/api \
  --set provisioning.pat=your-pat-here
```

Or with an existing secret:
```bash
kubectl create secret generic auth-secrets \
  --from-literal=provisioning-pat=your-pat-here

helm install excalibase-auth ./helm/excalibase-auth \
  --set provisioning.url=http://excalibase-provisioning:24005/api \
  --set provisioning.existingSecret=auth-secrets
```

See [helm/excalibase-auth/values.yaml](helm/excalibase-auth/values.yaml) for all configurable values.

## Database Roles

The provisioning service creates two roles per project:

| Role | Purpose |
|------|---------|
| `auth_admin` | Owns the `auth` schema. Used by this service for user registration, login, token management |
| `excalibase_app` | Has `public` schema access with RLS enforced. Used by excalibase-graphql/rest for data queries |

## Related Services

| Service | Description |
|---------|-------------|
| [excalibase-provisioning](https://github.com/excalibase/excalibase-provisioning) | Project provisioning, vault, database creation |
| [excalibase-graphql](https://github.com/excalibase/excalibase-graphql) | Auto-generated GraphQL API with RLS |

## License

This project is licensed under the [Apache License 2.0](LICENSE).
