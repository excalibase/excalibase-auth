# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

excalibase-auth is a multi-tenant JWT authentication microservice for the Excalibase platform. Each tenant (project) keeps its end users in its own database: an `auth` schema on a Postgres project, an `auth` database inside the project's instance on a MySQL project (ADR 0041). The service dynamically provisions connection pools per project by fetching credentials from the provisioning service's vault. JWTs issued here carry userId, projectId, and role claims used by GraphQL/REST APIs to enforce PostgreSQL RLS policies.

## Build & Test Commands

```bash
make build              # Build binary to bin/excalibase-auth
make test               # Unit + integration tests (integration uses testcontainers, needs Docker)
make test.unit          # Unit tests only (no Docker needed), uses -short flag
make test.e2e           # E2E tests against docker-compose PostgreSQL
make docker.build       # Build Docker image
make docker.up          # Start auth + PostgreSQL via docker-compose
make docker.down        # Stop all services
make dev                # Run server locally (needs PROVISIONING_PAT env var)
```

Run a single test:
```bash
go test ./internal/handler/ -run TestRegister -count=1
```

The Makefile defaults to `go` from PATH. Override with `make GO=/path/to/go build` if needed.

## Architecture

**Multi-tenant store pattern**: Requests include `{projectId}` in the URL. `pool.Manager` lazily creates/caches a `store.Store` per project by calling the provisioning API for credentials; the vault record's `engine` field picks Postgres (absent) or MySQL (`mysql`, TLS verified against the record's `sslrootcert`), anything else is refused. Pools are cached with a TTL and refreshed when credentials rotate. On first pool creation per project, golang-migrate runs embedded SQL migrations automatically.

**Request flow**: HTTP request -> chi router -> `handler.AuthHandler` -> `pool.Manager.GetStore(projectID)` -> auto-migrate -> per-tenant query through `internal/store/pgstore` or `internal/store/mysqlstore`.

**Key packages**:
- `internal/pool` — Multi-tenant connection pool manager. Fetches credentials from `{PROVISIONING_URL}/vault/secrets/projects/{id}/credentials/auth_admin`. Has injectable `poolCreator` and `migrator` functions.
- `internal/store` — the per-project end-user store interface; `pgstore` and `mysqlstore` implement it and `storetest` is the contract both pass against real databases.
- `internal/migrate` — golang-migrate runner with embedded SQL files, one tree per engine (`migrations/postgres/`, `migrations/mysql/`, versioned separately; a schema change needs a file in each). Provides `Run(ctx, pool)` and `Down(ctx, pool)`, run over the tenant's own pool so migrations authenticate like it (client certificate included).
- `internal/auth` — JWT signing/verification using ECDSA (ES256). Private key fetched from vault at startup.
- `internal/handler` — HTTP handlers for register, login, validate, refresh, logout. All routes scoped under `/auth/{projectId}/`.
- `internal/ratelimit` — keyed token-bucket limiter (in-memory, per replica) plus client-IP resolution behind trusted proxies and hashed identity keys.
- `internal/middleware` — CORS, security headers, tenant context, JWT guard, and the per-route rate-limit middleware (`RateLimits`) wired into the handler via `WithRateLimits`.
- `internal/oauth` — Google/GitHub sign-in: PKCE, Google id_token checks, redirect allow-list. `internal/testutil/idpfake` fakes both providers.
- `internal/emailotp` — eight-digit sign-in codes and the HMAC they are stored as (`handler/email_otp.go` serves `/otp` and `/verify`).
- `handler/linking.go` — a signed-in user links/unlinks Google, GitHub or another address (`/user/identities`); needs `auth_time` within 5 minutes, writes the link only when the app's PKCE verifier spends the code.
- `handler/user.go`, `email_change.go`, `sign_out.go`, `user_admin_detail.go` — the signed-in account (`/user`, address change, sign-out scopes) and admin read/merge/delete of accounts, behind `/info`'s `userApiEnabled`; `link_notice.go` mails the account when a way in is added.
- `internal/hooks` + `handler/auth_hooks.go` — the project's auth hooks (`authhooks`): Standard Webhooks signing, the public-address dialer (`internal/publicaddr`, a copy of the control plane's), 2 s / 64 KB limits, the claim rules for `custom_access_token`; every failure is `503 auth_hook_failed`.
- `handler/guest.go` — guest accounts (`/guest`, `authguest`): no address, role `guest`, tenant-DB budgets, optional Turnstile, the daily sweep of idle guests; upgrades go through `linking.go` and `email_change.go`.
- `internal/domain` — Domain types and DTOs.
- `internal/config` — Env-based config.

**Database schema** (per tenant, `auth` schema): `users` (password NULL for provider-made accounts), `refresh_tokens`, `identities`, `flow_states`, `auth_codes`, `email_otps` (+ `email_otp_lock`), `audit_log`, `email_change_tokens`, `users.user_metadata`/`app_metadata` (never in the token), `users.is_guest` with `guest_sign_ups` and `guest_lock`, and the link/key tables. Managed by golang-migrate migrations in `internal/migrate/migrations/`.

## Environment Variables

| Variable | Default | Required |
|---|---|---|
| `PROVISIONING_PAT` | — | Yes, unless `PROVISIONING_PAT_FILE` is set. If both are set, the file wins (env only seeds the value until first read). Neither set, or an unreadable/empty file with no prior good value: fails fast with an explicit error, never an empty bearer token. |
| `PROVISIONING_PAT_FILE` | — | Path to a rotatable token file, re-read on each provisioning call |
| `PROVISIONING_URL` | `http://localhost:24005/api` | No |
| `PORT` | `24000` | No |
| `ACCESS_TTL` | `3600` (seconds) | No |
| `REFRESH_EXPIRATION` | `604800` (seconds) | No |
| `RATE_LIMIT_ENABLED` | `true` | No |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | No |
| `RATE_LIMIT_REGISTER_PER_IP` / `_LOGIN_PER_IP` / `_TOKEN_PER_IP` | `5` / `10` / `30` | No |
| `RATE_LIMIT_REGISTER_PER_PROJECT` | `60` | No |
| `RATE_LIMIT_LOGIN_FAILURES` / `_LOGIN_FAILURE_WINDOW_SECONDS` | `5` / `900` | No |
| `RATE_LIMIT_OTP_PER_IP` | `5` (per `RATE_LIMIT_WINDOW_SECONDS`; the per-address and per-project budgets live in the tenant DB) | No |
| `TRUSTED_PROXY_CIDRS` | — (XFF never trusted) | No |
| `CORS_ORIGINS` | `https://app.excalibase.io` (platform/Studio; project routes add the project's allowlist) | No |
| `PROJECT_CORS_TTL_SECONDS` | `30` | No |
| `REQUEST_METRICS_ENABLED` | `false` (only `true` turns it on) | No. Per-project request counts and latency on an internal listener for Studio's request charts (EXC-656) |
| `REQUEST_METRICS_PORT` / `REQUEST_METRICS_MAX_PROJECTS` | `9465` / `1000` | No |
| `GUEST_INACTIVE_DAYS` | `30` (1 to 3650) | No. Idle guest accounts are deleted after this many days |
| `AUTH_HOOKS_DENY_CIDRS` | — | No. Extra ranges auth hooks may never reach |
| `AUTH_HOOKS_CA_FILE` | — | No. Extra PEM roots for verifying hook servers |

## Testing Strategy

- **Unit tests** (`_unit_test.go`, `_test.go` with `-short`): Mock the pool manager and HTTP dependencies. No Docker needed.
- **Integration tests** (`_test.go` without `-short`): Use testcontainers-go to spin up PostgreSQL. Migrations run via `migrate.Run()`.
- **E2E tests** (`e2e/`, build tag `e2e`): Full HTTP tests against a real auth binary + docker-compose PostgreSQL on port 5433.

## Docker

- `Dockerfile` — Multi-stage build (golang:1.26.10-alpine -> distroless static). Migrations are embedded in the binary.
- `devbox/docker/docker-compose.yml` — Runs auth service + PostgreSQL together.
