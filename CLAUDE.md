# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

excalibase-auth is a multi-tenant JWT authentication microservice for the Excalibase platform. Each tenant (project) gets its own PostgreSQL database with an `auth` schema. The service dynamically provisions connection pools per project by fetching credentials from the provisioning service's vault. JWTs issued here carry userId, projectId, and role claims used by GraphQL/REST APIs to enforce PostgreSQL RLS policies.

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

**Multi-tenant pool pattern**: Requests include `{projectId}` in the URL. `pool.Manager` lazily creates/caches a `pgxpool.Pool` per project by calling the provisioning API for credentials. Pools are cached with a TTL and refreshed when credentials rotate. On first pool creation per project, golang-migrate runs embedded SQL migrations automatically.

**Request flow**: HTTP request -> chi router -> `handler.AuthHandler` -> `pool.Manager.GetPool(projectID)` -> auto-migrate -> per-tenant PostgreSQL query.

**Key packages**:
- `internal/pool` — Multi-tenant connection pool manager. Fetches credentials from `{PROVISIONING_URL}/vault/secrets/projects/{id}/credentials/auth_admin`. Has injectable `poolCreator` and `migrator` functions.
- `internal/migrate` — golang-migrate runner with embedded SQL files (`internal/migrate/migrations/`). Provides `Run(connStr)` and `Down(connStr)`.
- `internal/auth` — JWT signing/verification using ECDSA (ES256). Private key fetched from vault at startup.
- `internal/handler` — HTTP handlers for register, login, validate, refresh, logout. All routes scoped under `/auth/{projectId}/`.
- `internal/domain` — Domain types and DTOs.
- `internal/config` — Env-based config.

**Database schema** (per tenant, `auth` schema): `users` table + `refresh_tokens` table. Managed by golang-migrate migrations in `internal/migrate/migrations/`.

## Environment Variables

| Variable | Default | Required |
|---|---|---|
| `PROVISIONING_PAT` | — | Yes |
| `PROVISIONING_URL` | `http://localhost:24005/api` | No |
| `PORT` | `24000` | No |
| `JWT_EXPIRATION` | `86400` (seconds) | No |
| `REFRESH_EXPIRATION` | `604800` (seconds) | No |

## Testing Strategy

- **Unit tests** (`_unit_test.go`, `_test.go` with `-short`): Mock the pool manager and HTTP dependencies. No Docker needed.
- **Integration tests** (`_test.go` without `-short`): Use testcontainers-go to spin up PostgreSQL. Migrations run via `migrate.Run()`.
- **E2E tests** (`e2e/`, build tag `e2e`): Full HTTP tests against a real auth binary + docker-compose PostgreSQL on port 5433.

## Docker

- `Dockerfile` — Multi-stage build (golang:1.24-alpine -> alpine:3.20). Migrations are embedded in the binary.
- `devbox/docker/docker-compose.yml` — Runs auth service + PostgreSQL together.
