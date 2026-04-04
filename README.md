# Excalibase Auth

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](https://go.dev/)
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

All endpoints are scoped under `/auth/{projectId}/`:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/{projectId}/register` | Register a new user |
| `POST` | `/auth/{projectId}/login` | Authenticate and receive tokens |
| `POST` | `/auth/{projectId}/validate` | Validate a JWT and return claims |
| `POST` | `/auth/{projectId}/refresh` | Exchange refresh token for new token pair |
| `POST` | `/auth/{projectId}/logout` | Revoke a refresh token |
| `GET`  | `/healthz` | Health check |

### Register

```bash
curl -X POST http://localhost:24000/auth/my-project/register \
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
curl -X POST http://localhost:24000/auth/my-project/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

### Validate

```bash
curl -X POST http://localhost:24000/auth/my-project/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJFUzI1NiIs..."}'
```

**Response (200):**
```json
{
  "valid": true,
  "email": "alice@example.com",
  "userId": 1,
  "projectId": "my-project",
  "role": "user"
}
```

### Refresh

```bash
curl -X POST http://localhost:24000/auth/my-project/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "550e8400-e29b-41d4-a716-446655440000"}'
```

### Logout

```bash
curl -X POST http://localhost:24000/auth/my-project/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "550e8400-e29b-41d4-a716-446655440000"}'
```

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
| `PROVISIONING_PAT` | — (required) | Personal access token for vault API access |
| `PROVISIONING_URL` | `http://localhost:24005/api` | Provisioning service base URL |
| `PORT` | `24000` | HTTP server port |
| `JWT_EXPIRATION` | `86400` | Access token TTL in seconds (default: 24h) |
| `REFRESH_EXPIRATION` | `604800` | Refresh token TTL in seconds (default: 7d) |

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

1. Request arrives at `/auth/{projectId}/register`
2. `pool.Manager` checks cache for an existing pool for this project
3. If missing or expired (1h TTL), fetches credentials from provisioning vault:
   `GET {PROVISIONING_URL}/vault/secrets/projects/{projectId}/credentials/auth_admin`
4. Creates a new `pgxpool.Pool` and runs golang-migrate migrations
5. If credentials rotated, old pool is gracefully closed and replaced
6. Handler executes queries against the per-tenant `auth` schema

### Database Schema

Each project gets an `auth` schema with two tables, managed by golang-migrate:

```sql
-- auth.users
id BIGSERIAL PRIMARY KEY
email VARCHAR(100) UNIQUE NOT NULL
password VARCHAR(255) NOT NULL        -- bcrypt hash
full_name VARCHAR(100) NOT NULL
role VARCHAR(50) DEFAULT 'user'
enabled BOOLEAN DEFAULT true
created_at TIMESTAMPTZ
updated_at TIMESTAMPTZ
last_login_at TIMESTAMPTZ

-- auth.refresh_tokens
id BIGSERIAL PRIMARY KEY
token VARCHAR(255) UNIQUE NOT NULL
user_id BIGINT REFERENCES users(id) ON DELETE CASCADE
expiry_date TIMESTAMPTZ NOT NULL
created_at TIMESTAMPTZ
revoked BOOLEAN DEFAULT false
```

### JWT Claims

Tokens are signed with ECDSA P-256 (ES256). The private key is fetched from the provisioning vault at startup.

```json
{
  "sub": "alice@example.com",
  "userId": 1,
  "projectId": "my-project",
  "role": "user",
  "iss": "excalibase",
  "iat": 1712200000,
  "exp": 1712286400
}
```

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
