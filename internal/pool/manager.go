package pool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

type poolEntry struct {
	pool        *pgxpool.Pool
	createdAt   time.Time
	fingerprint string // detects rotated credentials and renewed certificates
}

// ProjectInfo mirrors the response of provisioning's
// `GET /api/projects/{projectId}/info` — display names alongside opaque ids.
// Cached per projectId for `infoTTL` so we don't hammer provisioning at every login.
type ProjectInfo struct {
	ProjectID   string `json:"projectId"`
	ProjectName string `json:"projectName"`
	OrgID       string `json:"orgId"`
	OrgSlug     string `json:"orgSlug"`
	OrgName     string `json:"orgName"`
	// RequireEmailVerification gates login on a proven email address. Absent
	// from older control planes, and false by default, so enabling it is always
	// an explicit per-project decision.
	RequireEmailVerification bool `json:"requireEmailVerification"`
	// SiteURL is the project's own front end, used as the base for links in
	// verification and reset emails. Falls back to AUTH_SITE_URL when empty.
	SiteURL string `json:"siteUrl"`
}

type infoEntry struct {
	info      ProjectInfo
	createdAt time.Time
}

// authorizationHeader is the header carrying the provisioning service token.
const authorizationHeader = "Authorization"

// bearerPrefix prefixes the provisioning token in the Authorization header.
const bearerPrefix = "Bearer "

type Manager struct {
	provisioningURL string
	tokens          token.Source
	pools           map[string]*poolEntry
	infos           map[string]*infoEntry
	mu              sync.RWMutex
	ttl             time.Duration
	httpClient      *http.Client
	poolCreator     func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error)
	migrator        func(ctx context.Context, pool *pgxpool.Pool) error // optional, runs on first connect
	sslMode         string
}

// defaultTenantSSLMode: tenant logins are client-certificate only (EXC-410),
// and a certificate is only worth presenting to a verified server.
const defaultTenantSSLMode = "verify-full"

// maxCredentialAge bounds how long a vault record is trusted, so a renewed
// certificate or CA reaches new connections within the hour, restart-free.
const maxCredentialAge = time.Hour

// SetSSLMode sets the sslmode every tenant connection is opened with:
// disable (password, docker AIO only) or any TLS mode (verify-full + client cert).
func (m *Manager) SetSSLMode(mode string) {
	m.sslMode = mode
}

// NewManager builds a pool manager. tokens is consulted at request time so a
// provisioning token rotated on disk takes effect without a restart.
func NewManager(provisioningURL string, tokens token.Source, ttl time.Duration) *Manager {
	if ttl <= 0 || ttl > maxCredentialAge {
		ttl = maxCredentialAge
	}
	return &Manager{
		provisioningURL: provisioningURL,
		tokens:          tokens,
		pools:           make(map[string]*poolEntry),
		infos:           make(map[string]*infoEntry),
		ttl:             ttl,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		poolCreator:     defaultPoolCreator,
		sslMode:         defaultTenantSSLMode,
	}
}

func (m *Manager) SetMigrator(fn func(ctx context.Context, pool *pgxpool.Pool) error) {
	m.migrator = fn
}

// GetPool returns the pgx pool for a project. orgSlug + projectID together locate
// the vault path (projects/{orgSlug}/{projectID}/credentials/auth_admin). Cache key
// is projectID alone since provisioning mints it globally unique.
func (m *Manager) GetPool(ctx context.Context, orgSlug, projectID string) (*pgxpool.Pool, error) {
	m.mu.RLock()
	entry, ok := m.pools[projectID]
	fresh := ok && time.Since(entry.createdAt) < m.ttl
	m.mu.RUnlock()

	if fresh {
		return entry.pool, nil
	}

	return m.createPool(ctx, orgSlug, projectID)
}

func (m *Manager) createPool(ctx context.Context, orgSlug, projectID string) (*pgxpool.Pool, error) {
	record, err := m.fetchCredentials(ctx, orgSlug, projectID)
	if err != nil {
		log.Printf("ERROR: fetch credentials for %s: %v", projectID, err)
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}

	log.Printf("INFO: got credentials for %s: host=%s port=%s user=%s db=%s",
		projectID, record.Host, record.Port, record.Username, record.Database)

	fingerprint := record.fingerprint()
	if pool, ok := m.refreshUnchanged(projectID, fingerprint); ok {
		return pool, nil
	}

	config, err := tenantPoolConfig(record, m.sslMode)
	if err != nil {
		log.Printf("ERROR: tenant connection for %s: %v", projectID, err)
		return nil, fmt.Errorf("tenant connection: %w", err)
	}
	pool, err := m.poolCreator(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if pool != nil && m.migrator != nil {
		if err := m.migrator(ctx, pool); err != nil {
			log.Printf("WARN: migration failed for %s: %v", projectID, err)
		}
	}

	m.mu.Lock()
	old, replaced := m.pools[projectID]
	m.pools[projectID] = &poolEntry{pool: pool, createdAt: time.Now(), fingerprint: fingerprint}
	m.mu.Unlock()

	// Close waits for borrowed connections, so it must not hold up the caller.
	if replaced && old.pool != nil && old.pool != pool {
		go old.pool.Close()
	}
	return pool, nil
}

// ErrNoDatabase is returned for a project created without a database
// (EXC-426). It is not an outage: there is no database to connect to, and
// the handlers answer 409 rather than 503.
var ErrNoDatabase = errors.New("project has no database")

// refreshUnchanged keeps the existing pool when the vault record is identical.
func (m *Manager) refreshUnchanged(projectID, fingerprint string) (*pgxpool.Pool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.pools[projectID]
	if !ok || existing.pool == nil || existing.fingerprint != fingerprint {
		return nil, false
	}
	existing.createdAt = time.Now()
	return existing.pool, true
}

func (m *Manager) fetchCredentials(ctx context.Context, orgSlug, projectID string) (credentialRecord, error) {
	// Vault path: projects/{projectID}/credentials/auth_admin
	// orgSlug param kept for backward-compat with callers; vault paths are
	// project-scoped only (provisioning refactor 2026-05). Drop the org
	// dimension to match what provisioning writes.
	_ = orgSlug
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/credentials/auth_admin", m.provisioningURL, projectID)
	log.Printf("INFO: fetching credentials from %s", url)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return credentialRecord{}, err
	}
	tok, err := m.tokens.Get()
	if err != nil {
		return credentialRecord{}, fmt.Errorf("provisioning token: %w", err)
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return credentialRecord{}, fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Provisioning's answer for a project created without a database.
		return credentialRecord{}, fmt.Errorf("%w: %s", ErrNoDatabase, projectID)
	}
	if resp.StatusCode != 200 {
		return credentialRecord{}, fmt.Errorf("vault returned %d", resp.StatusCode)
	}

	var record credentialRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return credentialRecord{}, fmt.Errorf("decode credentials: %w", err)
	}
	return record, nil
}

// GetProjectInfo returns display-name metadata for a project (org name, project
// name) by calling provisioning's /api/projects/{projectId}/info endpoint.
// Cached per projectId for the manager's TTL so login-flow latency stays low.
// Returns (zero value, error) on lookup failure — callers should treat info as
// optional and fall through to URL-derived values.
func (m *Manager) GetProjectInfo(ctx context.Context, projectID string) (ProjectInfo, error) {
	m.mu.RLock()
	if entry, ok := m.infos[projectID]; ok && time.Since(entry.createdAt) < m.ttl {
		info := entry.info
		m.mu.RUnlock()
		return info, nil
	}
	m.mu.RUnlock()

	url := fmt.Sprintf("%s/projects/%s/info", m.provisioningURL, projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ProjectInfo{}, err
	}
	tok, err := m.tokens.Get()
	if err != nil {
		return ProjectInfo{}, fmt.Errorf("provisioning token: %w", err)
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ProjectInfo{}, fmt.Errorf("project info request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ProjectInfo{}, fmt.Errorf("project info returned %d", resp.StatusCode)
	}
	var info ProjectInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ProjectInfo{}, fmt.Errorf("decode project info: %w", err)
	}

	m.mu.Lock()
	m.infos[projectID] = &infoEntry{info: info, createdAt: time.Now()}
	m.mu.Unlock()
	return info, nil
}

func defaultPoolCreator(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	config.MinConns = 2
	config.MaxConns = 10
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	return pgxpool.NewWithConfig(ctx, config)
}
