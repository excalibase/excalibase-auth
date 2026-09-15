package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

type poolEntry struct {
	pool      *pgxpool.Pool
	createdAt time.Time
	connStr   string // to detect credential rotation
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
	poolCreator     func(ctx context.Context, connStr string) (*pgxpool.Pool, error)
	migrator        func(ctx context.Context, connStr string) error // optional, runs on first connect
}

// NewManager builds a pool manager. tokens is consulted at request time so a
// provisioning token rotated on disk takes effect without a restart.
func NewManager(provisioningURL string, tokens token.Source, ttl time.Duration) *Manager {
	return &Manager{
		provisioningURL: provisioningURL,
		tokens:          tokens,
		pools:           make(map[string]*poolEntry),
		infos:           make(map[string]*infoEntry),
		ttl:             ttl,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		poolCreator:     defaultPoolCreator,
	}
}

func (m *Manager) SetMigrator(fn func(ctx context.Context, connStr string) error) {
	m.migrator = fn
}

// GetPool returns the pgx pool for a project. orgSlug + projectID together locate
// the vault path (projects/{orgSlug}/{projectID}/credentials/auth_admin). Cache key
// is projectID alone since provisioning mints it globally unique.
func (m *Manager) GetPool(ctx context.Context, orgSlug, projectID string) (*pgxpool.Pool, error) {
	m.mu.RLock()
	entry, ok := m.pools[projectID]
	m.mu.RUnlock()

	if ok && time.Since(entry.createdAt) < m.ttl {
		return entry.pool, nil
	}

	return m.createPool(ctx, orgSlug, projectID)
}

func (m *Manager) createPool(ctx context.Context, orgSlug, projectID string) (*pgxpool.Pool, error) {
	creds, err := m.fetchCredentials(ctx, orgSlug, projectID)
	if err != nil {
		log.Printf("ERROR: fetch credentials for %s: %v", projectID, err)
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}

	log.Printf("INFO: got credentials for %s: host=%s port=%s user=%s db=%s",
		projectID, creds["host"], creds["port"], creds["username"], creds["database"])

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable search_path=auth",
		creds["host"], creds["port"], creds["username"], creds["password"], creds["database"])

	// If credentials haven't changed, just refresh the timestamp (keep existing pool)
	m.mu.RLock()
	existing, exists := m.pools[projectID]
	m.mu.RUnlock()
	if exists && existing.connStr == connStr && existing.pool != nil {
		m.mu.Lock()
		existing.createdAt = time.Now()
		m.mu.Unlock()
		return existing.pool, nil
	}

	pool, err := m.poolCreator(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// Run migrations on first connect
	if pool != nil && m.migrator != nil {
		if err := m.migrator(ctx, connStr); err != nil {
			fmt.Printf("WARN: migration failed for %s: %v\n", projectID, err)
		}
	}

	m.mu.Lock()
	// Close old pool if credentials changed
	if old, ok := m.pools[projectID]; ok && old.pool != nil {
		old.pool.Close()
	}
	m.pools[projectID] = &poolEntry{pool: pool, createdAt: time.Now(), connStr: connStr}
	m.mu.Unlock()

	return pool, nil
}

func (m *Manager) fetchCredentials(ctx context.Context, orgSlug, projectID string) (map[string]string, error) {
	// Vault path: projects/{projectID}/credentials/auth_admin
	// orgSlug param kept for backward-compat with callers; vault paths are
	// project-scoped only (provisioning refactor 2026-05). Drop the org
	// dimension to match what provisioning writes.
	_ = orgSlug
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/credentials/auth_admin", m.provisioningURL, projectID)
	log.Printf("INFO: fetching credentials from %s", url)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	tok, err := m.tokens.Get()
	if err != nil {
		return nil, fmt.Errorf("provisioning token: %w", err)
	}
	req.Header.Set(authorizationHeader, bearerPrefix+tok)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vault returned %d", resp.StatusCode)
	}

	var creds map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	return creds, nil
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

func defaultPoolCreator(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}
	config.MinConns = 2
	config.MaxConns = 10
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	return pgxpool.NewWithConfig(ctx, config)
}
