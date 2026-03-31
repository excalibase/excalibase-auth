package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type poolEntry struct {
	pool      *pgxpool.Pool
	createdAt time.Time
	connStr   string // to detect credential rotation
}

type Manager struct {
	provisioningURL string
	pat             string
	pools           map[string]*poolEntry
	mu              sync.RWMutex
	ttl             time.Duration
	httpClient      *http.Client
	poolCreator     func(ctx context.Context, connStr string) (*pgxpool.Pool, error)
	migrator        func(ctx context.Context, connStr string) error // optional, runs on first connect
}

func NewManager(provisioningURL, pat string, ttl time.Duration) *Manager {
	return &Manager{
		provisioningURL: provisioningURL,
		pat:             pat,
		pools:           make(map[string]*poolEntry),
		ttl:             ttl,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		poolCreator:     defaultPoolCreator,
	}
}

func (m *Manager) SetMigrator(fn func(ctx context.Context, connStr string) error) {
	m.migrator = fn
}

func (m *Manager) GetPool(ctx context.Context, projectID string) (*pgxpool.Pool, error) {
	m.mu.RLock()
	entry, ok := m.pools[projectID]
	m.mu.RUnlock()

	if ok && time.Since(entry.createdAt) < m.ttl {
		return entry.pool, nil
	}

	return m.createPool(ctx, projectID)
}

func (m *Manager) createPool(ctx context.Context, projectID string) (*pgxpool.Pool, error) {
	creds, err := m.fetchCredentials(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}

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

func (m *Manager) fetchCredentials(ctx context.Context, projectID string) (map[string]string, error) {
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/credentials/auth_admin", m.provisioningURL, projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.pat)

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
