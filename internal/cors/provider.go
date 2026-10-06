// Package cors resolves a project's browser-origin allowlist, the same list the
// project's GraphQL and REST engine answers CORS from.
package cors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/excalibase/auth/internal/token"
)

// ErrUnavailable means the allowlist could not be read and nothing is cached.
// Callers must refuse the cross-origin request: an empty list is a decision
// only provisioning may make.
var ErrUnavailable = errors.New("project cors allowlist unavailable")

const (
	requestTimeout = 5 * time.Second
	// maxInfoBytes bounds the project info body read per fetch.
	maxInfoBytes = 1 << 20
)

// ProvisioningProvider reads corsAllowedOrigins from provisioning's
// GET {base}/projects/{projectId}/info and caches it per project for ttl.
// A failed refresh serves the last good list; with none cached it fails.
type ProvisioningProvider struct {
	baseURL string
	tokens  token.Source
	ttl     time.Duration
	client  *http.Client
	now     func() time.Time

	mu    sync.RWMutex
	cache map[string]cachedOrigins
}

type cachedOrigins struct {
	origins   []string
	fetchedAt time.Time
}

type projectInfo struct {
	CorsAllowedOrigins []string `json:"corsAllowedOrigins"`
}

// NewProvisioningProvider builds a provider; tokens is read on every fetch so
// a rotated token file is picked up without a restart.
func NewProvisioningProvider(baseURL string, tokens token.Source, ttl time.Duration) *ProvisioningProvider {
	return &ProvisioningProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		tokens:  tokens,
		ttl:     ttl,
		client:  &http.Client{Timeout: requestTimeout},
		now:     time.Now,
		cache:   make(map[string]cachedOrigins),
	}
}

// Resolve returns the project's allowlist, or an error wrapping ErrUnavailable.
func (p *ProvisioningProvider) Resolve(ctx context.Context, projectID string) ([]string, error) {
	now := p.now()
	p.mu.RLock()
	cached, ok := p.cache[projectID]
	p.mu.RUnlock()
	if ok && now.Sub(cached.fetchedAt) < p.ttl {
		return clone(cached.origins), nil
	}

	fresh, err := p.fetch(ctx, projectID)
	if err != nil {
		if ok {
			return clone(cached.origins), nil
		}
		return nil, err
	}
	p.mu.Lock()
	p.cache[projectID] = cachedOrigins{origins: fresh, fetchedAt: now}
	p.mu.Unlock()
	return clone(fresh), nil
}

func (p *ProvisioningProvider) fetch(ctx context.Context, projectID string) ([]string, error) {
	tok, err := p.tokens.Get()
	if err != nil {
		return nil, fmt.Errorf("%w: provisioning token: %v", ErrUnavailable, err)
	}
	endpoint := p.baseURL + "/projects/" + url.PathEscape(projectID) + "/info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: provisioning returned %d", ErrUnavailable, resp.StatusCode)
	}
	var info projectInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInfoBytes)).Decode(&info); err != nil {
		return nil, fmt.Errorf("%w: decode project info: %v", ErrUnavailable, err)
	}
	return clone(info.CorsAllowedOrigins), nil
}

func clone(origins []string) []string {
	return append([]string{}, origins...)
}
