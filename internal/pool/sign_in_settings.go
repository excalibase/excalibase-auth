package pool

import (
	"context"
	"errors"
	"fmt"
	neturl "net/url"
)

// OAuthProvider is a provider the project switched on, with its own client id
// and the callback address registered at the provider.
type OAuthProvider struct {
	Provider    string `json:"provider"`
	ClientID    string `json:"clientId"`
	CallbackURL string `json:"callbackUrl"`
}

// ErrNoProviderSecret means the vault holds no client secret for the provider.
var ErrNoProviderSecret = errors.New("provider client secret is not set")

// knownProviders bounds the vault paths a provider name can reach.
var knownProviders = map[string]bool{"google": true, "github": true}

// OAuthProvider returns the named provider when the project enabled it.
func (info ProjectInfo) OAuthProvider(name string) (OAuthProvider, bool) {
	for _, provider := range info.OAuthProviders {
		if provider.Provider == name && provider.ClientID != "" && provider.CallbackURL != "" {
			return provider, true
		}
	}
	return OAuthProvider{}, false
}

// OAuthEnabled reports whether any provider sign-in is on for the project.
func (info ProjectInfo) OAuthEnabled() bool {
	for _, provider := range info.OAuthProviders {
		if _, ok := info.OAuthProvider(provider.Provider); ok {
			return true
		}
	}
	return false
}

// NewUsersAllowed is the project's sign-up switch; open unless it says closed.
func (info ProjectInfo) NewUsersAllowed() bool {
	return info.AllowNewUsers == nil || *info.AllowNewUsers
}

// CachedProjectInfo is the last copy read, however old.
func (m *Manager) CachedProjectInfo(projectID string) (ProjectInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.infos[projectID]
	if !ok {
		return ProjectInfo{}, false
	}
	return entry.info, true
}

// ProviderSecret reads the project's client secret for a provider from the
// vault, on every call, so a rotated secret applies at once.
func (m *Manager) ProviderSecret(ctx context.Context, projectID, provider string) (string, error) {
	if !knownProviders[provider] {
		return "", fmt.Errorf("unknown provider %q", provider)
	}
	var entry struct {
		ClientSecret string `json:"client_secret"`
	}
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/auth/providers/%s", m.provisioningURL, neturl.PathEscape(projectID), provider)
	if err := m.getJSON(ctx, url, "provider secret", &entry); err != nil {
		return "", err
	}
	if entry.ClientSecret == "" {
		return "", ErrNoProviderSecret
	}
	return entry.ClientSecret, nil
}
