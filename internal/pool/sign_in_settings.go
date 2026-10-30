package pool

import (
	"context"
	"encoding/base64"
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
		if provider.Provider == name && provider.ClientID != "" && absoluteURL(provider.CallbackURL) {
			return provider, true
		}
	}
	return OAuthProvider{}, false
}

// absoluteURL refuses a callback a browser would resolve against some other page.
func absoluteURL(raw string) bool {
	parsed, err := neturl.Parse(raw)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
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

// GuestsOn is whether the control plane's guest flag is on.
func (info ProjectInfo) GuestsOn() bool {
	return info.GuestSignInEnabled != nil
}

// GuestSignInOn is whether the project takes new guests.
func (info ProjectInfo) GuestSignInOn() bool {
	return info.GuestSignInEnabled != nil && *info.GuestSignInEnabled
}

// ErrNoCaptchaSecret means the vault holds no Turnstile secret for the project.
var ErrNoCaptchaSecret = errors.New("captcha secret is not set")

// CaptchaSecret reads the project's Turnstile secret from the vault on every call.
func (m *Manager) CaptchaSecret(ctx context.Context, projectID string) (string, error) {
	var entry struct {
		SecretKey string `json:"secret_key"`
	}
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/auth/captcha", m.provisioningURL, neturl.PathEscape(projectID))
	if err := m.getJSON(ctx, url, "captcha secret", &entry); err != nil {
		return "", err
	}
	if entry.SecretKey == "" {
		return "", ErrNoCaptchaSecret
	}
	return entry.SecretKey, nil
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

// ErrNoMFAKey means the vault holds no usable MFA key for the project.
var ErrNoMFAKey = errors.New("mfa key is not set")

// MFAKey reads the project's 32-byte MFA key from the vault on every call, so
// nothing but the vault keeps it.
func (m *Manager) MFAKey(ctx context.Context, projectID string) ([]byte, error) {
	var entry struct {
		Key string `json:"key"`
	}
	url := fmt.Sprintf("%s/vault/secrets/projects/%s/auth/mfa", m.provisioningURL, neturl.PathEscape(projectID))
	if err := m.getJSON(ctx, url, "mfa key", &entry); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(entry.Key)
	if err != nil || len(key) != mfaKeySize {
		return nil, ErrNoMFAKey
	}
	return key, nil
}

const mfaKeySize = 32
