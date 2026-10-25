package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// keysMaxAge bounds how long fetched signing keys are trusted; an unknown kid
// refetches at most once per keysMinRefetch.
const (
	keysMaxAge     = time.Hour
	keysMinRefetch = time.Minute
)

// keySet is a provider's JWKS, cached.
type keySet struct {
	url         string
	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newKeySet(url string) *keySet {
	return &keySet{url: url}
}

func (k *keySet) key(ctx context.Context, httpClient *http.Client, kid string) (*rsa.PublicKey, error) {
	if key, ok := k.cached(kid); ok {
		return key, nil
	}
	if !k.mayRefetch() {
		return nil, fmt.Errorf("%w: unknown signing key", ErrIDToken)
	}
	// Fetched outside the lock, so a slow key endpoint holds up only the
	// sign-ins that need a new key.
	keys, err := fetchKeys(ctx, httpClient, k.url)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	k.keys, k.fetchedAt = keys, time.Now()
	k.mu.Unlock()
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: unknown signing key", ErrIDToken)
}

func (k *keySet) cached(kid string) (*rsa.PublicKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[kid]
	return key, ok && time.Since(k.fetchedAt) < keysMaxAge
}

// mayRefetch allows one fetch per keysMinRefetch, claimed under the lock.
func (k *keySet) mayRefetch() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.lastAttempt.IsZero() && time.Since(k.lastAttempt) < keysMinRefetch {
		return false
	}
	k.lastAttempt = time.Now()
	return true
}

func fetchKeys(ctx context.Context, httpClient *http.Client, url string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: signing keys unreachable", ErrIDToken)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxProviderBody)).Decode(&set) != nil {
		return nil, fmt.Errorf("%w: signing keys unreadable", ErrIDToken)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, entry := range set.Keys {
		if key, ok := rsaKey(entry.Kty, entry.N, entry.E); ok && entry.Kid != "" {
			keys[entry.Kid] = key
		}
	}
	return keys, nil
}

func rsaKey(kty, modulus, exponent string) (*rsa.PublicKey, bool) {
	if kty != "RSA" {
		return nil, false
	}
	n, errN := base64.RawURLEncoding.DecodeString(modulus)
	e, errE := base64.RawURLEncoding.DecodeString(exponent)
	if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
		return nil, false
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, true
}

type idClaims struct {
	jwt.RegisteredClaims
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	AuthorizedBy  string `json:"azp"`
}

// googleIssuers are the two spellings Google documents for iss.
func acceptedIssuers(issuer string) map[string]bool {
	accepted := map[string]bool{issuer: true}
	if issuer == GoogleEndpoints.Issuer {
		accepted["accounts.google.com"] = true
	}
	return accepted
}

// verifyIDToken checks signature (RS256 by a published key), issuer, audience,
// expiry and nonce, then requires a verified address.
func verifyIDToken(ctx context.Context, httpClient *http.Client, keys *keySet, raw, issuer, audience, nonce string) (Identity, error) {
	if raw == "" || nonce == "" {
		return Identity{}, fmt.Errorf("%w: missing", ErrIDToken)
	}
	claims := idClaims{}
	_, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return keys.key(ctx, httpClient, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithLeeway(time.Minute))
	if err != nil {
		if errors.Is(err, ErrIDToken) {
			return Identity{}, err
		}
		return Identity{}, fmt.Errorf("%w: %s", ErrIDToken, "signature or claims")
	}
	if len(claims.Audience) > 1 && claims.AuthorizedBy != audience {
		return Identity{}, fmt.Errorf("%w: authorized party", ErrIDToken)
	}
	if !acceptedIssuers(issuer)[claims.Issuer] || claims.Nonce != nonce || claims.Subject == "" {
		return Identity{}, fmt.Errorf("%w: issuer, nonce or subject", ErrIDToken)
	}
	if !claims.EmailVerified || claims.Email == "" {
		return Identity{}, ErrEmailNotVerified
	}
	return Identity{Subject: claims.Subject, Email: claims.Email, Name: claims.Name}, nil
}
