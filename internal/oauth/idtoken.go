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
	url       string
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newKeySet(url string) *keySet {
	return &keySet{url: url}
}

func (k *keySet) key(ctx context.Context, httpClient *http.Client, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	age := time.Since(k.fetchedAt)
	if key, ok := k.keys[kid]; ok && age < keysMaxAge {
		return key, nil
	}
	if !k.fetchedAt.IsZero() && age < keysMinRefetch {
		return nil, fmt.Errorf("%w: unknown signing key", ErrIDToken)
	}
	keys, err := fetchKeys(ctx, httpClient, k.url)
	if err != nil {
		return nil, err
	}
	k.keys, k.fetchedAt = keys, time.Now()
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: unknown signing key", ErrIDToken)
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
	if !acceptedIssuers(issuer)[claims.Issuer] || claims.Nonce != nonce || claims.Subject == "" {
		return Identity{}, fmt.Errorf("%w: issuer, nonce or subject", ErrIDToken)
	}
	if !claims.EmailVerified || claims.Email == "" {
		return Identity{}, ErrEmailNotVerified
	}
	return Identity{Subject: claims.Subject, Email: claims.Email, Name: claims.Name}, nil
}
