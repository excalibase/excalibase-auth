// Package service contains business logic shared across auth handlers.
//
// apikey.go implements generation + hashing of opaque API keys used by the
// /token endpoint's grant_type=api_key flow. Unlike user passwords, api keys
// are high-entropy random strings (~143 bits) so SHA-256 is adequate; argon2id
// would be pointless cost on the hot path.
package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// KeyType enumerates the two kinds of api keys. Publishable keys identify a
// project and are safe to ship in browser code; secret keys have elevated scope
// and must stay server-side. Defined (not aliased) so callers cannot pass
// arbitrary strings — the compiler enforces correct usage.
type KeyType string

const (
	KeyTypePublishable KeyType = "publishable"
	KeyTypeSecret      KeyType = "secret"

	publishableNamespace = "esk_pub_live_"
	secretNamespace      = "esk_sec_live_"

	// randomLen is the length of the Base62 random portion after the namespace.
	// 24 chars * log2(62) ≈ 143 bits of entropy.
	randomLen = 24
	// prefixLen is how much of the random portion is surfaced for display in
	// the API key list (the full key is never readable after creation).
	prefixLen = 12

	base62alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// GenerateAPIKey returns the plaintext key (shown to the user exactly once),
// the SHA-256 hex hash (stored in auth.api_keys.key_hash), and the display
// prefix (first 12 chars of the random portion).
func GenerateAPIKey(keyType KeyType) (plaintext, hash, prefix string, err error) {
	var namespace string
	switch keyType {
	case KeyTypePublishable:
		namespace = publishableNamespace
	case KeyTypeSecret:
		namespace = secretNamespace
	default:
		return "", "", "", fmt.Errorf("unknown api key type: %q", keyType)
	}

	random, err := randomBase62(randomLen)
	if err != nil {
		return "", "", "", fmt.Errorf("generate random: %w", err)
	}

	plaintext = namespace + random
	hash = HashAPIKey(plaintext)
	prefix = random[:prefixLen]
	return plaintext, hash, prefix, nil
}

// HashAPIKey returns the SHA-256 hex hash of the given plaintext. Used for
// lookup at token-exchange time: the client presents plaintext, we hash it
// and match against auth.api_keys.key_hash.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randomBase62(n int) (string, error) {
	max := big.NewInt(int64(len(base62alphabet)))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = base62alphabet[idx.Int64()]
	}
	return string(out), nil
}
