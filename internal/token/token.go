// Package token mints and verifies the single-use, high-entropy secrets behind
// email verification and password reset links.
//
// Only the SHA-256 hash of a token is ever persisted, so a database leak does
// not hand an attacker usable verification or reset links. The plaintext exists
// exactly once — in the email that is sent to the address being proved.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// EntropyBytes is the amount of randomness behind every token. 32 bytes puts a
// brute-force search far out of reach regardless of how long the token lives.
const EntropyBytes = 32

// New returns a fresh URL-safe plaintext token and the hash to persist.
func New() (plaintext, hash string, err error) {
	raw := make([]byte, EntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("read random bytes: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)
	return plaintext, Hash(plaintext), nil
}

// Hash returns the lowercase hex SHA-256 of a plaintext token. Tokens carry
// full entropy from crypto/rand, so a plain hash (no salt, no KDF) is the right
// trade-off: lookups stay indexable and there is nothing to brute force.
func Hash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Equal compares two token hashes in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
