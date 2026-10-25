package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	minPKCELength = 43
	maxPKCELength = 128
	randomBytes   = 32
)

// Flow is the secrets of one sign-in: the state the provider echoes, our PKCE
// verifier for the provider leg, and the OIDC nonce.
type Flow struct {
	State    string
	Verifier string
	Nonce    string
}

// NewFlow draws fresh random values for a sign-in.
func NewFlow() (Flow, error) {
	var flow Flow
	for _, target := range []*string{&flow.State, &flow.Verifier, &flow.Nonce} {
		value, err := randomString()
		if err != nil {
			return Flow{}, err
		}
		*target = value
	}
	return flow, nil
}

func randomString() (string, error) {
	raw := make([]byte, randomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// S256 is the PKCE code challenge of a verifier (RFC 7636).
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidChallenge accepts a 43 to 128 character unpadded base64url value.
func ValidChallenge(challenge string) bool {
	return validPKCEValue(challenge)
}

// VerifierMatches checks a well-formed verifier against a stored challenge in
// constant time.
func VerifierMatches(verifier, challenge string) bool {
	if !validPKCEValue(verifier) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(S256(verifier)), []byte(challenge)) == 1
}

// validPKCEValue is RFC 7636's unreserved alphabet at its allowed length.
func validPKCEValue(value string) bool {
	if len(value) < minPKCELength || len(value) > maxPKCELength {
		return false
	}
	for _, r := range value {
		if !isUnreserved(r) {
			return false
		}
	}
	return true
}

func isUnreserved(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '.' || r == '_' || r == '~'
}
