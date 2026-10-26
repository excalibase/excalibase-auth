package auth

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

const derivedKeyLength = 32

// DerivedKey is a secret for one purpose, drawn from the signing key with
// HKDF so it never has to be stored. Whoever holds the signing key can already
// mint any session, so nothing new is exposed to them.
func (s *JWTService) DerivedKey(purpose string) ([]byte, error) {
	secret, err := s.privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	return hkdf.Key(sha256.New, secret, nil, "excalibase-auth "+purpose, derivedKeyLength)
}
