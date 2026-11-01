package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeySize is the per-project key the vault holds: 32 random bytes.
const KeySize = 32

// sealVersion leads every sealed secret, so a later key or scheme can be told apart.
const sealVersion byte = 1

var errSealed = errors.New("sealed secret is unreadable")

// Keys are a project's MFA keys: one seals factor secrets, one hashes recovery codes.
type Keys struct {
	seal     cipher.AEAD
	recovery []byte
}

// NewKeys derives both keys from the project's vault key.
func NewKeys(projectKey []byte) (Keys, error) {
	if len(projectKey) != KeySize {
		return Keys{}, fmt.Errorf("mfa key must be %d bytes", KeySize)
	}
	sealKey, err := hkdf.Key(sha256.New, projectKey, nil, "excalibase-auth mfa factor-secret v1", KeySize)
	if err != nil {
		return Keys{}, err
	}
	recoveryKey, err := hkdf.Key(sha256.New, projectKey, nil, "excalibase-auth mfa recovery-code v1", KeySize)
	if err != nil {
		return Keys{}, err
	}
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return Keys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Keys{}, err
	}
	return Keys{seal: aead, recovery: recoveryKey}, nil
}

// additionalData binds a sealed secret to its account and factor, so a row
// copied onto another account or factor does not open.
func additionalData(userID int64, factorID string) []byte {
	return []byte("excalibase-mfa|v" + strconv.Itoa(int(sealVersion)) + "|" + strconv.FormatInt(userID, 10) + "|" + factorID)
}

// Seal encrypts a factor's secret with AES-256-GCM: version, nonce, ciphertext.
func (k Keys) Seal(secret []byte, userID int64, factorID string) ([]byte, error) {
	nonce := make([]byte, k.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := append([]byte{sealVersion}, nonce...)
	return k.seal.Seal(sealed, nonce, secret, additionalData(userID, factorID)), nil
}

// Open decrypts what Seal made for the same account and factor.
func (k Keys) Open(sealed []byte, userID int64, factorID string) ([]byte, error) {
	nonceSize := k.seal.NonceSize()
	if len(sealed) < 1+nonceSize+k.seal.Overhead() || sealed[0] != sealVersion {
		return nil, errSealed
	}
	nonce, ciphertext := sealed[1:1+nonceSize], sealed[1+nonceSize:]
	secret, err := k.seal.Open(nil, nonce, ciphertext, additionalData(userID, factorID))
	if err != nil {
		return nil, errSealed
	}
	return secret, nil
}

const (
	// RecoveryCodeCount is how many codes one set holds.
	RecoveryCodeCount = 10
	recoveryCodeChars = 10
	// recoveryAlphabet leaves out 0, 1, l and o, which read alike; 32 symbols, 50 bits a code.
	recoveryAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"
)

// NewRecoveryCodes are n distinct codes shaped like "abcde-fghij".
func NewRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, 0, count)
	seen := map[string]bool{}
	for len(codes) < count {
		raw := make([]byte, recoveryCodeChars)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		var code strings.Builder
		for index, value := range raw {
			if index == recoveryCodeChars/2 {
				code.WriteByte('-')
			}
			code.WriteByte(recoveryAlphabet[value%byte(len(recoveryAlphabet))])
		}
		if !seen[code.String()] {
			seen[code.String()] = true
			codes = append(codes, code.String())
		}
	}
	return codes, nil
}

// HashRecoveryCode is the keyed hash a code is stored as; false when the
// typed text cannot be a code. Case, spaces and the dash do not matter.
func (k Keys) HashRecoveryCode(typed string) (string, bool) {
	normalized := strings.NewReplacer("-", "", " ", "").Replace(strings.ToLower(typed))
	if len(normalized) != recoveryCodeChars || strings.Trim(normalized, recoveryAlphabet) != "" {
		return "", false
	}
	mac := hmac.New(sha256.New, k.recovery)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil)), true
}
