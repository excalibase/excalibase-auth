// Package mfa holds the TOTP second factor (RFC 6238: HMAC-SHA1, six digits,
// thirty-second steps), the sealing of its secret and the recovery codes.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SecretBytes is RFC 4226's recommended 160-bit shared secret.
	SecretBytes = 20
	Digits      = 6
	Period      = 30 * time.Second
	// Skew is how many steps either side of now a code may come from.
	Skew = 1
)

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is a fresh shared secret.
func NewSecret() ([]byte, error) {
	secret := make([]byte, SecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// EncodeSecret is the secret as authenticator apps take it typed in.
func EncodeSecret(secret []byte) string {
	return secretEncoding.EncodeToString(secret)
}

// StepAt is the time step a moment falls in.
func StepAt(moment time.Time) int64 {
	return moment.Unix() / int64(Period/time.Second)
}

// Code is the six-digit code of one step.
func Code(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// Match is the step, within Skew of now and newer than lastUsed, whose code
// the given one is. Every candidate is computed and compared in constant time,
// so how long it takes says nothing about which step matched.
func Match(secret []byte, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(code, " ", "")
	if !sixDigits(code) {
		return 0, false
	}
	current := StepAt(now)
	var matched int64
	found := 0
	for step := current - Skew; step <= current+Skew; step++ {
		equal := subtle.ConstantTimeCompare([]byte(Code(secret, step)), []byte(code))
		fresh := 0
		if step > lastUsed {
			fresh = 1
		}
		hit := equal & fresh
		matched = int64(subtle.ConstantTimeSelect(hit, int(step), int(matched)))
		found |= hit
	}
	return matched, found == 1
}

func sixDigits(code string) bool {
	if len(code) != Digits {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// KeyURI is the otpauth:// address an app reads from a QR code.
func KeyURI(issuer, account string, secret []byte) string {
	query := url.Values{}
	query.Set("secret", EncodeSecret(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(Digits))
	query.Set("period", fmt.Sprint(int(Period/time.Second)))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + query.Encode()
}
