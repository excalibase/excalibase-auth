// Package emailotp makes the eight-digit sign-in codes and the HMAC each is
// stored as. Developers can read the auth schema, so a code is kept only under
// a key the database never sees.
package emailotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// CodeLength is the number of digits in a code.
const CodeLength = 8

var codeSpace = big.NewInt(100_000_000)

// NewCode draws a uniformly random code.
func NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, codeSpace)
	if err != nil {
		return "", fmt.Errorf("random code: %w", err)
	}
	return fmt.Sprintf("%0*d", CodeLength, n.Int64()), nil
}

// CodeMAC is the hex HMAC-SHA256 a code is stored as, bound to the project and
// to the address whatever its case.
func CodeMAC(key []byte, projectID, email, code string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(projectID + "\x00" + strings.ToLower(email) + "\x00" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

// CodeMatches compares a code against a stored HMAC in constant time.
func CodeMatches(key []byte, projectID, email, code, stored string) bool {
	return hmac.Equal([]byte(CodeMAC(key, projectID, email, code)), []byte(stored))
}
