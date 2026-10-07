package handler

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	minPasswordChars = 8
	// maxPasswordBytes bounds the input; argon2id itself has no 72-byte
	// truncation like bcrypt, so this is a sanity cap, not a hash limit.
	maxPasswordBytes = 256
)

var (
	errPasswordTooShort = errors.New("password must be at least 8 characters")
	errPasswordTooLong  = errors.New("password must be at most 256 bytes")
	errPasswordBlank    = errors.New("password must not be only whitespace")
)

// validatePassword is the one policy registration and reset both answer to,
// so tightening it can never leave one door more permissive than the other.
func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordChars {
		return errPasswordTooShort
	}
	if len(password) > maxPasswordBytes {
		return errPasswordTooLong
	}
	if strings.TrimSpace(password) == "" {
		return errPasswordBlank
	}
	return nil
}
