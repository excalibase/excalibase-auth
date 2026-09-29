package auth

import (
	"errors"
	"regexp"
)

// Roles the engine reserves: anon for unauthenticated or publishable-key
// traffic, service for secret-key tokens. No account may hold either.
const (
	RoleAnon    = "anon"
	RoleService = "service"
)

// ErrInvalidAccountRole refuses a sign-in whose users.role is reserved or not
// a role name the engine accepts.
var ErrInvalidAccountRole = errors.New("invalid_account_role")

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ValidateAccountRole checks that role can be the default role of an
// end-user token.
func ValidateAccountRole(role string) error {
	if !roleNamePattern.MatchString(role) || role == RoleAnon || role == RoleService {
		return ErrInvalidAccountRole
	}
	return nil
}
