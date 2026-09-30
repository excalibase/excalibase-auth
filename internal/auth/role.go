package auth

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// Roles the engine reserves: anon for unauthenticated or publishable-key
// traffic, service for secret-key tokens. No account may hold either.
const (
	RoleAnon    = "anon"
	RoleService = "service"
)

// MaxAllowedRoles bounds the roles one account may switch between.
const MaxAllowedRoles = 20

var (
	// ErrInvalidAccountRole refuses a sign-in whose users.role or
	// users.allowed_roles holds a reserved or malformed role name.
	ErrInvalidAccountRole = errors.New("invalid_account_role")
	// ErrInvalidRoleName refuses a name the engine cannot run as.
	ErrInvalidRoleName = errors.New("invalid_role")
	// ErrReservedRole refuses a name that belongs to the engine or the platform.
	ErrReservedRole = errors.New("reserved_role")
	// ErrRoleNotAllowed refuses a default role missing from the allowed roles.
	ErrRoleNotAllowed = errors.New("role_not_in_allowed_roles")
	// ErrTooManyAllowedRoles refuses more than MaxAllowedRoles allowed roles.
	ErrTooManyAllowedRoles = errors.New("too_many_allowed_roles")
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// reservedRoles are the engine's own roles plus the Postgres roles the
// platform provisions; an end user holding one would run as that role.
var reservedRoles = []string{
	RoleAnon, RoleService,
	"postgres", "auth_admin", "excalibase_app", "cdc_watcher",
	"streaming_replica", "excalibase_docbrowser", "app",
}

var reservedRolePrefixes = []string{"pg_", "excalibase_"}

// ValidateRoleName checks that role is a well-formed name no end user is
// barred from holding.
func ValidateRoleName(role string) error {
	if !roleNamePattern.MatchString(role) {
		return ErrInvalidRoleName
	}
	if slices.Contains(reservedRoles, role) {
		return ErrReservedRole
	}
	for _, prefix := range reservedRolePrefixes {
		if strings.HasPrefix(role, prefix) {
			return ErrReservedRole
		}
	}
	return nil
}

// ValidateAccountRole checks that role can be the default role of an
// end-user token.
func ValidateAccountRole(role string) error {
	if ValidateRoleName(role) != nil {
		return ErrInvalidAccountRole
	}
	return nil
}

// NormalizeAllowedRoles validates a requested role and allowed-roles pair and
// returns the allowed roles de-duplicated in order; nil means [role].
func NormalizeAllowedRoles(role string, allowed []string) ([]string, error) {
	if err := ValidateRoleName(role); err != nil {
		return nil, err
	}
	if allowed == nil {
		return []string{role}, nil
	}
	unique := make([]string, 0, len(allowed))
	for _, entry := range allowed {
		if err := ValidateRoleName(entry); err != nil {
			return nil, err
		}
		if !slices.Contains(unique, entry) {
			unique = append(unique, entry)
		}
	}
	if len(unique) > MaxAllowedRoles {
		return nil, ErrTooManyAllowedRoles
	}
	if !slices.Contains(unique, role) {
		return nil, ErrRoleNotAllowed
	}
	return unique, nil
}

// AccountAllowedRoles is the allowed_roles claim for an account: its stored
// users.allowed_roles, or [role] when unset. Anything invalid refuses sign-in.
func AccountAllowedRoles(role string, stored []string) ([]string, error) {
	if err := ValidateAccountRole(role); err != nil {
		return nil, err
	}
	allowed, err := NormalizeAllowedRoles(role, stored)
	if err != nil {
		return nil, ErrInvalidAccountRole
	}
	return allowed, nil
}
