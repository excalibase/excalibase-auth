package hooks

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// Bounds on what custom_access_token may add to a token.
const (
	MaxCustomClaims     = 32
	MaxCustomBytes      = 4 << 10
	MaxClaimStringBytes = 1 << 10
	MaxClaimArrayLength = 32
)

// claimName matches the engine's session variable names, which it lower-cases.
var claimName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// reservedClaims are set by auth or read by the platform; a hook never adds one.
var reservedClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "token_use", "scope",
	"projectid", "project_id", "userid", "user_id", "role", "allowed_roles",
	"keyid", "key_id", "email", "email_verified", "is_guest", "orgslug", "projectname",
	"orgname", "actor", "auth_time", "amr", "aal", "session_id", "sid", "azp",
}

// Roles a hook may never pick, whatever the account allows.
var forbiddenRoles = []string{"service", "anon"}

// AccessClaims is what a custom_access_token answer may change.
type AccessClaims struct {
	Role   string
	Custom map[string]any
}

// ApplyAccessClaims checks a hook's answer against the claims it was sent:
// every claim auth set stays as it was, the role may move within
// allowedRoles, and new claims must be flat, named like session variables
// and small. Any breach fails the whole answer.
func ApplyAccessClaims(sent, answer map[string]any, allowedRoles []string) (AccessClaims, error) {
	fixed, err := normalized(sent)
	if err != nil {
		return AccessClaims{}, failed("the claims could not be compared")
	}
	result := AccessClaims{Role: stringOf(fixed["role"]), Custom: map[string]any{}}
	for name, value := range answer {
		switch _, wasSent := fixed[name]; {
		case name == "role":
			role, ok := value.(string)
			if !ok || slices.Contains(forbiddenRoles, role) || !slices.Contains(allowedRoles, role) {
				return AccessClaims{}, failed("role must be one of the account's allowed roles")
			}
			result.Role = role
		case wasSent:
			if !reflect.DeepEqual(fixed[name], value) {
				return AccessClaims{}, failed("the claim " + name + " is set by auth and cannot change")
			}
		default:
			if err := checkCustomClaim(name, value); err != nil {
				return AccessClaims{}, err
			}
			result.Custom[name] = value
		}
	}
	return result, checkCustomBounds(result.Custom)
}

func checkCustomClaim(name string, value any) error {
	if slices.Contains(reservedClaims, strings.ToLower(name)) {
		return failed("the claim " + name + " is set by auth")
	}
	if !claimName.MatchString(name) {
		return failed("a claim name must be lower-case letters, digits and underscores")
	}
	if elements, ok := value.([]any); ok {
		if len(elements) > MaxClaimArrayLength {
			return failed("the claim " + name + " has too many elements")
		}
		for _, element := range elements {
			if !scalarClaim(element) {
				return failed("the claim " + name + " must be a flat list of strings, numbers or booleans")
			}
		}
		return nil
	}
	if !scalarClaim(value) {
		return failed("the claim " + name + " must be a string, number, boolean or flat list")
	}
	return nil
}

func scalarClaim(value any) bool {
	switch typed := value.(type) {
	case string:
		return len(typed) <= MaxClaimStringBytes
	case bool:
		return true
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0)
	}
	return false
}

func checkCustomBounds(custom map[string]any) error {
	if len(custom) > MaxCustomClaims {
		return failed("too many custom claims")
	}
	encoded, err := json.Marshal(custom)
	if err != nil || len(encoded) > MaxCustomBytes {
		return failed("the custom claims are over 4 KB")
	}
	return nil
}

// normalized gives the sent claims the types a JSON answer decodes to.
func normalized(claims map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}
