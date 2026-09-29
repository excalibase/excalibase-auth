package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAccountRole_AcceptsLowercaseIdentifiers(t *testing.T) {
	for _, role := range []string{"user", "editor", "a", "shop_manager2", "r" + strings.Repeat("x", 62)} {
		if err := ValidateAccountRole(role); err != nil {
			t.Errorf("ValidateAccountRole(%q): %v", role, err)
		}
	}
}

func TestValidateAccountRole_RefusesReservedAndMalformed(t *testing.T) {
	refused := []string{
		RoleAnon, RoleService,
		"", "User", "2fa", "_admin", "has-dash", "has space", "émile",
		"r" + strings.Repeat("x", 63),
	}
	for _, role := range refused {
		if err := ValidateAccountRole(role); !errors.Is(err, ErrInvalidAccountRole) {
			t.Errorf("ValidateAccountRole(%q): got %v, want ErrInvalidAccountRole", role, err)
		}
	}
}
