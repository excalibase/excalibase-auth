package auth

import (
	"errors"
	"slices"
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

func TestValidateRoleName_RefusesReservedNames(t *testing.T) {
	reserved := []string{
		"anon", "service", "postgres", "auth_admin", "excalibase_app", "cdc_watcher",
		"streaming_replica", "excalibase_docbrowser", "app",
		"pg_read_all_data", "pg_", "excalibase_", "excalibase_anything",
	}
	for _, role := range reserved {
		if err := ValidateRoleName(role); !errors.Is(err, ErrReservedRole) {
			t.Errorf("ValidateRoleName(%q): got %v, want ErrReservedRole", role, err)
		}
		if err := ValidateAccountRole(role); !errors.Is(err, ErrInvalidAccountRole) {
			t.Errorf("ValidateAccountRole(%q): got %v, want ErrInvalidAccountRole", role, err)
		}
	}
}

func TestValidateRoleName_RefusesMalformed(t *testing.T) {
	for _, role := range []string{"", "Editor", "has-dash", "1st", "r" + strings.Repeat("x", 63)} {
		if err := ValidateRoleName(role); !errors.Is(err, ErrInvalidRoleName) {
			t.Errorf("ValidateRoleName(%q): got %v, want ErrInvalidRoleName", role, err)
		}
	}
}

func TestValidateRoleName_AcceptsNamesNearReservedOnes(t *testing.T) {
	for _, role := range []string{"editor", "apps", "application", "pgadmin", "excalibase", "postgres_fan", "services"} {
		if err := ValidateRoleName(role); err != nil {
			t.Errorf("ValidateRoleName(%q): %v", role, err)
		}
	}
}

func TestNormalizeAllowedRoles(t *testing.T) {
	got, err := NormalizeAllowedRoles("editor", nil)
	if err != nil || !slices.Equal(got, []string{"editor"}) {
		t.Errorf("nil allowed: got %v %v, want [editor]", got, err)
	}
	got, err = NormalizeAllowedRoles("editor", []string{"user", "editor", "user"})
	if err != nil || !slices.Equal(got, []string{"user", "editor"}) {
		t.Errorf("dedupe: got %v %v, want [user editor]", got, err)
	}

	tooMany := make([]string, 0, MaxAllowedRoles+1)
	for i := 0; i <= MaxAllowedRoles; i++ {
		tooMany = append(tooMany, "r"+strings.Repeat("x", i))
	}
	cases := map[string]struct {
		role    string
		allowed []string
		want    error
	}{
		"role missing from list": {"editor", []string{"user"}, ErrRoleNotAllowed},
		"empty list":             {"editor", []string{}, ErrRoleNotAllowed},
		"reserved entry":         {"editor", []string{"editor", "anon"}, ErrReservedRole},
		"platform entry":         {"editor", []string{"editor", "pg_monitor"}, ErrReservedRole},
		"malformed entry":        {"editor", []string{"editor", "Bad"}, ErrInvalidRoleName},
		"reserved role":          {"service", []string{"service"}, ErrReservedRole},
		"malformed role":         {"Bad", nil, ErrInvalidRoleName},
		"too many":               {"r", tooMany, ErrTooManyAllowedRoles},
	}
	for name, tc := range cases {
		if _, err := NormalizeAllowedRoles(tc.role, tc.allowed); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

func TestAccountAllowedRoles(t *testing.T) {
	got, err := AccountAllowedRoles("editor", nil)
	if err != nil || !slices.Equal(got, []string{"editor"}) {
		t.Errorf("NULL allowed_roles: got %v %v, want [editor]", got, err)
	}
	got, err = AccountAllowedRoles("editor", []string{"editor", "user"})
	if err != nil || !slices.Equal(got, []string{"editor", "user"}) {
		t.Errorf("stored allowed_roles: got %v %v", got, err)
	}
	for name, tc := range map[string]struct {
		role   string
		stored []string
	}{
		"role not in list": {"editor", []string{"user"}},
		"reserved entry":   {"editor", []string{"editor", "postgres"}},
		"malformed entry":  {"editor", []string{"editor", "Nope"}},
		"reserved role":    {"app", nil},
	} {
		if _, err := AccountAllowedRoles(tc.role, tc.stored); !errors.Is(err, ErrInvalidAccountRole) {
			t.Errorf("%s: got %v, want ErrInvalidAccountRole", name, err)
		}
	}
}
