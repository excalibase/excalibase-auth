package handler

import (
	"errors"
	"slices"
	"testing"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/service"
)

var testLabels = projectLabels{orgSlug: "acme", projectName: "blog", orgName: "Acme"}

func TestEndUserClaims_CarryAccountRole(t *testing.T) {
	user := domain.UserInfo{ID: 12, Email: "ed@test.com", FullName: "Ed"}
	claims, err := endUserClaims("proj_1", testLabels, user, accountRoles{role: "editor"}, true)
	if err != nil {
		t.Fatalf("endUserClaims: %v", err)
	}
	if claims.Role != "editor" || !slices.Equal(claims.AllowedRoles, []string{"editor"}) {
		t.Errorf("role %q allowed %v, want editor [editor]", claims.Role, claims.AllowedRoles)
	}
	if claims.Scope != "authenticated" || claims.UserID != 12 || claims.Sub != "ed@test.com" || !claims.EmailVerified {
		t.Errorf("unexpected end-user claims: %+v", claims)
	}
	if claims.OrgSlug != "acme" || claims.ProjectName != "blog" || claims.OrgName != "Acme" || claims.ProjectID != "proj_1" {
		t.Errorf("unexpected project labels: %+v", claims)
	}
}

func TestEndUserClaims_RefuseReservedOrInvalidRole(t *testing.T) {
	user := domain.UserInfo{ID: 12, Email: "ed@test.com"}
	for _, role := range []string{"anon", "service", "", "Admin", "not-valid", "postgres", "pg_monitor", "excalibase_app"} {
		if _, err := endUserClaims("proj_1", testLabels, user, accountRoles{role: role}, false); !errors.Is(err, auth.ErrInvalidAccountRole) {
			t.Errorf("role %q: got %v, want ErrInvalidAccountRole", role, err)
		}
	}
}

func TestEndUserClaims_CarryStoredAllowedRoles(t *testing.T) {
	user := domain.UserInfo{ID: 12, Email: "ed@test.com"}
	claims, err := endUserClaims("proj_1", testLabels, user, accountRoles{role: "editor", allowed: []string{"user", "editor"}}, false)
	if err != nil {
		t.Fatalf("endUserClaims: %v", err)
	}
	if claims.Role != "editor" || !slices.Equal(claims.AllowedRoles, []string{"user", "editor"}) {
		t.Errorf("role %q allowed %v, want editor [user editor]", claims.Role, claims.AllowedRoles)
	}
}

func TestEndUserClaims_RefuseInvalidStoredAllowedRoles(t *testing.T) {
	user := domain.UserInfo{ID: 12, Email: "ed@test.com"}
	for name, allowed := range map[string][]string{
		"role missing":    {"user"},
		"reserved entry":  {"editor", "service"},
		"malformed entry": {"editor", "Bad"},
	} {
		_, err := endUserClaims("proj_1", testLabels, user, accountRoles{role: "editor", allowed: allowed}, false)
		if !errors.Is(err, auth.ErrInvalidAccountRole) {
			t.Errorf("%s: got %v, want ErrInvalidAccountRole", name, err)
		}
	}
}

func TestAPIKeyClaims_PublishableIsAnon(t *testing.T) {
	claims, err := apiKeyClaims("proj_1", testLabels, 5, string(service.KeyTypePublishable))
	if err != nil {
		t.Fatalf("apiKeyClaims: %v", err)
	}
	if claims.Role != "anon" || !slices.Equal(claims.AllowedRoles, []string{"anon"}) || claims.Scope != "public" {
		t.Errorf("publishable: role %q allowed %v scope %q", claims.Role, claims.AllowedRoles, claims.Scope)
	}
	if claims.UserID != 0 || claims.KeyID != 5 || claims.Sub != "apikey:5" {
		t.Errorf("publishable identity: %+v", claims)
	}
}

func TestAPIKeyClaims_SecretIsService(t *testing.T) {
	claims, err := apiKeyClaims("proj_1", testLabels, 6, string(service.KeyTypeSecret))
	if err != nil {
		t.Fatalf("apiKeyClaims: %v", err)
	}
	if claims.Role != "service" || !slices.Equal(claims.AllowedRoles, []string{"service"}) || claims.Scope != "service" {
		t.Errorf("secret: role %q allowed %v scope %q", claims.Role, claims.AllowedRoles, claims.Scope)
	}
	if claims.UserID != 0 || claims.KeyID != 6 {
		t.Errorf("secret identity: %+v", claims)
	}
}

func TestAPIKeyClaims_RefuseUnknownKeyType(t *testing.T) {
	if _, err := apiKeyClaims("proj_1", testLabels, 7, "master"); err == nil {
		t.Error("unknown key type must not mint a token")
	}
}
