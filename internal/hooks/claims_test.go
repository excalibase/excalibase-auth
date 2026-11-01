package hooks

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func sentClaims() map[string]any {
	return map[string]any{
		"sub": "42", "userId": int64(42), "projectId": "proj_a", "orgSlug": "acme", "projectName": "blog", "orgName": "Acme",
		"role": "user", "allowed_roles": []string{"user", "editor"}, "scope": "authenticated", "iss": "excalibase",
		"aud": []string{"excalibase:proj_a"}, "token_use": "access", "email_verified": true, "email": "a@example.com",
	}
}

// answered round-trips the claims through JSON, as the hook's answer arrives.
func answered(t *testing.T, change func(map[string]any)) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(sentClaims())
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	change(claims)
	return claims
}

func apply(t *testing.T, change func(map[string]any)) (AccessClaims, error) {
	t.Helper()
	return ApplyAccessClaims(sentClaims(), answered(t, change), []string{"user", "editor"})
}

func TestApplyAccessClaims_AddsCustomClaimsAndKeepsTheRest(t *testing.T) {
	got, err := apply(t, func(claims map[string]any) {
		claims["tenant_id"] = "acme"
		claims["plan_level"] = 3.0
		claims["beta"] = true
		claims["groups"] = []any{"admins", "staff"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "user" || got.Custom["tenant_id"] != "acme" || got.Custom["plan_level"] != 3.0 || got.Custom["beta"] != true {
		t.Fatalf("got %+v", got)
	}
	if groups, _ := got.Custom["groups"].([]any); len(groups) != 2 || len(got.Custom) != 4 {
		t.Fatalf("custom = %v", got.Custom)
	}
}

func TestApplyAccessClaims_AnAnswerWithoutTheFixedClaimsKeepsThem(t *testing.T) {
	got, err := ApplyAccessClaims(sentClaims(), map[string]any{"team": "blue"}, []string{"user", "editor"})
	if err != nil || got.Role != "user" || got.Custom["team"] != "blue" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestApplyAccessClaims_PicksADefaultRoleAmongTheAllowedRoles(t *testing.T) {
	got, err := apply(t, func(claims map[string]any) { claims["role"] = "editor" })
	if err != nil || got.Role != "editor" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestApplyAccessClaims_RefusesForbiddenChanges(t *testing.T) {
	cases := map[string]func(map[string]any){
		"role service":          func(c map[string]any) { c["role"] = "service" },
		"role anon":             func(c map[string]any) { c["role"] = "anon" },
		"role outside allowed":  func(c map[string]any) { c["role"] = "admin" },
		"role not a string":     func(c map[string]any) { c["role"] = 7.0 },
		"userId":                func(c map[string]any) { c["userId"] = 43.0 },
		"projectId":             func(c map[string]any) { c["projectId"] = "proj_b" },
		"iss":                   func(c map[string]any) { c["iss"] = "evil" },
		"aud":                   func(c map[string]any) { c["aud"] = []any{"excalibase:proj_b"} },
		"token_use":             func(c map[string]any) { c["token_use"] = "refresh" },
		"scope":                 func(c map[string]any) { c["scope"] = "service" },
		"sub":                   func(c map[string]any) { c["sub"] = "1" },
		"email":                 func(c map[string]any) { c["email"] = "boss@example.com" },
		"email_verified":        func(c map[string]any) { c["email_verified"] = false },
		"allowed_roles":         func(c map[string]any) { c["allowed_roles"] = []any{"user", "editor", "admin"} },
		"added exp":             func(c map[string]any) { c["exp"] = 9999999999.0 },
		"added is_guest":        func(c map[string]any) { c["is_guest"] = true },
		"added keyId":           func(c map[string]any) { c["keyId"] = 1.0 },
		"added user_id":         func(c map[string]any) { c["user_id"] = 1.0 },
		"added actor":           func(c map[string]any) { c["actor"] = "someone" },
		"camel case name":       func(c map[string]any) { c["tenantId"] = "acme" },
		"hyphenated name":       func(c map[string]any) { c["tenant-id"] = "acme" },
		"nested object":         func(c map[string]any) { c["profile"] = map[string]any{"a": 1.0} },
		"nested array":          func(c map[string]any) { c["matrix"] = []any{[]any{"a"}} },
		"null value":            func(c map[string]any) { c["gone"] = nil },
		"long string":           func(c map[string]any) { c["note"] = strings.Repeat("a", MaxClaimStringBytes+1) },
		"long array":            func(c map[string]any) { c["tags"] = make([]any, MaxClaimArrayLength+1) },
		"removed fixed by null": func(c map[string]any) { c["projectId"] = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := apply(t, change); !errors.Is(err, ErrFailed) {
				t.Fatalf("err = %v, want ErrFailed", err)
			}
		})
	}
}

func TestApplyAccessClaims_BoundsTheCustomClaims(t *testing.T) {
	_, err := apply(t, func(claims map[string]any) {
		for i := 0; i <= MaxCustomClaims; i++ {
			claims["c"+strconv.Itoa(i)] = "x"
		}
	})
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("too many claims: err = %v", err)
	}
	_, err = apply(t, func(claims map[string]any) {
		for i := 0; i < 8; i++ {
			claims["c"+strconv.Itoa(i)] = strings.Repeat("a", MaxClaimStringBytes)
		}
	})
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("too many bytes: err = %v", err)
	}
}

func TestApplyAccessClaims_TheReasonNamesTheClaimNotItsValue(t *testing.T) {
	_, err := apply(t, func(claims map[string]any) { claims["projectId"] = "secret-value" })
	if err == nil || !strings.Contains(err.Error(), "projectId") || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("err = %v", err)
	}
}
