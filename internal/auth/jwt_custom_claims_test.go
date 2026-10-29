package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestSign_AddsCustomClaimsButNeverOverAuthsOwn(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)
	signed, err := svc.Sign(Claims{Sub: "42", UserID: 42, ProjectID: "p", Role: "user", AllowedRoles: []string{"user"},
		Custom: map[string]any{"tenant_id": "acme", "projectId": "other", "role": "service"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["tenant_id"] != "acme" || claims["projectId"] != "p" || claims["role"] != "user" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestPublicClaims_AreWhatSignWritesWithoutTheTimes(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)
	claims := svc.PublicClaims(Claims{Sub: "42", UserID: 42, ProjectID: "p", Role: "user", AllowedRoles: []string{"user"},
		Scope: "authenticated", Email: "a@example.com", AuthTime: 99})
	if claims["iss"] != "excalibase" || claims["token_use"] != TokenUseAccess || claims["userId"] != int64(42) ||
		claims["email"] != "a@example.com" || claims["scope"] != "authenticated" {
		t.Fatalf("claims = %v", claims)
	}
	for _, timed := range []string{"iat", "exp", "auth_time"} {
		if _, ok := claims[timed]; ok {
			t.Fatalf("%s is in the hook's claims: %v", timed, claims)
		}
	}
}
