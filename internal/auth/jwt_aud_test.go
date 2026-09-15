package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// EXC-11: every minted token must carry an `aud` array scoped to the project so
// downstream verifiers (graphql engine, control plane) can reject a token that
// was minted for a different project.

func parseUnverified(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims are not a map")
	}
	return claims
}

func audienceOf(t *testing.T, claims jwt.MapClaims) []string {
	t.Helper()
	raw, ok := claims["aud"].([]interface{})
	if !ok {
		t.Fatalf("aud must be a JSON array, got %T (%v)", claims["aud"], claims["aud"])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("aud entry must be a string, got %T", v)
		}
		out = append(out, s)
	}
	return out
}

func TestSign_EmitsProjectScopedAudienceArray(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)

	token, err := svc.Sign(Claims{Sub: "u@test.com", UserID: 1, ProjectID: "proj_abc"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	aud := audienceOf(t, parseUnverified(t, token))
	if len(aud) != 1 || aud[0] != "excalibase:proj_abc" {
		t.Fatalf("aud: got %v, want [excalibase:proj_abc]", aud)
	}
}

func TestSign_AudiencePrefixIsConfigurable(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)
	svc.SetAudiencePrefix("tenant/")

	token, _ := svc.Sign(Claims{Sub: "u@test.com", ProjectID: "proj_abc"})

	aud := audienceOf(t, parseUnverified(t, token))
	if len(aud) != 1 || aud[0] != "tenant/proj_abc" {
		t.Fatalf("aud: got %v, want [tenant/proj_abc]", aud)
	}
}

func TestSetAudiencePrefix_EmptyKeepsDefault(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)
	svc.SetAudiencePrefix("")

	token, _ := svc.Sign(Claims{ProjectID: "proj_abc"})

	aud := audienceOf(t, parseUnverified(t, token))
	if len(aud) != 1 || aud[0] != DefaultAudiencePrefix+"proj_abc" {
		t.Fatalf("aud: got %v, want default prefix", aud)
	}
}

func TestSign_MarksTokenUseAccess(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)

	token, _ := svc.Sign(Claims{Sub: "u@test.com", ProjectID: "proj_abc"})

	if use := parseUnverified(t, token)["token_use"]; use != TokenUseAccess {
		t.Fatalf("token_use: got %v, want %q", use, TokenUseAccess)
	}
}

func TestSign_EmitsEmailVerifiedClaim(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)

	verified, _ := svc.Sign(Claims{ProjectID: "p", EmailVerified: true})
	if got := parseUnverified(t, verified)["email_verified"]; got != true {
		t.Fatalf("email_verified: got %v, want true", got)
	}

	unverified, _ := svc.Sign(Claims{ProjectID: "p"})
	if got := parseUnverified(t, unverified)["email_verified"]; got != false {
		t.Fatalf("email_verified: got %v, want false", got)
	}
}

func TestVerify_RoundTripsAudienceAndTokenUse(t *testing.T) {
	svc, _ := NewJWTService(testKeyPEM(t), "excalibase", 3600)

	token, _ := svc.Sign(Claims{Sub: "u@test.com", ProjectID: "proj_abc", EmailVerified: true})

	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "excalibase:proj_abc" {
		t.Fatalf("audience: got %v", claims.Audience)
	}
	if claims.TokenUse != TokenUseAccess {
		t.Fatalf("tokenUse: got %q", claims.TokenUse)
	}
	if !claims.EmailVerified {
		t.Fatal("emailVerified should round-trip as true")
	}
}
