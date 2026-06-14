package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
}

func TestSignAndVerify(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, err := NewJWTService(keyPEM, "excalibase", 3600)
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	token, err := svc.Sign(Claims{
		Sub:       "user@test.com",
		UserID:    42,
		ProjectID: "my-app",
		Role:      "user",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "user@test.com" {
		t.Errorf("sub: got %s", claims.Sub)
	}
	if claims.UserID != 42 {
		t.Errorf("userId: got %d", claims.UserID)
	}
	if claims.ProjectID != "my-app" {
		t.Errorf("projectId: got %s", claims.ProjectID)
	}
	if claims.Role != "user" {
		t.Errorf("role: got %s", claims.Role)
	}
}

func TestExpiredToken(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", -1) // negative = already expired

	token, _ := svc.Sign(Claims{Sub: "expired@test.com", UserID: 1, ProjectID: "p"})
	_, err := svc.Verify(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestTamperedToken(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	token, _ := svc.Sign(Claims{Sub: "user@test.com", UserID: 1, ProjectID: "p"})

	// Tamper with the token
	tampered := token[:len(token)-5] + "XXXXX"
	_, err := svc.Verify(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestWrongKey(t *testing.T) {
	key1 := testKeyPEM(t)
	key2 := testKeyPEM(t)

	svc1, _ := NewJWTService(key1, "excalibase", 3600)
	svc2, _ := NewJWTService(key2, "excalibase", 3600)

	token, _ := svc1.Sign(Claims{Sub: "user@test.com", UserID: 1, ProjectID: "p"})
	_, err := svc2.Verify(token)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func _ () { _ = time.Now() } // keep time import used

// A token signed by an issuer different from the verifier's configured issuer
// must be rejected. We sign with svcA (issuer "issuer-a") and verify with svcB
// (issuer "issuer-b") using the SAME key, so the signature is valid and only the
// issuer differs — isolating the issuer check from the signature check.
func TestVerify_RejectsWrongIssuer(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	svcA, _ := NewJWTService(keyPEM, "issuer-a", 3600)
	svcB, _ := NewJWTService(keyPEM, "issuer-b", 3600)

	token, err := svcA.Sign(Claims{Sub: "u@test.com", UserID: 1, ProjectID: "p"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := svcB.Verify(token); err == nil {
		t.Fatal("expected error verifying a token with a mismatched issuer")
	}
}

// When no issuer is configured (empty string), the issuer check must be skipped
// so deployments that never set an issuer keep working.
func TestVerify_SkipsIssuerCheckWhenUnconfigured(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	// Signer stamps iss="something"; verifier has empty issuer → must accept.
	signer, _ := NewJWTService(keyPEM, "something", 3600)
	verifier, _ := NewJWTService(keyPEM, "", 3600)

	token, _ := signer.Sign(Claims{Sub: "u@test.com", UserID: 1, ProjectID: "p"})
	if _, err := verifier.Verify(token); err != nil {
		t.Fatalf("expected token to verify when issuer unconfigured, got %v", err)
	}
}

// --- Phase 3: scope + keyId round-trip ---

// A Claims round-trip must carry scope and keyId untouched when they are set
// (api-key grant) and must omit them entirely from the token when they aren't
// (password grant) so existing consumers see no observable change.
func TestSignVerify_ScopeAndKeyIdRoundTrip(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	token, err := svc.Sign(Claims{
		Sub:       "apikey:7",
		UserID:    42,
		ProjectID: "acme/prod",
		Role:      "service",
		Scope:     "service",
		KeyID:     7,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Scope != "service" {
		t.Errorf("scope: got %q, want service", claims.Scope)
	}
	if claims.KeyID != 7 {
		t.Errorf("keyId: got %d, want 7", claims.KeyID)
	}
	if claims.Sub != "apikey:7" {
		t.Errorf("sub: got %q, want apikey:7", claims.Sub)
	}
}

// A password-grant token must verify cleanly with empty scope / zero keyId so
// existing legacy flows aren't broken by the new optional fields.
func TestSignVerify_OmitsScopeAndKeyIdWhenUnset(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	token, err := svc.Sign(Claims{
		Sub:       "alice@test.com",
		UserID:    1,
		ProjectID: "acme/prod",
		Role:      "user",
		// Scope and KeyID intentionally zero-value
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Scope != "" {
		t.Errorf("scope should be empty when unset, got %q", claims.Scope)
	}
	if claims.KeyID != 0 {
		t.Errorf("keyId should be zero when unset, got %d", claims.KeyID)
	}
}

// Publishable-key tokens use Scope="public" which is a distinct branch from
// service-scope and must also round-trip.
func TestSignVerify_PublishableKeyScope(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	token, _ := svc.Sign(Claims{
		Sub:       "apikey:3",
		UserID:    1,
		ProjectID: "acme/prod",
		Role:      "user",
		Scope:     "public",
		KeyID:     3,
	})
	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Scope != "public" {
		t.Errorf("scope: got %q, want public", claims.Scope)
	}
}

// Verify() must not crash on a token missing optional claims. Construct a raw
// token via Sign() with everything empty — this is the minimum-shape path.
func TestVerify_MinimumShapeToken(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	token, err := svc.Sign(Claims{Sub: "", UserID: 0, ProjectID: ""})
	if err != nil {
		t.Fatalf("Sign minimal: %v", err)
	}
	claims, err := svc.Verify(token)
	if err != nil {
		t.Fatalf("Verify minimal: %v", err)
	}
	if claims == nil {
		t.Fatal("claims should not be nil")
	}
}

func TestNewJWTService_RejectsInvalidPEM(t *testing.T) {
	_, err := NewJWTService("not a pem block", "excalibase", 3600)
	if err == nil {
		t.Error("expected error for invalid PEM input")
	}
}

func TestNewJWTService_RejectsUnparseableKey(t *testing.T) {
	bogus := "-----BEGIN EC PRIVATE KEY-----\nQUFB\n-----END EC PRIVATE KEY-----\n"
	_, err := NewJWTService(bogus, "excalibase", 3600)
	if err == nil {
		t.Error("expected error for unparseable key bytes")
	}
}

// PublicKeyJWKS is consumed by the /.well-known/jwks.json endpoint. Downstream
// services like excalibase-graphql use the produced JWK Set to verify tokens,
// so the serialization shape (kty, crv, x, y, alg, kid) must stay stable.
func TestPublicKeyJWKS_SerializesP256(t *testing.T) {
	keyPEM := testKeyPEM(t)
	svc, _ := NewJWTService(keyPEM, "excalibase", 3600)

	jwks := svc.PublicKeyJWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly one JWK, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "EC" {
		t.Errorf("kty: got %q, want EC", k.Kty)
	}
	if k.Crv != "P-256" {
		t.Errorf("crv: got %q, want P-256", k.Crv)
	}
	if k.Alg != "ES256" {
		t.Errorf("alg: got %q, want ES256", k.Alg)
	}
	if k.Kid == "" {
		t.Error("kid must not be empty — downstream caches key on this value")
	}
	if k.X == "" || k.Y == "" {
		t.Error("x and y coordinates must be populated")
	}
	if k.Use != "sig" {
		t.Errorf("use: got %q, want sig", k.Use)
	}
}
