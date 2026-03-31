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
