package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewSigner_TokenLivesForAccessTTL(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	signer, err := newSigner(keyPEM, config.Config{AccessTTL: 1234})
	if err != nil {
		t.Fatalf("newSigner: %v", err)
	}
	tok, err := signer.Sign(auth.Claims{ProjectID: "p"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		t.Fatalf("parse: %v", err)
	}
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if int(exp-iat) != 1234 {
		t.Errorf("exp - iat: got %d, want 1234", int(exp-iat))
	}
}
