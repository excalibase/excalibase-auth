package auth

import (
	"bytes"
	"testing"
)

func TestDerivedKeyIsStablePerPurposeAndSigningKey(t *testing.T) {
	pem := testKeyPEM(t)
	first, err := NewJWTService(pem, "excalibase", 60)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := NewJWTService(pem, "excalibase", 60)
	other, _ := NewJWTService(testKeyPEM(t), "excalibase", 60)

	derive := func(s *JWTService, purpose string) []byte {
		key, err := s.DerivedKey(purpose)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key := derive(first, "email-otp")
	if len(key) != 32 || !bytes.Equal(key, derive(again, "email-otp")) {
		t.Fatalf("a derived key is not stable across loads of one signing key")
	}
	if bytes.Equal(key, derive(first, "other-purpose")) || bytes.Equal(key, derive(other, "email-otp")) {
		t.Fatal("a derived key repeated across purposes or signing keys")
	}
}
