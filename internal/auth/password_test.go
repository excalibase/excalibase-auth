package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordProducesArgon2id(t *testing.T) {
	hash, err := HashPassword("test-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected argon2id prefix, got: %s", hash[:20])
	}
}

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword("secret123", hash) {
		t.Error("valid password should verify")
	}
	if CheckPassword("wrong", hash) {
		t.Error("wrong password should not verify")
	}
}

func TestHashPasswordUniqueSalt(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("same password should produce different hashes")
	}
}

func TestCheckPasswordRejectsBcrypt(t *testing.T) {
	bcryptHash := "$2a$10$IevCHEIm2tE4uQg50oah3eZsCPQ0qsaHOrchTH1uMLn9/cMFwlt52"
	if CheckPassword("admin123", bcryptHash) {
		t.Error("bcrypt hash should be rejected")
	}
}

func TestCheckPasswordEmptyHash(t *testing.T) {
	if CheckPassword("anything", "") {
		t.Error("empty hash should not verify")
	}
}
