package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func hashPassword(pw string) (string, error) {
	return NewHasher(1, time.Second).Hash(context.Background(), pw)
}

func checkPassword(pw, hash string) bool {
	ok, _ := NewHasher(1, time.Second).Check(context.Background(), pw, hash)
	return ok
}

func TestHashPasswordProducesArgon2id(t *testing.T) {
	hash, err := hashPassword("test-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected argon2id prefix, got: %s", hash[:20])
	}
}

func TestHashAndVerify(t *testing.T) {
	hash, err := hashPassword("secret123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !checkPassword("secret123", hash) {
		t.Error("valid password should verify")
	}
	if checkPassword("wrong", hash) {
		t.Error("wrong password should not verify")
	}
}

func TestHashPasswordUniqueSalt(t *testing.T) {
	h1, _ := hashPassword("same")
	h2, _ := hashPassword("same")
	if h1 == h2 {
		t.Error("same password should produce different hashes")
	}
}

func TestCheckPasswordRejectsBcrypt(t *testing.T) {
	bcryptHash := "$2a$10$IevCHEIm2tE4uQg50oah3eZsCPQ0qsaHOrchTH1uMLn9/cMFwlt52"
	if checkPassword("admin123", bcryptHash) {
		t.Error("bcrypt hash should be rejected")
	}
}

func TestCheckPasswordEmptyHash(t *testing.T) {
	if checkPassword("anything", "") {
		t.Error("empty hash should not verify")
	}
}
