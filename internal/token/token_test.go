package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNew_ProducesHighEntropyPlaintext(t *testing.T) {
	plaintext, _, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(plaintext)
	if err != nil {
		t.Fatalf("plaintext must be raw base64url: %v", err)
	}
	if len(raw) != EntropyBytes {
		t.Fatalf("entropy: got %d bytes, want %d", len(raw), EntropyBytes)
	}
	if strings.ContainsAny(plaintext, "+/=") {
		t.Fatalf("plaintext must be URL-safe, got %q", plaintext)
	}
}

func TestNew_IsUniquePerCall(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		plaintext, _, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if seen[plaintext] {
			t.Fatal("New returned a duplicate token")
		}
		seen[plaintext] = true
	}
}

func TestNew_ReturnsHashOfPlaintextNotPlaintext(t *testing.T) {
	plaintext, hash, _ := New()
	if hash == plaintext {
		t.Fatal("hash must not equal the plaintext")
	}
	if len(hash) != 64 {
		t.Fatalf("hash must be 64 hex chars, got %d", len(hash))
	}
	if hash != Hash(plaintext) {
		t.Fatal("hash must be Hash(plaintext)")
	}
	if strings.Contains(hash, plaintext) {
		t.Fatal("hash must not embed the plaintext")
	}
}

func TestHash_IsStable(t *testing.T) {
	if Hash("abc") != Hash("abc") {
		t.Fatal("Hash must be deterministic")
	}
	if Hash("abc") == Hash("abd") {
		t.Fatal("Hash must differ for different inputs")
	}
}

func TestEqual_MatchesOnlyIdenticalHashes(t *testing.T) {
	h := Hash("abc")
	if !Equal(h, Hash("abc")) {
		t.Fatal("Equal must be true for identical hashes")
	}
	if Equal(h, Hash("abd")) {
		t.Fatal("Equal must be false for different hashes")
	}
	if Equal(h, "") {
		t.Fatal("Equal must be false for a length mismatch")
	}
}
