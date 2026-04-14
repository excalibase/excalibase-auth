package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerate_PublishableFormat(t *testing.T) {
	plaintext, _, _, err := GenerateAPIKey(KeyTypePublishable)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	const prefix = "esk_pub_live_"
	if !strings.HasPrefix(plaintext, prefix) {
		t.Errorf("publishable key must start with %q, got %q", prefix, plaintext)
	}
	random := strings.TrimPrefix(plaintext, prefix)
	if len(random) != 24 {
		t.Errorf("random portion must be 24 chars, got %d (%q)", len(random), random)
	}
}

func TestGenerate_SecretFormat(t *testing.T) {
	plaintext, _, _, err := GenerateAPIKey(KeyTypeSecret)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	const prefix = "esk_sec_live_"
	if !strings.HasPrefix(plaintext, prefix) {
		t.Errorf("secret key must start with %q, got %q", prefix, plaintext)
	}
	random := strings.TrimPrefix(plaintext, prefix)
	if len(random) != 24 {
		t.Errorf("random portion must be 24 chars, got %d", len(random))
	}
}

func TestGenerate_HashIsSHA256HexOfPlaintext(t *testing.T) {
	plaintext, hash, _, err := GenerateAPIKey(KeyTypePublishable)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	sum := sha256.Sum256([]byte(plaintext))
	want := hex.EncodeToString(sum[:])
	if hash != want {
		t.Errorf("hash mismatch\n  got:  %q\n  want: %q", hash, want)
	}
	if len(hash) != 64 {
		t.Errorf("sha256 hex length must be 64, got %d", len(hash))
	}
}

func TestGenerate_PrefixIsFirst12OfRandomPortion(t *testing.T) {
	plaintext, _, prefix, err := GenerateAPIKey(KeyTypePublishable)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	random := strings.TrimPrefix(plaintext, "esk_pub_live_")
	want := random[:12]
	if prefix != want {
		t.Errorf("prefix: got %q, want %q", prefix, want)
	}
	if len(prefix) != 12 {
		t.Errorf("prefix length: got %d, want 12", len(prefix))
	}
}

func TestGenerate_TwoKeysDiffer(t *testing.T) {
	a, _, _, _ := GenerateAPIKey(KeyTypePublishable)
	b, _, _, _ := GenerateAPIKey(KeyTypePublishable)
	if a == b {
		t.Error("two generated keys are identical — randomness broken")
	}
}

func TestGenerate_InvalidKeyTypeErrors(t *testing.T) {
	_, _, _, err := GenerateAPIKey("bogus")
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

// HashAPIKey(plaintext) must return the same hash that GenerateAPIKey returned
// for the same plaintext, so that lookup-by-plaintext can find the stored row.
func TestHashAPIKey_MatchesGenerate(t *testing.T) {
	plaintext, genHash, _, err := GenerateAPIKey(KeyTypeSecret)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	got := HashAPIKey(plaintext)
	if got != genHash {
		t.Errorf("HashAPIKey vs Generate mismatch\n  got:   %q\n  want:  %q", got, genHash)
	}
}

// Valid api keys use a Base62-style alphabet. This keeps them URL-safe and
// avoids characters that look alike in logs (no 0/O/I/l ambiguity specifically,
// but standard Base62 is acceptable for this session).
func TestGenerate_RandomPortionIsAlphaNumeric(t *testing.T) {
	plaintext, _, _, _ := GenerateAPIKey(KeyTypePublishable)
	random := strings.TrimPrefix(plaintext, "esk_pub_live_")
	for _, r := range random {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			t.Errorf("non-base62 rune %q in random portion %q", r, random)
		}
	}
}
