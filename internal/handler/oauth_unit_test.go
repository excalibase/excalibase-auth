package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/oauth"
)

// recordingHasher records what Check was asked to compare against.
type recordingHasher struct {
	passwordHasher
	checked []string
}

func (r *recordingHasher) Check(ctx context.Context, password, encoded string) (bool, error) {
	r.checked = append(r.checked, encoded)
	return r.passwordHasher.Check(ctx, password, encoded)
}

func TestAnAccountWithoutAPasswordStillCostsAHash(t *testing.T) {
	argon := auth.NewHasher(1, auth.DefaultHashWait)
	recorder := &recordingHasher{passwordHasher: argon}
	h := (&AuthHandler{}).WithHasher(recorder)
	matched, err := h.checkPassword(context.Background(), "anything", "")
	if err != nil || matched || len(recorder.checked) != 1 || recorder.checked[0] != noPasswordHash {
		t.Fatalf("matched=%v err=%v checked=%v", matched, err, recorder.checked)
	}
	// The stand-in must have our own hash's shape, or Check refuses it without hashing.
	sample, err := argon.Hash(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	want, got := strings.Split(sample, "$"), strings.Split(noPasswordHash, "$")
	if len(want) != len(got) || strings.Join(want[:4], "$") != strings.Join(got[:4], "$") ||
		len(want[4]) != len(got[4]) || len(want[5]) != len(got[5]) {
		t.Fatalf("noPasswordHash %q does not match the shape of %q", noPasswordHash, sample)
	}
}

func TestDisplayNameFallsBackAndIsBounded(t *testing.T) {
	if got := displayName(oauth.Identity{Email: "ann@x.test"}); got != "ann" {
		t.Fatalf("got %q", got)
	}
	if got := displayName(oauth.Identity{Name: strings.Repeat("é", 150)}); len([]rune(got)) != maxFullName {
		t.Fatalf("got %d runes", len([]rune(got)))
	}
}
