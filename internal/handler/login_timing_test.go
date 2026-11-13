package handler

import (
	"context"
	"testing"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/store"
)

type fakeAccounts struct {
	account store.Account
	err     error
}

func (f fakeAccounts) AccountByEmail(context.Context, string) (store.Account, error) {
	return f.account, f.err
}

func hasherFor(t *testing.T) (*AuthHandler, *recordingHasher, string) {
	t.Helper()
	argon := auth.NewHasher(1, auth.DefaultHashWait)
	recorder := &recordingHasher{passwordHasher: argon}
	hash, err := argon.Hash(context.Background(), "right-password")
	if err != nil {
		t.Fatal(err)
	}
	return (&AuthHandler{}).WithHasher(recorder), recorder, hash
}

func TestUnknownEmailStillCostsAHash(t *testing.T) {
	h, recorder, _ := hasherFor(t)
	_, status, err := h.authenticate(context.Background(), fakeAccounts{err: store.ErrNotFound}, "nobody@x.test", "pw")
	if status != 401 || err != errInvalidCredentials {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if len(recorder.checked) != 1 || recorder.checked[0] != noPasswordHash {
		t.Fatalf("expected one check against the dummy hash, got %v", recorder.checked)
	}
}

func TestDisabledAccountWithWrongPasswordLooksLikeAnyWrongPassword(t *testing.T) {
	h, _, hash := hasherFor(t)
	accounts := fakeAccounts{account: store.Account{Enabled: false, PasswordHash: hash}}
	_, status, err := h.authenticate(context.Background(), accounts, "a@x.test", "wrong")
	if status != 401 || err != errInvalidCredentials {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestDisabledShowsOnlyAfterTheRightPassword(t *testing.T) {
	h, _, hash := hasherFor(t)
	accounts := fakeAccounts{account: store.Account{Enabled: false, PasswordHash: hash}}
	_, status, err := h.authenticate(context.Background(), accounts, "a@x.test", "right-password")
	if status != 403 || err != errAccountDisabled {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestEnabledAccountWithRightPasswordAuthenticates(t *testing.T) {
	h, _, hash := hasherFor(t)
	accounts := fakeAccounts{account: store.Account{Enabled: true, PasswordHash: hash}}
	_, status, err := h.authenticate(context.Background(), accounts, "a@x.test", "right-password")
	if status != 0 || err != nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
}
