package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/mfa"
	"github.com/excalibase/auth/internal/store"
)

// codesStore answers AddRecoveryCodesIfNone and nothing else.
type codesStore struct {
	store.Store
	added  bool
	err    error
	hashes []string
}

func (s *codesStore) AddRecoveryCodesIfNone(_ context.Context, _ int64, hashes []string) (bool, error) {
	s.hashes = hashes
	return s.added, s.err
}

func TestStepUpRecoveryCodes(t *testing.T) {
	keys, err := mfa.NewKeys([]byte(strings.Repeat("k", mfa.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	h := &AuthHandler{}
	request := httptest.NewRequest("POST", "/", nil)
	cases := []struct {
		name        string
		db          *codesStore
		wantCodes   bool
		wantMissing bool
	}{
		{"an account with none gets a set", &codesStore{added: true}, true, false},
		{"an account with unspent codes gets none", &codesStore{}, false, false},
		{"a set that could not be stored is reported missing", &codesStore{err: errors.New("db down")}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome := h.stepUpRecoveryCodes(request, tc.db, keys, 7)
			if (len(outcome.codes) == mfa.RecoveryCodeCount) != tc.wantCodes || (outcome.codes != nil) != tc.wantCodes ||
				outcome.missing != tc.wantMissing {
				t.Fatalf("outcome = %+v", outcome)
			}
			if len(tc.db.hashes) != mfa.RecoveryCodeCount {
				t.Fatalf("stored %d hashes", len(tc.db.hashes))
			}
		})
	}
}

func TestElevatedSessionSaysWhenCodesAreMissing(t *testing.T) {
	raw, _ := json.Marshal(elevatedSession{AuthResponse: &domain.AuthResponse{}, RecoveryCodesMissing: true})
	if !strings.Contains(string(raw), `"recoveryCodesMissing":true`) {
		t.Fatalf("body = %s", raw)
	}
	raw, _ = json.Marshal(elevatedSession{AuthResponse: &domain.AuthResponse{}})
	if strings.Contains(string(raw), "recoveryCodesMissing") {
		t.Fatalf("body = %s", raw)
	}
}
