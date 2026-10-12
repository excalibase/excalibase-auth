package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// An answer with no user (an api-key sign-in) must not invent one: apps test `if (user)` (EXC-607).
func TestAuthResponseWithoutAUserOmitsTheField(t *testing.T) {
	encoded, err := json.Marshal(AuthResponse{AccessToken: "t", TokenType: "Bearer", ExpiresIn: 60})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"user"`) {
		t.Fatalf("anonymous answer carries a user: %s", encoded)
	}
	encoded, _ = json.Marshal(AuthResponse{AccessToken: "t", User: &UserInfo{ID: 7, Email: "a@b.c"}})
	if !strings.Contains(string(encoded), `"user":{"id":7,"email":"a@b.c","fullName":""}`) {
		t.Fatalf("signed-in answer lost its user: %s", encoded)
	}
}
