package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		want     error
	}{
		{"empty", "", errPasswordTooShort},
		{"seven characters", "abcdefg", errPasswordTooShort},
		{"eight characters", "abcdefgh", nil},
		{"eight multibyte characters", "ééééééé€", nil},
		{"only whitespace", "  \t \n    ", errPasswordBlank},
		{"inner whitespace is fine", "correct horse", nil},
		{"at the byte limit", strings.Repeat("a", maxPasswordBytes), nil},
		{"over the byte limit", strings.Repeat("a", maxPasswordBytes+1), errPasswordTooLong},
		{"multibyte over the byte limit", strings.Repeat("€", maxPasswordBytes/3+1), errPasswordTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.password); got != tc.want {
				t.Errorf("validatePassword(%q): got %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func postUnit(t *testing.T, path, body string) (int, map[string]interface{}) {
	t.Helper()
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var decoded map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &decoded)
	return w.Code, decoded
}

// Registration names the password rule it broke, before touching the database.
func TestRegister_RefusesPasswordsOutsideThePolicy(t *testing.T) {
	cases := map[string]struct {
		password string
		want     error
	}{
		"empty":           {"", errPasswordTooShort},
		"short":           {"abc", errPasswordTooShort},
		"whitespace only": {"          ", errPasswordBlank},
		"too long":        {strings.Repeat("x", maxPasswordBytes+1), errPasswordTooLong},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": tc.password, "fullName": "A"})
			code, resp := postUnit(t, "/register", string(body))
			if code != 400 || resp["error"] != tc.want.Error() {
				t.Errorf("got %d %v, want 400 %q", code, resp["error"], tc.want.Error())
			}
		})
	}
}

func TestRegister_MissingEmailOrNameIsNotAPasswordError(t *testing.T) {
	code, resp := postUnit(t, "/register", `{"email":"a@b.com","password":"long-enough-1"}`)
	if code != 400 || resp["error"] != errEmailAndNameRequired.Error() {
		t.Errorf("got %d %v, want 400 %q", code, resp["error"], errEmailAndNameRequired.Error())
	}
}

// A reset holds the new password to the same rule, checked before the token.
func TestResetPassword_RefusesPasswordsOutsideThePolicy(t *testing.T) {
	for _, password := range []string{"", "short", "         "} {
		body, _ := json.Marshal(map[string]string{"token": "any", "newPassword": password})
		code, resp := postUnit(t, "/reset-password", string(body))
		if code != 400 || resp["error"] != validatePassword(password).Error() {
			t.Errorf("%q: got %d %v", password, code, resp["error"])
		}
	}
}
