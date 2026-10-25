package oauth_test

import (
	"testing"

	"github.com/excalibase/auth/internal/oauth"
)

func TestRedirectAllowListIsAnExactMatch(t *testing.T) {
	allowed := []string{"https://app.example.com", "https://app.example.com/auth/callback", "http://localhost:3000/cb"}
	cases := map[string]bool{
		"https://app.example.com":                    true,
		"https://app.example.com/":                   true,
		"https://APP.example.com/auth/callback":      true,
		"https://app.example.com:443/auth/callback":  true,
		"https://app.example.com/auth/callback?x=1":  true,
		"http://localhost:3000/cb":                   true,
		"https://app.example.com/auth/callback/":     false,
		"https://app.example.com/auth/callbackx":     false,
		"https://app.example.com/auth":               false,
		"http://app.example.com/auth/callback":       false,
		"https://app.example.com:8443/auth/callback": false,
		"https://evil.example.com/auth/callback":     false,
		"https://app.example.com.evil.com":           false,
		"https://user@app.example.com":               false,
		"https://app.example.com#frag":               false,
		"//app.example.com":                          false,
		"/auth/callback":                             false,
		"javascript:alert(1)":                        false,
		"http://localhost:3001/cb":                   false,
		"":                                           false,
		"https://app.example.com/a/../auth/callback": false,
	}
	for raw, want := range cases {
		if _, got := oauth.AllowedRedirect(raw, allowed); got != want {
			t.Errorf("AllowedRedirect(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestAllowedRedirectIgnoresBrokenEntries(t *testing.T) {
	if _, ok := oauth.AllowedRedirect("https://app.example.com", []string{"", "not a url", "app.example.com"}); ok {
		t.Fatal("a malformed allow-list entry matched")
	}
}

func TestWithParamReplacesAndKeepsTheRest(t *testing.T) {
	got := oauth.WithParam("https://app.example.com/cb?next=%2Fhome&code=old", "code", "new")
	if got != "https://app.example.com/cb?code=new&next=%2Fhome" {
		t.Fatalf("got %s", got)
	}
	errored := oauth.WithError("https://app.example.com/cb?code=old", "access_denied")
	if errored != "https://app.example.com/cb?error=access_denied" {
		t.Fatalf("got %s", errored)
	}
}
