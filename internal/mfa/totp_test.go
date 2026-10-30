package mfa

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret is the SHA-1 seed of RFC 6238 appendix B.
var rfc6238Secret = []byte("12345678901234567890")

func TestCodeMatchesTheRFC6238Vectors(t *testing.T) {
	// The RFC prints eight digits; six digits are their last six.
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for unix, want := range vectors {
		if got := Code(rfc6238Secret, StepAt(time.Unix(unix, 0))); got != want {
			t.Errorf("code at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestMatchAcceptsOneStepOfSkewEitherWay(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := StepAt(now)
	for _, offset := range []int64{-1, 0, 1} {
		got, ok := Match(rfc6238Secret, Code(rfc6238Secret, step+offset), now, 0)
		if !ok || got != step+offset {
			t.Errorf("offset %d: step=%d ok=%v", offset, got, ok)
		}
	}
	for _, offset := range []int64{-2, 2} {
		if _, ok := Match(rfc6238Secret, Code(rfc6238Secret, step+offset), now, 0); ok {
			t.Errorf("offset %d accepted", offset)
		}
	}
}

func TestMatchRefusesAStepAlreadyUsedOrOlder(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := StepAt(now)
	if _, ok := Match(rfc6238Secret, Code(rfc6238Secret, step), now, step); ok {
		t.Fatal("the last used step was accepted again")
	}
	if _, ok := Match(rfc6238Secret, Code(rfc6238Secret, step-1), now, step); ok {
		t.Fatal("a step older than the last used one was accepted")
	}
	if got, ok := Match(rfc6238Secret, Code(rfc6238Secret, step+1), now, step); !ok || got != step+1 {
		t.Fatalf("a newer step was refused: %d %v", got, ok)
	}
}

func TestMatchRefusesMalformedCodes(t *testing.T) {
	now := time.Unix(1111111111, 0)
	for _, code := range []string{"", "12345", "1234567", "abcdef", " 50471", "05047١"} {
		if _, ok := Match(rfc6238Secret, code, now, 0); ok {
			t.Errorf("code %q accepted", code)
		}
	}
	if _, ok := Match(rfc6238Secret, " 050 471 ", now, 0); !ok {
		t.Error("a code with spaces, as apps show it, was refused")
	}
}

func TestNewSecretIsTwentyRandomBytes(t *testing.T) {
	first, err := NewSecret()
	if err != nil || len(first) != SecretBytes {
		t.Fatalf("secret len=%d err=%v", len(first), err)
	}
	second, _ := NewSecret()
	if string(first) == string(second) {
		t.Fatal("two secrets are equal")
	}
	if encoded := EncodeSecret(first); len(encoded) != 32 || strings.ContainsAny(encoded, "=") {
		t.Fatalf("encoded secret %q", encoded)
	}
}

func TestKeyURIFollowsTheAuthenticatorFormat(t *testing.T) {
	uri := KeyURI("Acme App", "ana@example.com", rfc6238Secret)
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Path != "/Acme App:ana@example.com" {
		t.Fatalf("uri = %s", uri)
	}
	query := parsed.Query()
	if query.Get("secret") != EncodeSecret(rfc6238Secret) || query.Get("issuer") != "Acme App" ||
		query.Get("algorithm") != "SHA1" || query.Get("digits") != "6" || query.Get("period") != "30" {
		t.Fatalf("query = %v", query)
	}
}
