package emailotp

import (
	"strings"
	"testing"
)

func TestNewCodeIsEightDigitsAndVaries(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		code, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if CodeLength != 8 || len(code) != CodeLength || strings.Trim(code, "0123456789") != "" {
			t.Fatalf("code %q is not %d digits", code, CodeLength)
		}
		seen[code] = true
	}
	if len(seen) < 45 {
		t.Fatalf("only %d distinct codes in 50", len(seen))
	}
}

func TestCodeMACBindsTheKeyProjectAddressAndCode(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	mac := CodeMAC(key, "p1", "Ann@Example.com", "123456")
	if len(mac) != 64 || strings.Contains(mac, "123456") {
		t.Fatalf("mac = %q", mac)
	}
	if !CodeMatches(key, "p1", "ann@example.com", "123456", mac) {
		t.Fatal("the address's case changed the code")
	}
	for name, ok := range map[string]bool{
		"other code":    CodeMatches(key, "p1", "ann@example.com", "123457", mac),
		"other project": CodeMatches(key, "p2", "ann@example.com", "123456", mac),
		"other address": CodeMatches(key, "p1", "bob@example.com", "123456", mac),
		"other key":     CodeMatches([]byte("another key of thirty-two bytes!"), "p1", "ann@example.com", "123456", mac),
		"empty stored":  CodeMatches(key, "p1", "ann@example.com", "123456", ""),
	} {
		if ok {
			t.Errorf("%s matched", name)
		}
	}
}
