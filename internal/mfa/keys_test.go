package mfa

import (
	"bytes"
	"strings"
	"testing"
)

func testKeys(t *testing.T, fill byte) Keys {
	t.Helper()
	keys, err := NewKeys(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestNewKeysRefusesAKeyOfTheWrongSize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := NewKeys(make([]byte, size)); err == nil {
			t.Errorf("a %d-byte key was accepted", size)
		}
	}
}

func TestSealedSecretOpensOnlyForItsAccountAndFactor(t *testing.T) {
	keys := testKeys(t, 7)
	sealed, err := keys.Seal(rfc6238Secret, 42, "factor-a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, rfc6238Secret) {
		t.Fatal("the secret is stored in the clear")
	}
	opened, err := keys.Open(sealed, 42, "factor-a")
	if err != nil || !bytes.Equal(opened, rfc6238Secret) {
		t.Fatalf("open = %q %v", opened, err)
	}
	if _, err := keys.Open(sealed, 43, "factor-a"); err == nil {
		t.Fatal("another account opened the secret")
	}
	if _, err := keys.Open(sealed, 42, "factor-b"); err == nil {
		t.Fatal("another factor opened the secret")
	}
	if _, err := testKeys(t, 8).Open(sealed, 42, "factor-a"); err == nil {
		t.Fatal("another project's key opened the secret")
	}
}

func TestSealUsesAFreshNonceEveryTime(t *testing.T) {
	keys := testKeys(t, 7)
	first, _ := keys.Seal(rfc6238Secret, 1, "f")
	second, _ := keys.Seal(rfc6238Secret, 1, "f")
	if bytes.Equal(first, second) {
		t.Fatal("two seals of one secret are equal")
	}
}

func TestOpenRefusesTamperedOrTruncatedOrUnknownVersion(t *testing.T) {
	keys := testKeys(t, 7)
	sealed, _ := keys.Seal(rfc6238Secret, 1, "f")
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	unknown := bytes.Clone(sealed)
	unknown[0] = 9
	for name, input := range map[string][]byte{"tampered": tampered, "truncated": sealed[:10], "empty": nil, "version": unknown} {
		if _, err := keys.Open(input, 1, "f"); err == nil {
			t.Errorf("%s secret opened", name)
		}
	}
}

func TestRecoveryCodesAreDistinctAndReadable(t *testing.T) {
	codes, err := NewRecoveryCodes(RecoveryCodeCount)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("codes=%v err=%v", codes, err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 11 || code[5] != '-' || strings.ContainsAny(code, "01lo") {
			t.Fatalf("code %q", code)
		}
		if seen[code] {
			t.Fatalf("code %q twice", code)
		}
		seen[code] = true
	}
}

func TestRecoveryCodeHashIsKeyedAndForgivesFormatting(t *testing.T) {
	keys := testKeys(t, 7)
	hash, ok := keys.HashRecoveryCode("abcde-fghij")
	if !ok || len(hash) != 64 {
		t.Fatalf("hash %q ok=%v", hash, ok)
	}
	for _, typed := range []string{"ABCDE-FGHIJ", " abcde fghij ", "abcdefghij"} {
		if again, ok := keys.HashRecoveryCode(typed); !ok || again != hash {
			t.Errorf("%q hashed differently", typed)
		}
	}
	if other, _ := testKeys(t, 8).HashRecoveryCode("abcde-fghij"); other == hash {
		t.Fatal("the hash does not depend on the project's key")
	}
	for _, malformed := range []string{"", "abcd", "abcde-fghijk", "abcde-fghi!"} {
		if _, ok := keys.HashRecoveryCode(malformed); ok {
			t.Errorf("%q accepted", malformed)
		}
	}
}
