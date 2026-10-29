package hooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// testSecret is whsec_ + base64 of the 32 bytes "0123456789abcdef0123456789abcdef".
var testSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func TestSignature_IsStandardWebhooksV1(t *testing.T) {
	body := []byte(`{"type":"custom_access_token"}`)
	at := time.Unix(1700000000, 0)
	got, err := signature(testSecret, "msg_1", at, body)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	mac.Write([]byte("msg_1.1700000000." + string(body)))
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestSignature_RefusesAMalformedSecret(t *testing.T) {
	for _, secret := range []string{"", "whsec_", "secret", "whsec_!!!not-base64", "whsec_" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := signature(secret, "msg_1", time.Now(), nil); !errors.Is(err, ErrNoSecret) {
			t.Errorf("signature(%q) err = %v, want ErrNoSecret", secret, err)
		}
	}
}

func TestMessageID_IsFreshAndPrefixed(t *testing.T) {
	first, err := messageID()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := messageID()
	if !strings.HasPrefix(first, "msg_") || len(first) < 20 || first == second {
		t.Fatalf("ids %q and %q", first, second)
	}
}
