package hooks

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const (
	secretPrefix = "whsec_"
	// minSecretBytes refuses a key too short to sign with; provisioning makes 32.
	minSecretBytes = 24
)

// signature is the Standard Webhooks v1 signature of one message:
// base64(HMAC-SHA256(key, id + "." + timestamp + "." + body)).
func signature(secret, id string, at time.Time, body []byte) (string, error) {
	key, err := secretKey(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(at.Unix(), 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func secretKey(secret string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(secret, secretPrefix)
	if !ok {
		return nil, ErrNoSecret
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) < minSecretBytes {
		return nil, ErrNoSecret
	}
	return key, nil
}

// messageID is a fresh webhook-id, so a receiver can refuse a replay.
func messageID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(raw), nil
}
