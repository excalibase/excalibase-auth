package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/token"
)

// errVaultSealed is provisioning's answer while its vault waits for an admin.
var errVaultSealed = errors.New("vault is sealed")

const (
	sealedRetryFirst = 2 * time.Second
	sealedRetryMax   = 15 * time.Second
)

// waitForSigningKey fetches the JWT signing key, waiting as long as the vault
// is sealed: with manual unseal (EXC-579) a sealed vault is the normal state
// after a platform restart. Auth stays unready and logs why; any other
// failure still stops the start.
func waitForSigningKey(provisioningURL string, tokens token.Source, sleep func(time.Duration),
	logf func(string, ...interface{})) (string, error) {
	delay := sealedRetryFirst
	for {
		key, err := fetchSigningKey(provisioningURL, tokens)
		if !errors.Is(err, errVaultSealed) {
			return key, err
		}
		logf("the vault is sealed: waiting for a platform admin to unseal it (Studio /setup, or `excalibase-provisioning vault unseal` in the provisioning container); retrying in %s", delay)
		sleep(delay)
		delay = min(delay*2, sealedRetryMax)
	}
}

func fetchSigningKey(provisioningURL string, tokens token.Source) (string, error) {
	url := provisioningURL + "/vault/secrets/pki/signing/private"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	tok, err := tokens.Get()
	if err != nil {
		return "", fmt.Errorf("provisioning token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if strings.Contains(string(body), errVaultSealed.Error()) {
			return "", errVaultSealed
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}

	key, ok := data["key"]
	if !ok || key == "" {
		return "", fmt.Errorf("signing key not found in vault response")
	}
	return key, nil
}
