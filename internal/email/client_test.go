package email

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/token"
)

type capturedRequest struct {
	path    string
	authz   string
	message Message
}

func newStubProvisioning(t *testing.T, status int, captured *capturedRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		captured.authz = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&captured.message)
		w.WriteHeader(status)
	}))
}

const secretURL = "https://app.test/verify?token=s3cr3t"

func testMessage() Message {
	return Message{
		ProjectID: "proj_abc",
		To:        "alice@test.com",
		Template:  TemplateVerifyEmail,
		Data:      map[string]string{"verifyUrl": secretURL, "expiresHour": "24"},
	}
}

func TestSend_PostsToInternalEndpointWithServicePAT(t *testing.T) {
	var captured capturedRequest
	srv := newStubProvisioning(t, http.StatusAccepted, &captured)
	defer srv.Close()

	if err := NewClient(srv.URL, token.Literal("service-pat")).Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if captured.path != "/internal/email/send" {
		t.Errorf("path: got %q, want /internal/email/send", captured.path)
	}
	if captured.authz != "Bearer service-pat" {
		t.Errorf("authorization: got %q", captured.authz)
	}
	if captured.message.To != "alice@test.com" || captured.message.Template != TemplateVerifyEmail {
		t.Errorf("message not forwarded verbatim: %+v", captured.message)
	}
	if captured.message.ProjectID != "proj_abc" {
		t.Errorf("projectId: got %q", captured.message.ProjectID)
	}
	if captured.message.Data["verifyUrl"] != secretURL {
		t.Errorf("data not forwarded: %+v", captured.message.Data)
	}
}

func TestNewClient_TrimsPublicAPIBaseSoInternalRoutesResolve(t *testing.T) {
	var captured capturedRequest
	srv := newStubProvisioning(t, http.StatusAccepted, &captured)
	defer srv.Close()

	// PROVISIONING_URL points at the public API base; /internal/* is at the root.
	if err := NewClient(srv.URL+"/api", token.Literal("pat")).Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if captured.path != "/internal/email/send" {
		t.Errorf("path: got %q, want /internal/email/send", captured.path)
	}
}

func TestTemplateNamesMatchProvisioning(t *testing.T) {
	if TemplateVerifyEmail != "verify_email" {
		t.Errorf("TemplateVerifyEmail: got %q", TemplateVerifyEmail)
	}
	if TemplatePasswordReset != "password_reset" {
		t.Errorf("TemplatePasswordReset: got %q", TemplatePasswordReset)
	}
}

func TestSend_ErrorsOnNon2xxWithoutLeakingRecipientOrToken(t *testing.T) {
	var captured capturedRequest
	srv := newStubProvisioning(t, http.StatusInternalServerError, &captured)
	defer srv.Close()

	err := NewClient(srv.URL, token.Literal("service-pat")).Send(context.Background(), testMessage())
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	// The error text travels into logs, so it must carry neither recipient nor token.
	if strings.Contains(err.Error(), "alice@test.com") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error text leaks sensitive data: %v", err)
	}
}

func TestSend_ErrorsWhenProvisioningUnreachable(t *testing.T) {
	err := NewClient("http://127.0.0.1:1", token.Literal("service-pat")).Send(context.Background(), testMessage())
	if err == nil {
		t.Fatal("expected an error when provisioning is unreachable")
	}
	if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "alice@test.com") {
		t.Fatalf("error text leaks sensitive data: %v", err)
	}
}

func TestNoopSender_Succeeds(t *testing.T) {
	if err := (NoopSender{}).Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("NoopSender must never fail: %v", err)
	}
}

func TestClientAndNoopImplementSender(t *testing.T) {
	var _ Sender = NewClient("http://example.test", token.Literal("pat"))
	var _ Sender = NoopSender{}
}

// TestSend_UsesCurrentTokenFromSourceAfterRotation proves email delivery
// survives the weekly PROVISIONING_PAT_FILE rotation CronJob without an auth
// restart: the client must ask its token.Source for the current value on
// every Send, not capture one at construction time.
func TestSend_UsesCurrentTokenFromSourceAfterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(path, []byte("first-pat\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	var captured capturedRequest
	srv := newStubProvisioning(t, http.StatusAccepted, &captured)
	defer srv.Close()

	// interval 0: every Get re-checks the file, so the test never sleeps.
	client := NewClient(srv.URL, token.NewFileSource(path, "", token.WithInterval(0)))

	if err := client.Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if captured.authz != "Bearer first-pat" {
		t.Errorf("first send authorization: got %q, want %q", captured.authz, "Bearer first-pat")
	}

	if err := os.WriteFile(path, []byte("rotated-pat-value\n"), 0o600); err != nil {
		t.Fatalf("rotate token file: %v", err)
	}

	if err := client.Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("second send: %v", err)
	}
	if captured.authz != "Bearer rotated-pat-value" {
		t.Errorf("second send authorization: got %q, want %q", captured.authz, "Bearer rotated-pat-value")
	}
}

// TestSend_TokenSourceErrorFailsSendWithoutBearer proves that when the token
// source has nothing usable (file missing/empty/unreadable with no prior good
// value, or neither PROVISIONING_PAT nor PROVISIONING_PAT_FILE configured),
// Send fails explicitly instead of posting a request with an empty bearer
// token.
func TestSend_TokenSourceErrorFailsSendWithoutBearer(t *testing.T) {
	var captured capturedRequest
	srv := newStubProvisioning(t, http.StatusAccepted, &captured)
	defer srv.Close()

	client := NewClient(srv.URL, token.Literal(""))

	err := client.Send(context.Background(), testMessage())
	if err == nil {
		t.Fatal("expected an error when the token source has no token")
	}
	if !errors.Is(err, token.ErrNoToken) {
		t.Errorf("err: got %v, want wrapping token.ErrNoToken", err)
	}
	if captured.path != "" {
		t.Errorf("no request should have reached provisioning, got path %q authz %q", captured.path, captured.authz)
	}
}
