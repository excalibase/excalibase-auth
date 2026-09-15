package email

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	if err := NewClient(srv.URL, "service-pat").Send(context.Background(), testMessage()); err != nil {
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
	if err := NewClient(srv.URL+"/api", "pat").Send(context.Background(), testMessage()); err != nil {
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

	err := NewClient(srv.URL, "service-pat").Send(context.Background(), testMessage())
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	// The error text travels into logs, so it must carry neither recipient nor token.
	if strings.Contains(err.Error(), "alice@test.com") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error text leaks sensitive data: %v", err)
	}
}

func TestSend_ErrorsWhenProvisioningUnreachable(t *testing.T) {
	err := NewClient("http://127.0.0.1:1", "service-pat").Send(context.Background(), testMessage())
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
	var _ Sender = NewClient("http://example.test", "pat")
	var _ Sender = NoopSender{}
}
