// Package email sends the transactional mail behind end-user email
// verification and password reset.
//
// The auth service deliberately carries no mail SDK of its own. Provisioning
// already owns provider selection (Resend / SES / noop) and the message
// templates, so auth posts a rendered-by-name request to provisioning's
// internal endpoint and lets the control plane do the delivery. That keeps one
// provider integration, one set of templates, and one place where mail
// credentials live.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/token"
)

// Template names. These must match the templates provisioning renders in
// internal/email/templates.go.
const (
	TemplateVerifyEmail   = "verify_email"
	TemplatePasswordReset = "password_reset"
)

// sendPath is provisioning's PAT-authenticated transport endpoint.
const sendPath = "/internal/email/send"

// Message is one transactional email, named by template rather than rendered
// here — the bodies live in provisioning.
type Message struct {
	ProjectID string            `json:"projectId"`
	To        string            `json:"to"`
	Template  string            `json:"template"`
	Data      map[string]string `json:"data,omitempty"`
}

// Sender delivers a Message. Implemented by Client in production and by
// NoopSender when no provisioning PAT is configured.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// NoopSender drops messages. Used so a misconfigured deployment degrades to
// "no mail" rather than to "registration is broken".
type NoopSender struct{}

func (NoopSender) Send(context.Context, Message) error { return nil }

// Client posts messages to provisioning's internal email endpoint.
type Client struct {
	baseURL    string
	tokens     token.Source
	httpClient *http.Client
}

// NewClient builds a client for provisioning's internal email endpoint.
// tokens is consulted on every Send, not just at construction, so a
// provisioning token rotated on disk (PROVISIONING_PAT_FILE) takes effect for
// outgoing mail without restarting auth.
//
// PROVISIONING_URL points at the public API base (".../api"), but provisioning
// mounts its service-to-service `/internal/*` routes at the service root, so
// the trailing "/api" is trimmed here rather than pushed onto every caller.
func NewClient(provisioningURL string, tokens token.Source) *Client {
	base := strings.TrimRight(provisioningURL, "/")
	base = strings.TrimSuffix(base, "/api")
	return &Client{
		baseURL:    base,
		tokens:     tokens,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Send delivers msg via provisioning. Errors are deliberately terse: they end
// up in logs, so they name the template and status but never the recipient
// address or the link (which embeds a single-use secret).
func (c *Client) Send(ctx context.Context, msg Message) error {
	// Resolved before building the request so a missing/unreadable token never
	// reaches provisioning as an empty bearer token.
	tok, err := c.tokens.Get()
	if err != nil {
		return fmt.Errorf("send %s: provisioning token: %w", msg.Template, err)
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode %s message", msg.Template)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+sendPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request", msg.Template)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send %s: provisioning unreachable", msg.Template)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("send %s: provisioning returned %d", msg.Template, resp.StatusCode)
	}
	return nil
}
