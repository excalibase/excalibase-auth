// Package hooks calls a project's auth hooks (EXC-662): HTTPS POSTs signed in
// the Standard Webhooks format, sent only to public addresses, with a short
// deadline and a bounded answer. Every failure is ErrFailed, so callers fail
// closed, and no error names the target, the payload or the answer.
package hooks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/publicaddr"
)

const (
	// Timeout bounds one hook call, connect to last byte.
	Timeout = 2 * time.Second
	// MaxAnswerBytes bounds the answer read from a hook.
	MaxAnswerBytes = 64 << 10
	// MaxTargetLength bounds a hook URL.
	MaxTargetLength = 2048
	userAgent       = "excalibase-auth-hooks"
)

// ErrFailed is every hook failure; the sign-in that needed the hook fails closed.
var ErrFailed = errors.New("auth hook failed")

// Failure is a hook failure with a reason safe to log.
type Failure struct{ Reason string }

func (f *Failure) Error() string { return "auth hook failed: " + f.Reason }

// Is makes every Failure match ErrFailed.
func (f *Failure) Is(target error) bool { return target == ErrFailed }

func failed(reason string) error { return &Failure{Reason: reason} }

// ErrNoSecret means the project has no usable signing secret.
var ErrNoSecret error = &Failure{Reason: "no usable signing secret"}

// Options shape the production client.
type Options struct {
	// Deny adds ranges to the public-address guard, such as the platform's own edge.
	Deny []netip.Prefix
	// RootCAs verifies hook servers; nil is the system roots.
	RootCAs *x509.CertPool
}

// Client sends hook calls.
type Client struct {
	http    *http.Client
	timeout time.Duration
	// checkTarget refuses a URL before anything is sent.
	checkTarget func(string) error
}

// NewClient reaches hooks only through the public-address dialer, never
// through a proxy, and never follows a redirect.
func NewClient(options Options) *Client {
	dialer := publicaddr.NewDialer(nil, options.Deny)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
	}
	client := NewClientWith(&http.Client{Transport: transport})
	client.checkTarget = ValidateTarget
	return client
}

// NewClientWith wraps an HTTP client whose transport decides which addresses
// are reachable (tests); it still takes only https URLs and never redirects.
func NewClientWith(client *http.Client) *Client {
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	noRedirects.Timeout = 0
	return &Client{http: &noRedirects, timeout: Timeout, checkTarget: func(raw string) error {
		_, err := parseTarget(raw)
		return err
	}}
}

// Call POSTs payload signed with secret and decodes a 2xx answer into out;
// a nil out accepts any 2xx answer.
func (c *Client) Call(ctx context.Context, target, secret string, payload, out any) error {
	if err := c.checkTarget(target); err != nil {
		return failed("the hook URL is not an https URL on a public host")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return failed("the request could not be encoded")
	}
	req, err := c.signedRequest(ctx, target, secret, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return failed("the hook did not answer in time or could not be reached")
	}
	defer resp.Body.Close()
	return readAnswer(resp, out)
}

func (c *Client) signedRequest(ctx context.Context, target, secret string, body []byte) (*http.Request, error) {
	id, err := messageID()
	if err != nil {
		return nil, failed("no message id")
	}
	now := time.Now()
	signed, err := signature(secret, id, now, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, failed("the hook URL is not usable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("webhook-signature", signed)
	return req, nil
}

func readAnswer(resp *http.Response, out any) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return failed("the hook answered " + strconv.Itoa(resp.StatusCode))
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswerBytes+1))
	switch {
	case err != nil:
		return failed("the answer could not be read in time")
	case len(answer) > MaxAnswerBytes:
		return failed("the answer is over 64 KB")
	case out == nil:
		return nil
	case json.Unmarshal(answer, out) != nil:
		return failed("the answer is not the expected JSON")
	}
	return nil
}

// ValidateTarget accepts an https URL on one public host, with no user:password
// and no fragment. The dialer checks every resolved address again at connect.
func ValidateTarget(raw string) error {
	parsed, err := parseTarget(raw)
	if err != nil {
		return err
	}
	host := parsed.Hostname()
	if err := publicaddr.ValidateHostSyntax(host); err != nil {
		return err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return publicaddr.ClassifyAddr(addr)
	}
	return nil
}

func parseTarget(raw string) (*neturl.URL, error) {
	if raw == "" || len(raw) > MaxTargetLength || strings.Contains(raw, "#") {
		return nil, publicaddr.ErrInvalidHost
	}
	parsed, err := neturl.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.Hostname() == "" {
		return nil, publicaddr.ErrInvalidHost
	}
	return parsed, nil
}
