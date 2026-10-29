package hooks

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type echoAnswer struct {
	Seen string `json:"seen"`
}

// receiver checks the signature the way a customer's endpoint would.
func receiver(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, body []byte)) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		answer(w, r, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testClient(srv *httptest.Server) *Client {
	return NewClientWith(srv.Client())
}

func TestCall_SignsTheBodyAndDecodesTheAnswer(t *testing.T) {
	srv := receiver(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		id, stamp := r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp")
		sent, err := strconv.ParseInt(stamp, 10, 64)
		if err != nil || time.Since(time.Unix(sent, 0)).Abs() > time.Minute {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		want, _ := signature(testSecret, id, time.Unix(sent, 0), body)
		if r.Header.Get("webhook-signature") != want || r.Header.Get("Content-Type") != "application/json" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(echoAnswer{Seen: string(body)})
	})
	var answer echoAnswer
	if err := testClient(srv).Call(context.Background(), srv.URL+"/hook", testSecret, map[string]string{"type": "x"}, &answer); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if answer.Seen != `{"type":"x"}` {
		t.Fatalf("answer = %+v", answer)
	}
}

func TestCall_FailsOnEveryBadAnswer(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request, body []byte){
		"server error": func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusInternalServerError) },
		"not json":     func(w http.ResponseWriter, _ *http.Request, _ []byte) { _, _ = w.Write([]byte("<html>")) },
		"too large": func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			_, _ = w.Write([]byte(`{"seen":"` + strings.Repeat("a", MaxAnswerBytes) + `"}`))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request, _ []byte) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			var followed atomic.Bool
			srv := receiver(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
				if r.URL.Path == "/elsewhere" {
					followed.Store(true)
				}
				answer(w, r, body)
			})
			var out echoAnswer
			err := testClient(srv).Call(context.Background(), srv.URL+"/hook", testSecret, map[string]string{}, &out)
			if !errors.Is(err, ErrFailed) {
				t.Fatalf("err = %v, want ErrFailed", err)
			}
			if followed.Load() {
				t.Fatal("the client followed a redirect")
			}
			if strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("the error names the target: %v", err)
			}
		})
	}
}

func TestCall_ANoContentAnswerIsAcceptedWhenNothingIsExpected(t *testing.T) {
	srv := receiver(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusNoContent) })
	if err := testClient(srv).Call(context.Background(), srv.URL, testSecret, map[string]string{}, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
}

func TestCall_ASlowHookTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := receiver(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	client := testClient(srv)
	client.timeout = 100 * time.Millisecond
	started := time.Now()
	err := client.Call(context.Background(), srv.URL, testSecret, map[string]string{}, nil)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v, want ErrFailed", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("the call took %v", time.Since(started))
	}
}

func TestCall_RefusesATargetBeforeSending(t *testing.T) {
	var reached atomic.Bool
	srv := receiver(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { reached.Store(true) })
	err := testClient(srv).Call(context.Background(), strings.Replace(srv.URL, "https://", "http://", 1), testSecret, map[string]string{}, nil)
	if !errors.Is(err, ErrFailed) || reached.Load() {
		t.Fatalf("err = %v, reached = %v", err, reached.Load())
	}
	if err := testClient(srv).Call(context.Background(), srv.URL, "not-a-secret", map[string]string{}, nil); !errors.Is(err, ErrNoSecret) || reached.Load() {
		t.Fatalf("bad secret: err = %v, reached = %v", err, reached.Load())
	}
}

// The production client dials only public addresses, so a hook pointed at the
// platform's own network is refused at connect time, even with a trusted certificate.
func TestNewClient_RefusesInternalAddresses(t *testing.T) {
	var reached atomic.Bool
	srv := receiver(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { reached.Store(true) })
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	client := NewClient(Options{RootCAs: roots})
	err := client.Call(context.Background(), srv.URL, testSecret, map[string]string{}, nil)
	if !errors.Is(err, ErrFailed) || reached.Load() {
		t.Fatalf("err = %v, reached = %v", err, reached.Load())
	}
}

func TestNewClient_RefusesTheExtraDeniedRanges(t *testing.T) {
	client := NewClient(Options{Deny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	err := client.Call(context.Background(), "https://203.0.113.9/hook", testSecret, map[string]string{}, nil)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v, want ErrFailed", err)
	}
}

func TestValidateTarget(t *testing.T) {
	good := []string{"https://hooks.example.com/auth", "https://hooks.example.com:443/a?b=c", "https://203.0.113.10/hook"}
	for _, raw := range good {
		if err := ValidateTarget(raw); err != nil {
			t.Errorf("ValidateTarget(%q) = %v", raw, err)
		}
	}
	bad := []string{
		"", "http://hooks.example.com/", "ftp://hooks.example.com/", "https://", "https:///path",
		"https://user:pass@hooks.example.com/", "https://hooks.example.com/#frag",
		"https://localhost/", "https://db.internal/", "https://10.0.0.5/", "https://169.254.169.254/latest",
		"https://[::1]/", "https://[fd00:ec2::254]/", "https://nohost/", "https://hooks.example.com:8443/", "https://hooks.example.com:6443/", "https://127.1/", "https://0x7f000001/", "https://hooks.example.com%00.evil.com/",
		"https://hooks.example.com/" + strings.Repeat("a", 2048),
	}
	for _, raw := range bad {
		if err := ValidateTarget(raw); err == nil {
			t.Errorf("ValidateTarget(%q) accepted", raw)
		}
	}
}
