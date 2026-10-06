package cors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
)

// provisioningStub answers GET /projects/{id}/info like provisioning does and
// counts the calls it receives.
type provisioningStub struct {
	status int
	body   string
	calls  atomic.Int32
	path   atomic.Value
	bearer atomic.Value
}

func (s *provisioningStub) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.path.Store(r.URL.EscapedPath())
		s.bearer.Store(r.Header.Get("Authorization"))
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newProvider(url string, c *clock) *ProvisioningProvider {
	p := NewProvisioningProvider(url, token.Literal("svc-token"), 30*time.Second)
	p.now = c.Now
	return p
}

func TestResolveReadsTheProjectInfoAllowlist(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"projectId":"proj-1","corsAllowedOrigins":["https://shop.example.com","http://localhost:5173"]}`}
	srv := stub.serve(t)

	got, err := newProvider(srv.URL, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 2 || got[0] != "https://shop.example.com" || got[1] != "http://localhost:5173" {
		t.Errorf("origins = %v", got)
	}
	if p := stub.path.Load(); p != "/projects/proj-1/info" {
		t.Errorf("path = %v, want /projects/proj-1/info", p)
	}
	if b := stub.bearer.Load(); b != "Bearer svc-token" {
		t.Errorf("Authorization = %v", b)
	}
}

func TestResolveAMissingFieldIsNoOrigins(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"projectId":"proj-1"}`}
	srv := stub.serve(t)

	got, err := newProvider(srv.URL, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("origins = %v, want none", got)
	}
}

func TestResolveCachesWithinTheTTLAndRefetchesAfter(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"corsAllowedOrigins":["https://a.example.com"]}`}
	srv := stub.serve(t)
	c := &clock{now: time.Unix(1000, 0)}
	p := newProvider(srv.URL, c)

	for i := 0; i < 3; i++ {
		if _, err := p.Resolve(context.Background(), "proj-1"); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if n := stub.calls.Load(); n != 1 {
		t.Fatalf("calls within TTL = %d, want 1", n)
	}

	c.now = c.now.Add(31 * time.Second)
	if _, err := p.Resolve(context.Background(), "proj-1"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if n := stub.calls.Load(); n != 2 {
		t.Errorf("calls after TTL = %d, want 2", n)
	}
}

// An unknown project (404) or a provisioning outage with nothing cached is an
// error, never an empty list: the caller must refuse rather than guess.
func TestResolveFailsClosedWithNothingCached(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable, http.StatusForbidden} {
		stub := &provisioningStub{status: status, body: `{"error":"x"}`}
		srv := stub.serve(t)

		_, err := newProvider(srv.URL, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "proj-1")
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("status %d: err = %v, want ErrUnavailable", status, err)
		}
	}
}

func TestResolveFailsClosedWhenProvisioningIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	_, err := newProvider(url, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "proj-1")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

func TestResolveFailsClosedWithoutAToken(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"corsAllowedOrigins":["*"]}`}
	srv := stub.serve(t)
	p := NewProvisioningProvider(srv.URL, token.Literal(""), time.Minute)

	if _, err := p.Resolve(context.Background(), "proj-1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
	if n := stub.calls.Load(); n != 0 {
		t.Errorf("provisioning called %d times with no token", n)
	}
}

func TestResolveFailsClosedOnAMalformedBody(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"corsAllowedOrigins":"https://a.example.com"}`}
	srv := stub.serve(t)

	if _, err := newProvider(srv.URL, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "proj-1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
}

// Same contract as the engine: a failed refresh keeps serving the last list
// provisioning gave for that project.
func TestResolveServesTheLastGoodListWhenARefreshFails(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"corsAllowedOrigins":["https://a.example.com"]}`}
	srv := stub.serve(t)
	c := &clock{now: time.Unix(1000, 0)}
	p := newProvider(srv.URL, c)
	if _, err := p.Resolve(context.Background(), "proj-1"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	stub.status = http.StatusServiceUnavailable
	c.now = c.now.Add(time.Minute)
	got, err := p.Resolve(context.Background(), "proj-1")
	if err != nil || len(got) != 1 || got[0] != "https://a.example.com" {
		t.Errorf("got %v, %v; want the cached list", got, err)
	}
}

// The project id comes from the URL; it is escaped into one path segment so it
// cannot steer the lookup to another provisioning route.
func TestResolveEscapesTheProjectID(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{}`}
	srv := stub.serve(t)

	_, _ = newProvider(srv.URL, &clock{now: time.Unix(0, 0)}).Resolve(context.Background(), "../vault?x=1")
	if p := stub.path.Load(); p != "/projects/..%2Fvault%3Fx=1/info" {
		t.Errorf("path = %v", p)
	}
}

func TestResolveReturnsACopyCallersCannotMutate(t *testing.T) {
	stub := &provisioningStub{status: http.StatusOK, body: `{"corsAllowedOrigins":["https://a.example.com"]}`}
	srv := stub.serve(t)
	p := newProvider(srv.URL, &clock{now: time.Unix(0, 0)})

	first, _ := p.Resolve(context.Background(), "proj-1")
	first[0] = "https://evil.example.com"
	second, _ := p.Resolve(context.Background(), "proj-1")
	if second[0] != "https://a.example.com" {
		t.Errorf("cache was mutated through a returned slice: %v", second)
	}
}
