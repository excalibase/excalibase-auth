package publicaddr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

// fakeResolver answers each lookup of a host with the next queued answer, so a
// test can play a DNS server that rebinds between lookups.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	lookups int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	queue := f.answers[host]
	if len(queue) == 0 {
		return nil, errors.New("no such host")
	}
	answer := queue[0]
	if len(queue) > 1 {
		f.answers[host] = queue[1:]
	}
	return answer, nil
}

func addrs(raw ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(raw))
	for _, value := range raw {
		out = append(out, netip.MustParseAddr(value))
	}
	return out
}

// recordingDialer stands in for the socket dial and remembers what was dialled.
type recordingDialer struct {
	mu     sync.Mutex
	dialed []string
}

func (r *recordingDialer) dial(_ context.Context, _, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, address)
	r.mu.Unlock()
	client, server := net.Pipe()
	go server.Close()
	return client, nil
}

func newTestDialer(resolver Resolver, deny ...netip.Prefix) (*Dialer, *recordingDialer) {
	recorder := &recordingDialer{}
	dialer := NewDialer(resolver, deny)
	dialer.dialAddress = recorder.dial
	return dialer, recorder
}

func TestDialer_DialsTheCheckedAddressNotTheName(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][][]netip.Addr{"logs.example.com": {addrs("203.0.113.10")}}}
	dialer, recorder := newTestDialer(resolver)
	conn, err := dialer.DialContext(context.Background(), "tcp", "logs.example.com:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if len(recorder.dialed) != 1 || recorder.dialed[0] != "203.0.113.10:443" {
		t.Errorf("dialed %v, want the resolved address only", recorder.dialed)
	}
}

// A name that answers public once and internal next is refused the second
// time: every connect resolves and checks again, and dials what it checked.
func TestDialer_RefusesDNSRebinding(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][][]netip.Addr{
		"rebind.example.com": {addrs("203.0.113.10"), addrs("127.0.0.1")},
	}}
	dialer, recorder := newTestDialer(resolver)
	conn, err := dialer.DialContext(context.Background(), "tcp", "rebind.example.com:443")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()
	_, err = dialer.DialContext(context.Background(), "tcp", "rebind.example.com:443")
	if !errors.Is(err, ErrInternalAddress) {
		t.Fatalf("second dial err = %v, want ErrInternalAddress", err)
	}
	if len(recorder.dialed) != 1 {
		t.Errorf("dialed %v: the rebound address must never be dialled", recorder.dialed)
	}
}

func TestDialer_RefusesWhenAnyResolvedAddressIsInternal(t *testing.T) {
	cases := map[string][]netip.Addr{
		"private second":  addrs("203.0.113.10", "10.0.0.7"),
		"metadata v4":     addrs("169.254.169.254"),
		"metadata v6":     addrs("2001:db8::1", "fd00:ec2::254"),
		"cgnat":           addrs("100.64.1.1"),
		"loopback v6":     addrs("::1"),
		"mapped loopback": addrs("::ffff:127.0.0.1"),
		"multicast":       addrs("224.0.0.1"),
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			resolver := &fakeResolver{answers: map[string][][]netip.Addr{"mixed.example.com": {answer}}}
			dialer, recorder := newTestDialer(resolver)
			_, err := dialer.DialContext(context.Background(), "tcp", "mixed.example.com:443")
			if !errors.Is(err, ErrInternalAddress) {
				t.Fatalf("err = %v, want ErrInternalAddress", err)
			}
			if len(recorder.dialed) != 0 {
				t.Errorf("dialed %v", recorder.dialed)
			}
		})
	}
}

// Cluster pod and service ranges an install names are refused like private ones.
func TestDialer_RefusesExtraDeniedRanges(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][][]netip.Addr{"svc.example.com": {addrs("198.51.100.20")}}}
	dialer, _ := newTestDialer(resolver, netip.MustParsePrefix("198.51.100.0/24"))
	if _, err := dialer.DialContext(context.Background(), "tcp", "svc.example.com:443"); !errors.Is(err, ErrInternalAddress) {
		t.Fatalf("err = %v, want ErrInternalAddress", err)
	}
}

// A denied range is refused however the address is wrapped in IPv6.
func TestDialer_ExtraDeniedRangesCoverEmbeddedIPv4(t *testing.T) {
	dialer := NewDialer(nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	for _, raw := range []string{"::ffff:198.51.100.7", "64:ff9b::c633:6407", "2002:c633:6407::1"} {
		if err := dialer.Check(netip.MustParseAddr(raw)); !errors.Is(err, ErrInternalAddress) {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestDialer_IPLiteralIsCheckedWithoutLookup(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][][]netip.Addr{}}
	dialer, recorder := newTestDialer(resolver)
	if _, err := dialer.DialContext(context.Background(), "tcp", "10.0.0.1:443"); !errors.Is(err, ErrInternalAddress) {
		t.Fatalf("err = %v, want ErrInternalAddress", err)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "[fd00:ec2::254]:443"); !errors.Is(err, ErrInternalAddress) {
		t.Fatalf("err = %v, want ErrInternalAddress", err)
	}
	if resolver.lookups != 0 || len(recorder.dialed) != 0 {
		t.Errorf("lookups %d, dialed %v", resolver.lookups, recorder.dialed)
	}
}

func TestDialer_LookupFailureIsAnError(t *testing.T) {
	dialer, recorder := newTestDialer(&fakeResolver{answers: map[string][][]netip.Addr{}})
	if _, err := dialer.DialContext(context.Background(), "tcp", "nowhere.example.com:443"); err == nil {
		t.Fatal("want an error for a name that does not resolve")
	}
	if len(recorder.dialed) != 0 {
		t.Errorf("dialed %v", recorder.dialed)
	}
}

// The socket-level check refuses what a resolver bypass would hand it.
func TestDialer_ControlRefusesInternalPeer(t *testing.T) {
	dialer := NewDialer(nil, nil)
	if err := dialer.control("tcp", "127.0.0.1:443", nil); !errors.Is(err, ErrInternalAddress) {
		t.Errorf("loopback: %v", err)
	}
	if err := dialer.control("tcp", "not-an-address", nil); !errors.Is(err, ErrInternalAddress) {
		t.Errorf("garbage: %v", err)
	}
	if err := dialer.control("tcp", "203.0.113.10:443", nil); err != nil {
		t.Errorf("public: %v", err)
	}
}

// End to end through a real socket: a TLS server on loopback is never reached.
func TestDialer_RealClientCannotReachLoopbackServer(t *testing.T) {
	reached := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer server.Close()
	dialer := NewDialer(nil, nil)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("want the loopback server refused")
	}
	if !errors.Is(err, ErrInternalAddress) || reached {
		t.Errorf("err = %v, reached = %v", err, reached)
	}
}
