package pool

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
)

// stallingProxy forwards to a database until stall: from then on every open
// connection stays up but nothing crosses it, as when the pod behind a
// pooled connection is replaced. After resume only new connections forward.
type stallingProxy struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	stalled  bool
	links    []*atomic.Bool
	conns    []net.Conn
}

func startStallingProxy(t *testing.T, target string) *stallingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &stallingProxy{listener: listener, target: target}
	go proxy.serve()
	t.Cleanup(proxy.close)
	return proxy
}

func (p *stallingProxy) port() string {
	return strconv.Itoa(p.listener.Addr().(*net.TCPAddr).Port)
}

func (p *stallingProxy) serve() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		dead := &atomic.Bool{}
		p.mu.Lock()
		dead.Store(p.stalled)
		p.links = append(p.links, dead)
		p.conns = append(p.conns, client)
		p.mu.Unlock()
		if dead.Load() {
			go discard(client)
			continue
		}
		upstream, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, upstream)
		p.mu.Unlock()
		go pump(upstream, client, dead)
		go pump(client, upstream, dead)
	}
}

func pump(dst, src net.Conn, dead *atomic.Bool) {
	defer func() { _ = dst.Close(); _ = src.Close() }()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !dead.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func discard(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4<<10)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func (p *stallingProxy) stall() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stalled = true
	for _, dead := range p.links {
		dead.Store(true)
	}
}

func (p *stallingProxy) resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stalled = false
}

func (p *stallingProxy) close() {
	_ = p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		_ = conn.Close()
	}
}

// lookupWithin runs one auth read, failing the test if it outlives limit.
func lookupWithin(t *testing.T, db store.Store, limit time.Duration) (time.Duration, error) {
	t.Helper()
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := db.AccountByEmail(context.Background(), "nobody@example.com")
		done <- err
	}()
	select {
	case err := <-done:
		return time.Since(started), err
	case <-time.After(limit):
		t.Fatalf("the call hung for %s on a server that stopped answering", limit)
		return 0, nil
	}
}

// EXC-650: after an in-place restore or failover a pooled connection to the
// replaced server must fail the call in seconds, not hold the request until
// the edge answers 504, and the next call must reach the new server.
func TestIntegration_APostgresProjectFailsFastWhenTheServerStopsAnsweringThenReachesTheNewOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	host, port := startPostgres(t)
	proxy := startStallingProxy(t, net.JoinHostPort(host, port))
	record := credentialRecord{Host: "127.0.0.1", Port: proxy.port(), Database: "app", Username: "auth_admin", Password: "secret"}
	mgr := NewManager(vaultServing(t, record), token.Literal("pat"), time.Hour)
	mgr.SetSSLMode(sslModeDisable)
	mgr.SetMigrator(migrate.Run)
	db, err := mgr.GetStore(context.Background(), "org", "pg-project")
	if err != nil {
		t.Fatalf("GetStore: %v", err)
	}
	if _, err := lookupWithin(t, db, 30*time.Second); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("warm the pool: %v", err)
	}

	proxy.stall()
	elapsed, err := lookupWithin(t, db, 40*time.Second)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stalled server answered: %v", err)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("the call failed only after %s", elapsed)
	}

	proxy.resume()
	elapsed, err = lookupWithin(t, db, 40*time.Second)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the next call did not reach the server: %v", err)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("the next call took %s; stale connections were not evicted", elapsed)
	}
}
