package pool

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func pipeDial(t *testing.T) (dial func(context.Context, string, string) (net.Conn, error), peer func() net.Conn) {
	t.Helper()
	var server net.Conn
	return func(context.Context, string, string) (net.Conn, error) {
			client, other := net.Pipe()
			server = other
			t.Cleanup(func() { _ = client.Close(); _ = other.Close() })
			return client, nil
		}, func() net.Conn {
			return server
		}
}

func TestBoundIOFailsAReadOnASilentServer(t *testing.T) {
	dial, _ := pipeDial(t)
	conn, err := boundIO(dial, 50*time.Millisecond)(context.Background(), "tcp", "db:5432")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = conn.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read on a silent server: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("read failed only after %s", elapsed)
	}
}

func TestBoundIOFailsAWriteNobodyReads(t *testing.T) {
	dial, _ := pipeDial(t)
	conn, _ := boundIO(dial, 50*time.Millisecond)(context.Background(), "tcp", "db:5432")
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write nobody reads: %v", err)
	}
}

func TestBoundIOPassesDataThrough(t *testing.T) {
	dial, peer := pipeDial(t)
	conn, _ := boundIO(dial, time.Second)(context.Background(), "tcp", "db:5432")
	go func() { _, _ = peer().Write([]byte("ok")) }()
	buf := make([]byte, 2)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
}

// pgx cancels a call by setting a deadline in the past; the bound must not
// push it back out.
func TestBoundIOKeepsASoonerDeadlineTheCallerSet(t *testing.T) {
	dial, _ := pipeDial(t)
	conn, _ := boundIO(dial, time.Hour)(context.Background(), "tcp", "db:5432")
	for name, set := range map[string]func(time.Time) error{
		"SetDeadline": conn.SetDeadline, "SetReadDeadline": conn.SetReadDeadline,
	} {
		_ = set(time.Now())
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s in the past: read got %v", name, err)
		}
		_ = conn.SetDeadline(time.Time{})
	}
	_ = conn.SetWriteDeadline(time.Now())
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("SetWriteDeadline in the past: write got %v", err)
	}
}

func TestBoundIOReturnsTheDialError(t *testing.T) {
	refused := errors.New("refused")
	_, err := boundIO(func(context.Context, string, string) (net.Conn, error) { return nil, refused }, time.Second)(context.Background(), "tcp", "db:5432")
	if !errors.Is(err, refused) {
		t.Fatalf("dial error: %v", err)
	}
}

func TestTenantPoolConfigBoundsConnectAndIO(t *testing.T) {
	config, err := tenantPoolConfig(credentialRecord{Host: "db", Port: "5432", Database: "app", Username: "u", Password: "p"}, sslModeDisable)
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.ConnectTimeout != connectTimeout {
		t.Fatalf("connect timeout = %s", config.ConnConfig.ConnectTimeout)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := config.ConnConfig.DialFunc(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if bounded, ok := conn.(*deadlineConn); !ok || bounded.timeout != ioTimeout {
		t.Fatalf("tenant connections are not bounded: %T", conn)
	}
}

func TestDefaultPoolCreatorBoundsTheLivenessPing(t *testing.T) {
	config, err := tenantPoolConfig(credentialRecord{Host: "127.0.0.1", Port: "1", Database: "app", Username: "u", Password: "p"}, sslModeDisable)
	if err != nil {
		t.Fatal(err)
	}
	created, err := defaultPoolCreator(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	if got := created.Config().PingTimeout; got != pingTimeout {
		t.Fatalf("ping timeout = %s", got)
	}
}
