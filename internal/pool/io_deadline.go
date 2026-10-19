package pool

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// ioTimeout bounds one read or write on a tenant connection, as for MySQL
// projects; every auth statement is a short keyed read or write.
const ioTimeout = 10 * time.Second

// pingTimeout bounds the liveness ping on acquire. Each stale idle
// connection costs one, so it is kept well under ioTimeout.
const pingTimeout = 2 * time.Second

// connectTimeout bounds dial, TLS and login together.
const connectTimeout = 10 * time.Second

// boundIO wraps every connection dial opens so a server that stops answering
// (its pod replaced by a restore or failover) fails the call instead of
// holding it until the edge answers 504 (EXC-650).
func boundIO(dial pgconn.DialFunc, timeout time.Duration) pgconn.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &deadlineConn{Conn: conn, timeout: timeout}, nil
	}
}

// deadlineConn arms a fresh deadline before each read and write. A deadline
// pgx sets itself (to interrupt a cancelled call) wins while it is sooner.
type deadlineConn struct {
	net.Conn
	timeout time.Duration

	mu         sync.Mutex
	readLimit  time.Time
	writeLimit time.Time
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if err := c.arm(&c.readLimit, c.Conn.SetReadDeadline); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if err := c.arm(&c.writeLimit, c.Conn.SetWriteDeadline); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// arm holds the lock while setting the deadline, so a concurrent cancel
// either is seen here or overrides what is set.
func (c *deadlineConn) arm(limit *time.Time, set func(time.Time) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := time.Now().Add(c.timeout)
	if !limit.IsZero() && limit.Before(deadline) {
		deadline = *limit
	}
	return set(deadline)
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readLimit, c.writeLimit = t, t
	return c.Conn.SetDeadline(t)
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readLimit = t
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeLimit = t
	return c.Conn.SetWriteDeadline(t)
}
