package publicaddr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Resolver is the lookup the Dialer uses; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

const defaultDialTimeout = 10 * time.Second

// Dialer connects only to public addresses. Each connect resolves the name,
// refuses it when ANY answer is internal, then dials the checked address
// itself, so a name that rebinds between check and connect gains nothing.
// The socket's peer is checked once more as it connects.
type Dialer struct {
	resolver Resolver
	deny     []netip.Prefix
	timeout  time.Duration
	// dialAddress connects to an already checked IP:port; tests replace it.
	dialAddress func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDialer refuses ClassifyAddr's ranges plus deny (an install's cluster
// ranges). A nil resolver is the system one.
func NewDialer(resolver Resolver, deny []netip.Prefix) *Dialer {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	d := &Dialer{resolver: resolver, deny: append([]netip.Prefix(nil), deny...), timeout: defaultDialTimeout}
	socket := &net.Dialer{Timeout: d.timeout, Control: d.control}
	d.dialAddress = socket.DialContext
	return d
}

// Check refuses an address the platform must not dial on a tenant's behalf.
func (d *Dialer) Check(addr netip.Addr) error {
	if err := ClassifyAddr(addr); err != nil {
		return err
	}
	candidates := []netip.Addr{addr.Unmap()}
	if embedded, ok := embeddedIPv4(addr.Unmap()); ok {
		candidates = append(candidates, embedded)
	}
	for _, prefix := range d.deny {
		for _, candidate := range candidates {
			if prefix.Contains(candidate) {
				return ErrInternalAddress
			}
		}
	}
	return nil
}

// DialContext is an http.Transport DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", ErrInvalidHost)
	}
	targets, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, target := range targets {
		conn, err := d.dialAddress(ctx, network, net.JoinHostPort(target.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// resolve answers the addresses to dial, all of them checked.
func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		if err := d.Check(literal); err != nil {
			return nil, err
		}
		return []netip.Addr{literal}, nil
	}
	found, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %w", errLookup)
	}
	if len(found) == 0 {
		return nil, errLookup
	}
	for _, addr := range found {
		if err := d.Check(addr); err != nil {
			return nil, err
		}
	}
	return found, nil
}

var errLookup = errors.New("the destination's name did not resolve")

// control re-checks the peer the socket is about to connect to.
func (d *Dialer) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrInternalAddress
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ErrInternalAddress
	}
	return d.Check(addr)
}
