package portsscanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrInvalidOption — an invalid option value in New.
var ErrInvalidOption = errors.New("portscan: invalid option")

// DialFunc establishes a connection; its signature is the same as that of net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialFunc establishes a connection; its signature is the same as that of net.Dialer.DialContext.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type config struct {
	concurrency    int
	connectTimeout time.Duration
	resolveTimeout time.Duration
	resolveWorkers int
	resolver       Resolver
	dial           DialFunc
}

// Option configures the Scanner.
type Option func(*config) error

// WithConcurrency sets the maximum number of concurrent connections for the entire Scanner—
// // that is, the total across all simultaneous Scan calls (default is 100).
// // Keep in mind the OS file descriptor limit (ulimit -n); if this limit is reached,
// // some checks will return a StateError.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n <= 0 {
			return fmt.Errorf("%w: concurrency must be > 0, got %d", ErrInvalidOption, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout for a single connection (default is 1s).
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be > 0, got %v", ErrInvalidOption, d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolveTimeout sets the timeout for resolving a single DNS name (default is 5s).
func WithResolveTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: resolve timeout must be > 0, got %v", ErrInvalidOption, d)
		}
		c.resolveTimeout = d
		return nil
	}
}

// WithResolveConcurrency sets how many DNS names within a single Scan can be
// resolved concurrently (defaults to 8). The order in which targets are processed is unaffected by this.
func WithResolveConcurrency(n int) Option {
	return func(c *config) error {
		if n <= 0 {
			return fmt.Errorf("%w: resolve concurrency must be > 0, got %d", ErrInvalidOption, n)
		}
		c.resolveWorkers = n
		return nil
	}
}

// WithResolver replaces the DNS resolver (primarily for testing purposes).
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return fmt.Errorf("%w: nil resolver", ErrInvalidOption)
		}
		c.resolver = r
		return nil
	}
}

// WithDialFunc replaces the connection function (for proxies, tests).
func WithDialFunc(d DialFunc) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: nil dial func", ErrInvalidOption)
		}
		c.dial = d
		return nil
	}
}
