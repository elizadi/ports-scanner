package portsscanner

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// trackedConn counts calls to Close.
type trackedConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c trackedConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

// akeNet — a simulated network: tracks calls, peak concurrency, and
// // open/closed connections.
type fakeNet struct {
	mu     sync.Mutex
	calls  int
	cur    int
	max    int
	opened atomic.Int32
	closed atomic.Int32
	addrs  []netip.AddrPort

	// behave determines the outcome of the connection; nil always signifies success.
	behave func(ctx context.Context, ap netip.AddrPort) (net.Conn, error)
}

func (f *fakeNet) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	ap := netip.MustParseAddrPort(address)
	f.mu.Lock()
	f.calls++
	f.cur++
	f.max = max(f.max, f.cur)
	f.addrs = append(f.addrs, ap)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.cur--
		f.mu.Unlock()
	}()
	if f.behave == nil {
		return f.open()
	}
	return f.behave(ctx, ap)
}

// `open` returns an "established" connection, taking counters into account.
func (f *fakeNet) open() (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	f.opened.Add(1)
	return trackedConn{Conn: a, closed: &f.closed}, nil
}

func (f *fakeNet) snapshot() (calls, cur, peak int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.cur, f.max
}

func blockUntilDone(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// fakeResolver — a swappable DNS.
type fakeResolver struct {
	mu       sync.Mutex
	networks []string
	hosts    []string
	table    map[string][]netip.Addr
	fn       func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.networks = append(r.networks, network)
	r.hosts = append(r.hosts, host)
	r.mu.Unlock()
	if r.fn != nil {
		return r.fn(ctx, network, host)
	}
	addrs, ok := r.table[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range addrs {
		switch network {
		case "ip4":
			if !a.Is4() {
				continue
			}
		case "ip6":
			if !a.Is6() {
				continue
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func mustNew(t *testing.T, opts ...Option) *Scanner {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// `drain` reads from the channel until it closes; if it hasn’t closed within duration `d`, the test fails.
func drain(t *testing.T, ch <-chan Result, d time.Duration) []Result {
	t.Helper()
	var out []Result
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, r)
		case <-timer.C:
			t.Fatalf("results channel not closed within %v (got %d results)", d, len(out))
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func sortResults(rs []Result) {
	slices.SortFunc(rs, func(a, b Result) int {
		if c := a.IP.String(); c != b.IP.String() {
			if c < b.IP.String() {
				return -1
			}
			return 1
		}
		return int(a.Port) - int(b.Port)
	})
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}
