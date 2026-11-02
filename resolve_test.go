package portsscanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSNameWithMultipleIPs(t *testing.T) {
	res := &fakeResolver{table: map[string][]netip.Addr{
		"multi.test": addrs("10.0.0.2", "10.0.0.1", "::1", "10.0.0.1"),
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(res))
	got, err := sc.ScanAll(context.Background(), []string{"Multi.Test"}, Port(80))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(got), got)
	}
	sortResults(got)
	for i, want := range []string{"10.0.0.1", "10.0.0.2", "::1"} {
		if got[i].IP.String() != want || got[i].Host != "Multi.Test" {
			t.Errorf("result %d: %+v, want IP %s and Host as given", i, got[i], want)
		}
	}
	if res.hosts[0] != "multi.test" {
		t.Errorf("resolver got %q, want lowercase name", res.hosts[0])
	}
}

func TestUnresolvableNameDoesNotStopScan(t *testing.T) {
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(&fakeResolver{}))
	got, err := sc.ScanAll(context.Background(), []string{"10.0.0.1", "nope.test", "10.0.0.2"}, Ports(80, 81))
	if err != nil {
		t.Fatal(err)
	}
	var open, failed []Result
	for _, r := range got {
		if r.State == StateOpen {
			open = append(open, r)
		} else {
			failed = append(failed, r)
		}
	}
	if len(open) != 4 || len(failed) != 1 {
		t.Fatalf("open=%d failed=%d, want 4/1", len(open), len(failed))
	}
	f := failed[0]
	var dnsErr *net.DNSError
	if f.Host != "nope.test" || f.Port != 0 || f.IP != nil || f.State != StateError {
		t.Errorf("unexpected result: %+v", f)
	}
	if !errors.Is(f.Err, ErrResolve) || !errors.As(f.Err, &dnsErr) {
		t.Errorf("Err = %v, want ErrResolve wrapping *net.DNSError", f.Err)
	}
}

func TestNameWithoutAddressesIsResolveError(t *testing.T) {
	r := &fakeResolver{fn: func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r))
	got, err := sc.ScanAll(context.Background(), []string{"empty.test"}, Port(80))
	if err != nil || len(got) != 1 || !errors.Is(got[0].Err, ErrResolve) {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

func TestCancelDuringResolveEmitsNoResults(t *testing.T) {
	started := make(chan struct{})
	r := &fakeResolver{fn: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := sc.Scan(ctx, []string{"hang.test", "10.0.0.1"}, Port(80))
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	if got := drain(t, ch, 3*time.Second); len(got) != 0 {
		t.Fatalf("expected no results, got %+v", got)
	}
}

func TestResolveTimeout(t *testing.T) {
	r := &fakeResolver{fn: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r), WithResolveTimeout(30*time.Millisecond))
	start := time.Now()
	got, err := sc.ScanAll(context.Background(), []string{"slow.test", "10.0.0.1"}, Port(80))
	if err != nil {
		t.Fatal(err) // таймаут DNS — не отмена сканирования
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("resolve timeout was not applied")
	}
	var dnsFailed, open int
	for _, g := range got {
		if g.Host == "slow.test" && errors.Is(g.Err, ErrResolve) && errors.Is(g.Err, context.DeadlineExceeded) {
			dnsFailed++
		}
		if g.State == StateOpen {
			open++
		}
	}
	if dnsFailed != 1 || open != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestResolveConcurrencyLimit(t *testing.T) {
	for _, n := range []int{1, 4} {
		var cur, peak atomic.Int32
		r := &fakeResolver{fn: func(ctx context.Context, _, host string) ([]netip.Addr, error) {
			c := cur.Add(1)
			defer cur.Add(-1)
			for {
				p := peak.Load()
				if c <= p || peak.CompareAndSwap(p, c) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			return addrs("10.0.0.1"), nil
		}}
		sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r), WithResolveConcurrency(n))
		var hosts []string
		for i := 0; i < 12; i++ {
			hosts = append(hosts, fmt.Sprintf("h%d.test", i))
		}
		if _, err := sc.ScanAll(context.Background(), hosts, Port(80)); err != nil {
			t.Fatal(err)
		}
		got := int(peak.Load())
		if got > n || (n > 1 && got < 2) {
			t.Errorf("resolve concurrency %d: peak %d", n, got)
		}
	}
}

// A quick response from a second name must not overtake a slower response from the first:
// the shared address goes to the one that appears earlier in the list.
func TestResolveKeepsTargetOrderForDedup(t *testing.T) {
	r := &fakeResolver{fn: func(ctx context.Context, _, host string) ([]netip.Addr, error) {
		if host == "slow.test" {
			time.Sleep(50 * time.Millisecond)
		}
		return addrs("10.0.0.1"), nil
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r), WithResolveConcurrency(4))
	got, err := sc.ScanAll(context.Background(), []string{"slow.test", "fast.test"}, Port(80))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "slow.test" {
		t.Fatalf("got %+v, want one result for slow.test", got)
	}
}

func TestTrailingDotNameIsPassedToResolver(t *testing.T) {
	r := &fakeResolver{table: map[string][]netip.Addr{
		"example.org.": addrs("10.0.0.1"),
		"example.org":  addrs("10.0.0.2"),
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r))
	got, err := sc.ScanAll(context.Background(), []string{"Example.ORG.", "example.org"}, Port(80))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v, want 2 results", got)
	}
	seen := map[string]bool{}
	for _, h := range r.hosts {
		seen[h] = true
	}
	if !seen["example.org."] || !seen["example.org"] {
		t.Errorf("resolver got %v, want both with and without dot", r.hosts)
	}
}

func TestResolveCancelStopsEverything(t *testing.T) {
	started := make(chan struct{}, 8)
	r := &fakeResolver{fn: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	sc := mustNew(t, WithDialFunc((&fakeNet{}).dial), WithResolver(r), WithResolveConcurrency(4))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := sc.Scan(ctx, []string{"a.test", "b.test", "c.test", "d.test", "e.test"}, Port(80))
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	if got := drain(t, ch, 3*time.Second); len(got) != 0 {
		t.Fatalf("expected no results, got %+v", got)
	}
}
