package portsscanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

// `listen` sets up a listening socket that accepts connections and immediately closes them.
func listen(t *testing.T, addr string) (port int) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// freePort returns a port on which (most likely) no one is listening.
func freePort(t *testing.T, addr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func TestScanRealLoopback(t *testing.T) {
	for _, tc := range []struct{ name, host, bind string }{
		{"ipv4", "127.0.0.1", "127.0.0.1:0"},
		{"ipv6", "::1", "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			open := listen(t, tc.bind)
			closed := freePort(t, tc.bind)

			// Time margin: on Windows, a connection refusal on the loopback interface
			// sometimes does not arrive instantaneously.
			sc := mustNew(t, WithConnectTimeout(5*time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res, err := sc.ScanAll(ctx, []string{tc.host}, Ports(open, closed))
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 2 {
				t.Fatalf("got %d results: %+v", len(res), res)
			}
			sortResults(res)
			byPort := map[int]Result{}
			for _, r := range res {
				byPort[int(r.Port)] = r
			}
			if r := byPort[open]; r.State != StateOpen || r.Err != nil || r.Host != tc.host || !r.IP.Equal(net.ParseIP(tc.host)) {
				t.Errorf("open port result: %+v", r)
			}
			r := byPort[closed]
			if r.State != StateClosed {
				t.Errorf("closed port state = %v (err=%v), want closed", r.State, r.Err)
			}
			// Duration can be 0: on Windows, the system clock resolution
			// is coarser than the time it takes for an immediate failure on a loopback interface.
			if r.Err == nil || r.Duration < 0 {
				t.Errorf("closed result should carry Err and a non-negative Duration: %+v", r)
			}
		})
	}
}

func TestStatesViaFakeDial(t *testing.T) {
	fn := &fakeNet{behave: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		switch ap.Port() {
		case 1:
			return (&fakeNet{}).open()
		case 2:
			return blockUntilDone(ctx, ap)
		default:
			return nil, errors.New("boom")
		}
	}}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConnectTimeout(40*time.Millisecond))
	res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1"}, Range(1, 3))
	if err != nil {
		t.Fatal(err)
	}
	sortResults(res)
	want := []State{StateOpen, StateTimeout, StateError}
	if len(res) != 3 {
		t.Fatalf("results: %+v", res)
	}
	for i, r := range res {
		if r.State != want[i] {
			t.Errorf("port %d: state %v, want %v (err=%v)", r.Port, r.State, want[i], r.Err)
		}
	}
	if !errors.Is(res[1].Err, context.DeadlineExceeded) {
		t.Errorf("timeout Err = %v, want DeadlineExceeded", res[1].Err)
	}
	// The threshold is set below the actual timeout (40ms), allowing a margin for the low precision of Windows system clocks.
	if res[1].Duration < 20*time.Millisecond {
		t.Errorf("timeout Duration = %v, want >= ~40ms", res[1].Duration)
	}
	if res[0].Err != nil {
		t.Errorf("open result has Err: %v", res[0].Err)
	}
}

func TestOpenConnectionsAreClosed(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(8))
	res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, Range(1, 200))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 400 {
		t.Fatalf("got %d results", len(res))
	}
	if o, c := fn.opened.Load(), fn.closed.Load(); o != 400 || c != o {
		t.Fatalf("opened=%d closed=%d, want 400/400", o, c)
	}
}

func TestConcurrencyLimitIsRespected(t *testing.T) {
	const limit = 5
	fn := &fakeNet{behave: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		select {
		case <-time.After(2 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&fakeNet{}).open()
	}}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(limit))
	res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, Range(1, 150))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 300 {
		t.Fatalf("got %d results, want 300", len(res))
	}
	if _, _, peak := fn.snapshot(); peak > limit || peak < 2 {
		t.Fatalf("peak concurrent dials = %d, want 2..%d", peak, limit)
	}
}

func TestCancelStopsDispatchAndClosesChannel(t *testing.T) {
	const limit = 10
	fn := &fakeNet{behave: blockUntilDone}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(limit), WithConnectTimeout(time.Minute))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := sc.Scan(ctx, []string{"10.0.0.1"}, Range(1, 5000))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "all workers dialing", func() bool { _, cur, _ := fn.snapshot(); return cur == limit })

	cancel()
	got := drain(t, ch, 3*time.Second)

	for _, r := range got {
		if r.State != StateCanceled {
			t.Errorf("port %d: state %v, want canceled", r.Port, r.State)
		}
		if !errors.Is(r.Err, context.Canceled) {
			t.Errorf("port %d: Err = %v, want context.Canceled", r.Port, r.Err)
		}
	}
	if calls, cur, _ := fn.snapshot(); calls > limit || cur != 0 {
		t.Fatalf("calls=%d in-flight=%d: new dials started after cancel or dials leaked", calls, cur)
	}
}

func TestParentDeadlineIsCanceledNotTimeout(t *testing.T) {
	fn := &fakeNet{behave: blockUntilDone}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConnectTimeout(time.Minute), WithConcurrency(2))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	res, err := sc.ScanAll(ctx, []string{"10.0.0.1"}, Range(1, 100))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ScanAll err = %v, want DeadlineExceeded", err)
	}
	for _, r := range res {
		if r.State != StateCanceled {
			t.Errorf("state = %v, want canceled", r.State)
		}
	}
}

func TestSlowConsumerBackpressure(t *testing.T) {
	const limit = 4
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(limit))
	ch, err := sc.Scan(context.Background(), []string{"10.0.0.1"}, Range(1, 500))
	if err != nil {
		t.Fatal(err)
	}

	// No one reads this: the number of initiated connections should be limited
	// by the channel buffer and the workers, not by the task size.
	time.Sleep(100 * time.Millisecond)
	if calls, _, _ := fn.snapshot(); calls > 3*limit {
		t.Fatalf("%d dials started with a stalled consumer, want <= %d", calls, 3*limit)
	}

	n := 0
	for range ch {
		n++
		if n%50 == 0 {
			time.Sleep(time.Millisecond) // we read slowly
		}
	}
	if n != 500 {
		t.Fatalf("received %d results, want 500", n)
	}
	if _, _, peak := fn.snapshot(); peak > limit {
		t.Fatalf("peak = %d, want <= %d", peak, limit)
	}
}

func TestAbandonedScanDoesNotLeakGoroutinesAfterCancel(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(16))
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := sc.Scan(ctx, []string{"10.0.0.1"}, Range(1, 5000)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the consumer reads nothing
	if g := runtime.NumGoroutine(); g <= before {
		t.Fatalf("expected scan goroutines to be parked, goroutines before=%d now=%d", before, g)
	}
	cancel()
	waitFor(t, "goroutines to exit after cancel", func() bool { return runtime.NumGoroutine() <= before })
}

func TestScannerReuseAndConcurrentScans(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(5))

	const scans = 8
	var wg sync.WaitGroup
	errs := make(chan error, scans)
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			from := i*100 + 1
			res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1"}, Range(from, from+99))
			if err != nil {
				errs <- err
				return
			}
			if len(res) != 100 {
				errs <- errors.New("wrong result count")
				return
			}
			for _, r := range res {
				if int(r.Port) < from || int(r.Port) >= from+100 {
					errs <- errors.New("result from foreign scan")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// and consistent reuse
	for i := 0; i < 3; i++ {
		res, err := sc.ScanAll(context.Background(), []string{"10.0.0.9"}, Port(80))
		if err != nil || len(res) != 1 {
			t.Fatalf("reuse #%d: %v %v", i, res, err)
		}
	}
}

func TestScanInvalidHostsAreResults(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial))
	got, err := sc.ScanAll(context.Background(), []string{"10.0.0.1", "999.0.0.1", "", "999.0.0.1"}, Ports(80, 81))
	if err != nil {
		t.Fatal(err)
	}
	var open, invalid, empty int
	for _, g := range got {
		switch {
		case g.State == StateOpen:
			open++
		case g.State == StateError && g.Port == 0 && errors.Is(g.Err, ErrInvalidHost) && g.Host == "999.0.0.1":
			invalid++
		case g.State == StateError && g.Port == 0 && errors.Is(g.Err, ErrEmptyHost):
			empty++
		default:
			t.Errorf("unexpected result %+v", g)
		}
	}
	if open != 2 || invalid != 1 || empty != 1 {
		t.Fatalf("open=%d invalid=%d empty=%d, results %+v", open, invalid, empty, got)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	for name, opts := range map[string][]Option{
		"nil option":          {nil},
		"nil among valid":     {WithConcurrency(1), nil},
		"resolve concurrency": {WithResolveConcurrency(0)},
	} {
		if _, err := New(opts...); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("%s: err = %v, want ErrInvalidOption", name, err)
		}
	}
}

func TestScanArgumentErrorsAreSynchronous(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial))
	ctx := context.Background()

	cases := []struct {
		name  string
		hosts []string
		ports PortSet
		want  error
	}{
		{"no hosts", nil, Port(80), ErrNoTargets},
		{"port 0", []string{"10.0.0.1"}, Port(0), ErrInvalidPort},
		{"reversed", []string{"10.0.0.1"}, Range(10, 1), ErrReversedRange},
		{"no ports", []string{"10.0.0.1"}, Ports(), ErrNoPorts},
		{"zero ports", []string{"10.0.0.1"}, PortSet{}, ErrNoPorts},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := sc.Scan(ctx, tc.hosts, tc.ports)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.want)
			}
			if ch != nil {
				t.Fatal("channel must be nil on argument error")
			}
		})
	}
	if calls, _, _ := fn.snapshot(); calls != 0 {
		t.Fatalf("%d dials happened despite argument errors", calls)
	}

	t.Run("nil context", func(t *testing.T) {
		var nilCtx context.Context
		if _, err := sc.Scan(nilCtx, []string{"10.0.0.1"}, Port(80)); !errors.Is(err, ErrNilContext) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := sc.Scan(c, []string{"10.0.0.1"}, Port(80)); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDuplicateTargetsScannedOnce(t *testing.T) {
	fn := &fakeNet{}
	res := &fakeResolver{table: map[string][]netip.Addr{"alias.test": addrs("10.0.0.1")}}
	sc := mustNew(t, WithDialFunc(fn.dial), WithResolver(res))
	got, err := sc.ScanAll(context.Background(),
		[]string{"10.0.0.1", " 10.0.0.1 ", "alias.test", "10.0.0.2"}, Ports(80, 443))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d results, want 4 (2 unique IPs x 2 ports): %+v", len(got), got)
	}
	for _, r := range got {
		if r.IP.String() == "10.0.0.1" && r.Host != "10.0.0.1" {
			t.Errorf("Host = %q, want the first spelling", r.Host)
		}
	}
}

func TestOptionsValidation(t *testing.T) {
	bad := map[string]Option{
		"concurrency 0":      WithConcurrency(0),
		"concurrency -1":     WithConcurrency(-1),
		"connect timeout 0":  WithConnectTimeout(0),
		"connect timeout <0": WithConnectTimeout(-time.Second),
		"resolve timeout 0":  WithResolveTimeout(0),
		"nil resolver":       WithResolver(nil),
		"nil dial":           WithDialFunc(nil),
	}
	for name, opt := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := New(opt); !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("err = %v, want ErrInvalidOption", err)
			}
		})
	}
	if _, err := New(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrencyLimitIsSharedAcrossScans(t *testing.T) {
	const limit = 5
	fn := &fakeNet{behave: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		select {
		case <-time.After(2 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&fakeNet{}).open()
	}}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(limit))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1"}, Range(i*100+1, i*100+100))
			if err != nil || len(res) != 100 {
				t.Errorf("scan %d: %d results, err=%v", i, len(res), err)
			}
		}()
	}
	wg.Wait()
	if _, _, peak := fn.snapshot(); peak > limit || peak < 2 {
		t.Fatalf("peak concurrent dials across scans = %d, want 2..%d", peak, limit)
	}
}

func TestScanAllNoErrorIfFinishedBeforeCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The context is cancelled at the moment of the last successful connection:
	// the scan has already been fully completed, so there should be no errors.
	fn := &fakeNet{behave: func(context.Context, netip.AddrPort) (net.Conn, error) {
		cancel()
		return (&fakeNet{}).open()
	}}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(1))
	res, err := sc.ScanAll(ctx, []string{"10.0.0.1"}, Port(80))
	if err != nil || len(res) != 1 || res[0].State != StateOpen {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestLargeScan(t *testing.T) {
	if testing.Short() {
		t.Skip("large scan")
	}
	errFail := errors.New("fail")
	fn := &fakeNet{behave: func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, errFail }}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(200))
	ch, err := sc.Scan(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, Range(1, 65535))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 2*65535 {
		t.Fatalf("got %d results, want %d", n, 2*65535)
	}
	if _, _, peak := fn.snapshot(); peak > 200 {
		t.Fatalf("peak = %d, want <= 200", peak)
	}
}

func TestHugeConcurrencyDoesNotAllocateUpfront(t *testing.T) {
	fn := &fakeNet{}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(1<<30))
	before := runtime.NumGoroutine()

	res, err := sc.ScanAll(context.Background(), []string{"10.0.0.1"}, Range(1, 20))
	if err != nil || len(res) != 20 {
		t.Fatalf("got %d results, err=%v", len(res), err)
	}
	waitFor(t, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= before })
	if _, _, peak := fn.snapshot(); peak > 20 {
		t.Fatalf("peak = %d with only 20 jobs", peak)
	}
}

func TestWorkersAreStartedLazily(t *testing.T) {
	fn := &fakeNet{behave: blockUntilDone}
	sc := mustNew(t, WithDialFunc(fn.dial), WithConcurrency(1000), WithConnectTimeout(time.Minute))
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := sc.Scan(ctx, []string{"10.0.0.1"}, Range(1, 5))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "5 dials in flight", func() bool { _, cur, _ := fn.snapshot(); return cur == 5 })
	if g := runtime.NumGoroutine() - before; g > 20 {
		t.Fatalf("%d goroutines for 5 jobs with concurrency 1000", g)
	}
	cancel()
	drain(t, ch, 3*time.Second)
}
