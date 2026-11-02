package portsscanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNilContext — nil was passed to Scan instead of a context.
var ErrNilContext = errors.New("portscan: nil context")

// maxResultBuffer — the maximum size of the result channel buffer.
const maxResultBuffer = 256

// Scanner performs a TCP Connect scan. Once created via New, it is immutable and
// safe for use from multiple goroutines.
type Scanner struct {
	cfg config
	sem chan struct{} // total limit of simultaneous connections
}

// New create Scanner.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    100,
		connectTimeout: time.Second,
		resolveTimeout: 5 * time.Second,
		resolveWorkers: 8,
		resolver:       &net.Resolver{},
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidOption)
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	if cfg.dial == nil {
		cfg.dial = (&net.Dialer{}).DialContext
	}
	return &Scanner{cfg: cfg, sem: make(chan struct{}, cfg.concurrency)}, nil
}

// Scan initiates a scan and returns a results channel, which is closed
// upon completion.
//
// An error is returned only if there is an issue with the arguments (e.g., an empty
// list of hosts, invalid ports, a nil context, or a context that has already been
// canceled); in such cases, no scan is started.
// All other issues are reported via the results channel—including those related to
// invalid hosts. For each such host, a Result is emitted with Port == 0, StateError,
// and an error (err) for which errors.Is(err, ErrEmptyHost) or errors.Is(err, ErrInvalidHost)
// is true. Other hosts are scanned as usual.
//
// Each unique IP address is checked only once. A DNS name that resolves to
// multiple addresses will yield results for each address; however, if all addresses
// associated with a given name have already been checked (under a different name),
// no results will be produced for that name.
//
// The channel must be read until it is closed, or the context (ctx) must be canceled.
// Once the context is canceled, no new tasks are issued, and any ongoing
// connections are terminated—returning, where possible, with a state of StateCanceled.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	r, err := s.scan(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}
	return r.out, nil
}

// ScanAll collects all Scan results into a slice. If the scan was
// interrupted by the cancellation of ctx, it returns the accumulated results
// along with ctx.Err(); if it completed fully, no error is returned.
func (s *Scanner) ScanAll(ctx context.Context, hosts []string, ports PortSet) ([]Result, error) {
	r, err := s.scan(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}
	var res []Result
	for x := range r.out {
		res = append(res, x)
	}
	if r.interrupted.Load() {
		return res, ctx.Err()
	}
	return res, nil
}

func (s *Scanner) scan(ctx context.Context, hosts []string, ports PortSet) (*run, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ports.validate(); err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	targets, err := parseTargets(hosts)
	if err != nil {
		return nil, err
	}

	r := &run{
		cfg:     s.cfg,
		sem:     s.sem,
		ctx:     ctx,
		targets: targets,
		ports:   ports.ports,
		// The buffer is limited so that a massive WithConcurrency value doesn't cause excessive memory usage.
		out: make(chan Result, min(s.cfg.concurrency, maxResultBuffer)),
	}
	r.start()
	return r, nil
}

type job struct {
	host string
	ip   netip.Addr
	port uint16
}

// run — the state of a single Scan call.
type run struct {
	cfg     config
	sem     chan struct{}
	ctx     context.Context
	targets []target
	ports   []uint16
	out     chan Result

	// `interrupted` is set if the cancellation of `ctx` prevented the scan from being completed.
	interrupted atomic.Bool

	wg      sync.WaitGroup
	workers int // number of running workers; can only be changed by the producer
}

func (r *run) start() {
	jobs := make(chan job)

	// The producer also writes to 'out' (e.g., DNS errors), so we close 'out'
	// only after the producer and all workers have finished. The producer
	// launches the workers while it is itself part of the WaitGroup,
	// ensuring the counter does not reach zero prematurely.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(jobs)
		r.produce(jobs)
	}()

	go func() {
		r.wg.Wait()
		close(r.out)
	}()
}

// dispatch assigns a task to a worker. Workers are started lazily: a new one is
// created only if all existing workers are busy and their total count is less
// than the concurrency limit. This ensures that small tasks don't spawn a
// multitude of goroutines, while a high concurrency setting doesn't lead to
// excessive memory usage.
// Returns false if the context (ctx) has been canceled.
func (r *run) dispatch(jobs chan job, j job) bool {
	if r.ctx.Err() != nil {
		return false
	}
	select {
	case jobs <- j:
		return true
	default:
	}
	if r.workers < r.cfg.concurrency {
		if r.ctx.Err() != nil {
			return false
		}
		r.workers++
		r.wg.Add(1)
		go r.worker(jobs)
	}
	select {
	case jobs <- j:
		return true
	case <-r.ctx.Done():
		return false
	}
}

func (r *run) worker(jobs <-chan job) {
	defer r.wg.Done()
	for j := range jobs {
		if !r.acquire() {
			r.interrupted.Store(true)
			return
		}
		res := r.probe(j)
		<-r.sem // free up the slot before sending: a slow reader does not count toward the limit
		r.emit(res)
	}
}

// acquire occupies a slot within the total connection limit. Returns false
// if ctx is canceled.
func (r *run) acquire() bool {
	select {
	case r.sem <- struct{}{}:
		if r.ctx.Err() != nil {
			<-r.sem
			return false
		}
		return true
	case <-r.ctx.Done():
		return false
	}
}

// lookup — prepared target: addresses for scanning or a resolution error.
type lookup struct {
	t     target
	addrs []netip.Addr
	err   error
}

// `prepare` initiates name resolution in advance and in parallel: no more than
// `cfg.resolveWorkers` resolutions are performed simultaneously. Each target
// receives a response channel, and these channels are provided in the same
// order as the original targets. Consequently, a fast DNS response cannot
// overtake a slower one, and deduplication (determining which target claims
// an address first) does not depend on DNS response speed. The window size
// also serves to limit the buffer.
func (r *run) prepare() <-chan chan lookup {
	window := min(r.cfg.resolveWorkers, len(r.targets))
	pending := make(chan chan lookup, window-1)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(pending)
		for _, t := range r.targets {
			f := make(chan lookup, 1)
			select {
			case pending <- f:
			case <-r.ctx.Done():
				return
			}
			if t.err != nil || t.ip.IsValid() {
				f <- lookup{t: t, addrs: []netip.Addr{t.ip}}
				continue
			}
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				addrs, err := r.resolve(t)
				f <- lookup{t: t, addrs: addrs, err: err}
			}()
		}
	}()
	return pending
}

// `produce` yields tasks one by one, so memory usage does not depend on the size of the task.
func (r *run) produce(jobs chan job) {
	var (
		seen = make(map[netip.Addr]bool)
		done int // сколько целей обработано
	)
	for f := range r.prepare() {
		var l lookup
		select {
		case l = <-f:
		case <-r.ctx.Done():
			r.interrupted.Store(true)
			return
		}
		if r.ctx.Err() != nil {
			r.interrupted.Store(true)
			return
		}
		done++
		switch {
		case l.t.err != nil:
			r.emit(Result{Host: l.t.host, State: StateError, Err: l.t.err})
			continue
		case l.err != nil:
			r.emit(Result{Host: l.t.host, State: StateError, Err: l.err})
			continue
		}
		for _, ip := range l.addrs {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			for _, port := range r.ports {
				if !r.dispatch(jobs, job{host: l.t.host, ip: ip, port: port}) {
					r.interrupted.Store(true)
					return
				}
			}
		}
	}
	if done < len(r.targets) {
		r.interrupted.Store(true)
	}
}

func (r *run) resolve(t target) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.resolveTimeout)
	defer cancel()

	found, err := r.cfg.resolver.LookupNetIP(ctx, "ip", t.name)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrResolve, t.host, err)
	}
	addrs := make([]netip.Addr, 0, len(found))
	for _, a := range found {
		addrs = append(addrs, a.Unmap())
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	addrs = slices.Compact(addrs)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q: no addresses", ErrResolve, t.host)
	}
	return addrs, nil
}

// The probe makes a single connection attempt and always closes the connection.
func (r *run) probe(j job) Result {
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.connectTimeout)
	defer cancel()

	start := time.Now()
	conn, err := r.cfg.dial(ctx, "tcp", netip.AddrPortFrom(j.ip, j.port).String())
	res := Result{
		Host:     j.host,
		IP:       net.IP(j.ip.AsSlice()),
		Port:     j.port,
		Duration: time.Since(start),
	}
	if err != nil {
		res.State = classify(r.ctx, err)
		res.Err = err
		if res.State == StateCanceled {
			r.interrupted.Store(true)
		}
		return res
	}
	conn.Close()
	res.State = StateOpen
	return res
}

// emit sends the result. If the channel is not being read, it waits (backpressure)
// until ctx is canceled; after cancellation, the result is delivered only if the
// reader is ready to accept it immediately, ensuring that goroutines do not hang.
func (r *run) emit(res Result) {
	select {
	case r.out <- res:
		return
	default:
	}
	select {
	case r.out <- res:
	case <-r.ctx.Done():
		select {
		case r.out <- res:
		default:
			r.interrupted.Store(true) // result lost due to cancellation
		}
	}
}
