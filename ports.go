package portsscanner

import (
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrInvalidPort — port is outside the range 1–65535 (including 0).
	ErrInvalidPort = errors.New("portscan: invalid port, want 1..65535")
	// ErrReversedRange — the start of the range is greater than the end, for example Range(1000, 1).
	ErrReversedRange = errors.New("portscan: reversed port range")
	// ErrNoPorts — the set of ports is empty.
	ErrNoPorts = errors.New("portscan: no ports to scan")
)

// PortSet is an immutable set of ports. Duplicates are removed, and ports are
// scanned in ascending order. Constructors do not return errors; instead,
// any error is captured and returned by the Scan method, which makes it
// convenient to nest them:
//
//	portscan.Merge(portscan.Range(1, 1024), portscan.Port(8080))
//
// Port 0, ports greater than 65535, inverted ranges, and empty sets are considered errors.
//
// The constructors accept int rather than uint16 by design; otherwise, values
// such as 70000 or -1 could not be distinguished from valid inputs, making it
// impossible to report an error.
type PortSet struct {
	ports []uint16 // sorted, without duplicates
	err   error
}

// Port — a set consisting of a single port.
func Port(p int) PortSet { return Range(p, p) }

// Ports — a set consisting of the listed ports.
func Ports(ports ...int) PortSet {
	if len(ports) == 0 {
		return PortSet{err: ErrNoPorts}
	}
	set := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if !validPort(p) {
			return PortSet{err: fmt.Errorf("%w: %d", ErrInvalidPort, p)}
		}
		set = append(set, uint16(p))
	}
	return newPortSet(set)
}

// Range — a range of ports from `from` to `to`, inclusive.
func Range(from, to int) PortSet {
	for _, p := range []int{from, to} {
		if !validPort(p) {
			return PortSet{err: fmt.Errorf("%w: %d", ErrInvalidPort, p)}
		}
	}
	if from > to {
		return PortSet{err: fmt.Errorf("%w: %d-%d", ErrReversedRange, from, to)}
	}
	set := make([]uint16, 0, to-from+1)
	for p := from; p <= to; p++ {
		set = append(set, uint16(p))
	}
	return PortSet{ports: set}
}

// Merge combines sets. The errors from all the sets are combined.
func Merge(sets ...PortSet) PortSet {
	var (
		all  []uint16
		errs []error
	)
	for _, s := range sets {
		if s.err != nil {
			errs = append(errs, s.err)
			continue
		}
		all = append(all, s.ports...)
	}
	if len(errs) > 0 {
		return PortSet{err: errors.Join(errs...)}
	}
	return newPortSet(all)
}

// Len returns the number of distinct ports.
func (s PortSet) Len() int { return len(s.ports) }

func (s PortSet) validate() error {
	if s.err != nil {
		return s.err
	}
	if len(s.ports) == 0 {
		return ErrNoPorts
	}
	return nil
}

func newPortSet(ports []uint16) PortSet {
	slices.Sort(ports)
	return PortSet{ports: slices.Compact(ports)}
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }
