package portsscanner

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// Winsock codes. On Windows, socket errors are reported using these codes,
// rather than values like syscall.ECONNREFUSED (which are Go-specific
// abstractions). These codes do not appear on other platforms, so checking
// for them is harmless.
const (
	wsaeNetUnreach  = syscall.Errno(10051)
	wsaeTimedOut    = syscall.Errno(10060)
	wsaeConnRefused = syscall.Errno(10061)
	wsaeHostUnreach = syscall.Errno(10065)
)

// classify determines the port state based on the connection error.
// The state is derived from error types and the errno value; the error text itself is not analyzed.
// parent represents the context of the entire scan; it is used to distinguish between
// a user-initiated cancellation and a connection timeout.
func classify(parent context.Context, err error) State {
	var ne net.Error
	switch {
	case err == nil:
		return StateOpen
	case errors.Is(err, context.Canceled):
		return StateCanceled
	case errors.Is(err, context.DeadlineExceeded) && parent.Err() != nil:
		return StateCanceled // The parent context deadline has expired.
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, wsaeTimedOut),
		errors.As(err, &ne) && ne.Timeout():
		return StateTimeout
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, wsaeConnRefused):
		return StateClosed
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, wsaeNetUnreach), errors.Is(err, wsaeHostUnreach):
		return StateUnreachable
	default:
		return StateError
	}
}
