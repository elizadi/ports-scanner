package portsscanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func opErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

func TestClassify(t *testing.T) {
	live := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()

	tests := []struct {
		name   string
		parent context.Context
		err    error
		want   State
	}{
		{"nil", live, nil, StateOpen},
		{"canceled", canceled, context.Canceled, StateCanceled},
		{"canceled wrapped", canceled, fmt.Errorf("dial: %w", context.Canceled), StateCanceled},
		{"own timeout", live, context.DeadlineExceeded, StateTimeout},
		{"parent deadline", expired, context.DeadlineExceeded, StateCanceled},
		{"net.Error timeout", live, timeoutErr{}, StateTimeout},
		{"os deadline", live, os.ErrDeadlineExceeded, StateTimeout},
		{"refused", live, opErr(syscall.ECONNREFUSED), StateClosed},
		{"refused wrapped", live, fmt.Errorf("x: %w", opErr(syscall.ECONNREFUSED)), StateClosed},
		{"net unreachable", live, opErr(syscall.ENETUNREACH), StateUnreachable},
		{"host unreachable", live, opErr(syscall.EHOSTUNREACH), StateUnreachable},
		// Winsock codes, as returned by Windows
		{"winsock refused", live, opErr(wsaeConnRefused), StateClosed},
		{"winsock net unreachable", live, opErr(wsaeNetUnreach), StateUnreachable},
		{"winsock host unreachable", live, opErr(wsaeHostUnreach), StateUnreachable},
		{"winsock timed out", live, opErr(wsaeTimedOut), StateTimeout},
		{"reset", live, opErr(syscall.ECONNRESET), StateError},
		{"other", live, errors.New("boom"), StateError},
		// the error text should not affect the result
		{"text only", live, errors.New("connection refused"), StateError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.parent, tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
