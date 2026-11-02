package portsscanner

import "testing"

func TestStateString(t *testing.T) {
	want := map[State]string{
		StateOpen: "open", StateClosed: "closed", StateTimeout: "timeout",
		StateUnreachable: "unreachable", StateCanceled: "canceled",
		StateError: "error", StateUnknown: "unknown", State(200): "unknown",
	}
	for s, str := range want {
		if s.String() != str {
			t.Errorf("State(%d) = %q, want %q", s, s.String(), str)
		}
	}
}
