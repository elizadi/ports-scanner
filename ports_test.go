package portsscanner

import (
	"errors"
	"slices"
	"testing"
)

func TestPortSet(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want []uint16
	}{
		{"single", Port(80), []uint16{80}},
		{"list sorted and deduped", Ports(443, 22, 80, 22), []uint16{22, 80, 443}},
		{"range", Range(1, 3), []uint16{1, 2, 3}},
		{"range bounds", Range(65534, 65535), []uint16{65534, 65535}},
		{"merge overlapping", Merge(Range(1, 5), Range(3, 8), Port(20)), []uint16{1, 2, 3, 4, 5, 6, 7, 8, 20}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set.validate(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(tc.set.ports, tc.want) {
				t.Fatalf("ports = %v, want %v", tc.set.ports, tc.want)
			}
			if tc.set.Len() != len(tc.want) {
				t.Fatalf("Len = %d", tc.set.Len())
			}
		})
	}
}

func TestPortSetErrors(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want error
	}{
		{"port 0", Port(0), ErrInvalidPort},
		{"port 65536", Port(65536), ErrInvalidPort},
		{"negative", Port(-1), ErrInvalidPort},
		{"list with 0", Ports(80, 0), ErrInvalidPort},
		{"range from 0", Range(0, 10), ErrInvalidPort},
		{"range to 65536", Range(1, 65536), ErrInvalidPort},
		{"reversed", Range(1000, 1), ErrReversedRange},
		{"empty list", Ports(), ErrNoPorts},
		{"zero value", PortSet{}, ErrNoPorts},
		{"empty merge", Merge(), ErrNoPorts},
		{"merge with bad", Merge(Range(1, 10), Port(0)), ErrInvalidPort},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set.validate(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMergeDoesNotModifyInputs(t *testing.T) {
	a := Range(1, 5)
	_ = Merge(a, Range(3, 9))
	if !slices.Equal(a.ports, []uint16{1, 2, 3, 4, 5}) {
		t.Fatalf("input modified: %v", a.ports)
	}
}
