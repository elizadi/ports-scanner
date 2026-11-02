package portsscanner

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	valid := map[string]string{
		"192.168.1.10":   "192.168.1.10",
		"  10.0.0.1 ":    "10.0.0.1",
		"::1":            "::1",
		"[::1]":          "::1",
		"2001:db8::1":    "2001:db8::1",
		"::ffff:1.2.3.4": "1.2.3.4",
		"example.org":    "example.org",
		"Example.ORG.":   "example.org.",
		"my_host.local":  "my_host.local",
	}
	for in, key := range valid {
		got, err := parseTarget(in)
		if err != nil {
			t.Errorf("parseTarget(%q): %v", in, err)
			continue
		}
		if got.key() != key {
			t.Errorf("parseTarget(%q).key() = %q, want %q", in, got.key(), key)
		}
	}

	invalid := map[string]error{
		"":                               ErrEmptyHost,
		"   ":                            ErrEmptyHost,
		"999.1.1.1":                      ErrInvalidHost,
		"1.2.3":                          ErrInvalidHost,
		"::zz":                           ErrInvalidHost,
		"[::1":                           ErrInvalidHost,
		"::1]":                           ErrInvalidHost,
		"[":                              ErrInvalidHost,
		"[]":                             ErrInvalidHost,
		"[example.org]":                  ErrInvalidHost,
		"host:80":                        ErrInvalidHost,
		"exa mple.org":                   ErrInvalidHost,
		"a..b":                           ErrInvalidHost,
		"-bad.example":                   ErrInvalidHost,
		"пример.рф":                      ErrInvalidHost,
		"http://a.org":                   ErrInvalidHost,
		strings.Repeat("a", 64) + ".org": ErrInvalidHost,
	}
	for in, want := range invalid {
		if _, err := parseTarget(in); !errors.Is(err, want) {
			t.Errorf("parseTarget(%q) err = %v, want %v", in, err, want)
		}
	}
}

func TestParseTargets(t *testing.T) {
	got, err := parseTargets([]string{"b.example", "10.0.0.1", "B.EXAMPLE.", " 10.0.0.1", "a.example"})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, g := range got {
		keys = append(keys, g.key())
	}
	want := "b.example,10.0.0.1,b.example.,a.example"
	if strings.Join(keys, ",") != want {
		t.Fatalf("keys = %v, want %s", keys, want)
	}

	if _, err := parseTargets(nil); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("nil hosts: %v", err)
	}

	// Invalid hosts do not interrupt parsing and are not duplicated.
	got, err = parseTargets([]string{"bad host", "10.0.0.1", "999.1.1.1", "", "bad host"})
	if err != nil || len(got) != 4 {
		t.Fatalf("got %d targets, err %v", len(got), err)
	}
	if !errors.Is(got[0].err, ErrInvalidHost) || got[1].err != nil ||
		!errors.Is(got[2].err, ErrInvalidHost) || !errors.Is(got[3].err, ErrEmptyHost) {
		t.Fatalf("targets: %+v", got)
	}
	if !strings.Contains(got[0].err.Error(), `"bad host"`) {
		t.Errorf("error does not mention the host: %v", got[0].err)
	}
}
