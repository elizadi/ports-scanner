package portsscanner

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrNoTargets — the list of hosts is empty.
	ErrNoTargets = errors.New("portscan: no targets to scan")
	// ErrEmptyHost — an empty string instead of a host.
	ErrEmptyHost = errors.New("portscan: empty host")
	// ErrInvalidHost — строка не является IP-адресом или DNS-именем.
	ErrInvalidHost = errors.New("portscan: invalid host")
	// ErrInvalidHost — the string is not an IP address or a DNS name.
	ErrResolve = errors.New("portscan: cannot resolve host")
)

// target — a single destination: either an IP address (ip.IsValid) or a DNS name (name).
type target struct {
	host string     // as it returns to Result.Host
	name string     // DNS name in lowercase, a trailing dot is saved
	ip   netip.Addr // populated if the target is an IP
	err  error      // not nil if the host is invalid: it will not be scanned
}

func (t target) key() string {
	if t.err != nil {
		return "\x00" + t.host // invalid hosts do not overlap with valid ones
	}
	if t.ip.IsValid() {
		return t.ip.String()
	}
	return t.name
}

// parseTargets parses hosts and removes duplicates while preserving the original order.
// An invalid host does not interrupt the parsing process; it remains in the list with its
// err field populated, and Scan will report it as a separate result.
func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}
	var (
		out  []target
		seen = make(map[string]bool)
	)
	for _, h := range hosts {
		t, err := parseTarget(h)
		if err != nil {
			t = target{host: h, err: fmt.Errorf("host %q: %w", h, err)}
		}
		if !seen[t.key()] {
			seen[t.key()] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func parseTarget(s string) (target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return target{}, ErrEmptyHost
	}
	// "[::1]" -> "::1"; brackets are only allowed in pairs.
	lit := s
	open, closed := strings.HasPrefix(s, "["), strings.HasSuffix(s, "]")
	if open != closed {
		return target{}, ErrInvalidHost
	}
	if open {
		lit = s[1 : len(s)-1]
	}
	if ip, err := netip.ParseAddr(lit); err == nil {
		return target{host: s, ip: ip.Unmap()}, nil
	}
	if !validHostname(s) {
		return target{}, ErrInvalidHost
	}
	return target{host: s, name: strings.ToLower(s)}, nil
}

// validHostname checks the syntax of a DNS name (ASCII; IDN must be in punycode).
// Strings consisting solely of digits and dots (e.g., 999.1.1.1) are considered invalid IP addresses, not hostnames.
func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	onlyDigits := true
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
				onlyDigits = false
			default:
				return false
			}
		}
	}
	return !onlyDigits
}
