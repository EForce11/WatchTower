// Package safety is the wt-turret safety layer: self-preservation ranges,
// target parsing, the origin x action policy and the reflex limiter.
package safety

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/EForce11/WatchTower/internal/turret/verify"
)

// Origin is where a request came from.
type Origin int

// Request origins.
const (
	OriginReflex Origin = iota + 1
	OriginAutomation
	OriginAdmin
)

// OriginFor maps a signing key class to its origin.
func OriginFor(c verify.KeyClass) Origin {
	if c == verify.KeyAdmin {
		return OriginAdmin
	}
	return OriginAutomation
}

const (
	minPrefixV4 = 16
	minPrefixV6 = 32
)

// ParseNetTarget parses a single IP (to /32 or /128; IPv4-mapped IPv6 is
// unmapped) or, for non-reflex origins only, a CIDR (an explicit /32 or /128
// counts as a CIDR, so reflex origins may not use it) no broader than /16 (IPv4) or /32 (IPv6).
func ParseNetTarget(s string, o Origin) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid target %q", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	if o == OriginReflex {
		return netip.Prefix{}, fmt.Errorf("target %q: reflex origin may only target single IPs", s)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid target %q: %w", s, err)
	}
	if p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid target %q", s)
	}
	limit := minPrefixV6
	if p.Addr().Is4() {
		limit = minPrefixV4
	}
	if p.Bits() < limit {
		return netip.Prefix{}, fmt.Errorf("target %q: prefix broader than /%d", s, limit)
	}
	return p.Masked(), nil
}

// ParsePIDTarget parses "pid:<n>" with n > 1.
func ParsePIDTarget(s string) (int, error) {
	rest, ok := strings.CutPrefix(s, "pid:")
	if !ok {
		return 0, fmt.Errorf("invalid pid target %q", s)
	}
	if rest == "" || strings.Trim(rest, "0123456789") != "" {
		return 0, fmt.Errorf("invalid pid target %q", s)
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n <= 1 {
		return 0, fmt.Errorf("invalid pid target %q", s)
	}
	return n, nil
}
