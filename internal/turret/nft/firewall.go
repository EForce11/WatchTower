// Package nft enforces Turret bans through a single self-owned nftables
// table (`inet watchtower`). It never touches any other table.
package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// TableName is the only nftables table (family inet) Turret owns.
const TableName = "watchtower"

// Kind selects the enforcement set an address is added to.
type Kind int

// Enforcement kinds.
const (
	KindBan       Kind = iota + 1 // timed drop (ban4/ban6)
	KindPerm                      // permanent drop (perm4/perm6); ttl ignored
	KindRateLimit                 // timed rate limit of one address (ratelim4/ratelim6)
)

func (k Kind) String() string {
	switch k {
	case KindBan:
		return "ban"
	case KindPerm:
		return "perm"
	case KindRateLimit:
		return "ratelimit"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// Firewall is the enforcement surface the Turret engine drives.
type Firewall interface {
	// Ensure creates table/sets/chain if missing and keeps the contents of an
	// existing, correctly laid out table. A table whose layout differs from
	// the spec is deleted and recreated empty.
	Ensure() error
	// SetAllow atomically replaces the allow4/allow6 contents.
	SetAllow(p []netip.Prefix) error
	// Add inserts p into the set for k. ttl is ignored for KindPerm and must
	// be positive otherwise. KindRateLimit requires a single address. Adding
	// a prefix that is already present refreshes it.
	Add(k Kind, p netip.Prefix, ttl time.Duration) error
	// Remove deletes exactly p from the ban, perm and ratelimit sets. A
	// missing entry is not an error.
	Remove(p netip.Prefix) error
	// Flush deletes table inet watchtower. A missing table is not an error.
	Flush() error
}

// normalize returns p masked, without zone, with IPv4-mapped IPv6 prefixes
// (::ffff:a.b.c.d/n, n>=96) converted to plain IPv4.
func normalize(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.New("nft: invalid prefix")
	}
	a := p.Addr().WithZone("")
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a = a.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}

// validateAdd is shared by every Firewall implementation so fakes cannot
// accept what the real one rejects.
func validateAdd(k Kind, p netip.Prefix, ttl time.Duration) (netip.Prefix, error) {
	switch k {
	case KindBan, KindRateLimit, KindPerm:
	default:
		return netip.Prefix{}, fmt.Errorf("nft: invalid kind %d", int(k))
	}
	np, err := normalize(p)
	if err != nil {
		return netip.Prefix{}, err
	}
	if k != KindPerm && ttl <= 0 {
		return netip.Prefix{}, fmt.Errorf("nft: %s requires a positive ttl, got %s", k, ttl)
	}
	if k == KindRateLimit && np.Bits() != np.Addr().BitLen() {
		return netip.Prefix{}, fmt.Errorf("nft: ratelimit requires a single address, got %s", np)
	}
	return np, nil
}

func normalizeAll(ps []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		np, err := normalize(p)
		if err != nil {
			return nil, err
		}
		out = append(out, np)
	}
	return out, nil
}

// Call is one recorded Fake invocation.
type Call struct {
	Op   string
	Kind Kind
	P    netip.Prefix
	TTL  time.Duration
}

// Fake is an in-memory Firewall for engine tests. It enforces the same
// argument validation as the real implementation.
type Fake struct {
	mu       sync.Mutex
	state    map[Kind]map[netip.Prefix]time.Duration
	allow    []netip.Prefix
	calls    []Call
	failNext error
}

var _ Firewall = (*Fake)(nil)

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{state: map[Kind]map[netip.Prefix]time.Duration{}}
}

// FailNext makes the next Firewall call return err without mutating state.
func (f *Fake) FailNext(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = err
}

// begin records the call and consumes a pending injected failure.
func (f *Fake) begin(c Call) error {
	f.calls = append(f.calls, c)
	if err := f.failNext; err != nil {
		f.failNext = nil
		return err
	}
	return nil
}

// Calls returns a copy of the recorded calls, oldest first.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Has reports whether p is present in the set for k.
func (f *Fake) Has(k Kind, p netip.Prefix) bool {
	np, err := normalize(p)
	if err != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.state[k][np]
	return ok
}

// TTL returns the ttl recorded for p in the set for k.
func (f *Fake) TTL(k Kind, p netip.Prefix) (time.Duration, bool) {
	np, err := normalize(p)
	if err != nil {
		return 0, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.state[k][np]
	return d, ok
}

// Allow returns a copy of the current allow list.
func (f *Fake) Allow() []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Prefix(nil), f.allow...)
}

// Ensure records the call.
func (f *Fake) Ensure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.begin(Call{Op: "Ensure"})
}

// SetAllow replaces the allow list.
func (f *Fake) SetAllow(p []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "SetAllow"}); err != nil {
		return err
	}
	np, err := normalizeAll(p)
	if err != nil {
		return err
	}
	f.allow = np
	return nil
}

// Add validates and records p.
func (f *Fake) Add(k Kind, p netip.Prefix, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "Add", Kind: k, P: p, TTL: ttl}); err != nil {
		return err
	}
	np, err := validateAdd(k, p, ttl)
	if err != nil {
		return err
	}
	if k == KindPerm {
		ttl = 0
	}
	if f.state[k] == nil {
		f.state[k] = map[netip.Prefix]time.Duration{}
	}
	f.state[k][np] = ttl
	return nil
}

// Remove deletes p from every kind.
func (f *Fake) Remove(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "Remove", P: p}); err != nil {
		return err
	}
	np, err := normalize(p)
	if err != nil {
		return err
	}
	for _, m := range f.state {
		delete(m, np)
	}
	return nil
}

// Flush clears all state, including the allow list.
func (f *Fake) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "Flush"}); err != nil {
		return err
	}
	f.state = map[Kind]map[netip.Prefix]time.Duration{}
	f.allow = nil
	return nil
}
