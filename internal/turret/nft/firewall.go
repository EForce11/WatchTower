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

// Entry is one ban record handed to Firewall.Replace.
type Entry struct {
	Kind     Kind
	Prefix   netip.Prefix
	Deadline time.Time // zero = permanent (KindPerm only)
}

// validateEntries normalizes and checks entries, dropping expired ones.
func validateEntries(entries []Entry, now time.Time) ([]Entry, error) {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		ttl := time.Hour // placeholder positive ttl: the deadline is explicit
		np, err := validateAdd(e.Kind, e.Prefix, ttl)
		if err != nil {
			return nil, err
		}
		if e.Kind == KindPerm {
			e.Deadline = time.Time{}
		} else {
			if e.Deadline.IsZero() {
				return nil, fmt.Errorf("nft: %s entry %s needs a deadline", e.Kind, np)
			}
			if !e.Deadline.After(now) {
				continue
			}
		}
		e.Prefix = np
		out = append(out, e)
	}
	return out, nil
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
	// Replace makes entries the complete content of the ban, perm and
	// ratelimit sets (expired entries are skipped) in one transaction; the
	// allow sets are untouched. The table must exist (Ensure).
	Replace(entries []Entry) error
	// Remove deletes exactly p from the ban, perm and ratelimit sets. A
	// missing entry is not an error.
	Remove(p netip.Prefix) error
	// Flush deletes table inet watchtower. A missing table is not an error.
	Flush() error
	// Close releases background resources (the expiry timer). The table and
	// its contents are left in place.
	Close() error
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
// argument validation and models the same effective coverage as the real
// implementation: bans are never shortened, an address stays blocked until
// the latest deadline of any entry covering it, and Remove deletes exactly
// the given prefix.
type Fake struct {
	mu       sync.Mutex
	now      func() time.Time
	state    map[Kind]*recordSet
	allow    []netip.Prefix
	calls    []Call
	failNext error
	hook     func(Call)
}

var _ Firewall = (*Fake)(nil)

// NewFake returns an empty Fake using the wall clock.
func NewFake() *Fake { return NewFakeAt(time.Now) }

// NewFakeFrom returns a Fake whose ban/perm/ratelimit state is what a kernel
// table left behind by prev would be imported as on restart: the effective
// coverage, with adjacent equal-deadline entries merged into one interval.
// It shares prev's clock.
func NewFakeFrom(prev *Fake) *Fake {
	prev.mu.Lock()
	defer prev.mu.Unlock()
	f := NewFakeAt(prev.now)
	now := prev.now()
	for k, rs := range prev.state {
		var out recordSet
		for _, seg := range rs.segments(now) {
			out = append(out, record(seg))
		}
		f.state[k] = &out
	}
	f.allow = append([]netip.Prefix(nil), prev.allow...)
	return f
}

// NewFakeAt returns an empty Fake using the given clock.
func NewFakeAt(now func() time.Time) *Fake {
	return &Fake{now: now, state: map[Kind]*recordSet{}}
}

// FailNext makes the next Firewall call return err without mutating state.
func (f *Fake) FailNext(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = err
}

// OnCall installs fn to run at the start of every Add and SetAllow, before
// the Fake takes its lock, so tests can block a call to force an ordering.
// nil removes it.
func (f *Fake) OnCall(fn func(Call)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = fn
}

func (f *Fake) runHook(c Call) {
	f.mu.Lock()
	fn := f.hook
	f.mu.Unlock()
	if fn != nil {
		fn(c)
	}
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

func (f *Fake) records(k Kind) *recordSet {
	if f.state[k] == nil {
		f.state[k] = &recordSet{}
	}
	return f.state[k]
}

// Has reports whether exactly p is a live entry for k.
func (f *Fake) Has(k Kind, p netip.Prefix) bool {
	np, err := normalize(p)
	if err != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records(k).has(prefixSpan(np), f.now())
}

// Blocked reports whether any live entry for k covers a.
func (f *Fake) Blocked(k Kind, a netip.Addr) bool {
	_, ok := f.Expiry(k, a)
	return ok
}

// Expiry returns when a stops being covered for k (zero time: never) and
// whether it is covered at all.
func (f *Fake) Expiry(k Kind, a netip.Addr) (time.Time, bool) {
	a = a.WithZone("").Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records(k).coverage(a, f.now())
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
	f.runHook(Call{Op: "SetAllow"})
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
	f.runHook(Call{Op: "Add", Kind: k, P: p, TTL: ttl})
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "Add", Kind: k, P: p, TTL: ttl}); err != nil {
		return err
	}
	np, err := validateAdd(k, p, ttl)
	if err != nil {
		return err
	}
	var deadline time.Time
	if k != KindPerm {
		deadline = f.now().Add(ttl)
	}
	rs := f.records(k)
	rs.prune(f.now())
	rs.add(prefixSpan(np), deadline)
	return nil
}

// Replace swaps the ban/perm/ratelimit state for exactly entries.
func (f *Fake) Replace(entries []Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(Call{Op: "Replace"}); err != nil {
		return err
	}
	es, err := validateEntries(entries, f.now())
	if err != nil {
		return err
	}
	f.state = map[Kind]*recordSet{}
	for _, e := range es {
		f.records(e.Kind).add(prefixSpan(e.Prefix), e.Deadline)
	}
	return nil
}

// Remove deletes exactly p from every kind.
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
	sp := prefixSpan(np)
	for _, rs := range f.state {
		rs.remove(sp)
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
	f.state = map[Kind]*recordSet{}
	f.allow = nil
	return nil
}

// Close is a no-op.
func (f *Fake) Close() error { return nil }
