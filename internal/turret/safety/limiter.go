package safety

import (
	"net/netip"
	"sync"
	"time"

	"github.com/EForce11/WatchTower/internal/turret/config"
)

// Clock returns the current time.
type Clock func() time.Time

// ReflexLimiter enforces the reflex budget and the local prefix limiter.
// It is safe for concurrent use.
type ReflexLimiter struct {
	mu     sync.Mutex
	budget config.Budget
	lim    config.Limiter
	now    Clock

	admitted map[netip.Prefix]time.Time                // budget entries (IPs or prefixes)
	hits     map[netip.Prefix]map[netip.Addr]time.Time // per-prefix distinct IPs
}

// NewReflexLimiter builds a limiter using now as its time source.
func NewReflexLimiter(b config.Budget, l config.Limiter, now Clock) *ReflexLimiter {
	return &ReflexLimiter{
		budget:   b,
		lim:      l,
		now:      now,
		admitted: map[netip.Prefix]time.Time{},
		hits:     map[netip.Prefix]map[netip.Addr]time.Time{},
	}
}

// Admit returns the prefix to ban for ip: the single IP, or its /24 (/64)
// once the prefix threshold is crossed. ok is false when the budget is
// exhausted. A prefix ban counts as one budget entry.
func (r *ReflexLimiter) Admit(ip netip.Addr) (netip.Prefix, bool) {
	if !ip.IsValid() {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap().WithZone("")
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.prune(now)

	bits := 24
	if ip.Is6() {
		bits = 64
	}
	group, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	single := netip.PrefixFrom(ip, ip.BitLen())

	// Already covered by an admitted prefix ban: no extra budget.
	if _, ok := r.admitted[group]; ok {
		return group, true
	}

	h := r.hits[group]
	if h == nil {
		h = map[netip.Addr]time.Time{}
		r.hits[group] = h
	}
	_, seen := h[ip]
	h[ip] = now

	candidate := single
	if len(h) > r.lim.Threshold {
		candidate = group
	}
	if _, ok := r.admitted[candidate]; ok {
		return candidate, true
	}

	// Entries the candidate would absorb (single IPs inside a prefix ban).
	if len(r.admitted)-r.absorbed(candidate)+1 > r.budget.MaxTargets {
		if !seen {
			delete(h, ip)
			if len(h) == 0 {
				delete(r.hits, group)
			}
		}
		return netip.Prefix{}, false
	}
	for _, p := range r.inside(candidate) {
		delete(r.admitted, p)
	}
	r.admitted[candidate] = now
	return candidate, true
}

// prune drops state older than the respective windows.
func (r *ReflexLimiter) prune(now time.Time) {
	for p, t := range r.admitted {
		if now.Sub(t) >= r.budget.Window {
			delete(r.admitted, p)
		}
	}
	for g, h := range r.hits {
		for a, t := range h {
			if now.Sub(t) >= r.lim.Window {
				delete(h, a)
			}
		}
		if len(h) == 0 {
			delete(r.hits, g)
		}
	}
}

// inside lists admitted entries strictly contained in the wider prefix c.
func (r *ReflexLimiter) inside(c netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for p := range r.admitted {
		if c.Bits() < p.Bits() && c.Overlaps(p) {
			out = append(out, p)
		}
	}
	return out
}

// absorbed counts admitted entries that admitting c would replace.
func (r *ReflexLimiter) absorbed(c netip.Prefix) int { return len(r.inside(c)) }
