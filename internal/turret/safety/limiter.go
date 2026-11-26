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
	last     admission
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

// admission remembers how to undo the most recent admission.
type admission struct {
	p    netip.Prefix
	undo func()
}

// Admit returns the prefix to ban for ip: the single IP, or its /24 (/64)
// once the prefix threshold is crossed and mayWiden(group) allows it. When
// widening is not allowed the single IP is recorded (and counted) instead.
// ok is false when the budget is exhausted. A prefix ban counts as one
// budget entry.
func (r *ReflexLimiter) Admit(ip netip.Addr, mayWiden func(netip.Prefix) bool) (netip.Prefix, bool) {
	if !ip.IsValid() {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap().WithZone("")
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.prune(now)
	r.last = admission{}

	bits := 24
	if ip.Is6() {
		bits = 64
	}
	group, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	single := netip.PrefixFrom(ip, ip.BitLen())

	// Already covered by an admitted prefix ban: no extra budget, provided
	// the prefix is still allowed to be applied (the protected set may have
	// changed since); otherwise fall back to the budgeted single address.
	if _, ok := r.admitted[group]; ok && mayWiden != nil && mayWiden(group) {
		return group, true
	}

	h, restoreHit := r.recordHit(group, ip, now)

	candidate := single
	if len(h) > r.lim.Threshold && mayWiden != nil && mayWiden(group) {
		candidate = group
	}
	if prev, ok := r.admitted[candidate]; ok {
		r.last = admission{candidate, func() { r.admitted[candidate] = prev; restoreHit() }}
		return candidate, true
	}

	// Entries the candidate would absorb (single IPs inside a prefix ban).
	absorbed := r.inside(candidate)
	if len(r.admitted)-len(absorbed)+1 > r.budget.MaxTargets {
		restoreHit()
		return netip.Prefix{}, false
	}
	saved := make(map[netip.Prefix]time.Time, len(absorbed))
	for _, p := range absorbed {
		saved[p] = r.admitted[p]
		delete(r.admitted, p)
	}
	r.admitted[candidate] = now
	r.last = admission{candidate, func() {
		delete(r.admitted, candidate)
		for p, t := range saved {
			r.admitted[p] = t
		}
		restoreHit()
	}}
	return candidate, true
}

// recordHit notes ip in group's window and returns the group map plus a
// function that undoes exactly this note.
func (r *ReflexLimiter) recordHit(group netip.Prefix, ip netip.Addr, now time.Time) (hits map[netip.Addr]time.Time, undo func()) {
	h := r.hits[group]
	hadGroup := h != nil
	if h == nil {
		h = map[netip.Addr]time.Time{}
		r.hits[group] = h
	}
	prevHit, seen := h[ip]
	h[ip] = now
	return h, func() {
		hh := r.hits[group]
		if hh == nil {
			hh = map[netip.Addr]time.Time{}
			r.hits[group] = hh
		}
		if seen {
			hh[ip] = prevHit
		} else {
			delete(hh, ip)
		}
		if len(hh) == 0 && !hadGroup {
			delete(r.hits, group)
		}
	}
}

// AdmitSingle accounts a single-address action (rate limit) against the
// budget. It never widens and never counts toward the prefix threshold.
func (r *ReflexLimiter) AdmitSingle(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap().WithZone("")
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.prune(now)
	r.last = admission{}
	single := netip.PrefixFrom(ip, ip.BitLen())
	if _, ok := r.admitted[single]; ok {
		return true
	}
	if len(r.admitted)+1 > r.budget.MaxTargets {
		return false
	}
	r.admitted[single] = now
	r.last = admission{single, func() { delete(r.admitted, single) }}
	return true
}

// Release undoes the most recent admission if it was for p. The engine calls
// it when the action failed after being admitted.
func (r *ReflexLimiter) Release(p netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last.undo != nil && r.last.p == p {
		r.last.undo()
	}
	r.last = admission{}
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
