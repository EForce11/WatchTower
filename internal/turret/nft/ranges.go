package nft

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/google/nftables"
)

// span is a half-open address range [lo, hi). open means hi lies beyond the
// end of the address space (no end element exists).
type span struct {
	lo, hi netip.Addr
	open   bool
}

func prefixSpan(p netip.Prefix) span {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(b)
	hi := last.Next()
	return span{lo: p.Addr(), hi: hi, open: !hi.IsValid()}
}

func (s span) equal(o span) bool {
	return s.lo == o.lo && s.open == o.open && (s.open || s.hi == o.hi)
}

func (s span) covers(a netip.Addr) bool {
	return s.lo.Compare(a) <= 0 && (s.open || s.hi.Compare(a) > 0)
}

// elems returns the interval start (carrying ttl) and end elements.
func (s span) elems(ttl time.Duration) []nftables.SetElement {
	el := []nftables.SetElement{{Key: s.lo.AsSlice(), Timeout: ttl}}
	if !s.open {
		el = append(el, nftables.SetElement{Key: s.hi.AsSlice(), IntervalEnd: true})
	}
	return el
}

// spanElem is one imported interval with its remaining lifetime.
type spanElem struct {
	span
	expires time.Duration
}

// parseSpans pairs interval start/end elements into ranges. An end element
// without a start is an error: the set is not something this package wrote.
func parseSpans(elems []nftables.SetElement) ([]spanElem, error) {
	es := slices.Clone(elems)
	sort.SliceStable(es, func(i, j int) bool {
		if c := bytes.Compare(es[i].Key, es[j].Key); c != 0 {
			return c < 0
		}
		return es[i].IntervalEnd && !es[j].IntervalEnd // an end closes the previous range first
	})
	var out []spanElem
	var cur *spanElem
	for i := range es {
		e := &es[i]
		a, ok := netip.AddrFromSlice(e.Key)
		if !ok {
			return nil, errors.New("nft: malformed set element key")
		}
		switch {
		case !e.IntervalEnd:
			if cur != nil { // previous range ran to the end of the address space
				cur.open = true
				out = append(out, *cur)
			}
			cur = &spanElem{span: span{lo: a}, expires: e.Expires}
		case cur != nil:
			cur.hi = a
			out = append(out, *cur)
			cur = nil
		default:
			return nil, errors.New("nft: interval end element without a start")
		}
	}
	if cur != nil {
		cur.open = true
		out = append(out, *cur)
	}
	return out, nil
}

// record is one requested entry. A zero deadline means it never expires
// (perm sets only).
type record struct {
	span
	deadline time.Time
}

// later returns the later of two deadlines, zero (never) winning.
func later(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if b.After(a) {
		return b
	}
	return a
}

func (r *record) live(now time.Time) bool {
	return r.deadline.IsZero() || r.deadline.After(now)
}

// recordSet is the requested content of one set: effective coverage is the
// union of the live records, each address living until the latest deadline
// of any record covering it (bans are never shortened).
type recordSet []record

// add inserts sp, keeping the later deadline if it already exists.
func (rs *recordSet) add(sp span, deadline time.Time) {
	for i := range *rs {
		if (*rs)[i].equal(sp) {
			(*rs)[i].deadline = later((*rs)[i].deadline, deadline)
			return
		}
	}
	*rs = append(*rs, record{span: sp, deadline: deadline})
}

// remove deletes exactly sp and reports whether it existed.
func (rs *recordSet) remove(sp span) bool {
	for i := range *rs {
		if (*rs)[i].equal(sp) {
			*rs = slices.Delete(*rs, i, i+1)
			return true
		}
	}
	return false
}

func (rs *recordSet) prune(now time.Time) {
	*rs = slices.DeleteFunc(*rs, func(r record) bool { return !r.live(now) })
}

func (rs recordSet) has(sp span, now time.Time) bool {
	for i := range rs {
		if rs[i].equal(sp) && rs[i].live(now) {
			return true
		}
	}
	return false
}

// coverage returns the latest deadline over live records covering a
// (zero time = never expires) and whether any covers it.
func (rs recordSet) coverage(a netip.Addr, now time.Time) (time.Time, bool) {
	var dl time.Time
	found := false
	for i := range rs {
		if !rs[i].live(now) || !rs[i].covers(a) {
			continue
		}
		if !found {
			dl, found = rs[i].deadline, true
		} else {
			dl = later(dl, rs[i].deadline)
		}
	}
	return dl, found
}

type segment struct {
	span
	deadline time.Time
}

// segments sweeps all record boundaries and returns disjoint, ordered
// ranges whose deadline is the latest of the records covering them.
// Adjacent ranges with equal deadlines are merged.
func (rs recordSet) segments(now time.Time) []segment {
	bounds := make([]netip.Addr, 0, 2*len(rs))
	for i := range rs {
		if !rs[i].live(now) {
			continue
		}
		bounds = append(bounds, rs[i].lo)
		if !rs[i].open {
			bounds = append(bounds, rs[i].hi)
		}
	}
	slices.SortFunc(bounds, netip.Addr.Compare)
	bounds = slices.Compact(bounds)
	out := make([]segment, 0, len(bounds))
	for i, b := range bounds {
		dl, ok := rs.coverage(b, now)
		if !ok {
			continue
		}
		seg := segment{span: span{lo: b, open: true}, deadline: dl}
		if i+1 < len(bounds) {
			seg.hi, seg.open = bounds[i+1], false
		}
		if n := len(out); n > 0 && !out[n-1].open && out[n-1].hi == seg.lo && out[n-1].deadline.Equal(dl) {
			out[n-1].hi, out[n-1].open = seg.hi, seg.open
			continue
		}
		out = append(out, seg)
	}
	return out
}

// timeoutFor converts a deadline to a kernel element timeout (0 = none),
// including expiryMargin: Turret's expiry rewrite removes the element first.
func timeoutFor(deadline, now time.Time) time.Duration {
	if deadline.IsZero() {
		return 0
	}
	return max(deadline.Sub(now), time.Millisecond) + expiryMargin
}
