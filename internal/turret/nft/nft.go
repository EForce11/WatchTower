package nft

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const chainName = "input"

type setSpec struct {
	name     string
	v6       bool
	interval bool
	timeout  bool
}

// Spec §3.4.2, in definition order.
var setSpecs = []setSpec{
	{"ban4", false, true, true},
	{"ban6", true, true, true},
	{"perm4", false, true, false},
	{"perm6", true, true, false},
	{"ratelim4", false, false, true},
	{"ratelim6", true, false, true},
	{"allow4", false, true, false},
	{"allow6", true, true, false},
}

type ruleSpec struct {
	set     string
	v6      bool
	verdict expr.VerdictKind
	limit   bool
}

// Spec §3.4.2 rule order: allow wins, then perm, ban, ratelimit.
var ruleSpecs = []ruleSpec{
	{"allow4", false, expr.VerdictAccept, false},
	{"allow6", true, expr.VerdictAccept, false},
	{"perm4", false, expr.VerdictDrop, false},
	{"perm6", true, expr.VerdictDrop, false},
	{"ban4", false, expr.VerdictDrop, false},
	{"ban6", true, expr.VerdictDrop, false},
	{"ratelim4", false, expr.VerdictDrop, true},
	{"ratelim6", true, expr.VerdictDrop, true},
}

func keyType(v6 bool) nftables.SetDatatype {
	if v6 {
		return nftables.TypeIP6Addr
	}
	return nftables.TypeIPAddr
}

func setName(base string, v6 bool) string {
	if v6 {
		return base + "6"
	}
	return base + "4"
}

type nftFW struct {
	mu sync.Mutex // serializes read-modify-write sequences
}

// NewNFT returns the nftables-backed Firewall. It verifies that the kernel
// accepts nftables netlink requests.
func NewNFT() (Firewall, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nft: open netlink: %w", err)
	}
	if _, err := c.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		return nil, fmt.Errorf("nft: nftables unavailable: %w", err)
	}
	return &nftFW{}, nil
}

func ourTable() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
}

// findTable returns our table if it exists.
func findTable(c *nftables.Conn) (*nftables.Table, error) {
	tabs, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	for _, t := range tabs {
		if t.Name == TableName {
			return t, nil
		}
	}
	return nil, nil
}

// ---- Ensure --------------------------------------------------------------

func (f *nftFW) Ensure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil {
		return err
	}
	if t != nil {
		ok, err := layoutMatches(c, t)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		c.DelTable(t) // same transaction as the re-create below
	}
	buildLayout(c)
	return c.Flush()
}

func buildLayout(c *nftables.Conn) {
	tab := c.AddTable(ourTable())
	sets := make(map[string]*nftables.Set, len(setSpecs))
	for _, s := range setSpecs {
		set := &nftables.Set{
			Table:      tab,
			Name:       s.name,
			KeyType:    keyType(s.v6),
			Interval:   s.interval,
			HasTimeout: s.timeout,
		}
		// Elements are added later; AddSet only fails on anonymous sets.
		_ = c.AddSet(set, nil)
		sets[s.name] = set
	}
	policy := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    tab,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(-10),
		Policy:   &policy,
	})
	for _, r := range ruleSpecs {
		c.AddRule(&nftables.Rule{Table: tab, Chain: ch, Exprs: ruleExprs(r, sets[r.set])})
	}
}

func ruleExprs(r ruleSpec, set *nftables.Set) []expr.Any {
	proto, off, n := byte(unix.NFPROTO_IPV4), uint32(12), uint32(4) // ip saddr
	if r.v6 {
		proto, off, n = unix.NFPROTO_IPV6, 8, 16 // ip6 saddr
	}
	e := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}
	if r.limit {
		e = append(e, &expr.Limit{Type: expr.LimitTypePkts, Rate: 2, Unit: expr.LimitTimeSecond, Burst: 4, Over: true})
	}
	return append(e, &expr.Verdict{Kind: r.verdict})
}

// layoutMatches reports whether the existing table has exactly the spec
// layout: 8 sets with the right key type and flags, one input chain with the
// right hook/priority/policy, and the 8 rules in order.
func layoutMatches(c *nftables.Conn, t *nftables.Table) (bool, error) {
	if ok, err := setsMatch(c, t); !ok || err != nil {
		return false, err
	}
	ch, err := ourChain(c)
	if ch == nil || err != nil {
		return false, err
	}
	rules, err := c.GetRules(t, ch)
	if err != nil || len(rules) != len(ruleSpecs) {
		return false, err
	}
	for i, r := range rules {
		if !ruleMatches(r, ruleSpecs[i]) {
			return false, nil
		}
	}
	return true, nil
}

func setsMatch(c *nftables.Conn, t *nftables.Table) (bool, error) {
	sets, err := c.GetSets(t)
	if err != nil || len(sets) != len(setSpecs) {
		return false, err
	}
	byName := make(map[string]*nftables.Set, len(sets))
	for _, s := range sets {
		byName[s.Name] = s
	}
	for _, w := range setSpecs {
		s := byName[w.name]
		if s == nil || s.KeyType.Name != keyType(w.v6).Name || s.Interval != w.interval ||
			s.HasTimeout != w.timeout || s.IsMap || s.Anonymous {
			return false, nil
		}
	}
	return true, nil
}

// ourChain returns the single, correctly configured input chain, or nil.
func ourChain(c *nftables.Conn) (*nftables.Chain, error) {
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	var ours []*nftables.Chain
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == TableName {
			ours = append(ours, ch)
		}
	}
	if len(ours) != 1 {
		return nil, nil
	}
	ch := ours[0]
	if ch.Name != chainName || ch.Type != nftables.ChainTypeFilter ||
		ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookInput ||
		ch.Priority == nil || *ch.Priority != -10 ||
		ch.Policy == nil || *ch.Policy != nftables.ChainPolicyAccept {
		return nil, nil
	}
	return ch, nil
}

func ruleMatches(r *nftables.Rule, w ruleSpec) bool {
	var set string
	verdict, limit := expr.VerdictKind(-99), false
	for _, e := range r.Exprs {
		switch x := e.(type) {
		case *expr.Lookup:
			set = x.SetName
		case *expr.Verdict:
			verdict = x.Kind
		case *expr.Limit:
			limit = x.Type == expr.LimitTypePkts && x.Rate == 2 && x.Unit == expr.LimitTimeSecond &&
				x.Burst == 4 && x.Over
		}
	}
	return set == w.set && verdict == w.verdict && limit == w.limit
}

// ---- Flush ---------------------------------------------------------------

func (f *nftFW) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil || t == nil {
		return err
	}
	c.DelTable(t)
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// ---- address ranges ------------------------------------------------------

// span is a half-open address range [lo, hi). open means hi is beyond the
// end of the address space (no end element exists).
type span struct {
	lo, hi  netip.Addr
	open    bool
	expires time.Duration
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

func (s span) contains(o span) bool {
	if o.lo.Compare(s.lo) < 0 {
		return false
	}
	if s.open {
		return true
	}
	return !o.open && o.hi.Compare(s.hi) <= 0
}

func (s span) equal(o span) bool {
	return s.lo == o.lo && s.open == o.open && (s.open || s.hi == o.hi)
}

func (s span) elems(ttl time.Duration) []nftables.SetElement {
	el := []nftables.SetElement{{Key: s.lo.AsSlice(), Timeout: ttl}}
	if !s.open {
		el = append(el, nftables.SetElement{Key: s.hi.AsSlice(), IntervalEnd: true})
	}
	return el
}

// parseSpans pairs interval start/end elements into ranges.
func parseSpans(elems []nftables.SetElement) []span {
	es := slices.Clone(elems)
	sort.SliceStable(es, func(i, j int) bool {
		if c := bytes.Compare(es[i].Key, es[j].Key); c != 0 {
			return c < 0
		}
		return es[i].IntervalEnd && !es[j].IntervalEnd // an end closes the previous range first
	})
	var out []span
	var cur *span
	for i := range es {
		e := &es[i]
		a, ok := netip.AddrFromSlice(e.Key)
		if !ok {
			continue
		}
		switch {
		case !e.IntervalEnd:
			if cur != nil {
				cur.open = true
				out = append(out, *cur)
			}
			cur = &span{lo: a, expires: e.Expires}
		case cur != nil:
			cur.hi = a
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		cur.open = true
		out = append(out, *cur)
	}
	return out
}

// ---- Add / Remove / SetAllow ---------------------------------------------

func (f *nftFW) set(c *nftables.Conn, t *nftables.Table, name string) (*nftables.Set, error) {
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return nil, fmt.Errorf("nft: set %s: %w (was Ensure called?)", name, err)
	}
	return s, nil
}

func (f *nftFW) Add(k Kind, p netip.Prefix, ttl time.Duration) error {
	np, err := validateAdd(k, p, ttl)
	if err != nil {
		return err
	}
	if k == KindPerm {
		ttl = 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := ourTable()
	v6 := np.Addr().Is6()
	base := map[Kind]string{KindBan: "ban", KindPerm: "perm", KindRateLimit: "ratelim"}[k]
	s, err := f.set(c, t, setName(base, v6))
	if err != nil {
		return err
	}
	existing, err := c.GetSetElements(s)
	if err != nil {
		return err
	}
	if !s.Interval {
		return addPlain(c, s, existing, np, ttl)
	}
	return addInterval(c, s, existing, prefixSpan(np), ttl)
}

func addPlain(c *nftables.Conn, s *nftables.Set, existing []nftables.SetElement, p netip.Prefix, ttl time.Duration) error {
	key := p.Addr().AsSlice()
	for i := range existing {
		if bytes.Equal(existing[i].Key, key) {
			if err := c.SetDeleteElements(s, []nftables.SetElement{{Key: key}}); err != nil {
				return err
			}
			break
		}
	}
	if err := c.SetAddElements(s, []nftables.SetElement{{Key: key, Timeout: ttl}}); err != nil {
		return err
	}
	return c.Flush()
}

// addInterval inserts a range into an interval set. The kernel rejects
// overlapping ranges, so narrower existing entries are replaced by the new
// wider one, and a range already covered by a wider entry is left to it.
func addInterval(c *nftables.Conn, s *nftables.Set, existing []nftables.SetElement, n span, ttl time.Duration) error {
	for _, o := range parseSpans(existing) {
		switch {
		case o.equal(n):
			if err := c.SetDeleteElements(s, o.elems(0)); err != nil {
				return err
			}
		case o.contains(n):
			return nil // already blocked by a wider entry
		case n.contains(o):
			if err := c.SetDeleteElements(s, o.elems(0)); err != nil {
				return err
			}
		}
	}
	if err := c.SetAddElements(s, n.elems(ttl)); err != nil {
		return err
	}
	return c.Flush()
}

func (f *nftFW) Remove(p netip.Prefix) error {
	np, err := normalize(p)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil || t == nil {
		return err
	}
	single := np.Bits() == np.Addr().BitLen()
	changed := false
	for _, base := range []string{"ban", "perm", "ratelim"} {
		if base == "ratelim" && !single {
			continue
		}
		s, err := f.set(c, t, setName(base, np.Addr().Is6()))
		if err != nil {
			return err
		}
		n, err := removeFromSet(c, s, np)
		if err != nil {
			return err
		}
		changed = changed || n > 0
	}
	if !changed {
		return nil
	}
	return c.Flush()
}

// removeFromSet queues deletion of exactly p from s and returns how many
// entries it queued.
func removeFromSet(c *nftables.Conn, s *nftables.Set, p netip.Prefix) (int, error) {
	existing, err := c.GetSetElements(s)
	if err != nil {
		return 0, err
	}
	if !s.Interval {
		key := p.Addr().AsSlice()
		for i := range existing {
			if bytes.Equal(existing[i].Key, key) {
				return 1, c.SetDeleteElements(s, []nftables.SetElement{{Key: key}})
			}
		}
		return 0, nil
	}
	n := prefixSpan(p)
	for _, o := range parseSpans(existing) {
		if o.equal(n) {
			return 1, c.SetDeleteElements(s, o.elems(0))
		}
	}
	return 0, nil
}

// mergePrefixes drops duplicates and prefixes covered by a wider one, so the
// interval set never receives overlapping ranges.
func mergePrefixes(ps []netip.Prefix) []netip.Prefix {
	s := slices.Clone(ps)
	sort.Slice(s, func(i, j int) bool {
		if c := s[i].Addr().Compare(s[j].Addr()); c != 0 {
			return c < 0
		}
		return s[i].Bits() < s[j].Bits()
	})
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		if n := len(out); n > 0 && out[n-1].Overlaps(p) {
			continue // sorted: the earlier one is the wider (or equal)
		}
		out = append(out, p)
	}
	return out
}

func (f *nftFW) SetAllow(ps []netip.Prefix) error {
	nps, err := normalizeAll(ps)
	if err != nil {
		return err
	}
	var v4, v6 []netip.Prefix
	for _, p := range nps {
		if p.Addr().Is6() {
			v6 = append(v6, p)
		} else {
			v4 = append(v4, p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := ourTable()
	for _, g := range []struct {
		name string
		ps   []netip.Prefix
	}{{"allow4", mergePrefixes(v4)}, {"allow6", mergePrefixes(v6)}} {
		s, err := f.set(c, t, g.name)
		if err != nil {
			return err
		}
		c.FlushSet(s)
		var el []nftables.SetElement
		for _, p := range g.ps {
			el = append(el, prefixSpan(p).elems(0)...)
		}
		if len(el) > 0 {
			if err := c.SetAddElements(s, el); err != nil {
				return err
			}
		}
	}
	return c.Flush()
}
