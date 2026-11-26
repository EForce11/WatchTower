package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
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

// expiryMargin is added to every kernel element timeout. While Turret runs,
// the expiry timer (see schedule) rewrites a set at the earliest record
// deadline, so the kernel never expires an element itself: kernel GC of an
// interval element adjacent to another one is not something to depend on.
// The kernel timeout stays as a backstop when Turret is down, so a ban lasts
// at most expiryMargin longer than requested and never shorter.
const expiryMargin = 5 * time.Second

// expiryRetry is how soon a failed expiry rewrite is retried.
const expiryRetry = time.Second

type nftFW struct {
	mu     sync.Mutex // serializes read-modify-write sequences; guards all fields
	now    func() time.Time
	recs   map[string]*recordSet // set name -> requested entries; nil until loaded
	timer  *time.Timer           // fires at the earliest record deadline; nil if none
	closed bool
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
	return &nftFW{now: time.Now}, nil
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
			// Keep contents, remember them for later rewrites.
			if err := f.load(c, t); err != nil {
				return err
			}
			f.schedule()
			return nil
		}
		c.DelTable(t) // same transaction as the re-create below
	}
	buildLayout(c)
	if err := c.Flush(); err != nil {
		f.recs = nil
		return err
	}
	f.recs = map[string]*recordSet{}
	for _, sp := range setSpecs {
		f.recs[sp.name] = &recordSet{}
	}
	f.schedule()
	return nil
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
		// NOTE: one shared token bucket for ALL addresses in the ratelim set
		// (aggregate, not per-source), exactly as spec 3.4.2 (R10).
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

// ruleMatches compares the kernel's expression list with the one we would
// install (set IDs are per-transaction and ignored), so any tampering such as
// a daddr match or a changed limit triggers a recreate.
func ruleMatches(r *nftables.Rule, w ruleSpec) bool {
	want := ruleExprs(w, &nftables.Set{Name: w.set})
	return reflect.DeepEqual(stripIDs(r.Exprs), stripIDs(want))
}

func stripIDs(in []expr.Any) []expr.Any {
	out := make([]expr.Any, len(in))
	for i, e := range in {
		if l, ok := e.(*expr.Lookup); ok {
			cp := *l
			cp.SetID = 0
			e = &cp
		}
		out[i] = e
	}
	return out
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
	f.recs = nil
	f.schedule()
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// ---- records and rewrites -------------------------------------------------
//
// The kernel rejects overlapping interval elements, and an overlapping
// narrower entry would otherwise shorten or drop a longer ban. So every
// mutation updates an in-process record of what was requested (exact span ->
// absolute deadline) and then rewrites the whole affected set in one
// transaction from a sweep over all records (see recordSet.segments).

func baseName(k Kind) string {
	switch k {
	case KindPerm:
		return "perm"
	case KindRateLimit:
		return "ratelim"
	default:
		return "ban"
	}
}

func (f *nftFW) set(c *nftables.Conn, t *nftables.Table, name string) (*nftables.Set, error) {
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return nil, fmt.Errorf("nft: set %s: %w (was Ensure called?)", name, err)
	}
	return s, nil
}

// load imports the kernel's current ban/perm/ratelim elements as records.
func (f *nftFW) load(c *nftables.Conn, t *nftables.Table) error {
	recs := map[string]*recordSet{}
	now := f.now()
	for _, sp := range setSpecs {
		if strings.HasPrefix(sp.name, "allow") {
			continue
		}
		s, err := f.set(c, t, sp.name)
		if err != nil {
			return err
		}
		el, err := c.GetSetElements(s)
		if err != nil {
			return err
		}
		rs := &recordSet{}
		// The kernel timeout carries expiryMargin on top of the requested
		// deadline; an element left only with its margin is already due and
		// is pruned by the first rewrite.
		deadline := func(e time.Duration) time.Time {
			if !sp.timeout {
				return time.Time{}
			}
			return now.Add(e - expiryMargin)
		}
		if s.Interval {
			spans, err := parseSpans(el)
			if err != nil {
				return fmt.Errorf("nft: import %s: %w", sp.name, err)
			}
			for _, e := range spans {
				*rs = append(*rs, record{span: e.span, deadline: deadline(e.expires)})
			}
		} else {
			for i := range el {
				a, ok := netip.AddrFromSlice(el[i].Key)
				if !ok {
					return fmt.Errorf("nft: import %s: malformed key", sp.name)
				}
				*rs = append(*rs, record{span: prefixSpan(netip.PrefixFrom(a, a.BitLen())), deadline: deadline(el[i].Expires)})
			}
		}
		recs[sp.name] = rs
	}
	f.recs = recs
	return nil
}

// ensureLoaded imports records on first use (table must exist).
func (f *nftFW) ensureLoaded(c *nftables.Conn) (*nftables.Table, error) {
	t, err := findTable(c)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, errors.New("nft: table watchtower missing (was Ensure called?)")
	}
	if f.recs == nil {
		if err := f.load(c, t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// rewrite replaces the contents of one set with the sweep of its records in a
// single transaction. Expired records are dropped first.
func (f *nftFW) rewrite(c *nftables.Conn, t *nftables.Table, name string) error {
	if err := f.queueRewrite(c, t, name); err != nil {
		return err
	}
	return c.Flush()
}

// queueRewrite queues the set rewrite on c without committing it.
func (f *nftFW) queueRewrite(c *nftables.Conn, t *nftables.Table, name string) error {
	s, err := f.set(c, t, name)
	if err != nil {
		return err
	}
	now := f.now()
	rs := f.recs[name]
	rs.prune(now)
	var el []nftables.SetElement
	if s.Interval {
		for _, seg := range rs.segments(now) {
			el = append(el, seg.elems(timeoutFor(seg.deadline, now))...)
		}
	} else {
		for i := range *rs {
			r := &(*rs)[i]
			el = append(el, nftables.SetElement{Key: r.lo.AsSlice(), Timeout: timeoutFor(r.deadline, now)})
		}
	}
	c.FlushSet(s)
	if len(el) > 0 {
		if err := c.SetAddElements(s, el); err != nil {
			return err
		}
	}
	return nil
}

// Replace makes entries the whole content of the ban, perm and ratelim sets
// in one transaction (the table's bans.json-style source of truth wins over
// whatever Ensure imported from the kernel).
func (f *nftFW) Replace(entries []Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.schedule()
	es, err := validateEntries(entries, f.now())
	if err != nil {
		return err
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("nft: table watchtower missing (was Ensure called?)")
	}
	recs := map[string]*recordSet{}
	for _, sp := range setSpecs {
		if !strings.HasPrefix(sp.name, "allow") {
			recs[sp.name] = &recordSet{}
		}
	}
	for _, e := range es {
		recs[setName(baseName(e.Kind), e.Prefix.Addr().Is6())].add(prefixSpan(e.Prefix), e.Deadline)
	}
	old := f.recs
	f.recs = recs
	for _, sp := range setSpecs {
		if strings.HasPrefix(sp.name, "allow") {
			continue
		}
		if err := f.queueRewrite(c, t, sp.name); err != nil {
			f.recs = old
			return err
		}
	}
	if err := c.Flush(); err != nil {
		f.recs = old
		return err
	}
	return nil
}

// Add never shortens: the address stays blocked until the latest deadline of
// any entry covering it, and re-adding keeps the later of old and new.
func (f *nftFW) Add(k Kind, p netip.Prefix, ttl time.Duration) error {
	np, err := validateAdd(k, p, ttl)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.schedule()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := f.ensureLoaded(c)
	if err != nil {
		return err
	}
	name := setName(baseName(k), np.Addr().Is6())
	var deadline time.Time
	if k != KindPerm {
		deadline = f.now().Add(ttl)
	}
	rs := f.recs[name]
	old := slices.Clone(*rs)
	rs.add(prefixSpan(np), deadline)
	if err := f.rewrite(c, t, name); err != nil {
		*rs = old
		return err
	}
	return nil
}

// Remove deletes exactly the record p. Addresses still covered by other
// (wider or narrower-overlapping) records stay blocked.
func (f *nftFW) Remove(p netip.Prefix) error {
	np, err := normalize(p)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.schedule()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil || t == nil {
		return err
	}
	if f.recs == nil {
		if err := f.load(c, t); err != nil {
			return err
		}
	}
	single := np.Bits() == np.Addr().BitLen()
	for _, base := range []string{"ban", "perm", "ratelim"} {
		if base == "ratelim" && !single {
			continue
		}
		name := setName(base, np.Addr().Is6())
		rs := f.recs[name]
		old := slices.Clone(*rs)
		if !rs.remove(prefixSpan(np)) {
			continue
		}
		if err := f.rewrite(c, t, name); err != nil {
			*rs = old
			return err
		}
	}
	return nil
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

// ---- expiry ----------------------------------------------------------------

// Close stops the expiry timer. Elements already in the kernel keep their
// backstop timeouts. It is safe to call more than once.
func (f *nftFW) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.stopTimer()
	return nil
}

func (f *nftFW) stopTimer() {
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
}

// arm (re)sets the single expiry timer to fire after d; f.mu is held.
func (f *nftFW) arm(d time.Duration) {
	if f.closed {
		return
	}
	if f.timer == nil {
		f.timer = time.AfterFunc(max(d, 0), f.expire)
		return
	}
	f.timer.Reset(max(d, 0))
}

// schedule points the expiry timer at the earliest live record deadline (or
// stops it when there is none); f.mu is held.
func (f *nftFW) schedule() {
	var next time.Time
	for _, rs := range f.recs {
		for i := range *rs {
			if dl := (*rs)[i].deadline; !dl.IsZero() && (next.IsZero() || dl.Before(next)) {
				next = dl
			}
		}
	}
	if next.IsZero() {
		f.stopTimer()
		return
	}
	f.arm(next.Sub(f.now()))
}

// expire is the timer callback: it rewrites, in one transaction, every set
// holding a record whose deadline has passed, then reschedules. It takes
// f.mu; Close never waits for it, so the two cannot deadlock.
func (f *nftFW) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.recs == nil {
		return
	}
	if err := f.rewriteExpired(); err != nil {
		f.arm(expiryRetry)
		return
	}
	f.schedule()
}

func (f *nftFW) rewriteExpired() error {
	now := f.now()
	var due []string
	for _, sp := range setSpecs {
		rs := f.recs[sp.name]
		if !sp.timeout || rs == nil {
			continue
		}
		if slices.ContainsFunc(*rs, func(r record) bool { return !r.live(now) }) {
			due = append(due, sp.name)
		}
	}
	if len(due) == 0 {
		return nil
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := findTable(c)
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("nft: table watchtower missing")
	}
	old := make(map[string]recordSet, len(due))
	for _, name := range due {
		old[name] = slices.Clone(*f.recs[name])
		if err := f.queueRewrite(c, t, name); err != nil {
			f.restore(old)
			return err
		}
	}
	if err := c.Flush(); err != nil {
		f.restore(old)
		return err
	}
	return nil
}

func (f *nftFW) restore(old map[string]recordSet) {
	for name, rs := range old {
		*f.recs[name] = rs
	}
}
