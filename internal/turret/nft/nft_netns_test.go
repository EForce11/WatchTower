//go:build netns

package nft

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const dialTimeout = 500 * time.Millisecond

// ---- helpers -------------------------------------------------------------

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if f() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func newConn(t *testing.T) *nftables.Conn {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	return c
}

func inetTable(name string) *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: name}
}

func tableExists(t *testing.T, name string) bool {
	t.Helper()
	tabs, err := newConn(t).ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tabs {
		if tb.Name == name {
			return true
		}
	}
	return false
}

func setElems(t *testing.T, set string) []nftables.SetElement {
	t.Helper()
	c := newConn(t)
	s, err := c.GetSetByName(inetTable(TableName), set)
	if err != nil {
		t.Fatalf("GetSetByName(%s): %v", set, err)
	}
	el, err := c.GetSetElements(s)
	if err != nil {
		t.Fatalf("GetSetElements(%s): %v", set, err)
	}
	return el
}

// hasStart reports whether set holds a (start) element with the given address.
func hasStart(t *testing.T, set string, a netip.Addr) bool {
	t.Helper()
	el := setElems(t, set)
	for i := range el {
		if !el[i].IntervalEnd && bytes.Equal(el[i].Key, a.AsSlice()) {
			return true
		}
	}
	return false
}

func newFW(t *testing.T) Firewall {
	t.Helper()
	fw, err := NewNFT()
	if err != nil {
		t.Fatalf("NewNFT: %v", err)
	}
	t.Cleanup(func() { _ = fw.Flush() })
	return fw
}

type peer struct {
	ns netns.NsHandle
}

// newPeer creates netns B connected to the current netns (A) by a veth pair;
// A=10.99.0.1/24, B=10.99.0.2/24.
func newPeer(t *testing.T) *peer {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	bns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New: %v", err)
	}
	if err := netns.Set(origin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bns.Close() })

	la := netlink.NewLinkAttrs()
	la.Name = "wta0"
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: "wtb0"}); err != nil {
		t.Fatalf("veth add: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName("wta0"); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	pl, err := netlink.LinkByName("wtb0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(pl, int(bns)); err != nil {
		t.Fatalf("move peer: %v", err)
	}
	al, err := netlink.LinkByName("wta0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(al, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.99.0.1"), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(al); err != nil {
		t.Fatal(err)
	}
	h, err := netlink.NewHandleAt(bns)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	bl, err := h.LinkByName("wtb0")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddrAdd(bl, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.99.0.2"), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.LinkSetUp(bl); err != nil {
		t.Fatal(err)
	}
	return &peer{ns: bns}
}

// dial connects from B to addr. The goroutine is locked to B's netns and
// exits still locked, so the runtime discards the thread.
func (p *peer) dial(addr string) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(p.ns); err != nil {
			ch <- err
			return
		}
		c, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err == nil {
			_ = c.Close()
		}
		ch <- err
	}()
	return <-ch
}

func listenA(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "10.99.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().String()
}

func mustReach(t *testing.T, p *peer, addr string) {
	t.Helper()
	if err := p.dial(addr); err != nil {
		t.Fatalf("expected connect to succeed: %v", err)
	}
}

func mustBeBlocked(t *testing.T, p *peer, addr string) {
	t.Helper()
	err := p.dial(addr)
	if err == nil {
		t.Fatal("expected connect to be blocked")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}

// ---- layout --------------------------------------------------------------

var wantSets = []struct {
	name     string
	key      nftables.SetDatatype
	interval bool
	timeout  bool
}{
	{"ban4", nftables.TypeIPAddr, true, true},
	{"ban6", nftables.TypeIP6Addr, true, true},
	{"perm4", nftables.TypeIPAddr, true, false},
	{"perm6", nftables.TypeIP6Addr, true, false},
	{"ratelim4", nftables.TypeIPAddr, false, true},
	{"ratelim6", nftables.TypeIP6Addr, false, true},
	{"allow4", nftables.TypeIPAddr, true, false},
	{"allow6", nftables.TypeIP6Addr, true, false},
}

var wantRules = []struct {
	set     string
	verdict expr.VerdictKind
	limit   bool
}{
	{"allow4", expr.VerdictAccept, false},
	{"allow6", expr.VerdictAccept, false},
	{"perm4", expr.VerdictDrop, false},
	{"perm6", expr.VerdictDrop, false},
	{"ban4", expr.VerdictDrop, false},
	{"ban6", expr.VerdictDrop, false},
	{"ratelim4", expr.VerdictDrop, true},
	{"ratelim6", expr.VerdictDrop, true},
}

func assertLayout(t *testing.T) {
	t.Helper()
	if !tableExists(t, TableName) {
		t.Fatal("table inet watchtower missing")
	}
	c := newConn(t)
	assertSets(t, c)
	in := assertChain(t, c)
	assertRules(t, c, in)
}

func assertSets(t *testing.T, c *nftables.Conn) {
	t.Helper()
	sets, err := c.GetSets(inetTable(TableName))
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != len(wantSets) {
		t.Fatalf("got %d sets, want %d", len(sets), len(wantSets))
	}
	byName := map[string]*nftables.Set{}
	for _, s := range sets {
		byName[s.Name] = s
	}
	for _, w := range wantSets {
		s := byName[w.name]
		if s == nil {
			t.Fatalf("set %s missing", w.name)
		}
		if s.KeyType.Name != w.key.Name || s.Interval != w.interval || s.HasTimeout != w.timeout {
			t.Errorf("set %s: key=%s interval=%v timeout=%v; want key=%s interval=%v timeout=%v",
				w.name, s.KeyType.Name, s.Interval, s.HasTimeout, w.key.Name, w.interval, w.timeout)
		}
	}
}

func assertChain(t *testing.T, c *nftables.Conn) *nftables.Chain {
	t.Helper()
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	var in *nftables.Chain
	for _, ch := range chains {
		if ch.Table.Name == TableName {
			if in != nil {
				t.Fatal("more than one chain")
			}
			in = ch
		}
	}
	if in == nil || in.Name != "input" {
		t.Fatalf("chain input missing: %+v", in)
	}
	if in.Hooknum == nil || *in.Hooknum != *nftables.ChainHookInput ||
		in.Priority == nil || *in.Priority != -10 ||
		in.Policy == nil || *in.Policy != nftables.ChainPolicyAccept ||
		in.Type != nftables.ChainTypeFilter {
		t.Fatalf("chain mismatch: %+v", in)
	}
	return in
}

func assertRules(t *testing.T, c *nftables.Conn, in *nftables.Chain) {
	t.Helper()
	rules, err := c.GetRules(inetTable(TableName), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(wantRules) {
		t.Fatalf("got %d rules, want %d", len(rules), len(wantRules))
	}
	for i, r := range rules {
		var set string
		var verdict expr.VerdictKind = -99
		var limit bool
		for _, e := range r.Exprs {
			switch x := e.(type) {
			case *expr.Lookup:
				set = x.SetName
			case *expr.Verdict:
				verdict = x.Kind
			case *expr.Limit:
				limit = x.Type == expr.LimitTypePkts && x.Rate == 2 && x.Unit == expr.LimitTimeSecond && x.Burst == 4 && x.Over
			}
		}
		w := wantRules[i]
		if set != w.set || verdict != w.verdict || limit != w.limit {
			t.Errorf("rule %d: set=%q verdict=%v limit=%v; want %+v", i, set, verdict, limit, w)
		}
	}
}

func TestEnsureCreatesLayout(t *testing.T) {
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	assertLayout(t)

	if err := fw.Add(KindBan, netip.MustParsePrefix("203.0.113.7/32"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	assertLayout(t)
	if !hasStart(t, "ban4", netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("second Ensure must keep existing elements")
	}
}

func TestEnsureRecreatesOnMismatch(t *testing.T) {
	t.Run("different chain priority", func(t *testing.T) {
		c := newConn(t)
		tab := c.AddTable(inetTable(TableName))
		pol := nftables.ChainPolicyAccept
		c.AddChain(&nftables.Chain{Name: "input", Table: tab, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(5), Policy: &pol})
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
		fw := newFW(t)
		if err := fw.Ensure(); err != nil {
			t.Fatal(err)
		}
		assertLayout(t)
	})
	t.Run("missing rule drops contents", func(t *testing.T) {
		fw := newFW(t)
		if err := fw.Ensure(); err != nil {
			t.Fatal(err)
		}
		if err := fw.Add(KindBan, netip.MustParsePrefix("203.0.113.9/32"), time.Hour); err != nil {
			t.Fatal(err)
		}
		c := newConn(t)
		tab := inetTable(TableName)
		ch, err := c.ListChain(tab, "input")
		if err != nil {
			t.Fatal(err)
		}
		rules, err := c.GetRules(tab, ch)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.DelRule(rules[len(rules)-1]); err != nil {
			t.Fatal(err)
		}
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := fw.Ensure(); err != nil {
			t.Fatal(err)
		}
		assertLayout(t)
		if hasStart(t, "ban4", netip.MustParseAddr("203.0.113.9")) {
			t.Fatal("recreated table should be empty")
		}
	})
}

// ---- behavior -----------------------------------------------------------

func TestBanBlocksTrafficAndAllowWins(t *testing.T) {
	p := newPeer(t)
	addr := listenA(t)
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	b := netip.MustParsePrefix("10.99.0.2/32")

	mustReach(t, p, addr)
	if err := fw.Add(KindBan, b, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	mustBeBlocked(t, p, addr)

	if err := fw.SetAllow([]netip.Prefix{b}); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)

	if err := fw.SetAllow(nil); err != nil {
		t.Fatal(err)
	}
	mustBeBlocked(t, p, addr)
	if err := fw.Remove(b); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)
}

func TestPermBlocksUntilRemoved(t *testing.T) {
	p := newPeer(t)
	addr := listenA(t)
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	b := netip.MustParsePrefix("10.99.0.2/32")
	if err := fw.Add(KindPerm, b, 0); err != nil {
		t.Fatal(err)
	}
	mustBeBlocked(t, p, addr)
	if err := fw.Remove(b); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)
}

func TestTimeoutExpires(t *testing.T) {
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("198.51.100.20")
	if err := fw.Add(KindBan, netip.PrefixFrom(a, 32), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if !hasStart(t, "ban4", a) {
		t.Fatal("ban not present after Add")
	}
	eventually(t, 6*time.Second, "ban to expire", func() bool { return !hasStart(t, "ban4", a) })
}

func TestFlushRestoresConnectivity(t *testing.T) {
	p := newPeer(t)
	addr := listenA(t)
	fw := newFW(t)
	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush on missing table: %v", err)
	}
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.2/32"), time.Minute); err != nil {
		t.Fatal(err)
	}
	mustBeBlocked(t, p, addr)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)
	if tableExists(t, TableName) {
		t.Fatal("table still exists after Flush")
	}
	if err := fw.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
}

func TestCIDRBan(t *testing.T) {
	p := newPeer(t)
	addr := listenA(t)
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	if err := fw.Add(KindBan, cidr, time.Minute); err != nil {
		t.Fatal(err)
	}
	mustBeBlocked(t, p, addr)
	if err := fw.Remove(cidr); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)
}

func TestNestedPrefixesDoNotError(t *testing.T) {
	p := newPeer(t)
	addr := listenA(t)
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	host := netip.MustParsePrefix("10.99.0.2/32")
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	if err := fw.Add(KindBan, host, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Wider prefix subsumes the host entry (limiter escalation).
	if err := fw.Add(KindBan, cidr, time.Minute); err != nil {
		t.Fatalf("wider prefix over existing host: %v", err)
	}
	mustBeBlocked(t, p, addr)
	// Narrower prefix inside an existing wider one is already covered.
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.77/32"), time.Minute); err != nil {
		t.Fatalf("host inside existing cidr: %v", err)
	}
	if err := fw.Remove(cidr); err != nil {
		t.Fatal(err)
	}
	mustReach(t, p, addr)
}

func ensured(t *testing.T) Firewall {
	t.Helper()
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestAddRefreshesExisting(t *testing.T) {
	fw := ensured(t)
	one := netip.MustParsePrefix("192.0.2.1/32")
	if err := fw.Add(KindBan, one, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, one, time.Hour); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	el := setElems(t, "ban4")
	for i := range el {
		if !el[i].IntervalEnd && bytes.Equal(el[i].Key, one.Addr().AsSlice()) && el[i].Expires < 30*time.Minute {
			t.Fatalf("timeout not refreshed: expires=%v", el[i].Expires)
		}
	}
	rl := netip.MustParsePrefix("192.0.2.9/32")
	for i := 0; i < 2; i++ {
		if err := fw.Add(KindRateLimit, rl, time.Minute); err != nil {
			t.Fatalf("ratelim add #%d: %v", i, err)
		}
	}
}

func TestAddPicksSetByFamilyAndKind(t *testing.T) {
	fw := ensured(t)
	cases := []struct {
		k    Kind
		p    string
		set  string
		addr string
	}{
		{KindBan, "::ffff:192.0.2.2/128", "ban4", "192.0.2.2"},
		{KindBan, "2001:db8::/32", "ban6", "2001:db8::"},
		{KindPerm, "2001:db9::/32", "perm6", "2001:db9::"},
		{KindPerm, "198.18.0.0/15", "perm4", "198.18.0.0"},
		{KindRateLimit, "192.0.2.9/32", "ratelim4", "192.0.2.9"},
		{KindRateLimit, "2001:db8:1::5/128", "ratelim6", "2001:db8:1::5"},
	}
	for _, tc := range cases {
		if err := fw.Add(tc.k, netip.MustParsePrefix(tc.p), time.Hour); err != nil {
			t.Fatalf("%v %s: %v", tc.k, tc.p, err)
		}
		if !hasStart(t, tc.set, netip.MustParseAddr(tc.addr)) {
			t.Errorf("%v %s: not found in %s", tc.k, tc.p, tc.set)
		}
	}
	rl := netip.MustParsePrefix("192.0.2.9/32")
	if err := fw.Remove(rl); err != nil {
		t.Fatal(err)
	}
	if hasStart(t, "ratelim4", rl.Addr()) {
		t.Fatal("ratelim4 element not removed")
	}
	// Removing something that is not there is fine.
	if err := fw.Remove(netip.MustParsePrefix("192.0.2.200/32")); err != nil {
		t.Fatal(err)
	}
}

func TestAddValidationErrors(t *testing.T) {
	fw := ensured(t)
	one := netip.MustParsePrefix("192.0.2.1/32")
	if err := fw.Add(KindRateLimit, netip.MustParsePrefix("192.0.2.0/24"), time.Minute); err == nil {
		t.Fatal("ratelimit of a prefix must fail")
	}
	if err := fw.Add(KindBan, one, 0); err == nil {
		t.Fatal("ban with zero ttl must fail")
	}
	if err := fw.Add(KindBan, one, -time.Second); err == nil {
		t.Fatal("ban with negative ttl must fail")
	}
}

func TestSetAllowReplacesAndMergesOverlap(t *testing.T) {
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	// Overlapping and duplicate input must not break the transaction.
	err := fw.SetAllow([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasStart(t, "allow4", netip.MustParseAddr("10.0.0.0")) || hasStart(t, "allow4", netip.MustParseAddr("10.1.0.0")) {
		t.Fatal("allow4 should hold only the merged /8")
	}
	if !hasStart(t, "allow6", netip.MustParseAddr("fd00::")) {
		t.Fatal("allow6 missing")
	}
	if err := fw.SetAllow([]netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}); err != nil {
		t.Fatal(err)
	}
	if hasStart(t, "allow4", netip.MustParseAddr("10.0.0.0")) || hasStart(t, "allow6", netip.MustParseAddr("fd00::")) {
		t.Fatal("old allow entries must be replaced")
	}
	if !hasStart(t, "allow4", netip.MustParseAddr("172.16.0.0")) {
		t.Fatal("new allow entry missing")
	}
}

func TestOtherTablesUntouched(t *testing.T) {
	c := newConn(t)
	c.AddTable(inetTable("other"))
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cc := newConn(t)
		cc.DelTable(inetTable("other"))
		_ = cc.Flush()
	})
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	if !tableExists(t, "other") {
		t.Fatal("other table lost after Ensure")
	}
	if err := fw.SetAllow([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	if !tableExists(t, "other") {
		t.Fatal("other table lost after SetAllow")
	}
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	if !tableExists(t, "other") {
		t.Fatal("other table lost after Flush")
	}
	if tableExists(t, TableName) {
		t.Fatal("watchtower table should be gone")
	}
}
