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
	// The thread stays locked until we are back in the origin netns; if
	// restoring fails the test goroutine exits locked and the runtime
	// discards the thread instead of reusing it in the wrong namespace.
	runtime.LockOSThread()
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
		t.Fatal(err) // deliberately still locked
	}
	runtime.UnlockOSThread()
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
	configurePeerSide(t, bns)
	return &peer{ns: bns}
}

func configurePeerSide(t *testing.T, bns netns.NsHandle) {
	t.Helper()
	h, err := netlink.NewHandleAt(bns)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	bl, err := h.LinkByName("wtb0")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.99.0.2", "10.99.0.3"} {
		if err := h.AddrAdd(bl, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.LinkSetUp(bl); err != nil {
		t.Fatal(err)
	}
}

// dial connects from B to addr. The goroutine is locked to B's netns and
// exits still locked, so the runtime discards the thread.
func (p *peer) dial(addr string) error { return p.dialFrom("", addr) }

// dialFrom is dial with an explicit source address ("" = default).
func (p *peer) dialFrom(local, addr string) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(p.ns); err != nil {
			ch <- err
			return
		}
		d := net.Dialer{Timeout: dialTimeout}
		if local != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
		}
		c, err := d.Dial("tcp", addr)
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
	mustBeBlockedFrom(t, p, "", addr)
}

func mustReachFrom(t *testing.T, p *peer, local, addr string) {
	t.Helper()
	if err := p.dialFrom(local, addr); err != nil {
		t.Fatalf("expected connect from %s to succeed: %v", local, err)
	}
}

func mustBeBlockedFrom(t *testing.T, p *peer, local, addr string) {
	t.Helper()
	err := p.dialFrom(local, addr)
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

func TestEnsureRecreatesOnTamperedRule(t *testing.T) {
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
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
	last := rules[len(rules)-1]
	for _, e := range last.Exprs {
		if pl, ok := e.(*expr.Payload); ok {
			pl.Offset = 24 // ip6 daddr instead of saddr
		}
	}
	if err := c.DelRule(last); err != nil {
		t.Fatal(err)
	}
	c.AddRule(&nftables.Rule{Table: tab, Chain: ch, Exprs: last.Exprs})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// Sanity: the tampered table has the same rule/set/verdict shape.
	if rs, _ := newConn(t).GetRules(tab, ch); len(rs) != len(wantRules) {
		t.Fatalf("setup: %d rules", len(rs))
	}
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	assertLayout(t)
	assertRuleOffsets(t)
}

// assertRuleOffsets checks that the saddr payload offsets are the spec ones.
func assertRuleOffsets(t *testing.T) {
	t.Helper()
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
	for i, r := range rules {
		want := uint32(12)
		if i%2 == 1 {
			want = 8
		}
		for _, e := range r.Exprs {
			if pl, ok := e.(*expr.Payload); ok && pl.Offset != want {
				t.Errorf("rule %d payload offset %d, want %d", i, pl.Offset, want)
			}
		}
	}
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

// Peer B owns 10.99.0.2 (default source) and 10.99.0.3.
const (
	bHost  = "10.99.0.2"
	bOther = "10.99.0.3"
)

func neverShortenSetup(t *testing.T) (*peer, string, Firewall) {
	t.Helper()
	p := newPeer(t)
	addr := listenA(t)
	return p, addr, ensured(t)
}

func TestNarrowerLongerInsideWiderShorter(t *testing.T) {
	p, addr, fw := neverShortenSetup(t)
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.0/24"), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.2/32"), 8*time.Second); err != nil {
		t.Fatal(err)
	}
	mustBeBlockedFrom(t, p, bOther, addr)
	time.Sleep(3 * time.Second) // /24 (2 s) is over, /32 (8 s) is not
	mustBeBlockedFrom(t, p, bHost, addr)
	mustReachFrom(t, p, bOther, addr)
}

func TestWiderShorterOverNarrowerLonger(t *testing.T) {
	p, addr, fw := neverShortenSetup(t)
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.2/32"), 8*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.0/24"), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	mustBeBlockedFrom(t, p, bOther, addr)
	time.Sleep(3 * time.Second)
	mustBeBlockedFrom(t, p, bHost, addr)
	mustReachFrom(t, p, bOther, addr)
}

func TestRemoveWiderKeepsNarrower(t *testing.T) {
	p, addr, fw := neverShortenSetup(t)
	wide := netip.MustParsePrefix("10.99.0.0/24")
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.2/32"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, wide, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := fw.Remove(wide); err != nil {
		t.Fatal(err)
	}
	mustBeBlockedFrom(t, p, bHost, addr)
	mustReachFrom(t, p, bOther, addr)
}

func TestRemoveNarrowerInsideWiderKeepsBlocking(t *testing.T) {
	p, addr, fw := neverShortenSetup(t)
	host := netip.MustParsePrefix("10.99.0.2/32")
	if err := fw.Add(KindBan, netip.MustParsePrefix("10.99.0.0/24"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, host, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := fw.Remove(host); err != nil {
		t.Fatal(err)
	}
	mustBeBlockedFrom(t, p, bHost, addr)
}

func TestEnsureImportsExistingContent(t *testing.T) {
	fw1 := ensured(t)
	x := netip.MustParsePrefix("203.0.113.1/32")
	y := netip.MustParsePrefix("203.0.113.2/32")
	if err := fw1.Add(KindBan, x, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := fw1.Add(KindPerm, netip.MustParsePrefix("198.18.0.0/15"), 0); err != nil {
		t.Fatal(err)
	}
	// A fresh instance (daemon restart) must adopt the kernel contents and
	// not lose them on its first rewrite.
	fw2, err := NewNFT()
	if err != nil {
		t.Fatal(err)
	}
	if err := fw2.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := fw2.Add(KindBan, y, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := fw2.Add(KindPerm, netip.MustParsePrefix("192.0.2.0/24"), 0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ set, addr string }{
		{"ban4", "203.0.113.1"}, {"ban4", "203.0.113.2"}, {"perm4", "198.18.0.0"}, {"perm4", "192.0.2.0"},
	} {
		if !hasStart(t, c.set, netip.MustParseAddr(c.addr)) {
			t.Errorf("%s lost %s", c.set, c.addr)
		}
	}
	if e := expiresOf(t, "ban4", x.Addr()); e < 50*time.Minute {
		t.Fatalf("imported ban lost its timeout: %v", e)
	}
}

// expiresOf returns the remaining lifetime of the element starting at a.
func expiresOf(t *testing.T, set string, a netip.Addr) time.Duration {
	t.Helper()
	el := setElems(t, set)
	for i := range el {
		if !el[i].IntervalEnd && bytes.Equal(el[i].Key, a.AsSlice()) {
			return el[i].Expires
		}
	}
	t.Fatalf("no element %s in %s", a, set)
	return 0
}

func ensured(t *testing.T) Firewall {
	t.Helper()
	fw := newFW(t)
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestAddNeverShortensTimeout(t *testing.T) {
	fw := ensured(t)
	one := netip.MustParsePrefix("192.0.2.1/32")
	if err := fw.Add(KindBan, one, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindBan, one, time.Hour); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if e := expiresOf(t, "ban4", one.Addr()); e < 59*time.Minute {
		t.Fatalf("timeout not extended: %v", e)
	}
	if err := fw.Add(KindBan, one, 5*time.Second); err != nil {
		t.Fatalf("shorter re-add: %v", err)
	}
	if e := expiresOf(t, "ban4", one.Addr()); e < 59*time.Minute {
		t.Fatalf("shorter re-add shortened the ban: %v", e)
	}
	rl := netip.MustParsePrefix("192.0.2.9/32")
	if err := fw.Add(KindRateLimit, rl, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := fw.Add(KindRateLimit, rl, time.Second); err != nil {
		t.Fatalf("ratelim re-add: %v", err)
	}
	if e := expiresOf(t, "ratelim4", rl.Addr()); e < 59*time.Minute {
		t.Fatalf("ratelim shortened: %v", e)
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

// restarted simulates a daemon restart: a fresh instance that imports the
// kernel contents on Ensure.
func restarted(t *testing.T) Firewall {
	t.Helper()
	fw, err := NewNFT()
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.Ensure(); err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestReplaceSplitsMergedAdjacentPerms(t *testing.T) {
	p, addr, fw1 := neverShortenSetup(t)
	for _, s := range []string{"10.99.0.2/32", "10.99.0.3/32"} {
		if err := fw1.Add(KindPerm, netip.MustParsePrefix(s), 0); err != nil {
			t.Fatal(err)
		}
	}
	mustBeBlockedFrom(t, p, bHost, addr)
	mustBeBlockedFrom(t, p, bOther, addr)
	fw2 := restarted(t) // imports the merged [.2,.4) interval
	if err := fw2.Replace([]Entry{{Kind: KindPerm, Prefix: netip.MustParsePrefix("10.99.0.3/32")}}); err != nil {
		t.Fatal(err)
	}
	mustReachFrom(t, p, bHost, addr)
	mustBeBlockedFrom(t, p, bOther, addr)
	// Later mutations stay consistent with the replaced records.
	if err := fw2.Remove(netip.MustParsePrefix("10.99.0.3/32")); err != nil {
		t.Fatal(err)
	}
	mustReachFrom(t, p, bOther, addr)
}

func TestReplaceDropsNarrowerSplitOfWider(t *testing.T) {
	p, addr, fw1 := neverShortenSetup(t)
	if err := fw1.Add(KindPerm, netip.MustParsePrefix("10.99.0.0/24"), 0); err != nil {
		t.Fatal(err)
	}
	if err := fw1.Add(KindPerm, netip.MustParsePrefix("10.99.0.3/32"), 0); err != nil {
		t.Fatal(err)
	}
	fw2 := restarted(t)
	if err := fw2.Replace([]Entry{{Kind: KindPerm, Prefix: netip.MustParsePrefix("10.99.0.3/32")}}); err != nil {
		t.Fatal(err)
	}
	mustReachFrom(t, p, bHost, addr)
	mustBeBlockedFrom(t, p, bOther, addr)
}

func TestReplaceTimedRatelimAndExpired(t *testing.T) {
	fw := ensured(t)
	if err := fw.Add(KindPerm, netip.MustParsePrefix("203.0.113.9/32"), 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err := fw.Replace([]Entry{
		{Kind: KindBan, Prefix: netip.MustParsePrefix("203.0.113.1/32"), Deadline: now.Add(time.Hour)},
		{Kind: KindBan, Prefix: netip.MustParsePrefix("203.0.113.2/32"), Deadline: now.Add(-time.Second)}, // expired: skipped
		{Kind: KindRateLimit, Prefix: netip.MustParsePrefix("2001:db8::1/128"), Deadline: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasStart(t, "ban4", netip.MustParseAddr("203.0.113.1")) ||
		hasStart(t, "ban4", netip.MustParseAddr("203.0.113.2")) ||
		len(setElems(t, "perm4")) != 0 || len(setElems(t, "ratelim6")) != 1 {
		t.Fatal("Replace did not produce exactly the given entries")
	}
	if e := expiresOf(t, "ban4", netip.MustParseAddr("203.0.113.1")); e < 50*time.Minute {
		t.Fatalf("timeout lost: %v", e)
	}
	if err := fw.Replace([]Entry{{Kind: KindRateLimit, Prefix: netip.MustParsePrefix("10.0.0.0/24"), Deadline: now.Add(time.Hour)}}); err == nil {
		t.Fatal("non-single ratelimit entry must be rejected")
	}
}
