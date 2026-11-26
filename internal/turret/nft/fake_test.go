package nft

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
)

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestFakeImplementsFirewall(t *testing.T) {
	var _ Firewall = NewFake()
}

func TestFakeValidationMatchesReal(t *testing.T) {
	f := NewFake()
	cases := []struct {
		name string
		k    Kind
		p    netip.Prefix
		ttl  time.Duration
		ok   bool
	}{
		{"ratelimit non-single v4", KindRateLimit, mp("10.0.0.0/24"), time.Minute, false},
		{"ratelimit non-single v6", KindRateLimit, mp("2001:db8::/64"), time.Minute, false},
		{"ratelimit single", KindRateLimit, mp("10.0.0.1/32"), time.Minute, true},
		{"ban zero ttl", KindBan, mp("10.0.0.1/32"), 0, false},
		{"ban negative ttl", KindBan, mp("10.0.0.1/32"), -time.Second, false},
		{"ratelimit zero ttl", KindRateLimit, mp("10.0.0.1/32"), 0, false},
		{"perm ignores ttl", KindPerm, mp("10.0.0.0/24"), 0, true},
		{"perm negative ttl ignored", KindPerm, mp("10.0.0.0/24"), -time.Hour, true},
		{"invalid kind", Kind(0), mp("10.0.0.1/32"), time.Minute, false},
		{"invalid prefix", KindBan, netip.Prefix{}, time.Minute, false},
		{"ban cidr", KindBan, mp("10.0.0.0/24"), time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Add(tc.k, tc.p, tc.ttl)
			if (err == nil) != tc.ok {
				t.Fatalf("Add err=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestFakeStateAndRemove(t *testing.T) {
	f := NewFake()
	if err := f.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := f.Add(KindBan, mp("10.0.0.5/32"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// 4in6 form is normalised.
	if !f.Has(KindBan, mp("::ffff:10.0.0.5/128")) {
		t.Fatal("4in6 prefix should match the v4 entry")
	}
	if f.Has(KindPerm, mp("10.0.0.5/32")) {
		t.Fatal("perm must not have it")
	}
	if err := f.Remove(mp("10.0.0.5/32")); err != nil {
		t.Fatal(err)
	}
	if f.Has(KindBan, mp("10.0.0.5/32")) {
		t.Fatal("still present after Remove")
	}
	if err := f.Remove(mp("10.0.0.5/32")); err != nil {
		t.Fatalf("missing Remove must be nil: %v", err)
	}
	if err := f.SetAllow([]netip.Prefix{mp("10.1.0.0/16"), mp("fd00::/8")}); err != nil {
		t.Fatal(err)
	}
	if got := f.Allow(); len(got) != 2 {
		t.Fatalf("Allow()=%v", got)
	}
	if err := f.SetAllow(nil); err != nil {
		t.Fatal(err)
	}
	if got := f.Allow(); len(got) != 0 {
		t.Fatalf("Allow()=%v", got)
	}
	if err := f.Add(KindBan, mp("10.0.0.6/32"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.Has(KindBan, mp("10.0.0.6/32")) {
		t.Fatal("Flush must clear state")
	}
}

func TestFakeFailNext(t *testing.T) {
	f := NewFake()
	boom := errors.New("boom")
	f.FailNext(boom)
	if err := f.Add(KindBan, mp("10.0.0.1/32"), time.Minute); !errors.Is(err, boom) {
		t.Fatalf("err=%v", err)
	}
	if f.Has(KindBan, mp("10.0.0.1/32")) {
		t.Fatal("failed call must not mutate")
	}
	if err := f.Add(KindBan, mp("10.0.0.1/32"), time.Minute); err != nil {
		t.Fatalf("only the next call fails: %v", err)
	}
}

func TestFakeRecordsCalls(t *testing.T) {
	f := NewFake()
	_ = f.Ensure()
	_ = f.Add(KindPerm, mp("10.0.0.0/24"), 0)
	calls := f.Calls()
	if len(calls) != 2 || calls[0].Op != "Ensure" || calls[1].Op != "Add" || calls[1].Kind != KindPerm {
		t.Fatalf("calls=%+v", calls)
	}
}

func TestSetAllowValidation(t *testing.T) {
	f := NewFake()
	if err := f.SetAllow([]netip.Prefix{{}}); err == nil {
		t.Fatal("invalid prefix must be rejected")
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func TestFakeNeverShortens(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.2")
	other := netip.MustParseAddr("10.0.0.3")

	t.Run("narrower longer inside wider shorter", func(t *testing.T) {
		c := newClock()
		f := NewFakeAt(c.now)
		_ = f.Add(KindBan, mp("10.0.0.0/24"), 2*time.Second)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), 8*time.Second)
		c.advance(3 * time.Second)
		if !f.Blocked(KindBan, a) || f.Blocked(KindBan, other) {
			t.Fatal("only the /32 should still block")
		}
		if f.Has(KindBan, mp("10.0.0.0/24")) {
			t.Fatal("expired /24 record must not be reported")
		}
	})
	t.Run("wider shorter added over narrower longer", func(t *testing.T) {
		c := newClock()
		f := NewFakeAt(c.now)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), 8*time.Second)
		_ = f.Add(KindBan, mp("10.0.0.0/24"), 2*time.Second)
		c.advance(3 * time.Second)
		if !f.Blocked(KindBan, a) || f.Blocked(KindBan, other) {
			t.Fatal("only the /32 should still block")
		}
	})
	t.Run("remove wider keeps narrower", func(t *testing.T) {
		f := NewFakeAt(newClock().now)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), time.Minute)
		_ = f.Add(KindBan, mp("10.0.0.0/24"), time.Minute)
		_ = f.Remove(mp("10.0.0.0/24"))
		if !f.Blocked(KindBan, a) || f.Blocked(KindBan, other) {
			t.Fatal("narrower ban must survive Remove of the wider one")
		}
	})
	t.Run("remove narrower inside wider keeps blocking", func(t *testing.T) {
		f := NewFakeAt(newClock().now)
		_ = f.Add(KindBan, mp("10.0.0.0/24"), time.Minute)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), time.Minute)
		_ = f.Remove(mp("10.0.0.2/32"))
		if !f.Blocked(KindBan, a) {
			t.Fatal("still covered by the /24")
		}
	})
	t.Run("re-add shorter keeps longer", func(t *testing.T) {
		c := newClock()
		f := NewFakeAt(c.now)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), time.Hour)
		_ = f.Add(KindBan, mp("10.0.0.2/32"), time.Second)
		exp, ok := f.Expiry(KindBan, a)
		if !ok || exp.Sub(c.now()) != time.Hour {
			t.Fatalf("expiry=%v ok=%v", exp, ok)
		}
	})
	t.Run("perm has no expiry", func(t *testing.T) {
		c := newClock()
		f := NewFakeAt(c.now)
		_ = f.Add(KindPerm, mp("10.0.0.0/24"), 0)
		c.advance(1000 * time.Hour)
		exp, ok := f.Expiry(KindPerm, a)
		if !ok || !exp.IsZero() {
			t.Fatalf("expiry=%v ok=%v", exp, ok)
		}
	})
}

func TestRecordSetSegments(t *testing.T) {
	c := newClock()
	var rs recordSet
	rs.add(prefixSpan(mp("10.0.0.0/24")), c.now().Add(2*time.Second))
	rs.add(prefixSpan(mp("10.0.0.2/32")), c.now().Add(8*time.Second))
	segs := rs.segments(c.now())
	if len(segs) != 3 {
		t.Fatalf("segments=%+v", segs)
	}
	if segs[1].lo.String() != "10.0.0.2" || segs[1].hi.String() != "10.0.0.3" || !segs[1].deadline.Equal(c.now().Add(8*time.Second)) {
		t.Fatalf("middle=%+v", segs[1])
	}
	// Whole address space: no end element.
	var all recordSet
	all.add(prefixSpan(mp("0.0.0.0/0")), c.now().Add(time.Second))
	if s := all.segments(c.now()); len(s) != 1 || !s[0].open {
		t.Fatalf("segments=%+v", s)
	}
}

func TestFakeReplaceAndImport(t *testing.T) {
	c := newClock()
	f := NewFakeAt(c.now)
	_ = f.Add(KindPerm, mp("10.0.0.1/32"), 0)
	_ = f.Add(KindPerm, mp("10.0.0.2/32"), 0)
	g := NewFakeFrom(f)
	if g.Has(KindPerm, mp("10.0.0.1/32")) || !g.Blocked(KindPerm, netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("import must merge adjacent perms into one interval")
	}
	if err := g.Replace([]Entry{
		{Kind: KindPerm, Prefix: mp("10.0.0.2/32")},
		{Kind: KindBan, Prefix: mp("10.0.0.9/32"), Deadline: c.now().Add(time.Minute)},
		{Kind: KindBan, Prefix: mp("10.0.0.8/32"), Deadline: c.now().Add(-time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	if g.Blocked(KindPerm, netip.MustParseAddr("10.0.0.1")) || !g.Has(KindPerm, mp("10.0.0.2/32")) ||
		!g.Has(KindBan, mp("10.0.0.9/32")) || g.Has(KindBan, mp("10.0.0.8/32")) {
		t.Fatal("Replace must set exactly the given live entries")
	}
	if err := g.Replace([]Entry{{Kind: KindRateLimit, Prefix: mp("10.0.0.0/24"), Deadline: c.now().Add(time.Minute)}}); err == nil {
		t.Fatal("invalid entry must be rejected")
	}
}

func TestParseSpansOrphanEnds(t *testing.T) {
	k := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	// What the kernel leaves after the starts of [.0,.2) and [.3,1.0) expired
	// around a live [.2,.3).
	el := []nftables.SetElement{
		{Key: k("10.99.1.0"), IntervalEnd: true},
		{Key: k("10.99.0.3"), IntervalEnd: true},
		{Key: k("10.99.0.2"), Expires: time.Minute},
		{Key: k("10.99.0.2"), IntervalEnd: true},
	}
	if _, err := parseSpans(el, false); err == nil {
		t.Fatal("orphan end accepted in a set without timeouts")
	}
	got, err := parseSpans(el, true)
	if err != nil {
		t.Fatal(err)
	}
	want := prefixSpan(netip.MustParsePrefix("10.99.0.2/32"))
	if len(got) != 1 || !got[0].equal(want) || got[0].expires != time.Minute {
		t.Fatalf("spans = %+v, want [%+v]", got, want)
	}
}
