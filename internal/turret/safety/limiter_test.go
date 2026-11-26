package safety

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/EForce11/WatchTower/internal/turret/config"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func yes(netip.Prefix) bool { return true }

func newLimiter() (*ReflexLimiter, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return NewReflexLimiter(
		config.Budget{MaxTargets: 50, Window: 10 * time.Minute},
		config.Limiter{Threshold: 10, Window: 60 * time.Second},
		c.now), c
}

// spread returns the i-th IP, each in its own /24.
func spread(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("203.0.%d.9", i)) }

func TestBudgetExhaustionAndSlide(t *testing.T) {
	l, c := newLimiter()
	for i := range 50 {
		p, ok := l.Admit(spread(i), yes)
		if !ok || p != netip.PrefixFrom(spread(i), 32) {
			t.Fatalf("ip %d: %v %v", i, p, ok)
		}
	}
	if _, ok := l.Admit(spread(50), yes); ok {
		t.Fatal("51st must be refused")
	}
	c.advance(10*time.Minute + time.Second)
	if _, ok := l.Admit(spread(50), yes); !ok {
		t.Fatal("51st must be admitted after the window slides")
	}
}

func TestSameIPCountsOnce(t *testing.T) {
	l, _ := newLimiter()
	for range 3 {
		if _, ok := l.Admit(spread(0), yes); !ok {
			t.Fatal("refused")
		}
	}
	for i := 1; i < 50; i++ {
		if _, ok := l.Admit(spread(i), yes); !ok {
			t.Fatalf("ip %d refused; repeated IP was counted more than once", i)
		}
	}
	if _, ok := l.Admit(spread(50), yes); ok {
		t.Fatal("51st distinct must be refused")
	}
}

func TestPrefixAggregationV4(t *testing.T) {
	l, _ := newLimiter()
	for i := 1; i <= 10; i++ {
		p, ok := l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), yes)
		if !ok || p.Bits() != 32 {
			t.Fatalf("ip %d: %v %v", i, p, ok)
		}
	}
	p, ok := l.Admit(netip.MustParseAddr("198.51.100.11"), yes)
	if !ok || p != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("11th: %v %v", p, ok)
	}
	// Further IPs in the banned prefix are covered without new budget.
	p, ok = l.Admit(netip.MustParseAddr("198.51.100.200"), yes)
	if !ok || p != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("covered: %v %v", p, ok)
	}
}

func TestPrefixAggregationV6(t *testing.T) {
	l, _ := newLimiter()
	var p netip.Prefix
	for i := 1; i <= 11; i++ {
		var ok bool
		p, ok = l.Admit(netip.MustParseAddr(fmt.Sprintf("2001:db8:0:1::%x", i)), yes)
		if !ok {
			t.Fatalf("ip %d refused", i)
		}
	}
	if p != netip.MustParsePrefix("2001:db8:0:1::/64") {
		t.Fatalf("got %v", p)
	}
}

func TestPrefixWindowExpires(t *testing.T) {
	l, c := newLimiter()
	for i := 1; i <= 10; i++ {
		l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), yes)
		c.advance(7 * time.Second)
	}
	// First hits are older than 60 s by now, so the 11th is still a single IP.
	p, ok := l.Admit(netip.MustParseAddr("198.51.100.11"), yes)
	if !ok || p.Bits() != 32 {
		t.Fatalf("got %v %v", p, ok)
	}
}

func TestPrefixBanCountsAsOneEntry(t *testing.T) {
	l, _ := newLimiter()
	// 11 IPs in one /24 become a single prefix entry (10 singles absorbed).
	for i := 1; i <= 11; i++ {
		l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), yes)
	}
	// 49 further distinct /24s fit: 1 prefix + 49 = 50.
	for i := range 49 {
		if _, ok := l.Admit(spread(i), yes); !ok {
			t.Fatalf("ip %d refused; prefix ban should count as one entry", i)
		}
	}
	if _, ok := l.Admit(spread(49), yes); ok {
		t.Fatal("budget should now be exhausted")
	}
}

func TestRefusedAdmitDoesNotPoisonPrefixCount(t *testing.T) {
	l, _ := newLimiter()
	for i := range 50 {
		l.Admit(spread(i), yes)
	}
	for i := 1; i <= 20; i++ {
		if _, ok := l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), yes); ok {
			t.Fatalf("ip %d admitted past exhausted budget", i)
		}
	}
	if len(l.hits) != 50 {
		t.Fatalf("refused IPs changed hit state: %d prefixes (want 50)", len(l.hits))
	}
}

func TestLimiterBoundedAndConcurrent(t *testing.T) {
	l, c := newLimiter()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				l.Admit(netip.MustParseAddr(fmt.Sprintf("10.%d.%d.1", g, i)), yes)
			}
		}()
	}
	wg.Wait()
	c.advance(time.Hour)
	l.Admit(spread(0), yes)
	if len(l.admitted) != 1 || len(l.hits) != 1 {
		t.Fatalf("state not pruned: %d admitted, %d hit groups", len(l.admitted), len(l.hits))
	}
}

func TestAdmitInvalidAndMapped(t *testing.T) {
	l, _ := newLimiter()
	if p, ok := l.Admit(netip.Addr{}, yes); ok || p.IsValid() {
		t.Fatalf("invalid addr: %v %v", p, ok)
	}
	if len(l.admitted) != 0 {
		t.Fatal("invalid addr consumed budget")
	}
	p, ok := l.Admit(netip.MustParseAddr("::ffff:203.0.113.7"), yes)
	if !ok || p != netip.MustParsePrefix("203.0.113.7/32") {
		t.Fatalf("mapped: %v %v", p, ok)
	}
}

func TestAdmitFallsBackToSingleWhenWideningDenied(t *testing.T) {
	l, _ := newLimiter()
	no := func(netip.Prefix) bool { return false }
	got := 0
	for i := 1; i <= 150; i++ {
		p, ok := l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), no)
		if ok {
			got++
			if p.Bits() != 32 {
				t.Fatalf("ip %d widened to %v", i, p)
			}
		}
	}
	if got != 50 {
		t.Fatalf("admitted %d, want 50", got)
	}
}

func TestAdmitSingleCountsBudgetNeverEscalates(t *testing.T) {
	l, _ := newLimiter()
	got := 0
	for i := 1; i <= 100; i++ {
		if l.AdmitSingle(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i))) {
			got++
		}
	}
	if got != 50 {
		t.Fatalf("admitted %d, want 50", got)
	}
	if len(l.hits) != 0 {
		t.Fatal("AdmitSingle contributed to prefix counts")
	}
	l, _ = newLimiter()
	for i := 1; i <= 12; i++ {
		l.AdmitSingle(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)))
	}
	if p, ok := l.Admit(netip.MustParseAddr("198.51.100.13"), yes); !ok || p.Bits() != 32 {
		t.Fatalf("rate limits must not trigger widening: %v %v", p, ok)
	}
	if !l.AdmitSingle(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("same single twice must count once")
	}
	if l.AdmitSingle(netip.Addr{}) {
		t.Fatal("invalid addr admitted")
	}
}

func TestReleaseUndoesLastAdmission(t *testing.T) {
	l, _ := newLimiter()
	for i := range 50 {
		p, _ := l.Admit(spread(i), yes)
		if i == 49 {
			l.Release(p)
		}
	}
	if len(l.admitted) != 49 || len(l.hits) != 49 {
		t.Fatalf("admitted=%d hits=%d after release", len(l.admitted), len(l.hits))
	}
	// Releasing a different prefix is a no-op.
	l.Release(netip.MustParsePrefix("1.2.3.4/32"))
	if len(l.admitted) != 49 {
		t.Fatal("foreign release changed state")
	}
	// Release of a repeat admission keeps the earlier entry.
	p, _ := l.Admit(spread(0), yes)
	l.Release(p)
	if len(l.admitted) != 49 {
		t.Fatalf("release of re-admission dropped the original: %d", len(l.admitted))
	}
	// Release of a widening restores absorbed singles.
	l2, _ := newLimiter()
	for i := 1; i <= 10; i++ {
		l2.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)), yes)
	}
	p, _ = l2.Admit(netip.MustParseAddr("198.51.100.11"), yes)
	if p.Bits() != 24 {
		t.Fatalf("p = %v", p)
	}
	l2.Release(p)
	if len(l2.admitted) != 10 {
		t.Fatalf("absorbed singles not restored: %d", len(l2.admitted))
	}
}
