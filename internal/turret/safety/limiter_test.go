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
		p, ok := l.Admit(spread(i))
		if !ok || p != netip.PrefixFrom(spread(i), 32) {
			t.Fatalf("ip %d: %v %v", i, p, ok)
		}
	}
	if _, ok := l.Admit(spread(50)); ok {
		t.Fatal("51st must be refused")
	}
	c.advance(10*time.Minute + time.Second)
	if _, ok := l.Admit(spread(50)); !ok {
		t.Fatal("51st must be admitted after the window slides")
	}
}

func TestSameIPCountsOnce(t *testing.T) {
	l, _ := newLimiter()
	for range 3 {
		if _, ok := l.Admit(spread(0)); !ok {
			t.Fatal("refused")
		}
	}
	for i := 1; i < 50; i++ {
		if _, ok := l.Admit(spread(i)); !ok {
			t.Fatalf("ip %d refused; repeated IP was counted more than once", i)
		}
	}
	if _, ok := l.Admit(spread(50)); ok {
		t.Fatal("51st distinct must be refused")
	}
}

func TestPrefixAggregationV4(t *testing.T) {
	l, _ := newLimiter()
	for i := 1; i <= 10; i++ {
		p, ok := l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)))
		if !ok || p.Bits() != 32 {
			t.Fatalf("ip %d: %v %v", i, p, ok)
		}
	}
	p, ok := l.Admit(netip.MustParseAddr("198.51.100.11"))
	if !ok || p != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("11th: %v %v", p, ok)
	}
	// Further IPs in the banned prefix are covered without new budget.
	p, ok = l.Admit(netip.MustParseAddr("198.51.100.200"))
	if !ok || p != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("covered: %v %v", p, ok)
	}
}

func TestPrefixAggregationV6(t *testing.T) {
	l, _ := newLimiter()
	var p netip.Prefix
	for i := 1; i <= 11; i++ {
		var ok bool
		p, ok = l.Admit(netip.MustParseAddr(fmt.Sprintf("2001:db8:0:1::%x", i)))
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
		l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)))
		c.advance(7 * time.Second)
	}
	// First hits are older than 60 s by now, so the 11th is still a single IP.
	p, ok := l.Admit(netip.MustParseAddr("198.51.100.11"))
	if !ok || p.Bits() != 32 {
		t.Fatalf("got %v %v", p, ok)
	}
}

func TestPrefixBanCountsAsOneEntry(t *testing.T) {
	l, _ := newLimiter()
	// 11 IPs in one /24 become a single prefix entry (10 singles absorbed).
	for i := 1; i <= 11; i++ {
		l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)))
	}
	// 49 further distinct /24s fit: 1 prefix + 49 = 50.
	for i := range 49 {
		if _, ok := l.Admit(spread(i)); !ok {
			t.Fatalf("ip %d refused; prefix ban should count as one entry", i)
		}
	}
	if _, ok := l.Admit(spread(49)); ok {
		t.Fatal("budget should now be exhausted")
	}
}

func TestRefusedAdmitDoesNotPoisonPrefixCount(t *testing.T) {
	l, _ := newLimiter()
	for i := range 50 {
		l.Admit(spread(i))
	}
	for i := 1; i <= 20; i++ {
		if _, ok := l.Admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i))); ok {
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
				l.Admit(netip.MustParseAddr(fmt.Sprintf("10.%d.%d.1", g, i)))
			}
		}()
	}
	wg.Wait()
	c.advance(time.Hour)
	l.Admit(spread(0))
	if len(l.admitted) != 1 || len(l.hits) != 1 {
		t.Fatalf("state not pruned: %d admitted, %d hit groups", len(l.admitted), len(l.hits))
	}
}

func TestAdmitInvalidAndMapped(t *testing.T) {
	l, _ := newLimiter()
	if p, ok := l.Admit(netip.Addr{}); ok || p.IsValid() {
		t.Fatalf("invalid addr: %v %v", p, ok)
	}
	if len(l.admitted) != 0 {
		t.Fatal("invalid addr consumed budget")
	}
	p, ok := l.Admit(netip.MustParseAddr("::ffff:203.0.113.7"))
	if !ok || p != netip.MustParsePrefix("203.0.113.7/32") {
		t.Fatalf("mapped: %v %v", p, ok)
	}
}
