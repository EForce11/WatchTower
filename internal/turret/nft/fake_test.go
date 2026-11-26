package nft

import (
	"errors"
	"net/netip"
	"testing"
	"time"
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
