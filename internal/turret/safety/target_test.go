package safety

import (
	"net/netip"
	"testing"

	"github.com/EForce11/WatchTower/internal/turret/verify"
)

func TestOriginFor(t *testing.T) {
	if OriginFor(verify.KeyAutomation) != OriginAutomation || OriginFor(verify.KeyAdmin) != OriginAdmin {
		t.Fatal("OriginFor mapping wrong")
	}
}

func TestParseNetTarget(t *testing.T) {
	tests := []struct {
		in   string
		o    Origin
		want string // empty means error
	}{
		{"203.0.113.7", OriginReflex, "203.0.113.7/32"},
		{"2001:db8::1", OriginReflex, "2001:db8::1/128"},
		{"203.0.113.0/24", OriginReflex, ""},
		{"203.0.113.0/24", OriginAutomation, "203.0.113.0/24"},
		{"203.0.113.0/24", OriginAdmin, "203.0.113.0/24"},
		{"10.0.0.0/16", OriginAdmin, "10.0.0.0/16"},
		{"10.0.0.0/15", OriginAdmin, ""},
		{"2001:db8::/32", OriginAdmin, "2001:db8::/32"},
		{"2001:db8::/31", OriginAdmin, ""},
		{"203.0.113.7/24", OriginAdmin, "203.0.113.0/24"},
		{"::ffff:203.0.113.7", OriginReflex, "203.0.113.7/32"},
		{"::ffff:203.0.113.0/120", OriginAdmin, ""},
		{"203.0.113.7/32", OriginReflex, ""},
		{"garbage", OriginAdmin, ""},
		{"", OriginAdmin, ""},
		{"fe80::1%eth0", OriginAdmin, ""},
	}
	for _, tc := range tests {
		got, err := ParseNetTarget(tc.in, tc.o)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%q origin %d: want error, got %v", tc.in, tc.o, got)
			}
			continue
		}
		if err != nil || got != netip.MustParsePrefix(tc.want) {
			t.Errorf("%q origin %d: got %v, %v; want %s", tc.in, tc.o, got, err, tc.want)
		}
	}
}

func TestParsePIDTarget(t *testing.T) {
	for _, in := range []string{"pid:1", "pid:0", "pid:-5", "pid:x", "4412", "pid:", "pid:+4412", "pid: 44", "pid:4 4"} {
		if n, err := ParsePIDTarget(in); err == nil {
			t.Errorf("%q: want error, got %d", in, n)
		}
	}
	if n, err := ParsePIDTarget("pid:004412"); err != nil || n != 4412 {
		t.Errorf("leading zeros: %d, %v", n, err)
	}
	if n, err := ParsePIDTarget("pid:4412"); err != nil || n != 4412 {
		t.Errorf("got %d, %v", n, err)
	}
}
