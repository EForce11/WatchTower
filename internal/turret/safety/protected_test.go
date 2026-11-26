package safety

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EForce11/WatchTower/internal/turret/config"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const route4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

const route6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
	"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"

type fixture struct {
	cfg config.Config
	src Sources
	dir string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	d := t.TempDir()
	cfg := config.Config{
		CoreEndpoint:  "192.0.2.10:7443",
		WireGuardCIDR: "10.8.0.0/24",
		WhitelistFile: write(t, d, "whitelist.txt", "# mgmt\n203.0.113.50\n\n198.51.100.0/24 # office\n2001:db8:aaaa::/48\n"),
	}
	src := Sources{
		InterfaceAddrs: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.23/24")}, nil
		},
		RouteFiles: [2]string{write(t, d, "route", route4), write(t, d, "ipv6_route", route6)},
		ResolvConf: write(t, d, "resolv.conf", "# c\nsearch example\nnameserver 9.9.9.9\nnameserver 2620:fe::fe\n"),
	}
	return fixture{cfg, src, d}
}

func TestDiscoverProtects(t *testing.T) {
	f := newFixture(t)
	p, err := Discover(f.cfg, f.src)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"127.0.0.1/32", "::1/128", "169.254.1.1/32", "fe80::5/128", // hardcoded
		"192.168.1.23/32",               // interface address
		"192.168.1.1/32",                // v4 default gateway
		"fe80::1/128",                   // v6 default gateway
		"9.9.9.9/32", "2620:fe::fe/128", // resolvers
		"192.0.2.10/32",        // core endpoint
		"10.8.0.77/32",         // wireguard
		"203.0.113.50/32",      // whitelist IP
		"198.51.100.9/32",      // whitelist CIDR
		"2001:db8:aaaa::1/128", // whitelist v6 CIDR
	} {
		if _, hit := p.Overlaps(netip.MustParsePrefix(s)); !hit {
			t.Errorf("%s should be protected", s)
		}
	}
}

func TestDiscoverOverlap(t *testing.T) {
	f := newFixture(t)
	p, err := Discover(f.cfg, f.src)
	if err != nil {
		t.Fatal(err)
	}
	if got, hit := p.Overlaps(netip.MustParsePrefix("10.8.0.0/16")); !hit || got != netip.MustParsePrefix("10.8.0.0/24") {
		t.Errorf("10.8.0.0/16: %v %v", got, hit)
	}
	if _, hit := p.Overlaps(netip.MustParsePrefix("0.0.0.0/0")); !hit {
		t.Error("0.0.0.0/0 must hit")
	}
	if got, hit := p.Overlaps(netip.MustParsePrefix("203.0.113.7/32")); hit {
		t.Errorf("203.0.113.7 must not hit, got %v", got)
	}
}

func TestDiscoverMissingFiles(t *testing.T) {
	f := newFixture(t)
	f.cfg.WhitelistFile = filepath.Join(f.dir, "absent")
	f.src.RouteFiles = [2]string{filepath.Join(f.dir, "no4"), filepath.Join(f.dir, "no6")}
	f.src.ResolvConf = filepath.Join(f.dir, "noresolv")
	if _, err := Discover(f.cfg, f.src); err != nil {
		t.Fatalf("missing files must not be an error: %v", err)
	}
}

func TestDiscoverWhitelistErrors(t *testing.T) {
	f := newFixture(t)
	f.cfg.WhitelistFile = write(t, f.dir, "bad.txt", "203.0.113.1\n# ok\nnot-an-ip\n")
	_, err := Discover(f.cfg, f.src)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want error naming line 3, got %v", err)
	}
	// An existing but unreadable path (a directory) is an error.
	f.cfg.WhitelistFile = f.dir
	if _, err := Discover(f.cfg, f.src); err == nil {
		t.Fatal("unreadable whitelist must error")
	}
}

func TestDiscoverIsImmutable(t *testing.T) {
	f := newFixture(t)
	p, err := Discover(f.cfg, f.src)
	if err != nil {
		t.Fatal(err)
	}
	ps := p.Prefixes()
	ps[0] = netip.MustParsePrefix("1.2.3.4/32")
	if p.Prefixes()[0] == ps[0] {
		t.Fatal("Prefixes must return a copy")
	}
}
