package safety

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/EForce11/WatchTower/internal/turret/config"
)

// Sources are the system inputs of Discover; injectable for tests.
type Sources struct {
	InterfaceAddrs func() ([]netip.Prefix, error)
	RouteFiles     [2]string // default /proc/net/route, /proc/net/ipv6_route
	ResolvConf     string    // default /etc/resolv.conf
}

// Protected is an immutable set of self-preservation prefixes. Discover
// returns a new value each time, so readers may share one concurrently.
type Protected struct {
	prefixes []netip.Prefix
}

// Discover collects every self-preservation range for cfg.
//
//nolint:gocritic // signature fixed by the Task 3 contract; called rarely
func Discover(cfg config.Config, src Sources) (*Protected, error) {
	if src.InterfaceAddrs == nil {
		src.InterfaceAddrs = systemInterfaceAddrs
	}
	if src.RouteFiles[0] == "" {
		src.RouteFiles[0] = "/proc/net/route"
	}
	if src.RouteFiles[1] == "" {
		src.RouteFiles[1] = "/proc/net/ipv6_route"
	}
	if src.ResolvConf == "" {
		src.ResolvConf = "/etc/resolv.conf"
	}

	ps := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
	}

	addrs, err := src.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("interface addresses: %w", err)
	}
	for _, p := range addrs {
		a := p.Addr().Unmap().WithZone("")
		ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
	}

	for i, parse := range [2]func(string) ([]netip.Addr, error){parseRoute4, parseRoute6} {
		gws, err := parse(src.RouteFiles[i])
		if err != nil {
			return nil, err
		}
		ps = appendAddrs(ps, gws)
	}

	dns, err := parseResolv(src.ResolvConf)
	if err != nil {
		return nil, err
	}
	ps = appendAddrs(ps, dns)

	host, _, err := net.SplitHostPort(cfg.CoreEndpoint)
	if err != nil {
		return nil, fmt.Errorf("core endpoint %q: %w", cfg.CoreEndpoint, err)
	}
	core, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("core endpoint host %q: %w", host, err)
	}
	ps = appendAddrs(ps, []netip.Addr{core})

	wg, err := netip.ParsePrefix(cfg.WireGuardCIDR)
	if err != nil {
		return nil, fmt.Errorf("wireguard cidr %q: %w", cfg.WireGuardCIDR, err)
	}
	wgn, ok := normalize(wg)
	if !ok {
		return nil, fmt.Errorf("wireguard cidr %q: unusable prefix", cfg.WireGuardCIDR)
	}
	ps = append(ps, wgn)

	wl, err := parseWhitelist(cfg.WhitelistFile)
	if err != nil {
		return nil, err
	}
	ps = append(ps, wl...)

	return &Protected{prefixes: dedupe(ps)}, nil
}

// normalize returns the canonical form of p: zone stripped, IPv4-mapped IPv6
// prefixes converted to IPv4 (bits-96) and the host bits masked. ok is false
// for an invalid prefix or a mapped prefix broader than /96, which has no
// IPv4 equivalent.
func normalize(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	a := p.Addr().WithZone("")
	bits := p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked(), true
}

// Overlaps reports the first protected prefix that overlaps target. It fails
// closed: an invalid target, or a mapped one with no IPv4 equivalent, is
// reported as a hit (with the zero prefix).
func (p *Protected) Overlaps(target netip.Prefix) (netip.Prefix, bool) {
	target, ok := normalize(target)
	if !ok {
		return netip.Prefix{}, true
	}
	for _, q := range p.prefixes {
		if q.Overlaps(target) {
			return q, true
		}
	}
	return netip.Prefix{}, false
}

// Prefixes returns a copy of the protected prefixes.
func (p *Protected) Prefixes() []netip.Prefix { return slices.Clone(p.prefixes) }

func appendAddrs(ps []netip.Prefix, as []netip.Addr) []netip.Prefix {
	for _, a := range as {
		a = a.Unmap().WithZone("")
		ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
	}
	return ps
}

func dedupe(ps []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(ps))
	out := ps[:0]
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func systemInterfaceAddrs() ([]netip.Prefix, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(as))
	for _, a := range as {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			return nil, fmt.Errorf("interface address %q: %w", a.String(), err)
		}
		out = append(out, p)
	}
	return out, nil
}

// readLines returns the file's lines; a missing file yields none.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // paths come from daemon config / fixed system files
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return lines, nil
}

// parseRoute4 extracts default gateways from /proc/net/route. The gateway is
// a host-order hex word, decoded as little-endian (amd64/arm64 hosts only);
// only the main routing table is visible there.
func parseRoute4(path string) ([]netip.Addr, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	gws := make([]netip.Addr, 0, 2)
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		g, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || g == 0 {
			continue
		}
		gws = append(gws, netip.AddrFrom4([4]byte{byte(g), byte(g >> 8), byte(g >> 16), byte(g >> 24)}))
	}
	return gws, nil
}

// parseRoute6 extracts default next hops from /proc/net/ipv6_route.
func parseRoute6(path string) ([]netip.Addr, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	const zero32 = "00000000000000000000000000000000"
	gws := make([]netip.Addr, 0, 2)
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 || f[0] != zero32 || f[1] != "00" || f[4] == zero32 || len(f[4]) != 32 {
			continue
		}
		var b [16]byte
		ok := true
		for i := range b {
			v, err := strconv.ParseUint(f[4][2*i:2*i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			b[i] = byte(v)
		}
		if ok {
			gws = append(gws, netip.AddrFrom16(b))
		}
	}
	return gws, nil
}

// parseResolv extracts nameserver addresses.
func parseResolv(path string) ([]netip.Addr, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(lines))
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("resolv.conf %s: nameserver %q: %w", path, f[1], err)
		}
		out = append(out, a.WithZone(""))
	}
	return out, nil
}

// parseWhitelist reads IPs and CIDRs, one per line, with # comments.
func parseWhitelist(path string) ([]netip.Prefix, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(lines))
	for i, l := range lines {
		if j := strings.IndexByte(l, '#'); j >= 0 {
			l = l[:j]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.Contains(l, "/") {
			p, err := netip.ParsePrefix(l)
			if err != nil {
				return nil, fmt.Errorf("whitelist %s line %d: %w", path, i+1, err)
			}
			pn, ok := normalize(p)
			if !ok {
				return nil, fmt.Errorf("whitelist %s line %d: unusable prefix %q", path, i+1, l)
			}
			out = append(out, pn)
			continue
		}
		a, err := netip.ParseAddr(l)
		if err != nil {
			return nil, fmt.Errorf("whitelist %s line %d: %w", path, i+1, err)
		}
		a = a.Unmap().WithZone("")
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
