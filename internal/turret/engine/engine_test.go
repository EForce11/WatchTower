package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/EForce11/WatchTower/internal/turret/config"
	"github.com/EForce11/WatchTower/internal/turret/ioc"
	"github.com/EForce11/WatchTower/internal/turret/nft"
	"github.com/EForce11/WatchTower/internal/turret/proc"
	"github.com/EForce11/WatchTower/internal/turret/replay"
	"github.com/EForce11/WatchTower/internal/turret/safety"
	"github.com/EForce11/WatchTower/internal/turret/verify"
	synapsev1 "github.com/EForce11/WatchTower/pkg/synapse/v1"
)

const agent = "agent-1"

type clock struct{ ns atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.ns.Store(time.Unix(1_800_000_000, 0).UnixNano())
	return c
}
func (c *clock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *clock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

type killCall struct {
	pid   int
	exe   string
	start uint64
}

type env struct {
	t       *testing.T
	clk     *clock
	fw      *nft.Fake
	eng     *Engine
	deps    Deps
	autoKey ed25519.PrivateKey
	admKey  ed25519.PrivateKey
	autoPub ed25519.PublicKey
	admPub  ed25519.PublicKey
	kills   []killCall
	temps   []int
	killErr error
	mu      sync.Mutex
	state   string
	replayP string
}

func pemOf(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func testProtected(t *testing.T, cfg *config.Config) *safety.Protected {
	t.Helper()
	p, err := safety.Discover(*cfg, safety.Sources{
		InterfaceAddrs: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.23/24")}, nil
		},
		RouteFiles: [2]string{"/nonexistent/route", "/nonexistent/ipv6_route"},
		ResolvConf: "/nonexistent/resolv.conf",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, clk: newClock(), state: filepath.Join(dir, "state"), replayP: filepath.Join(dir, "replay.json")}
	var err error
	e.autoPub, e.autoKey, _ = ed25519.GenerateKey(rand.Reader)
	e.admPub, e.admKey, _ = ed25519.GenerateKey(rand.Reader)
	autoPath := filepath.Join(dir, "automation.pub")
	if err = os.WriteFile(autoPath, pemOf(t, e.autoPub), 0o600); err != nil {
		t.Fatal(err)
	}
	adminDir := filepath.Join(dir, "admin")
	if err = os.Mkdir(adminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(adminDir, "alice.pub"), pemOf(t, e.admPub), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := verify.LoadKeyring(autoPath, adminDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AgentID:       agent,
		StateDir:      e.state,
		CoreEndpoint:  "192.0.2.10:7443",
		WireGuardCIDR: "10.8.0.0/24",
		ReflexBudget:  config.Budget{MaxTargets: 50, Window: 10 * time.Minute},
		PrefixLimiter: config.Limiter{Threshold: 10, Window: 60 * time.Second},
	}
	e.fw = nft.NewFakeAt(e.clk.Now)
	e.deps = Deps{
		Cfg:       cfg,
		Keys:      keys,
		Protected: testProtected(t, &cfg),
		Limiter:   safety.NewReflexLimiter(cfg.ReflexBudget, cfg.PrefixLimiter, e.clk.Now),
		FW:        e.fw,
		IOC:       func() (*ioc.Set, error) { return &ioc.Set{}, nil },
		Kill: func(pid int, exe string, start uint64) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.kills = append(e.kills, killCall{pid, exe, start})
			return e.killErr
		},
		KillTemp: func(pid int, _ *ioc.Set) (string, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.temps = append(e.temps, pid)
			return "/tmp/x", e.killErr
		},
		Now: e.clk.Now,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e.start()
	return e
}

// start (re)creates the replay cache and the engine on the same state.
func (e *env) start() {
	e.t.Helper()
	rc, err := replay.Open(e.replayP, e.clk.Now)
	if err != nil {
		e.t.Fatal(err)
	}
	e.deps.Replay = rc
	e.eng, err = New(e.deps)
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sign(priv ed25519.PrivateKey, pub ed25519.PublicKey, p *synapsev1.CommandPayload) *synapsev1.TurretRequest {
	e.t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		e.t.Fatal(err)
	}
	return &synapsev1.TurretRequest{Kind: &synapsev1.TurretRequest_Signed{Signed: &synapsev1.SignedCommand{
		Payload: b, Signature: ed25519.Sign(priv, b), KeyId: verify.KeyID(pub),
		Scheme: synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519,
	}}}
}

func (e *env) payload(id string, a synapsev1.Action, target string, ttl, life int64) *synapsev1.CommandPayload {
	return &synapsev1.CommandPayload{
		CommandId: id, AgentId: agent, IssuedAt: e.clk.Now().Unix(), ExpiresAt: e.clk.Now().Unix() + life,
		Action: a, Target: target, TtlSeconds: ttl,
	}
}

func (e *env) auto(id string, a synapsev1.Action, target string, ttl int64) *synapsev1.TurretRequest {
	return e.sign(e.autoKey, e.autoPub, e.payload(id, a, target, ttl, 60))
}

func (e *env) admin(id string, a synapsev1.Action, target string, ttl int64) *synapsev1.TurretRequest {
	return e.sign(e.admKey, e.admPub, e.payload(id, a, target, ttl, 600))
}

func reflex(id string, a synapsev1.Action, target string, ttl int64) *synapsev1.TurretRequest {
	return &synapsev1.TurretRequest{Kind: &synapsev1.TurretRequest_Reflex{Reflex: &synapsev1.ReflexRequest{
		RequestId: id, Action: a, Target: target, TtlSeconds: ttl,
	}}}
}

const (
	okRes     = synapsev1.TurretResult_TURRET_RESULT_APPLIED
	safetyRef = synapsev1.TurretResult_TURRET_RESULT_REFUSED_SAFETY
	sigRef    = synapsev1.TurretResult_TURRET_RESULT_REFUSED_SIGNATURE
	replayRef = synapsev1.TurretResult_TURRET_RESULT_REFUSED_REPLAY
	budgetRef = synapsev1.TurretResult_TURRET_RESULT_REFUSED_BUDGET
	failedRes = synapsev1.TurretResult_TURRET_RESULT_FAILED
)

func (e *env) expect(req *synapsev1.TurretRequest, want synapsev1.TurretResult) *synapsev1.TurretResponse {
	e.t.Helper()
	got := e.eng.Handle(req)
	if got.GetResult() != want {
		e.t.Fatalf("result = %s (%q), want %s", got.GetResult(), got.GetDetail(), want)
	}
	return got
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestReflexBanTemp(t *testing.T) {
	e := newEnv(t)
	r := e.expect(reflex("r1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.9", 600), okRes)
	if r.GetId() != "r1" {
		t.Fatalf("id = %q", r.GetId())
	}
	if !e.fw.Has(nft.KindBan, pfx("203.0.113.9/32")) {
		t.Fatal("ban not in firewall")
	}
	if exp, _ := e.fw.Expiry(nft.KindBan, netip.MustParseAddr("203.0.113.9")); !exp.Equal(e.clk.Now().Add(600 * time.Second)) {
		t.Fatalf("expiry = %v", exp)
	}
}

func TestReflexRefusals(t *testing.T) {
	e := newEnv(t)
	for name, req := range map[string]*synapsev1.TurretRequest{
		"wireguard subnet": reflex("a", synapsev1.Action_ACTION_BAN_TEMP, "10.8.0.4", 60),
		"core endpoint":    reflex("b", synapsev1.Action_ACTION_BAN_TEMP, "192.0.2.10", 60),
		"cidr":             reflex("c", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.0/24", 60),
		"ttl too long":     reflex("d", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.9", 901),
		"perm":             reflex("e", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.9", 0),
		"unban":            reflex("f", synapsev1.Action_ACTION_UNBAN, "203.0.113.9", 0),
		"kill process":     reflex("g", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0),
		"garbage":          reflex("h", synapsev1.Action_ACTION_BAN_TEMP, "not-an-ip", 60),
		"huge ttl":         reflex("i", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.9", 1<<62),
		"negative ttl":     reflex("j", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.9", -5),
	} {
		t.Run(name, func(t *testing.T) { e.expect(req, safetyRef) })
	}
	if n := len(e.fw.Calls()); n != 2 { // Ensure + SetAllow only
		t.Fatalf("firewall calls = %d, want 2", n)
	}
}

func TestReflexBudget(t *testing.T) {
	e := newEnv(t)
	for i := range 50 {
		e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, fmt.Sprintf("203.0.%d.9", i), 60), okRes)
	}
	e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, "203.0.99.9", 60), budgetRef)
	if e.fw.Has(nft.KindBan, pfx("203.0.99.9/32")) {
		t.Fatal("over-budget target was banned")
	}
}

func TestReflexPrefixEscalation(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 11; i++ {
		e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, fmt.Sprintf("198.51.100.%d", i), 60), okRes)
	}
	if !e.fw.Has(nft.KindBan, pfx("198.51.100.0/24")) {
		t.Fatalf("expected /24 ban, calls: %v", e.fw.Calls())
	}
}

func TestReflexEscalationAvoidsProtectedPrefix(t *testing.T) {
	e := newEnv(t)
	// 192.168.1.0/24 is the interface subnet, but only .23 is protected here;
	// use a protected /32 inside a /24 the reflex would widen to.
	e.deps.Protected = testProtectedWith(t, &e.deps.Cfg, "198.51.100.200")
	e.start()
	for i := 1; i <= 11; i++ {
		e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, fmt.Sprintf("198.51.100.%d", i), 60), okRes)
	}
	if e.fw.Has(nft.KindBan, pfx("198.51.100.0/24")) {
		t.Fatal("widened prefix overlaps protected address")
	}
	if !e.fw.Has(nft.KindBan, pfx("198.51.100.11/32")) {
		t.Fatal("expected single-address fallback")
	}
}

func testProtectedWith(t *testing.T, base *config.Config, whitelisted string) *safety.Protected {
	t.Helper()
	wl := filepath.Join(t.TempDir(), "wl.txt")
	if err := os.WriteFile(wl, []byte(whitelisted+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := *base
	cfg.WhitelistFile = wl
	return testProtected(t, &cfg)
}

func TestReflexRateLimitUsesSingleAddress(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 11; i++ {
		e.expect(reflex("r", synapsev1.Action_ACTION_RATE_LIMIT, fmt.Sprintf("198.51.100.%d", i), 60), okRes)
	}
	if !e.fw.Has(nft.KindRateLimit, pfx("198.51.100.11/32")) {
		t.Fatal("rate limit should stay on the single address")
	}
}

func TestSignedAutomationBanAndReplay(t *testing.T) {
	e := newEnv(t)
	req := e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 3600)
	r := e.expect(req, okRes)
	if r.GetId() != "c1" {
		t.Fatalf("id = %q", r.GetId())
	}
	if !e.fw.Has(nft.KindBan, pfx("203.0.113.5/32")) {
		t.Fatal("not banned")
	}
	e.expect(req, replayRef)
}

func TestSignedCIDRAndRateLimit(t *testing.T) {
	e := newEnv(t)
	e.expect(e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.0/24", 3600), okRes)
	if !e.fw.Has(nft.KindBan, pfx("203.0.113.0/24")) {
		t.Fatal("cidr ban missing")
	}
	e.expect(e.auto("c2", synapsev1.Action_ACTION_RATE_LIMIT, "203.0.113.0/24", 60), safetyRef)
	e.expect(e.auto("c3", synapsev1.Action_ACTION_RATE_LIMIT, "203.0.113.7", 60), okRes)
	e.expect(e.auto("c4", synapsev1.Action_ACTION_BAN_TEMP, "192.168.0.0/16", 60), safetyRef)
	e.expect(e.auto("c5", synapsev1.Action_ACTION_BAN_TEMP, "10.0.0.0/8", 60), safetyRef) // too broad
}

func TestSignedRefusals(t *testing.T) {
	e := newEnv(t)
	forged := e.auto("f1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60)
	forged.GetSigned().Signature[0] ^= 0xff
	if r := e.expect(forged, sigRef); r.GetId() != "" {
		t.Fatalf("id on failed verification = %q", r.GetId())
	}

	p := e.payload("x1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60, 60)
	p.IssuedAt -= 1000
	p.ExpiresAt -= 1000
	e.expect(e.sign(e.autoKey, e.autoPub, p), sigRef) // expired

	p = e.payload("x2", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60, 60)
	p.AgentId = "other"
	e.expect(e.sign(e.autoKey, e.autoPub, p), sigRef)

	e.expect(e.sign(e.autoKey, e.autoPub, e.payload("", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60, 60)), sigRef)

	e.expect(e.auto("k1", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0), safetyRef)
	e.expect(e.auto("k2", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.5", 0), safetyRef)
	e.expect(e.auto("k3", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 8*24*3600), safetyRef)
	if len(e.kills) != 0 {
		t.Fatal("kill called")
	}
	// Policy refusals do not burn the command id.
	e.expect(e.admin("k1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.5", 0), okRes)
}

func TestAdminKillProcess(t *testing.T) {
	e := newEnv(t)
	p := e.payload("k1", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0, 600)
	p.TargetExec, p.TargetStartTime = "/usr/bin/evil", 987654
	e.expect(e.sign(e.admKey, e.admPub, p), okRes)
	if len(e.kills) != 1 || e.kills[0] != (killCall{4242, "/usr/bin/evil", 987654}) {
		t.Fatalf("kills = %+v", e.kills)
	}
	p = e.payload("k2", synapsev1.Action_ACTION_KILL_PROCESS, "pid:1", 0, 600)
	e.expect(e.sign(e.admKey, e.admPub, p), safetyRef)
	p = e.payload("k3", synapsev1.Action_ACTION_KILL_PROCESS, "pid:abc", 0, 600)
	e.expect(e.sign(e.admKey, e.admPub, p), safetyRef)
	p = e.payload("k4", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0, 600)
	p.TargetStartTime = -1
	e.expect(e.sign(e.admKey, e.admPub, p), safetyRef)
}

func TestKillErrorMapping(t *testing.T) {
	e := newEnv(t)
	for i, tc := range []struct {
		err  error
		want synapsev1.TurretResult
	}{
		{proc.ErrImmune, safetyRef},
		{fmt.Errorf("wrap: %w", proc.ErrMismatch), safetyRef},
		{proc.ErrNotTempPath, safetyRef},
		{proc.ErrNotInIOC, safetyRef},
		{proc.ErrMemfdOrDeleted, safetyRef},
		{errors.New("boom"), failedRes},
	} {
		e.killErr = tc.err
		e.expect(e.admin(fmt.Sprintf("k%d", i), synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0), tc.want)
	}
}

func TestKillTempMalware(t *testing.T) {
	e := newEnv(t)
	r := &synapsev1.TurretRequest{Kind: &synapsev1.TurretRequest_Reflex{Reflex: &synapsev1.ReflexRequest{
		RequestId: "r1", Action: synapsev1.Action_ACTION_KILL_TEMP_MALWARE, Pid: 777,
	}}}
	e.expect(r, okRes)
	e.expect(e.auto("k1", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "pid:888", 0), okRes)
	if len(e.temps) != 2 || e.temps[0] != 777 || e.temps[1] != 888 {
		t.Fatalf("temps = %v", e.temps)
	}
	r.GetReflex().Pid = 1
	e.expect(r, safetyRef)
	e.deps.IOC = func() (*ioc.Set, error) { return nil, errors.New("no bundle") }
	e.start()
	e.expect(e.auto("k2", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "pid:888", 0), failedRes)
}

func TestIsolateNotImplemented(t *testing.T) {
	e := newEnv(t)
	for _, a := range []synapsev1.Action{synapsev1.Action_ACTION_ISOLATE_HOST, synapsev1.Action_ACTION_RELEASE_HOST} {
		r := e.expect(e.admin("i-"+a.String(), a, "", 0), failedRes)
		if r.GetDetail() != "not implemented in v0.4.0" {
			t.Fatalf("detail = %q", r.GetDetail())
		}
	}
	e.expect(e.auto("i3", synapsev1.Action_ACTION_ISOLATE_HOST, "", 0), safetyRef)
}

func TestUnban(t *testing.T) {
	e := newEnv(t)
	e.expect(e.admin("p1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.5", 0), okRes)
	e.expect(e.auto("u1", synapsev1.Action_ACTION_UNBAN, "203.0.113.5", 0), safetyRef)
	if !e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("perm ban lifted by automation")
	}
	e.expect(e.admin("u2", synapsev1.Action_ACTION_UNBAN, "203.0.113.5", 0), okRes)
	if e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("perm ban still present")
	}
	// Record removed: a restart must not resurrect it.
	e.start()
	if e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("perm ban resurrected")
	}

	// Automation may lift a temp ban; reflex may not.
	e.expect(e.auto("t1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.6", 600), okRes)
	e.expect(reflex("r1", synapsev1.Action_ACTION_UNBAN, "203.0.113.6", 0), safetyRef)
	e.expect(e.auto("u3", synapsev1.Action_ACTION_UNBAN, "203.0.113.6", 0), okRes)
	if e.fw.Blocked(nft.KindBan, netip.MustParseAddr("203.0.113.6")) {
		t.Fatal("temp ban still present")
	}
	e.expect(e.auto("u4", synapsev1.Action_ACTION_UNBAN, "bogus", 0), safetyRef)
}

func TestRestartReappliesUnexpiredBans(t *testing.T) {
	e := newEnv(t)
	e.expect(e.auto("long", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.1", 600), okRes)
	e.expect(e.auto("short", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.2", 100), okRes)
	e.expect(e.admin("perm", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.0/28", 0), okRes)
	e.expect(e.auto("rl", synapsev1.Action_ACTION_RATE_LIMIT, "203.0.113.50", 300), okRes)
	replayed := e.auto("again", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.3", 60)
	e.expect(replayed, okRes)

	e.clk.Advance(200 * time.Second)
	e.fw = nft.NewFakeAt(e.clk.Now)
	e.deps.FW = e.fw
	e.start()

	if exp, ok := e.fw.Expiry(nft.KindBan, netip.MustParseAddr("203.0.113.1")); !ok || !exp.Equal(e.clk.Now().Add(400*time.Second)) {
		t.Fatalf("long ban = %v %v", exp, ok)
	}
	if e.fw.Blocked(nft.KindBan, netip.MustParseAddr("203.0.113.2")) {
		t.Fatal("expired ban re-okRes")
	}
	if !e.fw.Has(nft.KindPerm, pfx("203.0.113.0/28")) {
		t.Fatal("perm ban missing after restart")
	}
	if exp, ok := e.fw.Expiry(nft.KindRateLimit, netip.MustParseAddr("203.0.113.50")); !ok || !exp.Equal(e.clk.Now().Add(100*time.Second)) {
		t.Fatalf("ratelimit = %v %v", exp, ok)
	}
	// Expired record was dropped from the file.
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	if len(b) == 0 || strings.Contains(string(b), "203.0.113.2/32") {
		t.Fatalf("state not pruned: %s", b)
	}
	// Replay survives a restart.
	p := e.payload("again2", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.3", 60, 60)
	req := e.sign(e.autoKey, e.autoPub, p)
	e.expect(req, okRes)
	e.start()
	e.expect(req, replayRef)
}

func TestRestartKeepsReplayedIDRefused(t *testing.T) {
	e := newEnv(t)
	req := e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60)
	e.expect(req, okRes)
	e.start()
	e.expect(req, replayRef)
}

func TestStateFileModeAndMerge(t *testing.T) {
	e := newEnv(t)
	e.expect(e.auto("a", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 600), okRes)
	e.expect(e.auto("b", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60), okRes) // shorter: must not shorten
	fi, err := os.Stat(filepath.Join(e.state, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	e.clk.Advance(10 * time.Second)
	e.start()
	if exp, _ := e.fw.Expiry(nft.KindBan, netip.MustParseAddr("203.0.113.5")); !exp.Equal(e.clk.Now().Add(590 * time.Second)) {
		t.Fatalf("merged expiry = %v", exp)
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	e := newEnv(t)
	for _, body := range []string{"{not json", "null", `[{"prefix":"bad","kind":"ban"}]`, `[{"prefix":"1.2.3.4/32","kind":"weird"}]`} {
		if err := os.WriteFile(filepath.Join(e.state, stateFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(e.deps); err == nil {
			t.Fatalf("New accepted corrupt state %q", body)
		}
	}
}

func TestNewRequiresDeps(t *testing.T) {
	e := newEnv(t)
	d := e.deps
	d.FW = nil
	if _, err := New(d); err == nil {
		t.Fatal("expected error")
	}
}

func TestCrashSafetyRecordBeforeFirewall(t *testing.T) {
	e := newEnv(t)
	e.fw.FailNext(errors.New("nft down"))
	req := e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60)
	e.expect(req, failedRes)
	e.expect(req, replayRef)
	if e.fw.Has(nft.KindBan, pfx("203.0.113.5/32")) {
		t.Fatal("ban okRes despite firewall failure")
	}
	// Failed ban leaves no state record.
	if b, _ := os.ReadFile(filepath.Join(e.state, stateFile)); strings.Contains(string(b), "203.0.113.5") {
		t.Fatalf("state has failed ban: %s", b)
	}
}

func TestReplayRecordFailureIsFailedAndDoesNotAct(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Dir(e.replayP)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e.expect(e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60), failedRes)
	if e.fw.Has(nft.KindBan, pfx("203.0.113.5/32")) {
		t.Fatal("acted without recording")
	}
}

func TestAllowWinsOverExistingBan(t *testing.T) {
	e := newEnv(t)
	e.expect(e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.77", 600), okRes)
	e.deps.Protected = testProtectedWith(t, &e.deps.Cfg, "203.0.113.77")
	e.start()
	found := false
	for _, p := range e.fw.Allow() {
		if p.Contains(netip.MustParseAddr("203.0.113.77")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("allow = %v", e.fw.Allow())
	}
	// And new bans of it are refused outright.
	e.expect(e.auto("c2", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.77", 600), safetyRef)
}

func TestSetProtected(t *testing.T) {
	e := newEnv(t)
	p := testProtectedWith(t, &e.deps.Cfg, "203.0.113.90")
	if err := e.eng.SetProtected(p); err != nil {
		t.Fatal(err)
	}
	e.expect(e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.90", 60), safetyRef)
	if len(e.fw.Allow()) != len(p.Prefixes()) {
		t.Fatalf("allow not refreshed: %v", e.fw.Allow())
	}
	if err := e.eng.SetProtected(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

// TestBanNotAppliedAfterProtectedRefresh interleaves a ban with a refresh
// that protects its target: the ban must either be refused or be applied
// while the old protected set is still installed, never after the new one.
func TestBanNotAppliedAfterProtectedRefresh(t *testing.T) {
	e := newEnv(t)
	const target = "203.0.113.90"
	old := e.eng.prot.Load()
	newSet := testProtectedWith(t, &e.deps.Cfg, target)

	gate := make(chan struct{})
	blocked := make(chan struct{})
	var once sync.Once
	var lateBan atomic.Bool
	e.fw.OnCall(func(c nft.Call) {
		if c.Op != "Add" {
			return
		}
		if c.P.Addr() == netip.MustParseAddr("198.51.100.1") {
			once.Do(func() { close(blocked) })
			<-gate // hold request A inside the firewall
			return
		}
		if c.P.Contains(netip.MustParseAddr(target)) && e.eng.prot.Load() != old {
			lateBan.Store(true)
		}
	})

	var wg sync.WaitGroup
	res := make(chan synapsev1.TurretResult, 2)
	wg.Add(1)
	go func() { // A: an unrelated ban that blocks in Add
		defer wg.Done()
		res <- e.eng.Handle(e.auto("a", synapsev1.Action_ACTION_BAN_TEMP, "198.51.100.1", 60)).GetResult()
	}()
	<-blocked
	var bRes synapsev1.TurretResult
	wg.Add(2)
	go func() { // B: ban of the target, issued while the old set is current
		defer wg.Done()
		bRes = e.eng.Handle(e.auto("b", synapsev1.Action_ACTION_BAN_TEMP, target, 60)).GetResult()
	}()
	time.Sleep(50 * time.Millisecond) // let B reach its protected check
	go func() {                       // the refresh that adds the target's range
		defer wg.Done()
		if err := e.eng.SetProtected(newSet); err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if r := <-res; r != okRes {
		t.Fatalf("request A = %s", r)
	}
	if lateBan.Load() {
		t.Fatal("ban of a protected target applied after the refresh installed the new set")
	}
	if bRes != okRes && bRes != safetyRef {
		t.Fatalf("request B = %s", bRes)
	}
	if bRes == safetyRef && e.fw.Blocked(nft.KindBan, netip.MustParseAddr(target)) {
		t.Fatal("refused ban is in the firewall")
	}
}

func TestHandleNeverPanics(t *testing.T) {
	e := newEnv(t)
	for name, req := range map[string]*synapsev1.TurretRequest{
		"nil":           nil,
		"empty":         {},
		"nil reflex":    {Kind: &synapsev1.TurretRequest_Reflex{}},
		"nil signed":    {Kind: &synapsev1.TurretRequest_Signed{}},
		"empty reflex":  {Kind: &synapsev1.TurretRequest_Reflex{Reflex: &synapsev1.ReflexRequest{}}},
		"empty signed":  {Kind: &synapsev1.TurretRequest_Signed{Signed: &synapsev1.SignedCommand{}}},
		"garbage proto": {Kind: &synapsev1.TurretRequest_Signed{Signed: &synapsev1.SignedCommand{Payload: []byte{0xff, 0xff}, Scheme: synapsev1.SignatureScheme_SIGNATURE_SCHEME_ED25519}}},
	} {
		t.Run(name, func(t *testing.T) {
			if r := e.eng.Handle(req); r == nil || r.GetResult() == okRes {
				t.Fatalf("resp = %v", r)
			}
		})
	}
}

func TestHandleRecoversFromPanic(t *testing.T) {
	e := newEnv(t)
	e.deps.Kill = func(int, string, uint64) error { panic("boom") }
	e.start()
	r := e.eng.Handle(e.admin("k1", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0))
	if r.GetResult() != failedRes || r.GetDetail() != "internal error" {
		t.Fatalf("resp = %v", r)
	}
}

func TestConcurrentSameCommand(t *testing.T) {
	e := newEnv(t)
	req := e.auto("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 60)
	var wg sync.WaitGroup
	var nApplied, nReplay atomic.Int32
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch e.eng.Handle(req).GetResult() {
			case okRes:
				nApplied.Add(1)
			case replayRef:
				nReplay.Add(1)
			}
		}()
	}
	wg.Wait()
	if nApplied.Load() != 1 || nReplay.Load() != 15 {
		t.Fatalf("okRes=%d replay=%d", nApplied.Load(), nReplay.Load())
	}
}

func countApplied(e *env, act synapsev1.Action, addrs func(i int) string, n int) int {
	got := 0
	for i := range n {
		if e.eng.Handle(reflex("r", act, addrs(i), 60)).GetResult() == okRes {
			got++
		}
	}
	return got
}

func TestReflexBudgetNotBypassedByProtectedFallback(t *testing.T) {
	e := newEnv(t)
	e.deps.Protected = testProtectedWith(t, &e.deps.Cfg, "198.51.100.200")
	e.deps.Limiter = safety.NewReflexLimiter(e.deps.Cfg.ReflexBudget, e.deps.Cfg.PrefixLimiter, e.clk.Now)
	e.start()
	got := countApplied(e, synapsev1.Action_ACTION_BAN_TEMP, func(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }, 150)
	if got != 50 {
		t.Fatalf("applied = %d, want exactly the budget (50)", got)
	}
	if e.fw.Has(nft.KindBan, pfx("198.51.100.0/24")) {
		t.Fatal("/24 containing a protected address was banned")
	}
}

func TestReflexRateLimitBudgetAndNoEscalation(t *testing.T) {
	e := newEnv(t)
	got := countApplied(e, synapsev1.Action_ACTION_RATE_LIMIT, func(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }, 100)
	if got != 50 {
		t.Fatalf("rate limits applied = %d, want 50", got)
	}
	// Rate limits never count toward the >10 bans/prefix rule.
	e = newEnv(t)
	for i := 1; i <= 12; i++ {
		e.expect(reflex("r", synapsev1.Action_ACTION_RATE_LIMIT, fmt.Sprintf("198.51.100.%d", i), 60), okRes)
	}
	e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, "198.51.100.13", 60), okRes)
	if e.fw.Has(nft.KindBan, pfx("198.51.100.0/24")) || !e.fw.Has(nft.KindBan, pfx("198.51.100.13/32")) {
		t.Fatalf("rate limits caused escalation: %v", e.fw.Calls())
	}
}

func TestReflexAdmissionReleasedWhenFirewallFails(t *testing.T) {
	e := newEnv(t)
	for i := range 50 {
		if i == 0 {
			e.fw.FailNext(errors.New("nft down"))
			e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, "203.0.0.9", 60), failedRes)
			continue
		}
		e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, fmt.Sprintf("203.0.%d.9", i), 60), okRes)
	}
	// The failed attempt must not have consumed budget: one slot is left.
	e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, "203.0.99.9", 60), okRes)
	e.expect(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, "203.0.98.9", 60), budgetRef)
}

func TestStateFilePrunesExpiredRecords(t *testing.T) {
	e := newEnv(t)
	e.expect(e.auto("a", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.1", 60), okRes)
	e.clk.Advance(100 * time.Second)
	e.expect(e.auto("b", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.2", 60), okRes)
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	if strings.Contains(string(b), "203.0.113.1/32") || !strings.Contains(string(b), "203.0.113.2/32") {
		t.Fatalf("state = %s", b)
	}
}

func TestTTLClampReported(t *testing.T) {
	e := newEnv(t)
	r := e.expect(e.admin("c1", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.5", 1<<62), okRes)
	if !strings.Contains(r.GetDetail(), "ttl clamped to 100y") {
		t.Fatalf("detail = %q", r.GetDetail())
	}
	r = e.expect(e.admin("c2", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.6", 3600), okRes)
	if strings.Contains(r.GetDetail(), "clamped") {
		t.Fatalf("unexpected clamp note: %q", r.GetDetail())
	}
}

func TestPanicResponseKeepsID(t *testing.T) {
	e := newEnv(t)
	e.deps.Kill = func(int, string, uint64) error { panic("boom") }
	e.start()
	if r := e.eng.Handle(e.admin("k1", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0)); r.GetId() != "k1" {
		t.Fatalf("id = %q", r.GetId())
	}
	if r := e.eng.Handle(reflex("rq", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "", 0)); r.GetId() != "rq" && r.GetResult() == failedRes {
		t.Fatalf("id = %q", r.GetId())
	}
}

func TestKillNotExecutedWhenRecordFails(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Dir(e.replayP)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	e.expect(e.admin("k1", synapsev1.Action_ACTION_KILL_PROCESS, "pid:4242", 0), failedRes)
	if len(e.kills) != 0 {
		t.Fatalf("kill executed without a replay record: %v", e.kills)
	}
}

func TestConcurrentMixedFinalState(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	bans := map[string]bool{}
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("203.0.%d.9", i)
			r := e.eng.Handle(reflex("r", synapsev1.Action_ACTION_BAN_TEMP, ip, 60))
			mu.Lock()
			bans[ip] = r.GetResult() == okRes
			mu.Unlock()
			_ = e.eng.SetProtected(e.deps.Protected)
		}()
	}
	wg.Wait()
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	for ip, ok := range bans {
		if !ok {
			t.Fatalf("%s not applied", ip)
		}
		if !e.fw.Has(nft.KindBan, pfx(ip+"/32")) || !strings.Contains(string(b), ip+"/32") {
			t.Fatalf("%s missing from firewall or state", ip)
		}
	}
}

func TestPersistFailureRetriedOnNextMutationAndClose(t *testing.T) {
	e := newEnv(t)
	away := e.state + ".away"
	if err := os.Rename(e.state, away); err != nil {
		t.Fatal(err)
	}
	r := e.expect(e.auto("a", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.1", 600), okRes)
	if !strings.Contains(r.GetDetail(), "state not persisted") {
		t.Fatalf("detail = %q", r.GetDetail())
	}
	if err := e.eng.Close(); err == nil {
		t.Fatal("Close must report the pending persist failure")
	}
	if err := os.Rename(away, e.state); err != nil {
		t.Fatal(err)
	}
	e.expect(e.auto("b", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.2", 600), okRes)
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	if !strings.Contains(string(b), "203.0.113.1/32") || !strings.Contains(string(b), "203.0.113.2/32") {
		t.Fatalf("next mutation did not write the full state: %s", b)
	}

	// Close alone flushes a pending write.
	if err := os.Rename(e.state, away); err != nil {
		t.Fatal(err)
	}
	e.expect(e.auto("c", synapsev1.Action_ACTION_BAN_TEMP, "203.0.113.3", 600), okRes)
	if err := os.Rename(away, e.state); err != nil {
		t.Fatal(err)
	}
	if err := e.eng.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(e.state, stateFile))
	if !strings.Contains(string(b), "203.0.113.3/32") {
		t.Fatalf("Close did not flush: %s", b)
	}
}

// An UNBAN whose state save fails must not lift the ban: otherwise the next
// restart re-applies bans.json and the ban comes back while the caller was
// told it was removed.
func TestUnbanNotAppliedWhenStateSaveFails(t *testing.T) {
	e := newEnv(t)
	e.expect(e.admin("p1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.5", 0), okRes)
	away := e.state + ".away"
	if err := os.Rename(e.state, away); err != nil {
		t.Fatal(err)
	}
	e.expect(e.admin("u1", synapsev1.Action_ACTION_UNBAN, "203.0.113.5", 0), failedRes)
	if !e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("firewall ban lifted although the state save failed")
	}
	if err := os.Rename(away, e.state); err != nil {
		t.Fatal(err)
	}
	// Firewall and state agree: a retry with a new command unbans cleanly.
	e.expect(e.admin("u2", synapsev1.Action_ACTION_UNBAN, "203.0.113.5", 0), okRes)
	if e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("perm ban still present after a successful unban")
	}
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	if strings.Contains(string(b), "203.0.113.5/32") {
		t.Fatalf("unbanned record still in state: %s", b)
	}
}

// If the firewall rejects the UNBAN after the state was saved, the record is
// restored so state and kernel keep agreeing.
func TestUnbanFirewallFailureRestoresState(t *testing.T) {
	e := newEnv(t)
	e.expect(e.admin("p1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.5", 0), okRes)
	e.fw.FailNext(errors.New("netlink down"))
	e.expect(e.admin("u1", synapsev1.Action_ACTION_UNBAN, "203.0.113.5", 0), failedRes)
	if !e.fw.Has(nft.KindPerm, pfx("203.0.113.5/32")) {
		t.Fatal("ban missing after failed firewall remove")
	}
	b, _ := os.ReadFile(filepath.Join(e.state, stateFile))
	if !strings.Contains(string(b), "203.0.113.5/32") {
		t.Fatalf("record dropped from state although the firewall still bans it: %s", b)
	}
}

func TestRestartUnbanOfMergedImportedSpan(t *testing.T) {
	e := newEnv(t)
	e.expect(e.admin("p1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.1", 0), okRes)
	e.expect(e.admin("p2", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.2", 0), okRes)
	// Restart: the kernel table holds the two perms merged into one interval.
	e.fw = nft.NewFakeFrom(e.fw)
	e.deps.FW = e.fw
	e.start()
	e.expect(e.admin("u1", synapsev1.Action_ACTION_UNBAN, "203.0.113.1", 0), okRes)
	if e.fw.Blocked(nft.KindPerm, netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("unbanned address still dropped")
	}
	if !e.fw.Blocked(nft.KindPerm, netip.MustParseAddr("203.0.113.2")) {
		t.Fatal("other perm ban lost")
	}
}

func TestRestartWithoutStateFileKeepsImportedKernelState(t *testing.T) {
	e := newEnv(t)
	e.fw.Add(nft.KindPerm, pfx("198.18.0.0/15"), 0) //nolint:errcheck // fake
	e.fw = nft.NewFakeFrom(e.fw)
	e.deps.FW = e.fw
	e.start() // no bans.json exists
	if !e.fw.Blocked(nft.KindPerm, netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("imported state must be kept when bans.json is absent")
	}
	for _, c := range e.fw.Calls() {
		if c.Op == "Replace" {
			t.Fatal("Replace must not run without a state file")
		}
	}
}

func TestEmptyStateFileIsAuthoritative(t *testing.T) {
	e := newEnv(t)
	e.expect(e.admin("p1", synapsev1.Action_ACTION_BAN_PERM, "203.0.113.1", 0), okRes)
	e.expect(e.admin("u1", synapsev1.Action_ACTION_UNBAN, "203.0.113.1", 0), okRes)
	f := nft.NewFakeAt(e.clk.Now)
	f.Add(nft.KindPerm, pfx("198.18.0.0/15"), 0) //nolint:errcheck // fake
	e.fw, e.deps.FW = f, f
	e.start() // bans.json exists with zero records
	if f.Blocked(nft.KindPerm, netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("an empty bans.json must clear stale kernel bans")
	}
}

func TestIOCSetCachedUntilBundleChanges(t *testing.T) {
	e := newEnv(t)
	bundle := filepath.Join(t.TempDir(), "ioc.bin")
	if err := os.WriteFile(bundle, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	loads := 0
	e.deps.Cfg.IOCBundlePath = bundle
	e.deps.IOC = func() (*ioc.Set, error) { loads++; return &ioc.Set{}, nil }
	e.start()
	e.expect(e.auto("k1", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "pid:888", 0), okRes)
	e.expect(e.auto("k2", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "pid:889", 0), okRes)
	if loads != 1 {
		t.Fatalf("unchanged bundle loaded %d times, want 1", loads)
	}
	if err := os.WriteFile(bundle, []byte("version-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.expect(e.auto("k3", synapsev1.Action_ACTION_KILL_TEMP_MALWARE, "pid:890", 0), okRes)
	if loads != 2 {
		t.Fatalf("modified bundle loaded %d times, want 2", loads)
	}
}
