package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EForce11/WatchTower/internal/turret/config"
	"github.com/EForce11/WatchTower/internal/turret/safety"
)

func runCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func stubFlush(t *testing.T, fn func() error) {
	t.Helper()
	old := flush
	flush = fn
	t.Cleanup(func() { flush = old })
}

func TestPanicFlushNeedsNoConfig(t *testing.T) {
	called := false
	stubFlush(t, func() error { called = true; return nil })
	t.Chdir(t.TempDir()) // no config anywhere
	code, _, stderr := runCmd(t, "panic-flush")
	if code != 0 || !called {
		t.Fatalf("code=%d called=%v stderr=%q", code, called, stderr)
	}
}

func TestPanicFlushError(t *testing.T) {
	stubFlush(t, func() error { return errors.New("netlink boom") })
	code, _, stderr := runCmd(t, "panic-flush")
	if code != 1 || !strings.Contains(stderr, "netlink boom") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestServeMissingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.yaml")
	code, _, stderr := runCmd(t, "serve", "--config", path)
	if code != 2 || !strings.Contains(stderr, path) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestServeNoAllowedPeers(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "turret.yaml")
	body := "agent_id: a1\ncore_endpoint: 10.0.0.1:50051\nstate_dir: " + dir + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCmd(t, "serve", "--config", cfg)
	if code != 2 || !strings.Contains(stderr, "no allowed socket peers") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestUnknownSubcommandAndUsage(t *testing.T) {
	for _, args := range [][]string{{"bogus"}, {}} {
		code, _, stderr := runCmd(t, args...)
		if code != 2 || !strings.Contains(stderr, "usage:") {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCmd(t, "version")
	if code != 0 || stdout != "wt-turret "+Version+"\n" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestStateLockIsExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // created 0700 on demand
	first, err := acquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir: %v %v", fi, err)
	}
	if _, err := acquireLock(dir); !errors.Is(err, errLocked) {
		t.Fatalf("second lock err = %v, want errLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	_ = again.Close()
}

func TestServeSecondInstanceExits2(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "turret.yaml")
	body := "agent_id: a1\ncore_endpoint: 10.0.0.1:50051\nstate_dir: " + dir + "\nallowed_uids: [" + itoa(os.Getuid()) + "]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := acquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	code, _, stderr := runCmd(t, "serve", "--config", cfg)
	if code != 2 || !strings.Contains(stderr, "another wt-turret is running") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testCfg() config.Config {
	return config.Config{CoreEndpoint: "10.0.0.1:50051", WireGuardCIDR: "10.8.0.0/24"}
}

type fakeSetter struct {
	mu   sync.Mutex
	sets [][]netip.Prefix
	done chan struct{}
}

func (f *fakeSetter) SetProtected(p *safety.Protected) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, p.Prefixes())
	select {
	case f.done <- struct{}{}:
	default:
	}
	return nil
}

func TestRefreshProtectedKeepsOldSetOnError(t *testing.T) {
	cfgFn := func(a string) func() (*safety.Protected, error) {
		return func() (*safety.Protected, error) {
			return safety.Discover(testCfg(), safety.Sources{
				InterfaceAddrs: func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix(a)}, nil },
				RouteFiles:     [2]string{"/nonexistent4", "/nonexistent6"},
				ResolvConf:     "/nonexistent",
			})
		}
	}
	first, err := cfgFn("10.1.0.5/24")()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	discover := func() (*safety.Protected, error) {
		calls++
		switch calls {
		case 1:
			return first, nil // unchanged: no SetProtected
		case 2:
			return nil, errors.New("transient")
		default:
			return cfgFn("10.2.0.5/24")()
		}
	}
	set := &fakeSetter{done: make(chan struct{}, 1)}
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		refreshProtected(stop, time.Millisecond, first, discover, set, discardLogger())
		close(finished)
	}()
	select {
	case <-set.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no SetProtected after change")
	}
	close(stop)
	<-finished
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.sets) != 1 {
		t.Fatalf("SetProtected calls = %d, want 1 (unchanged and error ticks must not call it)", len(set.sets))
	}
}

type flakySetter struct {
	mu    sync.Mutex
	calls int
	last  []netip.Prefix
	ok    chan struct{}
}

func (f *flakySetter) SetProtected(p *safety.Protected) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls == 1 {
		return errors.New("setallow failed")
	}
	f.last = p.Prefixes()
	select {
	case f.ok <- struct{}{}:
	default:
	}
	return nil
}

func TestRefreshProtectedRetriesFailedApply(t *testing.T) {
	mk := func(a string) *safety.Protected {
		p, err := safety.Discover(testCfg(), safety.Sources{
			InterfaceAddrs: func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix(a)}, nil },
			RouteFiles:     [2]string{"/nonexistent4", "/nonexistent6"},
			ResolvConf:     "/nonexistent",
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	old, next := mk("10.1.0.5/24"), mk("10.2.0.5/24")
	set := &flakySetter{ok: make(chan struct{}, 1)}
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		refreshProtected(stop, time.Millisecond, old, func() (*safety.Protected, error) { return next, nil }, set, discardLogger())
		close(finished)
	}()
	select {
	case <-set.ok:
	case <-time.After(5 * time.Second):
		t.Fatal("failed SetProtected was never retried")
	}
	close(stop)
	<-finished
	set.mu.Lock()
	defer set.mu.Unlock()
	if !slices.Equal(set.last, next.Prefixes()) {
		t.Fatalf("last applied = %v, want %v", set.last, next.Prefixes())
	}
}

func TestPanicFlushClearStateMovesBans(t *testing.T) {
	stubFlush(t, func() error { return nil })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bans.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCmd(t, "panic-flush", "--clear-state", "--state-dir", dir)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "bans.json")); !os.IsNotExist(err) {
		t.Fatalf("bans.json still present: %v", err)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "bans.json.flushed-*"))
	if len(m) != 1 || !strings.Contains(stdout, m[0]) {
		t.Fatalf("flushed files=%v stdout=%q", m, stdout)
	}
}

func TestPanicFlushClearStateMissingFileIsFine(t *testing.T) {
	stubFlush(t, func() error { return nil })
	code, _, stderr := runCmd(t, "panic-flush", "--clear-state", "--state-dir", t.TempDir())
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestPanicFlushWithoutClearStateKeepsBans(t *testing.T) {
	stubFlush(t, func() error { return nil })
	dir := t.TempDir()
	p := filepath.Join(dir, "bans.json")
	_ = os.WriteFile(p, []byte(`[]`), 0o600)
	if code, _, stderr := runCmd(t, "panic-flush", "--state-dir", dir); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("bans.json must stay without --clear-state")
	}
}

func TestPanicFlushFailureLeavesState(t *testing.T) {
	stubFlush(t, func() error { return errors.New("netlink boom") })
	dir := t.TempDir()
	p := filepath.Join(dir, "bans.json")
	_ = os.WriteFile(p, []byte(`[]`), 0o600)
	if code, _, _ := runCmd(t, "panic-flush", "--clear-state", "--state-dir", dir); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("state must not be cleared when the flush failed")
	}
}

func TestPanicFlushBadFlag(t *testing.T) {
	stubFlush(t, func() error { t.Fatal("must not flush"); return nil })
	if code, _, _ := runCmd(t, "panic-flush", "--nope"); code != 2 {
		t.Fatalf("code=%d", code)
	}
}
