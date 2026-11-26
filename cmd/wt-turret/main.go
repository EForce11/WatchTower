// Command wt-turret is the root enforcement daemon: it receives Reflex
// requests from Sentry and signed commands from Core or admins over a Unix
// socket and enforces them through its own nftables table.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/EForce11/WatchTower/internal/turret/config"
	"github.com/EForce11/WatchTower/internal/turret/engine"
	"github.com/EForce11/WatchTower/internal/turret/nft"
	"github.com/EForce11/WatchTower/internal/turret/replay"
	"github.com/EForce11/WatchTower/internal/turret/safety"
	"github.com/EForce11/WatchTower/internal/turret/server"
	"github.com/EForce11/WatchTower/internal/turret/verify"
)

// Version is injected at build time via ldflags (-X main.Version=...).
var Version = "dev"

const (
	usage            = "usage: wt-turret serve --config <file> | panic-flush | version"
	protectedRefresh = 60 * time.Second
)

var errLocked = errors.New("another wt-turret is running")

// flush deletes the Turret firewall table; replaced in tests.
var flush = func() error {
	fw, err := nft.NewNFT()
	if err != nil {
		return err
	}
	return fw.Flush()
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "panic-flush":
		if err := flush(); err != nil {
			fmt.Fprintf(stderr, "panic-flush: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "watchtower firewall table removed")
		return 0
	case "version":
		fmt.Fprintf(stdout, "wt-turret %s\n", Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n%s\n", args[0], usage)
		return 2
	}
}

// acquireLock takes an exclusive, non-blocking flock on <stateDir>/turret.lock,
// creating stateDir (0700) if needed. The caller holds the file open for the
// process lifetime; closing it releases the lock.
func acquireLock(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "turret.lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path under configured state dir
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // fd fits int
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, fmt.Errorf("lock: %w", err)
	}
	return f, nil
}

// socketGroup resolves the socket group's gid. A missing group is tolerated
// only when not running as root (tests): the current gid is used then.
func socketGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err == nil {
		return strconv.Atoi(g.Gid)
	}
	if os.Geteuid() != 0 {
		return os.Getgid(), nil
	}
	return 0, fmt.Errorf("socket group %q: %w", name, err)
}

// prepareSocketDir creates the socket's parent dir (0750, root:gid as root).
func prepareSocketDir(socketPath string, gid int) error {
	dir := filepath.Dir(socketPath)
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return os.Chown(dir, 0, gid)
	}
	return nil
}

type protectedSetter interface {
	SetProtected(*safety.Protected) error
}

// refreshProtected re-runs discover every interval and installs the result
// when its prefixes changed. A discover error keeps the old set.
func refreshProtected(stop <-chan struct{}, interval time.Duration, cur *safety.Protected,
	discover func() (*safety.Protected, error), set protectedSetter, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		next, err := discover()
		if err != nil {
			log.Error("protected set refresh failed; keeping previous set", "err", err)
			continue
		}
		if slices.Equal(next.Prefixes(), cur.Prefixes()) {
			continue
		}
		if err := set.SetProtected(next); err != nil {
			log.Error("applying protected set failed", "err", err)
		}
		cur = next
		log.Info("protected set updated", "prefixes", fmt.Sprint(next.Prefixes()))
	}
}

func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/watchtower/turret.yaml", "path to turret.yaml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config %s: %v\n", *cfgPath, err)
		return 2
	}
	if len(cfg.AllowedUIDs) == 0 {
		fmt.Fprintln(stderr, "no allowed socket peers: set allowed_uids or create the watchtower user")
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))

	lock, err := acquireLock(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		if errors.Is(err, errLocked) {
			return 2
		}
		return 1
	}
	defer lock.Close()

	if err := runDaemon(&cfg, log); err != nil {
		log.Error("wt-turret failed", "err", err)
		return 1
	}
	return 0
}

func runDaemon(cfg *config.Config, log *slog.Logger) error {
	keys, err := verify.LoadKeyring(cfg.AutomationKey, cfg.AdminKeysDir)
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	rc, err := replay.Open(filepath.Join(cfg.StateDir, "replay.json"), time.Now)
	if err != nil {
		return fmt.Errorf("replay cache: %w", err)
	}
	discover := func() (*safety.Protected, error) { return safety.Discover(*cfg, safety.Sources{}) }
	prot, err := discover()
	if err != nil {
		return fmt.Errorf("discover protected set: %w", err)
	}
	fw, err := nft.NewNFT()
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	eng, err := engine.New(engine.Deps{
		Cfg:       *cfg,
		Keys:      keys,
		Replay:    rc,
		Protected: prot,
		Limiter:   safety.NewReflexLimiter(cfg.ReflexBudget, cfg.PrefixLimiter, time.Now),
		FW:        fw,
		Now:       time.Now,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	gid, err := socketGroup(cfg.SocketGroup)
	if err != nil {
		_ = eng.Close()
		return err
	}
	if err := prepareSocketDir(cfg.SocketPath, gid); err != nil {
		_ = eng.Close()
		return fmt.Errorf("socket dir: %w", err)
	}
	srv, err := server.New(cfg.SocketPath, gid, cfg.AllowedUIDs, eng.Handle, log)
	if err != nil {
		_ = eng.Close()
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	go refreshProtected(ctx.Done(), protectedRefresh, prot, discover, eng, log)

	log.Info("wt-turret serving", "socket", cfg.SocketPath, "version", Version)
	serveErr := srv.Serve(ctx)
	// Shutdown never flushes the firewall: bans persist across restarts.
	if err := eng.Close(); err != nil {
		log.Error("persisting ban state", "err", err)
	}
	return serveErr
}
