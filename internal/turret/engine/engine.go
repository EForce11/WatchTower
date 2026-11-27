// Package engine ties verification, the safety layer, the firewall and
// process killing together behind one request handler.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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

// maxTTL clamps client-supplied TTLs so converting seconds to a Duration
// cannot overflow (the limit is ~292 years). Policy limits are far below it.
const maxTTL = 100 * 365 * 24 * time.Hour

const stateFile = "bans.json"

// Deps are the engine's collaborators. Keys, Replay, Protected, Limiter and
// FW are required; the rest default to the production implementations.
type Deps struct {
	Cfg       config.Config
	Keys      *verify.Keyring
	Replay    *replay.Cache // opened with the same clock as Now
	Protected *safety.Protected
	Limiter   *safety.ReflexLimiter
	FW        nft.Firewall
	IOC       func() (*ioc.Set, error)
	Kill      func(pid int, exe string, start uint64) error
	KillTemp  func(pid int, s *ioc.Set) (string, error)
	Now       func() time.Time
	Log       *slog.Logger
}

// Engine handles Turret requests. It is safe for concurrent use.
type Engine struct {
	d    Deps
	prot atomic.Pointer[safety.Protected]

	mu    sync.Mutex // guards store and orders limiter + firewall + persist
	store *banStore

	iocMu    sync.Mutex // guards the verified IOC set cache
	iocSet   *ioc.Set
	iocStamp fileStamp
}

// fileStamp identifies a file version cheaply (mtime, size, inode).
type fileStamp struct {
	mtime int64
	size  int64
	ino   uint64
}

func stampOf(path string) (fileStamp, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, false
	}
	st := fileStamp{mtime: fi.ModTime().UnixNano(), size: fi.Size()}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.ino = sys.Ino
	}
	return st, true
}

// iocSetCached returns the verified IOC set, re-loading (and re-verifying)
// only when the bundle file changed, so a flood of KILL_TEMP_MALWARE requests
// cannot force a signature check per request.
func (e *Engine) iocSetCached() (*ioc.Set, error) {
	e.iocMu.Lock()
	defer e.iocMu.Unlock()
	st, ok := stampOf(e.d.Cfg.IOCBundlePath)
	if ok && e.iocSet != nil && st == e.iocStamp {
		return e.iocSet, nil
	}
	set, err := e.d.IOC()
	if err != nil {
		e.iocSet = nil
		return nil, err
	}
	if ok {
		e.iocSet, e.iocStamp = set, st
	} else {
		e.iocSet = nil
	}
	return set, nil
}

// New validates deps, loads persisted bans, prepares the firewall, installs
// the allow list and re-applies unexpired bans.
//
//nolint:gocritic // signature fixed by the Task 6 contract; called once
func New(d Deps) (*Engine, error) {
	if d.Keys == nil || d.Replay == nil || d.Protected == nil || d.Limiter == nil || d.FW == nil {
		return nil, errors.New("engine: Keys, Replay, Protected, Limiter and FW are required")
	}
	if d.Cfg.StateDir == "" {
		return nil, errors.New("engine: state_dir is required")
	}
	fillDefaults(&d)
	if err := os.MkdirAll(d.Cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("engine: state dir: %w", err)
	}
	now := d.Now()
	statePath := filepath.Join(d.Cfg.StateDir, stateFile)
	_, statErr := os.Stat(statePath)
	haveState := statErr == nil
	store, err := loadStore(statePath, now)
	if err != nil {
		return nil, err
	}
	e := &Engine{d: d, store: store}
	e.prot.Store(d.Protected)
	if err := d.FW.Ensure(); err != nil {
		return nil, fmt.Errorf("engine: firewall ensure: %w", err)
	}
	if err := d.FW.SetAllow(d.Protected.Prefixes()); err != nil {
		return nil, fmt.Errorf("engine: set allow list: %w", err)
	}
	// bans.json is authoritative once it exists; without it (first run or
	// lost state) whatever Ensure imported from the kernel is kept.
	if haveState {
		if err := e.replaceFromStore(now); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// fillDefaults installs production implementations for unset optional deps.
func fillDefaults(d *Deps) {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.IOC == nil {
		path, keys := d.Cfg.IOCBundlePath, d.Keys
		d.IOC = func() (*ioc.Set, error) { return ioc.Load(path, keys) }
	}
	if d.Kill == nil {
		d.Kill = proc.Kill
	}
	if d.KillTemp == nil {
		d.KillTemp = func(pid int, s *ioc.Set) (string, error) {
			return proc.KillTempMalware(pid, s, proc.DefaultTempDirs)
		}
	}
}

// replaceFromStore makes the firewall hold exactly the persisted records.
func (e *Engine) replaceFromStore(now time.Time) error {
	recs := e.store.sorted()
	entries := make([]nft.Entry, 0, len(recs))
	for _, r := range recs {
		k, err := parseRecord(r)
		if err != nil {
			return err
		}
		ent := nft.Entry{Kind: k.kind, Prefix: k.prefix}
		if k.kind != nft.KindPerm {
			ent.Deadline = time.Unix(r.ExpiresAt, 0)
			if !ent.Deadline.After(now) {
				continue
			}
		}
		entries = append(entries, ent)
	}
	if err := e.d.FW.Replace(entries); err != nil {
		return fmt.Errorf("engine: restore bans: %w", err)
	}
	return nil
}

// SetProtected swaps the protected set and refreshes the firewall allow
// list. The new set is used for overlap checks even if SetAllow fails. It
// holds e.mu like netAction, so a ban checked against the old set is
// applied before the new set is installed, never after.
func (e *Engine) SetProtected(p *safety.Protected) error {
	if p == nil {
		return errors.New("engine: nil protected set")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prot.Store(p)
	return e.d.FW.SetAllow(p.Prefixes())
}

// cmd is a request after origin resolution, common to both paths.
type cmd struct {
	id      string
	origin  safety.Origin
	action  synapsev1.Action
	target  string
	ttl     time.Duration
	clamped bool  // ttl was clamped to maxTTL
	pid     int32 // reflex only
	exe     string
	start   int64
	record  func() error // replay recording (signed only)
}

func ttlOf(secs int64) (ttl time.Duration, clamped bool) {
	switch {
	case secs <= 0:
		return 0, false
	case secs >= int64(maxTTL/time.Second):
		return maxTTL, true
	default:
		return time.Duration(secs) * time.Second, false
	}
}

// Close flushes ban state that could not be persisted earlier and stops the
// firewall's background work (its kernel contents stay in place).
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(e.save(), e.d.FW.Close())
}

// save persists the store (pruning expired records); e.mu is held. Every
// save writes the full state, so a failed one is repaired by the next.
func (e *Engine) save() error {
	return e.store.persist(e.d.Now())
}

func originName(o safety.Origin) string {
	switch o {
	case safety.OriginReflex:
		return "reflex"
	case safety.OriginAutomation:
		return "automation"
	case safety.OriginAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// Handle processes one request. It never panics.
func (e *Engine) Handle(req *synapsev1.TurretRequest) (resp *synapsev1.TurretResponse) {
	id := requestID(req)
	defer func() {
		if r := recover(); r != nil {
			e.d.Log.Error("turret handler panic", "panic", fmt.Sprint(r), "id", id)
			resp = reply(id, synapsev1.TurretResult_TURRET_RESULT_FAILED, "internal error")
		}
	}()
	switch {
	case req.GetReflex() != nil:
		return e.handleReflex(req.GetReflex())
	case req.GetSigned() != nil:
		return e.handleSigned(req.GetSigned())
	default:
		e.d.Log.Warn("turret decision", "origin", "unknown", "result", "FAILED", "reason", "empty request")
		return reply("", synapsev1.TurretResult_TURRET_RESULT_FAILED, "empty request")
	}
}

// requestID extracts the id without verifying anything; it is only used to
// label a panic response. Signed payloads are decoded best-effort.
func requestID(req *synapsev1.TurretRequest) string {
	if r := req.GetReflex(); r != nil {
		return r.GetRequestId()
	}
	if sc := req.GetSigned(); sc != nil {
		var p synapsev1.CommandPayload
		if proto.Unmarshal(sc.GetPayload(), &p) == nil {
			return p.GetCommandId()
		}
	}
	return ""
}

func reply(id string, r synapsev1.TurretResult, detail string) *synapsev1.TurretResponse {
	return &synapsev1.TurretResponse{Id: id, Result: r, Detail: detail}
}

func (e *Engine) handleReflex(r *synapsev1.ReflexRequest) *synapsev1.TurretResponse {
	ttl, clamped := ttlOf(r.GetTtlSeconds())
	c := &cmd{
		id:      r.GetRequestId(),
		origin:  safety.OriginReflex,
		action:  r.GetAction(),
		target:  r.GetTarget(),
		ttl:     ttl,
		clamped: clamped,
		pid:     r.GetPid(),
	}
	return e.finish(c, e.dispatch(c))
}

func (e *Engine) handleSigned(sc *synapsev1.SignedCommand) *synapsev1.TurretResponse {
	v, err := e.d.Keys.Verify(sc, e.d.Cfg.AgentID, e.d.Now())
	if err != nil {
		e.d.Log.Warn("turret decision", "origin", "unverified", "result", "REFUSED_SIGNATURE", "reason", err.Error())
		return reply("", synapsev1.TurretResult_TURRET_RESULT_REFUSED_SIGNATURE, err.Error())
	}
	p := v.Payload
	if p.GetCommandId() == "" {
		e.d.Log.Warn("turret decision", "origin", "unverified", "result", "REFUSED_SIGNATURE", "reason", "missing command_id")
		return reply("", synapsev1.TurretResult_TURRET_RESULT_REFUSED_SIGNATURE, "missing command_id")
	}
	id, exp := p.GetCommandId(), time.Unix(p.GetExpiresAt(), 0)
	ttl, clamped := ttlOf(p.GetTtlSeconds())
	c := &cmd{
		id:      id,
		origin:  safety.OriginFor(v.Class),
		action:  p.GetAction(),
		target:  p.GetTarget(),
		ttl:     ttl,
		clamped: clamped,
		exe:     p.GetTargetExec(),
		start:   p.GetTargetStartTime(),
		record:  func() error { return e.d.Replay.Record(id, exp) },
	}
	return e.finish(c, e.dispatch(c))
}

type outcome struct {
	result synapsev1.TurretResult
	detail string
}

func refused(format string, args ...any) outcome {
	return outcome{synapsev1.TurretResult_TURRET_RESULT_REFUSED_SAFETY, fmt.Sprintf(format, args...)}
}

func failed(format string, args ...any) outcome {
	return outcome{synapsev1.TurretResult_TURRET_RESULT_FAILED, fmt.Sprintf(format, args...)}
}

func applied(format string, args ...any) outcome {
	return outcome{synapsev1.TurretResult_TURRET_RESULT_APPLIED, fmt.Sprintf(format, args...)}
}

func (e *Engine) finish(c *cmd, o outcome) *synapsev1.TurretResponse {
	lvl := slog.LevelInfo
	if o.result != synapsev1.TurretResult_TURRET_RESULT_APPLIED {
		lvl = slog.LevelWarn
	}
	e.d.Log.Log(context.Background(), lvl, "turret decision",
		"origin", originName(c.origin), "action", c.action.String(), "target", c.target,
		"id", c.id, "result", o.result.String(), "reason", o.detail)
	return reply(c.id, o.result, o.detail)
}

// commit records the replay id (signed commands). It runs after all checks
// and before any side effect, so a crash can never replay an applied command.
func (e *Engine) commit(c *cmd) (outcome, bool) {
	if c.record == nil {
		return outcome{}, true
	}
	err := c.record()
	switch {
	case err == nil:
		return outcome{}, true
	case errors.Is(err, replay.ErrSeen):
		return outcome{synapsev1.TurretResult_TURRET_RESULT_REFUSED_REPLAY, "command already processed"}, false
	default:
		return failed("replay cache: %v", err), false
	}
}

func (e *Engine) dispatch(c *cmd) outcome {
	if d := safety.Check(c.origin, c.action, c.ttl); !d.Allowed {
		return outcome{d.Result, d.Reason}
	}
	switch c.action {
	case synapsev1.Action_ACTION_BAN_TEMP, synapsev1.Action_ACTION_BAN_PERM,
		synapsev1.Action_ACTION_RATE_LIMIT, synapsev1.Action_ACTION_UNBAN:
		return e.netAction(c)
	case synapsev1.Action_ACTION_KILL_PROCESS, synapsev1.Action_ACTION_KILL_TEMP_MALWARE:
		return e.killAction(c)
	default:
		return failed("not implemented in v0.4.0")
	}
}

func isSingle(p netip.Prefix) bool { return p.Bits() == p.Addr().BitLen() }

func (e *Engine) netAction(c *cmd) outcome {
	prefix, err := safety.ParseNetTarget(c.target, c.origin)
	if err != nil {
		return refused("%v", err)
	}
	if c.action == synapsev1.Action_ACTION_RATE_LIMIT && !isSingle(prefix) {
		return refused("rate limit requires a single address")
	}
	// The protected check, limiter and firewall change form one critical
	// section with SetProtected, so a refresh cannot install a set covering
	// the target between the check and the ban.
	e.mu.Lock()
	defer e.mu.Unlock()
	// UNBAN is allowed to touch protected ranges so stale bans can be lifted.
	if c.action != synapsev1.Action_ACTION_UNBAN {
		if hit, bad := e.prot.Load().Overlaps(prefix); bad {
			return refused("target %s overlaps protected range %s", prefix, hit)
		}
	}
	if c.action == synapsev1.Action_ACTION_UNBAN && e.store.hasPerm(prefix) && c.origin != safety.OriginAdmin {
		return refused("permanent ban requires admin to lift")
	}
	if o, ok := e.commit(c); !ok {
		return o
	}
	if c.action == synapsev1.Action_ACTION_UNBAN {
		return e.unban(prefix)
	}
	if c.origin == safety.OriginReflex {
		var ok bool
		if prefix, ok = e.admitReflex(prefix, c.action); !ok {
			return outcome{synapsev1.TurretResult_TURRET_RESULT_REFUSED_BUDGET, "reflex budget exhausted"}
		}
	}
	return e.ban(c, prefix)
}

// admitReflex accounts a reflex action with the limiter and returns the
// prefix to act on; e.mu is held. The limiter only widens to a prefix that does not touch
// a protected range, so what it records is what is applied. Rate limits
// always act on the single address and never widen.
func (e *Engine) admitReflex(single netip.Prefix, a synapsev1.Action) (netip.Prefix, bool) {
	if a == synapsev1.Action_ACTION_RATE_LIMIT {
		return single, e.d.Limiter.AdmitSingle(single.Addr())
	}
	prot := e.prot.Load()
	return e.d.Limiter.Admit(single.Addr(), func(p netip.Prefix) bool {
		_, hit := prot.Overlaps(p)
		return !hit
	})
}

func expiryUnix(now time.Time, ttl time.Duration) int64 {
	t := now.Add(ttl)
	exp := t.Unix()
	if t.Nanosecond() > 0 {
		exp++ // round up: never shorten
	}
	return exp
}

// ban applies and persists a ban; e.mu is held.
func (e *Engine) ban(c *cmd, p netip.Prefix) outcome {
	var kind nft.Kind
	switch c.action {
	case synapsev1.Action_ACTION_BAN_PERM:
		kind = nft.KindPerm
	case synapsev1.Action_ACTION_RATE_LIMIT:
		kind = nft.KindRateLimit
	default:
		kind = nft.KindBan
	}
	ttl := c.ttl
	if kind == nft.KindPerm {
		ttl = 0
	}
	now := e.d.Now()
	if err := e.d.FW.Add(kind, p, ttl); err != nil {
		if c.origin == safety.OriginReflex {
			e.d.Limiter.Release(p)
		}
		return failed("firewall: %v", err)
	}
	var exp int64
	if kind != nft.KindPerm {
		exp = expiryUnix(now, ttl)
	}
	e.store.put(recKey{p, kind}, exp)
	note := ""
	if c.clamped && kind != nft.KindPerm {
		note = " (ttl clamped to 100y)"
	}
	if err := e.save(); err != nil {
		e.d.Log.Error("persist ban state", "err", err)
		return applied("%s %s%s applied; state not persisted: %v", kind, p, note, err)
	}
	return applied("%s %s%s", kind, p, note)
}

// unban removes p from the firewall and the state; e.mu is held.
// unban persists the removal before touching the firewall. bans.json is
// authoritative on restart, so lifting a ban the state file still holds would
// let the next start re-apply it after the caller was told it was removed.
// Either step failing leaves state and kernel as they were.
func (e *Engine) unban(p netip.Prefix) outcome {
	prev := maps.Clone(e.store.recs)
	e.store.deletePrefix(p)
	if err := e.save(); err != nil {
		e.store.recs = prev
		e.d.Log.Error("persist ban state", "err", err)
		return failed("unban %s not applied: state not persisted: %v", p, err)
	}
	if err := e.d.FW.Remove(p); err != nil {
		e.store.recs = prev
		if perr := e.save(); perr != nil {
			e.d.Log.Error("restore ban state after failed unban", "err", perr)
		}
		return failed("firewall: %v", err)
	}
	return applied("unban %s", p)
}

func (e *Engine) killAction(c *cmd) outcome {
	pid := int(c.pid)
	if c.origin != safety.OriginReflex {
		var err error
		if pid, err = safety.ParsePIDTarget(c.target); err != nil {
			return refused("%v", err)
		}
	} else if pid <= 1 {
		return refused("invalid pid %d", pid)
	}
	if c.action == synapsev1.Action_ACTION_KILL_PROCESS && c.start < 0 {
		return refused("invalid target_start_time")
	}
	if o, ok := e.commit(c); !ok {
		return o
	}
	if c.action == synapsev1.Action_ACTION_KILL_PROCESS {
		if err := e.d.Kill(pid, c.exe, uint64(c.start)); err != nil { //nolint:gosec // checked >= 0 above
			return killErr(err)
		}
		return applied("killed pid %d", pid)
	}
	set, err := e.iocSetCached()
	if err != nil {
		return failed("ioc bundle: %v", err)
	}
	path, err := e.d.KillTemp(pid, set)
	if err != nil {
		return killErr(err)
	}
	return applied("killed pid %d (%s)", pid, path)
}

func killErr(err error) outcome {
	for _, safe := range []error{proc.ErrImmune, proc.ErrNotTempPath, proc.ErrNotInIOC, proc.ErrMemfdOrDeleted, proc.ErrMismatch} {
		if errors.Is(err, safe) {
			return refused("%v", err)
		}
	}
	return failed("kill: %v", err)
}
