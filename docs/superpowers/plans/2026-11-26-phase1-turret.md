# Phase 1 — `wt-turret` (Safety First) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `wt-turret`, the privileged enforcement daemon. It accepts Reflex requests from Sentry and signed commands from Core/admins over a Unix socket, refuses anything the safety layer forbids, and enforces through its own nftables table with a one-command rollback. Target: `v0.4.0`.

**Architecture:** Each concern is a small package under `internal/turret/`, unit-tested without privileges:
- `config`: configuration
- `verify`: keys and signatures
- `replay`: replay cache
- `safety`: protected ranges, policy, budgets
- `ioc`: signed IOC bundle
- `proc`: process inspection and kill
- `nft`: firewall
- `engine`: orchestration and persisted state
- `server`: socket

Only `nft` touches the kernel. Its integration tests run inside a user and network namespace (`unshare -Urn`), so they need no real root. `cmd/wt-turret` wires everything together.

**Tech Stack:** Go 1.25 (`CGO_ENABLED=0`), `github.com/google/nftables` (pure-Go netlink), `golang.org/x/sys/unix` (pidfd, `SO_PEERCRED`), `github.com/vishvananda/netns` and `github.com/vishvananda/netlink` (test-only, veth and namespaces), stdlib `crypto/ed25519`, `crypto/x509`.

**Spec:** `docs/architecture.md` (v3.2) §3.4, §5.1, §5.2, §7 Phase 1, §9.

## Global Constraints

- Every binary builds with `CGO_ENABLED=0 go build ./...`. No shelling out to `nft`, `iptables`, `ip` or `kill` from production code.
- Turret owns exactly one nftables table, `inet watchtower`, with the sets and chain layout of spec §3.4.2 (chain `input`, hook input, priority `-10`, policy accept, allow sets evaluated first). It never touches other tables.
- Self-preservation is hardcoded and cannot be overridden by any command, signed or not: `127.0.0.0/8`, `::1/128`, `169.254.0.0/16`, `fe80::/10`, all local interface addresses, default gateways, DNS resolvers from `/etc/resolv.conf`, the Core endpoint, the WireGuard subnet, and every entry of the whitelist file.
- Origin × action table exactly as spec §3.4.1. TTL limits: `RATE_LIMIT` ≤ 900 s for every origin; REFLEX `BAN_TEMP` ≤ 900 s; automation `BAN_TEMP` ≤ 604800 s (7 d); admin `BAN_TEMP` > 0 with no upper bound.
- Reflex budget: at most 50 distinct targets per rolling 10 minutes (configurable). Prefix limiter: more than 10 Reflex bans inside one IPv4 `/24` or IPv6 `/64` within 60 s → ban the prefix instead (configurable).
- Signed-command verification order and window exactly as spec §5.2. Clock skew 30 s. Lifetime `expires_at − issued_at` ≤ 120 s for the automation key and ≤ 3600 s for admin keys.
- `key_id` = lowercase hex SHA-256 of the raw 32-byte Ed25519 public key. Public keys are PEM `PUBLIC KEY` (PKIX).
- IPC uses `synapsev1.WriteFrame` / `ReadFrame` (max 65536 bytes). The server closes a connection after any read or parse error.
- `golangci-lint` v1.64.8 (v1 config) stays clean. `make verify` passes.

## Scope rulings (decided in this plan; record them in the ledger)

- **`ISOLATE_HOST` / `RELEASE_HOST` are not enforced in v0.4.0.** They pass verification and policy (admin key only), then return `TURRET_RESULT_FAILED` with detail `not implemented in v0.4.0`. Isolation needs the admin approval tooling (Phase 4) and its own netns test. Spec §3.4.4 stays the target design.
- **`SIGNATURE_SCHEME_WEBAUTHN_ES256` is refused** (`TURRET_RESULT_REFUSED_SIGNATURE`, detail `scheme not supported until Phase 5`). Only Ed25519 is verified in this phase.
- **`KILL_TEMP_MALWARE` gets the same re-verification for every origin** (temp-dir prefix, Turret's own SHA-256, signed IOC bundle), not just for REFLEX. This is stricter than the spec table and costs nothing.
- **Network targets must be at least `/16` (IPv4) or `/32` (IPv6).** REFLEX targets must be single addresses; prefix bans come only from the prefix limiter. A target is refused if it *overlaps* any protected range, not only if it is contained in one.
- **The agent ID comes from config** (`agent_id`). Enrollment writes it in Phase 3.
- **Bans survive restarts and reboots.** A JSON state file holds permanent bans and temporary bans with their expiry. On start the engine re-applies the ones not yet expired.
- **The IOC bundle format is new.** The spec names a "Core-signed IOC bundle" but never defines it. Task 1 adds `ioc.proto`.

## Review Focus

1. **A ban that covers a protected range.** For example, `10.8.0.0/16` while the WireGuard subnet is `10.8.0.0/24`, or `0.0.0.0/0`. It must be refused (Task 3 tests overlap and minimum prefix length).
2. **A replayed command after a Turret restart.** The seen-ID cache must be persisted *before* the action runs, so a crash mid-action cannot allow a second run (Tasks 2 and 6 test reload).
3. **PID reuse between check and kill.** The exe path or start time must change and the kill must refuse. Killing goes through a pidfd opened before the checks (Task 4 tests a mismatched `start_time` and a mismatched exe).
4. **A hostile Sentry floods the socket.** Oversized frames, garbage, many connections: each bad connection is closed, the connection count is capped, and other clients keep working (Task 6 tests garbage, oversize and the cap).
5. **`panic-flush` when the config or keys are broken.** It must still delete the table, because it is the emergency path (Task 7 tests `panic-flush` with a missing config file).

---

## File Structure

```
proto/watchtower/synapse/v1/ioc.proto      # IocBundle, SignedIocBundle (new)
pkg/synapse/v1/ioc.pb.go                   # generated
internal/turret/config/   config.go, config_test.go
internal/turret/verify/   keys.go, verify.go, verify_test.go
internal/turret/replay/   replay.go, replay_test.go
internal/turret/safety/   protected.go, target.go, policy.go, limiter.go, *_test.go
internal/turret/ioc/      bundle.go, bundle_test.go
internal/turret/proc/     inspect.go, kill.go, proc_test.go
internal/turret/nft/      firewall.go, nft.go, nft_netns_test.go (build tag netns)
internal/turret/engine/   engine.go, state.go, engine_test.go
internal/turret/server/   server.go, server_test.go
cmd/wt-turret/            main.go
configs/turret.yaml
```

---

### Task 1: IOC bundle contract and Turret config

**Files:**
- Create: `proto/watchtower/synapse/v1/ioc.proto`, generated `pkg/synapse/v1/ioc.pb.go`
- Create: `internal/turret/config/config.go`, `config_test.go`, `configs/turret.yaml`

**Interfaces:**
- Produces (proto):
  - `IocBundle { uint64 version = 1; int64 issued_at = 2; repeated bytes sha256 = 3; repeated string cidrs = 4; }`
  - `SignedIocBundle { bytes payload = 1; bytes signature = 2; string key_id = 3; }` (the signature covers `payload`, a serialized `IocBundle`)
- Produces (Go, package `config`):
  ```go
  type Config struct {
      AgentID        string   `yaml:"agent_id"`
      SocketPath     string   `yaml:"socket_path"`      // default /run/watchtower/turret.sock
      SocketGroup    string   `yaml:"socket_group"`     // default watchtower
      AllowedUIDs    []int    `yaml:"allowed_uids"`     // peers allowed on the socket; default: uid of user "watchtower"
      AutomationKey  string   `yaml:"automation_key"`   // default /etc/watchtower/automation.pub
      AdminKeysDir   string   `yaml:"admin_keys_dir"`   // default /etc/watchtower/admin_keys.d
      IOCBundlePath  string   `yaml:"ioc_bundle"`       // default /var/lib/watchtower/ioc.bundle
      StateDir       string   `yaml:"state_dir"`        // default /var/lib/watchtower/turret
      WhitelistFile  string   `yaml:"whitelist_file"`   // default /etc/watchtower/whitelist.txt
      CoreEndpoint   string   `yaml:"core_endpoint"`    // host:port; host must be an IP literal
      WireGuardCIDR  string   `yaml:"wireguard_cidr"`   // default 10.8.0.0/24
      ReflexBudget   Budget   `yaml:"reflex_budget"`    // default {MaxTargets: 50, Window: 10m}
      PrefixLimiter  Limiter  `yaml:"prefix_limiter"`   // default {Threshold: 10, Window: 60s}
  }
  type Budget  struct { MaxTargets int; Window time.Duration }
  type Limiter struct { Threshold int; Window time.Duration }
  func Load(path string) (Config, error)   // defaults applied, then Validate
  func (c Config) Validate() error
  ```

- [ ] **Step 1: Write `ioc.proto`** (same package and `go_package` as the other v1 files) and run `make proto`. Verify: `buf lint` is clean and `make proto-check` leaves no diff after commit.
- [ ] **Step 2: Write failing tests** in `config_test.go`:
  - `TestLoadDefaults`: a minimal file containing only `agent_id` and `core_endpoint: "10.8.0.1:50051"` gives every default above.
  - `TestValidate` table cases:
    - empty `agent_id` → error
    - `core_endpoint` with a hostname (`core.example:50051`) → error "must be an IP"
    - invalid `wireguard_cidr` → error
    - `reflex_budget.max_targets` ≤ 0 → error
    - `prefix_limiter.threshold` ≤ 0 → error
    - a relative `socket_path` → error
  - `TestLoadMissingFile` → error wrapping `fs.ErrNotExist`.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** Use `gopkg.in/yaml.v3` with `KnownFields(true)`, so an unknown key is an error. Durations are YAML strings parsed by `time.ParseDuration`; give `Budget` and `Limiter` YAML tags `max_targets`, `window` and `threshold`. Resolve `AllowedUIDs` from user `watchtower` only when the list is empty and the user exists (`os/user`). Otherwise leave it empty; `serve` will refuse to start in that case (Task 7).
- [ ] **Step 5: Run** `go test -race ./internal/turret/config/` → PASS. Write `configs/turret.yaml` with every key and its default commented. **Commit** (`feat(turret): IOC bundle contract and config`).

---

### Task 2: Key loading, signature verification, replay cache

**Files:**
- Create: `internal/turret/verify/keys.go`, `verify.go`, `verify_test.go`
- Create: `internal/turret/replay/replay.go`, `replay_test.go`

**Interfaces:**
- Consumes: `synapsev1.SignedCommand`, `CommandPayload`, `SignatureScheme` (Phase 0).
- Produces (package `verify`):
  ```go
  type KeyClass int
  const ( KeyAutomation KeyClass = iota + 1; KeyAdmin )
  type Keyring struct { /* id → (pub, class) */ }
  func KeyID(pub ed25519.PublicKey) string
  func LoadKeyring(automationPEM string, adminDir string) (*Keyring, error) // admin dir may be missing → no admin keys
  func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error)
  type Verified struct { Payload *synapsev1.CommandPayload; Class KeyClass; KeyID string }
  var ( ErrUnknownKey, ErrBadSignature, ErrUnsupportedScheme, ErrWrongAgent, ErrNotYetValid, ErrExpired, ErrLifetime error )
  func (k *Keyring) Verify(sc *synapsev1.SignedCommand, agentID string, now time.Time) (Verified, error)
  ```
- Produces (package `replay`):
  ```go
  type Cache struct { /* command_id → expires_at */ }
  func Open(path string, now time.Time) (*Cache, error)   // loads, drops expired; missing file = empty
  func (c *Cache) Seen(id string) bool
  func (c *Cache) Record(id string, expiresAt time.Time) error // persists atomically BEFORE returning
  ```

- [ ] **Step 1: Write failing tests.**
  - Verify, with keys generated in the test (`ed25519.GenerateKey`):
    - valid automation command → `Class == KeyAutomation`
    - valid admin command → `KeyAdmin`
    - unknown `key_id` → `ErrUnknownKey`
    - one flipped payload byte → `ErrBadSignature`
    - WebAuthn scheme → `ErrUnsupportedScheme`
    - `agent_id` mismatch → `ErrWrongAgent`
    - `now < issued_at − 30s` → `ErrNotYetValid`, while `now = issued_at − 29s` passes
    - `now > expires_at` → `ErrExpired`
    - automation lifetime 121 s → `ErrLifetime`, while 120 s passes
    - admin lifetime 3601 s → `ErrLifetime`
    - an admin key file that also equals the automation key → the load errors (a key can't be in both classes)
  - Keys: `ParsePublicKeyPEM` rejects RSA and garbage. `KeyID` is 64 lowercase hex characters.
  - Replay:
    - `Record` then `Seen` → true
    - reopen the file → still `Seen`
    - reopen after expiry → not seen, and the file is pruned
    - a corrupt file → `Open` errors (fail closed; Turret must not run without a replay cache)
    - `Record` writes via a temp file plus `os.Rename` in the same directory: a leftover `*.tmp` in the dir is ignored by `Open`
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.**
  - Verification order: scheme → key known → `ed25519.Verify` over `sc.Payload` → `proto.Unmarshal` → agent → window → lifetime.
  - The replay file is JSON `{"<id>": <unix expires_at>}`, mode `0600`. `Record` is safe for concurrent use (mutex). After writing the temp file and before the rename, call `f.Sync()`.
- [ ] **Step 4: Run** `go test -race ./internal/turret/verify/ ./internal/turret/replay/` → PASS. **Commit** (`feat(turret): signature verification and persistent replay cache`).

---

### Task 3: Safety layer

**Files:**
- Create: `internal/turret/safety/protected.go`, `target.go`, `policy.go`, `limiter.go` and tests

**Interfaces:**
- Consumes: `config.Config`, `verify.KeyClass`, `synapsev1.Action`.
- Produces:
  ```go
  type Origin int
  const ( OriginReflex Origin = iota + 1; OriginAutomation; OriginAdmin )
  func OriginFor(c verify.KeyClass) Origin

  // protected.go
  type Protected struct { /* []netip.Prefix */ }
  type Sources struct { // injectable for tests
      InterfaceAddrs func() ([]netip.Prefix, error)
      RouteFiles     [2]string // default /proc/net/route, /proc/net/ipv6_route
      ResolvConf     string    // default /etc/resolv.conf
  }
  func Discover(cfg config.Config, src Sources) (*Protected, error)
  func (p *Protected) Overlaps(target netip.Prefix) (netip.Prefix, bool) // returns the protected prefix hit
  func (p *Protected) Prefixes() []netip.Prefix

  // target.go
  func ParseNetTarget(s string, o Origin) (netip.Prefix, error) // IP → /32 or /128; CIDR allowed only for non-reflex, min /16 v4, /32 v6
  func ParsePIDTarget(s string) (int, error)                      // "pid:<n>", n > 1

  // policy.go
  type Decision struct { Allowed bool; Result synapsev1.TurretResult; Reason string }
  func Check(o Origin, a synapsev1.Action, ttl time.Duration) Decision // origin×action table + TTL limits

  // limiter.go
  type Clock func() time.Time
  type ReflexLimiter struct { /* budget + prefix windows */ }
  func NewReflexLimiter(b config.Budget, l config.Limiter, now Clock) *ReflexLimiter
  // Admit returns the prefix to actually ban (the single IP, or the /24 or /64 once the threshold is crossed)
  // or ok=false when the budget is exhausted.
  func (r *ReflexLimiter) Admit(ip netip.Addr) (ban netip.Prefix, ok bool)
  ```

- [ ] **Step 1: Write failing tests.**
  - Protected, with fake `Sources` (`t.TempDir()` route and resolv files):
    - hardcoded ranges are always present
    - an interface address, the default gateway parsed from a fixture `/proc/net/route` line (`eth0 00000000 0101A8C0 0003 …` → `192.168.1.1`), the IPv6 default from a fixture `ipv6_route` line, a `nameserver` line, the Core endpoint IP, the WireGuard CIDR and the whitelist entries (IPs and CIDRs; `#` comments; blank lines; an invalid line → error naming the line number) are all protected
    - overlap: `10.8.0.0/16` with WG `10.8.0.0/24` → hit; `0.0.0.0/0` → hit; `203.0.113.7/32` → no hit
  - Target:
    - `"203.0.113.7"` → `/32`
    - `"2001:db8::1"` → `/128`
    - `"203.0.113.0/24"` from REFLEX → error, from automation → ok
    - `/15` v4 or `/31` v6 → error
    - garbage → error
    - `pid:1`, `pid:0`, `pid:-5` and `pid:x` → error; `pid:4412` → 4412
  - Policy: a table test covering every cell of the §3.4.1 table (3 origins × 8 actions), plus the TTL rules from Global Constraints:
    - REFLEX `BAN_TEMP` 901 s → refused
    - automation 604801 s → refused
    - admin 30 d → allowed
    - `RATE_LIMIT` 901 s → refused for every origin
    - TTL 0 for a temp action → refused
    - `ACTION_UNSPECIFIED` → refused
  - Limiter, with a fake clock:
    - 50 distinct IPs are admitted, the 51st is refused, and after the window slides the 51st is admitted
    - the same IP twice counts once
    - 11 IPs in `198.51.100.0/24` within 60 s: the 11th returns `198.51.100.0/24`
    - IPv6: 11 addresses in one `/64` → the `/64`
    - a prefix ban counts as one budget entry
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** with `net/netip` only. Two prefixes overlap iff `a.Overlaps(b)`. Route parsing: in `/proc/net/route`, field 2 = gateway, little-endian hex, where destination `00000000` is the default route; in `/proc/net/ipv6_route`, destination `000…0/00` with a next hop ≠ `::` is the default route.
- [ ] **Step 4: Run** `go test -race ./internal/turret/safety/` → PASS. **Commit** (`feat(turret): safety layer — protected ranges, policy, reflex limiter`).

---

### Task 4: IOC bundle and verified process kill

**Files:**
- Create: `internal/turret/ioc/bundle.go`, `bundle_test.go`
- Create: `internal/turret/proc/inspect.go`, `kill.go`, `proc_test.go`

**Interfaces:**
- Consumes: `verify.Keyring` (automation key only), `synapsev1.SignedIocBundle`, `IocBundle`.
- Produces:
  ```go
  // ioc
  type Set struct { Version uint64; hashes map[[32]byte]struct{} }
  func Load(path string, k *verify.Keyring) (*Set, error) // signature must be from the automation key; missing file → empty Set, no error
  func (s *Set) HasSHA256(h [32]byte) bool

  // proc
  type Info struct { PID, PPID int; Exe string; StartTime uint64; Deleted, Memfd, Kernel bool }
  func Inspect(pid int) (Info, error)            // reads /proc/<pid>/{exe,stat}
  var ( ErrImmune, ErrMismatch, ErrNotTempPath, ErrNotInIOC, ErrMemfdOrDeleted error )
  func Immune(i Info, self int) bool              // pid 1, self, kernel threads (ppid 2 or pid 2), exe basename in {wt-turret,wt-sentry,wt-core,wg,wg-quick,wireguard-go}, sshd with ppid 1
  func Kill(pid int, expectExe string, expectStart uint64) error                // KILL_PROCESS
  func KillTempMalware(pid int, iocs *ioc.Set, tempDirs []string) (string, error) // returns exe path; chmods it 0600
  var DefaultTempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
  ```

- [ ] **Step 1: Write failing tests** (unprivileged: they act only on child processes the test starts).
  - IOC:
    - signed by the automation key → loads, `HasSHA256` true
    - signed by an admin key → error
    - tampered payload → error
    - missing file → empty set
  - Inspect: on a started `sleep 30` child → exe equals the resolved `sleep` path, start time > 0, not immune.
  - Immune: `Info{PID:1}`, `self` and `Info{PPID:2}` → true; `sshd` with ppid 1 → true; `sshd` with ppid 500 → false.
  - Kill:
    - a correct exe and start time kills the child (`Wait` returns a signal error)
    - a wrong start time → `ErrMismatch` and the child is still alive
    - a wrong exe → `ErrMismatch`
  - KillTempMalware: copy the `sleep` binary into `t.TempDir()` and run it. Pass `tempDirs = []string{t.TempDir() + "/"}`, so the test does not depend on `/tmp`.
    - its hash in the set → killed and the file mode is `0600`
    - hash not in the set → `ErrNotInIOC`, still alive
    - binary outside `tempDirs` → `ErrNotTempPath`
    - delete the file while it runs (exe shows `(deleted)`) → `ErrMemfdOrDeleted`
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.**
  - Open the pidfd (`unix.PidfdOpen`) **first**.
  - Then `Inspect` and compare, which defeats PID reuse.
  - Then `unix.PidfdSendSignal(fd, SIGKILL)`.
  - `start_time` is field 22 of `/proc/<pid>/stat`. Parse it after the last `)` so command names containing spaces or parentheses are safe.
  - Hash the exe through `/proc/<pid>/exe`, not the path, so a path swapped after the check can't be substituted.
  - Check the temp-dir prefix on `filepath.Clean(exe)` and `filepath.EvalSymlinks(exe)`.
- [ ] **Step 4: Run** `go test -race ./internal/turret/ioc/ ./internal/turret/proc/` → PASS. **Commit** (`feat(turret): signed IOC bundle and PID-reuse-safe kill`).

---

### Task 5: nftables firewall

**Files:**
- Create: `internal/turret/nft/firewall.go` (interface and an in-memory fake), `nft.go` (real implementation), `nft_netns_test.go` (`//go:build netns`), `fake_test.go`
- Modify: `Makefile` (target `test-netns`)

**Interfaces:**
- Produces:
  ```go
  type Kind int
  const ( KindBan Kind = iota + 1; KindPerm; KindRateLimit )
  type Firewall interface {
      Ensure() error                                   // create table/sets/chain if missing; keep existing set contents
      SetAllow(p []netip.Prefix) error                 // replace allow4/allow6 atomically
      Add(k Kind, p netip.Prefix, ttl time.Duration) error // ttl ignored for KindPerm; KindRateLimit requires a single address
      Remove(p netip.Prefix) error                     // from ban, perm and ratelim sets; missing → nil
      Flush() error                                    // delete table inet watchtower; missing table → nil
  }
  func NewNFT() (Firewall, error)
  func NewFake() *Fake // records calls; exported for engine tests
  const TableName = "watchtower"
  ```
- The rule order and the set definitions are exactly spec §3.4.2.

- [ ] **Step 1: Write failing tests.** `nft_netns_test.go` runs in a fresh netns. The Makefile target runs it as `unshare --user --map-root-user --net go test -tags netns -race ./internal/turret/nft/`.
  - `TestEnsureCreatesLayout`: after `Ensure`, list via `nftables.Conn`: table `inet watchtower`, the 8 sets with their key types and flags, chain `input` (hook input, priority −10, policy accept), and 8 rules in spec order. A second `Ensure` is a no-op and keeps elements already added.
  - `TestBanBlocksTrafficAndAllowWins`:
    - Create netns B and a veth pair, A=`10.99.0.1/24` and B=`10.99.0.2/24`.
    - Run a TCP listener in A.
    - B connects → ok.
    - `Add(KindBan, 10.99.0.2/32, 30s)` → B's connect times out.
    - `SetAllow([10.99.0.2/32])` → B connects again (allow evaluated first).
    - `SetAllow(nil)` and then `Remove` → ok.
  - `TestTimeoutExpires`: a ban with a 2 s TTL is gone from the set after 3 s.
  - `TestFlushRestoresConnectivity`: ban B, then `Flush` → B connects, and the table no longer exists. `Flush` on a missing table → nil.
  - `TestCIDRBan`: `Add(KindBan, 10.99.0.0/24, …)` blocks B. `Remove` of the same prefix unblocks it.
  - `fake_test.go`: the fake rejects `KindRateLimit` with a non-single prefix, same as the real one.
- [ ] **Step 2: Run** `make test-netns` → FAIL. **Step 3: Implement** with `github.com/google/nftables` (pin the latest release).
  - Interval sets need start and end elements (`IntervalEnd: true` on the address after the range). Element timeouts come from `ttl`.
  - The rate-limit rule uses `expr.Limit{Type: expr.LimitTypePkts, Rate: 2, Unit: expr.LimitTimeSecond, Burst: 4, Over: true}` followed by a drop verdict.
  - Every mutating method is one `Conn.Flush()` transaction.
- [ ] **Step 4: Run** `make test-netns` → PASS, and `go test ./internal/turret/nft/` (without the tag) → PASS. **Commit** (`feat(turret): nftables firewall with netns tests`).

---

### Task 6: Engine, persisted bans and socket server

**Files:**
- Create: `internal/turret/engine/engine.go`, `state.go`, `engine_test.go`
- Create: `internal/turret/server/server.go`, `server_test.go`

**Interfaces:**
- Consumes everything above.
- Produces:
  ```go
  // engine
  type Deps struct {
      Cfg config.Config; Keys *verify.Keyring; Replay *replay.Cache; Protected *safety.Protected
      Limiter *safety.ReflexLimiter; FW nft.Firewall; IOC func() (*ioc.Set, error)
      Kill func(pid int, exe string, start uint64) error
      KillTemp func(pid int, s *ioc.Set) (string, error)
      Now func() time.Time; Log *slog.Logger
  }
  type Engine struct{ /* … */ }
  func New(d Deps) (*Engine, error)          // loads state, Ensure()s the firewall, SetAllow(protected), re-applies unexpired bans
  func (e *Engine) Handle(req *synapsev1.TurretRequest) *synapsev1.TurretResponse

  // state.go — JSON at <state_dir>/bans.json, 0600, written atomically like replay
  type BanRecord struct { Prefix string; Kind string; ExpiresAt int64 /* 0 = permanent */ }

  // server
  type Server struct{ /* … */ }
  func New(path string, gid int, allowed []int, h func(*synapsev1.TurretRequest) *synapsev1.TurretResponse, log *slog.Logger) (*Server, error) // removes a stale socket, listens, chmod 0660, chown root:gid (skips chown when not root)
  func (s *Server) Serve(ctx context.Context) error // returns when ctx is done
  const MaxConns = 8; const ReadTimeout = 10 * time.Second
  ```

- [ ] **Step 1: Write failing tests.**
  - Engine: `nft.NewFake()`, fake `Kill`/`KillTemp`, a fixed clock, test keys, `t.TempDir()` state and replay files.
    - REFLEX `BAN_TEMP` 600 s → `APPLIED`, and the fake has the ban
    - a REFLEX target in the WG subnet → `REFUSED_SAFETY`
    - the 51st distinct REFLEX target → `REFUSED_BUDGET`
    - the 11th in one `/24` → the fake receives the `/24`
    - a valid automation `BAN_TEMP` → `APPLIED`; the same `command_id` again → `REFUSED_REPLAY`
    - a forged signature → `REFUSED_SIGNATURE`
    - an expired command → `REFUSED_SIGNATURE`
    - automation `KILL_PROCESS` → `REFUSED_SAFETY` (policy)
    - admin `KILL_PROCESS` → fake `Kill` called with the payload's exe and start time
    - admin `ISOLATE_HOST` → `FAILED` with detail `not implemented in v0.4.0`
    - automation `UNBAN` of a permanent ban → `REFUSED_SAFETY`; admin `UNBAN` → `APPLIED`
    - **Restart**: a new `Engine` on the same state dir re-applies the unexpired ban and skips the expired one. The replayed `command_id` is still refused after restart.
    - **Crash safety**: the replay `Record` happens before the firewall call (a fake firewall that fails still leaves the ID recorded, and a retry → `REFUSED_REPLAY`).
    - The protected set includes an address that is already banned → `SetAllow` still contains it (allow wins).
  - Server: a socket in `t.TempDir()`, allowed = the test's own uid.
    - a valid frame → a response frame
    - garbage bytes → the connection is closed and the next client still works
    - a header announcing 70000 bytes → closed
    - 9 simultaneous idle connections → the 9th is closed immediately
    - a disallowed uid (allowed list = `[uid+1]`) → closed without a response
    - the socket file mode is `0660`
    - cancelling ctx → `Serve` returns and the socket file is removed
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.**
  - `Handle` order:
    - REFLEX: parse target → safety overlap → policy → limiter → firewall
    - Signed: verify → replay seen? → policy (`OriginFor`) → `Record` → execute
  - Map errors to `TurretResult`:
    - verify errors → `REFUSED_SIGNATURE`
    - replay → `REFUSED_REPLAY`
    - safety or policy → `REFUSED_SAFETY`
    - budget → `REFUSED_BUDGET`
    - execution error → `FAILED`
  - Log every decision with `slog` (fields: origin, action, target, result, reason). `Handle` must never panic on nil oneofs or nil payload fields.
  - Server: read the peer UID with `unix.GetsockoptUcred` on the accepted conn's fd.
- [ ] **Step 4: Run** `go test -race ./internal/turret/...` → PASS. **Commit** (`feat(turret): engine with persisted bans and unix socket server`).

---

### Task 7: `wt-turret` binary, CI and docs

**Files:**
- Create: `cmd/wt-turret/main.go`, `cmd/wt-turret/main_test.go`
- Modify: `Makefile` (`build` already covers `cmd/*`; `verify` gains `test-netns` when `unshare` is usable), `.github/workflows/ci.yml` (new `netns` job), `.goreleaser.yml` (add the wt-turret build), `CHANGELOG.md`, `README.md`, `docs/architecture.md`

**Interfaces:**
- CLI:
  - `wt-turret serve --config /etc/watchtower/turret.yaml`
  - `wt-turret panic-flush` (no config needed; deletes `table inet watchtower`; exit 0 when the table is already absent)
  - `wt-turret version`

- [ ] **Step 1: Write failing tests** in `main_test.go`, driving a `run(args []string, stdout, stderr io.Writer) int` function:
  - `panic-flush` with no config file present → its exit code is non-zero only for netlink errors. Use an injectable `flush func() error`: when it returns nil, the exit code is 0, whatever state the config is in.
  - `serve` with a missing config → exit 2, and the message names the path.
  - `serve` with empty `allowed_uids` after defaults → exit 2 with "no allowed socket peers".
  - Unknown subcommand → exit 2 with usage.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.**
  - `serve` builds `Deps`:
    - `safety.Discover` refreshes every 60 s and calls `SetAllow` when the set changes
    - the IOC bundle is re-read on each `KILL_TEMP_MALWARE`
  - Handles `SIGINT` and `SIGTERM` by cancelling the server context. It does **not** flush the firewall on shutdown; bans persist.
  - Version comes from an ldflag (`main.Version`), as in the other binaries.
- [ ] **Step 4: CI.** Add a `netns` job to `ci.yml`:
  - setup-go (`go-version-file: go.mod`)
  - `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (Ubuntu 24.04 blocks unprivileged user namespaces by default)
  - `make test-netns`

  Add a `wt-turret` build to `.goreleaser.yml`, mirroring the existing builds.
- [ ] **Step 5: Docs.**
  - CHANGELOG `[Unreleased]`: Added and Changed for Phase 1.
  - README roadmap: leave Phase 1 unticked until CI is green. Add Turret to the Quick Start: `make test-netns`, and `sudo ./wt-turret panic-flush` as the emergency step.
  - architecture §3.4: a note that `ISOLATE_HOST`/`RELEASE_HOST` and WebAuthn are deferred (scope rulings above).
  - architecture §5: document the `IocBundle` / `SignedIocBundle` messages next to §5.2.
  - architecture §3.4.1: the minimum-prefix and overlap rule.
- [ ] **Step 6: Verify.** `make verify` and `make test-netns` pass locally. The workflow YAML parses. **Commit** (`feat(turret): wt-turret binary, netns CI job and docs`).

---

## Phase 1 exit gate (spec §7)

- `go test -race ./internal/turret/...` passes, and `make test-netns` passes locally and in CI. Together they cover:
  - self-ban refusal (Task 3/6)
  - path traversal refusal for `KILL_TEMP_MALWARE` (Task 4)
  - forged, replayed and expired command refusal (Task 2/6)
  - `panic-flush` restoring connectivity (Task 5/7)
- `CGO_ENABLED=0 go build ./...`, lint and `make verify` are clean.
- The CHANGELOG and README are updated, and `v0.4.0` is tagged after merge.
