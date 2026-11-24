# 🏛️ WatchTower XDR — System Design Document v3.2

**Project Status:** Pre-Alpha, Single-Maintainer, Active Development ⚠️ | Code: Pre-Release (`v0.2.0` → v3.2 architectural transition)
**Last Updated:** 2026-11-25
**Architect & Developer:** Emir Furkan Ulu
**Vision:** "Simple setup, bounded and reversible self-inflicted risk, explainable fleet-wide detection and response powered by deterministic rules — with AI as an optional, advisory analyst."

> **Documentation rule (carried over from v2.2):** a ✅ in this document means *verified in code and CI*, not *designed*. Everything in this document is a design target unless explicitly marked ✅.

Previous revisions live in [`docs/archive/`](archive/).

---

## 🔍 Version History

### v3.1 → v3.2 (XDR Core & Trust-Model Corrections) ⭐ CURRENT

v3.1 got the direction right (scope cut, privilege split, CSR PKI, read-only FIM, signed commands). v3.2 fills in the part that actually makes this an XDR — the data model, detection language and cross-host correlation — and fixes trust-model and math errors found in the v3.1 review.

**XDR core (new):**
1. **Fleet Immunity** is now the headline feature (§3.1.4): one agent's confirmed detection becomes a fleet-wide block. This is the concrete value over per-host tools like Fail2Ban.
2. **WatchTower Event Schema (WES)** (§4.1): one normalized, OCSF-inspired event model with explicit entities (`host`, `user`, `process`, `src/dst endpoint`, `file`). Correlation is keyed on entities, not only `SourceIP`/`AgentID`.
3. **Detection-as-code** (§4.2): rules are Sigma-compatible YAML (detection + Sigma correlation rules), versioned in the repo and tested against a regression corpus.
4. **Process telemetry** (§3.3.3): exec/connect events via tiered collectors (eBPF → auditd log → `/proc` polling). v3.1's AI example ("suspicious curl under www-data") was undetectable without it.
5. **Deterministic scoring** (§3.1.3): the incident score and the allowed response tier come from rules, never from the LLM.

**Trust-model fixes:**
6. **Two signing keys** (§5.2): the online *Core Automation Key* can only sign reversible network actions; destructive actions (`KILL_PROCESS`, `ISOLATE_HOST`, `BAN_PERM`) require the *Administrator Approval Key*, which never lives on Core. In v3.1, a compromised Core could bypass Human-in-the-Loop because Core both received the approval click and signed the command.
7. **Replay protection** (§5.2): signed commands carry `command_id`, `agent_id`, `issued_at`, `expires_at`; Turret keeps a seen-ID cache. Signatures are over the exact serialized bytes (no "canonical string" re-serialization).
8. **Turret verifies, never trusts Sentry** (§3.4.1): for `KILL_TEMP_MALWARE`, Turret re-hashes `/proc/<pid>/exe` itself and checks it against a **Core-signed** IOC bundle. Sentry-originated bans have a per-agent budget to limit the DoS lever of a compromised Sentry.
9. **No automatic `BAN_PERM`** (§3.4.2): replaced by escalating TTL bans (15m → 1h → 24h → 7d). Permanent bans require the admin key.

**Correctness fixes:**
10. **Baseline math** (§3.1.2): v3.1's "7-day `dow:hour` baseline" has one sample per bucket, so `stddev` is undefined. v3.2 uses robust statistics (median/MAD), a minimum sample count, a 28-day cold start for seasonal buckets and an hour-of-day fallback.
11. **FIM package verification** (§3.3.2): changes are judged against package manifests (dpkg `md5sums` / rpmdb digests), not against the package-manager lock. A root attacker could hold the dpkg lock to downgrade alerts.
12. **Connection → process attribution** requires privileges an unprivileged Sentry does not have (reading other users' `/proc/<pid>/fd`). v3.2 states this and gets attribution from the eBPF tier instead.
13. **nftables instead of iptables/ipset** (§3.4.2): one atomic, self-owned `inet watchtower` table via the pure-Go `google/nftables` library; no shelling out. One-command rollback. "TARPIT" renamed to `RATE_LIMIT` (hashlimit is not a real tarpit).
14. **Audit log** (§4.3): tables are owned by a separate migration role (REVOKE on the owner is meaningless), and the hash-chain head is anchored outside the database.
15. **Prompt handling** (§3.2): hex-encoding telemetry is removed (the model either can't read it or decodes it and gets injected anyway). Frontal receives structured features and short, delimited, sanitized excerpts as JSON string fields.

**Simplification:**
16. **Fewer binaries**: `wt-midbrain` becomes a package inside `wt-core` (it is a feed poller). Shipped binaries: `wt-core`, `wt-sentry`, `wt-turret`, `wt-cli`, plus optional `wt-frontal`. `wt-interceptor` (WAF) is dropped.
17. **Naming**: biological names are kept as module codenames for documentation and package names; binaries keep functional names (§2.3). Mixed metaphors are no longer a headline item.
18. **Toolchain**: Go version tracks `go.mod` (currently 1.25), not a hardcoded 1.21.

**Operator experience:**
19. **Web Console (Visual Cortex)** (§3.6): an embedded Svelte SPA served by `wt-core` over WireGuard replaces "Grafana as the dashboard". It covers incidents, fleet, response, approvals and audit, with passkey login and passkey approvals. Grafana becomes optional. A demo stack with an attack simulator (§3.6.4) provides data for development, E2E tests and screenshots.

### Earlier revisions
- **v3.1 (draft, 2026-11-06):** Neuro-architecture naming, REFLEX/CORTEX_SIGNED split, CSR PKI, read-only FIM, Redis/CGo removal, adaptive subnet limiter. → [`archive/architecture-v3.1-draft.md`](archive/architecture-v3.1-draft.md)
- **v2.2 (2026-09-28):** Operational hardening, detection false-positive fixes, CI gates. → [`archive/architecture-v2.2-hardening.md`](archive/architecture-v2.2-hardening.md)
- **v2.2 "Universal" (2026-02-08):** AI SOC (WT-Advisor), Interceptor WAF, LSTM. → [`archive/architecture-v2.2-universal.md`](archive/architecture-v2.2-universal.md)

---

## 📋 Table of Contents

1. [Executive Summary & Global Invariants](#1-executive-summary--global-invariants)
2. [System Topology](#2-system-topology)
3. [Component Specifications](#3-component-specifications)
4. [Data Model, Detection & Storage](#4-data-model-detection--storage)
5. [Security, PKI & Trust Boundaries](#5-security-pki--trust-boundaries)
6. [Operational Procedures & CLI](#6-operational-procedures--cli)
7. [Development Roadmap](#7-development-roadmap)
8. [Migration From the Current Codebase](#8-migration-from-the-current-codebase)
9. [Threat Model & Known Limitations](#9-threat-model--known-limitations)

---

## 1. Executive Summary & Global Invariants

### 1.1 Project Vision

WatchTower XDR is a self-hosted, open-source detection and response platform for small-to-medium Linux server fleets (VPS, bare metal, hybrid; roughly 1–200 hosts). It collects host, application and network telemetry into one normalized model, correlates weak signals **across layers and across hosts**, and responds with bounded, reversible actions — escalating to a human for anything destructive.

**What makes it XDR rather than "Fail2Ban with a database":**

| Capability | Per-host tools (Fail2Ban, OSSEC-style) | WatchTower |
|---|---|---|
| Data model | Per-tool log lines | One normalized event schema with entities (§4.1) |
| Detection | Regex per log file | Sigma-compatible rules + correlation rules (§4.2) |
| Correlation scope | Single host, single log | Cross-layer (auth + web + process + FIM + network) **and** cross-host |
| Response scope | Local host | Local reflex **plus** fleet-wide immunity (§3.1.4) |
| Explainability | Matched line | Incident timeline, matched rules, score breakdown, optional AI narrative |

### 1.2 Non-Negotiable Architectural Invariants

1. **Pure Go, static binaries.** `CGO_ENABLED=0` for every shipped binary. (eBPF programs are compiled to BPF bytecode at build time with `bpf2go` and embedded; the loader is pure Go `cilium/ebpf`. This needs `clang` on the build machine only. Likewise, the Web Console is built with Node.js in CI/release and embedded as static files; no Node.js runs in production.)
2. **Single data store.** PostgreSQL 14+ with TimescaleDB on Core. No Redis, no message brokers.
3. **Bounded self-inflicted risk.** Every automated action is reversible and has a TTL. Self-preservation rules (§3.4.1) cannot be overridden by any command, signed or not. A single command removes every WatchTower firewall rule (`wt-turret panic-flush`).
4. **No agent modifies system files.** Sentry is read-only. Turret's only filesystem write outside its own state directory is `chmod 0600` on a verified malware binary inside a temp directory.
5. **Deterministic authority.** Only the deterministic Policy Engine decides what may happen. The LLM (if enabled) explains and recommends from an allow-list; its "confidence" never gates an action.
6. **Least privilege per process.** The component that parses attacker-controlled input (Sentry) has the least privilege. The component with privilege (Turret) has no network listener and parses only signed or locally-authenticated messages.

### 1.3 Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Language | Go (version per `go.mod`, currently 1.25), `CGO_ENABLED=0` | Single static binary, low memory, native concurrency |
| Remote IPC | gRPC + Protobuf (`pkg/synapse`), mTLS | Typed bi-directional streams |
| Local IPC | Unix domain socket `/run/watchtower/turret.sock` (`0660 root:watchtower`) + `SO_PEERCRED` | Zero network surface for the privileged daemon |
| Storage | PostgreSQL 14+ / TimescaleDB | Hypertables, compression, retention, ACID |
| Network enforcement | nftables via `github.com/google/nftables` | Atomic transactions, native sets with timeouts, no shell-out |
| Process telemetry | `cilium/ebpf` (Tier A), auditd log (Tier B), `/proc` (Tier C) | See §3.3.3 |
| Detection rules | Sigma-compatible YAML (subset) | Community format, reviewable, testable |
| AI (optional) | Any OpenAI-compatible HTTP API (OpenRouter, Bedrock gateway, Ollama, vLLM, llama-server) | Provider-agnostic, local-model friendly |
| Notifications | ntfy (self-hostable) | Push notifications with action buttons |
| Web Console | Svelte 5 + TypeScript SPA, embedded in `wt-core` via `go:embed`; Connect RPC API | One binary to deploy; same API as `wt-cli`; Node.js only at build time |
| Metrics exploration (optional) | Grafana 10+ | Read-only PostgreSQL role, no hard dependency |
| Management plane | WireGuard | Kernel-native, simple, encrypted admin network |

---

## 2. System Topology

### 2.1 High-Level Architecture

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ PROTECTED HOST  (peripheral nervous system)                               │
│                                                                           │
│  ┌──────────────────────────────────────┐   user: watchtower (+adm)       │
│  │ wt-sentry  (Sensory Nerves)          │   optional caps: CAP_BPF,       │
│  │  • LogWatcher (auth, web, journald)  │                  CAP_PERFMON    │
│  │  • Process telemetry (Tier A/B/C)    │                                 │
│  │  • Read-only FIM + package verify    │                                 │
│  │  • /proc metrics, IOC matcher        │                                 │
│  │  • Local rules + sliding windows     │                                 │
│  └───────┬───────────────────────┬──────┘                                 │
│          │ Reflex Arc            │ forwards SignedCommand bytes           │
│          │ (unix socket,         │ (opaque, cannot modify)                │
│          ▼  SO_PEERCRED)         ▼                                        │
│  ┌──────────────────────────────────────┐   root, no network listener     │
│  │ wt-turret  (Motor Nerves)            │                                 │
│  │  • Safety layer (self-preservation)  │                                 │
│  │  • Signature + replay verification   │                                 │
│  │  • nftables table `inet watchtower`  │                                 │
│  │  • Verified process kill             │                                 │
│  └──────────────────────────────────────┘                                 │
└───────────┬───────────────────────────────────────────────────────────────┘
            │ pkg/synapse — gRPC over mTLS (:50051), agent-initiated stream
┌───────────▼───────────────────────────────────────────────────────────────┐
│ CORE HOST  (central nervous system)                                       │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ wt-core  (Brainstem)                                                │  │
│  │  • Enrollment CA (CSR), Ingest, Heartbeat, CommandStream            │  │
│  │  • Correlator: rule engine + Sigma correlation (entity-keyed)       │  │
│  │  • Hippocampus: robust seasonal baselines                           │  │
│  │  • Fleet Immunity: cross-host reputation & fleet-wide bans          │  │
│  │  • Midbrain: CTI feed poller → signed IOC bundles                   │  │
│  │  • Policy Engine + Core Automation Key (network actions only)       │  │
│  │  • Approval queue (destructive actions need admin signature)        │  │
│  │  • Visual Cortex: embedded Web Console (WireGuard only)             │  │
│  └──────┬──────────────────────────┬───────────────────────────────────┘  │
│         │ pgx                      │ gRPC, loopback, optional             │
│         ▼                          ▼                                      │
│  ┌──────────────────────┐   ┌────────────────────────────┐                │
│  │ PostgreSQL+Timescale │   │ wt-frontal (Frontal Cortex)│ ──HTTPS──► LLM │
│  │ events, detections,  │   │  advisory only, stateless  │                │
│  │ incidents, actions,  │   └────────────────────────────┘                │
│  │ approvals, audit     │                                                 │
│  └──────────────────────┘                                                 │
└───────────┬───────────────────────────────────────────────────────────────┘
            │ WireGuard (management network, e.g. 10.8.0.0/24)
┌───────────▼───────────────────────────────────────────────────────────────┐
│ ADMINISTRATOR PLANE  (conscious override)                                 │
│  • wt-cli with Administrator Approval Key (signs destructive actions)     │
│  • Web Console in browser (passkey login + passkey approvals)             │
│  • ntfy on mobile (notification + deep link to the console)               │
│  • Grafana (optional, ad-hoc metrics)                                     │
└───────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Communication Matrix (`pkg/synapse`)

| Source → Destination | Transport | Authentication | Purpose |
|---|---|---|---|
| `wt-sentry` → `wt-turret` | Unix socket | File mode `0660` + `SO_PEERCRED` UID check | `REFLEX` requests; forwarding opaque `SignedCommand` bytes |
| `wt-sentry` → `wt-core` | gRPC :50051 | mTLS (agent cert from CSR enrollment) | Event batches, heartbeat (incl. collector tier), `CommandStream`, IOC/rule bundle sync |
| `wt-core` → `wt-frontal` | gRPC 127.0.0.1:50052 | Loopback + shared secret (mTLS optional) | `IncidentContext` → `Assessment` |
| `wt-frontal` → LLM | HTTPS | API key | Schema-constrained inference |
| `wt-core` → ntfy | HTTPS | ntfy access token | Notifications with deep links |
| `wt-cli` → `wt-core` | Connect/gRPC over WireGuard | mTLS (admin cert) | Queries, approvals (carrying admin signatures) |
| Browser → `wt-core` console | Connect (HTTP/JSON) over HTTPS, WireGuard only | Passkey session cookie + CSRF header; per-approval passkey signature | Web Console (§3.6) |

The agent always initiates the connection to Core. Agents need no inbound ports.

### 2.3 Module Codenames

Biological names are documentation and package codenames. Binaries keep functional names so operators don't need the metaphor.

| Codename | Binary / package | Function |
|---|---|---|
| Brainstem | `wt-core` | Ingest, storage, correlation, policy, signing |
| Hippocampus | `internal/core/hippocampus` | Baselines and anomaly scores |
| Midbrain | `internal/core/midbrain` | CTI feed ingestion, IOC bundles |
| Frontal Cortex | `wt-frontal` (optional) | AI triage and narrative |
| Visual Cortex | `internal/core/console` + `web/` | Web Console |
| Sensory Nerves | `wt-sentry` | Telemetry collection, local detection |
| Motor Nerves | `wt-turret` | Privileged enforcement |
| Reflex Arc | Sentry → Turret local path | Fast, bounded, local responses |
| Synapse | `pkg/synapse` | Protobuf contracts (remote + local IPC) |
| Amygdala | `internal/sentry/decoy` (v1.x) | Canary files / decoy credentials |

> **Note:** Synapse `.proto` sources live in `proto/watchtower/synapse/v1/`; the generated Go code is committed in `pkg/synapse/v1/` and kept current by `make proto-check`.

---

## 3. Component Specifications

### 3.1 `wt-core` (Brainstem)

**Resource target:** 512 MB–2 GB RAM, 1–2 cores for ~200 agents.

#### 3.1.1 Ingest & Correlator (`internal/core/ingest`, `internal/core/correlator`)

- Receives WES event batches (§4.1). Events are validated, enriched (GeoIP/ASN optional, IOC lookup, fleet reputation) and written to TimescaleDB with `COPY`.
- Runs **core-side rules** (§4.2) that need fleet-wide or cross-layer context. Agent-side rules handle single-host, single-source patterns.
- Correlation state is held per **entity key**: `src_ip`, `(agent_id, user)`, `(agent_id, process.exe)`, `file.sha256`. A detection may update several entity states.
- Window state is in memory with periodic snapshots to PostgreSQL (`correlation_state`) so a Core restart loses at most the snapshot interval (default 60 s).

#### 3.1.2 Hippocampus — Baselines (`internal/core/hippocampus`)

- Metrics: CPU, memory, network bytes in/out, outbound connection count, auth failures per hour, process spawn rate, per agent.
- **Buckets:** `agent:metric:dow:hour` (168 buckets) and a fallback `agent:metric:hour` (24 buckets).
- **Statistics:** median and MAD (median absolute deviation) per bucket, computed nightly from hourly continuous aggregates. Robust score: `z = 0.6745 × (x − median) / MAD`.
- **Cold start:** a seasonal bucket is used only once it has ≥ 4 samples (≈ 28 days). Before that, the hour-of-day bucket is used (≥ 7 samples). Before that, no anomaly signals are emitted at all — only rule-based detections.
- **Guards:** `MAD = 0` falls back to a configured absolute delta; anomalies contribute low weight (§3.1.3) and can never trigger a response on their own.
- The in-memory cache (`map[key]*Baseline` behind `sync.RWMutex`) refreshes every 10 minutes; lookups are O(1).

#### 3.1.3 Deterministic Scoring & Response Tiers (`internal/core/policy`)

Each rule declares a `level` (Sigma: `informational`, `low`, `medium`, `high`, `critical`) that maps to a weight. An **incident** groups detections that share an entity within a window (default 15 min, sliding).

```
incident_score = Σ weight(distinct rule hits, decayed by age)
               × cross_layer_multiplier   (1.0 for one layer, 1.5 for two, 2.0 for three or more)
               + fleet_bonus              (same src_ip active against ≥ 3 agents)
               + ioc_bonus                (any CTI match)
```

Weights, multipliers and thresholds live in `core.yaml` and are covered by table-driven tests. The score maps to a **response tier**, and the tier is the only thing that decides what is permitted:

| Tier | Score (default) | Permitted actions | Signer | Human? |
|---|---|---|---|---|
| T0 Observe | < 20 | none (log, dashboard) | — | — |
| T1 Contain-network | 20–49 | `RATE_LIMIT`, `BAN_TEMP` on the affected agent | Core Automation Key | No |
| T2 Fleet-contain | 50–79 | T1 + fleet-wide `BAN_TEMP` (escalating TTL) | Core Automation Key | No; notification sent |
| T3 Destructive | ≥ 80, or any critical host-level rule | `KILL_PROCESS`, `ISOLATE_HOST`, `BAN_PERM` | Admin Approval Key | **Yes, always** |

Policy rules, applied in order:
1. **Immunity:** targets in the fleet whitelist or any self-preservation range are rejected regardless of tier.
2. **Tier gate:** an action is permitted only if its tier ≤ the incident's tier.
3. **AI is advisory:** a Frontal recommendation is accepted only if it is in the permitted set for the current tier. It can never raise the tier.
4. **Destructive actions** create a `pending_approvals` row and a notification. Core cannot sign them (§5.2).

#### 3.1.4 Fleet Immunity (`internal/core/fleet`)

The core XDR value proposition for small fleets:

1. A T1+ incident with a `src_ip` entity on any agent produces a **fleet reputation record** for that IP (`ip_reputation` table).
2. At T2 (or when the same IP is seen by ≥ 3 agents within the window), Core issues a **fleet-wide `BAN_TEMP`** to every agent, signed with the Core Automation Key.
3. **Escalating TTL** per IP across offenses: 15 min → 1 h → 24 h → 7 d. Offense history decays after 30 days without activity.
4. Prefix aggregation: ≥ 10 distinct banned IPs in one `/24` (IPv4) or `/64` (IPv6) within 10 minutes → ban the prefix with the same TTL ladder. This replaces the per-host-only subnet limiter from v3.1 for fleet scope; Turret keeps its local limiter (§3.4.1).
5. Fleet whitelist (CIDRs, ASNs) is checked before any fleet action; agents' self-preservation is checked again on each host.

#### 3.1.5 Midbrain — CTI (`internal/core/midbrain`, v1.x)

- Polls abuse.ch Feodo Tracker, ThreatFox and MalwareBazaar (recent hashes) on a schedule; normalizes into `ioc_indicators`.
- Builds a compact **IOC bundle** (SHA-256 set + IP/CIDR set + version) and **signs it with the Core Automation Key**. Sentry uses it for matching; Turret uses it to independently verify `KILL_TEMP_MALWARE` (§3.4.1).
- Expired indicators are pruned; each bundle has a monotonic version reported in heartbeats.

#### 3.1.6 Agent Liveness

Heartbeat every 30 s with agent version, rule/IOC bundle versions, collector tier and self-health. Missing heartbeats: `STALE` after 2 min, `DEAD` after 10 min → high-severity detection on that host. Stopping or killing Sentry is itself a signal.

---

### 3.2 `wt-frontal` (Frontal Cortex — Optional AI Analyst)

**Design principle:** stateless, advisory, no database or agent access. WatchTower must be fully functional with Frontal disabled.

**Input (`IncidentContext`)** — structured, minimized:
- Incident score breakdown, tier, permitted actions (the allow-list).
- Entities (IPs optionally masked, usernames, process exe/cmdline hashes and truncated cmdlines).
- Matched rules (IDs, titles, ATT&CK tags) and a timeline of normalized events.
- Up to N untrusted excerpts (e.g. log lines), each ≤ 256 bytes after stripping control/ANSI characters, passed as JSON string values inside a field named `untrusted_excerpts`. The system prompt states that these are data, not instructions.

**Output (`Assessment`)** — enforced with `response_format: json_schema` and validated again in Go:

```json
{
  "incident_id": "inc-01JD8Z…",
  "summary": "Three SSH failures from 45.x.x.x followed by a curl to a raw IP spawned by www-data.",
  "attack_techniques": ["T1110.001", "T1105"],
  "recommended_action": "KILL_PROCESS",
  "target": "pid:4412",
  "rationale": "…"
}
```

- `recommended_action` must be in the permitted set sent in the input, otherwise it becomes `NO_OP`.
- There is no `confidence` field that the policy reads. A model's self-reported confidence is not calibrated.
- Timeout (> 15 s), transport error or schema failure → `NO_OP`; the incident proceeds on deterministic policy alone.
- The output is shown to humans (approval notification, dashboard) and stored in `incidents.ai_assessment`. Text is rendered as plain text, never as Markdown/HTML.

---

### 3.3 `wt-sentry` (Sensory Nerves)

**Privileges:** user `watchtower`, group `adm` (log reading). Never root. Optional ambient `CAP_BPF` + `CAP_PERFMON` for Tier A process telemetry, opt-in, documented as a privilege increase.
**Resource target:** 64–128 MB RAM, ≤ 0.2 CPU at idle.

#### 3.3.1 LogWatcher (`internal/sentry/logwatcher`)

- Tails `/var/log/auth.log` / `/var/log/secure`, nginx/Apache access logs and (optionally) journald via its export format; handles rotation (`IN_MOVE_SELF`, `IN_CREATE`) and truncation.
- Parses into WES events (`Authentication`, `HTTP Activity`) **before** rule evaluation, so rules match fields rather than raw lines.
- Agent-side rules with Sigma correlation (`event_count` over a `timespan`) drive the Reflex Arc, e.g. 5 failed SSH logins in 60 s → `BAN_TEMP 900s`.

#### 3.3.2 Read-only FIM + Package Verification (`internal/sentry/fim`)

- `fsnotify` watches on an explicit path list (`/etc/passwd`, `/etc/shadow` metadata, `/etc/sudoers*`, `/etc/ssh/`, `/etc/cron*`, `/usr/bin`, `/usr/sbin`, `/tmp`, `/var/tmp`, `/dev/shm`, systemd unit dirs). Symlinked paths (`/bin` → `/usr/bin` on usr-merged systems) are deduplicated after `EvalSymlinks`. No full-disk scanning.
- **Package verification** for changes under system directories:
  - Debian/Ubuntu: compare against `/var/lib/dpkg/info/*.md5sums` (MD5 is used only as a consistency check, not as a security primitive).
  - RHEL/Fedora: read file digests from the rpm database with a pure-Go reader (e.g. `knqyf263/go-rpmdb`).
  - Matches the package manifest → `low` (`package_consistent_change`). Mismatch or not owned by any package → `high`/`critical`.
- The package-manager lock state is recorded as **context only**; it never lowers severity.
- Sentry never moves, deletes, `chattr`s or rewrites any file.

#### 3.3.3 Process Telemetry — Tiered Collectors (`internal/sentry/proc`)

| Tier | Mechanism | Needs | Sees | Gaps |
|---|---|---|---|---|
| **A** | eBPF (`sched_process_exec`, `tcp_connect`/`inet_sock_set_state` tracepoints) via `cilium/ebpf` | Kernel ≥ 5.8 with BTF, `CAP_BPF` + `CAP_PERFMON` | Every exec (incl. short-lived), connect → PID/exe attribution, `memfd` executions | Requires opt-in caps |
| **B** | Tail `/var/log/audit/audit.log` (auditd with `log_group = watchtower` and WatchTower's `execve`/`connect` rule set) | auditd installed, config change | Every exec, connect syscalls | Depends on auditd rules being present; noisier |
| **C** | Poll `/proc` every 2 s | Nothing | Long-running processes, own-UID fd mapping | Misses short-lived processes; **no connection→process attribution for other users** |

The active tier is reported in every heartbeat and shown in the Web Console, so operators know their real visibility. Rules that need Tier A/B data declare it (`requires: process_exec`) and are reported as inactive on Tier C agents rather than silently never firing.

#### 3.3.4 Metrics & IOC Matching (`internal/sentry/metrics`, `internal/sentry/ioc`)

- Parses `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`, `/proc/net/tcp{,6}` directly; never spawns `ps`/`netstat`.
- Verifies the Core signature on IOC bundles before loading them.
- SHA-256 of new executables in watched temp directories (size-capped, default 64 MB) is checked against the IOC set. A match in `/tmp`, `/var/tmp`, `/dev/shm` → `REFLEX KILL_TEMP_MALWARE` request to Turret (Turret re-verifies). A match elsewhere → `critical` detection to Core, no local action.
- Outbound connections to IOC IPs → `high` detection; with Tier A attribution the process entity is included.

#### 3.3.5 Amygdala — Decoys (v1.x)

Canary files (fake `.env`, fake SSH private key, fake cloud credentials) watched with `IN_OPEN` / `IN_ACCESS`. Any access by a non-WatchTower process is a `critical`, near-zero-false-positive detection. Decoys are created by the installer, never by Sentry at runtime.

---

### 3.4 `wt-turret` (Motor Nerves)

**Privileges:** root (or `CAP_NET_ADMIN` + `CAP_KILL` + `CAP_DAC_READ_SEARCH` + `CAP_FOWNER`).
**Socket:** `/run/watchtower/turret.sock`, `0660 root:watchtower`. Peer UID verified with `SO_PEERCRED`. **No network listeners.**
**Design goal:** small, boring, heavily tested. Turret parses only two message types: `ReflexRequest` (locally authenticated) and `SignedCommand` (cryptographically authenticated).

#### 3.4.1 Safety Layer (`internal/turret/safety`) — runs before every action

1. **Self-preservation (hardcoded, unoverridable):** `127.0.0.0/8`, `::1`, link-local, all local interface addresses, default gateway(s), configured DNS resolvers, the Core endpoint, the WireGuard subnet, and the local whitelist file.
2. **Origin rules:**

| Action | `REFLEX` (from Sentry) | `SignedCommand` with Automation Key | `SignedCommand` with Admin Key |
|---|---|---|---|
| `RATE_LIMIT` (≤ 15 min) | ✔ | ✔ | ✔ |
| `BAN_TEMP` | ✔ TTL ≤ 900 s | ✔ TTL ≤ 7 d | ✔ |
| `KILL_TEMP_MALWARE` | ✔ after re-verification | ✔ | ✔ |
| `UNBAN` | ✗ | ✔ | ✔ |
| `BAN_PERM` | ✗ | ✗ | ✔ |
| `KILL_PROCESS` | ✗ | ✗ | ✔ |
| `ISOLATE_HOST` / `RELEASE_HOST` | ✗ | ✗ | ✔ |

3. **Reflex budget:** at most 50 distinct IPs banned via `REFLEX` per 10 minutes (configurable). Beyond that, Reflex bans are refused and a `high` detection is raised: either a large attack (Core's fleet logic takes over) or a compromised Sentry trying to use Turret as a DoS tool.
4. **Local prefix limiter:** > 10 Reflex bans from one `/24` (`/64`) in 60 s → ban the prefix for the Reflex TTL instead of individual IPs. Protection stays active for all other traffic (no `LOG_ONLY` fallback).
5. **`KILL_TEMP_MALWARE` re-verification:** Turret reads `/proc/<pid>/exe` itself, `filepath.Clean` + `EvalSymlinks`, requires a prefix of `/tmp/`, `/var/tmp/` or `/dev/shm/`, computes SHA-256 itself and requires it to be in the **Core-signed** IOC bundle on disk. Sentry's claimed hash is ignored. `memfd:` or `(deleted)` executables are refused locally and raised as `critical` for human decision.

#### 3.4.2 Enforcement (`internal/turret/nft`)

Turret owns a single nftables table and never touches other tables or chains:

```
table inet watchtower {
  set ban4      { type ipv4_addr; flags interval, timeout; }
  set ban6      { type ipv6_addr; flags interval, timeout; }
  set perm4     { type ipv4_addr; flags interval; }
  set perm6     { type ipv6_addr; flags interval; }
  set ratelim4  { type ipv4_addr; flags timeout; }
  set ratelim6  { type ipv6_addr; flags timeout; }
  set allow4    { type ipv4_addr; flags interval; }   # self-preservation, mirrored
  set allow6    { type ipv6_addr; flags interval; }

  chain input {
    type filter hook input priority -10; policy accept;
    ip  saddr @allow4 accept
    ip6 saddr @allow6 accept
    ip  saddr @perm4 drop
    ip6 saddr @perm6 drop
    ip  saddr @ban4  drop
    ip6 saddr @ban6  drop
    ip  saddr @ratelim4 limit rate over 2/second burst 4 packets drop
    ip6 saddr @ratelim6 limit rate over 2/second burst 4 packets drop
  }
}
```

- Changes are applied as nftables transactions through `google/nftables` (atomic; no shelling out).
- Priority `-10` runs before the default filter chains (priority 0), including the iptables-nft compatibility tables, so bans apply regardless of existing `ESTABLISHED,RELATED` accepts.
- `allow4/allow6` are evaluated first, so even a bug that inserts a self-preservation address into a ban set cannot cut management access.
- **Rollback:** `wt-turret panic-flush` deletes `table inet watchtower`. This is the documented emergency procedure and is tested in CI.
- Hosts using legacy iptables only (no nftables kernel support) are out of scope for v1.

#### 3.4.3 Process Termination

- `KILL_PROCESS` carries `pid`, expected `exe` path and expected `start_time` (field 22 of `/proc/<pid>/stat`). Turret verifies both immediately before `SIGKILL`, which defeats PID reuse. Prefer `pidfd_open` + `pidfd_send_signal` (Linux ≥ 5.3) to close the remaining race.
- PID 1, kernel threads, WatchTower's own processes, `sshd` master, `wireguard`/`wg-quick` and the Core connection path are immune.
- `KILL_TEMP_MALWARE` additionally sets the binary to `0600` (no execute) for forensics; it is not deleted.

#### 3.4.4 Host Isolation (`ISOLATE_HOST`)

Adds an `isolate` chain to the same table: drop all input/output except the self-preservation set, the WireGuard interface and the Core endpoint. Isolation persists across Turret restarts (state file) until `RELEASE_HOST`, which also requires the admin key. Because isolation is the most outage-prone action, it is admin-signed only and has its own network-namespace CI test.

---

### 3.5 `wt-cli`

Single binary for operators: PKI initialization, setup wizard, enrollment tokens, fleet/event/incident queries, approvals (signs with the Administrator Approval Key locally), audit-chain verification, rule testing (`wt-cli rules test`).

---

### 3.6 Web Console (Visual Cortex)

**Package:** `internal/core/console` (Go API + static asset server), frontend source in `web/`. It is served by `wt-core`; there is no separate binary.
**Purpose:** the day-to-day operator interface, and the face of the project. Screenshots and the demo GIF in the README come from it. It sits on the same API as `wt-cli`, so anything the console does can also be done from the CLI.

#### 3.6.1 Screens

| Screen | Content |
|---|---|
| **Overview** | Fleet health (alive/stale/dead), open incidents by tier, bans in the last 24 h (local vs fleet-wide), live attack feed, world map of attack sources, top attacked services |
| **Incidents** | Filterable list; detail view with event timeline, entity graph (IP → host → user → process → file), score breakdown, matched rules with ATT&CK tags, AI narrative (if enabled), response actions taken |
| **Fleet** | Agents with status, version, collector tier (A/B/C), rule and IOC bundle versions, last heartbeat; per-agent event volume sparkline |
| **Response** | Active bans fleet-wide with TTL countdown and offense ladder, isolated hosts, unban/release (release needs approval) |
| **Approvals** | Pending T3 actions showing the **decoded command payload** next to the narrative; approve/reject with a passkey |
| **Detections** | Loaded rules, hit counts, false-positive markings, rules inactive because of collector tier |
| **Audit** | Audit log with chain-verification status and the latest anchored head hash |

#### 3.6.2 Technology

- **Frontend:** Svelte 5 + TypeScript + Vite, built as a static SPA. Charts use uPlot (small, fast time series). The world map is a bundled SVG/TopoJSON, with no tile servers and no external requests.
- **Embedding:** the built assets are embedded into `wt-core` with `go:embed`. Node.js is needed **only to build the UI** (in CI and release), like `clang` for eBPF. A `go build` without built assets embeds a placeholder page saying "console not built, run `make ui`", so the pure-Go build keeps working.
- **API:** Connect RPC (`connectrpc.com/connect`, pure Go). The same `.proto` service definitions serve gRPC to `wt-cli` and HTTP/JSON to the browser, so there is one API surface, not two. The live feed uses Connect server streaming.
- **GeoIP (optional):** DB-IP Lite country database (CC BY 4.0), downloaded by the installer. Without it the map is hidden; nothing breaks.

#### 3.6.3 Security

The console renders attacker-controlled strings (log excerpts, user agents, URLs, command lines), so it is an XSS target by design.

- **Exposure:** listens only on the WireGuard interface (default `10.8.0.1:8443`), TLS with a certificate from the Core CA.
- **Authentication:** passkey (WebAuthn) login for registered admins. Sessions are 8 h, `HttpOnly; Secure; SameSite=Strict` cookies. State-changing requests also require a custom header (CSRF).
- **Roles:** `viewer` (read-only) and `approver`. Approving a T3 action needs a **fresh passkey signature over that action's payload** (§5.3); a logged-in session alone can never approve.
- **Output encoding:** all telemetry is rendered as text. Svelte's `{@html}` is banned by a lint rule in CI. URLs from telemetry are never rendered as clickable links.
- **CSP:** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`. No inline scripts, no third-party origins.

#### 3.6.4 Demo Stack

`deployments/demo/` is a docker-compose stack: Core, PostgreSQL, three Sentry+Turret agents and an **attack simulator** container. The simulator replays SSH brute force, web scanning, an exploit followed by a payload download into `/tmp`, and a C2 beacon to a test IOC. It serves three purposes:
1. the Phase 3 end-to-end test environment,
2. realistic data for UI development and the Phase 5 UI tests,
3. README screenshots and the demo GIF (`make demo`).

#### 3.6.5 Grafana

Grafana is **optional**. It is for ad-hoc metric exploration through the read-only `wt_grafana` role. Provisioned dashboards may be shipped later, but nothing in WatchTower depends on Grafana.

---

## 4. Data Model, Detection & Storage

### 4.1 WatchTower Event Schema (WES)

OCSF-inspired: class names and core field names follow OCSF where practical, without claiming full OCSF compliance. Defined in `proto/watchtower/synapse/v1/event.proto` (generated into `pkg/synapse/v1`).

| WES class | OCSF analogue (class_uid) | Produced by |
|---|---|---|
| `authentication` | Authentication (3002) | LogWatcher (sshd, sudo, su, PAM) |
| `http_activity` | HTTP Activity (4002) | LogWatcher (nginx/Apache) |
| `process_activity` | Process Activity (1007) | Process collectors (Tier A/B/C) |
| `network_activity` | Network Activity (4001) | Tier A connect events, `/proc/net/tcp` |
| `file_activity` | File System Activity (1001) | FIM |
| `metric_sample` | (WatchTower-specific) | Metrics collector |
| `detection_finding` | Detection Finding (2004) | Rule engines (agent and core) |

Common envelope and entities:

```protobuf
message Event {
  string   event_id   = 1;   // UUIDv7, generated on the agent
  google.protobuf.Timestamp time = 2;
  string   agent_id   = 3;
  EventClass class    = 4;
  Severity severity   = 5;   // INFO, LOW, MEDIUM, HIGH, CRITICAL
  Endpoint src        = 6;   // ip, port
  Endpoint dst        = 7;
  User     user       = 8;   // name, uid
  Process  process    = 9;   // pid, ppid, exe, cmdline (truncated), uid, start_time, parent_exe
  File     file       = 10;  // path, sha256, owner, mode, package_status
  Http     http       = 11;  // method, path (no query by default), status, user_agent (truncated)
  Auth     auth       = 12;  // outcome, method, service
  map<string, string> attrs = 13;  // bounded: ≤ 16 keys, ≤ 64 bytes per key, ≤ 256 bytes per value
  string   raw_excerpt = 14; // sanitized, ≤ 512 bytes, optional
}
```

### 4.2 Detection-as-Code

- Rules live in `rules/` in the repository, one YAML file per rule, using the **Sigma** format (detection blocks) plus **Sigma correlation rules** (`event_count`, `value_count`, `temporal`) for thresholds and sequences.
- WatchTower supports a documented subset of Sigma modifiers (`contains`, `startswith`, `endswith`, `re`, `cidr`, `all`). Unsupported features fail the rule at load time, never silently.
- Field names in rules map to WES fields through a single mapping file (`rules/wes-mapping.yaml`).
- Each rule carries WatchTower extensions under `custom`: `scope: agent | core`, `requires: [process_exec]`, optional `response: {action: BAN_TEMP, ttl: 900s}` (agent rules only, within Reflex limits).
- **Every rule ships with test events**: positive samples that must match and negative samples (the false-positive regression corpus) that must not. `make test-rules` runs them in CI.
- Core distributes agent rule bundles signed with the Core Automation Key (v1.x); in v1, agent rules are embedded in the Sentry binary.

Example (agent-side, with correlation):

```yaml
title: SSH authentication failure
id: 8f0c6c1e-1f6b-4c3e-9a3e-0b5f8e6b2a11
logsource: { product: linux, service: sshd }
detection:
  sel: { class: authentication, auth.service: sshd, auth.outcome: failure }
  condition: sel
level: low
---
title: SSH brute force
id: 3a2d7e5b-8a8b-4b0e-9a77-6d4f5e1c9b02
correlation:
  type: event_count
  rules: [8f0c6c1e-1f6b-4c3e-9a3e-0b5f8e6b2a11]
  group-by: [src.ip]
  timespan: 60s
  condition: { gte: 5 }
level: medium
custom:
  scope: agent
  response: { action: BAN_TEMP, ttl: 900s }
```

### 4.3 PostgreSQL / TimescaleDB Schema (`deployments/sql/`)

Migrations are applied by role `wt_owner` (owns all objects). The runtime role `wt_core` gets only the privileges listed. Optional Grafana uses read-only `wt_grafana`.

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Roles (created by the installer; passwords set out of band)
-- CREATE ROLE wt_owner  LOGIN;      -- no password; see note below
-- CREATE ROLE wt_core   LOGIN;
-- CREATE ROLE wt_grafana LOGIN;
--
-- wt_owner needs LOGIN because TimescaleDB policy jobs (compression, retention)
-- run as the table owner. It has no password, so pg_hba.conf must not allow any
-- passwordless method (trust, peer, ident, cert) for it. Add explicit
-- first-match lines:
--   host  all  wt_owner  0.0.0.0/0  reject
--   host  all  wt_owner  ::/0       reject
--   local all  wt_owner             reject
-- Background workers do not go through pg_hba, so policy jobs keep working.
-- Migrations reach it via SET ROLE from an administrative connection, never by
-- logging in as wt_owner. bootstrap.sql also revokes CREATE on schema public
-- from PUBLIC (PostgreSQL <= 14 default) so other roles cannot plant objects
-- that migrations would resolve and run as wt_owner.

-- 1. AGENTS
CREATE TYPE agent_status AS ENUM ('PENDING', 'ALIVE', 'STALE', 'DEAD', 'ISOLATED', 'REVOKED');

CREATE TABLE agents (
    id              TEXT PRIMARY KEY,                -- e.g. UUIDv7
    hostname        TEXT NOT NULL,
    ip_address      INET,
    version         TEXT NOT NULL,
    collector_tier  CHAR(1) NOT NULL DEFAULT 'C',    -- 'A' | 'B' | 'C'
    rule_version    BIGINT NOT NULL DEFAULT 0,
    ioc_version     BIGINT NOT NULL DEFAULT 0,
    status          agent_status NOT NULL DEFAULT 'PENDING',
    last_seen       TIMESTAMPTZ,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. ENROLLMENT TOKENS (only hashes stored)
CREATE TABLE enrollment_tokens (
    token_sha256    BYTEA PRIMARY KEY,
    name            TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    used_by_agent   TEXT REFERENCES agents(id)
);

-- 3. CERTIFICATES (public material only; private keys never leave the agent)
CREATE TABLE certificates (
    serial_number      TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL REFERENCES agents(id),
    cert_pem           TEXT NOT NULL,
    fingerprint_sha256 BYTEA NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revocation_reason  TEXT
);
CREATE INDEX idx_certs_agent ON certificates(agent_id);   -- multiple certs per agent across renewals

-- 4. EVENTS (hypertable, WES flattened)
CREATE TABLE events (
    time          TIMESTAMPTZ NOT NULL,
    event_id      UUID NOT NULL,
    agent_id      TEXT NOT NULL,
    class         TEXT NOT NULL,
    severity      SMALLINT NOT NULL,
    src_ip        INET,
    dst_ip        INET,
    dst_port      INTEGER,
    user_name     TEXT,
    process_pid   INTEGER,
    process_exe   TEXT,
    process_cmdline TEXT,
    file_path     TEXT,
    file_sha256   BYTEA,
    attrs         JSONB,
    raw_excerpt   TEXT,
    PRIMARY KEY (time, event_id)
);
SELECT create_hypertable('events', 'time', chunk_time_interval => INTERVAL '1 day');
ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id');
SELECT add_compression_policy('events', INTERVAL '7 days');
SELECT add_retention_policy('events', INTERVAL '90 days');
CREATE INDEX idx_events_agent_time ON events(agent_id, time DESC);
CREATE INDEX idx_events_src_time   ON events(src_ip, time DESC) WHERE src_ip IS NOT NULL;

-- 5. DETECTIONS (rule hits; kept longer than raw events)
CREATE TABLE detections (
    time          TIMESTAMPTZ NOT NULL,
    detection_id  UUID NOT NULL,
    agent_id      TEXT,                              -- NULL for fleet-level detections
    rule_id       UUID NOT NULL,
    rule_title    TEXT NOT NULL,
    level         SMALLINT NOT NULL,
    entity_keys   TEXT[] NOT NULL,                   -- e.g. {'ip:45.1.2.3','user:web-1/www-data'}
    event_ids     UUID[] NOT NULL,
    incident_id   UUID,
    PRIMARY KEY (time, detection_id)
);
SELECT create_hypertable('detections', 'time');
SELECT add_retention_policy('detections', INTERVAL '365 days');

-- 6. INCIDENTS
CREATE TABLE incidents (
    id             UUID PRIMARY KEY,
    opened_at      TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    closed_at      TIMESTAMPTZ,
    score          NUMERIC(8,2) NOT NULL,
    tier           SMALLINT NOT NULL,                -- 0..3
    score_breakdown JSONB NOT NULL,
    entity_keys    TEXT[] NOT NULL,
    agent_ids      TEXT[] NOT NULL,
    ai_assessment  JSONB,
    status         TEXT NOT NULL DEFAULT 'OPEN'      -- OPEN, CONTAINED, CLOSED, FALSE_POSITIVE
);

-- 7. RESPONSE ACTIONS (every action, automated or approved)
CREATE TABLE response_actions (
    command_id     UUID PRIMARY KEY,
    incident_id    UUID REFERENCES incidents(id),
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    ttl_seconds    INTEGER,
    origin         TEXT NOT NULL,                    -- REFLEX, AUTOMATION, ADMIN
    signer_key_id  TEXT,
    issued_at      TIMESTAMPTZ NOT NULL,
    acked_at       TIMESTAMPTZ,
    result         TEXT                              -- APPLIED, REFUSED_SAFETY, REFUSED_SIGNATURE, FAILED
);

-- 8. PENDING APPROVALS (destructive actions)
CREATE TABLE pending_approvals (
    id             UUID PRIMARY KEY,
    incident_id    UUID NOT NULL REFERENCES incidents(id),
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    action         TEXT NOT NULL,                    -- KILL_PROCESS, ISOLATE_HOST, RELEASE_HOST, BAN_PERM
    target         TEXT NOT NULL,
    target_exec    TEXT,
    target_start_time BIGINT,
    command_payload BYTEA NOT NULL,                  -- exact bytes the admin will sign
    status         TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, APPROVED, REJECTED, EXPIRED
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    decided_by_key TEXT,
    decided_at     TIMESTAMPTZ
);

-- 9. ADMIN APPROVAL KEYS (public keys only)
CREATE TABLE admin_keys (
    key_id         TEXT PRIMARY KEY,                 -- SHA-256 of the public key, hex
    owner          TEXT NOT NULL,
    algorithm      TEXT NOT NULL,                    -- 'ed25519' | 'webauthn-es256'
    public_key     BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);

-- 10. BASELINES (Hippocampus)
CREATE TABLE baselines (
    agent_id       TEXT NOT NULL,
    metric_name    TEXT NOT NULL,
    bucket         TEXT NOT NULL,                    -- 'dow:hour:1:14' or 'hour:14'
    median_value   DOUBLE PRECISION NOT NULL,
    mad_value      DOUBLE PRECISION NOT NULL,
    sample_count   INTEGER NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, metric_name, bucket)
);

-- 11. FLEET IP REPUTATION
CREATE TABLE ip_reputation (
    ip             INET PRIMARY KEY,
    offense_count  INTEGER NOT NULL DEFAULT 0,
    agents_seen    TEXT[] NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_ban_until TIMESTAMPTZ
);

-- 12. CTI INDICATORS (Midbrain)
CREATE TABLE ioc_indicators (
    id             BIGSERIAL PRIMARY KEY,
    indicator_type TEXT NOT NULL,                    -- SHA256, IPV4, IPV6, CIDR
    value          TEXT NOT NULL,
    threat_family  TEXT,
    source_feed    TEXT NOT NULL,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,
    UNIQUE (indicator_type, value)
);

-- 13. CORRELATION STATE SNAPSHOTS
CREATE TABLE correlation_state (
    entity_key     TEXT PRIMARY KEY,
    state          JSONB NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);

-- 14. AUDIT LOG (append-only, hash-chained)
CREATE TABLE audit_logs (
    id             BIGSERIAL PRIMARY KEY,
    time           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor          TEXT NOT NULL,                    -- 'core', 'admin:<key_id>', 'agent:<id>'
    action_type    TEXT NOT NULL,
    target         TEXT,
    detail         JSONB,
    prev_hash      BYTEA NOT NULL,
    entry_hash     BYTEA NOT NULL                    -- SHA-256(prev_hash || canonical(entry))
);

-- Privileges: everything is owned by wt_owner, so these grants actually bind.
GRANT SELECT, INSERT, UPDATE ON agents, enrollment_tokens, certificates, incidents,
      response_actions, pending_approvals, baselines, ip_reputation, ioc_indicators,
      correlation_state TO wt_core;
GRANT SELECT, INSERT ON events, detections TO wt_core;
GRANT SELECT ON admin_keys TO wt_core;                -- admin keys are added via wt_owner only
GRANT SELECT, INSERT ON audit_logs TO wt_core;        -- no UPDATE/DELETE/TRUNCATE
GRANT USAGE ON SEQUENCE audit_logs_id_seq, ioc_indicators_id_seq TO wt_core;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO wt_grafana;
```

**Audit anchoring.** A hash chain inside the same database only detects tampering if its head is stored elsewhere. Core publishes the current head hash daily (and on every destructive action) to the admin's ntfy topic, and `wt-cli audit verify --anchor <hash>` re-walks the chain. This detects tampering by anyone who can write to PostgreSQL, including a compromised `wt_owner`, as long as the admin keeps the notifications.

**Retention defaults:** raw events 90 days (compressed after 7), detections 365 days, incidents/actions/audit indefinitely. Optional IP masking for exports and AI calls (`/24` for IPv4, `/48` for IPv6).

---

## 5. Security, PKI & Trust Boundaries

### 5.1 Keys and Where They Live

| Key | Location | Signs | Compromise impact |
|---|---|---|---|
| Enrollment CA | Core, `/etc/watchtower/pki/ca.key` (`0600 wt-core`) | Agent and admin client certificates | Attacker can enroll rogue agents (inject fake telemetry) |
| Core Automation Key (Ed25519) | Core, `/etc/watchtower/pki/automation.key` | T1/T2 commands, IOC bundles, rule bundles | Attacker can issue bans (≤ 7 d) on any agent; **cannot** kill processes, isolate hosts or ban permanently; self-preservation still applies |
| Administrator Approval Key(s) | Admin workstation (`~/.config/watchtower/admin.key`, passphrase-encrypted) or a passkey (Web Console, Phase 5) | T3 commands, `RELEASE_HOST`, `UNBAN` of permanent bans | Full response authority — protect accordingly |
| Agent key | Agent, `/etc/watchtower/agent.key` (`0600 watchtower`) | mTLS client auth | Impersonate that one agent |

Turret holds only public keys: `/etc/watchtower/automation.pub` and `/etc/watchtower/admin_keys.d/*.pub`, written by the installer (root-owned, `0644`). Adding an admin key to a host is a root operation on that host, not something Core can push.

### 5.2 Signed Commands (`proto/watchtower/synapse/v1/command.proto`)

```protobuf
message CommandPayload {
  string command_id  = 1;  // UUIDv7
  string agent_id    = 2;  // must equal the local agent ID
  int64  issued_at   = 3;  // unix seconds
  int64  expires_at  = 4;  // ≤ issued_at + 120 s (automation), ≤ + 1 h (admin approval window)
  Action action      = 5;
  string target      = 6;  // ip, cidr, "pid:<n>"
  string target_exec = 7;
  int64  target_start_time = 8;
  int64  ttl_seconds = 9;
}

message SignedCommand {
  bytes  payload   = 1;  // serialized CommandPayload — the signature covers these exact bytes
  bytes  signature = 2;
  string key_id    = 3;
  SignatureScheme scheme = 4;  // SIGNATURE_SCHEME_ED25519 | SIGNATURE_SCHEME_WEBAUTHN_ES256
  WebAuthnAssertion webauthn = 5;  // set only for SIGNATURE_SCHEME_WEBAUTHN_ES256
}

message WebAuthnAssertion {
  bytes authenticator_data = 1;
  bytes client_data_json   = 2;
}
```

Turret verification order: (1) `key_id` known and allowed for this action (§3.4.1 table); (2) signature over `payload` bytes; (3) parse payload; (4) `agent_id` matches; (5) `now` within `[issued_at − 30 s, expires_at]`; (6) `command_id` not in the seen-ID cache (kept until `expires_at`, persisted across restarts); (7) Safety Layer. Every refusal is reported back to Core and audited.

Because Sentry only forwards `SignedCommand` bytes, a compromised Sentry can drop or delay commands but cannot alter or forge them.

### 5.3 Human-in-the-Loop Flow

1. Policy Engine creates a `pending_approvals` row containing the exact `CommandPayload` bytes, and sends an ntfy notification: summary, score breakdown, AI narrative (if any), and a deep link.
2. **v1 (wt-cli):** `wt-cli approvals show <id>` displays the decoded payload; `wt-cli approvals approve <id>` signs the bytes locally with the admin key and uploads the signature. Core cannot produce this signature.
3. **Web Console (passkey, Phase 5):** the deep link opens the console's Approvals screen (§3.6) over WireGuard. The admin's phone signs the payload hash as a WebAuthn challenge (ES256). Turret verifies the WebAuthn assertion (`authenticatorData`, `clientDataJSON`, challenge = SHA-256(payload)) against the registered public key. Pure Go (`crypto/ecdsa`, `encoding/json`).
4. Rejection or expiry is audited; nothing is sent to the agent.

A compromised Core can show the admin a misleading summary, but the admin signs the actual payload bytes — the CLI and the console always render the decoded payload (action, agent, target, exec) next to the narrative.

### 5.4 CSR-Based Enrollment

1. `wt-cli agent token-create --name web-1 --ttl 15m` → random 32-byte token; Core stores only its SHA-256.
2. Sentry generates its private key locally (`0600`), builds a CSR and calls `EnrollAgent(token, csr)` over TLS. On first contact Sentry pins Core's CA by the fingerprint printed by `token-create` (passed to the installer), preventing a MITM on enrollment.
3. Core checks the token (unused, unexpired), signs the CSR (90-day certificate, agent ID in SAN URI), marks the token used.
4. Renewal: Sentry re-enrolls with a new CSR over its existing mTLS session when < 30 days remain. Revocation: `wt-cli agent revoke` → Core refuses that serial at the TLS layer (in-memory revocation set, loaded from `certificates`).

### 5.5 Network Exposure

- Core: gRPC `:50051` reachable from agents (public or VPN); Web Console, wt-cli API, PostgreSQL and (optional) Grafana only on the WireGuard interface.
- Agents: no inbound ports for WatchTower.
- Frontal: loopback only; outbound HTTPS to the configured LLM endpoint (or none, with a local model).

---

## 6. Operational Procedures & CLI

```bash
# Core host
wt-cli pki init --output /etc/watchtower/pki/          # CA + Core Automation Key
wt-cli setup-wizard                                    # DB roles/migrations, ntfy, optional LLM endpoint

# Administrator workstation
wt-cli admin keygen                                    # Admin Approval Key (passphrase-protected)
wt-cli admin register --pub ~/.config/watchtower/admin.pub   # records public key; prints install line for agents
wt-cli admin passkey-invite --role approver           # one-time link to register a passkey in the Web Console

# New agent
wt-cli agent token-create --name web-1 --ttl 15m       # prints token + CA fingerprint + install command

# Day to day
wt-cli agents list
wt-cli incidents list --open
wt-cli incidents show <id>                             # timeline, rules, score breakdown, AI narrative
wt-cli events tail --agent web-1 --min-severity high
wt-cli approvals list
wt-cli approvals approve <id> --reason "Confirmed miner in /tmp"
wt-cli bans list --fleet
wt-cli unban 203.0.113.7 --fleet

# Detection engineering
wt-cli rules test rules/                               # runs positive/negative samples
wt-cli rules lint rules/

# Web Console & demo
make ui                                               # build the console and embed it into wt-core
make demo                                             # docker-compose demo stack with attack simulator

# Integrity & emergencies
wt-cli audit verify --anchor <hash>
wt-turret panic-flush                                  # on an agent: remove every WatchTower firewall rule
```

---

## 7. Development Roadmap

Ordering principle: **ship the smallest thing that is already better than Fail2Ban** (fleet immunity with safe enforcement), make it **visible** (the Web Console comes before process-telemetry depth, because it is how people evaluate the project), then add depth. Anomaly detection comes late because it needs weeks of collected data anyway.

| Phase | Version | Focus | Deliverables | Verification gate |
|---|---|---|---|---|
| **0** | v0.3.0 | Contracts | `pkg/synapse` (`event.proto`, `command.proto`, `agent.proto`, `ipc.proto`), `deployments/sql/` migrations with roles, `rules/` layout + `wes-mapping.yaml`, Makefile targets | `buf lint` / `buf generate` run cleanly; `CGO_ENABLED=0 go build ./...`; migrations apply on a fresh TimescaleDB in CI |
| **1** | v0.4.0 | `wt-turret` safety first | Safety layer, origin table, reflex budget, signature + replay verification, nftables table, `panic-flush`, verified kill | `go test -race ./internal/turret/...` 100% pass, including netns tests: self-ban refusal, path traversal refusal, forged/replayed/expired command refusal, `panic-flush` restores connectivity |
| **2** | v0.5.0 | `wt-sentry` | LogWatcher → WES, Sigma subset engine + correlation, FIM + package verification, `/proc` metrics, Tier C process collector, Reflex Arc, enrollment client | Rule regression corpus (WordPress `.php`, `;` query strings, single SSH typo) passes; FIM ignores package-consistent upgrades in a Debian container test |
| **3** | v0.6.0 | `wt-core` + demo stack | CSR enrollment, ingest, core rules, entity correlator, scoring/tiers, **Fleet Immunity**, Policy Engine, Automation Key signing, audit chain, `deployments/demo/` with attack simulator (§3.6.4) | E2E on the demo stack (3 agents): brute force on agent 1 → fleet ban on agents 2–3 within 10 s; whitelisted IP never banned; Core cannot produce a valid T3 command |
| **4** | v0.7.0 | `wt-cli` + HITL | Connect API, CLI, admin keys, approvals, ntfy notifications, audit anchoring | Approval E2E: `KILL_PROCESS` executes only with admin signature; tampered payload refused |
| **5** | v0.8.0 | **Web Console** (Visual Cortex) | Svelte SPA embedded in `wt-core`: Overview, Incidents, Fleet, Response, Approvals, Detections, Audit; passkey login and passkey approvals; live feed; `make ui`, `make demo` | Playwright E2E on the demo stack with a virtual authenticator: login, approve a `KILL_PROCESS`, reject a tampered payload; XSS corpus (`<script>`, `javascript:` URLs, ANSI codes in log lines) renders as inert text; zero CSP violations; README screenshots and demo GIF regenerated from the demo stack |
| **6** | v0.9.0 | Process telemetry depth | Tier B (auditd), Tier A (eBPF exec/connect) | Short-lived process (`sh -c 'curl …'`) detected on Tier A/B; tier reported in heartbeat |
| **7** | v0.10.0 | Hippocampus | Continuous aggregates, median/MAD baselines, cold-start logic | Synthetic 6-week dataset: no anomaly signals before thresholds, injected spikes detected, `MAD = 0` handled |
| **8** | v1.0.0 | Hardening & release | Installer, systemd units (with sandboxing), upgrade path, docs, threat model review | Fresh-install-to-first-detection < 15 min on Debian 12 and Rocky 9 |
| **9** | v1.1+ | Frontal, Midbrain, Amygdala | Optional AI analyst (narratives shown in the console), CTI feeds + signed IOC bundles, decoys, optional Grafana dashboards | Prompt-injection corpus → never an action outside the allow-list; 100k-IOC lookup benchmark < 1 µs |

---

## 8. Migration From the Current Codebase

The current repository (`v0.2.0`, ~2.3k lines of Go) is small enough to restructure in place.

| Current | Decision | Target |
|---|---|---|
| `pkg/protocol/agent.proto` (+ generated) | Replace | `proto/watchtower/synapse/v1/*.proto` → `pkg/synapse/v1` (new WES and command contracts) |
| `internal/config` | Keep, extend | `internal/config` (per-binary sections) |
| `internal/sentry/logwatcher.go` (+ tests) | Keep, refactor | `internal/sentry/logwatcher` — output WES events instead of matched lines |
| `internal/sentry/patterns.go` (+ tests) | Convert | `rules/*.yml` (Sigma); existing test cases become rule samples |
| `internal/sentry/metrics.go` (+ tests) | Keep | `internal/sentry/metrics` |
| `cmd/wt-interceptor` | Delete | — (WAF dropped from scope) |
| `cmd/wt-core`, `cmd/wt-sentry`, `cmd/wt-cli` | Keep | same |
| — | Add | `cmd/wt-turret`, `cmd/wt-frontal` (Phase 9) |
| — | Add | `web/` (console frontend), `internal/core/console`, `deployments/demo/` |
| `test/integration/phase0_test.go`, `scripts/verify-phase0.sh` | Replace | New Phase 0 gate per §7 |
| `.github/workflows`, `.golangci.yml`, `.goreleaser.yml`, `Makefile` | Keep, update | Add `test-rules`, netns tests (privileged runner), migration test |
| `WatchTower-XDR-Architecture-v2_2.md`, old `docs/architecture.md` | Archived | `docs/archive/` |
| `configs/*.yaml` | Update | Add `turret.yaml`, tiers/weights in `core.yaml` |

README roadmap and CHANGELOG must be updated in the same change that starts Phase 0 (documentation consistency is a phase-close requirement since v2.2).

---

## 9. Threat Model & Known Limitations

**In scope:**
- Internet attackers against exposed services (SSH, web): brute force, scanning, exploitation followed by payload download/execution, C2 beacons to known infrastructure.
- Compromise of an unprivileged service account (e.g. `www-data`) on a protected host.
- Compromise of `wt-sentry` (it parses attacker-controlled input): bounded to Reflex-level actions within budget, plus fake telemetry from that host.
- Compromise of Core: bounded to reversible network actions and misleading dashboards; no destructive actions without admin signature.

**Out of scope / known limitations:**
- **Root on a protected host** can stop Sentry and Turret, edit their config and remove the nftables table. WatchTower turns this into a signal (heartbeat loss, FIM on `/etc/watchtower`, `DEAD` agent alert) but cannot prevent it.
- **Kernel rootkits** and eBPF-aware evasion.
- **Tier C visibility** misses short-lived processes and cannot attribute other users' connections to processes; operators should be told this, which is why the tier is shown everywhere.
- **Encrypted application traffic** is visible only through application logs; there is no TLS interception or packet capture.
- **Fake telemetry** from a compromised agent can raise fleet reputation for an IP. It is bounded by T2 actions (temporary bans with TTL) and by the fleet whitelist; destructive actions always involve a human.
- **LLM output** is untrusted text; it can be wrong or manipulated, which is why it is advisory-only and allow-listed.
- **Scale:** designed for ~200 agents on one Core. Horizontal Core scaling is not planned for v1.
