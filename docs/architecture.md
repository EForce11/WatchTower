# WatchTower XDR — Architecture

> **Document status:** Living document. Updated as phases are completed.
> **Current version:** v0.2.0 (Phase 1 in progress)

---

## Table of Contents

- [System Overview](#system-overview)
- [Components](#components)
  - [wt-core](#wt-core--central-server)
  - [wt-sentry](#wt-sentry--monitoring-agent)
  - [wt-cli](#wt-cli--management-cli-phase-3)
- [Communication Protocol](#communication-protocol)
- [Internal Packages](#internal-packages)
  - [sentry/LogWatcher](#sentrylogwatcher)
  - [sentry/PatternMatcher](#sentrypatternmatcher)
- [Data Flow](#data-flow)
- [Deployment Model](#deployment-model)
- [Roadmap Phases](#roadmap-phases)

---

## System Overview

WatchTower XDR is a **distributed security monitoring platform** with a hub-and-spoke architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WatchTower XDR                              │
│                                                                     │
│   Host A                          Central Infrastructure            │
│  ┌──────────────┐                 ┌────────────────────────────┐   │
│  │  wt-sentry   │ ─── gRPC ────► │         wt-core            │   │
│  │   (agent)    │  :50051         │     (central server)       │   │
│  └──────────────┘                 │                            │   │
│                                   │  - Agent registry          │   │
│   Host B                          │  - Event ingestion         │   │
│  ┌──────────────┐                 │  - Alert dispatch          │   │
│  │  wt-sentry   │ ─── gRPC ────► │  - (future: correlation)   │   │
│  │   (agent)    │                 └────────────────────────────┘   │
│  └──────────────┘                                                   │
│                                   ┌────────────────────────────┐   │
│                                   │  wt-cli (Phase 3+)         │   │
│                                   │  Management interface       │   │
│                                   └────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**Design principles:**
- **Self-hosted first** — no data leaves the operator's infrastructure.
- **Agent is stateless** — all persistent state lives in the core.
- **Protocol-first** — the gRPC contract (`agent.proto`) is the source of truth.
- **Fail-safe agents** — agents reconnect automatically; core continues without them.

---

## Components

### `wt-core` — Central Server

| Property | Value |
|----------|-------|
| Binary | `cmd/wt-core/main.go` |
| Port | `:50051` (gRPC, configurable) |
| Protocol | gRPC (plaintext in dev, mTLS in production) |

**Responsibilities:**
- Accept incoming gRPC connections from `wt-sentry` agents.
- Handle `Heartbeat` RPC — validate agent identity, log health state.
- (Phase 2+) Ingest security events, store in TimescaleDB, dispatch alerts.

**Startup sequence:**
1. Create TCP listener on `:50051`
2. Create gRPC server and register `AgentService`
3. Launch server in a goroutine
4. Block on `SIGINT` / `SIGTERM`
5. Call `grpcServer.GracefulStop()` on shutdown signal

---

### `wt-sentry` — Monitoring Agent

| Property | Value |
|----------|-------|
| Binary | `cmd/wt-sentry/main.go` |
| Connects to | `wt-core` on `:50051` |
| Heartbeat interval | 10 seconds |

**Responsibilities:**
- Maintain a persistent gRPC connection to `wt-core`.
- Send `Heartbeat` RPC every 10 seconds to signal liveness.
- (Phase 1) Watch log files for new entries via `internal/sentry/LogWatcher`.
- (Phase 1) Match log lines against threat patterns via `internal/sentry/PatternMatcher`.
- (Phase 1+) Stream security events to `wt-core`.

**Reconnection strategy:**
- On startup: up to 3 connection attempts with exponential backoff (1s, 2s).
- Post-connection loss: handled at the gRPC transport layer.

---

### `wt-cli` — Management CLI (Phase 3+)

| Property | Value |
|----------|-------|
| Binary | `cmd/wt-cli/main.go` |
| Status | Stub — implementation deferred to Phase 3 |

Planned capabilities: query agents, view alerts, manage threat rules, trigger actions.

---

## Communication Protocol

Protocol definitions live in `pkg/protocol/agent.proto`.
Go bindings are generated via `protoc` and committed as `agent.pb.go` and `agent_grpc.pb.go`.

### Current RPCs

```protobuf
service AgentService {
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}

message HeartbeatRequest {
  string    agent_id  = 1;
  Timestamp timestamp = 2;
}

message HeartbeatResponse {
  AgentStatus status = 1;
}

enum AgentStatus {
  AGENT_STATUS_UNSPECIFIED = 0;
  AGENT_STATUS_OK          = 1;
  AGENT_STATUS_ERROR       = 2;
}
```

### Planned RPCs (Phase 1+)

```protobuf
rpc StreamEvents(stream SecurityEvent) returns (EventAck);
rpc GetConfig(ConfigRequest)           returns (AgentConfig);
```

---

## Internal Packages

### `sentry/LogWatcher`

Located at `internal/sentry/logwatcher.go`.

Watches one or more log files for new content using `fsnotify` (inotify on Linux).

**Key design decisions:**
- Tracks per-file **byte offsets** so only *new* lines (written after `Watch()` is called) are emitted.
- Uses a buffered channel (`cap=100`) to decouple reading from processing.
- Thread-safe: offset map is protected by a `sync.Mutex`.
- `Close()` closes the underlying `fsnotify.Watcher` (caller must stop consuming `Events()` first).

```
LogWatcher
├── fsnotify.Watcher       ← OS-level inotify subscription
├── offsets map[path]int64 ← last read position per file
├── events chan LogEvent    ← buffered output channel (cap=100)
└── mu sync.Mutex          ← guards offsets
```

### `sentry/PatternMatcher`

Located at `internal/sentry/patterns.go`.

Matches log lines against a set of compiled regular expression rules. Each rule has a name, pattern, and severity level.

---

## Data Flow

### Phase 0 (current) — Heartbeat

```
wt-sentry                              wt-core
    │                                      │
    │── grpc.NewClient(:50051) ──────────► │
    │                                      │
    │── Heartbeat{agent_id, timestamp} ──► │ log.Printf(heartbeat from ...)
    │ ◄── HeartbeatResponse{OK} ──────────│
    │                                      │
    │   (repeat every 10s)                 │
```

### Phase 1 (in progress) — Log Events

```
Log file           wt-sentry                    wt-core
    │                  │                             │
    │── inotify ──────►│                             │
    │                  │── LogWatcher.handleChange() │
    │                  │── PatternMatcher.Match()    │
    │                  │── StreamEvents{event} ─────►│
    │                  │ ◄── EventAck ───────────────│
```

---

## Deployment Model

### Development (single host)

```bash
# Terminal 1
make run-core

# Terminal 2
make run-sentry
```

### Production (multi-host) — Planned

```
                    ┌──────────────┐
                    │   wt-core    │  ← dedicated server or container
                    │  :50051/TLS  │
                    └──────┬───────┘
                           │  gRPC / mTLS
          ┌────────────────┼────────────────┐
          │                │                │
   ┌──────▼─────┐  ┌───────▼────┐  ┌───────▼────┐
   │ wt-sentry  │  │ wt-sentry  │  │ wt-sentry  │
   │  (host A)  │  │  (host B)  │  │  (host C)  │
   └────────────┘  └────────────┘  └────────────┘
```

mTLS configuration and systemd service files are planned for Phase 2.

---

## Roadmap Phases

| Phase | Feature | Target Version | Status |
|-------|---------|---------------|--------|
| 0 | gRPC heartbeat, agent ↔ core communication | v0.2.0 | ✅ Complete |
| 1 | Log monitoring, pattern matching, event streaming | v0.3.0 | ⏳ In Progress |
| 2 | TimescaleDB storage, Grafana dashboards | v0.4.0 | 🔲 Planned |
| 3 | Turret — automated IP blocking | v0.6.0 | 🔲 Planned |
| 4 | Anomaly detection engine | v0.8.0 | 🔲 Planned |
| 6 | Interceptor — Application WAF | v1.0.0 | 🔲 Planned |
