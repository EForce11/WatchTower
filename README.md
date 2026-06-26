# WatchTower XDR

<div align="center">

  **Enterprise-grade Extended Detection and Response — open, auditable, self-hosted.**

  <p align="center">
    <a href="https://github.com/EForce11/WatchTower/actions/workflows/ci.yml"><img src="https://github.com/EForce11/WatchTower/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
    <a href="https://github.com/EForce11/WatchTower/actions/workflows/codeql.yml"><img src="https://github.com/EForce11/WatchTower/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.24-00ADD8?logo=go" alt="Go Version"></a>
    <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
    <a href="https://github.com/EForce11/WatchTower/releases"><img src="https://img.shields.io/github/v/release/EForce11/WatchTower?include_prereleases" alt="Release"></a>
  </p>

</div>

---

## What is WatchTower XDR?

WatchTower is an **open-source XDR (Extended Detection and Response)** platform designed to be self-hosted, auditable, and extensible. It collects security telemetry from distributed agents, correlates events against threat patterns, and provides real-time alerting — without sending your data to a third party.

> **Status:** Active development — see the [Roadmap](#roadmap) for what's coming next.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        WatchTower XDR                           │
│                                                                 │
│  ┌──────────────┐   gRPC / mTLS   ┌──────────────────────────┐  │
│  │  wt-sentry   │ ◄─────────────► │       wt-core            │  │
│  │   (Agent)    │  Heartbeat 10s  │   (Central Server)       │  │
│  │              │                 │   Port :50051            │  │
│  │ - Log watch  │                 │ - Agent registry         │  │
│  │ - Pattern    │                 │ - Event correlation      │  │
│  │   matching   │                 │ - Alert dispatch         │  │
│  └──────────────┘                 └──────────────────────────┘  │
│                                                                 │
│  ┌───────────────┐                                              │
│  │    wt-cli     │  ← unified management interface (Phase 3+)   │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘
```

For full architecture details, see [docs/architecture.md](docs/architecture.md).

---

## Features

### ✅ Phase 0 — Core Communication (v0.2.0)
- gRPC-based agent ↔ core communication
- Heartbeat mechanism with health monitoring
- Automatic reconnection with exponential backoff
- Graceful shutdown handling
- Integration test suite

### ⏳ Phase 1 — Log Monitoring (In Progress)
- Real-time log file monitoring via inotify (`fsnotify`)
- Security event pattern matching (regex-based rules)
- Log event streaming to core

### 🔲 Upcoming Phases
| Phase | Feature | Target |
|-------|---------|--------|
| 2 | TimescaleDB + Grafana dashboards | v0.4.0 |
| 3 | Automated IP blocking (Turret) | v0.6.0 |
| 4 | Anomaly detection engine | v0.8.0 |
| 6 | Application WAF (Interceptor) | v1.0.0 |

---

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.24+ | Build toolchain |
| protoc | Any | Compile .proto files |
| make | Any | Build automation |

### Install

```bash
# Clone the repository
git clone https://github.com/EForce11/WatchTower
cd WatchTower

# Install Go code generation tools
make dev-deps

# Build all binaries
make build
```

### Run

```bash
# Terminal 1 — Start the central server
make run-core

# Terminal 2 — Start a monitoring agent
make run-sentry

# You should see heartbeats logged every 10 seconds
```

### Test

```bash
# Run all unit and integration tests
make test

# Run integration test only
make integration-test

# Run integration test with race detector
make integration-test-race

# Verify Phase 0 completion
./scripts/verify-phase0.sh
```

---

## Project Structure

```
WatchTower/
├── cmd/
│   ├── wt-core/         # Central server (gRPC, event correlation)
│   ├── wt-sentry/       # Monitoring agent (log watcher, heartbeat)
│   └── wt-cli/          # Management CLI (Phase 3+, stub)
├── internal/
│   └── sentry/          # Agent internals (log watcher, pattern matcher)
├── pkg/
│   └── protocol/        # Protobuf definitions + generated gRPC code
├── test/
│   └── integration/     # End-to-end integration tests
├── docs/                # Architecture and deployment documentation
└── scripts/             # Developer helper scripts
```

---

## Development

See [docs/architecture.md](docs/architecture.md) for full architecture documentation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, branch naming, and commit conventions.

---

## Roadmap

- [x] Phase 0: gRPC communication (v0.2.0)
- [ ] Phase 1: Log monitoring & pattern detection
- [ ] Phase 2: TimescaleDB & Grafana dashboards
- [ ] Phase 3: Automated IP blocking (Turret)
- [ ] Phase 4: Anomaly detection engine
- [ ] Phase 6: Application WAF (Interceptor)
- [ ] v1.0.0: Production release

---

## Contributing

WatchTower is an open project. Contributions, bug reports, and feature requests are welcome.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## Security

If you discover a security vulnerability, **do not open a public issue.**
Please follow the responsible disclosure process described in [SECURITY.md](SECURITY.md).

---

## License

WatchTower XDR is free software: you can redistribute it and/or modify it under the terms of the
[GNU General Public License v3.0](LICENSE) as published by the Free Software Foundation.

---

## Author

**Emir Furkan Ulu**
GitHub: [@EForce11](https://github.com/EForce11)

---

<div align="center">
<sub>WatchTower XDR — Security you can trust, infrastructure you control.</sub>
</div>
