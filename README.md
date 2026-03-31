# WatchTower XDR

Enterprise-grade Extended Detection and Response for everyone, everywhere.

## Project Status

- **Phase 0:** ✅ Complete (gRPC communication)
- **Phase 1:** ⏳ In Progress (log monitoring)
- **Version:** v0.2.0-alpha

## Features (Phase 0)

- ✅ gRPC-based agent-core communication
- ✅ Heartbeat mechanism (agent health monitoring)
- ✅ Automatic reconnection with exponential backoff
- ✅ Graceful shutdown handling
- ✅ Integration tests

## Architecture

```
┌──────────────┐         gRPC/mTLS          ┌──────────────┐
│  WT-Sentry   │ ◄──────────────────────► │   WT-Core    │
│   (Agent)    │    Heartbeat (10s)         │  (Central)   │
│              │                            │              │
│ Port: N/A    │                            │ Port: 50051  │
└──────────────┘                            └──────────────┘
```

## Quick Start

### Prerequisites
- Go 1.21+
- protoc (Protocol Buffers compiler)

### Install

```bash
# Clone repository
git clone https://github.com/EForce11/WatchTower
cd WatchTower

# Build
make build
```

### Run

```bash
# Terminal 1: Start Core
make run-core

# Terminal 2: Start Sentry (in another terminal)
make run-sentry

# You should see heartbeats every 10 seconds
```

### Test

```bash
# Run all tests
make test

# Run integration test
make integration-test

# Verify Phase 0 completion
./scripts/verify-phase0.sh
```

## Build from Source

```bash
# Compile protobuf
make proto

# Build all components
make build

# Clean build artifacts
make clean
```

## Project Structure

```
WatchTower/
├── cmd/
│   ├── wt-core/         # Central server
│   ├── wt-sentry/       # Monitoring agent
│   └── wt-cli/          # CLI tool (future)
├── pkg/
│   └── protocol/        # gRPC protocol definitions
├── internal/            # Private packages (future)
├── test/
│   └── integration/     # Integration tests
└── scripts/             # Helper scripts
```

## Development

See [WatchTower-XDR-Architecture-v2.1.md](WatchTower-XDR-Architecture-v2.1.md) for complete architecture.

See [progress.md](progress.md) for development status.

See [agents.md](agents.md) for AI agent workflow.

## Roadmap

- [x] Phase 0: gRPC communication (v0.2.0)
- [ ] Phase 1: Log monitoring & pattern detection
- [ ] Phase 2: TimescaleDB & Grafana dashboards
- [ ] Phase 3: Automated IP blocking (Turret)
- [ ] Phase 4: Anomaly detection engine
- [ ] Phase 6: Application WAF (Interceptor)
- [ ] v1.0.0: Production release

## Contributing

This is a senior design/capstone project. Contributions welcome after v1.0.0 release.

## License

MIT License - See LICENSE file

## Author

Emir Furkan Ulu  
GitHub: [@EForce11](https://github.com/EForce11)

---

**WatchTower XDR** - Security you can trust, infrastructure you control.
# CI Pipeline Test
