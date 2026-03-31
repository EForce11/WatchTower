# Contributing to WatchTower XDR

Thank you for your interest in WatchTower XDR. This document describes how to set up a development environment, work with the codebase, and submit contributions.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Branch Naming](#branch-naming)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Coding Standards](#coding-standards)

---

## Code of Conduct

Be respectful. Offensive language, personal attacks, or discriminatory behaviour will not be tolerated. All contributions are reviewed on merit.

---

## Before You Start

- Check [open issues](https://github.com/EForce11/WatchTower/issues) to avoid duplicate work.
- For significant features, open an issue to discuss the design before writing code.
- For bug fixes, it is acceptable to open a PR directly with a clear description.

---

## Development Setup

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.24+ | [go.dev/dl](https://go.dev/dl/) |
| protoc | Any | Protocol Buffers compiler |
| make | Any | GNU Make or compatible |
| golangci-lint | v1.64+ | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |

### Steps

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-username>/WatchTower
cd WatchTower

# 2. Add upstream remote
git remote add upstream https://github.com/EForce11/WatchTower

# 3. Install Go code generation tools
make dev-deps

# 4. Build everything
make build

# 5. Verify tests pass
make test
```

---

## Branch Naming

Use the following prefixes:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat/` | New feature | `feat/phase1-alert-dispatch` |
| `fix/` | Bug fix | `fix/sentry-reconnect-panic` |
| `docs/` | Documentation only | `docs/deployment-guide` |
| `test/` | Tests only | `test/logwatcher-edge-cases` |
| `refactor/` | Refactoring | `refactor/core-server-struct` |
| `ci/` | CI/CD pipeline | `ci/add-gosec-step` |
| `chore/` | Maintenance | `chore/bump-grpc-version` |

Branch names must be lowercase with hyphens. No spaces, no capital letters, no underscores.

---

## Commit Messages

WatchTower uses [Conventional Commits](https://www.conventionalcommits.org/). All commits and PR titles **must** follow this format:

```
type(scope): short description in lowercase

[optional body]

[optional footer: closes #123]
```

### Allowed Types

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code change without feature or bug |
| `perf` | Performance improvement |
| `ci` | CI/CD configuration |
| `chore` | Maintenance, dependency updates |
| `security` | Security-related fix |

### Rules

- Description must start with a **lowercase letter**
- Description must be **at least 10 characters** long
- Scope is optional but encouraged: `feat(sentry): ...`, `fix(core): ...`

### Examples

```
feat(sentry): add fsnotify-based log watcher
fix(core): prevent null pointer on empty agent_id
ci: pin golangci-lint to v1.64.8
docs: update phase 1 architecture diagram
chore(deps): bump grpc to v1.79.2
```

---

## Pull Request Process

1. **Sync with upstream** before opening a PR:
   ```bash
   git fetch upstream
   git rebase upstream/master
   ```

2. **Open a PR against `master`** with a title following Conventional Commits format.

3. **Fill in the PR template** — describe what changed and why.

4. **All CI checks must pass** before merging:
   - `test` — unit and integration tests with race detector
   - `lint` — golangci-lint passes
   - `CodeQL` — no new security issues introduced

5. **At least one approval** from `@EForce11` is required (enforced by CODEOWNERS).

6. **No force-pushes** to `master`. Rebase your branch if needed.

---

## Testing Requirements

- Every new function or method must have at least one test.
- Tests must pass with the race detector: `go test -race ./...`
- Aim to maintain coverage above **80%** per package.
- Use table-driven tests where multiple input/output pairs are tested.
- Integration tests live in `test/integration/`.

```bash
# Run all tests
make test

# Run with race detector
make integration-test-race

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## Coding Standards

- Run `make fmt` before committing (`go fmt ./...`).
- Run `make lint` and fix all reported issues (`golangci-lint run ./...`).
- Run `go mod tidy` if you add or remove dependencies — `go.mod` and `go.sum` must be consistent.
- Do not commit secrets, credentials, or internal IPs.
- Binary build artifacts (`wt-core`, `wt-sentry`, `wt-cli`) must never be committed — they are in `.gitignore`.
- Log messages should use structured format: `[component] event: detail`.

---

## License

By contributing, you agree that your contributions will be licensed under the
[GNU General Public License v3.0](LICENSE).
