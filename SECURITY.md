# Security Policy

## Supported Versions

The table below shows which versions of WatchTower XDR currently receive security updates.

| Version | Supported |
|---------|-----------|
| `master` (latest) | ✅ Active |
| `v0.2.x` | ✅ Active |
| `< v0.2.0` | ❌ End of Life |

---

## Reporting a Vulnerability

WatchTower XDR is a security tool — we take vulnerability reports seriously.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### Preferred Method

Open a [GitHub Security Advisory](https://github.com/EForce11/WatchTower/security/advisories/new) (private disclosure).
This allows us to discuss, validate, and patch the issue before any public disclosure.

### What to Include

A good report significantly speeds up the response. Please include:

- **Description:** A clear summary of the vulnerability and its impact.
- **Affected component:** Which binary or package is affected (`wt-core`, `wt-sentry`, `internal/sentry`, etc.).
- **Steps to reproduce:** Minimal reproduction steps or a proof-of-concept.
- **Environment:** Go version, OS, WatchTower version/commit.
- **Suggested fix:** Optional, but very welcome.

### Response Timeline

| Stage | Target Time |
|-------|-------------|
| Initial acknowledgement | Within **48 hours** |
| Severity assessment | Within **5 business days** |
| Patch / mitigation | Depends on severity — critical issues are prioritised |
| Public disclosure | Coordinated with reporter after patch is released |

---

## Scope

The following are **in scope** for security reports:

- Remote code execution (RCE) in any component
- Authentication or authorisation bypass
- Directory traversal or path injection in the log watcher
- Denial of service (DoS) via crafted log lines or gRPC messages
- Privilege escalation when running as a non-root user
- Sensitive data leakage (credentials, tokens, PII) in logs or network traffic

The following are **out of scope**:

- Theoretical vulnerabilities with no practical exploit
- Issues in transitive dependencies with no demonstrated impact on WatchTower
- Social engineering attacks
- Physical security issues

---

## Disclosure Policy

WatchTower follows **coordinated vulnerability disclosure**. We ask that you:

1. Report privately using the method above.
2. Give us a reasonable time to investigate and patch before any public disclosure.
3. Avoid exploiting the vulnerability beyond what is necessary to demonstrate the issue.

We commit to:

1. Acknowledging your report promptly.
2. Keeping you informed of our progress.
3. Crediting you in the security advisory (unless you prefer to remain anonymous).
4. Not taking legal action against researchers acting in good faith.

---

## Contact

**Emir Furkan Ulu** — [@EForce11](https://github.com/EForce11)

For non-security issues, please open a [regular issue](https://github.com/EForce11/WatchTower/issues).
