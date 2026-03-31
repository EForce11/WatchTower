# Branch Protection Setup

Branch protection rules for WatchTower XDR are applied programmatically via
the GitHub API using the `gh` CLI. The script below is the **single source of
truth** — re-run it any time rules are reset or the repo is transferred.

> **Applied:** 2026-03-31 — run `scripts/apply-branch-protection.sh` to re-apply.

---

## Applying the Rules

```bash
# Requires: gh CLI authenticated with repo scope
gh auth status

# Apply all rules
./scripts/apply-branch-protection.sh
```

---

## `master` Branch — Active Rules

| Rule | Value |
|------|-------|
| Require PR before merging | ✅ Enabled |
| Required approvals | 1 |
| Dismiss stale reviews on new push | ✅ Enabled |
| Require Code Owner review | ✅ Enabled (CODEOWNERS enforced) |
| Require status checks to pass | ✅ Enabled |
| Require branch to be up to date | ✅ Strict (must be current with `master`) |
| Required checks | `Test`, `Lint`, `Security (gosec)`, `CodeQL Analysis`, `Validate PR title (Conventional Commits)` |
| Require conversation resolution | ✅ Enabled |
| Enforce rules on admins | ✅ Enabled (no bypass) |
| Allow force pushes | ❌ Disabled |
| Allow branch deletion | ❌ Disabled |

---

## Branch Naming Conventions

| Pattern | Purpose | Merges into |
|---------|---------|-------------|
| `master` | Protected release checkpoint | — |
| `develop` | Phase integration branch | `master` via PR |
| `feat/*` | New feature | `develop` or `master` |
| `fix/*` | Bug fix / hotfix | `master` (back-port to `develop`) |
| `ci/*` | CI/CD pipeline changes | `master` |
| `docs/*` | Documentation only | `master` |
| `chore/*` | Maintenance / deps | `master` |
| `task-X.Y/*` | Legacy task branch format | `develop` |

---

## Notes

### PR title check must run once before it appears in required checks

The `Validate PR title (Conventional Commits)` check won't appear in the
GitHub UI as a selectable required check until it has executed at least once
on an actual PR targeting `master`.

If you need to re-add it via GH UI: open any PR against `master`, let the
workflow run, then go to **Settings → Branches → master → Edit → Status checks**.

### The script already includes this check

`scripts/apply-branch-protection.sh` sets `Validate PR title (Conventional Commits)`
by name — this works via API even before the first UI run.

### CODEOWNERS

`require_code_owner_reviews: true` is set, which means every PR must be
approved by the owner listed in `.github/CODEOWNERS` for the changed paths.
Currently `@EForce11` owns all paths.