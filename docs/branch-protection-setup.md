# Branch Protection Setup

This document describes the GitHub UI configuration required to enforce branch
protection in the WatchTower XDR repository. Apply these settings after pushing
the files in `.github/` to the repository.

Navigate to **Settings → Branches → Branch protection rules** to manage these
rules.

---

## `master` Branch

`master` is the default branch and every merge is treated as a release
checkpoint. Apply the strictest set of protections.

1. **Require a pull request before merging** → **Enabled**
2. **Required number of approvals before merging** → **1**
   _(For a solo project, self-approval satisfies this requirement.)_
3. **Dismiss stale pull request approvals when new commits are pushed** → **Enabled**
4. **Require status checks to pass before merging** → **Enabled**
   Required checks (search and select each individually):
   - `build`
   - `lint`
   - `vet`
   - `format`
   - `unit-tests`
5. **Require branches to be up to date before merging** → **Enabled**
6. **Do not allow bypassing the above settings** → **Enabled**
7. **Allow force pushes** → **Disabled**
8. **Allow deletions** → **Disabled**

---

## `develop` Branch

`develop` is the phase integration branch. It has lighter protections to allow
more frequent integration merges from feature branches.

1. **Require a pull request before merging** → **Enabled**
2. **Required number of approvals before merging** → **1**
3. **Require status checks to pass before merging** → **Enabled**
   Required checks:
   - `build`
   - `unit-tests`
4. **Allow force pushes** → **Disabled**
5. **Allow deletions** → **Disabled**

---

## Branch Naming Conventions

| Branch pattern | Purpose | Merges into |
|---|---|---|
| `master` | Protected release checkpoint | — |
| `develop` | Phase integration branch | `master` |
| `task-X.Y/*` | Short-lived feature branch for a single task | `develop` |
| `fix/*` | Hotfix branch | `master` (and back-ported to `develop`) |

Examples:
- `task-1.3/sentry-log-watcher`
- `task-2.1/turret-rate-limiter`
- `fix/prevent-self-ban`

---

## Notes

### PR title check must run at least once before it appears in required checks

The `pr-title-check` workflow will not appear in the **required status checks**
search box until it has executed at least once on an actual pull request
targeting `master`. To make it available:

1. Open any pull request targeting `master`.
2. Wait for the `check-pr-title` job to complete (pass or fail — both register
   the check name with GitHub).
3. Return to **Settings → Branches → Branch protection rules → master**.
4. In the **Status checks** search box, type `check-pr-title` — it should now
   appear and can be added as a required check.

### CODEOWNERS review requirement

GitHub enforces CODEOWNERS reviews only when **Require review from Code Owners**
is enabled under the pull request protection settings. Enable this alongside
the approval count setting on both `master` and `develop` if desired.
