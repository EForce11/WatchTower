#!/usr/bin/env bash
# apply-branch-protection.sh
# Applies WatchTower XDR branch protection rules via the GitHub API.
#
# Prerequisites:
#   - gh CLI installed and authenticated: gh auth login
#   - Token must have 'repo' scope
#
# Usage:
#   ./scripts/apply-branch-protection.sh
#
# Idempotent: safe to re-run; each call overwrites the current rules.

set -euo pipefail

OWNER="EForce11"
REPO="WatchTower"

echo "🔒 Applying branch protection rules for ${OWNER}/${REPO}..."

# ─────────────────────────────────────────────
# master — strictest protection
# ─────────────────────────────────────────────
echo ""
echo "  Configuring: master"

gh api \
  --method PUT \
  "repos/${OWNER}/${REPO}/branches/master/protection" \
  --header "Accept: application/vnd.github+json" \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Test",
      "Lint",
      "Security (gosec)",
      "CodeQL Analysis",
      "Validate PR title (Conventional Commits)"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false
}
EOF

echo "  ✅ master → protected"

# ─────────────────────────────────────────────
# Verify
# ─────────────────────────────────────────────
echo ""
echo "🔍 Verification:"
gh api "repos/${OWNER}/${REPO}/branches/master/protection" \
  --jq '{
    strict:   .required_status_checks.strict,
    checks:   [.required_status_checks.checks[].context],
    approvals: .required_pull_request_reviews.required_approving_review_count,
    codeowners: .required_pull_request_reviews.require_code_owner_reviews,
    dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
    enforce_admins: .enforce_admins.enabled,
    force_push: .allow_force_pushes.enabled,
    deletions: .allow_deletions.enabled,
    conversation_resolution: .required_conversation_resolution.enabled
  }'

echo ""
echo "✅ Branch protection applied successfully."
echo "   View at: https://github.com/${OWNER}/${REPO}/settings/branches"
